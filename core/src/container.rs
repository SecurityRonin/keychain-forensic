//! The Apple `AppleDatabase` container that backs a `login.keychain-db`.
//!
//! Layout (all fields big-endian), reverse-engineered by `chainbreaker` and
//! matching Apple's `libsecurity_cdsa_utilities` `AppleDatabase.cpp`:
//!
//! * a 20-byte header (`kych` signature, version, header size, schema offset);
//! * a schema at `schema_offset` listing `table_count` table offsets;
//! * each table has a 28-byte header then an array of 4-byte record offsets;
//! * the `DbBlob` (master-key metadata) sits `0x38` past the metadata table;
//! * secrets live in the generic/internet-password tables as `SSGP` blobs whose
//!   per-record key is wrapped in the symmetric-key table.
//!
//! Every read is bounds-checked through the fleet `safe-read` crate: malformed
//! input yields a typed error or an empty attribute, never a panic.

use std::collections::BTreeMap;

use safe_read::try_be_u32;

use crate::error::KeychainError;

/// `kych` — the `AppleDatabase` / keychain file signature.
pub const KEYCHAIN_SIGNATURE: u32 = 0x6b79_6368;
/// `0xFADE0711` — the `CommonBlob` magic prefixing every `DbBlob` / `KeyBlob`.
pub const COMMON_BLOB_MAGIC: u32 = 0xFADE_0711;

const HEADER_SIZE: usize = 20;
const SCHEMA_HEADER_SIZE: usize = 8;
const TABLE_HEADER_SIZE: usize = 28;
const ATOM: usize = 4;
const DB_BLOB_OFFSET_IN_METADATA: usize = 0x38;

// CSSM record types (see `cssmtype.h`).
/// `CSSM_DL_DB_RECORD_METADATA` — the table holding the `DbBlob`.
pub const RECORD_METADATA: u32 = 0x8000_8000;
/// `CSSM_DL_DB_RECORD_SYMMETRIC_KEY` — wrapped per-record keys.
pub const RECORD_SYMMETRIC_KEY: u32 = 0x0000_0011;
/// `CSSM_DL_DB_RECORD_GENERIC_PASSWORD` — generic secrets (incl. Safe Storage).
pub const RECORD_GENERIC_PASSWORD: u32 = 0x8000_0000;
/// `CSSM_DL_DB_RECORD_INTERNET_PASSWORD`.
pub const RECORD_INTERNET_PASSWORD: u32 = 0x8000_0001;

/// The `DbBlob`: the salt/IV/ciphertext that guard the DBKey (master wrap).
#[derive(Debug, Clone)]
pub struct DbBlob {
    /// PBKDF2 salt for master-key derivation.
    pub salt: [u8; 20],
    /// 3DES-CBC IV for the DBKey unwrap.
    pub iv: [u8; 8],
    /// The wrapped DBKey ciphertext.
    pub cipher: Vec<u8>,
}

/// A record in the symmetric-key table: a per-record key wrapped under the DBKey.
#[derive(Debug, Clone)]
pub struct KeyBlobRecord {
    /// 20-byte label (`ssgp` magic + 16-byte key label) that a secret references.
    pub label: [u8; 20],
    /// The blob's own 3DES-CBC IV (second unwrap pass).
    pub iv: [u8; 8],
    /// The wrapped key ciphertext.
    pub cipher: Vec<u8>,
}

/// The `SSGP` (Secure Storage Group) blob carrying one encrypted secret.
#[derive(Debug, Clone)]
pub struct SsgpBlob {
    /// 20-byte key index (magic + label) mapping to a [`KeyBlobRecord::label`].
    pub key_index: [u8; 20],
    /// 3DES-CBC IV for the payload.
    pub iv: [u8; 8],
    /// The encrypted secret.
    pub payload: Vec<u8>,
}

/// A generic-password record's cleartext attributes plus its encrypted secret.
#[derive(Debug, Clone)]
pub struct GenericRecord {
    /// The `acct` attribute (account / username).
    pub account: String,
    /// The `svce` attribute (service name; e.g. `Chrome Safe Storage`).
    pub service: String,
    /// The `PrintName` label shown in Keychain Access.
    pub label: String,
    /// The encrypted secret, if the record has an SSGP area.
    pub ssgp: Option<SsgpBlob>,
}

/// A parsed keychain container over borrowed bytes.
#[derive(Debug)]
pub struct Container<'a> {
    data: &'a [u8],
    /// CSSM record type -> table offset (relative to the end of the header).
    table_by_type: BTreeMap<u32, usize>,
}

impl<'a> Container<'a> {
    /// Parse the header + schema and index every table by its CSSM type.
    pub fn parse(data: &'a [u8]) -> Result<Self, KeychainError> {
        let sig = read_u32(data, 0)?;
        if sig != KEYCHAIN_SIGNATURE {
            return Err(KeychainError::BadSignature { found: sig });
        }
        let schema_offset = read_u32(data, 12)? as usize;
        let table_count = read_u32(data, schema_offset + 4)? as usize;

        let mut table_by_type = BTreeMap::new();
        let base = HEADER_SIZE + SCHEMA_HEADER_SIZE;
        for i in 0..table_count {
            let table_offset = read_u32(data, base + ATOM * i)? as usize;
            // Read the table's own header to learn its CSSM type id.
            let table_base = HEADER_SIZE + table_offset;
            let table_id = read_u32(data, table_base + ATOM)?;
            table_by_type.entry(table_id).or_insert(table_offset);
        }

        Ok(Self {
            data,
            table_by_type,
        })
    }

    /// Locate and parse the `DbBlob` (salt / IV / wrapped DBKey).
    pub fn db_blob(&self) -> Result<DbBlob, KeychainError> {
        let meta_offset = *self
            .table_by_type
            .get(&RECORD_METADATA)
            .ok_or(KeychainError::DbBlobMissing)?;
        let base = HEADER_SIZE + meta_offset + DB_BLOB_OFFSET_IN_METADATA;

        let magic = read_u32(self.data, base)?;
        if magic != COMMON_BLOB_MAGIC {
            return Err(KeychainError::BadBlobMagic {
                found: magic,
                offset: base,
            });
        }
        // CommonBlob(8) magic@0 ver@4; StartCryptoBlob@8; TotalLength@12;
        // RandomSignature[16]@16; Sequence@32; Params(8)@36; Salt[20]@44;
        // IV[8]@64; BlobSignature[20]@72.
        let start_crypto = read_u32(self.data, base + 8)? as usize;
        let total_length = read_u32(self.data, base + 12)? as usize;
        let salt = read_array::<20>(self.data, base + 44)?;
        let iv = read_array::<8>(self.data, base + 64)?;
        let cipher = slice(self.data, base + start_crypto, base + total_length)?.to_vec();

        Ok(DbBlob { salt, iv, cipher })
    }

    /// Every wrapped per-record key in the symmetric-key table.
    ///
    /// Records that are not `ssgp`-tagged are skipped (they carry no secret key).
    pub fn symmetric_key_records(&self) -> Vec<KeyBlobRecord> {
        let mut out = Vec::new();
        for base in self.record_bases(RECORD_SYMMETRIC_KEY) {
            if let Some(rec) = self.parse_key_blob(base) {
                out.push(rec);
            }
        }
        out
    }

    /// Every generic-password record with its cleartext attributes and SSGP blob.
    pub fn generic_password_records(&self) -> Vec<GenericRecord> {
        self.record_bases(RECORD_GENERIC_PASSWORD)
            .into_iter()
            .filter_map(|base| self.parse_generic_record(base))
            .collect()
    }

    /// Parse one symmetric-key-table record into a [`KeyBlobRecord`].
    fn parse_key_blob(&self, base: usize) -> Option<KeyBlobRecord> {
        // _KEY_BLOB_REC_HEADER: RecordSize@0, RecordCount@4, Dummy[124] (132).
        let record_size = try_be_u32(self.data, base)? as usize;
        let rec = self.data.get(base + 132..base + record_size)?;
        // _KEY_BLOB: CommonBlob(8)@0, StartCryptoBlob@8, TotalLength@12, IV[8]@16.
        let start_crypto = try_be_u32(rec, 8)? as usize;
        let total_length = try_be_u32(rec, 12)? as usize;
        let iv = read_array::<8>(rec, 16).ok()?;
        // The 20-byte label sits 8 bytes past the ciphertext, tagged `ssgp`.
        if rec.get(total_length + 8..total_length + 12)? != b"ssgp" {
            return None;
        }
        let label = read_array::<20>(rec, total_length + 8).ok()?;
        let cipher = rec.get(start_crypto..total_length)?.to_vec();
        if cipher.is_empty() {
            return None;
        }
        Some(KeyBlobRecord { label, iv, cipher })
    }

    /// Parse one generic-password record's attributes + SSGP blob.
    fn parse_generic_record(&self, base: usize) -> Option<GenericRecord> {
        // _GENERIC_PW_HEADER: 22 x u32. Field i at offset 4*i.
        //  [0]RecordSize [4]SSGPArea [13]PrintName [19]Account [20]Service.
        let record_size = try_be_u32(self.data, base)? as usize;
        let ssgp_area = try_be_u32(self.data, base + 4 * 4)? as usize;
        let print_name_col = try_be_u32(self.data, base + 4 * 13)?;
        let account_col = try_be_u32(self.data, base + 4 * 19)?;
        let service_col = try_be_u32(self.data, base + 4 * 20)?;

        let body = self.data.get(base + 88..base + record_size)?;

        let ssgp = if ssgp_area != 0 {
            let area = body.get(..ssgp_area)?;
            let key_index = read_array::<20>(area, 0).ok()?;
            let iv = read_array::<8>(area, 20).ok()?;
            let payload = area.get(28..)?.to_vec();
            Some(SsgpBlob {
                key_index,
                iv,
                payload,
            })
        } else {
            None
        };

        Some(GenericRecord {
            account: read_lv(self.data, base, account_col),
            service: read_lv(self.data, base, service_col),
            label: read_lv(self.data, base, print_name_col),
            ssgp,
        })
    }

    /// The absolute base address of every record in a table.
    fn record_bases(&self, table_type: u32) -> Vec<usize> {
        let Some(&table_offset) = self.table_by_type.get(&table_type) else {
            return Vec::new();
        };
        let table_base = HEADER_SIZE + table_offset;
        let Some(record_count) = try_be_u32(self.data, table_base + 8) else {
            return Vec::new();
        };
        let record_count = record_count as usize;
        let list_base = table_base + TABLE_HEADER_SIZE;

        let mut out = Vec::new();
        let mut o = 0usize;
        // Bounded by the record count AND by staying inside the buffer, so a
        // crafted count can never spin forever.
        while out.len() < record_count {
            let Some(record_offset) = try_be_u32(self.data, list_base + ATOM * o) else {
                break; // ran off the end of the buffer
            };
            let record_offset = record_offset as usize;
            if record_offset != 0 && record_offset % 4 == 0 {
                out.push(HEADER_SIZE + table_offset + record_offset);
            }
            o += 1;
        }
        out
    }
}

/// Read a big-endian `u32`, erroring loudly with the offending offset.
fn read_u32(data: &[u8], off: usize) -> Result<u32, KeychainError> {
    try_be_u32(data, off).ok_or(KeychainError::TooShort {
        offset: off,
        needed: 4,
        available: data.len().saturating_sub(off.min(data.len())),
    })
}

/// Read a fixed-size byte array at `off`.
fn read_array<const N: usize>(data: &[u8], off: usize) -> Result<[u8; N], KeychainError> {
    let end = off.checked_add(N).ok_or(KeychainError::TooShort {
        offset: off,
        needed: N,
        available: 0,
    })?;
    let slice = data.get(off..end).ok_or(KeychainError::TooShort {
        offset: off,
        needed: N,
        available: data.len().saturating_sub(off.min(data.len())),
    })?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Slice `data[start..end]`, erroring loudly if out of range.
fn slice(data: &[u8], start: usize, end: usize) -> Result<&[u8], KeychainError> {
    if start > end {
        return Err(KeychainError::TooShort {
            offset: start,
            needed: 0,
            available: 0,
        });
    }
    data.get(start..end).ok_or(KeychainError::TooShort {
        offset: start,
        needed: end.saturating_sub(start),
        available: data.len().saturating_sub(start.min(data.len())),
    })
}

/// Read a length-prefixed attribute value at `base + (col & !1)`.
///
/// The column pointer's low bit is a flag (cleared here); a zero column means
/// the attribute is absent. The 4-byte length is padded up to a 4-byte
/// boundary. Trailing NULs are trimmed. Any out-of-range read yields an empty
/// string rather than a panic — a truncated attribute is not fatal to the scan.
fn read_lv(data: &[u8], base: usize, col: u32) -> String {
    let col = (col & 0xFFFF_FFFE) as usize;
    if col == 0 {
        return String::new();
    }
    let Some(len) = try_be_u32(data, base + col) else {
        return String::new();
    };
    let len = len as usize;
    let padded = len.div_ceil(4) * 4;
    let start = base + col + 4;
    let end = start.saturating_add(padded).min(data.len());
    let bytes = data.get(start..end).unwrap_or(&[]);
    let trimmed = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map_or(&bytes[..0], |p| &bytes[..=p]);
    String::from_utf8_lossy(trimmed).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_be_bytes());
    }

    /// A minimal synthetic `AppleDatabase`: 20-byte header, an 8-byte schema
    /// naming one table of `table_id` at `table_offset`, and `len` bytes total
    /// for the caller to stamp table/record fields into. This is the
    /// attacker's-eye view — a crafted evidence file is exactly this plus
    /// hostile field values.
    fn scaffold(len: usize, table_offset: u32, table_id: u32) -> Vec<u8> {
        let mut b = vec![0u8; len];
        put_u32(&mut b, 0, KEYCHAIN_SIGNATURE);
        put_u32(&mut b, 12, HEADER_SIZE as u32); // schema follows the header
        put_u32(&mut b, 24, 1); // table_count
        put_u32(&mut b, 28, table_offset);
        put_u32(&mut b, HEADER_SIZE + table_offset as usize + ATOM, table_id);
        b
    }

    /// A container with exactly one symmetric-key record, so a test can vary
    /// just the 4-byte tag where the 20-byte `ssgp` label is expected and the
    /// blob's crypto extents.
    fn key_blob_fixture(tag: [u8; 4], start_crypto: u32, total_length: u32) -> Vec<u8> {
        let mut b = scaffold(512, 12, RECORD_SYMMETRIC_KEY);
        put_u32(&mut b, 40, 1); // record_count (table_base 32 + 8)
        put_u32(&mut b, 60, 200); // the one record offset (list_base 32 + 28)
        let base = HEADER_SIZE + 12 + 200; // 232
        put_u32(&mut b, base, 228); // record_size -> a 96-byte _KEY_BLOB body
        let rec = base + 132; // _KEY_BLOB_REC_HEADER is 132 bytes
        put_u32(&mut b, rec + 8, start_crypto);
        put_u32(&mut b, rec + 12, total_length);
        let label = rec + total_length as usize + 8;
        b[label..label + 4].copy_from_slice(&tag);
        b
    }

    #[test]
    fn parse_rejects_non_keychain() {
        let err = Container::parse(b"NOTAKEYCHAINxxxxxxxx").unwrap_err();
        assert!(matches!(err, KeychainError::BadSignature { .. }));
    }

    #[test]
    fn parse_rejects_truncated_header() {
        assert!(matches!(
            Container::parse(b"kyc").unwrap_err(),
            KeychainError::TooShort { .. }
        ));
    }

    #[test]
    fn read_lv_absent_column_is_empty() {
        assert_eq!(read_lv(&[0u8; 64], 0, 0), "");
    }

    #[test]
    fn read_lv_out_of_range_is_empty_not_panic() {
        // col points past the buffer -> empty, no panic.
        assert_eq!(read_lv(&[0u8; 8], 0, 0x1000), "");
    }

    #[test]
    fn db_blob_rejects_a_bad_common_blob_magic() {
        // Metadata table at +12 puts the DbBlob at 20 + 12 + 0x38 = 88. The
        // error must name the offending magic AND its offset, not just "bad".
        let mut b = scaffold(96, 12, RECORD_METADATA);
        put_u32(&mut b, 88, 0xDEAD_BEEF);
        assert_eq!(
            Container::parse(&b).unwrap().db_blob().unwrap_err(),
            KeychainError::BadBlobMagic {
                found: 0xDEAD_BEEF,
                offset: 88,
            }
        );
    }

    #[test]
    fn db_blob_rejects_crypto_start_past_total_length() {
        // A crafted StartCryptoBlob (100) beyond TotalLength (50) would make an
        // unguarded `data[start..end]` panic; `slice`'s start>end arm errors.
        let mut b = scaffold(176, 12, RECORD_METADATA);
        put_u32(&mut b, 88, COMMON_BLOB_MAGIC);
        put_u32(&mut b, 96, 100); // StartCryptoBlob
        put_u32(&mut b, 100, 50); // TotalLength
        assert_eq!(
            Container::parse(&b).unwrap().db_blob().unwrap_err(),
            KeychainError::TooShort {
                offset: 188,
                needed: 0,
                available: 0,
            }
        );
    }

    #[test]
    fn record_bases_is_empty_when_the_table_type_is_absent() {
        // Only a metadata table exists, so both record lookups miss.
        let b = scaffold(96, 12, RECORD_METADATA);
        let c = Container::parse(&b).unwrap();
        assert!(c.symmetric_key_records().is_empty());
        assert!(c.generic_password_records().is_empty());
    }

    #[test]
    fn record_bases_is_empty_when_the_record_count_is_unreadable() {
        // The buffer ends right after the table's type id, so the record count
        // at table_base+8 cannot be read.
        let b = scaffold(68, 40, RECORD_SYMMETRIC_KEY);
        assert!(Container::parse(&b)
            .unwrap()
            .symmetric_key_records()
            .is_empty());
    }

    #[test]
    fn record_bases_stops_when_the_offset_list_runs_off_the_buffer() {
        // A crafted count claims 3 records but the offset list starts exactly at
        // the end of the buffer: the walk must break, not spin or panic.
        let mut b = scaffold(88, 40, RECORD_SYMMETRIC_KEY);
        put_u32(&mut b, 68, 3);
        assert!(Container::parse(&b)
            .unwrap()
            .symmetric_key_records()
            .is_empty());
    }

    #[test]
    fn ssgp_tagged_key_blob_is_parsed() {
        let b = key_blob_fixture(*b"ssgp", 24, 48);
        let recs = Container::parse(&b).unwrap().symmetric_key_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(&recs[0].label[..4], b"ssgp");
        assert_eq!(recs[0].cipher.len(), 24); // total_length - start_crypto
    }

    #[test]
    fn key_blob_without_the_ssgp_tag_is_skipped() {
        // Same fixture, only the tag differs: a non-ssgp key blob carries no
        // secret key, so it is skipped rather than mis-parsed.
        let b = key_blob_fixture(*b"xxxx", 24, 48);
        assert!(Container::parse(&b)
            .unwrap()
            .symmetric_key_records()
            .is_empty());
    }

    #[test]
    fn key_blob_with_an_empty_ciphertext_is_skipped() {
        // start_crypto == total_length -> a zero-length wrapped key: there is
        // nothing to unwrap, so the record must not be reported.
        let b = key_blob_fixture(*b"ssgp", 24, 24);
        assert!(Container::parse(&b)
            .unwrap()
            .symmetric_key_records()
            .is_empty());
    }

    #[test]
    fn generic_record_without_an_ssgp_area_has_no_secret() {
        // SSGPArea == 0: the record's cleartext attributes are still recovered,
        // but there is no encrypted secret to report.
        let mut b = scaffold(384, 12, RECORD_GENERIC_PASSWORD);
        put_u32(&mut b, 40, 1); // record_count
        put_u32(&mut b, 60, 200); // the one record offset
        let base = HEADER_SIZE + 12 + 200; // 232
        put_u32(&mut b, base, 96); // record_size
        put_u32(&mut b, base + 4 * 4, 0); // SSGPArea = 0
        put_u32(&mut b, base + 4 * 19, 100); // Account column pointer
        put_u32(&mut b, base + 100, 5); // the attribute's length prefix
        b[base + 104..base + 109].copy_from_slice(b"alice");

        let recs = Container::parse(&b).unwrap().generic_password_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].account, "alice");
        assert_eq!(recs[0].service, ""); // column pointer 0 -> absent
        assert!(recs[0].ssgp.is_none());
    }
}
