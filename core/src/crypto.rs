//! Cryptographic primitives for `login.keychain-db`, all via audited RustCrypto
//! crates — no hand-rolled math.
//!
//! Apple's keychain unlock chain is fully documented (securityd `BLOBFORMAT`,
//! `libsecurity_cdsa_client` `securestorage.cpp`, `AppleCSP` `wrapKeyCms.cpp`):
//!
//! 1. `master = PBKDF2-HMAC-SHA1(password, DbBlob.salt, 1000, dklen=24)`.
//! 2. `DBKey  = unpad(3DES-EDE3-CBC-decrypt(master, DbBlob.iv, cipher))[..24]`.
//! 3. Each record key is CMS-unwrapped from the symmetric-key table with the
//!    DBKey (a magic fixed IV, a 32-byte reversal, then a second 3DES pass).
//! 4. A secret is `unpad(3DES-EDE3-CBC-decrypt(record_key, ssgp.iv, payload))`.
//!
//! Reference: `chainbreaker` (n0fate) and Apple's open-source `securityd`.

#[allow(unused_imports)] // used by GREEN kcdecrypt + the test module
use cbc::Decryptor;
#[allow(unused_imports)]
use cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
#[allow(unused_imports)]
use des::TdesEde3;
use sha1::Sha1;

use crate::error::KeychainError;

/// Length of the derived master key and every unwrapped DBKey / record key: the
/// 3DES-EDE3 (three 8-byte keys) key size.
pub const MASTER_KEY_LEN: usize = 24;

/// 3DES / DES CBC block size.
pub const BLOCK_SIZE: usize = 8;

/// PBKDF2 iteration count Apple fixes for the login keychain.
pub const PBKDF2_ROUNDS: u32 = 1000;

/// The fixed "magic CMS IV" used for the first pass of the CMS key unwrap
/// (`AppleCSP/wrapKeyCms.cpp`).
pub const MAGIC_CMS_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// Derive the 24-byte master key from the login password and the `DbBlob` salt.
///
/// `PBKDF2-HMAC-SHA1(password, salt, 1000)` truncated/expanded to 24 bytes.
#[must_use]
pub fn derive_master_key(password: &[u8], salt: &[u8]) -> [u8; MASTER_KEY_LEN] {
    let mut out = [0u8; MASTER_KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, PBKDF2_ROUNDS, &mut out);
    out
}

/// Decrypt a 3DES-EDE3-CBC ciphertext and strip its PKCS#7 padding.
///
/// This is `chainbreaker`'s `_kcdecrypt`: 3DES-CBC with no library-side padding,
/// then a manual unpad where the final byte is the pad length (must be in
/// `1..=8` and every pad byte must equal it). A wrong key surfaces here as
/// [`KeychainError::DecryptionFailed`] via the padding check — never silent
/// garbage.
pub fn kcdecrypt(_key: &[u8], _iv: &[u8], _data: &[u8]) -> Result<Vec<u8>, KeychainError> {
    // RED: not yet implemented — the 3DES-CBC + padding logic lands in GREEN.
    Err(KeychainError::DecryptionFailed)
}

/// Unwrap a per-record symmetric key wrapped under the DBKey (CMS key wrap).
///
/// `securestorage.cpp` / `wrapKeyCms.cpp`: decrypt the wrapped blob with the
/// fixed [`MAGIC_CMS_IV`], reverse the first 32 plaintext bytes, decrypt that
/// again under the blob's own IV, and take bytes `4..` as the 24-byte key.
pub fn unwrap_key_blob(
    _dbkey: &[u8],
    _iv: &[u8],
    _wrapped: &[u8],
) -> Result<[u8; MASTER_KEY_LEN], KeychainError> {
    // RED: not yet implemented — the CMS two-pass unwrap lands in GREEN.
    Err(KeychainError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent PBKDF2-HMAC-SHA1 known-answer tests authored by RFC 6070, not
    // by us — a genuine tier-1 KAT of the KDF crate wiring. RFC 6070 fixes the
    // iteration counts, so these exercise the raw primitive at its own `c`
    // (`derive_master_key` fixes c=1000, the value Apple uses for the keychain).
    #[test]
    fn pbkdf2_hmac_sha1_matches_rfc6070() {
        // P="password", S="salt", c=1,    dkLen=20
        let mut out = [0u8; 20];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"password", b"salt", 1, &mut out);
        assert_eq!(
            &out[..],
            &hex("0c60c80f961f0e71f3a9b524af6012062fe037a6")[..]
        );

        // P="password", S="salt", c=4096, dkLen=20
        let mut out = [0u8; 20];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"password", b"salt", 4096, &mut out);
        assert_eq!(
            &out[..],
            &hex("4b007901b765489abead49d926f721d065a429c1")[..]
        );
    }

    // The keychain KDF wiring: `derive_master_key` is exactly a 24-byte,
    // 1000-round PBKDF2-HMAC-SHA1 over (password, salt).
    #[test]
    fn derive_master_key_is_1000_round_pbkdf2() {
        assert_eq!(PBKDF2_ROUNDS, 1000);
        let mut expect = [0u8; MASTER_KEY_LEN];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"login-pass", b"0123456789abcdefghij", 1000, &mut expect);
        assert_eq!(
            derive_master_key(b"login-pass", b"0123456789abcdefghij"),
            expect
        );
    }

    #[test]
    fn kcdecrypt_roundtrips_3des_cbc() {
        use cbc::Encryptor;
        use cipher::{block_padding::Pkcs7, BlockEncryptMut};
        let key = [0x11u8; 24];
        let iv = [0x22u8; 8];
        let msg = b"keychain secret payload";
        let mut buf = vec![0u8; msg.len() + 8];
        buf[..msg.len()].copy_from_slice(msg);
        let ct = Encryptor::<TdesEde3>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut buf, msg.len())
            .unwrap()
            .to_vec();
        let pt = kcdecrypt(&key, &iv, &ct).expect("decrypt");
        assert_eq!(pt, msg);
    }

    #[test]
    fn kcdecrypt_wrong_key_fails_on_padding() {
        use cbc::Encryptor;
        use cipher::{block_padding::Pkcs7, BlockEncryptMut};
        let key = [0x11u8; 24];
        let iv = [0x22u8; 8];
        let msg = b"secret!!";
        let mut buf = vec![0u8; msg.len() + 8];
        buf[..msg.len()].copy_from_slice(msg);
        let ct = Encryptor::<TdesEde3>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut buf, msg.len())
            .unwrap()
            .to_vec();
        let wrong = [0x99u8; 24];
        // Overwhelmingly likely to produce invalid padding -> a clean error,
        // never silent wrong plaintext.
        assert!(kcdecrypt(&wrong, &iv, &ct).is_err());
    }

    #[test]
    fn kcdecrypt_rejects_bad_lengths() {
        assert_eq!(
            kcdecrypt(&[0u8; 8], &[0u8; 8], &[0u8; 8]),
            Err(KeychainError::InvalidKeyLength)
        );
        assert_eq!(
            kcdecrypt(&[0u8; 24], &[0u8; 8], &[0u8; 7]),
            Err(KeychainError::DecryptionFailed)
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
