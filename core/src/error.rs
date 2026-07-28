//! Error type shared across the keychain container parser, the crypto layer,
//! and the high-level decryptor.

/// A failure decoding or decrypting a `login.keychain-db` artifact.
///
/// Every variant that reports something *unrecognized* carries the offending
/// value (magic, offset, length) so an examiner can diagnose it — an "unknown"
/// without the bytes is a dead end (Fail-loud / show-the-value discipline).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeychainError {
    /// A read ran past the end of the buffer.
    #[error("data too short at offset {offset}: need {needed} more bytes, have {available}")]
    TooShort {
        offset: usize,
        needed: usize,
        available: usize,
    },
    /// The file does not begin with the `kych` AppleDatabase signature.
    #[error("not a keychain: signature {found:#010x} != 'kych' (0x6b796368)")]
    BadSignature { found: u32 },
    /// The `DbBlob` metadata record was not found or is malformed.
    #[error("DbBlob (schema metadata) table not found or malformed")]
    DbBlobMissing,
    /// A `CommonBlob` magic did not match the expected `0xFADE0711`.
    #[error("bad blob magic {found:#010x} at offset {offset}: expected 0xFADE0711")]
    BadBlobMagic { found: u32, offset: usize },
    /// A required table type is absent from the schema.
    #[error("keychain schema has no table of type {table_type:#010x}")]
    MissingTable { table_type: u32 },
    /// 3DES decryption produced invalid PKCS#7 padding — almost always a wrong
    /// login password (the master key did not unwrap the DBKey).
    #[error("decryption failed: invalid padding (wrong password or corrupt blob)")]
    DecryptionFailed,
    /// A key or IV had the wrong length for the cipher.
    #[error("invalid key/IV length")]
    InvalidKeyLength,
    /// The DBKey could not be unwrapped with the derived master key: the store
    /// is present but locked. The login password is wrong or absent.
    #[error("keychain is LOCKED: the DBKey did not unwrap (wrong or missing login password)")]
    Locked,
}
