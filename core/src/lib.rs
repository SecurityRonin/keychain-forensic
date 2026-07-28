//! Pure-Rust, byte-oriented **offline** reader for macOS `login.keychain-db`.
//!
//! `keychain-core` parses Apple's `AppleDatabase` keychain container and, given
//! the account login password, decrypts generic-password secrets — the macOS
//! analogue of Windows DPAPI offline recovery. This includes the Chromium
//! **Safe Storage** key (service `Chrome Safe Storage`), which unlocks Chrome /
//! Edge cookie and login databases on a mounted, acquired disk.
//!
//! Every entry point takes `&[u8]` and performs no I/O, so the same code serves
//! a live file, a file carved from a disk image, or a byte buffer from memory.
//!
//! The unlock chain (all via audited RustCrypto crates — no hand-rolled math):
//!
//! 1. `master = PBKDF2-HMAC-SHA1(password, DbBlob.salt, 1000, dklen=24)`;
//! 2. `DBKey` = 3DES-EDE3-CBC-decrypt of the `DbBlob` ciphertext under `master`;
//! 3. each per-record key is CMS-unwrapped from the symmetric-key table;
//! 4. each secret is 3DES-CBC-decrypted with its per-record key.
//!
//! A wrong or absent password is reported as [`KeychainError::Locked`] — the
//! store is present-but-locked, never a fabricated secret.
//!
//! Format reference: the community `chainbreaker` tool (n0fate) and Apple's
//! open-source `securityd` / `libsecurity_cdsa_*`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod container;
pub mod crypto;
pub mod error;
pub mod keychain;

pub use container::{
    Container, DbBlob, GenericRecord, KeyBlobRecord, SsgpBlob, COMMON_BLOB_MAGIC,
    KEYCHAIN_SIGNATURE, RECORD_GENERIC_PASSWORD, RECORD_METADATA, RECORD_SYMMETRIC_KEY,
};
pub use crypto::{
    derive_master_key, kcdecrypt, unwrap_key_blob, MAGIC_CMS_IV, MASTER_KEY_LEN, PBKDF2_ROUNDS,
};
pub use error::KeychainError;
pub use keychain::{GenericSecret, Keychain, UnlockedKeychain};
