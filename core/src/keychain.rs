//! The high-level offline decryptor: open a `login.keychain-db`, unlock it with
//! the login password, and recover generic-password secrets.
//!
//! ```no_run
//! use keychain_core::Keychain;
//! let bytes = std::fs::read("login.keychain-db").unwrap();
//! let kc = Keychain::open(&bytes).unwrap();
//! let unlocked = kc.unlock(b"login-password").unwrap();
//! for s in unlocked.generic_secrets() {
//!     println!("{} / {} => {}", s.account, s.service, s.display());
//! }
//! ```

use std::collections::BTreeMap;

use crate::container::{Container, GenericRecord};
use crate::crypto::{kcdecrypt, MASTER_KEY_LEN};
use crate::error::KeychainError;

/// A parsed but still-locked keychain.
#[derive(Debug)]
pub struct Keychain<'a> {
    container: Container<'a>,
}

/// An unlocked keychain: the DBKey and every per-record key are recovered.
#[derive(Debug)]
pub struct UnlockedKeychain<'a> {
    container: &'a Container<'a>,
    /// 20-byte SSGP index -> 24-byte per-record 3DES key.
    key_list: BTreeMap<[u8; 20], [u8; MASTER_KEY_LEN]>,
}

/// A recovered secret and the attributes that identify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericSecret {
    /// Account / username (`acct`).
    pub account: String,
    /// Service name (`svce`); `Chrome Safe Storage` for the Chromium key.
    pub service: String,
    /// Keychain Access display label (`PrintName`).
    pub label: String,
    /// The decrypted secret bytes (UTF-8 for passwords; raw for binary keys).
    pub secret: Vec<u8>,
}

impl GenericSecret {
    /// The secret as UTF-8 text, if it decodes cleanly.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.secret).ok()
    }

    /// A display form: the UTF-8 text, or a hex rendering for binary secrets
    /// (e.g. the 16-byte Chromium Safe Storage AES key).
    #[must_use]
    pub fn display(&self) -> String {
        self.as_text().map_or_else(
            || {
                let mut s = String::with_capacity(self.secret.len() * 2);
                use std::fmt::Write as _;
                for b in &self.secret {
                    let _ = write!(s, "{b:02x}");
                }
                format!("hex:{s}")
            },
            ToString::to_string,
        )
    }
}

impl<'a> Keychain<'a> {
    /// Parse the container structure (no decryption yet).
    pub fn open(data: &'a [u8]) -> Result<Self, KeychainError> {
        Ok(Self {
            container: Container::parse(data)?,
        })
    }

    /// Derive the master key, unwrap the DBKey, and build the per-record key list.
    ///
    /// A wrong or absent login password surfaces as [`KeychainError::Locked`] —
    /// the store is reported present-but-locked, never a fabricated secret.
    pub fn unlock(&'a self, _password: &[u8]) -> Result<UnlockedKeychain<'a>, KeychainError> {
        // RED: not yet implemented — the derive -> DBKey unwrap -> key-list build
        // lands in GREEN. Report Locked so no fabricated secret is ever returned.
        Err(KeychainError::Locked)
    }
}

impl UnlockedKeychain<'_> {
    /// Recover every generic-password secret whose record key was unwrapped.
    #[must_use]
    pub fn generic_secrets(&self) -> Vec<GenericSecret> {
        self.container
            .generic_password_records()
            .into_iter()
            .filter_map(|rec| self.decrypt_generic(rec))
            .collect()
    }

    /// Number of per-record keys recovered (a proxy for how many secrets unlock).
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.key_list.len()
    }

    fn decrypt_generic(&self, rec: GenericRecord) -> Option<GenericSecret> {
        let ssgp = rec.ssgp?;
        let key = self.key_list.get(&ssgp.key_index)?;
        let secret = kcdecrypt(key, &ssgp.iv, &ssgp.payload).ok()?;
        Some(GenericSecret {
            account: rec.account,
            service: rec.service,
            label: rec.label,
            secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_rejects_garbage() {
        assert!(Keychain::open(b"not a keychain at all!!").is_err());
    }

    #[test]
    fn display_renders_binary_as_hex() {
        let s = GenericSecret {
            account: "Chrome".into(),
            service: "Chrome Safe Storage".into(),
            label: "Chrome".into(),
            secret: vec![0x00, 0xff, 0x10],
        };
        assert_eq!(s.as_text(), None);
        assert_eq!(s.display(), "hex:00ff10");
    }

    #[test]
    fn display_renders_text() {
        let s = GenericSecret {
            account: "alice".into(),
            service: "svc".into(),
            label: "l".into(),
            secret: b"hunter2".to_vec(),
        };
        assert_eq!(s.as_text(), Some("hunter2"));
        assert_eq!(s.display(), "hunter2");
    }
}
