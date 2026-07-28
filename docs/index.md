# keychain-forensic

Offline macOS `login.keychain-db` decryption in pure Rust — recover
generic-password secrets, including the Chromium `Safe Storage` key, from an
acquired disk given only the account login password.

`login.keychain-db` is the macOS analogue of Windows DPAPI. The account password
protects a chain of keys that encrypts every stored secret; recovering the
Chrome/Edge/Brave **Safe Storage** key lets an examiner decrypt that browser's
saved cookies and logins on a mounted image.

## Crates

- **`keychain-core`** — byte-oriented reader/decryptor (`&[u8]` in, no I/O).
- **`keychain-forensic`** — the `kc4n6` analyzer that classifies recovered items
  and flags the high-value `Safe Storage` keys.

## The unlock chain

1. `master = PBKDF2-HMAC-SHA1(password, DbBlob.salt, 1000, dkLen=24)`;
2. `DBKey  = unpad(3DES-EDE3-CBC-decrypt(master, DbBlob.iv, ciphertext))`;
3. each per-record key is CMS-unwrapped from the symmetric-key table;
4. each secret is `3DES-CBC-decrypt(record_key, ssgp.iv, payload)`.

All cryptography uses audited RustCrypto crates. A wrong or absent password is
reported as `KeychainError::Locked`, never a fabricated secret.

See [Validation](validation.md) for the tier-2 real-artifact evidence.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
