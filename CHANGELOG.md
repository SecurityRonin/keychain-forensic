# Changelog

All notable changes to `keychain-forensic` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — `keychain-core` (library)

- Pure-Rust, byte-oriented **offline** reader/decryptor for macOS
  `login.keychain-db` — every entry point takes `&[u8]` and performs no I/O.
- `Keychain::open(&[u8])` / `unlock(password)` / `generic_secrets()` — parse the
  `AppleDatabase` container and, given the login password, run the full unlock
  chain: `PBKDF2-HMAC-SHA1` master key → `3DES-EDE3-CBC` DBKey unwrap → CMS
  per-record key unwrap → `3DES-CBC` SSGP secret decrypt.
- Recovers the Chromium/Edge/Brave **Safe Storage** key (and any generic-password
  secret) from an acquired disk.
- `crypto::{derive_master_key, kcdecrypt, unwrap_key_blob}` primitives; all
  cryptography uses audited RustCrypto crates (`pbkdf2`, `des`, `cbc`, `hmac`,
  `sha1`) — no hand-rolled math.
- `error::KeychainError` — typed errors; a wrong or absent password reports
  `Locked`, never a fabricated secret.
- Fixed-width integer reads go through the fuzzed `safe-read` crate; two
  `cargo-fuzz` targets assert the never-panic invariant.

### Added — `keychain-forensic` (analyzer)

- `kc4n6` CLI over `keychain-core`: recover secrets from a keychain path given
  `--password`, text or `--json`; `classify()` flags `… Safe Storage` services as
  the high-value browser key; a locked store exits non-zero.

### Validated

- Tier-2 against Apple's own `/usr/bin/security`: the test fixture is minted by
  `security create-keychain` / `add-generic-password` and both secrets are
  confirmed with `security find-generic-password` before `keychain-core` decrypts
  them. Tier-1 RFC 6070 known-answer tests cover the PBKDF2 wiring.

[Unreleased]: https://github.com/SecurityRonin/keychain-forensic/commits/main
