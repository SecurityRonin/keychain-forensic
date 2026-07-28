# keychain-forensic

[![Crates.io](https://img.shields.io/crates/v/keychain-core.svg)](https://crates.io/crates/keychain-core)
[![Docs.rs](https://docs.rs/keychain-core/badge.svg)](https://docs.rs/keychain-core)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/keychain-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/keychain-forensic/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Sponsor](https://img.shields.io/badge/sponsor-%E2%9D%A4-db61a2.svg)](https://github.com/sponsors/h4x0r)

**Offline macOS `login.keychain-db` decryption in pure Rust — recover generic-password secrets, including the Chromium `Safe Storage` key, from an acquired disk given only the account login password.**

`login.keychain-db` is the macOS analogue of Windows DPAPI: the account password
protects a chain of keys that in turn encrypts every stored secret. Recover the
Chrome/Edge/Brave **Safe Storage** key and you can decrypt that browser's saved
cookies and logins on a mounted, acquired image. `keychain-core` does the whole
unlock chain offline — no live target, no Keychain Access, no macOS API — from a
byte buffer.

## Quick start

```toml
[dependencies]
keychain-core = "0.1"
```

```rust
use keychain_core::Keychain;

let bytes = std::fs::read("login.keychain-db")?;
let kc = Keychain::open(&bytes)?;
let unlocked = kc.unlock(b"login-password")?; // wrong pw -> KeychainError::Locked
for s in unlocked.generic_secrets() {
    println!("{} / {} => {}", s.account, s.service, s.display());
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Or the `kc4n6` CLI (the `keychain-forensic` analyzer):

```console
$ kc4n6 login.keychain-db --password 'login-password'
[SAFE-STORAGE] service=Chrome Safe Storage account=Chrome secret=hex:1a2b...
[generic]      service=MySecretService account=alice secret=S3cr3t-KC-Value!
```

## How it works

The unlock chain, all via audited [RustCrypto](https://github.com/RustCrypto)
crates — no hand-rolled math:

1. `master = PBKDF2-HMAC-SHA1(password, DbBlob.salt, 1000, dkLen=24)`;
2. `DBKey  = unpad(3DES-EDE3-CBC-decrypt(master, DbBlob.iv, ciphertext))`;
3. each per-record key is CMS-unwrapped from the symmetric-key table with the
   DBKey (fixed magic IV, 32-byte reversal, second 3DES pass);
4. each secret is `3DES-CBC-decrypt(record_key, ssgp.iv, payload)`.

A wrong or absent password fails the DBKey padding check and is reported as
`KeychainError::Locked` — the store is *present but locked*, never a fabricated
secret. In a forensic tool, a plausible-but-wrong plaintext is fabricated
evidence, so every failure surfaces as a typed error instead.

## Two crates

- **`keychain-core`** — the byte-oriented reader/decryptor. Every entry point
  takes `&[u8]` and performs no I/O, so the same code serves a live file, a file
  carved from a disk image, or a memory buffer.
- **`keychain-forensic`** — the `kc4n6` analyzer over `keychain-core`: classifies
  each recovered item and flags the high-value `Safe Storage` keys.

## Trust but verify

- **Tier-2 validated against Apple's own tooling.** The test fixture is minted by
  `/usr/bin/security` (Apple's Keychain Services CLI) and its secrets are
  confirmed with `security find-generic-password` *before* this crate touches the
  file. Recovering the exact same secret proves the crate agrees with Apple, not
  merely with itself. See [`docs/validation.md`](docs/validation.md).
- **Panic-free by lint.** `#![forbid(unsafe_code)]`, `clippy::unwrap_used` and
  `expect_used` denied in production; every integer field read goes through the
  fuzzed `safe-read` crate, and every length/offset is bounds-checked before use.
- **Fuzzed.** `cargo-fuzz` targets over the container navigation and the crypto
  edges assert the never-panic invariant on arbitrary bytes.

Format reference: the community `chainbreaker` tool (n0fate) and Apple's
open-source `securityd` / `libsecurity_cdsa_*`.

---

[Privacy Policy](https://securityronin.github.io/keychain-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/keychain-forensic/terms/) · © 2026 Security Ronin Ltd
