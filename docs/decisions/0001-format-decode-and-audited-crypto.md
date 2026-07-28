# 1. login.keychain-db format decode + audited-crypto unlock chain

Date: 2026-07-29
Status: Accepted

## Context

macOS stores the login keychain as `~/Library/Keychains/login.keychain-db`. The
`-db` suffix (macOS Sierra+) is a rename only: the file is still Apple's
file-based **`AppleDatabase`** CSSM container (signature `kych`), **not** SQLite.
The separate SQLite `keychain-2.db` (iCloud / data-protection keychain) is a
different format and out of scope here.

The unlock cryptography is fully documented — Apple's open-source `securityd`
(`doc/BLOBFORMAT`), `libsecurity_cdsa_client` (`securestorage.cpp`), and
`AppleCSP` (`wrapKeyCms.cpp`) — and independently reverse-engineered by the
community `chainbreaker` tool (n0fate). The chain is standard, solved
cryptography:

1. `master = PBKDF2-HMAC-SHA1(password, DbBlob.salt[20], 1000 rounds, dkLen=24)`;
2. `DBKey  = unpad(3DES-EDE3-CBC-decrypt(master, DbBlob.iv[8], ciphertext))[..24]`;
3. each per-record symmetric key is CMS-unwrapped from the symmetric-key table:
   3DES-decrypt under a fixed magic IV (`4adda22c79e82105`), reverse the first 32
   plaintext bytes, 3DES-decrypt again under the blob's own IV, take bytes `4..`;
4. each generic secret is `3DES-EDE3-CBC-decrypt(record_key, ssgp.iv, payload)`.

A recovery tool is exactly the fabrication-trap zone: it emits a value (a
decrypted secret) an independent oracle can check, so any hand-rolled or
placeholder crypto would be both wrong and dangerous (fleet crypto law —
`CLAUDE.core.md`, "never hand-roll … NEVER ship placeholder crypto").

## Decision

1. **Parse the `AppleDatabase` container directly** (`core/src/container.rs`):
   the 20-byte header, the schema table directory, each table's 28-byte header +
   4-byte record-offset array, the `DbBlob` at `0x38` into the metadata table
   (`CSSM_DL_DB_RECORD_METADATA` = `0x80008000`), the symmetric-key table
   (`0x11`), and the generic-password table (`0x80000000`). All fields are
   big-endian; offsets and structure follow `chainbreaker` / `AppleDatabase.cpp`.
2. **All cryptography is audited RustCrypto** (`core/src/crypto.rs`): `pbkdf2`,
   `des`/`cbc`/`cipher` (3DES-EDE3-CBC), `hmac`, `sha1`. No primitive is
   hand-rolled. PKCS#7 padding is validated manually so a wrong password is caught
   by the pad check.
3. **Refuse, never fabricate.** A wrong/absent password fails the DBKey padding
   check and surfaces as `KeychainError::Locked`; a bad key/IV length or a padding
   failure is a distinct typed `KeychainError`. The library never returns
   plausible-but-wrong plaintext.
4. **Fixed-width integer reads go through `safe-read`**, not a hand-rolled
   `bytes.rs` (Paranoid Gatekeeper standard); every length/offset from the image
   is range-checked before use.

## Consequences

- Correctness is checkable against an independent oracle (Apple's `security`
  tool, and `chainbreaker`), which is only meaningful because the crypto is the
  real, standard algorithm rather than a stand-in (see `validation.md`).
- The RustCrypto set is compiled in unconditionally (no feature gates), so the
  shipped tool can always run the full unlock chain (batteries-included).
- The container parser already reaches the internet-password and key tables;
  extending the decoders to those record types is additive, not a rewrite.
