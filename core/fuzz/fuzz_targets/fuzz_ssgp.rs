#![no_main]
//! Fuzz the crypto/unwrap structures over arbitrary bytes. Invariant: never
//! panic. `kcdecrypt`, the CMS key unwrap, and PBKDF2 master derivation run on
//! attacker-controllable key/IV/ciphertext lengths.

use keychain_core::{derive_master_key, kcdecrypt, unwrap_key_blob};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split the arbitrary bytes into (key, iv, body) and drive every crypto edge.
    if data.len() < 32 {
        // Still exercise derivation with short salts.
        let _ = derive_master_key(data, data);
        return;
    }
    let (key, rest) = data.split_at(24);
    let (iv, body) = rest.split_at(8);

    let _ = derive_master_key(key, iv);
    let _ = kcdecrypt(key, iv, body);
    let _ = unwrap_key_blob(key, iv, body);
});
