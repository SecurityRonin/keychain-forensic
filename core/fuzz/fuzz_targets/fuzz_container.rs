#![no_main]
//! Fuzz the whole keychain container navigation over arbitrary bytes. Invariant:
//! never panic. Header/schema/table/record parsing and the full open->unlock->
//! decrypt pipeline all run on attacker-controllable input.

use keychain_core::{container::Container, Keychain};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Low-level container navigation.
    if let Ok(c) = Container::parse(data) {
        let _ = c.db_blob();
        let _ = c.symmetric_key_records();
        let _ = c.generic_password_records();
    }

    // Whole pipeline: parse, then attempt an unlock + secret recovery. A wrong
    // password must return an error, never panic.
    if let Ok(kc) = Keychain::open(data) {
        if let Ok(unlocked) = kc.unlock(b"fuzz-password") {
            let _ = unlocked.generic_secrets();
        }
    }
});
