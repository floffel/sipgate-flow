//! Fuzz target: the base64 parser must return `Ok` or an error for arbitrary
//! bytes, never panic or disagree with `is_valid`.
//!
//! `decode` and `is_valid` take `&str`, so arbitrary bytes are fed through
//! `from_utf8_lossy`; invalid UTF-8 therefore exercises the replacement
//! character path as a hostile input byte.
//!
//! Run with `cargo +nightly fuzz run parse_base64`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let decoded = sipgate_flow::base64::decode(&input);
    assert_eq!(
        sipgate_flow::base64::is_valid(&input),
        decoded.is_ok(),
        "is_valid and decode must agree"
    );
});
