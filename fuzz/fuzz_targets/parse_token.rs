//! Fuzz target: the OAuth2 token response parser must never panic and must
//! never accept a token without an access token.
//!
//! Run with `cargo +nightly fuzz run parse_token`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    if let Ok(token) = sipgate_flow::Token::from_json(&value) {
        assert!(!token.access_token().is_empty());
    }
});
