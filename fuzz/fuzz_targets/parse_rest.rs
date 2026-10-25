//! Fuzz target: the REST response decoders must not panic, and decoding must
//! not depend on how the JSON was formatted.
//!
//! Covers `rest::parse_calls` (the `GET /v2/calls` envelope) and
//! `OutboundCallReceipt::parse` (the Flow outbound-call 201 body).
//!
//! Run with `cargo +nightly fuzz run parse_rest`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Whitespace, key order and number formatting must not change the result:
    // re-rendering the input through serde and decoding it again has to give
    // the same calls. (`CallInfo` is decode-only, so the comparison is by
    // length and id rather than by value.)
    if let Ok(calls) = sipgate_flow::rest::parse_calls(data) {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
            return;
        };
        let Ok(rendered) = serde_json::to_vec(&value) else {
            return;
        };
        let again = sipgate_flow::rest::parse_calls(&rendered).expect("a parsed body re-parses");
        assert_eq!(calls.len(), again.len(), "entry count must be stable");
        assert!(
            calls
                .iter()
                .zip(&again)
                .all(|(first, second)| first.call_id == second.call_id),
            "call ids must be stable"
        );
    }

    if let Ok(receipt) = sipgate_flow::OutboundCallReceipt::parse(data) {
        let rendered = serde_json::to_vec(receipt.raw()).expect("a Value always serialises");
        let again =
            sipgate_flow::OutboundCallReceipt::parse(&rendered).expect("our own output must parse");
        assert_eq!(receipt, again, "rendering must be idempotent");
    }
});
