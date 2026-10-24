//! Fuzz target: `Event::parse` must never panic, and whatever it accepts must
//! render back into something it accepts again.
//!
//! Run with `cargo +nightly fuzz run parse_event`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(event) = sipgate_flow::Event::parse(data) else {
        return;
    };
    let rendered = serde_json::to_vec(&event.to_json()).expect("a Value always serialises");
    let first = sipgate_flow::Event::parse(&rendered).expect("our own output must parse");
    let again = serde_json::to_vec(&first.to_json()).expect("a Value always serialises");
    let second = sipgate_flow::Event::parse(&again).expect("rendering is stable");
    assert_eq!(first, second, "rendering must be idempotent");
});
