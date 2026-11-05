#![no_main]

use libfuzzer_sys::fuzz_target;
use sipgate_flow::push::PushEvent;

fuzz_target!(|data: &[u8]| {
    // Any bytes are an acceptable input: the parser either rejects them or
    // produces a value, and it never panics.
    if let Ok(event) = PushEvent::parse(data) {
        // Parsing is deterministic, so the same body must produce the same
        // value; a difference would mean an unstable decoder.
        let again = PushEvent::parse(data).expect("the same bytes parse the same way");
        assert_eq!(event, again);

        // Every accessor is total, even for the unknown-event path.
        let _ = event.kind();
        let _ = event.event_name();
        let _ = event.call_id();
        let _ = event.direction();
        let _ = event.users();
        let _ = event.extras();
    }
});
