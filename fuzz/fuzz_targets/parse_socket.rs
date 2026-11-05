//! Fuzz target: the WebSocket frame path must never panic, and whatever it
//! accepts must render back into something it accepts again.
//!
//! The driver is async, so each iteration builds a current-thread runtime. That
//! is slower than the other targets on purpose: it is the only place a raw frame
//! reaches `Event::parse` through the transport, including the size ceiling and
//! the ping/pong handling.
//!
//! Run with `cargo +nightly fuzz run parse_socket`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipgate_flow::flow::socket::{FlowSocket, Frame, MockConnection};

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime");
    let (driver, probe) = {
        let connection = MockConnection::new([
            Frame::Binary(data.to_vec()),
            Frame::text(String::from_utf8_lossy(data)),
            Frame::Close,
        ]);
        (FlowSocket::new(connection.clone()), connection)
    };

    let mut parsed = Vec::new();
    while let Ok(Some(event)) = runtime.block_on(driver.next_event()) {
        let rendered = serde_json::to_vec(&event.to_json()).expect("a Value always serialises");
        let again = sipgate_flow::Event::parse(&rendered).expect("our own output must parse");
        assert_eq!(again.to_json(), event.to_json(), "rendering is stable");
        parsed.push(event);
    }
    assert!(parsed.len() <= 2, "the script holds at most two events");
    assert!(probe.sent().is_empty(), "the loop never answers on its own");
});
