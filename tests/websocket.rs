//! The WebSocket transport, proved against an in-memory connection.
//!
//! No test in this file opens a socket: `MockConnection` is the transport, so
//! the framing, the typed event set, the action encoding, the ping/pong
//! handling and every limit boundary are exercised as pure protocol behaviour.
//! The documented message example is `tests/fixtures/flow/websocket_message.json`
//! (<https://flow.sipgate.io/api/websocket>, "Receiving Events").

#![cfg(feature = "websocket")]

use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;
use sipgate_flow::flow::socket::{AcceptBackoff, Connection, FlowSocket, Frame, MockConnection};
use sipgate_flow::{
    Action, Error, Event, EventPayload, FlowResponse, Result, RetryPolicy,
    MAX_SOCKET_MESSAGE_BYTES, MIN_RETRY_DELAY,
};

const WEBSOCKET_MESSAGE: &str = include_str!("fixtures/flow/websocket_message.json");
const SESSION_START: &str = include_str!("fixtures/flow/session_start.json");
const SESSION_START_TRANSFER_FAILED: &str =
    include_str!("fixtures/flow/session_start_transfer_failed.json");
const USER_SPEECH_STARTED: &str = include_str!("fixtures/flow/user_speech_started.json");
const USER_SPEAK: &str = include_str!("fixtures/flow/user_speak.json");
const USER_SPEAK_BARGED_IN: &str = include_str!("fixtures/flow/user_speak_barged_in.json");
const USER_BARGE_IN: &str = include_str!("fixtures/flow/user_barge_in.json");
const DTMF_RECEIVED: &str = include_str!("fixtures/flow/dtmf_received.json");
const ASSISTANT_SPEAK: &str = include_str!("fixtures/flow/assistant_speak.json");
const ASSISTANT_SPEECH_ENDED: &str = include_str!("fixtures/flow/assistant_speech_ended.json");
const USER_INPUT_TIMEOUT: &str = include_str!("fixtures/flow/user_input_timeout.json");
const SESSION_END: &str = include_str!("fixtures/flow/session_end.json");
const SMS_FAILED: &str = include_str!("fixtures/flow/sms_failed.json");
const ERROR_EVENT: &str = include_str!("fixtures/flow/error.json");
const UNKNOWN_EVENT: &str = include_str!("fixtures/flow/unknown_event.json");

/// A driver over a scripted connection, plus the probe that sees what was sent.
fn socket(frames: impl IntoIterator<Item = Frame>) -> (FlowSocket<MockConnection>, MockConnection) {
    let connection = MockConnection::new(frames);
    (FlowSocket::new(connection.clone()), connection)
}

/// The single text frame a driver sent, parsed back into JSON.
fn only_sent_json(connection: &MockConnection) -> serde_json::Value {
    let sent = connection.sent();
    assert_eq!(sent.len(), 1, "expected exactly one message: {sent:?}");
    match &sent[0] {
        Frame::Text(body) => serde_json::from_str(body).expect("a JSON message"),
        other => panic!("expected a text frame, got {other:?}"),
    }
}

// --- the documented event set --------------------------------------------

#[test]
fn every_documented_event_arrives_over_the_socket_with_its_typed_payload() {
    let cases = [
        (WEBSOCKET_MESSAGE, "user_speak"),
        (SESSION_START, "session_start"),
        (SESSION_START_TRANSFER_FAILED, "session_start"),
        (USER_SPEECH_STARTED, "user_speech_started"),
        (USER_SPEAK, "user_speak"),
        (USER_SPEAK_BARGED_IN, "user_speak"),
        (USER_BARGE_IN, "user_barge_in"),
        (DTMF_RECEIVED, "dtmf_received"),
        (ASSISTANT_SPEAK, "assistant_speak"),
        (ASSISTANT_SPEECH_ENDED, "assistant_speech_ended"),
        (USER_INPUT_TIMEOUT, "user_input_timeout"),
        (SESSION_END, "session_end"),
        (SMS_FAILED, "sms_failed"),
        (ERROR_EVENT, "error"),
        (UNKNOWN_EVENT, "call_transferred"),
    ];
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    for (body, kind) in cases {
        let (driver, _probe) = socket([Frame::text(body)]);
        let event = runtime
            .block_on(driver.next_event())
            .unwrap_or_else(|error| panic!("{kind} must arrive over the socket: {error}"))
            .unwrap_or_else(|| panic!("{kind} must not end the link"));
        assert_eq!(event.kind(), kind, "for {body}");
        assert_eq!(
            event.to_json()["type"],
            serde_json::json!(kind),
            "the payload keeps its own type field for {body}"
        );
    }
}

#[test]
fn the_documented_websocket_example_is_the_fixture() {
    let (driver, _probe) = socket([Frame::text(WEBSOCKET_MESSAGE)]);
    let event = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime")
        .block_on(driver.next_event())
        .expect("valid")
        .expect("one event");
    assert!(matches!(
        event.payload(),
        EventPayload::UserSpeak { text, barged_in: false, .. } if text == "Hello"
    ));
    assert_eq!(
        event.session_id(),
        Some("550e8400-e29b-41d4-a716-446655440000")
    );
}

#[test]
fn a_binary_frame_carries_the_same_event_as_a_text_frame() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (from_text, _t) = socket([Frame::text(USER_SPEAK)]);
    let (from_bytes, _b) = socket([Frame::Binary(USER_SPEAK.as_bytes().to_vec())]);

    let text = runtime.block_on(from_text.next_event()).expect("valid");
    let bytes = runtime.block_on(from_bytes.next_event()).expect("valid");
    assert_eq!(text, bytes, "the transport must not change the event");
    assert!(text.is_some(), "a binary frame is not the end of the link");
}

#[test]
fn a_ping_is_answered_before_the_event_and_a_pong_is_ignored() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (driver, probe) = socket([
        Frame::Pong(b"stale".to_vec()),
        Frame::Ping(b"keep-alive".to_vec()),
        Frame::text(USER_SPEAK),
    ]);

    let event = runtime
        .block_on(driver.next_event())
        .expect("valid")
        .expect("the event after the control frames");
    assert_eq!(event.kind(), "user_speak");
    assert_eq!(
        probe.sent(),
        vec![Frame::Pong(b"keep-alive".to_vec())],
        "one pong echoes the ping, the pong is not echoed"
    );
}

#[test]
fn a_close_frame_and_an_empty_script_both_end_the_link() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");

    let (closed, closed_probe) = socket([Frame::Close]);
    assert_eq!(
        runtime.block_on(closed.next_event()).expect("no error"),
        None,
        "a close frame ends the link"
    );
    assert!(closed_probe.sent().is_empty(), "a close is not answered");

    let (exhausted, _) = socket([]);
    assert_eq!(
        runtime.block_on(exhausted.next_event()).expect("no error"),
        None,
        "an empty script is a closed connection"
    );
}

#[test]
fn an_empty_text_frame_is_an_empty_body_not_a_silent_skip() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (driver, _) = socket([Frame::text("   ")]);
    let error = runtime
        .block_on(driver.next_event())
        .expect_err("whitespace carries no event");
    assert!(matches!(error, Error::EmptyBody), "{error:?}");
}

// --- inbound ceiling: every boundary -------------------------------------

#[test]
fn an_inbound_frame_at_the_configured_ceiling_parses() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let body = USER_SPEAK.as_bytes();
    let limit = body.len();
    let driver = FlowSocket::new(MockConnection::new([Frame::text(USER_SPEAK)]))
        .with_max_message_bytes(limit)
        .expect("1..=MAX");

    assert_eq!(
        driver.max_message_bytes(),
        limit,
        "the configured limit is reported back"
    );
    let event = runtime
        .block_on(driver.next_event())
        .expect("exactly at the limit must parse")
        .expect("one event");
    assert_eq!(event.kind(), "user_speak");
}

#[test]
fn an_inbound_frame_one_byte_over_the_configured_ceiling_is_refused() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let body = USER_SPEAK.as_bytes();
    let limit = body.len() - 1;
    let driver = FlowSocket::new(MockConnection::new([Frame::text(USER_SPEAK)]))
        .with_max_message_bytes(limit)
        .expect("1..=MAX");

    let error = runtime
        .block_on(driver.next_event())
        .expect_err("one byte over must fail");
    assert!(
        matches!(
            error,
            Error::BodyTooLarge { size, limit: reported }
                if size == body.len() && reported == limit
        ),
        "{error:?}"
    );
}

#[test]
fn the_size_check_runs_before_the_json_parser() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    // Five spaces are below no limit that could matter; the point is that an
    // oversized *empty* payload is reported as oversized, not as `EmptyBody`.
    let driver = FlowSocket::new(MockConnection::new([Frame::text("     ")]))
        .with_max_message_bytes(4)
        .expect("1..=MAX");
    let error = runtime
        .block_on(driver.next_event())
        .expect_err("five bytes exceed four");
    assert!(
        matches!(error, Error::BodyTooLarge { size: 5, limit: 4 }),
        "the ceiling is applied before parsing: {error:?}"
    );
}

#[test]
fn the_default_ceiling_is_the_parser_ceiling_on_both_sides() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    assert_eq!(MAX_SOCKET_MESSAGE_BYTES, sipgate_flow::MAX_EVENT_BODY_BYTES);

    // A valid event padded to exactly the ceiling, then one byte past it.
    let prefix = br#"{"type":"user_speak","text":""#;
    let suffix = br#"","session":{"id":"s1"}}"#;
    let mut body = prefix.to_vec();
    body.extend(std::iter::repeat_n(
        b'a',
        MAX_SOCKET_MESSAGE_BYTES - prefix.len() - suffix.len(),
    ));
    body.extend_from_slice(suffix);
    assert_eq!(body.len(), MAX_SOCKET_MESSAGE_BYTES);

    let at_limit = String::from_utf8(body).expect("ASCII");
    let (driver, _) = socket([Frame::text(&at_limit)]);
    let event = runtime
        .block_on(driver.next_event())
        .expect("exactly MAX must parse")
        .expect("one event");
    assert_eq!(event.kind(), "user_speak");

    let mut over = at_limit.clone();
    over.push(' ');
    let (driver, _) = socket([Frame::text(&over)]);
    let error = runtime
        .block_on(driver.next_event())
        .expect_err("MAX + 1 must be refused");
    assert!(
        matches!(
            error,
            Error::BodyTooLarge { size, limit }
                if size == MAX_SOCKET_MESSAGE_BYTES + 1 && limit == MAX_SOCKET_MESSAGE_BYTES
        ),
        "{error:?}"
    );
}

#[test]
fn the_configured_ceiling_accepts_its_whole_range_and_nothing_outside_it() {
    let one = FlowSocket::new(MockConnection::default())
        .with_max_message_bytes(1)
        .expect("one byte is the smallest usable ceiling");
    assert_eq!(one.max_message_bytes(), 1);

    let widest = FlowSocket::new(MockConnection::default())
        .with_max_message_bytes(MAX_SOCKET_MESSAGE_BYTES)
        .expect("the parser ceiling is the widest accepted");
    assert_eq!(widest.max_message_bytes(), MAX_SOCKET_MESSAGE_BYTES);

    for rejected in [0, MAX_SOCKET_MESSAGE_BYTES + 1] {
        let error = FlowSocket::new(MockConnection::default())
            .with_max_message_bytes(rejected)
            .expect_err("outside 1..=MAX");
        assert!(
            matches!(
                error,
                Error::Validation {
                    field: "max_message_bytes",
                    ..
                }
            ),
            "{rejected} must be refused with a validation error: {error:?}"
        );
    }
}

// --- outbound actions -----------------------------------------------------

#[test]
fn one_action_is_one_json_object_mirroring_the_webhook_body() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (driver, probe) = socket([]);
    let event = Event::parse(br#"{"type":"user_speak","text":"Hallo","session":{"id":"s1"}}"#)
        .expect("valid");
    let response = FlowResponse::one(Action::speak("s1", "Hallo!").expect("valid"));

    let sent = runtime
        .block_on(driver.send_response(&event, &response))
        .expect("writable");
    assert_eq!(sent, 1);
    assert_eq!(
        only_sent_json(&probe),
        serde_json::json!({"type": "speak", "session_id": "s1", "text": "Hallo!"})
    );
    assert_eq!(
        response.body().expect("a body"),
        match &probe.sent()[0] {
            Frame::Text(body) => body.clone(),
            other => panic!("expected text, got {other:?}"),
        },
        "the socket frame and the webhook body are the same bytes"
    );
}

#[test]
fn several_actions_travel_as_one_ordered_array() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (driver, probe) = socket([]);
    let event = Event::parse(
        "{\"type\":\"user_speak\",\"text\":\"Tschüss\",\"session\":{\"id\":\"s1\"}}".as_bytes(),
    )
    .expect("valid");
    let response = FlowResponse::many([
        Action::speak("s1", "Auf Wiederhören").expect("valid"),
        Action::hangup("s1").expect("valid"),
    ]);

    let sent = runtime
        .block_on(driver.send_response(&event, &response))
        .expect("writable");
    assert_eq!(sent, 2);
    assert_eq!(
        only_sent_json(&probe),
        serde_json::json!([
            {"type": "speak", "session_id": "s1", "text": "Auf Wiederhören"},
            {"type": "hangup", "session_id": "s1"},
        ])
    );
}

#[test]
fn no_action_means_silence() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (driver, probe) = socket([]);
    let event =
        Event::parse(br#"{"type":"user_speak","text":"Hm","session":{"id":"s1"}}"#).expect("valid");

    let sent = runtime
        .block_on(driver.send_response(&event, &FlowResponse::none()))
        .expect("nothing to do is not an error");
    assert_eq!(sent, 0);
    assert!(probe.sent().is_empty(), "no action, no frame");
}

#[test]
fn an_event_without_an_action_contract_refuses_one() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (driver, probe) = socket([]);
    let action = FlowResponse::one(Action::speak("s1", "Tschüss").expect("valid"));

    for body in [SESSION_END, USER_SPEECH_STARTED, SMS_FAILED, UNKNOWN_EVENT] {
        let event = Event::parse(body.as_bytes()).expect("valid");
        assert!(!event.accepts_actions(), "{body} accepts no action");
        let error = runtime
            .block_on(driver.send_response(&event, &action))
            .expect_err("an action must be refused");
        assert!(
            matches!(error, Error::ActionNotAccepted { ref kind } if kind == event.kind()),
            "{error:?}"
        );

        // The same event with no action is fine: answering nothing is legal.
        let sent = runtime
            .block_on(driver.send_response(&event, &FlowResponse::none()))
            .expect("silence is allowed");
        assert_eq!(sent, 0);
    }
    assert!(
        probe.sent().is_empty(),
        "a refused action never reaches the wire"
    );
}

#[test]
fn a_proactive_action_is_sent_without_waiting_for_an_event() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (driver, probe) = socket([]);

    runtime
        .block_on(driver.send_action(&Action::hangup("s1").expect("valid")))
        .expect("writable");
    assert_eq!(
        only_sent_json(&probe),
        serde_json::json!({"type": "hangup", "session_id": "s1"}),
        "the unsolicited message is the same flat action object"
    );
}

#[test]
fn frames_report_their_payload_size_for_every_variant() {
    assert_eq!(Frame::text("{}").byte_len(), 2);
    assert_eq!(Frame::Binary(vec![0, 1]).byte_len(), 2);
    assert_eq!(Frame::Ping(vec![7]).byte_len(), 1);
    assert_eq!(Frame::Pong(vec![7, 8, 9]).byte_len(), 3);
    assert_eq!(Frame::Close.byte_len(), 0);
}

#[test]
fn a_frame_pushed_after_construction_is_delivered_in_order() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let connection = MockConnection::default();
    let driver = FlowSocket::new(connection.clone());
    assert!(driver.connection().sent().is_empty(), "nothing sent yet");

    connection.push(Frame::text(USER_SPEAK));
    let first = runtime
        .block_on(driver.next_event())
        .expect("valid")
        .expect("the pushed frame");
    assert_eq!(first.kind(), "user_speak");

    assert_eq!(
        runtime.block_on(driver.next_event()).expect("valid"),
        None,
        "an exhausted script is a closed connection"
    );
}

#[test]
fn a_many_response_with_no_actions_is_silence_like_an_empty_array() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (driver, probe) = socket([]);
    let event = Event::parse(USER_SPEAK.as_bytes()).expect("valid");
    let empty = FlowResponse::Many(Vec::new());

    assert_eq!(
        runtime
            .block_on(driver.send_response(&event, &empty))
            .expect("nothing to write"),
        0
    );
    assert!(probe.sent().is_empty(), "an empty array is not a message");
}

#[test]
fn a_terminal_socket_error_is_not_retryable() {
    let error = Error::socket_terminal("frame opcode this adapter cannot handle");
    assert!(!error.is_retryable(), "{error:?}");
    assert!(!error.is_ambiguous(), "{error:?}");
    assert_eq!(
        error.to_string(),
        "websocket error: frame opcode this adapter cannot handle"
    );
}

// --- the per-connection loop ---------------------------------------------

#[test]
fn run_answers_every_event_that_wants_an_answer_and_counts_the_rest() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (driver, probe) = socket([
        Frame::Ping(b"hb".to_vec()),
        Frame::text(USER_SPEAK),
        Frame::text(SESSION_END),
        Frame::Close,
    ]);

    let handled = runtime
        .block_on(driver.run(|event| async move {
            let Some(session) = event.session_id() else {
                return Ok(FlowResponse::none());
            };
            match event.payload() {
                EventPayload::UserSpeak { text, .. } => {
                    Ok(FlowResponse::one(Action::speak(session, text.clone())?))
                }
                _ => Ok(FlowResponse::none()),
            }
        }))
        .expect("the loop finishes cleanly");

    assert_eq!(handled, 2, "the session_end is handled too, with no answer");
    let sent = probe.sent();
    assert_eq!(
        sent.first(),
        Some(&Frame::Pong(b"hb".to_vec())),
        "the ping was answered first"
    );
    let replies: Vec<serde_json::Value> = sent
        .into_iter()
        .filter_map(|frame| match frame {
            Frame::Text(body) => serde_json::from_str(&body).ok(),
            _ => None,
        })
        .collect();
    assert_eq!(
        replies,
        vec![serde_json::json!({
            "type": "speak",
            "session_id": "550e8400-e29b-41d4-a716-446655440000",
            "text": "Hello, I need help",
        })]
    );
}

#[test]
fn run_returns_the_handler_error_and_leaves_the_remaining_frames_unread() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (driver, probe) = socket([Frame::text(USER_SPEAK), Frame::text(DTMF_RECEIVED)]);

    let error = runtime
        .block_on(
            driver
                .run(|_event| async move { Err(Error::validation("text", "the handler said no")) }),
        )
        .expect_err("the handler error ends the loop");
    assert!(matches!(error, Error::Validation { .. }), "{error:?}");
    assert!(probe.sent().is_empty(), "nothing was answered");

    // The unread frame is still there: a caller may retry with another handler.
    let second = runtime
        .block_on(driver.run(|_event| async move { Ok(FlowResponse::none()) }))
        .expect("the loop resumes where it stopped");
    assert_eq!(second, 1, "only the DTMF frame was still on the wire");
}

#[test]
fn run_stops_at_the_first_parse_failure() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");
    let (driver, _probe) = socket([Frame::text("not json"), Frame::text(USER_SPEAK)]);

    let error = runtime
        .block_on(driver.run(|_event| async move { Ok(FlowResponse::none()) }))
        .expect_err("the payload cannot be parsed");
    assert!(matches!(error, Error::Json { .. }), "{error:?}");
}

#[test]
fn a_connection_error_is_reported_as_a_socket_error() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a test runtime");

    let read_failure = FlowSocket::new(Failing::new(false));
    let error = runtime
        .block_on(read_failure.next_event())
        .expect_err("recv fails");
    assert!(
        matches!(
            error,
            Error::Socket {
                retryable: true,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(
        error.is_retryable(),
        "a dead link is worth a new connection"
    );
    assert!(
        !error.is_ambiguous(),
        "a lost frame is not an ambiguous write"
    );
    assert!(
        std::error::Error::source(&error).is_some(),
        "the adapter's cause stays reachable"
    );

    let write_failure = FlowSocket::new(Failing::new(true));
    let event = Event::parse(USER_SPEAK.as_bytes()).expect("valid");
    let response = FlowResponse::one(Action::barge_in("s1").expect("valid"));
    let error = runtime
        .block_on(write_failure.send_response(&event, &response))
        .expect_err("send fails");
    assert!(
        matches!(
            error,
            Error::Socket {
                retryable: true,
                ..
            }
        ),
        "{error:?}"
    );
}

/// A connection whose reads always fail and whose writes always fail, with the
/// cause attached - the two shapes an adapter reports.
struct Failing {
    read_ok: bool,
}

impl Failing {
    fn new(read_ok: bool) -> Self {
        Self { read_ok }
    }
}

impl Connection for Failing {
    async fn recv(&self) -> Result<Option<Frame>> {
        if self.read_ok {
            return Ok(Some(Frame::text(USER_SPEAK)));
        }
        Err(Error::socket_with_source(
            "recv: connection reset",
            true,
            std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset"),
        ))
    }

    async fn send(&self, _frame: Frame) -> Result<()> {
        Err(Error::socket("send: broken pipe"))
    }
}

// --- reconnect pacing -----------------------------------------------------

#[test]
fn accept_backoff_stays_inside_the_window_and_never_gives_up() {
    let policy = RetryPolicy::new(4)
        .with_base_delay(Duration::from_millis(200))
        .with_max_delay(Duration::from_secs(1));
    let backoff = AcceptBackoff::new(policy);
    assert_eq!(backoff.policy().max_attempts, 4);

    // Inside the budget: equal jitter inside [d/2, d], capped by the ceiling.
    for failures in 1..4 {
        let delay = backoff.delay(failures);
        assert!(delay >= MIN_RETRY_DELAY, "{failures}: {delay:?}");
        assert!(delay <= Duration::from_secs(1), "{failures}: {delay:?}");
    }
    let first = backoff.delay(1);
    assert!(
        first >= Duration::from_millis(100) && first <= Duration::from_millis(200),
        "the first step is the base delay, jittered: {first:?}"
    );

    // At and past the budget: the ceiling, forever - an endpoint that stopped
    // accepting would silently stop answering calls.
    assert_eq!(backoff.delay(4), Duration::from_secs(1));
    assert_eq!(backoff.delay(u32::MAX), Duration::from_secs(1));
}

#[test]
fn accept_backoff_never_returns_zero_even_for_an_impossible_policy() {
    // Fields are public, so a caller can defeat the builders' clamping.
    let mut policy = RetryPolicy::new(2);
    policy.base_delay = Duration::ZERO;
    policy.max_delay = Duration::ZERO;
    let backoff = AcceptBackoff::new(policy);
    assert_eq!(backoff.delay(1), MIN_RETRY_DELAY);
    assert_eq!(backoff.delay(2), MIN_RETRY_DELAY);
}

#[test]
fn accept_backoff_has_a_default_and_zero_failures_behaves_like_the_first() {
    let default = AcceptBackoff::default();
    assert_eq!(default.policy().base_delay, Duration::from_secs(1));
    assert!(default.delay(0) <= Duration::from_secs(1));
    assert!(default.delay(0) >= Duration::from_millis(500));
}

// --- thread safety --------------------------------------------------------

#[test]
fn one_socket_answers_from_many_tasks() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a test runtime");
    let connection = MockConnection::default();
    let driver = Arc::new(FlowSocket::new(connection.clone()));

    runtime.block_on(async {
        let mut tasks = Vec::new();
        for index in 0..32_u32 {
            let driver = Arc::clone(&driver);
            tasks.push(tokio::spawn(async move {
                let event =
                    Event::parse(br#"{"type":"user_speak","text":"Hallo","session":{"id":"s1"}}"#)
                        .expect("valid");
                let response = FlowResponse::one(
                    Action::speak("s1", format!("Antwort {index}")).expect("valid"),
                );
                driver.send_response(&event, &response).await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.expect("task joins").expect("writable"), 1);
        }
    });

    assert_eq!(connection.sent().len(), 32, "every answer reached the wire");
}

// --- properties -----------------------------------------------------------

proptest! {
    /// No text frame may panic the driver, whatever Flow (or an attacker)
    /// writes into it; whatever parses must re-render and re-parse unchanged.
    #[test]
    fn arbitrary_frames_never_panic_and_stay_stable(body in any::<String>()) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a test runtime");
        let (driver, _probe) = socket([Frame::text(&body), Frame::Close]);
        match runtime.block_on(driver.next_event()) {
            Ok(Some(event)) => {
                let rerendered = serde_json::to_vec(&event.to_json()).expect("JSON");
                let reparsed = Event::parse(&rerendered).expect("re-parses");
                prop_assert_eq!(reparsed.kind(), event.kind());
                prop_assert_eq!(reparsed.to_json(), event.to_json());
            }
            Ok(None) => prop_assert!(body.is_empty(), "{body:?} may not silently end the link"),
            Err(_) => {}
        }
    }

    /// Arbitrary bytes in a binary frame follow the same rule.
    #[test]
    fn arbitrary_binary_frames_never_panic(bytes in any::<Vec<u8>>()) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a test runtime");
        let (driver, _probe) = socket([Frame::Binary(bytes)]);
        let _ = runtime.block_on(driver.next_event());
    }

    /// Accept pacing stays bounded and non-zero for every failure count.
    #[test]
    fn accept_backoff_is_always_bounded(failures in any::<u32>(), attempts in 1_u32..64) {
        let policy = RetryPolicy::new(attempts)
            .with_base_delay(Duration::from_millis(50))
            .with_max_delay(Duration::from_secs(2));
        let backoff = AcceptBackoff::new(policy);
        let delay = backoff.delay(failures);
        prop_assert!(delay >= MIN_RETRY_DELAY, "{delay:?}");
        prop_assert!(delay <= Duration::from_secs(2), "{delay:?}");
    }
}
