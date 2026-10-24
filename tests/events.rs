//! The documented event corpus, plus the boundaries on both sides of "valid".
//!
//! Every fixture under `tests/fixtures/flow/` is a payload copied from
//! <https://flow.sipgate.io/api/events> (see `docs/contracts.md` for the
//! per-shape citation), so these tests fail if the model drifts from the
//! published wire format.

use sipgate_flow::{
    Action, Direction, Error, ErrorCode, Event, EventPayload, Severity, SmsFailureReason,
    TransferFailedReason,
};

const SESSION_START: &str = include_str!("fixtures/flow/session_start.json");
const SESSION_START_TRANSFER_FAILED: &str =
    include_str!("fixtures/flow/session_start_transfer_failed.json");
const USER_SPEECH_STARTED: &str = include_str!("fixtures/flow/user_speech_started.json");
const USER_SPEAK: &str = include_str!("fixtures/flow/user_speak.json");
const USER_SPEAK_BARGED_IN: &str = include_str!("fixtures/flow/user_speak_barged_in.json");
const DTMF_RECEIVED: &str = include_str!("fixtures/flow/dtmf_received.json");
const ASSISTANT_SPEAK: &str = include_str!("fixtures/flow/assistant_speak.json");
const ASSISTANT_SPEECH_ENDED: &str = include_str!("fixtures/flow/assistant_speech_ended.json");
const USER_INPUT_TIMEOUT: &str = include_str!("fixtures/flow/user_input_timeout.json");
const SESSION_END: &str = include_str!("fixtures/flow/session_end.json");
const SMS_FAILED: &str = include_str!("fixtures/flow/sms_failed.json");
const ERROR_EVENT: &str = include_str!("fixtures/flow/error.json");
const USER_BARGE_IN: &str = include_str!("fixtures/flow/user_barge_in.json");
const UNKNOWN_EVENT: &str = include_str!("fixtures/flow/unknown_event.json");

fn parse(body: &str) -> Event {
    Event::parse(body.as_bytes()).unwrap_or_else(|error| panic!("{body} should parse: {error}"))
}

#[test]
fn every_documented_event_parses_to_its_typed_payload() {
    let cases = [
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
    ];
    for (body, kind) in cases {
        let event = parse(body);
        assert_eq!(event.kind(), kind, "for {body}");
        assert!(!event.is_unknown(), "{kind} must be modelled");
        assert_eq!(event.payload().known_kind(), Some(kind));
    }
}

#[test]
fn session_fields_are_typed() {
    let event = parse(SESSION_START);
    let session = event.session().expect("session");
    assert_eq!(session.id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(session.account_id.as_deref(), Some("account-123"));
    assert_eq!(session.direction, Some(Direction::Inbound));
    assert_eq!(session.from_phone_number.as_deref(), Some("9876543210"));
    assert_eq!(session.to_phone_number.as_deref(), Some("1234567890"));
    assert_eq!(event.session_id(), Some(session.id.as_str()));
}

#[test]
fn a_failed_transfer_carries_its_reason() {
    let event = parse(SESSION_START_TRANSFER_FAILED);
    let EventPayload::SessionStart {
        transfer_failed_reason,
    } = event.payload()
    else {
        panic!("expected session_start, got {:?}", event.payload());
    };
    assert_eq!(transfer_failed_reason, &Some(TransferFailedReason::Busy));
    assert!(transfer_failed_reason
        .as_ref()
        .is_some_and(TransferFailedReason::is_worth_retrying));

    let fresh = parse(SESSION_START);
    let EventPayload::SessionStart {
        transfer_failed_reason,
    } = fresh.payload()
    else {
        panic!("expected session_start");
    };
    assert!(transfer_failed_reason.is_none(), "a new call has no reason");
}

#[test]
fn user_speak_reports_barge_in_and_defaults_it_to_false() {
    let plain = parse(USER_SPEAK);
    assert!(matches!(
        plain.payload(),
        EventPayload::UserSpeak { text, barged_in: false, .. } if text == "Hello, I need help"
    ));

    let interrupted = parse(USER_SPEAK_BARGED_IN);
    assert!(matches!(
        interrupted.payload(),
        EventPayload::UserSpeak {
            barged_in: true,
            ..
        }
    ));

    // `barged_in` is optional; omitting it means "not an interruption".
    let minimal = parse(r#"{"type":"user_speak","text":"Hallo","session":{"id":"s"}}"#);
    assert!(matches!(
        minimal.payload(),
        EventPayload::UserSpeak {
            barged_in: false,
            ..
        }
    ));
}

#[test]
fn assistant_speak_keeps_the_optional_metadata() {
    let event = parse(ASSISTANT_SPEAK);
    let EventPayload::AssistantSpeak {
        text,
        ssml,
        duration_ms,
        speech_started_at,
    } = event.payload()
    else {
        panic!("expected assistant_speak");
    };
    assert_eq!(text.as_deref(), Some("Hello! How can I help you?"));
    assert!(ssml
        .as_deref()
        .is_some_and(|ssml| ssml.starts_with("<speak")));
    assert_eq!(*duration_ms, Some(2000));
    assert_eq!(*speech_started_at, Some(1_234_567_890));

    let bare = parse(r#"{"type":"assistant_speak","session":{"id":"s"}}"#);
    assert!(matches!(
        bare.payload(),
        EventPayload::AssistantSpeak {
            text: None,
            ssml: None,
            duration_ms: None,
            speech_started_at: None
        }
    ));
}

#[test]
fn dtmf_digit_is_a_string_not_a_number() {
    let event = parse(DTMF_RECEIVED);
    assert!(matches!(event.payload(), EventPayload::DtmfReceived { digit } if digit == "1"));
}

#[test]
fn sms_failure_reasons_round_trip_and_unknown_ones_survive() {
    let event = parse(SMS_FAILED);
    let EventPayload::SmsFailed {
        recipient,
        reason,
        message,
    } = event.payload()
    else {
        panic!("expected sms_failed");
    };
    assert_eq!(recipient, "4915112345678");
    assert_eq!(reason, &SmsFailureReason::SenderNotAllowed);
    assert_eq!(message.as_deref(), Some("SMSC returned faultCode 403"));

    let unknown = parse(
        r#"{"type":"sms_failed","recipient":"49","reason":"carrier_pigeon","session":{"id":"s"}}"#,
    );
    assert!(matches!(
        unknown.payload(),
        EventPayload::SmsFailed { reason: SmsFailureReason::Other(reason), .. } if reason == "carrier_pigeon"
    ));
}

#[test]
fn error_events_branch_on_code_and_severity() {
    let event = parse(ERROR_EVENT);
    let EventPayload::Error {
        code,
        severity,
        message,
        action_type,
    } = event.payload()
    else {
        panic!("expected error");
    };
    assert_eq!(code, &ErrorCode::SynthesisUnavailable);
    assert_eq!(severity, &Severity::Error);
    assert!(!severity.call_continues());
    assert!(message.starts_with("Speech synthesis failed"));
    assert_eq!(action_type.as_deref(), Some("speak"));

    let warning = parse(
        r#"{"type":"error","code":"transcription_unavailable","severity":"warning","message":"m","session":{"id":"s"}}"#,
    );
    assert!(matches!(
        warning.payload(),
        EventPayload::Error {
            severity: Severity::Warning,
            ..
        }
    ));

    let future = parse(
        r#"{"type":"error","code":"quantum_flux","severity":"notice","message":"m","session":{"id":"s"}}"#,
    );
    let EventPayload::Error { code, severity, .. } = future.payload() else {
        panic!("expected error");
    };
    assert_eq!(code, &ErrorCode::Other("quantum_flux".into()));
    assert_eq!(severity, &Severity::Other("notice".into()));
    assert!(severity.call_continues(), "unknown severity is not fatal");
}

#[test]
fn unknown_events_keep_their_whole_payload() {
    let event = parse(UNKNOWN_EVENT);
    assert!(event.is_unknown());
    assert_eq!(
        event.session_id(),
        Some("550e8400-e29b-41d4-a716-446655440000")
    );
    let EventPayload::Unknown(raw) = event.payload() else {
        panic!("expected unknown");
    };
    assert_eq!(raw["type"], "call_transferred");
    assert_eq!(raw["detail"]["to"], "4915112345678");
    // Round-tripping an unknown event returns the original document.
    assert_eq!(event.to_json(), *raw);
}

#[test]
fn unknown_fields_on_known_events_are_preserved() {
    let event = parse(
        r#"{"type":"user_speak","text":"hi","session":{"id":"s","region":"eu"},"confidence":0.97}"#,
    );
    assert_eq!(event.extra()["confidence"], 0.97);
    assert_eq!(event.session().unwrap().extra["region"], "eu");
    let rendered = event.to_json();
    assert_eq!(rendered["confidence"], 0.97);
    assert_eq!(rendered["session"]["region"], "eu");
}

#[test]
fn camel_case_and_snake_case_are_both_accepted() {
    let event = parse(
        r#"{"type":"session_start","session":{"id":"s","accountId":"a1","phoneNumber":"1","fromPhoneNumber":"2","toPhoneNumber":"3"}}"#,
    );
    let session = event.session().unwrap();
    assert_eq!(session.account_id.as_deref(), Some("a1"));
    assert_eq!(session.phone_number.as_deref(), Some("1"));
    assert_eq!(session.from_phone_number.as_deref(), Some("2"));
    assert_eq!(session.to_phone_number.as_deref(), Some("3"));
}

#[test]
fn a_top_level_call_id_fills_a_missing_session_id() {
    // The 0.1 release accepted this shape, and the Push API uses the same name,
    // so it stays accepted without ever overriding a real session id.
    let event = parse(r#"{"type":"session_end","callId":"legacy-1"}"#);
    assert_eq!(event.session_id(), Some("legacy-1"));

    let both = parse(r#"{"type":"session_end","callId":"legacy","session":{"id":"real"}}"#);
    assert_eq!(both.session_id(), Some("real"));
}

#[test]
fn a_missing_or_empty_session_id_parses_but_cannot_be_addressed() {
    for body in [
        r#"{"type":"session_end"}"#,
        r#"{"type":"session_end","session":{}}"#,
        r#"{"type":"session_end","session":{"id":""}}"#,
    ] {
        let event = parse(body);
        assert_eq!(event.kind(), "session_end");
        assert_eq!(event.session_id(), None, "for {body}");
        // Tolerant parse, strict send: the builder refuses the empty id.
        assert!(Action::hangup(event.session_id().unwrap_or_default()).is_err());
    }
}

#[test]
fn an_event_without_a_type_is_unknown() {
    let event = parse(r#"{"session":{"id":"s"}}"#);
    assert_eq!(event.kind(), "");
    assert!(event.is_unknown());
}

#[test]
fn empty_and_whitespace_bodies_are_rejected() {
    for body in [&b""[..], b"   ", b"\n\t\r\n"] {
        assert!(matches!(Event::parse(body), Err(Error::EmptyBody)));
    }
}

#[test]
fn non_object_json_is_a_typed_error_not_a_panic() {
    for body in ["[]", "\"text\"", "5", "null", "true"] {
        let error = Event::parse(body.as_bytes()).expect_err(body);
        assert!(
            matches!(error, Error::Json { .. }),
            "{body} produced {error:?}"
        );
    }
}

#[test]
fn truncated_and_malformed_json_report_a_position() {
    let error = Event::parse(br#"{"type":"user_speak","text":"#).expect_err("truncated");
    match error {
        Error::Json { source } => {
            assert!(source.line() >= 1);
            assert!(source.column() >= 1);
        }
        other => panic!("expected a JSON error, got {other:?}"),
    }
}

#[test]
fn a_wrongly_typed_known_field_is_rejected() {
    let error = Event::parse(br#"{"type":"user_speak","text":42,"session":{"id":"s"}}"#)
        .expect_err("number where a string is documented");
    assert!(matches!(error, Error::Json { .. }));
    let error = Event::parse(br#"{"type":"user_speak","text":"hi","barged_in":"yes"}"#)
        .expect_err("string where a bool is documented");
    assert!(matches!(error, Error::Json { .. }));
}

#[test]
fn duplicate_known_keys_are_rejected_rather_than_guessed() {
    let error =
        Event::parse(br#"{"type":"session_end","type":"session_start","session":{"id":"s"}}"#)
            .expect_err("duplicate `type`");
    assert!(matches!(error, Error::Json { .. }), "{error:?}");
}

#[test]
fn duplicate_unknown_keys_do_not_block_the_event() {
    let event = parse(r#"{"type":"session_end","x":1,"x":2,"session":{"id":"s"}}"#);
    assert_eq!(event.kind(), "session_end");
    // serde_json keeps the last value for a duplicated unknown key.
    assert_eq!(event.extra()["x"], 2);
}

#[test]
fn unicode_nul_and_long_text_survive() {
    let event = parse(
        "{\"type\":\"user_speak\",\"text\":\"Grüße 🎉 \\u0000 Ende\",\"session\":{\"id\":\"s\"}}",
    );
    let EventPayload::UserSpeak { text, .. } = event.payload() else {
        panic!("expected user_speak");
    };
    assert!(text.contains("Grüße"));
    assert!(text.contains('🎉'));
    assert!(text.contains('\u{0}'));

    let long = "x".repeat(1024 * 1024);
    let body = format!(r#"{{"type":"user_speak","text":"{long}","session":{{"id":"s"}}}}"#);
    let event = parse(&body);
    assert!(
        matches!(event.payload(), EventPayload::UserSpeak { text, .. } if text.len() == 1024 * 1024)
    );
}

#[test]
fn field_order_does_not_matter() {
    let a = parse(r#"{"type":"dtmf_received","digit":"2","session":{"id":"s"}}"#);
    let b = parse(r#"{"session":{"id":"s"},"digit":"2","type":"dtmf_received"}"#);
    assert_eq!(a, b);
}

#[test]
fn every_documented_event_round_trips_through_json() {
    for body in [
        SESSION_START,
        SESSION_START_TRANSFER_FAILED,
        USER_SPEECH_STARTED,
        USER_SPEAK,
        USER_SPEAK_BARGED_IN,
        DTMF_RECEIVED,
        ASSISTANT_SPEAK,
        ASSISTANT_SPEECH_ENDED,
        USER_INPUT_TIMEOUT,
        SESSION_END,
        SMS_FAILED,
        ERROR_EVENT,
        UNKNOWN_EVENT,
    ] {
        let event = parse(body);
        let rendered = serde_json::to_vec(&event.to_json()).expect("render");
        let again = Event::parse(&rendered)
            .unwrap_or_else(|error| panic!("re-parsing {rendered:?} failed: {error}"));
        assert_eq!(event, again, "for {body}");
    }
}

#[test]
fn only_events_that_accept_actions_report_so() {
    let expected = [
        (SESSION_START, true),
        (USER_SPEECH_STARTED, false),
        (USER_SPEAK, true),
        (DTMF_RECEIVED, true),
        (ASSISTANT_SPEAK, true),
        (ASSISTANT_SPEECH_ENDED, true),
        (USER_INPUT_TIMEOUT, true),
        (SESSION_END, false),
        (SMS_FAILED, false),
        (ERROR_EVENT, true),
        (UNKNOWN_EVENT, false),
    ];
    for (body, accepts) in expected {
        assert_eq!(parse(body).accepts_actions(), accepts, "for {body}");
    }
}

#[test]
fn user_barge_in_carries_the_interrupting_text() {
    let event = parse(USER_BARGE_IN);
    assert_eq!(event.kind(), "user_barge_in");
    assert_eq!(
        event.session_id(),
        Some("550e8400-e29b-41d4-a716-446655440000")
    );
    match event.payload() {
        EventPayload::UserBargeIn { text } => assert_eq!(text, "Moment, bitte"),
        other => panic!("expected a user_barge_in payload, got {other:?}"),
    }
    // The documentation's response table does not cover this event, so the
    // conservative answer stays 204 - and the handler may still override it.
    assert!(!event.accepts_actions());
    assert_eq!(
        event.to_json(),
        serde_json::from_str::<serde_json::Value>(USER_BARGE_IN).expect("fixture")
    );
}

#[test]
fn user_barge_in_without_text_still_parses() {
    let event = parse(r#"{"type":"user_barge_in","session":{"id":"s1"}}"#);
    assert_eq!(event.kind(), "user_barge_in");
    assert_eq!(event.session_id(), Some("s1"));
    assert!(matches!(event.payload(), EventPayload::UserBargeIn { text } if text.is_empty()));
}
