//! The classic Push API contract, end to end: form bytes in, XML out.
//!
//! Every fixture is a body the reference documents (see
//! `docs/contracts.md` §11 and §10). The tests play the part of the HTTP
//! framework — they hand the verifier the header and body bytes a request
//! would carry and read the status, `Content-Type` and document the handler
//! would answer with — so no test here opens a socket, exactly like the Flow
//! and REST suites.

use std::io;

use sipgate_flow::push::{
    is_form_content_type, Dial, Gather, HangupCause, Play, PushAction, PushDirection, PushEvent,
    PushEventKind, PushResponse, PushVerifier, RejectReason, DEFAULT_GATHER_MAX_DIGITS,
    DEFAULT_GATHER_TIMEOUT_MS, FORM_CONTENT_TYPE, MAX_DIAL_TARGETS, MAX_PUSH_BODY_BYTES,
};
use sipgate_flow::{Error, WebhookVerifier};

/// The crate's shared field ceiling, mirrored here because the validator's
/// constant is crate-internal and this test pins the public behaviour.
const MAX_URL_BYTES: usize = 1024 * 1024;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/push/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    text.trim_end().as_bytes().to_vec()
}

fn parses(body: &[u8]) -> PushEvent {
    PushEvent::parse(body).expect("a documented body")
}

#[test]
fn the_new_call_fixture_carries_every_documented_field() {
    let event = parses(&fixture("new_call.form"));

    assert_eq!(event.kind(), &PushEventKind::NewCall);
    assert_eq!(event.event_name(), "newCall");
    assert_eq!(event.call_id(), Some("123456"));
    assert_eq!(event.from(), Some("492111234567"));
    assert_eq!(event.to(), Some("4915791234567"));
    assert_eq!(event.direction(), Some(&PushDirection::In));
    assert_eq!(event.users(), ["Alice", "Bob"]);
    assert_eq!(event.user_ids(), ["w0", "w1"]);
    assert_eq!(event.full_user_ids(), ["1234567w0", "1234567w1"]);
    assert_eq!(event.orig_call_id(), None);
    assert_eq!(event.diversion(), None);
    assert!(event.extras().is_empty());
}

#[test]
fn the_diverted_call_fixture_exposes_the_original_identifiers() {
    let event = parses(&fixture("new_call_diverted.form"));
    assert_eq!(event.orig_call_id(), Some("999"));
    assert_eq!(event.xcid(), Some("x-1"));
    assert_eq!(event.diversion(), Some("49211000"));
}

#[test]
fn the_answer_fixture_carries_the_answering_destination() {
    let event = parses(&fixture("answer.form"));
    assert_eq!(event.kind(), &PushEventKind::Answer);
    assert_eq!(event.users(), ["John Doe"], "`+` is a space");
    assert_eq!(event.answering_number(), Some("21199999999"));
}

#[test]
fn the_hangup_fixture_carries_the_cause() {
    let event = parses(&fixture("hangup.form"));
    assert_eq!(event.kind(), &PushEventKind::Hangup);
    assert_eq!(event.cause(), Some(&HangupCause::NormalClearing));
}

#[test]
fn the_gather_callback_fixtures_distinguish_digits_from_no_digits() {
    let digits = parses(&fixture("dtmf.form"));
    assert_eq!(digits.kind(), &PushEventKind::Dtmf);
    assert_eq!(digits.dtmf(), Some("1"));

    let empty = parses(&fixture("dtmf_empty.form"));
    assert_eq!(empty.dtmf(), Some(""), "documented as an empty value");
}

#[test]
fn an_unknown_event_is_carried_instead_of_failing_the_parse() {
    let event = parses(&fixture("unknown_event.form"));
    assert_eq!(event.kind(), &PushEventKind::Unknown("callWaiting".into()));
    assert_eq!(event.event_name(), "callWaiting");
    assert_eq!(event.extra("queued"), Some("1"));
}

#[test]
fn a_handler_turns_an_event_into_the_documented_xml() {
    let verifier = PushVerifier::new();

    let event = verifier
        .verify_and_parse(Some(FORM_CONTENT_TYPE), &fixture("new_call.form"))
        .expect("a documented body");
    assert_eq!(event.direction(), Some(&PushDirection::In));

    let response = PushResponse::new()
        .with_on_answer("https://example.com/answer")
        .expect("a valid URL")
        .with_on_hangup("https://example.com/hangup")
        .expect("a valid URL")
        .with_verb(PushAction::gather(
            Gather::new("https://example.com/menu")
                .expect("a valid URL")
                .with_max_digits(1)
                .expect("one digit is documented")
                .with_timeout_ms(10_000)
                .expect("ten seconds are documented")
                .with_play(Play::new("https://example.com/menu.wav").expect("a valid URL")),
        ));

    assert_eq!(response.status(), 200);
    assert_eq!(response.content_type(), "application/xml");
    assert_eq!(
        response.to_xml(),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Response onAnswer=\"https://example.com/answer\" onHangup=\"https://example.com/hangup\">\
         <Gather onData=\"https://example.com/menu\" type=\"dtmf\" maxDigits=\"1\" timeout=\"10000\">\
         <Play><Url>https://example.com/menu.wav</Url></Play>\
         </Gather>\
         </Response>"
    );
}

#[test]
fn a_dial_accepts_the_documented_five_targets_and_refuses_the_sixth() {
    let mut dial = Dial::to_number("4915799912341").expect("a valid number");
    for number in [
        "4915799912342",
        "4915799912343",
        "4915799912344",
        "4915799912345",
    ] {
        dial = dial
            .with_number(number)
            .expect("inside the documented limit");
    }
    assert_eq!(dial.targets().len(), MAX_DIAL_TARGETS);
    assert_eq!(dial.to_xml().matches("<Number>").count(), MAX_DIAL_TARGETS);

    let over = dial.with_number("4915799912346");
    assert!(
        matches!(
            over,
            Err(Error::Validation {
                field: "dial.targets",
                ..
            })
        ),
        "{over:?}"
    );
}

#[test]
fn a_dial_needs_at_least_one_target() {
    // The type cannot be built empty: the first target is the constructor.
    let dial = Dial::to_number("4915799912345").expect("a valid number");
    assert_eq!(dial.targets().len(), 1);
    assert_eq!(Dial::to_voicemail().targets().len(), 1);
}

#[test]
fn a_dial_target_keeps_the_documented_number_shape() {
    assert_eq!(
        Dial::to_number("+4915799912345")
            .expect("a leading + is accepted")
            .targets()[0]
            .as_number(),
        Some("4915799912345")
    );

    // The shared E.164 bounds: seven and fifteen digits are accepted, six and
    // sixteen are not.
    assert!(Dial::to_number("1234567").is_ok());
    assert!(Dial::to_number("123456789012345").is_ok());
    for refused in [
        "",
        "123456",
        "1234567890123456",
        "004915799912345",
        "0 49 1579",
        "abd",
    ] {
        assert!(Dial::to_number(refused).is_err(), "{refused:?}");
    }
    assert!(Dial::to_number("4915799912345")
        .expect("valid")
        .with_caller_id("0049230")
        .is_err());
}

#[test]
fn gather_bounds_are_exactly_the_documented_minimum() {
    let gather = Gather::new("https://example.com/dtmf").expect("a valid URL");

    assert_eq!(gather.max_digits(), DEFAULT_GATHER_MAX_DIGITS);
    assert_eq!(gather.timeout_ms(), DEFAULT_GATHER_TIMEOUT_MS);

    // maxDigits: integer >= 1, no documented upper bound.
    assert!(gather.clone().with_max_digits(1).is_ok());
    assert!(gather.clone().with_max_digits(u32::MAX).is_ok());
    assert!(matches!(
        gather.clone().with_max_digits(0),
        Err(Error::Validation {
            field: "gather.maxDigits",
            ..
        })
    ));

    // timeout: integer >= 1 ms, no upper bound documented.
    assert!(gather.clone().with_timeout_ms(1).is_ok());
    assert!(gather.clone().with_timeout_ms(u32::MAX).is_ok());
    assert!(matches!(
        gather.with_timeout_ms(0),
        Err(Error::Validation {
            field: "gather.timeout",
            ..
        })
    ));
}

#[test]
fn a_gather_without_a_callback_url_is_refused() {
    for bad in [
        "",
        "/dtmf",
        "ftp://example.com/dtmf",
        "https://u:p@example.com/dtmf",
    ] {
        assert!(Gather::new(bad).is_err(), "{bad:?}");
    }
    assert!(Gather::new("https://example.com/dtmf").is_ok());
}

#[test]
fn a_play_url_must_be_an_absolute_http_url() {
    assert!(Play::new("http://example.com/a.wav").is_ok());
    assert!(Play::new("https://example.com/a.wav").is_ok());
    for bad in [
        "",
        "example.com/a.wav",
        "file:///etc/passwd",
        "https://example.com/a b.wav",
    ] {
        assert!(Play::new(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn every_url_field_accepts_the_length_limit_and_refuses_one_byte_more() {
    let prefix = "https://example.com/";
    let at_limit = format!("{prefix}{}", "a".repeat(MAX_URL_BYTES - prefix.len()));
    assert_eq!(at_limit.len(), MAX_URL_BYTES);
    let over_limit = format!("{at_limit}a");
    assert_eq!(over_limit.len(), MAX_URL_BYTES + 1);

    assert!(Play::new(at_limit.clone()).is_ok());
    assert!(Play::new(over_limit.clone()).is_err());
    assert!(Gather::new(at_limit.clone()).is_ok());
    assert!(Gather::new(over_limit.clone()).is_err());
    assert!(PushResponse::new().with_on_answer(at_limit.clone()).is_ok());
    assert!(PushResponse::new()
        .with_on_answer(over_limit.clone())
        .is_err());
    assert!(PushResponse::new().with_on_hangup(at_limit).is_ok());
    assert!(PushResponse::new().with_on_hangup(over_limit).is_err());
}

#[test]
fn a_url_is_escaped_inside_its_text_node() {
    let play = Play::new("https://example.com/a.wav?v=1&size=2").expect("a valid URL");
    assert_eq!(
        play.to_xml(),
        "<Play><Url>https://example.com/a.wav?v=1&amp;size=2</Url></Play>"
    );
}

#[test]
fn every_verb_renders_its_documented_element() {
    assert_eq!(PushAction::reject(RejectReason::Busy).verb(), "Reject");
    let response = PushResponse::new()
        .with_verb(PushAction::reject(RejectReason::Rejected))
        .with_verb(PushAction::reject(RejectReason::Busy))
        .with_verb(PushAction::hangup());
    assert_eq!(
        response.to_xml(),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response>\
         <Reject reason=\"rejected\" />\
         <Reject reason=\"busy\" />\
         <Hangup />\
         </Response>"
    );
    assert_eq!(response.len(), 3);
}

#[test]
fn an_empty_response_is_valid_xml() {
    let response = PushResponse::new();
    assert!(response.is_empty());
    assert_eq!(
        response.to_xml(),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response />"
    );
    assert_eq!(response.status(), 200);
}

#[test]
fn the_subscription_urls_are_validated_before_the_response_exists() {
    let response = PushResponse::new();
    assert!(response.clone().with_on_answer("").is_err());
    assert!(response
        .clone()
        .with_on_answer("https://u:p@example.com/x")
        .is_err());
    assert!(response.with_on_hangup("/hangup").is_err());
}

#[test]
fn the_verifier_refuses_the_other_products_content_types() {
    let verifier = PushVerifier::new();
    let body = b"event=newCall&callId=1";

    assert!(verifier.verify_and_parse(None, body).is_ok());
    assert!(verifier.verify_and_parse(Some("  "), body).is_ok());
    assert!(verifier
        .verify_and_parse(Some(FORM_CONTENT_TYPE), body)
        .is_ok());

    for json in ["application/json", "application/vnd.api+json"] {
        let error = verifier
            .verify_and_parse(Some(json), body)
            .expect_err("JSON is Flow");
        assert!(
            matches!(error, Error::UnsupportedContentType { .. }),
            "{json}: {error:?}"
        );
    }
}

#[test]
fn form_content_type_accepts_parameters_and_any_casing() {
    assert!(is_form_content_type(
        "Application/X-WWW-Form-Urlencoded; charset=UTF-8"
    ));
    assert!(!is_form_content_type("application/json"));
    assert!(!is_form_content_type("text/plain"));
    assert!(!is_form_content_type("not a media type"));
}

#[test]
fn the_body_limit_is_exact_for_a_buffered_body() {
    let exact = b"event=newCall&callId=1234567890";
    let limit = exact.len();
    let verifier = PushVerifier::new()
        .with_max_body_bytes(limit)
        .expect("a body-sized limit is inside the accepted range");

    assert!(verifier
        .verify_and_parse(Some(FORM_CONTENT_TYPE), exact)
        .is_ok());

    let one_over = b"event=newCall&callId=12345678901";
    assert_eq!(one_over.len(), limit + 1);
    assert!(matches!(
        verifier.verify_and_parse(Some(FORM_CONTENT_TYPE), one_over),
        Err(Error::BodyTooLarge { size, .. }) if size == limit + 1
    ));
}

#[test]
fn the_parser_and_default_verifier_share_one_body_ceiling() {
    let prefix = b"event=newCall&pad=";
    let fill = MAX_PUSH_BODY_BYTES - prefix.len();
    let mut exact = prefix.to_vec();
    exact.extend(std::iter::repeat_n(b'a', fill));
    assert_eq!(exact.len(), MAX_PUSH_BODY_BYTES);
    assert!(PushVerifier::new().verify_and_parse(None, &exact).is_ok());

    exact.push(b'a');
    assert_eq!(exact.len(), MAX_PUSH_BODY_BYTES + 1);
    assert!(matches!(
        PushVerifier::new().verify_and_parse(None, &exact),
        Err(Error::BodyTooLarge { size, limit })
            if size == MAX_PUSH_BODY_BYTES + 1 && limit == MAX_PUSH_BODY_BYTES
    ));
    assert!(matches!(
        PushVerifier::new().with_max_body_bytes(MAX_PUSH_BODY_BYTES + 1),
        Err(Error::Validation {
            field: "max_body_bytes",
            ..
        })
    ));
}

#[test]
fn the_body_limit_is_exact_for_a_reader_and_stops_reading() {
    let exact = b"event=newCall&callId=1234567890";
    let limit = exact.len();
    let verifier = PushVerifier::new()
        .with_max_body_bytes(limit)
        .expect("a body-sized limit is inside the accepted range");

    assert!(verifier
        .verify_reader(Some(FORM_CONTENT_TYPE), exact.as_slice())
        .is_ok());

    // A reader that never ends must still be abandoned at the limit.
    let endless = io::repeat(b'a');
    let error = verifier
        .verify_reader(Some(FORM_CONTENT_TYPE), endless)
        .expect_err("an endless body is cut off");
    assert!(
        matches!(error, Error::BodyTooLarge { size, .. } if size == limit + 1),
        "{error:?}"
    );
}

#[test]
fn a_failing_reader_is_reported_as_a_body_read_error() {
    struct Broken;
    impl io::Read for Broken {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("connection lost"))
        }
    }

    let verifier = PushVerifier::new();
    let error = verifier
        .verify_reader(Some(FORM_CONTENT_TYPE), Broken)
        .expect_err("the reader failed");
    assert!(matches!(error, Error::BodyRead { .. }), "{error:?}");
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn the_flow_verifier_still_refuses_a_push_body() {
    // Two protocols, two entry points: the Flow verifier must not start
    // accepting form-encoded requests because the Push module exists.
    let flow = WebhookVerifier::new("shared").expect("a non-empty secret");
    let error = flow
        .verify_and_parse(
            Some("shared"),
            Some(FORM_CONTENT_TYPE),
            &fixture("new_call.form"),
        )
        .expect_err("a Push body belongs to the Push module");
    assert!(matches!(error, Error::UnsupportedContentType { .. }));
}
