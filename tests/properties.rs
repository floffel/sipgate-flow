//! Property tests: arbitrary input never panics, and what the crate renders
//! parses back to the same value.

use std::time::Duration;

use proptest::prelude::*;
use serde_json::{json, Value};
use sipgate_flow::auth::MAX_TOKEN_LIFETIME;
use sipgate_flow::{
    base64, classify, parse_retry_after, retry_after_from, wav, Action, Error, Event, EventPayload,
    Method, OutboundCall, RetryOutcome, RetryPolicy, SmsFailureReason, Token, TransferFailedReason,
    MIN_RETRY_DELAY,
};

/// A recursive JSON value, bounded in depth and width.
fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|number| json!(number)),
        "[ -~]{0,24}".prop_map(Value::String),
        Just(json!(0)),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::hash_map("[a-zA-Z_]{0,10}", inner, 0..4)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

/// A JSON event with a documented `type` and arbitrary auxiliary content.
fn documented_event() -> impl Strategy<Value = Value> {
    let kind = prop_oneof![
        Just("session_start"),
        Just("user_speech_started"),
        Just("user_speak"),
        Just("dtmf_received"),
        Just("assistant_speak"),
        Just("assistant_speech_ended"),
        Just("user_input_timeout"),
        Just("session_end"),
        Just("sms_failed"),
        Just("error"),
    ];
    (
        kind,
        "[ -~]{0,32}",
        "[ -~]{0,32}",
        any::<bool>(),
        prop_oneof![Just('0'), Just('*'), Just('#')],
    )
        .prop_map(|(kind, text, extra_key, flag, digit)| {
            let mut object = serde_json::Map::new();
            object.insert("type".into(), json!(kind));
            object.insert("text".into(), json!(text));
            if kind == "dtmf_received" {
                object.insert("digit".into(), json!(digit.to_string()));
            }
            if kind == "error" {
                object.insert("code".into(), json!("internal_error"));
                object.insert("severity".into(), json!("error"));
            }
            if !extra_key.is_empty()
                && !matches!(
                    extra_key.as_str(),
                    "type" | "text" | "digit" | "digits" | "session"
                )
            {
                object.insert(extra_key, json!(flag));
            }
            object.insert(
                "session".into(),
                json!({"id": "s1", "account_id": "a1", "direction": "inbound"}),
            );
            Value::Object(object)
        })
}

proptest! {
    #[test]
    fn the_event_parser_never_panics_on_arbitrary_json(value in json_value()) {
        let bytes = serde_json::to_vec(&value).expect("serialise");
        match Event::parse(&bytes) {
            Ok(event) => {
                // Whatever came in, the payload is one of the modelled shapes.
                let _ = event.kind();
                let _ = event.session_id();
                let _ = event.accepts_actions();
                let _ = event.to_json();
            }
            Err(error) => {
                let _ = error.to_string();
            }
        }
    }

    #[test]
    fn the_event_parser_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = Event::parse(&bytes);
    }

    #[test]
    fn documented_events_round_trip(event in documented_event()) {
        let bytes = serde_json::to_vec(&event).expect("serialise");
        let parsed = Event::parse(&bytes).expect("documented type must parse");
        let kind = event["type"].as_str().unwrap_or_default();
        prop_assume!(!parsed.is_unknown());
        prop_assert_eq!(parsed.kind(), kind);

        let rendered = serde_json::to_vec(&parsed.to_json()).expect("render");
        let again = Event::parse(&rendered).expect("re-parse");
        prop_assert_eq!(&parsed, &again);
    }

    #[test]
    fn rendering_an_event_is_idempotent(event in documented_event()) {
        let parsed = Event::parse(&serde_json::to_vec(&event).expect("serialise"))
            .expect("documented type must parse");
        let once = parsed.to_json();
        let twice = Event::parse(&serde_json::to_vec(&once).expect("render"))
            .expect("re-parse")
            .to_json();
        prop_assert_eq!(once, twice);
    }

    /// The headline tolerance contract: an unknown field on a *known* event is
    /// neither dropped nor rejected. It lands in `Event::extra` and survives a
    /// render/parse round-trip.
    #[test]
    fn unknown_fields_on_known_events_survive(
        key in "x_[a-zA-Z_]{0,12}",
        value in json_value(),
    ) {
        let mut object = serde_json::Map::new();
        object.insert("type".into(), json!("user_speak"));
        object.insert("text".into(), json!("hi"));
        object.insert("session".into(), json!({"id": "s1"}));
        object.insert(key.clone(), value.clone());
        let bytes = serde_json::to_vec(&Value::Object(object)).expect("serialise");

        let parsed = Event::parse(&bytes).expect("a known type with an extra field parses");
        prop_assert!(!parsed.is_unknown());
        prop_assert_eq!(parsed.extra().get(&key), Some(&value));
        let rendered = parsed.to_json();
        prop_assert_eq!(rendered.get(key.as_str()), Some(&value));

        let again = Event::parse(
            &serde_json::to_vec(&parsed.to_json()).expect("render"),
        )
        .expect("re-parse");
        prop_assert_eq!(again.extra().get(&key), Some(&value));
    }

    #[test]
    fn base64_round_trips(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let encoded = base64::encode(&bytes);
        prop_assert!(base64::is_valid(&encoded));
        prop_assert_eq!(
            encoded.len(),
            base64::encoded_len(bytes.len()).expect("small length")
        );
        prop_assert_eq!(base64::decode(&encoded).expect("decodes"), bytes);
    }

    /// Accepted input is *canonical*: it ends on a four-character group, and
    /// decoding then re-encoding reproduces the exact string. `is_valid` is the
    /// same rule as `decode`, never a cheaper approximation.
    #[test]
    fn accepted_base64_is_canonical(input in "[A-Za-z0-9+/]{0,60}={0,2}") {
        prop_assert_eq!(base64::is_valid(&input), base64::decode(&input).is_ok());
        if base64::is_valid(&input) {
            prop_assert!(input.len().is_multiple_of(4));
            let decoded = base64::decode(&input).expect("valid");
            prop_assert_eq!(base64::encode(&decoded), input);
        }
    }

    /// Padding is required, not optional: the engine's own encoding is valid,
    /// the same string with its `=` stripped is not.
    #[test]
    fn padding_is_required(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let encoded = base64::encode(&bytes);
        prop_assert!(base64::is_valid(&encoded));
        let stripped = encoded.trim_end_matches('=');
        if stripped.len() != encoded.len() {
            prop_assert!(!base64::is_valid(stripped));
        }
    }

    #[test]
    fn retry_delays_stay_within_the_ceiling(
        attempts in 0_u32..64,
        base_ms in 0_u64..5_000,
        cap_ms in 0_u64..30_000,
        hint_secs in proptest::option::of(0_u64..3_600),
    ) {
        let policy = RetryPolicy::new(8)
            .with_base_delay(std::time::Duration::from_millis(base_ms))
            .with_max_delay(std::time::Duration::from_millis(cap_ms));
        let hint = hint_secs.map(std::time::Duration::from_secs);
        if let Some(delay) = policy.delay(attempts, hint) {
            prop_assert!(delay <= policy.max_delay);
        }
    }

    #[test]
    fn retry_delays_never_fall_below_the_floor(
        attempts in 0_u32..64,
        base_ms in 0_u64..5_000,
        cap_ms in 0_u64..30_000,
        hint_secs in proptest::option::of(0_u64..3_600),
    ) {
        let policy = RetryPolicy::new(8)
            .with_base_delay(Duration::from_millis(base_ms))
            .with_max_delay(Duration::from_millis(cap_ms));
        let hint = hint_secs.map(Duration::from_secs);
        if let Some(delay) = policy.delay(attempts, hint) {
            prop_assert!(delay >= MIN_RETRY_DELAY, "delay {delay:?} below floor");
        }
    }

    #[test]
    fn backoff_stays_in_the_equal_jitter_window(
        attempts in 1_u32..6,
        base_ms in 1_u64..1_000,
    ) {
        let policy = RetryPolicy::new(10)
            .with_base_delay(Duration::from_millis(base_ms))
            .with_max_delay(Duration::from_secs(60));
        let uncapped = policy
            .base_delay
            .saturating_mul(1_u32 << attempts.saturating_sub(1));
        let expected_high = uncapped.min(policy.max_delay);
        let expected_low = expected_high / 2;
        let delay = policy.delay(attempts, None).expect("within budget");
        prop_assert!(delay >= expected_low.max(MIN_RETRY_DELAY));
        prop_assert!(delay <= expected_high);
    }

    #[test]
    fn identical_backoff_inputs_are_not_constant(
        attempts in 1_u32..4,
        base_ms in 2_u64..1_000,
    ) {
        let policy = RetryPolicy::new(10)
            .with_base_delay(Duration::from_millis(base_ms))
            .with_max_delay(Duration::from_secs(60));
        let mut values = std::collections::HashSet::new();
        for _ in 0..128 {
            values.insert(policy.delay(attempts, None).expect("within budget"));
        }
        prop_assert!(values.len() > 1, "jitter produced only {values:?}");
    }

    #[test]
    fn retry_after_parsing_never_panics(value in ".{0,32}") {
        let _ = parse_retry_after(&value);
    }

    #[test]
    fn retry_after_digits_round_trip(seconds in 0_u64..86_400) {
        prop_assert_eq!(
            parse_retry_after(&seconds.to_string()),
            Some(std::time::Duration::from_secs(seconds))
        );
    }

    #[test]
    fn a_present_retry_after_never_falls_back_to_no_hint(value in ".{0,32}") {
        let headers = |name: &str| (name == "retry-after").then_some(value.as_str());
        prop_assert!(retry_after_from(headers).is_some());
    }

    #[test]
    fn phone_numbers_are_accepted_within_the_e164_length(digits in "[1-9][0-9]{6,14}") {
        let action = Action::send_sms("s1", sipgate_flow::SendSms::new(&digits, "hi").expect("valid"));
        prop_assert!(action.is_ok());
    }

    #[test]
    fn too_short_phone_numbers_are_refused(digits in "[1-9][0-9]{0,5}") {
        prop_assert!(sipgate_flow::SendSms::new(&digits, "hi").is_err());
    }

    #[test]
    fn over_long_phone_numbers_are_refused(digits in "[1-9][0-9]{15,30}") {
        prop_assert!(sipgate_flow::SendSms::new(&digits, "hi").is_err());
    }

    #[test]
    fn session_ids_with_separators_are_refused(id in "/ ?#\\\\%") {
        let candidate = format!("a{id}b");
        prop_assert!(Action::hangup(&candidate).is_err());
    }

    #[test]
    fn session_ids_outside_the_path_alphabet_are_refused(id in "[^A-Za-z0-9._~:@-]{1,4}") {
        let candidate = format!("a{id}b");
        prop_assert!(Action::hangup(&candidate).is_err());
    }

    #[test]
    fn generated_wav_headers_always_validate(
        samples in prop::collection::vec(any::<u8>(), 0..2048),
        rate in prop_oneof![Just(8_000_u32), Just(16_000_u32)],
    ) {
        let clip = wav::pcm16_wav(&samples, rate, 1).expect("a small payload fits");
        prop_assert!(wav::validate_pcm16(&clip, rate, 1).is_ok());
        prop_assert!(wav::format(&clip).is_some());
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_wav_parser(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = wav::format(&bytes);
        let _ = wav::validate_pcm16(&bytes, 16_000, 1);
    }

    #[test]
    fn no_non_idempotent_request_is_retried_after_a_server_error(status in 100_u16..1000) {
        let outcome = classify(Method::Post, status);
        let repeatable = outcome == RetryOutcome::Retry;
        // The repeatable non-idempotent answers are the ones the server emits
        // before it processes anything. Permanent 5xx answers are terminal;
        // the remaining 5xx answers are the ambiguous class.
        let not_processed = matches!(status, 408 | 425 | 429);
        let permanent_server_error = matches!(status, 501 | 505);
        let ambiguous = (500..600).contains(&status) && !permanent_server_error;
        prop_assert_eq!(repeatable, not_processed);
        prop_assert_eq!(outcome == RetryOutcome::Ambiguous, ambiguous);
    }

    #[test]
    fn a_status_is_classified_the_same_way_for_every_idempotent_method(status in 100_u16..1000) {
        let get = classify(Method::Get, status);
        prop_assert_eq!(get, classify(Method::Put, status));
        prop_assert_eq!(get, classify(Method::Delete, status));
        // Retry and Ambiguous are mutually exclusive. Retryable answers are
        // 408/425/429 plus non-permanent 5xx; permanent 5xx, notably 501/505,
        // stay terminal.
        prop_assert!(!(get == RetryOutcome::Retry && get == RetryOutcome::Ambiguous));
        let retryable = matches!(status, 408 | 425 | 429)
            || ((500..600).contains(&status) && !matches!(status, 501 | 505));
        prop_assert_eq!(get == RetryOutcome::Terminal, !retryable);
    }

    #[test]
    fn unknown_enum_values_are_preserved(value in "[a-z_]{1,24}") {
        let reason = TransferFailedReason::from_wire(&value);
        prop_assert_eq!(reason.as_str(), value.as_str());
        let sms = SmsFailureReason::from_wire(&value);
        prop_assert_eq!(sms.as_str(), value.as_str());
    }

    #[test]
    fn a_speak_action_always_carries_text_or_ssml(text in "[ -~]{1,64}") {
        let action = Action::speak("s1", &text).expect("valid");
        let body = action.to_json();
        prop_assert_eq!(body["type"].as_str(), Some("speak"));
        prop_assert_eq!(body["session_id"].as_str(), Some("s1"));
        prop_assert_eq!(body["text"].as_str(), Some(text.as_str()));
        prop_assert!(matches!(action.body(), sipgate_flow::ActionKind::Speak(_)));
        let _ = EventPayload::SessionEnd;
    }

    #[test]
    fn an_arbitrary_expires_in_is_either_a_usable_lifetime_or_a_typed_error(seconds in any::<u64>()) {
        let parsed = Token::from_json(&json!({"access_token": "a", "expires_in": seconds}));
        match parsed {
            Ok(token) => {
                prop_assert_eq!(token.expires_in(), Some(Duration::from_secs(seconds)));
                prop_assert!(Duration::from_secs(seconds) <= MAX_TOKEN_LIFETIME);
            }
            Err(Error::TokenResponse { message: reason, .. }) => {
                prop_assert!(Duration::from_secs(seconds) > MAX_TOKEN_LIFETIME);
                prop_assert!(reason.contains("expires_in"), "{}", reason);
            }
            Err(other) => prop_assert!(false, "unexpected error for {}: {}", seconds, other),
        }
    }

    #[test]
    fn a_billing_device_never_escapes_the_documented_shape(suffix in "[a-z][a-z0-9]{0,7}") {
        let call = OutboundCall::new("flow-1", &suffix, "4915112345678");
        prop_assert!(call.is_ok(), "valid suffix {:?} rejected", suffix);
        let rendered = call.expect("checked above").to_json();
        prop_assert_eq!(rendered["billingDevice"].as_str(), Some(suffix.as_str()));
    }

    #[test]
    fn an_unbounded_or_non_ascii_billing_device_is_rejected(suffix in ".{0,32}") {
        let is_documented_shape = !suffix.is_empty()
            && suffix.len() <= 8
            && suffix.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_lowercase()
                } else {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit()
                }
            });
        let accepted = OutboundCall::new("flow-1", &suffix, "4915112345678").is_ok();
        prop_assert_eq!(accepted, is_documented_shape, "suffix {:?}", suffix);
    }
}
