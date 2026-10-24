//! Property tests: arbitrary input never panics, and what the crate renders
//! parses back to the same value.

use proptest::prelude::*;
use serde_json::{json, Value};
use sipgate_flow::{
    base64, parse_retry_after, wav, Action, Event, EventPayload, RetryPolicy, SmsFailureReason,
    TransferFailedReason,
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
    (kind, "[ -~]{0,32}", "[ -~]{0,32}", any::<bool>()).prop_map(|(kind, text, extra_key, flag)| {
        let mut object = serde_json::Map::new();
        object.insert("type".into(), json!(kind));
        object.insert("text".into(), json!(text));
        if !extra_key.is_empty() {
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

    #[test]
    fn base64_round_trips(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let encoded = base64::encode(&bytes);
        prop_assert!(base64::is_valid(&encoded));
        prop_assert_eq!(encoded.len(), base64::encoded_len(bytes.len()));
        prop_assert_eq!(base64::decode(&encoded).expect("decodes"), bytes);
    }

    #[test]
    fn anything_base64_accepts_decodes(input in "[A-Za-z0-9+/=]{0,64}") {
        if base64::is_valid(&input) {
            prop_assert!(base64::decode(&input).is_ok());
            // Re-encoding is stable even where the input was non-canonical.
            let decoded = base64::decode(&input).expect("valid");
            prop_assert!(base64::is_valid(&base64::encode(&decoded)));
        } else {
            prop_assert!(base64::decode(&input).is_err());
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
    fn backoff_never_shrinks_without_a_hint(
        first in 1_u32..6,
        second in 1_u32..6,
        base_ms in 1_u64..1_000,
    ) {
        let policy = RetryPolicy::new(10)
            .with_base_delay(std::time::Duration::from_millis(base_ms))
            .with_max_delay(std::time::Duration::from_secs(60));
        let (a, b) = (first.min(second), first.max(second));
        let low = policy.delay(a, None).expect("within budget");
        let high = policy.delay(b, None).expect("within budget");
        prop_assert!(low <= high);
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
    fn phone_numbers_are_accepted_up_to_the_e164_length(digits in "[1-9][0-9]{0,14}") {
        let action = Action::send_sms("s1", sipgate_flow::SendSms::new(&digits, "hi").expect("valid"));
        prop_assert!(action.is_ok());
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
    fn generated_wav_headers_always_validate(
        samples in prop::collection::vec(any::<u8>(), 0..2048),
        rate in prop_oneof![Just(8_000_u32), Just(16_000_u32)],
    ) {
        let clip = wav::pcm16_wav(&samples, rate, 1);
        prop_assert!(wav::validate_pcm16(&clip, rate, 1).is_ok());
        prop_assert!(wav::format(&clip).is_some());
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_wav_parser(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = wav::format(&bytes);
        let _ = wav::validate_pcm16(&bytes, 16_000, 1);
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
}
