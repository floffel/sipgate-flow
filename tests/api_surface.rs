//! The public surface beyond the wire shapes: accessors, alternates and the
//! error paths a caller reaches when a field is present but wrong.
//!
//! The shape tests live in `events.rs` / `actions.rs` / `rest.rs`; this file is
//! the "every documented accessor, and every documented rejection" companion, so
//! a getter that silently starts returning the wrong field fails here.

mod common;

use std::time::Duration;

use common::{FakeClock, MockTransport};
use sipgate_flow::auth::DEFAULT_TOKEN_URL;
use sipgate_flow::rest::{ChannelCall, RecordingSession};
use sipgate_flow::{
    wav, Action, Audio, BargeInConfig, BargeInStrategy, ClientCredentials, ConfigureTranscription,
    Direction, Error, Event, EventPayload, FnSleeper, MixAudio, NoSleep, OAuth2Client, RestClient,
    RetryPolicy, SendSms, Severity, Sleeper, SmsFailureReason, Speak, StaticToken, Transfer,
    TransferFailedReason, Tts, Vad,
};

#[test]
fn speak_exposes_the_text_or_the_ssml_it_was_built_from() {
    let text = Speak::text("Hallo").expect("valid");
    assert_eq!(text.text_value(), Some("Hallo"));
    assert_eq!(text.ssml_value(), None);

    let ssml = Speak::ssml("<speak/>").expect("valid");
    assert_eq!(ssml.ssml_value(), Some("<speak/>"));
    assert_eq!(ssml.text_value(), None);
}

#[test]
fn every_barge_in_strategy_round_trips() {
    for strategy in ["none", "manual", "minimum_characters", "immediate"] {
        assert_eq!(BargeInStrategy::from_wire(strategy).as_str(), strategy);
    }
    let invented = BargeInStrategy::from_wire("telepathy");
    assert_eq!(invented.as_str(), "telepathy");
    assert!(matches!(invented, BargeInStrategy::Other(_)));

    assert_eq!(BargeInConfig::manual().strategy(), &BargeInStrategy::Manual);
    assert_eq!(BargeInConfig::manual().to_json()["strategy"], "manual");
    assert_eq!(
        BargeInConfig::immediate().to_json()["strategy"],
        "immediate"
    );
    assert_eq!(BargeInConfig::none().to_json()["strategy"], "none");
    assert_eq!(
        BargeInConfig::with_strategy(BargeInStrategy::Other("telepathy".into())).to_json()
            ["strategy"],
        "telepathy",
        "a strategy this crate does not model still reaches the wire"
    );
}

#[test]
fn vad_keeps_the_configured_silence_window() {
    let vad = Vad::new(700);
    assert_eq!(vad.end_of_turn_silence_ms(), 700);
    assert_eq!(
        vad.to_json(),
        serde_json::json!({"end_of_turn_silence_ms": 700})
    );
}

#[test]
fn mix_audio_starts_from_a_clip_and_reports_its_state() {
    let clip = Audio::base64("UklGRiQAAABXQVZF").expect("valid");
    let started = MixAudio::start(&clip).expect("valid");
    assert_eq!(started.to_json()["audio"], clip.base64_data());
    assert!(!started.is_stop());
    let stopped = MixAudio::stop();
    assert!(stopped.is_stop());
    assert!(!stopped.is_started());
}

#[test]
fn every_sms_failure_reason_maps_back_to_its_wire_value() {
    let cases = [
        ("sender_not_allowed", SmsFailureReason::SenderNotAllowed),
        (
            "insufficient_balance",
            SmsFailureReason::InsufficientBalance,
        ),
        ("no_sms_extension", SmsFailureReason::NoSmsExtension),
        ("smsc_unavailable", SmsFailureReason::SmscUnavailable),
        ("unknown", SmsFailureReason::Unknown),
    ];
    for (wire, reason) in cases {
        assert_eq!(SmsFailureReason::from_wire(wire), reason);
        assert_eq!(reason.as_str(), wire);
    }
    assert_eq!(
        SmsFailureReason::from_wire("carrier_pigeon").as_str(),
        "carrier_pigeon"
    );
    assert!(SmsFailureReason::SmscUnavailable.is_retryable());
    assert!(!SmsFailureReason::Unknown.is_retryable());
}

#[test]
fn every_error_code_maps_back_to_its_wire_value() {
    let codes = [
        "action_invalid",
        "action_unknown_session",
        "transcription_unavailable",
        "transcription_switch_failed",
        "synthesis_unavailable",
        "transfer_target_invalid",
        "internal_error",
    ];
    for code in codes {
        assert_eq!(sipgate_flow::ErrorCode::from_wire(code).as_str(), code);
    }
}

#[test]
fn severity_and_unknown_events_keep_their_wire_identity() {
    assert_eq!(Severity::Error.as_str(), "error");
    assert_eq!(Severity::from_wire("notice").as_str(), "notice");
    assert!(Severity::from_wire("notice").call_continues());

    let unknown = Event::parse(br#"{"type":"not_yet","session":{"id":"s"}}"#).expect("parses");
    assert_eq!(unknown.payload().known_kind(), None);
    assert_eq!(unknown.kind(), "not_yet");
    assert!(!unknown.accepts_actions());
}

#[test]
fn a_top_level_call_id_fills_a_missing_session_id() {
    // Push API-era payloads carry `callId` instead of `session.id`.
    let event =
        Event::parse(br#"{"type":"dtmf_received","digit":"1","callId":"c9"}"#).expect("parses");
    assert_eq!(event.session_id(), Some("c9"));
    assert!(matches!(event.payload(), EventPayload::DtmfReceived { digit } if digit == "1"));
}

#[test]
fn a_language_on_user_speak_survives_the_round_trip() {
    // The docs' example reads `event.language`; the field table omits it, so it
    // is carried rather than required.
    let body = br#"{"type":"user_speak","text":"hi","language":"de-DE","session":{"id":"s"}}"#;
    let event = Event::parse(body).expect("parses");
    assert!(matches!(
        event.payload(),
        EventPayload::UserSpeak { language: Some(code), .. } if code == "de-DE"
    ));
    assert_eq!(event.to_json()["language"], "de-DE");
}

#[test]
fn the_oauth_client_accessors_report_what_was_configured() {
    let clock = FakeClock::new(Duration::ZERO);
    let credentials = ClientCredentials::new("id", "hunter2")
        .expect("valid")
        .with_scopes(["sessions:write", "rtcm:read"]);
    assert_eq!(credentials.client_id(), "id");
    assert_eq!(credentials.scopes(), ["sessions:write", "rtcm:read"]);
    assert_eq!(
        credentials.token_request_body()[3].1,
        "sessions:write rtcm:read"
    );

    let auth = OAuth2Client::new(MockTransport::json(&json_response_value()), credentials)
        .with_clock(clock)
        .with_token_url("https://proxy.test/token")
        .with_refresh_margin(Duration::from_secs(30))
        .with_timeout(Some(Duration::from_secs(7)));
    assert_eq!(auth.token_url(), "https://proxy.test/token");
    assert_eq!(auth.refresh_margin(), Duration::from_secs(30));
    assert_eq!(auth.timeout(), Some(Duration::from_secs(7)));
    assert_eq!(auth.credentials().client_id(), "id");
    assert!(!auth.has_valid_token());

    // Debug must name the configuration and never the secret.
    let rendered = format!("{auth:?}");
    assert!(rendered.contains("proxy.test"), "{rendered}");
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[test]
fn the_default_token_url_is_the_documented_one() {
    let auth = OAuth2Client::new(
        MockTransport::new(),
        ClientCredentials::new("id", "s").expect("valid"),
    );
    assert_eq!(auth.token_url(), DEFAULT_TOKEN_URL);
}

#[test]
fn a_static_token_never_prints_itself() {
    let token = StaticToken::new("super-secret").expect("valid");
    let rendered = format!("{token:?}");
    assert!(!rendered.contains("super-secret"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[test]
fn the_rest_client_accessors_report_what_was_configured() {
    let client = RestClient::new(MockTransport::new(), StaticToken::new("t").expect("valid"))
        .with_base_url("http://localhost:9/")
        .with_timeout(Some(Duration::from_secs(4)))
        .with_retry(RetryPolicy::default().without_retry_after());
    assert_eq!(client.base_url(), "http://localhost:9");
    assert_eq!(client.timeout(), Some(Duration::from_secs(4)));
    assert!(
        !client.retry().use_retry_after,
        "Retry-After is off for this client"
    );
    assert_eq!(
        client.retry().max_attempts,
        RetryPolicy::default().max_attempts
    );
}

#[test]
fn a_retry_after_hint_is_ignored_when_the_policy_says_so() {
    let policy = RetryPolicy::default().without_retry_after();
    assert_eq!(
        policy.delay(1, Some(Duration::from_secs(30))),
        Some(Duration::from_millis(250))
    );
    // An exhausted budget stays exhausted whatever the hint says.
    let exhausted = RetryPolicy::new(1);
    assert_eq!(exhausted.delay(1, Some(Duration::from_secs(1))), None);
}

#[test]
fn a_wav_can_be_validated_or_rejected_before_it_is_sent() {
    let good = wav::pcm16_wav(&[0, 1, 2, 3], 16_000, 1);
    wav::validate_pcm16(&good, 16_000, 1).expect("a 16 kHz mono clip");

    // A chunk that claims more bytes than the file has.
    let mut overlong = b"RIFF\xff\xff\xff\xffWAVE".to_vec();
    overlong.extend_from_slice(b"JUNK");
    overlong.extend_from_slice(&1_000_u32.to_le_bytes());
    overlong.extend_from_slice(b"abc");
    assert!(wav::format(&overlong).is_none());
    assert!(wav::validate_pcm16(&overlong, 16_000, 1).is_err());

    // An unknown chunk before `fmt ` is skipped, odd-sized chunks included.
    let mut with_junk = good.clone();
    let junk = b"JUNK\x03\x00\x00\x00abc\x00";
    with_junk.splice(12..12, junk.iter().copied());
    let format = wav::format(&with_junk).expect("fmt is found after the junk chunk");
    assert_eq!(format.sample_rate, 16_000);

    // A RIFF header with no fmt chunk at all.
    let header_only = b"RIFF\x04\x00\x00\x00WAVE";
    assert!(wav::format(header_only).is_none());
}

#[test]
fn a_channel_call_and_a_recording_session_render_exactly_what_was_set() {
    let call = ChannelCall::new("e0", "4915112345678")
        .with_caller_id("49211100200")
        .with_channel_id("c1");
    assert_eq!(
        call.to_json(),
        serde_json::json!({
            "deviceId": "e0",
            "targetNumber": "4915112345678",
            "callerId": "49211100200",
            "channelId": "c1",
        })
    );

    let bare = ChannelCall::new("e0", "4915112345678");
    assert_eq!(
        bare.to_json(),
        serde_json::json!({"deviceId": "e0", "targetNumber": "4915112345678"})
    );

    let session = RecordingSession::new()
        .with_device_id("e0")
        .with_endpoint("e1")
        .with_target_id("t1");
    assert_eq!(
        session.to_json(),
        serde_json::json!({"deviceId": "e0", "endpoint": "e1", "targetId": "t1"})
    );
    assert_eq!(RecordingSession::new().to_json(), serde_json::json!({}));
}

#[test]
fn a_malformed_local_audio_is_rejected_with_the_reason() {
    let error = Audio::wav(b"not a wav").expect_err("no RIFF header");
    assert!(
        matches!(error, Error::Validation { field: "audio", .. }),
        "{error:?}"
    );

    let mut eight_bit = wav::pcm16_wav(&[0, 1, 2, 3], 16_000, 1);
    // Patch the bit depth (offset 34 in the canonical layout) to 8.
    eight_bit[34] = 8;
    let error = wav::validate_pcm16(&eight_bit, 16_000, 1).expect_err("8-bit");
    assert!(error.to_string().contains("16-bit"), "{error}");

    let mut compressed = wav::pcm16_wav(&[0, 1, 2, 3], 16_000, 1);
    // Patch the format tag (offset 20) to 3 (IEEE float).
    compressed[20] = 3;
    let error = wav::validate_pcm16(&compressed, 16_000, 1).expect_err("compressed");
    assert!(error.to_string().contains("format tag 1"), "{error}");
}

#[test]
fn a_speak_action_reaches_the_wire_with_its_tts_and_vad() {
    let action = Action::speak_with(
        "s1",
        Speak::text("Hallo")
            .expect("valid")
            .with_tts(Tts::kugelaudio().with_voice("963").with_speed(1.5))
            .with_vad(Vad::new(800)),
    )
    .expect("valid");
    let body = action.to_json();
    assert_eq!(body["tts"]["provider"], "kugelaudio");
    assert_eq!(body["tts"]["speed"], 1.5);
    assert_eq!(body["vad"]["end_of_turn_silence_ms"], 800);
    assert_eq!(body["session_id"], "s1");
}

fn json_response_value() -> serde_json::Value {
    serde_json::json!({"access_token": "abc", "expires_in": 300})
}

#[test]
fn every_direction_and_transfer_failure_reason_round_trips() {
    for direction in ["inbound", "outbound"] {
        assert_eq!(Direction::from_wire(direction).as_str(), direction);
    }
    assert!(matches!(
        Direction::from_wire("sideways"),
        Direction::Other(_)
    ));

    for reason in [
        "busy",
        "rejected",
        "no_answer",
        "number_not_found",
        "technical_error",
        "unknown",
    ] {
        assert_eq!(TransferFailedReason::from_wire(reason).as_str(), reason);
    }
    assert_eq!(
        TransferFailedReason::from_wire("carrier_pigeon").as_str(),
        "carrier_pigeon"
    );
    assert_eq!(Severity::Warning.as_str(), "warning");
}

#[test]
fn a_session_without_an_id_takes_the_top_level_call_id() {
    let event = Event::parse(
        br#"{"type":"user_speak","text":"hi","callId":"c9","session":{"id":"","account_id":"a"}}"#,
    )
    .expect("parses");
    assert_eq!(event.session_id(), Some("c9"));
    assert_eq!(
        event.session().and_then(|s| s.account_id.as_deref()),
        Some("a")
    );
}

#[test]
fn a_transfer_exposes_its_target() {
    let transfer = Transfer::new("4915112345678").expect("valid");
    assert_eq!(transfer.target_phone_number(), "4915112345678");
}

#[test]
fn every_transcription_provider_round_trips() {
    for provider in [
        "AZURE",
        "AZURE_VOICE_LIVE",
        "ELEVEN_LABS",
        "DEEPGRAM",
        "OPENAI",
        "SIPGATE_QWEN",
        "SIPGATE_PARAKEET",
    ] {
        assert_eq!(
            sipgate_flow::TranscriptionProvider::from_wire(provider).as_str(),
            provider
        );
    }
    assert_eq!(
        sipgate_flow::TranscriptionProvider::from_wire("WHISPER").as_str(),
        "WHISPER"
    );
}

#[test]
fn a_configured_transcription_carries_vocabulary_vad_and_languages() {
    let config = ConfigureTranscription::new()
        .with_provider(sipgate_flow::TranscriptionProvider::SipgateParakeet)
        .with_languages(["de", "en"])
        .expect("1-4 languages")
        .with_vocabulary(["sipgate", "VoIP"])
        .expect("within limits")
        .with_vad(Vad::new(600));
    let body = config.to_json();
    assert_eq!(body["provider"], "SIPGATE_PARAKEET");
    assert_eq!(body["languages"], serde_json::json!(["de", "en"]));
    assert_eq!(
        body["custom_vocabulary"],
        serde_json::json!(["sipgate", "VoIP"])
    );
    assert_eq!(body["vad"]["end_of_turn_silence_ms"], 600);
    assert!(!config.is_empty());
}

#[test]
fn an_sms_exposes_its_recipient_and_message() {
    let sms = SendSms::new("4915112345678", "Hallo!").expect("valid");
    assert_eq!(sms.phone_number(), "4915112345678");
    assert_eq!(sms.message(), "Hallo!");
}

#[tokio::test]
async fn a_function_sleeper_calls_through_and_no_sleep_returns_at_once() {
    let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&recorded);
    let sleeper = FnSleeper::new(move |delay| {
        sink.lock().expect("lock").push(delay);
        std::future::ready(())
    });
    Sleeper::sleep(&sleeper, Duration::from_millis(20)).await;
    assert_eq!(
        recorded.lock().expect("lock").as_slice(),
        [Duration::from_millis(20)]
    );

    NoSleep.sleep(Duration::from_secs(3600)).await;
}

#[test]
fn every_accessor_a_caller_can_reach_returns_what_it_was_built_with() {
    // `RestClient::auth`, `Request::body_is_empty` and `Response::body` are
    // public but never needed by a wire test; a getter that starts returning
    // the wrong field would otherwise go unnoticed.
    use sipgate_flow::transport::{Method, Request, RequestBody, Response, Security};

    let client = RestClient::new(
        MockTransport::new(),
        StaticToken::new("access-token").expect("valid"),
    );
    // The token itself is never readable through the client - only the source.
    let _: &StaticToken = client.auth();

    let empty = Request::empty(Method::Get, "https://x.test/a", Security::None);
    assert!(empty.body_is_empty());
    let payload = serde_json::json!({"value": true});
    let json = Request::json(Method::Put, "https://x.test/a", Security::None, &payload);
    assert!(!json.body_is_empty());
    assert!(matches!(json.body, RequestBody::Json(_)));

    let response = Response::new(200, std::iter::empty(), b"ok".to_vec());
    assert_eq!(response.body(), b"ok");
}

#[test]
fn a_status_lookup_answers_none_for_every_error_without_one() {
    // The `Error::status` fallthrough arm: a validation, secret or ambiguous
    // error must not invent a status.
    for error in [
        Error::validation("text", "must not be empty"),
        Error::EmptySecret,
        Error::MissingSecret,
        Error::SecretMismatch,
        Error::EmptyBody,
        Error::Unauthorized,
        Error::ambiguous(None, "the connection died after the write"),
    ] {
        assert_eq!(error.status(), None, "{error:?}");
        assert!(!error.is_retryable(), "{error:?}");
    }
}

#[test]
fn the_standalone_rest_parsers_report_a_body_they_cannot_use() {
    use sipgate_flow::rest::{parse_calls, CallInfo};

    let calls: Vec<CallInfo> = parse_calls(br#"{"data":[]}"#).expect("the documented envelope");
    assert_eq!(calls.len(), 0);
    assert!(
        parse_calls(br#"{"data":{}}"#).is_err(),
        "data must be an array"
    );
    assert!(parse_calls(b"").is_err(), "an empty body is not JSON");
}
