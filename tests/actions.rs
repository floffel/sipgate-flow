//! Action wire shapes, the validation matrix, and the response envelope.

use sipgate_flow::{
    Action, ActionKind, Audio, BargeInConfig, ConfigureTranscription, Error, FlowResponse,
    MixAudio, SendSms, Speak, TranscriptionProvider, Transfer, Tts, Vad,
};

const SESSION: &str = "550e8400-e29b-41d4-a716-446655440000";

fn json(action: &Action) -> serde_json::Value {
    action.to_json()
}

#[test]
fn speak_renders_the_documented_shape() {
    let action = Action::speak(SESSION, "Hallo!").expect("valid");
    assert_eq!(
        json(&action),
        serde_json::json!({"type": "speak", "session_id": SESSION, "text": "Hallo!"})
    );
    assert_eq!(action.kind(), "speak");
    assert_eq!(action.session_id(), SESSION);
}

#[test]
fn speak_accepts_ssml_instead_of_text() {
    let ssml = r#"<speak version="1.0" xml:lang="de-DE">Hallo</speak>"#;
    let action = Action::speak_ssml(SESSION, ssml).expect("valid");
    let body = json(&action);
    assert_eq!(body["ssml"], ssml);
    assert!(body.get("text").is_none(), "text and ssml are exclusive");
}

#[test]
fn speak_carries_tts_barge_in_timeout_and_vad() {
    let speak = Speak::text("Wie lautet Ihre Nummer?")
        .expect("valid")
        .with_tts(
            Tts::azure()
                .with_language("de-DE")
                .with_voice("de-DE-KatjaNeural"),
        )
        .with_barge_in(
            BargeInConfig::minimum_characters(3)
                .expect("valid")
                .with_allow_after_ms(500),
        )
        .with_user_input_timeout(5)
        .expect("valid")
        .with_vad(Vad::new(1200));
    let action = Action::speak_with(SESSION, speak).expect("valid");
    assert_eq!(
        json(&action),
        serde_json::json!({
            "type": "speak",
            "session_id": SESSION,
            "text": "Wie lautet Ihre Nummer?",
            "tts": {"provider": "azure", "language": "de-DE", "voice": "de-DE-KatjaNeural"},
            "barge_in": {"strategy": "minimum_characters", "minimum_characters": 3, "allow_after_ms": 500},
            "user_input_timeout_seconds": 5,
            "vad": {"end_of_turn_silence_ms": 1200},
        })
    );
}

#[test]
fn empty_text_and_ssml_are_refused() {
    for result in [Action::speak(SESSION, ""), Action::speak_ssml(SESSION, "")] {
        assert!(matches!(
            result,
            Err(Error::Validation { field, .. }) if field == "text" || field == "ssml"
        ));
    }
}

#[test]
fn an_unusable_session_id_never_reaches_an_action() {
    for bad in ["", " ", "a/b", "a?b", "a#b", "a%b", "a\\b", "a\tb"] {
        assert!(
            Action::hangup(bad).is_err(),
            "session id {bad:?} should be refused"
        );
    }
    let long = "x".repeat(201);
    assert!(Action::hangup(long).is_err());
    assert!(Action::hangup("x".repeat(200)).is_ok());
    // Non-ASCII is fine: the id only ever travels inside a JSON string.
    assert!(Action::hangup("séance-1").is_ok());
}

#[test]
fn audio_requires_valid_base64() {
    assert!(Action::audio_base64(SESSION, "UklGRiQAAABXQVZF").is_ok());
    for bad in ["", "not base64!", "A", "A==="] {
        assert!(Action::audio_base64(SESSION, bad).is_err(), "{bad:?}");
    }
}

#[test]
fn audio_wav_refuses_a_clip_the_service_would_not_play() {
    let good = sipgate_flow::wav::pcm16_wav(&[0, 0, 1, 0], 16_000, 1).expect("a short clip");
    assert!(Action::audio_wav(SESSION, &good).is_ok());

    let wrong_rate = sipgate_flow::wav::pcm16_wav(&[0, 0], 44_100, 1).expect("a short clip");
    let error = Action::audio_wav(SESSION, &wrong_rate).expect_err("44.1 kHz");
    assert!(error.to_string().contains("16000 Hz"), "{error}");

    let stereo = sipgate_flow::wav::pcm16_wav(&[0, 0, 0, 0], 16_000, 2).expect("a short clip");
    assert!(Action::audio_wav(SESSION, &stereo).is_err());

    assert!(Action::audio_wav(SESSION, b"ID3\x04 not a wav").is_err());
    assert!(Action::audio_wav(SESSION, b"").is_err());
}

#[test]
fn audio_barge_in_is_omitted_until_set() {
    let clip = Audio::base64("UklGRiQAAABXQVZF").expect("valid");
    let plain = Action::audio(SESSION, clip.clone()).expect("valid");
    assert!(json(&plain).get("barge_in").is_none());

    let configured =
        Action::audio(SESSION, clip.with_barge_in(BargeInConfig::none())).expect("valid");
    assert_eq!(json(&configured)["barge_in"]["strategy"], "none");
}

#[test]
fn mix_audio_starts_and_stops() {
    let started = MixAudio::start_base64("UklGRiQAAABXQVZF")
        .expect("valid")
        .with_volume(0.3)
        .expect("valid");
    assert!(started.is_started());
    let action = Action::mix_audio(SESSION, started).expect("valid");
    assert_eq!(json(&action)["type"], "mix_audio");
    assert_eq!(json(&action)["volume"], serde_json::json!(0.3_f32));

    let stopped = Action::stop_audio(SESSION).expect("valid");
    assert_eq!(
        json(&stopped),
        serde_json::json!({"type": "mix_audio", "session_id": SESSION, "stop": true})
    );
}

#[test]
fn volume_must_be_finite_and_in_range() {
    let clip = || MixAudio::start_base64("UklGRiQAAABXQVZF").expect("valid");
    for good in [0.0_f32, 0.5, 1.0] {
        assert!(clip().with_volume(good).is_ok(), "{good}");
    }
    for bad in [
        -0.001_f32,
        1.001,
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
    ] {
        assert!(clip().with_volume(bad).is_err(), "{bad}");
    }
}

#[test]
fn transfer_validates_number_and_timeout() {
    let transfer = Transfer::new("+4915112345678")
        .expect("valid")
        .with_caller_id("Support", "4921112345678")
        .expect("valid")
        .with_timeout(30)
        .expect("valid");
    let action = Action::transfer(SESSION, transfer).expect("valid");
    assert_eq!(
        json(&action),
        serde_json::json!({
            "type": "transfer",
            "session_id": SESSION,
            "target_phone_number": "4915112345678",
            "caller_id_name": "Support",
            "caller_id_number": "4921112345678",
            "timeout": 30,
        })
    );

    assert!(Transfer::new("").is_err());
    assert!(Transfer::new("49 151").is_err());
    assert!(Transfer::new("1".repeat(16)).is_err());
    assert!(Transfer::new("1".repeat(15)).is_ok());
    assert!(Transfer::new("49").unwrap().with_timeout(4).is_err());
    assert!(Transfer::new("49").unwrap().with_timeout(5).is_ok());
    assert!(Transfer::new("49").unwrap().with_timeout(120).is_ok());
    assert!(Transfer::new("49").unwrap().with_timeout(121).is_err());
    assert!(Transfer::new("49")
        .unwrap()
        .with_caller_id("", "49")
        .is_err());
}

#[test]
fn barge_in_minimum_characters_is_bounded() {
    assert!(BargeInConfig::minimum_characters(0).is_err());
    assert!(BargeInConfig::minimum_characters(1).is_ok());
    assert!(BargeInConfig::minimum_characters(100).is_ok());
    assert!(BargeInConfig::minimum_characters(101).is_err());
}

#[test]
fn user_input_timeout_must_be_at_least_one_second() {
    assert!(Speak::text("hi")
        .unwrap()
        .with_user_input_timeout(0)
        .is_err());
    assert!(Speak::text("hi")
        .unwrap()
        .with_user_input_timeout(1)
        .is_ok());
}

#[test]
fn barge_in_action_has_no_fields_besides_type_and_session() {
    let action = Action::barge_in(SESSION).expect("valid");
    assert_eq!(
        json(&action),
        serde_json::json!({"type": "barge_in", "session_id": SESSION})
    );
}

#[test]
fn configure_transcription_replaces_languages_and_refuses_a_noop() {
    let config = ConfigureTranscription::new()
        .with_provider(TranscriptionProvider::Deepgram)
        .with_languages(["de-DE", "en-US"])
        .expect("valid");
    let action = Action::configure_transcription(SESSION, config).expect("valid");
    assert_eq!(
        json(&action),
        serde_json::json!({
            "type": "configure_transcription",
            "session_id": SESSION,
            "provider": "DEEPGRAM",
            "languages": ["de-DE", "en-US"],
        })
    );

    let empty = ConfigureTranscription::new();
    let error = Action::configure_transcription(SESSION, empty).expect_err("no-op");
    assert!(matches!(
        error,
        Error::Validation {
            field: "configure_transcription",
            ..
        }
    ));
}

#[test]
fn configure_transcription_bounds_languages_and_vocabulary() {
    assert!(ConfigureTranscription::new()
        .with_languages(Vec::<String>::new())
        .is_err());
    assert!(ConfigureTranscription::new()
        .with_languages(["de-DE", "en-US", "fr-FR", "it-IT"])
        .is_ok());
    assert!(ConfigureTranscription::new()
        .with_languages(["de-DE", "en-US", "fr-FR", "it-IT", "es-ES"])
        .is_err());
    for bad in ["", "de_DE", "de DE", "x".repeat(36).as_str()] {
        assert!(
            ConfigureTranscription::new().with_languages([bad]).is_err(),
            "{bad:?}"
        );
    }

    let hundred = (0..100).map(|i| format!("word{i}")).collect::<Vec<_>>();
    assert!(ConfigureTranscription::new()
        .with_vocabulary(hundred.clone())
        .is_ok());
    assert!(ConfigureTranscription::new()
        .with_vocabulary(hundred.into_iter().chain(["extra".to_string()]))
        .is_err());
    assert!(ConfigureTranscription::new()
        .with_vocabulary(["x".repeat(200)])
        .is_ok());
    assert!(ConfigureTranscription::new()
        .with_vocabulary(["x".repeat(201)])
        .is_err());
    assert!(ConfigureTranscription::new().with_vocabulary([""]).is_err());
}

#[test]
fn configure_transcription_normalises_provider_case() {
    assert_eq!(
        TranscriptionProvider::from_wire("deepgram").as_str(),
        "DEEPGRAM"
    );
    assert!(!TranscriptionProvider::ElevenLabs.supports_multiple_languages());
    assert!(TranscriptionProvider::Deepgram.supports_multiple_languages());
}

#[test]
fn send_sms_normalises_the_number() {
    let action = Action::send_sms(
        SESSION,
        SendSms::new("+4915112345678", "Ihr Code: 4242").expect("valid"),
    )
    .expect("valid");
    assert_eq!(
        json(&action),
        serde_json::json!({
            "type": "send_sms",
            "session_id": SESSION,
            "phone_number": "4915112345678",
            "message": "Ihr Code: 4242",
        })
    );

    assert!(SendSms::new("", "hi").is_err());
    assert!(SendSms::new("0151 1234 5678", "hi").is_err());
    assert!(SendSms::new("4915112345678", "").is_err());
    assert!(SendSms::new("1".repeat(16), "hi").is_err());
    // The documentation promises no length limit on the message.
    assert!(SendSms::new("49", "x".repeat(10_000)).is_ok());
}

#[test]
fn hangup_is_the_minimal_action() {
    let action = Action::hangup(SESSION).expect("valid");
    assert_eq!(action.kind(), "hangup");
    assert!(matches!(action.body(), ActionKind::Hangup));
    assert_eq!(
        json(&action),
        serde_json::json!({"type": "hangup", "session_id": SESSION})
    );
}

#[test]
fn no_action_exceeds_the_documented_type_names() {
    let kinds = [
        Action::speak(SESSION, "x").unwrap().kind(),
        Action::audio_base64(SESSION, "UklGRiQ=").unwrap().kind(),
        Action::stop_audio(SESSION).unwrap().kind(),
        Action::hangup(SESSION).unwrap().kind(),
        Action::transfer(SESSION, Transfer::new("49").unwrap())
            .unwrap()
            .kind(),
        Action::barge_in(SESSION).unwrap().kind(),
        Action::configure_transcription(
            SESSION,
            ConfigureTranscription::new().with_vad(Vad::new(500)),
        )
        .unwrap()
        .kind(),
        Action::send_sms(SESSION, SendSms::new("49", "x").unwrap())
            .unwrap()
            .kind(),
    ];
    assert_eq!(
        kinds,
        [
            "speak",
            "audio",
            "mix_audio",
            "hangup",
            "transfer",
            "barge_in",
            "configure_transcription",
            "send_sms",
        ]
    );
}

#[test]
fn response_none_is_204_and_carries_no_body() {
    let response = FlowResponse::none();
    assert_eq!(response.status(), 204);
    assert_eq!(response.body(), None);
    assert!(response.is_no_content());
    assert!(response.is_empty());
    assert_eq!(response.actions().len(), 0);
}

#[test]
fn response_one_is_a_single_object() {
    let response = FlowResponse::one(Action::hangup(SESSION).unwrap());
    assert_eq!(response.status(), 200);
    assert_eq!(response.len(), 1);
    assert!(response.body().unwrap().starts_with("{\"session_id\""));
}

#[test]
fn response_many_is_an_ordered_array() {
    let response = FlowResponse::many([
        Action::barge_in(SESSION).unwrap(),
        Action::speak(SESSION, "Korrektur").unwrap(),
    ]);
    assert_eq!(response.status(), 200);
    assert_eq!(response.len(), 2);
    let parsed: serde_json::Value = serde_json::from_str(&response.body().unwrap()).unwrap();
    assert_eq!(parsed[0]["type"], "barge_in");
    assert_eq!(parsed[1]["type"], "speak");
}

#[test]
fn response_many_of_one_collapses_to_an_object_and_empty_to_no_content() {
    assert!(matches!(
        FlowResponse::many([Action::hangup(SESSION).unwrap()]),
        FlowResponse::One(_)
    ));
    assert!(FlowResponse::many(std::iter::empty::<Action>()).is_no_content());
}

#[test]
fn an_action_converts_into_a_response() {
    let response: FlowResponse = Action::hangup(SESSION).unwrap().into();
    assert_eq!(response.status(), 200);
}

#[test]
fn every_documented_tts_provider_renders_its_provider_key() {
    let providers = [
        (Tts::azure(), "azure"),
        (Tts::eleven_labs(), "eleven_labs"),
        (Tts::kugelaudio(), "kugelaudio"),
        (Tts::openai(), "openai"),
    ];
    for (tts, expected) in providers {
        assert_eq!(tts.to_json()["provider"], expected);
        assert_eq!(tts.to_json().as_object().map(serde_json::Map::len), Some(1));
    }
}

#[test]
fn kugelaudio_carries_voice_language_and_speed() {
    let tts = Tts::kugelaudio()
        .with_voice("963")
        .with_language("de")
        .with_speed(1.25);
    assert_eq!(
        tts.to_json(),
        serde_json::json!({"provider": "kugelaudio", "voice": "963", "language": "de", "speed": 1.25})
    );
}

#[test]
fn a_non_finite_speed_is_never_sent() {
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        assert!(Tts::kugelaudio()
            .with_speed(value)
            .to_json()
            .get("speed")
            .is_none());
    }
    // Providers without the field ignore the setter entirely.
    assert!(Tts::azure()
        .with_speed(1.25)
        .to_json()
        .get("speed")
        .is_none());
    assert!(Tts::eleven_labs()
        .with_speed(1.25)
        .to_json()
        .get("speed")
        .is_none());
    assert!(Tts::openai()
        .with_speed(1.25)
        .to_json()
        .get("speed")
        .is_none());
}

#[test]
fn openai_voices_are_passed_through_verbatim() {
    for voice in [
        "alloy", "echo", "fable", "onyx", "nova", "shimmer", "coral", "sage",
    ] {
        let body = Tts::openai().with_voice(voice).to_json();
        assert_eq!(body["voice"], voice);
        assert!(
            body.get("language").is_none(),
            "OpenAI voices imply the language"
        );
    }
}

#[test]
fn language_and_voice_are_ignored_where_the_provider_has_no_field() {
    let eleven = Tts::eleven_labs().with_language("de-DE");
    assert!(eleven.to_json().get("language").is_none());
    let openai = Tts::openai().with_language("de-DE");
    assert!(openai.to_json().get("language").is_none());
    assert_eq!(
        Tts::kugelaudio().with_language("de").to_json()["language"],
        "de"
    );
}
