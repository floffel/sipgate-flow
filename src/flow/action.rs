//! Outbound actions, validated before they can reach the wire.
//!
//! Eight action types are documented (<https://flow.sipgate.io/api/actions>):
//! `speak`, `audio`, `mix_audio`, `hangup`, `transfer`, `barge_in`,
//! `configure_transcription` and `send_sms`. Each builder returns
//! [`Result`], so an [`Action`] value is always sendable — there is no
//! "validated at serialisation time" state to forget.
//!
//! ```
//! use sipgate_flow::{Action, FlowResponse};
//!
//! let speak = Action::speak("550e8400-e29b-41d4-a716-446655440000", "Willkommen!")?;
//! assert_eq!(speak.kind(), "speak");
//! let response = FlowResponse::one(speak);
//! assert_eq!(response.status(), 200);
//! # Ok::<(), sipgate_flow::Error>(())
//! ```

use serde_json::{json, Map, Value};

use crate::base64;
use crate::error::{Error, Result};
use crate::validate;

/// An action to return for a running session.
///
/// The wire shape is flat — `type`, `session_id` and the action's own fields —
/// which is why the session id is part of this type rather than an argument of
/// [`Action::to_json`].
///
/// ```
/// use sipgate_flow::Action;
///
/// let action = Action::hangup("s1")?;
/// assert_eq!(action.session_id(), "s1");
/// assert_eq!(action.to_json(), serde_json::json!({"type": "hangup", "session_id": "s1"}));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Action {
    session_id: String,
    kind: ActionKind,
}

/// The typed body of an [`Action`], one variant per documented action type.
///
/// ```
/// use sipgate_flow::{Action, ActionKind};
///
/// let action = Action::barge_in("s1")?;
/// assert!(matches!(action.body(), ActionKind::BargeIn));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ActionKind {
    /// Speak text or SSML.
    Speak(Speak),
    /// Play a base64 WAV clip once.
    Audio(Audio),
    /// Loop a background sound under the call.
    MixAudio(MixAudio),
    /// End the call.
    Hangup,
    /// Transfer to another number.
    Transfer(Transfer),
    /// Stop whatever is currently playing.
    BargeIn,
    /// Switch STT provider or languages mid-call.
    ConfigureTranscription(ConfigureTranscription),
    /// Send an SMS from the account.
    SendSms(SendSms),
}

impl Action {
    /// Wraps a [`Speak`] payload.
    ///
    /// ```
    /// use sipgate_flow::{Action, Speak};
    ///
    /// let action = Action::speak_with("s1", Speak::text("Hallo")?)?;
    /// assert_eq!(action.kind(), "speak");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable session id.
    pub fn speak_with(session_id: impl Into<String>, speak: Speak) -> Result<Self> {
        Self::new(session_id, ActionKind::Speak(speak))
    }

    /// Speaks plain text. This is the common case:
    ///
    /// ```
    /// use sipgate_flow::Action;
    ///
    /// let action = Action::speak("s1", "Einen Moment bitte.")?;
    /// assert_eq!(action.to_json()["text"], "Einen Moment bitte.");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty text or an unusable session id.
    pub fn speak(session_id: impl Into<String>, text: impl Into<String>) -> Result<Self> {
        Self::speak_with(session_id, Speak::text(text)?)
    }

    /// Speaks SSML. Exactly one of `text` and `ssml` may be set, per the
    /// documented contract.
    ///
    /// ```
    /// use sipgate_flow::Action;
    ///
    /// let ssml = r#"<speak version="1.0" xml:lang="de-DE">Hallo</speak>"#;
    /// let action = Action::speak_ssml("s1", ssml)?;
    /// assert_eq!(action.to_json()["ssml"], ssml);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty SSML string or an unusable session
    /// id.
    pub fn speak_ssml(session_id: impl Into<String>, ssml: impl Into<String>) -> Result<Self> {
        Self::speak_with(session_id, Speak::ssml(ssml)?)
    }

    /// Plays a pre-recorded clip once.
    ///
    /// ```
    /// use sipgate_flow::{Action, Audio};
    ///
    /// let clip = Audio::base64("UklGRiQAAABXQVZF")?;
    /// let action = Action::audio("s1", clip)?;
    /// assert_eq!(action.kind(), "audio");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable session id.
    pub fn audio(session_id: impl Into<String>, audio: Audio) -> Result<Self> {
        Self::new(session_id, ActionKind::Audio(audio))
    }

    /// Plays already-encoded WAV data.
    ///
    /// ```
    /// use sipgate_flow::Action;
    ///
    /// let action = Action::audio_base64("s1", "UklGRiQAAABXQVZF")?;
    /// assert_eq!(action.to_json()["audio"], "UklGRiQAAABXQVZF");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the data is empty, not base64, or the session
    /// id is unusable.
    pub fn audio_base64(session_id: impl Into<String>, data: impl Into<String>) -> Result<Self> {
        Self::audio(session_id, Audio::base64(data)?)
    }

    /// Encodes and plays WAV bytes, rejecting a file the service would refuse
    /// to play (wrong container, wrong sample format).
    ///
    /// ```
    /// use sipgate_flow::Action;
    ///
    /// // 44-byte header + one sample, 16 kHz mono 16-bit.
    /// let wav = sipgate_flow::wav::pcm16_wav(&[0, 0], 16_000, 1).expect("a short clip");
    /// let action = Action::audio_wav("s1", &wav)?;
    /// assert!(action.to_json()["audio"].as_str().unwrap().starts_with("UklGR"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the bytes are not a 16 kHz mono 16-bit PCM
    /// WAV file, or the session id is unusable.
    pub fn audio_wav(session_id: impl Into<String>, wav: &[u8]) -> Result<Self> {
        Self::audio(session_id, Audio::wav(wav)?)
    }

    /// Starts or replaces the ambient loop.
    ///
    /// ```
    /// use sipgate_flow::{Action, MixAudio};
    ///
    /// let action = Action::mix_audio("s1", MixAudio::stop())?;
    /// assert_eq!(action.to_json()["stop"], true);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable session id.
    pub fn mix_audio(session_id: impl Into<String>, mix: MixAudio) -> Result<Self> {
        Self::new(session_id, ActionKind::MixAudio(mix))
    }

    /// Stops the ambient loop, if one is running.
    ///
    /// ```
    /// use sipgate_flow::Action;
    ///
    /// let action = Action::stop_audio("s1")?;
    /// assert_eq!(action.kind(), "mix_audio");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable session id.
    pub fn stop_audio(session_id: impl Into<String>) -> Result<Self> {
        Self::mix_audio(session_id, MixAudio::stop())
    }

    /// Ends the call.
    ///
    /// ```
    /// use sipgate_flow::Action;
    ///
    /// let action = Action::hangup("s1")?;
    /// assert_eq!(action.kind(), "hangup");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable session id.
    pub fn hangup(session_id: impl Into<String>) -> Result<Self> {
        Self::new(session_id, ActionKind::Hangup)
    }

    /// Transfers the call.
    ///
    /// ```
    /// use sipgate_flow::{Action, Transfer};
    ///
    /// let transfer = Transfer::new("4915112345678")?;
    /// let action = Action::transfer("s1", transfer)?;
    /// assert_eq!(action.to_json()["target_phone_number"], "4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable session id.
    pub fn transfer(session_id: impl Into<String>, transfer: Transfer) -> Result<Self> {
        Self::new(session_id, ActionKind::Transfer(transfer))
    }

    /// Stops the current playback immediately. Pair it with a follow-up action
    /// in an array when correcting yourself mid-sentence.
    ///
    /// ```
    /// use sipgate_flow::Action;
    ///
    /// let action = Action::barge_in("s1")?;
    /// assert_eq!(action.to_json(), serde_json::json!({"type": "barge_in", "session_id": "s1"}));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable session id.
    pub fn barge_in(session_id: impl Into<String>) -> Result<Self> {
        Self::new(session_id, ActionKind::BargeIn)
    }

    /// Reconfigures speech recognition for the rest of the session.
    ///
    /// ```
    /// use sipgate_flow::{Action, ConfigureTranscription};
    ///
    /// let config = ConfigureTranscription::new().with_languages(["de-DE"])?;
    /// let action = Action::configure_transcription("s1", config)?;
    /// assert_eq!(action.to_json()["languages"], serde_json::json!(["de-DE"]));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when no field is set (the service treats that as a
    /// no-op, so sending it is pointless) or the session id is unusable.
    pub fn configure_transcription(
        session_id: impl Into<String>,
        config: ConfigureTranscription,
    ) -> Result<Self> {
        if config.is_empty() {
            return Err(Error::validation(
                "configure_transcription",
                "set at least one of provider, languages, custom_vocabulary or vad",
            ));
        }
        Self::new(session_id, ActionKind::ConfigureTranscription(config))
    }

    /// Sends an SMS from the account; failures arrive later as `sms_failed`.
    ///
    /// ```
    /// use sipgate_flow::{Action, SendSms};
    ///
    /// let sms = SendSms::new("+4915112345678", "Ihr Code: 4242")?;
    /// let action = Action::send_sms("s1", sms)?;
    /// assert_eq!(action.to_json()["phone_number"], "4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable session id.
    pub fn send_sms(session_id: impl Into<String>, sms: SendSms) -> Result<Self> {
        Self::new(session_id, ActionKind::SendSms(sms))
    }

    fn new(session_id: impl Into<String>, kind: ActionKind) -> Result<Self> {
        let session_id = session_id.into();
        validate::path_segment("session_id", &session_id)?;
        Ok(Self { session_id, kind })
    }

    /// The session this action targets.
    ///
    /// ```
    /// use sipgate_flow::Action;
    /// assert_eq!(Action::hangup("s1")?.session_id(), "s1");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The wire `type` value.
    ///
    /// ```
    /// use sipgate_flow::Action;
    /// assert_eq!(Action::barge_in("s1")?.kind(), "barge_in");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self.kind {
            ActionKind::Speak(_) => "speak",
            ActionKind::Audio(_) => "audio",
            ActionKind::MixAudio(_) => "mix_audio",
            ActionKind::Hangup => "hangup",
            ActionKind::Transfer(_) => "transfer",
            ActionKind::BargeIn => "barge_in",
            ActionKind::ConfigureTranscription(_) => "configure_transcription",
            ActionKind::SendSms(_) => "send_sms",
        }
    }

    /// The typed body, for inspection or matching.
    ///
    /// ```
    /// use sipgate_flow::{Action, ActionKind, Speak};
    ///
    /// let action = Action::speak("s1", "hi")?;
    /// match action.body() {
    ///     ActionKind::Speak(speak) => assert_eq!(speak.text_value(), Some("hi")),
    ///     _ => unreachable!(),
    /// }
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn body(&self) -> &ActionKind {
        &self.kind
    }

    /// Renders the flat wire object.
    ///
    /// ```
    /// use sipgate_flow::Action;
    ///
    /// let action = Action::hangup("s1")?;
    /// assert_eq!(action.to_json(), serde_json::json!({"type": "hangup", "session_id": "s1"}));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("type".into(), json!(self.kind()));
        object.insert("session_id".into(), json!(self.session_id));
        match &self.kind {
            ActionKind::Speak(speak) => merge(&mut object, speak.to_json()),
            ActionKind::Audio(audio) => merge(&mut object, audio.to_json()),
            ActionKind::MixAudio(mix) => merge(&mut object, mix.to_json()),
            ActionKind::Transfer(transfer) => merge(&mut object, transfer.to_json()),
            ActionKind::ConfigureTranscription(config) => merge(&mut object, config.to_json()),
            ActionKind::SendSms(sms) => merge(&mut object, sms.to_json()),
            ActionKind::Hangup | ActionKind::BargeIn => {}
        }
        Value::Object(object)
    }
}

fn merge(target: &mut Map<String, Value>, source: Value) {
    if let Value::Object(source) = source {
        for (key, value) in source {
            target.insert(key, value);
        }
    }
}

/// `speak`: text *or* SSML, with optional TTS, barge-in, VAD and timeout
/// settings.
///
/// ```
/// use sipgate_flow::Speak;
///
/// let speak = Speak::text("Hallo")?;
/// assert_eq!(speak.to_json(), serde_json::json!({"text": "Hallo"}));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Speak {
    text: Option<String>,
    ssml: Option<String>,
    tts: Option<Tts>,
    barge_in: Option<BargeInConfig>,
    user_input_timeout_seconds: Option<u32>,
    vad: Option<Vad>,
}

impl Speak {
    /// Speak plain text.
    ///
    /// ```
    /// use sipgate_flow::Speak;
    /// assert_eq!(Speak::text("hi")?.text_value(), Some("hi"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the text is empty.
    pub fn text(text: impl Into<String>) -> Result<Self> {
        let text = text.into();
        validate::non_empty("text", &text)?;
        Ok(Self {
            text: Some(text),
            ..Self::default()
        })
    }

    /// Speak SSML.
    ///
    /// ```
    /// use sipgate_flow::Speak;
    /// assert!(Speak::ssml("<speak>hi</speak>")?.ssml_value().is_some());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the SSML is empty.
    pub fn ssml(ssml: impl Into<String>) -> Result<Self> {
        let ssml = ssml.into();
        validate::non_empty("ssml", &ssml)?;
        Ok(Self {
            ssml: Some(ssml),
            ..Self::default()
        })
    }

    /// The text, when speaking plain text.
    ///
    /// ```
    /// use sipgate_flow::Speak;
    /// assert_eq!(Speak::text("hi")?.text_value(), Some("hi"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn text_value(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// The SSML, when speaking SSML.
    ///
    /// ```
    /// use sipgate_flow::Speak;
    /// assert_eq!(Speak::ssml("<speak/>")?.ssml_value(), Some("<speak/>"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn ssml_value(&self) -> Option<&str> {
        self.ssml.as_deref()
    }

    /// Sets the TTS provider configuration.
    ///
    /// ```
    /// use sipgate_flow::{Speak, Tts};
    ///
    /// let speak = Speak::text("hi")?.with_tts(Tts::eleven_labs().with_voice("v1"));
    /// assert_eq!(speak.to_json()["tts"]["provider"], "eleven_labs");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn with_tts(mut self, tts: Tts) -> Self {
        self.tts = Some(tts);
        self
    }

    /// Sets the barge-in configuration.
    ///
    /// ```
    /// use sipgate_flow::{BargeInConfig, Speak};
    ///
    /// let speak = Speak::text("hi")?.with_barge_in(BargeInConfig::immediate());
    /// assert_eq!(speak.to_json()["barge_in"]["strategy"], "immediate");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn with_barge_in(mut self, config: BargeInConfig) -> Self {
        self.barge_in = Some(config);
        self
    }

    /// Arms a `user_input_timeout` event for after the speech ends.
    ///
    /// ```
    /// use sipgate_flow::Speak;
    ///
    /// let speak = Speak::text("Wie lautet Ihre Nummer?")?.with_user_input_timeout(5)?;
    /// assert_eq!(speak.to_json()["user_input_timeout_seconds"], 5);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `seconds` is zero (a zero timeout would fire
    /// immediately and is not documented as meaningful).
    pub fn with_user_input_timeout(mut self, seconds: u32) -> Result<Self> {
        if seconds == 0 {
            return Err(Error::validation(
                "user_input_timeout_seconds",
                "must be at least 1",
            ));
        }
        self.user_input_timeout_seconds = Some(seconds);
        Ok(self)
    }

    /// Sets the end-of-turn silence window for the caller's reply.
    ///
    /// ```
    /// use sipgate_flow::{Speak, Vad};
    ///
    /// let speak = Speak::text("Bitte buchstabieren Sie.")?.with_vad(Vad::new(1500));
    /// assert_eq!(speak.to_json()["vad"]["end_of_turn_silence_ms"], 1500);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn with_vad(mut self, vad: Vad) -> Self {
        self.vad = Some(vad);
        self
    }

    /// Renders the action's own fields (without `type` and `session_id`).
    ///
    /// ```
    /// use sipgate_flow::Speak;
    /// assert_eq!(Speak::text("hi")?.to_json(), serde_json::json!({"text": "hi"}));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        if let Some(text) = &self.text {
            object.insert("text".into(), json!(text));
        }
        if let Some(ssml) = &self.ssml {
            object.insert("ssml".into(), json!(ssml));
        }
        if let Some(tts) = &self.tts {
            object.insert("tts".into(), tts.to_json());
        }
        if let Some(barge_in) = &self.barge_in {
            object.insert("barge_in".into(), barge_in.to_json());
        }
        if let Some(seconds) = self.user_input_timeout_seconds {
            object.insert("user_input_timeout_seconds".into(), json!(seconds));
        }
        if let Some(vad) = &self.vad {
            object.insert("vad".into(), vad.to_json());
        }
        Value::Object(object)
    }
}

/// TTS provider configuration for [`Speak`].
///
/// The providers documented on <https://flow.sipgate.io/api/tts-providers> are
/// `kugelaudio`, `azure` and `eleven_labs`; `openai` appears in the official
/// SDK's action schema (`TtsConfigOpenAiSchema`, `@sipgate/ai-flow-sdk` 2.1.0)
/// and is modelled here because the service accepts it there.
///
/// ```
/// use sipgate_flow::Tts;
///
/// assert_eq!(Tts::azure().with_language("de-DE").to_json()["language"], "de-DE");
/// assert_eq!(Tts::eleven_labs().to_json()["provider"], "eleven_labs");
/// assert_eq!(Tts::kugelaudio().with_voice("963").to_json()["voice"], "963");
/// assert_eq!(Tts::openai().with_voice("alloy").to_json()["provider"], "openai");
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Tts {
    /// Azure Speech.
    Azure {
        /// BCP-47 language, for example `de-DE`.
        language: Option<String>,
        /// Azure voice name, for example `de-DE-KatjaNeural`.
        voice: Option<String>,
    },
    /// `ElevenLabs`.
    ElevenLabs {
        /// `ElevenLabs` voice id; the provider default when omitted.
        voice: Option<String>,
    },
    /// `Kugelaudio`, sipgate's own voice set (`963` is the house voice).
    Kugelaudio {
        /// Language code, for example `de`.
        language: Option<String>,
        /// Voice id, for example `963` or `972`.
        voice: Option<String>,
        /// Speaking rate; the provider default applies when unset. Only this
        /// provider's schema carries the field.
        speed: Option<f32>,
    },
    /// `OpenAI` voices (`alloy`, `echo`, `fable`, `onyx`, `nova`, `shimmer`,
    /// `coral`, `sage`); they are listed in the SDK's schema, not on the TTS
    /// documentation page.
    OpenAi {
        /// Voice name; the provider default when omitted.
        voice: Option<String>,
    },
}

impl Tts {
    /// The Azure provider, with its default voice.
    ///
    /// ```
    /// use sipgate_flow::Tts;
    /// assert_eq!(Tts::azure().to_json()["provider"], "azure");
    /// ```
    #[must_use]
    pub fn azure() -> Self {
        Self::Azure {
            language: None,
            voice: None,
        }
    }

    /// The `ElevenLabs` provider, with its default voice.
    ///
    /// ```
    /// use sipgate_flow::Tts;
    /// assert_eq!(Tts::eleven_labs().to_json()["provider"], "eleven_labs");
    /// ```
    #[must_use]
    pub fn eleven_labs() -> Self {
        Self::ElevenLabs { voice: None }
    }

    /// The `Kugelaudio` provider, with the sipgate house voice.
    ///
    /// ```
    /// use sipgate_flow::Tts;
    /// assert_eq!(Tts::kugelaudio().to_json()["provider"], "kugelaudio");
    /// ```
    #[must_use]
    pub fn kugelaudio() -> Self {
        Self::Kugelaudio {
            language: None,
            voice: None,
            speed: None,
        }
    }

    /// The `OpenAI` provider, with its default voice.
    ///
    /// ```
    /// use sipgate_flow::Tts;
    /// assert_eq!(Tts::openai().to_json()["provider"], "openai");
    /// ```
    #[must_use]
    pub fn openai() -> Self {
        Self::OpenAi { voice: None }
    }

    /// Sets the language where the provider takes one (Azure, `Kugelaudio`);
    /// ignored by the others, which pick it from the voice.
    ///
    /// ```
    /// use sipgate_flow::Tts;
    /// assert_eq!(Tts::azure().with_language("en-US").to_json()["language"], "en-US");
    /// assert_eq!(Tts::eleven_labs().with_language("en-US").to_json().get("language"), None);
    /// ```
    #[must_use]
    pub fn with_language(self, language: impl Into<String>) -> Self {
        let language = language.into();
        match self {
            Self::Azure { voice, .. } => Self::Azure {
                language: Some(language),
                voice,
            },
            Self::Kugelaudio { voice, speed, .. } => Self::Kugelaudio {
                language: Some(language),
                voice,
                speed,
            },
            other => other,
        }
    }

    /// Sets the voice.
    ///
    /// ```
    /// use sipgate_flow::Tts;
    /// assert_eq!(Tts::eleven_labs().with_voice("abc").to_json()["voice"], "abc");
    /// ```
    #[must_use]
    pub fn with_voice(self, voice: impl Into<String>) -> Self {
        let voice = voice.into();
        match self {
            Self::Azure { language, .. } => Self::Azure {
                language,
                voice: Some(voice),
            },
            Self::ElevenLabs { .. } => Self::ElevenLabs { voice: Some(voice) },
            Self::Kugelaudio {
                language, speed, ..
            } => Self::Kugelaudio {
                language,
                voice: Some(voice),
                speed,
            },
            Self::OpenAi { .. } => Self::OpenAi { voice: Some(voice) },
        }
    }

    /// Sets the speaking rate (`Kugelaudio` only; ignored by the others, which
    /// do not document the field).
    ///
    /// A non-finite value is dropped rather than sent: the wire has no encoding
    /// for `NaN` and a provider would reject it anyway.
    ///
    /// ```
    /// use sipgate_flow::Tts;
    ///
    /// assert_eq!(Tts::kugelaudio().with_speed(1.25).to_json()["speed"], 1.25);
    /// assert!(Tts::kugelaudio().with_speed(f32::NAN).to_json().get("speed").is_none());
    /// assert!(Tts::azure().with_speed(1.25).to_json().get("speed").is_none());
    /// ```
    #[must_use]
    pub fn with_speed(self, speed: f32) -> Self {
        match self {
            Self::Kugelaudio {
                language, voice, ..
            } => Self::Kugelaudio {
                language,
                voice,
                speed: if speed.is_finite() { Some(speed) } else { None },
            },
            other => other,
        }
    }

    /// Renders the `tts` object.
    ///
    /// ```
    /// use sipgate_flow::Tts;
    /// assert_eq!(
    ///     Tts::azure().to_json(),
    ///     serde_json::json!({"provider": "azure"})
    /// );
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        let mut push = |key: &str, value: Option<Value>| {
            if let Some(value) = value {
                object.insert(key.to_string(), value);
            }
        };
        match self {
            Self::Azure { language, voice } => {
                push("provider", Some(json!("azure")));
                push("language", language.as_ref().map(|v| json!(v)));
                push("voice", voice.as_ref().map(|v| json!(v)));
            }
            Self::ElevenLabs { voice } => {
                push("provider", Some(json!("eleven_labs")));
                push("voice", voice.as_ref().map(|v| json!(v)));
            }
            Self::Kugelaudio {
                language,
                voice,
                speed,
            } => {
                push("provider", Some(json!("kugelaudio")));
                push("language", language.as_ref().map(|v| json!(v)));
                push("voice", voice.as_ref().map(|v| json!(v)));
                push(
                    "speed",
                    speed.filter(|value| value.is_finite()).map(|v| json!(v)),
                );
            }
            Self::OpenAi { voice } => {
                push("provider", Some(json!("openai")));
                push("voice", voice.as_ref().map(|v| json!(v)));
            }
        }
        Value::Object(object)
    }
}

/// How the caller may interrupt playback, attached to `speak` or `audio`.
///
/// Not to be confused with the [`Action::barge_in`] *action*, which interrupts
/// playback from the application side.
///
/// ```
/// use sipgate_flow::BargeInConfig;
///
/// assert_eq!(
///     BargeInConfig::none().to_json(),
///     serde_json::json!({"strategy": "none"})
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BargeInConfig {
    strategy: BargeInStrategy,
    minimum_characters: Option<u32>,
    allow_after_ms: Option<u32>,
}

/// The documented barge-in strategies.
///
/// ```
/// use sipgate_flow::BargeInStrategy;
///
/// assert_eq!(BargeInStrategy::Immediate.as_str(), "immediate");
/// assert_eq!(BargeInStrategy::from_wire("manual").as_str(), "manual");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BargeInStrategy {
    /// No interruption at all.
    None,
    /// Interruption only through the `barge_in` action.
    Manual,
    /// Interruption once the caller said `minimum_characters` characters.
    MinimumCharacters,
    /// Interruption as soon as voice activity is detected.
    Immediate,
    /// A value this crate does not model yet.
    Other(String),
}

impl BargeInStrategy {
    /// Maps a wire value, keeping unknown values verbatim.
    ///
    /// ```
    /// use sipgate_flow::BargeInStrategy;
    /// assert_eq!(BargeInStrategy::from_wire("immediate"), BargeInStrategy::Immediate);
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "none" => Self::None,
            "manual" => Self::Manual,
            "minimum_characters" => Self::MinimumCharacters,
            "immediate" => Self::Immediate,
            other => Self::Other(other.to_string()),
        }
    }

    /// The wire value.
    ///
    /// ```
    /// use sipgate_flow::BargeInStrategy;
    /// assert_eq!(BargeInStrategy::MinimumCharacters.as_str(), "minimum_characters");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Manual => "manual",
            Self::MinimumCharacters => "minimum_characters",
            Self::Immediate => "immediate",
            Self::Other(value) => value,
        }
    }
}

impl BargeInConfig {
    /// Disables interruption.
    ///
    /// ```
    /// use sipgate_flow::BargeInConfig;
    /// assert_eq!(BargeInConfig::none().strategy().as_str(), "none");
    /// ```
    #[must_use]
    pub fn none() -> Self {
        Self::with_strategy(BargeInStrategy::None)
    }

    /// Allows interruption only through the `barge_in` action.
    ///
    /// ```
    /// use sipgate_flow::BargeInConfig;
    /// assert_eq!(BargeInConfig::manual().to_json()["strategy"], "manual");
    /// ```
    #[must_use]
    pub fn manual() -> Self {
        Self::with_strategy(BargeInStrategy::Manual)
    }

    /// Interrupts as soon as voice activity is detected.
    ///
    /// ```
    /// use sipgate_flow::BargeInConfig;
    /// assert_eq!(BargeInConfig::immediate().to_json()["strategy"], "immediate");
    /// ```
    #[must_use]
    pub fn immediate() -> Self {
        Self::with_strategy(BargeInStrategy::Immediate)
    }

    /// Interrupts after `characters` recognised characters. The documented
    /// range is 1..=100; the default is 3.
    ///
    /// ```
    /// use sipgate_flow::BargeInConfig;
    ///
    /// assert_eq!(BargeInConfig::minimum_characters(5)?.to_json()["minimum_characters"], 5);
    /// assert!(BargeInConfig::minimum_characters(0).is_err());
    /// assert!(BargeInConfig::minimum_characters(101).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] outside 1..=100.
    pub fn minimum_characters(characters: u32) -> Result<Self> {
        if !(1..=100).contains(&characters) {
            return Err(Error::validation(
                "minimum_characters",
                "must be within 1..=100",
            ));
        }
        Ok(Self {
            strategy: BargeInStrategy::MinimumCharacters,
            minimum_characters: Some(characters),
            allow_after_ms: None,
        })
    }

    /// An explicit strategy, for one this crate does not know.
    ///
    /// ```
    /// use sipgate_flow::{BargeInConfig, BargeInStrategy};
    ///
    /// let config = BargeInConfig::with_strategy(BargeInStrategy::Other("someday".into()));
    /// assert_eq!(config.to_json()["strategy"], "someday");
    /// ```
    #[must_use]
    pub fn with_strategy(strategy: BargeInStrategy) -> Self {
        Self {
            strategy,
            minimum_characters: None,
            allow_after_ms: None,
        }
    }

    /// Ignores interruptions during the first `milliseconds` of playback.
    ///
    /// ```
    /// use sipgate_flow::BargeInConfig;
    ///
    /// let config = BargeInConfig::immediate().with_allow_after_ms(500);
    /// assert_eq!(config.to_json()["allow_after_ms"], 500);
    /// ```
    #[must_use]
    pub fn with_allow_after_ms(mut self, milliseconds: u32) -> Self {
        self.allow_after_ms = Some(milliseconds);
        self
    }

    /// The configured strategy.
    ///
    /// ```
    /// use sipgate_flow::BargeInConfig;
    /// assert_eq!(BargeInConfig::manual().strategy().as_str(), "manual");
    /// ```
    #[must_use]
    pub fn strategy(&self) -> &BargeInStrategy {
        &self.strategy
    }

    /// Renders the `barge_in` object.
    ///
    /// ```
    /// use sipgate_flow::BargeInConfig;
    ///
    /// let config = BargeInConfig::minimum_characters(3)?.with_allow_after_ms(200);
    /// assert_eq!(
    ///     config.to_json(),
    ///     serde_json::json!({"strategy": "minimum_characters", "minimum_characters": 3, "allow_after_ms": 200})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("strategy".into(), json!(self.strategy.as_str()));
        if let Some(characters) = self.minimum_characters {
            object.insert("minimum_characters".into(), json!(characters));
        }
        if let Some(milliseconds) = self.allow_after_ms {
            object.insert("allow_after_ms".into(), json!(milliseconds));
        }
        Value::Object(object)
    }
}

/// End-of-turn silence tuning, accepted by `speak` and
/// `configure_transcription`.
///
/// The documentation recommends 150–2000 ms but states that out-of-range values
/// are ignored by the service rather than rejected, so this type does not
/// enforce the range.
///
/// ```
/// use sipgate_flow::Vad;
///
/// assert_eq!(Vad::new(1200).to_json(), serde_json::json!({"end_of_turn_silence_ms": 1200}));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vad {
    end_of_turn_silence_ms: u32,
}

impl Vad {
    /// Silence in milliseconds before the caller's turn is considered finished.
    ///
    /// ```
    /// use sipgate_flow::Vad;
    /// assert_eq!(Vad::new(250).end_of_turn_silence_ms(), 250);
    /// ```
    #[must_use]
    pub fn new(end_of_turn_silence_ms: u32) -> Self {
        Self {
            end_of_turn_silence_ms,
        }
    }

    /// The configured window.
    ///
    /// ```
    /// use sipgate_flow::Vad;
    /// assert_eq!(Vad::new(1500).end_of_turn_silence_ms(), 1500);
    /// ```
    #[must_use]
    pub fn end_of_turn_silence_ms(&self) -> u32 {
        self.end_of_turn_silence_ms
    }

    /// Renders the `vad` object.
    ///
    /// ```
    /// use sipgate_flow::Vad;
    /// assert_eq!(Vad::new(500).to_json()["end_of_turn_silence_ms"], 500);
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "end_of_turn_silence_ms": self.end_of_turn_silence_ms })
    }
}

/// `audio`: a single base64 WAV clip (16 kHz, mono, 16-bit PCM).
///
/// ```
/// use sipgate_flow::Audio;
///
/// let clip = Audio::base64("UklGRiQAAABXQVZF")?;
/// assert_eq!(clip.to_json()["audio"], "UklGRiQAAABXQVZF");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Audio {
    data: String,
    barge_in: Option<BargeInConfig>,
}

impl Audio {
    /// Wraps already-encoded base64 WAV data, checking the alphabet and padding
    /// but not the container (that would need a decode).
    ///
    /// ```
    /// use sipgate_flow::Audio;
    ///
    /// assert!(Audio::base64("UklGRiQAAABXQVZF").is_ok());
    /// assert!(Audio::base64("not base64!").is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for empty or malformed base64.
    pub fn base64(data: impl Into<String>) -> Result<Self> {
        let data = data.into();
        validate::non_empty("audio", &data)?;
        if !base64::is_valid(&data) {
            return Err(Error::validation(
                "audio",
                "must be standard base64 (RFC 4648) WAV data",
            ));
        }
        Ok(Self {
            data,
            barge_in: None,
        })
    }

    /// Encodes WAV bytes after checking the container is one the service plays:
    /// RIFF/WAVE with a 16-bit PCM mono `fmt` chunk.
    ///
    /// ```
    /// use sipgate_flow::Audio;
    ///
    /// let wav = sipgate_flow::wav::pcm16_wav(&[1, 2, 3, 4], 16_000, 1).expect("a short clip");
    /// let clip = Audio::wav(&wav)?;
    /// assert!(clip.base64_data().starts_with("UklGR"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the bytes are not a 16-bit PCM mono WAV file.
    pub fn wav(wav_bytes: &[u8]) -> Result<Self> {
        crate::wav::validate_pcm16(wav_bytes, 16_000, 1)?;
        Self::base64(base64::encode(wav_bytes))
    }

    /// The encoded audio.
    ///
    /// ```
    /// use sipgate_flow::Audio;
    /// assert_eq!(Audio::base64("UklGRiQAAABXQVZF")?.base64_data(), "UklGRiQAAABXQVZF");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn base64_data(&self) -> &str {
        &self.data
    }

    /// Sets the barge-in configuration.
    ///
    /// ```
    /// use sipgate_flow::{Audio, BargeInConfig};
    ///
    /// let clip = Audio::base64("UklGRiQAAABXQVZF")?.with_barge_in(BargeInConfig::none());
    /// assert_eq!(clip.to_json()["barge_in"]["strategy"], "none");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn with_barge_in(mut self, config: BargeInConfig) -> Self {
        self.barge_in = Some(config);
        self
    }

    /// Renders the action's own fields.
    ///
    /// ```
    /// use sipgate_flow::Audio;
    /// assert_eq!(
    ///     Audio::base64("UklGRiQAAABXQVZF")?.to_json(),
    ///     serde_json::json!({"audio": "UklGRiQAAABXQVZF"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("audio".into(), json!(self.data));
        if let Some(barge_in) = &self.barge_in {
            object.insert("barge_in".into(), barge_in.to_json());
        }
        Value::Object(object)
    }
}

/// `mix_audio`: a looping background sound, or the instruction to stop it.
///
/// ```
/// use sipgate_flow::MixAudio;
///
/// assert_eq!(MixAudio::stop().to_json(), serde_json::json!({"stop": true}));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct MixAudio {
    audio: Option<String>,
    volume: Option<f32>,
    stop: bool,
}

impl MixAudio {
    /// Starts (or replaces) the loop with a validated clip.
    ///
    /// ```
    /// use sipgate_flow::{Audio, MixAudio};
    ///
    /// let clip = Audio::base64("UklGRiQAAABXQVZF")?;
    /// let mix = MixAudio::start(&clip)?.with_volume(0.3)?;
    /// assert_eq!(mix.to_json()["volume"], serde_json::json!(0.3_f32));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the clip cannot be used.
    pub fn start(clip: &Audio) -> Result<Self> {
        Ok(Self {
            audio: Some(clip.base64_data().to_string()),
            volume: None,
            stop: false,
        })
    }

    /// Starts the loop from raw base64 data.
    ///
    /// ```
    /// use sipgate_flow::MixAudio;
    /// assert!(MixAudio::start_base64("UklGRiQAAABXQVZF")?.is_started());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the data is empty or not base64.
    pub fn start_base64(data: impl Into<String>) -> Result<Self> {
        Ok(Self {
            audio: Some(Audio::base64(data)?.base64_data().to_string()),
            volume: None,
            stop: false,
        })
    }

    /// Removes the active loop.
    ///
    /// ```
    /// use sipgate_flow::MixAudio;
    /// assert!(MixAudio::stop().is_stop());
    /// ```
    #[must_use]
    pub fn stop() -> Self {
        Self {
            audio: None,
            volume: None,
            stop: true,
        }
    }

    /// Sets the loop volume, 0.0..=1.0 (documented default 0.5). `NaN` and
    /// infinities are rejected.
    ///
    /// ```
    /// use sipgate_flow::MixAudio;
    ///
    /// assert!(MixAudio::start_base64("UklGRiQAAABXQVZF")?.with_volume(1.0).is_ok());
    /// assert!(MixAudio::start_base64("UklGRiQAAABXQVZF")?.with_volume(f32::NAN).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the volume is not finite or outside 0..=1.
    pub fn with_volume(mut self, volume: f32) -> Result<Self> {
        if !(0.0..=1.0).contains(&volume) {
            return Err(Error::validation("volume", "must be within 0.0..=1.0"));
        }
        self.volume = Some(volume);
        Ok(self)
    }

    /// Whether this call starts a loop rather than stopping one.
    ///
    /// ```
    /// use sipgate_flow::MixAudio;
    /// assert!(!MixAudio::stop().is_started());
    /// ```
    #[must_use]
    pub fn is_started(&self) -> bool {
        self.audio.is_some() && !self.stop
    }

    /// Whether this call stops the loop.
    ///
    /// ```
    /// use sipgate_flow::MixAudio;
    /// assert!(MixAudio::stop().is_stop());
    /// ```
    #[must_use]
    pub fn is_stop(&self) -> bool {
        self.stop
    }

    /// Renders the action's own fields.
    ///
    /// ```
    /// use sipgate_flow::MixAudio;
    /// assert_eq!(
    ///     MixAudio::start_base64("UklGRiQAAABXQVZF")?.to_json(),
    ///     serde_json::json!({"audio": "UklGRiQAAABXQVZF"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        if let Some(audio) = &self.audio {
            object.insert("audio".into(), json!(audio));
        }
        if let Some(volume) = self.volume {
            object.insert("volume".into(), json!(volume));
        }
        if self.stop {
            object.insert("stop".into(), json!(true));
        }
        Value::Object(object)
    }
}

/// `transfer`: hand the call to another number, optionally with fallback.
///
/// `timeout` is what turns a failed transfer into a returning `session_start`
/// with a `transfer_failed_reason`; without it a failed transfer ends the call.
///
/// ```
/// use sipgate_flow::Transfer;
///
/// let transfer = Transfer::new("4915112345678")?
///     .with_caller_id("Support", "4921112345678")?
///     .with_timeout(30)?;
/// assert_eq!(transfer.to_json()["timeout"], 30);
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    target_phone_number: String,
    caller_id_name: Option<String>,
    caller_id_number: Option<String>,
    timeout: Option<u32>,
}

impl Transfer {
    /// A blind transfer to `target`, in E.164 digits (a leading `+` is
    /// accepted and stripped).
    ///
    /// The documentation marks `caller_id_name` and `caller_id_number` as
    /// required, yet its own DTMF example sends neither — so they are optional
    /// here and simply omitted from the wire, which the service accepts.
    ///
    /// ```
    /// use sipgate_flow::Transfer;
    /// assert_eq!(Transfer::new("+4915112345678")?.target_phone_number(), "4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the number is not 1..=15 digits.
    pub fn new(target_phone_number: impl Into<String>) -> Result<Self> {
        let target = validate::phone("target_phone_number", &target_phone_number.into())?;
        Ok(Self {
            target_phone_number: target,
            caller_id_name: None,
            caller_id_number: None,
            timeout: None,
        })
    }

    /// Sets the caller id shown to the transfer target.
    ///
    /// ```
    /// use sipgate_flow::Transfer;
    ///
    /// let transfer = Transfer::new("4915112345678")?.with_caller_id("Support", "4921112345678")?;
    /// assert_eq!(transfer.to_json()["caller_id_name"], "Support");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty name or an unusable number.
    pub fn with_caller_id(
        mut self,
        name: impl Into<String>,
        number: impl Into<String>,
    ) -> Result<Self> {
        let name = name.into();
        validate::non_empty("caller_id_name", &name)?;
        self.caller_id_number = Some(validate::phone("caller_id_number", &number.into())?);
        self.caller_id_name = Some(name);
        Ok(self)
    }

    /// Enables transfer fallback with a 5..=120 second timeout.
    ///
    /// ```
    /// use sipgate_flow::Transfer;
    ///
    /// assert!(Transfer::new("4915112345678")?.with_timeout(30).is_ok());
    /// assert!(Transfer::new("4915112345678")?.with_timeout(4).is_err());
    /// assert!(Transfer::new("4915112345678")?.with_timeout(121).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] outside the documented 5..=120 range.
    pub fn with_timeout(mut self, seconds: u32) -> Result<Self> {
        if !(5..=120).contains(&seconds) {
            return Err(Error::validation(
                "timeout",
                "must be within 5..=120 seconds",
            ));
        }
        self.timeout = Some(seconds);
        Ok(self)
    }

    /// The normalised target number.
    ///
    /// ```
    /// use sipgate_flow::Transfer;
    /// assert_eq!(Transfer::new("4915112345678")?.target_phone_number(), "4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn target_phone_number(&self) -> &str {
        &self.target_phone_number
    }

    /// Renders the action's own fields.
    ///
    /// ```
    /// use sipgate_flow::Transfer;
    /// assert_eq!(
    ///     Transfer::new("4915112345678")?.to_json(),
    ///     serde_json::json!({"target_phone_number": "4915112345678"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert(
            "target_phone_number".into(),
            json!(self.target_phone_number),
        );
        if let Some(name) = &self.caller_id_name {
            object.insert("caller_id_name".into(), json!(name));
        }
        if let Some(number) = &self.caller_id_number {
            object.insert("caller_id_number".into(), json!(number));
        }
        if let Some(timeout) = self.timeout {
            object.insert("timeout".into(), json!(timeout));
        }
        Value::Object(object)
    }
}

/// The STT providers `configure_transcription` accepts.
///
/// ```
/// use sipgate_flow::TranscriptionProvider;
///
/// assert_eq!(TranscriptionProvider::Deepgram.as_str(), "DEEPGRAM");
/// assert_eq!(TranscriptionProvider::from_wire("deepgram").as_str(), "DEEPGRAM");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TranscriptionProvider {
    /// Azure Speech.
    Azure,
    /// Azure Voice Live (experimental).
    AzureVoiceLive,
    /// Deepgram.
    Deepgram,
    /// `ElevenLabs`.
    ElevenLabs,
    /// Qwen, hosted by sipgate.
    SipgateQwen,
    /// Parakeet, hosted by sipgate.
    SipgateParakeet,
    /// A provider this crate does not model yet.
    Other(String),
}

impl TranscriptionProvider {
    /// Maps a wire value (case-insensitive: the docs use upper case, some
    /// examples use lower), keeping unknown values verbatim.
    ///
    /// ```
    /// use sipgate_flow::TranscriptionProvider;
    /// assert_eq!(TranscriptionProvider::from_wire("ELEVEN_LABS"), TranscriptionProvider::ElevenLabs);
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "AZURE" => Self::Azure,
            "AZURE_VOICE_LIVE" => Self::AzureVoiceLive,
            "DEEPGRAM" => Self::Deepgram,
            "ELEVEN_LABS" => Self::ElevenLabs,
            "SIPGATE_QWEN" => Self::SipgateQwen,
            "SIPGATE_PARAKEET" => Self::SipgateParakeet,
            _ => Self::Other(value.to_string()),
        }
    }

    /// The wire value, upper case as documented.
    ///
    /// ```
    /// use sipgate_flow::TranscriptionProvider;
    /// assert_eq!(TranscriptionProvider::SipgateQwen.as_str(), "SIPGATE_QWEN");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Azure => "AZURE",
            Self::AzureVoiceLive => "AZURE_VOICE_LIVE",
            Self::Deepgram => "DEEPGRAM",
            Self::ElevenLabs => "ELEVEN_LABS",
            Self::SipgateQwen => "SIPGATE_QWEN",
            Self::SipgateParakeet => "SIPGATE_PARAKEET",
            Self::Other(value) => value,
        }
    }

    /// Whether the provider can detect several languages at once. Only the
    /// first code is used by the others.
    ///
    /// ```
    /// use sipgate_flow::TranscriptionProvider;
    ///
    /// assert!(TranscriptionProvider::Deepgram.supports_multiple_languages());
    /// assert!(!TranscriptionProvider::ElevenLabs.supports_multiple_languages());
    /// ```
    #[must_use]
    pub fn supports_multiple_languages(&self) -> bool {
        matches!(self, Self::Azure | Self::AzureVoiceLive | Self::Deepgram)
    }
}

/// `configure_transcription`: switch STT provider, languages or vocabulary
/// mid-call. Every field uses full-replace semantics.
///
/// ```
/// use sipgate_flow::{ConfigureTranscription, TranscriptionProvider};
///
/// let config = ConfigureTranscription::new()
///     .with_provider(TranscriptionProvider::Deepgram)
///     .with_languages(["de-DE", "en-US"])?;
/// assert_eq!(config.to_json()["provider"], "DEEPGRAM");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigureTranscription {
    provider: Option<TranscriptionProvider>,
    languages: Option<Vec<String>>,
    custom_vocabulary: Option<Vec<String>>,
    vad: Option<Vad>,
}

impl ConfigureTranscription {
    /// An empty configuration; add at least one field before sending.
    ///
    /// ```
    /// use sipgate_flow::ConfigureTranscription;
    /// assert!(ConfigureTranscription::new().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Switches to `provider`.
    ///
    /// ```
    /// use sipgate_flow::{ConfigureTranscription, TranscriptionProvider};
    ///
    /// let config = ConfigureTranscription::new().with_provider(TranscriptionProvider::Deepgram);
    /// assert_eq!(config.to_json()["provider"], "DEEPGRAM");
    /// ```
    #[must_use]
    pub fn with_provider(mut self, provider: TranscriptionProvider) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Replaces the recognition languages with 1..=4 BCP-47 tags.
    ///
    /// ```
    /// use sipgate_flow::ConfigureTranscription;
    ///
    /// assert_eq!(
    ///     ConfigureTranscription::new().with_languages(["de-DE"])?.to_json()["languages"],
    ///     serde_json::json!(["de-DE"])
    /// );
    /// assert!(ConfigureTranscription::new().with_languages(Vec::<String>::new()).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for zero or more than four tags, or a malformed
    /// tag.
    pub fn with_languages<I, S>(mut self, languages: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let languages = languages.into_iter().map(Into::into).collect::<Vec<_>>();
        if languages.is_empty() || languages.len() > 4 {
            return Err(Error::validation(
                "languages",
                "must contain between 1 and 4 BCP-47 codes",
            ));
        }
        for language in &languages {
            validate::language_tag("languages", language)?;
        }
        self.languages = Some(languages);
        Ok(self)
    }

    /// Replaces the session vocabulary: at most 100 entries of at most 200
    /// characters each.
    ///
    /// ```
    /// use sipgate_flow::ConfigureTranscription;
    ///
    /// let config = ConfigureTranscription::new().with_vocabulary(["sipgate", "VoIP"])?;
    /// assert_eq!(config.to_json()["custom_vocabulary"], serde_json::json!(["sipgate", "VoIP"]));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty, oversized or over-long entry.
    pub fn with_vocabulary<I, S>(mut self, vocabulary: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let vocabulary = vocabulary.into_iter().map(Into::into).collect::<Vec<_>>();
        if vocabulary.len() > 100 {
            return Err(Error::validation(
                "custom_vocabulary",
                "must contain at most 100 entries",
            ));
        }
        for entry in &vocabulary {
            validate::non_empty("custom_vocabulary", entry)?;
            if entry.chars().count() > 200 {
                return Err(Error::validation(
                    "custom_vocabulary",
                    "each entry must be at most 200 characters",
                ));
            }
        }
        self.custom_vocabulary = Some(vocabulary);
        Ok(self)
    }

    /// Applies VAD settings for the rest of the session.
    ///
    /// ```
    /// use sipgate_flow::{ConfigureTranscription, Vad};
    ///
    /// let config = ConfigureTranscription::new().with_vad(Vad::new(1200));
    /// assert_eq!(config.to_json()["vad"]["end_of_turn_silence_ms"], 1200);
    /// ```
    #[must_use]
    pub fn with_vad(mut self, vad: Vad) -> Self {
        self.vad = Some(vad);
        self
    }

    /// Whether no field is set, which the service treats as a no-op.
    ///
    /// ```
    /// use sipgate_flow::ConfigureTranscription;
    /// assert!(ConfigureTranscription::new().is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.provider.is_none()
            && self.languages.is_none()
            && self.custom_vocabulary.is_none()
            && self.vad.is_none()
    }

    /// Renders the action's own fields.
    ///
    /// ```
    /// use sipgate_flow::ConfigureTranscription;
    ///
    /// assert_eq!(
    ///     ConfigureTranscription::new().with_languages(["de-DE"])?.to_json(),
    ///     serde_json::json!({"languages": ["de-DE"]})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        if let Some(provider) = &self.provider {
            object.insert("provider".into(), json!(provider.as_str()));
        }
        if let Some(languages) = &self.languages {
            object.insert("languages".into(), json!(languages));
        }
        if let Some(vocabulary) = &self.custom_vocabulary {
            object.insert("custom_vocabulary".into(), json!(vocabulary));
        }
        if let Some(vad) = &self.vad {
            object.insert("vad".into(), vad.to_json());
        }
        Value::Object(object)
    }
}

/// `send_sms`: a fire-and-forget text message from the account.
///
/// ```
/// use sipgate_flow::SendSms;
///
/// let sms = SendSms::new("4915112345678", "Ihr Code: 4242")?;
/// assert_eq!(sms.phone_number(), "4915112345678");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendSms {
    phone_number: String,
    message: String,
}

impl SendSms {
    /// Builds the action. The number is normalised to E.164 digits without a
    /// leading `+`, which is the form the documentation prefers (it strips a
    /// `+` anyway).
    ///
    /// ```
    /// use sipgate_flow::SendSms;
    ///
    /// assert_eq!(SendSms::new("+4915112345678", "hi")?.phone_number(), "4915112345678");
    /// assert!(SendSms::new("4915112345678", "").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a non-E.164 number or an empty message.
    pub fn new(phone_number: impl Into<String>, message: impl Into<String>) -> Result<Self> {
        let phone_number = validate::phone("phone_number", &phone_number.into())?;
        let message = message.into();
        validate::non_empty("message", &message)?;
        Ok(Self {
            phone_number,
            message,
        })
    }

    /// The normalised recipient number.
    ///
    /// ```
    /// use sipgate_flow::SendSms;
    /// assert_eq!(SendSms::new("4915112345678", "hi")?.phone_number(), "4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn phone_number(&self) -> &str {
        &self.phone_number
    }

    /// The message body.
    ///
    /// ```
    /// use sipgate_flow::SendSms;
    /// assert_eq!(SendSms::new("4915112345678", "hi")?.message(), "hi");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Renders the action's own fields.
    ///
    /// ```
    /// use sipgate_flow::SendSms;
    /// assert_eq!(
    ///     SendSms::new("4915112345678", "hi")?.to_json(),
    ///     serde_json::json!({"phone_number": "4915112345678", "message": "hi"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "phone_number": self.phone_number, "message": self.message })
    }
}
