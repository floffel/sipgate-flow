//! Inbound events, parsed tolerantly.
//!
//! Every event documented at <https://flow.sipgate.io/api/events> has a typed
//! payload, plus `user_barge_in`, which only the official TypeScript SDK's
//! schema publishes; anything else lands in [`EventPayload::Unknown`] with the
//! raw JSON intact. Unknown *fields* on known events are preserved in [`Event::extra`],
//! so a field sipgate adds tomorrow still reaches a caller that inspects the
//! remainder. [`Event::parse`] refuses bodies above [`MAX_EVENT_BODY_BYTES`]
//! before JSON deserialisation starts.
//!
//! ```
//! use sipgate_flow::{Event, EventPayload};
//!
//! let event = Event::parse(br#"{"type":"user_speak","text":"Hallo","session":{"id":"s1"}}"#)?;
//! assert_eq!(event.kind(), "user_speak");
//! assert_eq!(event.session_id(), Some("s1"));
//! assert!(matches!(event.payload(), EventPayload::UserSpeak { text, .. } if text == "Hallo"));
//! # Ok::<(), sipgate_flow::Error>(())
//! ```

use std::collections::BTreeMap;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, value::RawValue, Map, Value};

use crate::error::{Error, Result};

/// Largest event body [`Event::parse`] accepts, in bytes.
///
/// Real Flow events are a few KiB. This ceiling is checked before any JSON
/// deserialisation, so an attacker-reachable webhook or WebSocket handler
/// cannot force large parser allocations.
///
/// ```
/// assert_eq!(sipgate_flow::MAX_EVENT_BODY_BYTES, 64 * 1024);
/// ```
pub const MAX_EVENT_BODY_BYTES: usize = 64 * 1024;

/// Call direction, as reported in `session.direction`.
///
/// ```
/// use sipgate_flow::Direction;
///
/// assert_eq!(Direction::from_wire("inbound").as_str(), "inbound");
/// assert!(matches!(Direction::from_wire("sideways"), Direction::Other(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Direction {
    /// The caller dialled in.
    Inbound,
    /// The Flow placed the call through the outbound call API.
    Outbound,
    /// A value this crate does not model yet.
    Other(String),
}

impl Direction {
    /// Maps the wire value, keeping unknown values verbatim.
    ///
    /// ```
    /// use sipgate_flow::Direction;
    /// assert_eq!(Direction::from_wire("outbound"), Direction::Outbound);
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "inbound" => Self::Inbound,
            "outbound" => Self::Outbound,
            other => Self::Other(other.to_string()),
        }
    }

    /// The wire value.
    ///
    /// ```
    /// use sipgate_flow::Direction;
    /// assert_eq!(Direction::Outbound.as_str(), "outbound");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
            Self::Other(value) => value,
        }
    }
}

/// Why a `transfer` with a `timeout` returned the caller.
///
/// Documented at <https://flow.sipgate.io/api/events#failed-transfer>.
///
/// ```
/// use sipgate_flow::TransferFailedReason;
///
/// assert_eq!(TransferFailedReason::from_wire("busy").as_str(), "busy");
/// assert!(matches!(
///     TransferFailedReason::from_wire("carrier_pigeon"),
///     TransferFailedReason::Other(_)
/// ));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferFailedReason {
    /// The target was busy.
    Busy,
    /// The target actively declined the call.
    Rejected,
    /// The target rang until the timeout expired.
    NoAnswer,
    /// The target number does not exist.
    NumberNotFound,
    /// The call could not be delivered for technical reasons.
    TechnicalError,
    /// The outcome could not be determined.
    Unknown,
    /// A value this crate does not model yet.
    Other(String),
}

impl TransferFailedReason {
    /// Maps the wire value, keeping unknown values verbatim.
    ///
    /// ```
    /// use sipgate_flow::TransferFailedReason;
    /// assert_eq!(TransferFailedReason::from_wire("no_answer"), TransferFailedReason::NoAnswer);
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "busy" => Self::Busy,
            "rejected" => Self::Rejected,
            "no_answer" => Self::NoAnswer,
            "number_not_found" => Self::NumberNotFound,
            "technical_error" => Self::TechnicalError,
            "unknown" => Self::Unknown,
            other => Self::Other(other.to_string()),
        }
    }

    /// The wire value.
    ///
    /// ```
    /// use sipgate_flow::TransferFailedReason;
    /// assert_eq!(TransferFailedReason::NoAnswer.as_str(), "no_answer");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Busy => "busy",
            Self::Rejected => "rejected",
            Self::NoAnswer => "no_answer",
            Self::NumberNotFound => "number_not_found",
            Self::TechnicalError => "technical_error",
            Self::Unknown => "unknown",
            Self::Other(value) => value,
        }
    }

    /// Whether retrying the same target is worth it.
    ///
    /// `busy`, `rejected` and `no_answer` mean the target was reachable but did
    /// not pick up; the other reasons point at the number or the route.
    ///
    /// ```
    /// use sipgate_flow::TransferFailedReason;
    ///
    /// assert!(TransferFailedReason::Busy.is_worth_retrying());
    /// assert!(!TransferFailedReason::NumberNotFound.is_worth_retrying());
    /// ```
    #[must_use]
    pub fn is_worth_retrying(&self) -> bool {
        matches!(self, Self::Busy | Self::Rejected | Self::NoAnswer)
    }
}

/// Why a `send_sms` action failed, from the `sms_failed` event.
///
/// ```
/// use sipgate_flow::SmsFailureReason;
///
/// assert_eq!(SmsFailureReason::from_wire("smsc_unavailable").as_str(), "smsc_unavailable");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SmsFailureReason {
    /// The configured sender number is not verified for SMS.
    SenderNotAllowed,
    /// The account has insufficient credits.
    InsufficientBalance,
    /// The AI Flow is not linked to a sipgate account.
    NoSmsExtension,
    /// Transient SMSC failure; retrying later is safe.
    SmscUnavailable,
    /// Any other failure; the `message` field carries details.
    Unknown,
    /// A value this crate does not model yet.
    Other(String),
}

impl SmsFailureReason {
    /// Maps the wire value, keeping unknown values verbatim.
    ///
    /// ```
    /// use sipgate_flow::SmsFailureReason;
    /// assert_eq!(
    ///     SmsFailureReason::from_wire("insufficient_balance"),
    ///     SmsFailureReason::InsufficientBalance
    /// );
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "sender_not_allowed" => Self::SenderNotAllowed,
            "insufficient_balance" => Self::InsufficientBalance,
            "no_sms_extension" => Self::NoSmsExtension,
            "smsc_unavailable" => Self::SmscUnavailable,
            "unknown" => Self::Unknown,
            other => Self::Other(other.to_string()),
        }
    }

    /// The wire value.
    ///
    /// ```
    /// use sipgate_flow::SmsFailureReason;
    /// assert_eq!(SmsFailureReason::SmscUnavailable.as_str(), "smsc_unavailable");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::SenderNotAllowed => "sender_not_allowed",
            Self::InsufficientBalance => "insufficient_balance",
            Self::NoSmsExtension => "no_sms_extension",
            Self::SmscUnavailable => "smsc_unavailable",
            Self::Unknown => "unknown",
            Self::Other(value) => value,
        }
    }

    /// Whether a later retry of the same send could succeed.
    ///
    /// ```
    /// use sipgate_flow::SmsFailureReason;
    ///
    /// assert!(SmsFailureReason::SmscUnavailable.is_retryable());
    /// assert!(!SmsFailureReason::InsufficientBalance.is_retryable());
    /// ```
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::SmscUnavailable)
    }
}

/// Severity of an `error` event.
///
/// ```
/// use sipgate_flow::Severity;
///
/// assert_eq!(Severity::from_wire("warning").as_str(), "warning");
/// assert!(Severity::from_wire("warning").call_continues());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Severity {
    /// The call continues, possibly degraded.
    Warning,
    /// The intended effect did not happen.
    Error,
    /// The severity was absent, empty, or explicitly `unknown`.
    ///
    /// ```
    /// use sipgate_flow::Severity;
    ///
    /// assert_eq!(Severity::from_wire(""), Severity::Unknown);
    /// assert!(!Severity::Unknown.call_continues());
    /// ```
    Unknown,
    /// A value this crate does not model yet.
    Other(String),
}

impl Severity {
    /// Maps the wire value, keeping unknown values verbatim.
    ///
    /// ```
    /// use sipgate_flow::Severity;
    /// assert_eq!(Severity::from_wire("error"), Severity::Error);
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "warning" => Self::Warning,
            "error" => Self::Error,
            "" | "unknown" => Self::Unknown,
            other => Self::Other(other.to_string()),
        }
    }

    /// The wire value.
    ///
    /// ```
    /// use sipgate_flow::Severity;
    /// assert_eq!(Severity::Error.as_str(), "error");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Unknown => "unknown",
            Self::Other(value) => value,
        }
    }

    /// Whether the call keeps running after this failure.
    ///
    /// Unclassified severities stop the call: a handler that cannot tell whether
    /// an error was fatal must not keep the call alive by default.
    ///
    /// ```
    /// use sipgate_flow::Severity;
    ///
    /// assert!(Severity::Warning.call_continues());
    /// assert!(!Severity::Error.call_continues());
    /// assert!(!Severity::Unknown.call_continues());
    /// assert!(!Severity::Other("notice".into()).call_continues());
    /// ```
    #[must_use]
    pub fn call_continues(&self) -> bool {
        matches!(self, Self::Warning)
    }
}

/// Machine-readable code of an `error` event.
///
/// Branch on this rather than on `message`, which the documentation explicitly
/// calls unsafe for control flow.
///
/// ```
/// use sipgate_flow::ErrorCode;
///
/// assert_eq!(
///     ErrorCode::from_wire("synthesis_unavailable"),
///     Some(ErrorCode::SynthesisUnavailable)
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// An action could not be parsed or failed validation.
    ActionInvalid,
    /// An action referenced a session that is no longer active.
    ActionUnknownSession,
    /// The speech-recognition provider could not be reached.
    TranscriptionUnavailable,
    /// A `configure_transcription` switch could not be applied.
    TranscriptionSwitchFailed,
    /// Speech synthesis failed and the output was dropped.
    SynthesisUnavailable,
    /// A `transfer` was rejected or could not be placed.
    TransferTargetInvalid,
    /// An unexpected internal failure.
    InternalError,
    /// A value this crate does not model yet.
    Other(String),
}

impl ErrorCode {
    /// Maps the wire value, keeping unknown values verbatim.
    ///
    /// ```
    /// use sipgate_flow::ErrorCode;
    /// assert_eq!(ErrorCode::from_wire("internal_error"), Some(ErrorCode::InternalError));
    /// assert_eq!(ErrorCode::from_wire(""), None);
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "" => None,
            "action_invalid" => Some(Self::ActionInvalid),
            "action_unknown_session" => Some(Self::ActionUnknownSession),
            "transcription_unavailable" => Some(Self::TranscriptionUnavailable),
            "transcription_switch_failed" => Some(Self::TranscriptionSwitchFailed),
            "synthesis_unavailable" => Some(Self::SynthesisUnavailable),
            "transfer_target_invalid" => Some(Self::TransferTargetInvalid),
            "internal_error" => Some(Self::InternalError),
            other => Some(Self::Other(other.to_string())),
        }
    }

    /// The wire value.
    ///
    /// ```
    /// use sipgate_flow::ErrorCode;
    /// assert_eq!(ErrorCode::TransferTargetInvalid.as_str(), "transfer_target_invalid");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::ActionInvalid => "action_invalid",
            Self::ActionUnknownSession => "action_unknown_session",
            Self::TranscriptionUnavailable => "transcription_unavailable",
            Self::TranscriptionSwitchFailed => "transcription_switch_failed",
            Self::SynthesisUnavailable => "synthesis_unavailable",
            Self::TransferTargetInvalid => "transfer_target_invalid",
            Self::InternalError => "internal_error",
            Self::Other(value) => value,
        }
    }
}

/// The `session` object every event carries.
///
/// `#[non_exhaustive]`: sipgate adds session fields regularly, and a new one
/// must stay a non-breaking release. Build it with [`Session::default`] or
/// [`Session::new`], then set the fields a caller needs.
///
/// Fields the documentation marks required are `String`; the rest are
/// `Option`, because `user_speak`, `assistant_speak` and friends show a shorter
/// session object in the official examples than `session_start` does.
///
/// ```
/// use sipgate_flow::Session;
///
/// let session = Session::new("s1");
/// assert_eq!(session.id, "s1");
/// assert!(session.direction.is_none());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Session {
    /// Session identifier, the `session_id` every action must echo back.
    pub id: String,
    /// Account identifier.
    pub account_id: Option<String>,
    /// Phone number this Flow session is bound to.
    pub phone_number: Option<String>,
    /// Inbound or outbound, when reported.
    pub direction: Option<Direction>,
    /// Number of the caller.
    pub from_phone_number: Option<String>,
    /// Number of the callee.
    pub to_phone_number: Option<String>,
    /// Fields this crate does not model, preserved verbatim.
    pub extra: BTreeMap<String, Value>,
}

/// The typed part of an event, one variant per documented event type.
///
/// ```
/// use sipgate_flow::{Event, EventPayload};
///
/// let event = Event::parse(br#"{"type":"dtmf_received","digit":"1","session":{"id":"s1"}}"#)?;
/// assert!(matches!(event.payload(), EventPayload::DtmfReceived { digit } if digit == "1"));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EventPayload {
    /// The call session begins, or a failed transfer returns the caller.
    SessionStart {
        /// Present only when a failed transfer returned the caller.
        transfer_failed_reason: Option<TransferFailedReason>,
    },
    /// Speech onset detected. WebSocket only.
    UserSpeechStarted,
    /// A finished utterance after speech-to-text.
    UserSpeak {
        /// Recognised text; empty when the provider sent none.
        text: String,
        /// Whether the caller interrupted the assistant.
        barged_in: bool,
        /// Detected language, when the provider reports one.
        language: Option<String>,
    },
    /// The caller barged in on the assistant's speech.
    ///
    /// Taken from the official SDK's event enum and schema
    /// (`AiFlowEventUserBargeInSchema`, `@sipgate/ai-flow-sdk` 2.1.0); the
    /// public docs' event table does not list it. [`Event::accepts_actions`]
    /// answers `false` for it because the documentation's "Response
    /// Requirements" table does not cover it either — the conservative answer
    /// is `204`, and a handler that knows better can return
    /// [`FlowResponse`](crate::FlowResponse) anyway.
    UserBargeIn {
        /// Recognised text of the interruption; empty when none was sent.
        text: String,
    },
    /// A keypad press.
    DtmfReceived {
        /// The key pressed: `0`-`9`, `*` or `#`.
        ///
        /// [`Event::parse`] rejects a `dtmf_received` event that carries no
        /// key, an empty key, or anything outside this alphabet.
        digit: String,
    },
    /// The assistant started speaking.
    AssistantSpeak {
        /// Text that was spoken, when the TTS provider reports it.
        text: Option<String>,
        /// SSML that was used, when applicable.
        ssml: Option<String>,
        /// Speech duration in milliseconds.
        duration_ms: Option<u64>,
        /// Unix timestamp in milliseconds when speech started.
        speech_started_at: Option<i64>,
    },
    /// The assistant finished speaking.
    AssistantSpeechEnded,
    /// No speech arrived within `user_input_timeout_seconds`.
    UserInputTimeout,
    /// The call ended. No action may be returned for this event.
    SessionEnd,
    /// A `send_sms` action failed.
    SmsFailed {
        /// Number the message was addressed to.
        recipient: String,
        /// Machine-readable failure reason.
        reason: SmsFailureReason,
        /// Optional human-readable detail.
        message: Option<String>,
    },
    /// The service could not carry out something during the call.
    Error {
        /// Machine-readable code.
        code: ErrorCode,
        /// Whether the call continues.
        severity: Severity,
        /// Human-readable detail, for logs only.
        message: String,
        /// Action that triggered the failure, when one was involved.
        action_type: Option<String>,
    },
    /// An event this crate does not model, with its raw JSON preserved.
    ///
    /// The boxed raw value borrows no caller memory after parsing; it owns a
    /// single copy of the original JSON document.
    Unknown(Box<RawValue>),
}

impl PartialEq for EventPayload {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::SessionStart {
                    transfer_failed_reason: left,
                },
                Self::SessionStart {
                    transfer_failed_reason: right,
                },
            ) => left == right,
            (Self::UserSpeechStarted, Self::UserSpeechStarted)
            | (Self::AssistantSpeechEnded, Self::AssistantSpeechEnded)
            | (Self::UserInputTimeout, Self::UserInputTimeout)
            | (Self::SessionEnd, Self::SessionEnd) => true,
            (
                Self::UserSpeak {
                    text: left_text,
                    barged_in: left_barged_in,
                    language: left_language,
                },
                Self::UserSpeak {
                    text: right_text,
                    barged_in: right_barged_in,
                    language: right_language,
                },
            ) => {
                left_text == right_text
                    && left_barged_in == right_barged_in
                    && left_language == right_language
            }
            (Self::UserBargeIn { text: left }, Self::UserBargeIn { text: right }) => left == right,
            (Self::DtmfReceived { digit: left }, Self::DtmfReceived { digit: right }) => {
                left == right
            }
            (
                Self::AssistantSpeak {
                    text: left_text,
                    ssml: left_ssml,
                    duration_ms: left_duration_ms,
                    speech_started_at: left_speech_started_at,
                },
                Self::AssistantSpeak {
                    text: right_text,
                    ssml: right_ssml,
                    duration_ms: right_duration_ms,
                    speech_started_at: right_speech_started_at,
                },
            ) => {
                left_text == right_text
                    && left_ssml == right_ssml
                    && left_duration_ms == right_duration_ms
                    && left_speech_started_at == right_speech_started_at
            }
            (
                Self::SmsFailed {
                    recipient: left_recipient,
                    reason: left_reason,
                    message: left_message,
                },
                Self::SmsFailed {
                    recipient: right_recipient,
                    reason: right_reason,
                    message: right_message,
                },
            ) => {
                left_recipient == right_recipient
                    && left_reason == right_reason
                    && left_message == right_message
            }
            (
                Self::Error {
                    code: left_code,
                    severity: left_severity,
                    message: left_message,
                    action_type: left_action_type,
                },
                Self::Error {
                    code: right_code,
                    severity: right_severity,
                    message: right_message,
                    action_type: right_action_type,
                },
            ) => {
                left_code == right_code
                    && left_severity == right_severity
                    && left_message == right_message
                    && left_action_type == right_action_type
            }
            (Self::Unknown(left), Self::Unknown(right)) => raw_values_equal(left, right),
            _ => false,
        }
    }
}

impl Eq for EventPayload {}

impl EventPayload {
    /// The wire name of this payload, or `None` for an unknown event.
    ///
    /// ```
    /// use sipgate_flow::{Event, EventPayload};
    ///
    /// let event = Event::parse(br#"{"type":"session_end","session":{"id":"s"}}"#)?;
    /// assert!(matches!(event.payload(), EventPayload::SessionEnd));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn known_kind(&self) -> Option<&'static str> {
        Some(match self {
            Self::SessionStart { .. } => "session_start",
            Self::UserSpeechStarted => "user_speech_started",
            Self::UserSpeak { .. } => "user_speak",
            Self::UserBargeIn { .. } => "user_barge_in",
            Self::DtmfReceived { .. } => "dtmf_received",
            Self::AssistantSpeak { .. } => "assistant_speak",
            Self::AssistantSpeechEnded => "assistant_speech_ended",
            Self::UserInputTimeout => "user_input_timeout",
            Self::SessionEnd => "session_end",
            Self::SmsFailed { .. } => "sms_failed",
            Self::Error { .. } => "error",
            Self::Unknown(_) => return None,
        })
    }
}

/// An inbound Flow event: the wire `type`, the session, a typed payload and
/// every field this crate does not model.
///
/// ```
/// use sipgate_flow::{Event, EventPayload};
///
/// let event = Event::parse(
///     br#"{"type":"sms_failed","recipient":"4915112345678","reason":"smsc_unavailable","session":{"id":"s1"}}"#,
/// )?;
/// assert!(matches!(event.payload(), EventPayload::SmsFailed { .. }));
/// assert_eq!(event.session_id(), Some("s1"));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    kind: String,
    session: Option<Session>,
    payload: EventPayload,
    extra: BTreeMap<String, Value>,
}

impl Event {
    /// Parses a webhook or WebSocket body.
    ///
    /// Tolerant by design: unknown event types become
    /// [`EventPayload::Unknown`], unknown fields are kept in [`Event::extra`],
    /// both `camelCase` and `snake_case` spellings are accepted, and a missing
    /// `session.id` does not fail the parse (it yields an empty id that
    /// [`Action`](crate::Action) constructors then refuse).
    ///
    /// Advisory metadata fields tolerate type drift: `barged_in` degrades to
    /// `false`, and `duration_ms` plus `speech_started_at` degrade to `None`
    /// when upstream sends an unexpected JSON type. Control-flow fields stay
    /// strict: `type` chooses the payload and response capability, and
    /// `session`/`session.id` carry the identifier returned actions must echo.
    ///
    /// ```
    /// use sipgate_flow::{Event, EventPayload};
    ///
    /// let event = Event::parse(br#"{"type":"future_event","session":{"id":"s"},"payload":{"a":1}}"#)?;
    /// assert!(matches!(event.payload(), EventPayload::Unknown(_)));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// ```
    /// use sipgate_flow::{Event, EventPayload};
    ///
    /// let event = Event::parse(
    ///     br#"{"type":"assistant_speak","duration_ms":"1200","speech_started_at":1.5,"session":{"id":"s"}}"#,
    /// )?;
    /// assert!(matches!(
    ///     event.payload(),
    ///     EventPayload::AssistantSpeak {
    ///         duration_ms: None,
    ///         speech_started_at: None,
    ///         ..
    ///     }
    /// ));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// * [`Error::BodyTooLarge`] when the body is larger than
    ///   [`MAX_EVENT_BODY_BYTES`].
    /// * [`Error::EmptyBody`] when the body is empty or only whitespace.
    /// * [`Error::Json`] when the body is not JSON, is not an object, has a
    ///   strict field of the wrong type, or repeats a known key.
    /// * [`Error::Validation`] when a `dtmf_received` event does not carry
    ///   exactly one key from `0`-`9`, `*` or `#`.
    /// * [`Error::Validation`] when an `error` event does not carry a non-empty
    ///   `code`.
    pub fn parse(body: &[u8]) -> Result<Self> {
        if body.len() > MAX_EVENT_BODY_BYTES {
            return Err(Error::BodyTooLarge {
                size: body.len(),
                limit: MAX_EVENT_BODY_BYTES,
            });
        }
        if body.iter().all(u8::is_ascii_whitespace) {
            return Err(Error::EmptyBody);
        }
        let header: RawEventHeader = serde_json::from_slice(body).map_err(Error::json_parse)?;
        if header.kind.as_deref().is_some_and(is_known_kind) {
            Self::from_raw(serde_json::from_slice(body).map_err(Error::json_parse)?)
        } else {
            Ok(Self::from_unknown(
                header,
                serde_json::from_slice(body).map_err(Error::json_parse)?,
            ))
        }
    }

    fn from_raw(mut raw: RawEvent) -> Result<Self> {
        let session = raw.session.as_ref().map(RawSession::to_session);
        // Compatibility: the 0.1 stub accepted a top-level `callId`, and the
        // Push API uses exactly that name. It only fills a gap, never wins; a
        // conflicting value stays visible in `extra` under the Push API name.
        let session = match (session, raw.call_id.take()) {
            (Some(mut session), Some(call_id)) if session.id.is_empty() => {
                session.id = call_id;
                Some(session)
            }
            (Some(session), Some(call_id)) if session.id != call_id => {
                raw.extra.insert("callId".into(), Value::String(call_id));
                Some(session)
            }
            (Some(session), _) => Some(session),
            (None, Some(call_id)) => Some(Session {
                id: call_id,
                ..Session::default()
            }),
            (None, None) => None,
        };

        let kind = raw.kind.clone().unwrap_or_default();
        let payload = match raw.kind.as_deref() {
            Some("session_start") => EventPayload::SessionStart {
                transfer_failed_reason: raw
                    .transfer_failed_reason
                    .as_deref()
                    .map(TransferFailedReason::from_wire),
            },
            Some("user_speech_started") => EventPayload::UserSpeechStarted,
            Some("user_speak") => EventPayload::UserSpeak {
                text: raw.text.unwrap_or_default(),
                barged_in: raw
                    .barged_in
                    .as_ref()
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                language: raw.language,
            },
            Some("user_barge_in") => EventPayload::UserBargeIn {
                text: raw.text.unwrap_or_default(),
            },
            Some("dtmf_received") => EventPayload::DtmfReceived {
                digit: dtmf_digit(raw.digit, raw.digits)?,
            },
            Some("assistant_speak") => EventPayload::AssistantSpeak {
                text: raw.text,
                ssml: raw.ssml,
                duration_ms: raw.duration_ms.as_ref().and_then(Value::as_u64),
                speech_started_at: raw.speech_started_at.as_ref().and_then(Value::as_i64),
            },
            Some("assistant_speech_ended") => EventPayload::AssistantSpeechEnded,
            Some("user_input_timeout") => EventPayload::UserInputTimeout,
            Some("session_end") => EventPayload::SessionEnd,
            Some("sms_failed") => EventPayload::SmsFailed {
                recipient: raw.recipient.unwrap_or_default(),
                reason: SmsFailureReason::from_wire(raw.reason.as_deref().unwrap_or_default()),
                message: raw.message,
            },
            Some("error") => EventPayload::Error {
                code: ErrorCode::from_wire(raw.code.as_deref().unwrap_or_default())
                    .ok_or_else(|| Error::validation("code", "must not be empty"))?,
                severity: Severity::from_wire(raw.severity.as_deref().unwrap_or_default()),
                message: raw.message.unwrap_or_default(),
                action_type: raw.action_type,
            },
            _ => EventPayload::Unknown(null_raw_value()),
        };

        Ok(Self {
            kind,
            session,
            payload,
            extra: raw.extra,
        })
    }

    fn from_unknown(header: RawEventHeader, raw: Box<RawValue>) -> Self {
        let session = header.session.as_ref().map(RawSessionHeader::to_session);
        let session = match (session, header.call_id) {
            (Some(mut session), Some(call_id)) if session.id.is_empty() => {
                session.id = call_id;
                Some(session)
            }
            (Some(session), _) => Some(session),
            (None, Some(call_id)) => Some(Session {
                id: call_id,
                ..Session::default()
            }),
            (None, None) => None,
        };

        Self {
            kind: header.kind.unwrap_or_default(),
            session,
            payload: EventPayload::Unknown(raw),
            extra: BTreeMap::new(),
        }
    }

    /// The wire `type` value, empty when the payload carried none.
    ///
    /// ```
    /// use sipgate_flow::Event;
    ///
    /// let event = Event::parse(br#"{"type":"session_end","session":{"id":"s"}}"#)?;
    /// assert_eq!(event.kind(), "session_end");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The session, when the payload carried one.
    ///
    /// ```
    /// use sipgate_flow::Event;
    ///
    /// let event = Event::parse(br#"{"type":"session_end","session":{"id":"s"}}"#)?;
    /// assert_eq!(event.session().map(|s| s.id.as_str()), Some("s"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// The session id, when it is present **and** non-empty — the value every
    /// action has to echo back.
    ///
    /// ```
    /// use sipgate_flow::Event;
    ///
    /// let event = Event::parse(br#"{"type":"user_speak","text":"hi"}"#)?;
    /// assert_eq!(event.session_id(), None);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.session
            .as_ref()
            .map(|session| session.id.as_str())
            .filter(|id| !id.is_empty())
    }

    /// The typed payload.
    ///
    /// ```
    /// use sipgate_flow::{Event, EventPayload};
    ///
    /// let event = Event::parse(br#"{"type":"user_input_timeout","session":{"id":"s"}}"#)?;
    /// assert!(matches!(event.payload(), EventPayload::UserInputTimeout));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn payload(&self) -> &EventPayload {
        &self.payload
    }

    /// Fields on the event this crate does not model, preserved verbatim.
    ///
    /// A top-level `callId` that conflicts with `session.id` is also kept here
    /// under `callId`; `session.id` remains the authoritative Flow session id.
    ///
    /// ```
    /// use sipgate_flow::Event;
    ///
    /// let event = Event::parse(br#"{"type":"session_end","session":{"id":"s"},"new_field":7}"#)?;
    /// assert_eq!(event.extra().get("new_field"), Some(&serde_json::json!(7)));
    ///
    /// let conflict = Event::parse(
    ///     br#"{"type":"session_end","callId":"push-call","session":{"id":"flow-session"}}"#,
    /// )?;
    /// assert_eq!(conflict.session_id(), Some("flow-session"));
    /// assert_eq!(conflict.extra().get("callId"), Some(&serde_json::json!("push-call")));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn extra(&self) -> &BTreeMap<String, Value> {
        &self.extra
    }

    /// Whether this is an event type the crate does not model.
    ///
    /// ```
    /// use sipgate_flow::Event;
    ///
    /// assert!(Event::parse(br#"{"type":"brand_new","session":{"id":"s"}}"#)?.is_unknown());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        matches!(self.payload, EventPayload::Unknown(_))
    }

    /// Whether the protocol allows returning actions for this event.
    ///
    /// `session_end` explicitly allows none; `user_speech_started` and
    /// `sms_failed` are not in the documented response table either, so this
    /// reports `false` for them as well and the caller can answer `204`.
    ///
    /// ```
    /// use sipgate_flow::Event;
    ///
    /// let end = Event::parse(br#"{"type":"session_end","session":{"id":"s"}}"#)?;
    /// assert!(!end.accepts_actions());
    /// let start = Event::parse(br#"{"type":"session_start","session":{"id":"s"}}"#)?;
    /// assert!(start.accepts_actions());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn accepts_actions(&self) -> bool {
        matches!(
            self.payload,
            EventPayload::SessionStart { .. }
                | EventPayload::UserSpeak { .. }
                | EventPayload::DtmfReceived { .. }
                | EventPayload::AssistantSpeak { .. }
                | EventPayload::AssistantSpeechEnded
                | EventPayload::UserInputTimeout
                | EventPayload::Error { .. }
        )
    }

    /// Renders the event back to the wire shape.
    ///
    /// The output round-trips through [`Event::parse`] for every event this
    /// crate models, and preserves unknown fields plus unknown event payloads.
    ///
    /// ```
    /// use sipgate_flow::Event;
    ///
    /// let body = br#"{"type":"dtmf_received","digit":"7","session":{"id":"s1"}}"#;
    /// let event = Event::parse(body)?;
    /// assert_eq!(event.to_json(), serde_json::json!({
    ///     "type": "dtmf_received",
    ///     "digit": "7",
    ///     "session": {"id": "s1"},
    /// }));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        if let EventPayload::Unknown(raw) = &self.payload {
            return serde_json::from_str(raw.get()).unwrap_or(Value::Null);
        }

        let mut object = Map::new();
        object.insert("type".into(), Value::String(self.kind.clone()));
        if let Some(session) = &self.session {
            object.insert("session".into(), session.to_json());
        }
        match &self.payload {
            EventPayload::SessionStart {
                transfer_failed_reason,
            } => {
                if let Some(reason) = transfer_failed_reason {
                    object.insert("transfer_failed_reason".into(), json!(reason.as_str()));
                }
            }
            EventPayload::UserSpeak {
                text,
                barged_in,
                language,
            } => {
                object.insert("text".into(), json!(text));
                object.insert("barged_in".into(), json!(barged_in));
                if let Some(language) = language {
                    object.insert("language".into(), json!(language));
                }
            }
            EventPayload::UserBargeIn { text } => {
                object.insert("text".into(), json!(text));
            }
            EventPayload::DtmfReceived { digit } => {
                object.insert("digit".into(), json!(digit));
            }
            EventPayload::AssistantSpeak {
                text,
                ssml,
                duration_ms,
                speech_started_at,
            } => {
                if let Some(text) = text {
                    object.insert("text".into(), json!(text));
                }
                if let Some(ssml) = ssml {
                    object.insert("ssml".into(), json!(ssml));
                }
                if let Some(duration) = duration_ms {
                    object.insert("duration_ms".into(), json!(duration));
                }
                if let Some(started) = speech_started_at {
                    object.insert("speech_started_at".into(), json!(started));
                }
            }
            EventPayload::SmsFailed {
                recipient,
                reason,
                message,
            } => {
                object.insert("recipient".into(), json!(recipient));
                object.insert("reason".into(), json!(reason.as_str()));
                if let Some(message) = message {
                    object.insert("message".into(), json!(message));
                }
            }
            EventPayload::Error {
                code,
                severity,
                message,
                action_type,
            } => {
                object.insert("code".into(), json!(code.as_str()));
                object.insert("severity".into(), json!(severity.as_str()));
                object.insert("message".into(), json!(message));
                if let Some(action_type) = action_type {
                    object.insert("action_type".into(), json!(action_type));
                }
            }
            EventPayload::Unknown(_)
            | EventPayload::UserSpeechStarted
            | EventPayload::AssistantSpeechEnded
            | EventPayload::UserInputTimeout
            | EventPayload::SessionEnd => {}
        }
        for (key, value) in &self.extra {
            object.entry(key.clone()).or_insert_with(|| value.clone());
        }
        Value::Object(object)
    }
}

fn dtmf_digit(digit: Option<String>, digits: Option<String>) -> Result<String> {
    let singular = digit.filter(|value| !value.is_empty());
    let plural = digits.filter(|value| !value.is_empty());
    let candidate = match (singular, plural) {
        (Some(singular), None) | (None, Some(singular)) => singular,
        (Some(singular), Some(plural)) if singular == plural => singular,
        _ => return Err(dtmf_digit_error()),
    };

    if candidate.len() == 1
        && (candidate.as_bytes()[0].is_ascii_digit() || b"*#".contains(&candidate.as_bytes()[0]))
    {
        Ok(candidate)
    } else {
        Err(dtmf_digit_error())
    }
}

fn is_known_kind(kind: &str) -> bool {
    matches!(
        kind,
        "session_start"
            | "user_speech_started"
            | "user_speak"
            | "user_barge_in"
            | "dtmf_received"
            | "assistant_speak"
            | "assistant_speech_ended"
            | "user_input_timeout"
            | "session_end"
            | "sms_failed"
            | "error"
    )
}

fn null_raw_value() -> Box<RawValue> {
    RawValue::NULL.to_owned()
}

fn raw_values_equal(left: &RawValue, right: &RawValue) -> bool {
    serde_json::from_str::<Value>(left.get()).ok()
        == serde_json::from_str::<Value>(right.get()).ok()
}

fn dtmf_digit_error() -> Error {
    Error::validation("digit", "must contain exactly one key from 0-9, *, or #")
}

impl Session {
    /// A session with the given identifier and every optional field empty.
    ///
    /// ```
    /// use sipgate_flow::Session;
    ///
    /// let session = Session::new("s1");
    /// assert_eq!(session.id, "s1");
    /// assert!(session.to_json().get("direction").is_none());
    /// ```
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Self::default()
        }
    }

    /// Renders the session object; unknown fields are preserved.
    ///
    /// ```
    /// use sipgate_flow::Session;
    ///
    /// let mut session = Session::new("s1");
    /// session.direction = Some(sipgate_flow::Direction::Inbound);
    /// assert_eq!(
    ///     session.to_json(),
    ///     serde_json::json!({"id": "s1", "direction": "inbound"})
    /// );
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("id".into(), json!(self.id));
        if let Some(value) = &self.account_id {
            object.insert("account_id".into(), json!(value));
        }
        if let Some(value) = &self.phone_number {
            object.insert("phone_number".into(), json!(value));
        }
        if let Some(value) = &self.direction {
            object.insert("direction".into(), json!(value.as_str()));
        }
        if let Some(value) = &self.from_phone_number {
            object.insert("from_phone_number".into(), json!(value));
        }
        if let Some(value) = &self.to_phone_number {
            object.insert("to_phone_number".into(), json!(value));
        }
        for (key, value) in &self.extra {
            object.entry(key.clone()).or_insert_with(|| value.clone());
        }
        Value::Object(object)
    }
}

#[derive(Deserialize)]
struct RawSession {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, alias = "accountId")]
    account_id: Option<String>,
    #[serde(default, alias = "phoneNumber")]
    phone_number: Option<String>,
    #[serde(default)]
    direction: Option<String>,
    #[serde(default, alias = "fromPhoneNumber")]
    from_phone_number: Option<String>,
    #[serde(default, alias = "toPhoneNumber")]
    to_phone_number: Option<String>,
    #[serde(default, flatten)]
    extra: BTreeMap<String, Value>,
}

impl RawSession {
    fn to_session(&self) -> Session {
        Session {
            id: self.id.clone().unwrap_or_default(),
            account_id: self.account_id.clone(),
            phone_number: self.phone_number.clone(),
            direction: self.direction.as_deref().map(Direction::from_wire),
            from_phone_number: self.from_phone_number.clone(),
            to_phone_number: self.to_phone_number.clone(),
            extra: self.extra.clone(),
        }
    }
}

struct RawEventHeader {
    kind: Option<String>,
    session: Option<RawSessionHeader>,
    call_id: Option<String>,
}

impl<'de> Deserialize<'de> for RawEventHeader {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawEventHeaderVisitor;

        impl<'de> Visitor<'de> for RawEventHeaderVisitor {
            type Value = RawEventHeader;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut header = RawEventHeader {
                    kind: None,
                    session: None,
                    call_id: None,
                };
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" | "event" => {
                            if header.kind.is_some() {
                                return Err(serde::de::Error::duplicate_field("type"));
                            }
                            header.kind = map.next_value::<Option<String>>()?;
                        }
                        "session" => {
                            if header.session.is_some() {
                                return Err(serde::de::Error::duplicate_field("session"));
                            }
                            header.session = map.next_value::<Option<RawSessionHeader>>()?;
                        }
                        "callId" | "call_id" => {
                            if header.call_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("call_id"));
                            }
                            header.call_id = map.next_value::<Option<String>>()?;
                        }
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(header)
            }
        }

        deserializer.deserialize_map(RawEventHeaderVisitor)
    }
}

#[derive(Deserialize)]
struct RawSessionHeader {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, alias = "accountId")]
    account_id: Option<String>,
    #[serde(default, alias = "phoneNumber")]
    phone_number: Option<String>,
    #[serde(default)]
    direction: Option<String>,
    #[serde(default, alias = "fromPhoneNumber")]
    from_phone_number: Option<String>,
    #[serde(default, alias = "toPhoneNumber")]
    to_phone_number: Option<String>,
}

impl RawSessionHeader {
    fn to_session(&self) -> Session {
        Session {
            id: self.id.clone().unwrap_or_default(),
            account_id: self.account_id.clone(),
            phone_number: self.phone_number.clone(),
            direction: self.direction.as_deref().map(Direction::from_wire),
            from_phone_number: self.from_phone_number.clone(),
            to_phone_number: self.to_phone_number.clone(),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Deserialize)]
struct RawEvent {
    #[serde(default, rename = "type", alias = "event")]
    kind: Option<String>,
    #[serde(default)]
    session: Option<RawSession>,
    #[serde(default, alias = "callId", alias = "call_id")]
    call_id: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    ssml: Option<String>,
    #[serde(default)]
    digit: Option<String>,
    #[serde(default)]
    digits: Option<String>,
    #[serde(default, alias = "bargedIn")]
    barged_in: Option<Value>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default, alias = "durationMs")]
    duration_ms: Option<Value>,
    #[serde(default, alias = "speechStartedAt")]
    speech_started_at: Option<Value>,
    #[serde(default, alias = "transferFailedReason")]
    transfer_failed_reason: Option<String>,
    #[serde(default)]
    recipient: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default, alias = "actionType")]
    action_type: Option<String>,
    #[serde(default, flatten)]
    extra: BTreeMap<String, Value>,
}
