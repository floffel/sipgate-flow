//! Inbound events.

use serde::Deserialize;

/// An inbound voice-flow event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Call was answered.
    Answered {
        /// Call id used to address follow-up actions.
        call_id: String,
    },
    /// Caller input (DTMF) was received.
    Dtmf {
        /// Call id.
        call_id: String,
        /// Pressed digit(s).
        digits: String,
    },
    /// Speech-to-text result.
    Speech {
        /// Call id.
        call_id: String,
        /// Transcribed text.
        text: String,
    },
    /// Call ended.
    Hangup {
        /// Call id.
        call_id: String,
        /// Optional cause as reported by sipgate.
        cause: Option<String>,
    },
    /// Anything this crate does not model yet — log and ignore.
    Unknown {
        /// The raw `event` value, if present.
        kind: String,
    },
}

#[derive(Deserialize)]
struct Raw {
    #[serde(default, alias = "type")]
    event: Option<String>,
    #[serde(default, alias = "callId", alias = "call_id")]
    call_id: Option<String>,
    #[serde(default)]
    digits: Option<String>,
    #[serde(default, alias = "transcript", alias = "text")]
    text: Option<String>,
    #[serde(default)]
    cause: Option<String>,
}

impl Event {
    /// Parses an event from a JSON body, tolerating unknown shapes.
    ///
    /// # Errors
    ///
    /// Only fails when the body is not JSON or not an object.
    pub fn parse(body: &[u8]) -> crate::Result<Self> {
        let raw: Raw =
            serde_json::from_slice(body).map_err(|e| crate::Error::Payload(e.to_string()))?;
        let call_id = raw.call_id.clone().unwrap_or_default();
        Ok(match raw.event.as_deref() {
            Some("answered") => Self::Answered { call_id },
            Some("dtmf" | "digits") => Self::Dtmf {
                call_id,
                digits: raw.digits.unwrap_or_default(),
            },
            Some("speech" | "transcript") => Self::Speech {
                call_id,
                text: raw.text.unwrap_or_default(),
            },
            Some("hangup" | "ended") => Self::Hangup {
                call_id,
                cause: raw.cause,
            },
            other => Self::Unknown {
                kind: other.unwrap_or_default().to_string(),
            },
        })
    }

    /// The call id, when the event carries one.
    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        match self {
            Self::Answered { call_id }
            | Self::Dtmf { call_id, .. }
            | Self::Speech { call_id, .. }
            | Self::Hangup { call_id, .. } => Some(call_id),
            Self::Unknown { .. } => None,
        }
    }
}
