//! Outbound actions.

use serde_json::{json, Value};

/// An action to execute inside the running call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Text-to-speech.
    Say {
        /// What to speak.
        text: String,
    },
    /// Play an audio file by URL.
    Play {
        /// Publicly reachable URL.
        url: String,
    },
    /// Collect digits.
    Gather {
        /// Prompt spoken before collecting.
        prompt: String,
        /// Accepted digits, for example `"12"`.
        digits: String,
    },
    /// Hang up.
    Hangup,
}

impl Action {
    /// Convenience constructor for [`Action::Say`].
    #[must_use]
    pub fn say(text: impl Into<String>) -> Self {
        Self::Say { text: text.into() }
    }

    /// The action name sent to the API.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Say { .. } => "tts",
            Self::Play { .. } => "play",
            Self::Gather { .. } => "gather",
            Self::Hangup => "hangup",
        }
    }

    /// Renders the JSON body.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Self::Say { text } => json!({ "action": "tts", "text": text }),
            Self::Play { url } => json!({ "action": "play", "url": url }),
            Self::Gather { prompt, digits } => {
                json!({ "action": "gather", "prompt": prompt, "digits": digits })
            }
            Self::Hangup => json!({ "action": "hangup" }),
        }
    }
}
