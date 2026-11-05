//! sipgate flow: inbound events, outbound actions, and the webhook handshake.
//!
//! The protocol is documented at <https://flow.sipgate.io/api/>. Events arrive
//! as JSON; in the webhook mode actions are returned in the *response* to the
//! webhook call, not posted to a separate endpoint. In the WebSocket mode
//! (<https://flow.sipgate.io/api/websocket>, behind the `websocket` feature)
//! Flow opens a connection to your server and the same event arrives as one
//! JSON message, answered with actions on the same connection — see the
//! `websocket` module. See
//! [docs/contracts.md](https://github.com/floffel/sipgate-flow/blob/main/docs/contracts.md)
//! for the exact source of every shape this module models.
//!
//! Every submodule stays `pub` so the detailed paths keep working, but this
//! facade is the path a caller should reach for first: it re-exports the full
//! public surface of `action`, `client`, `event`, `response` and `webhook`,
//! including the constants, the helper function and the [`Error`]/[`Result`]
//! types a failure path matches on. `tests/flow_facade.rs` pins that promise at
//! compile time, so a type added to a submodule and forgotten here fails the
//! build instead of drifting out of the facade unnoticed.

pub mod action;
pub mod client;
pub mod event;
pub mod response;
#[cfg(feature = "websocket")]
pub mod socket;
pub mod webhook;

pub use crate::error::{Error, Result};

pub use action::{
    Action, ActionKind, Audio, BargeInConfig, BargeInStrategy, ConfigureTranscription, MixAudio,
    SendSms, Speak, TranscriptionProvider, Transfer, Tts, Vad,
};
pub use client::{
    AccountRetentionSettings, AgentVoices, AiWebhookSettings, CurrentVoice, FlowClient,
    OutboundCall, OutboundCallReceipt, RecordingAnnouncementMode, SetAccountRetentionSettings,
    SynthesizeRequest, SynthesizeStreamRequest, SynthesizedAudio, TranscriptionAnnouncementMode,
    TransferCallerIdSource, TtsSetting, TtsVoice, DEFAULT_BASE_URL,
    MAX_ACCOUNT_SETTING_TOKEN_BYTES, MAX_EVENT_RETENTION_DAYS, MIN_EVENT_RETENTION_DAYS,
};
pub use event::{
    Direction, ErrorCode, Event, EventPayload, Session, Severity, SmsFailureReason,
    TransferFailedReason, MAX_EVENT_BODY_BYTES,
};
pub use response::FlowResponse;
#[cfg(feature = "websocket")]
pub use socket::{
    AcceptBackoff, Connection, FlowSocket, Frame, MockConnection, MAX_SOCKET_MESSAGE_BYTES,
};
pub use webhook::{
    is_json_content_type, WebhookVerifier, DEFAULT_MAX_BODY_BYTES, SECRET_HEADER,
    SECRET_HEADER_LEGACY,
};
