//! sipgate flow: inbound events, outbound actions, and the webhook handshake.
//!
//! The protocol is documented at <https://flow.sipgate.io/api/>. Events arrive
//! as JSON; actions are returned in the *response* to the webhook call (or over
//! the WebSocket), not posted to a separate endpoint. See `docs/contracts.md`
//! for the exact source of every shape this module models.

pub mod action;
pub mod client;
pub mod event;
pub mod response;
pub mod webhook;

pub use action::{
    Action, ActionKind, Audio, BargeInConfig, BargeInStrategy, ConfigureTranscription, MixAudio,
    SendSms, Speak, TranscriptionProvider, Transfer, Tts, Vad,
};
pub use event::{
    Direction, ErrorCode, Event, EventPayload, Session, Severity, SmsFailureReason,
    TransferFailedReason,
};
pub use response::FlowResponse;
pub use webhook::WebhookVerifier;
