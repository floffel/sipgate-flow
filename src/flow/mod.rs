//! sipgate flow: inbound events, outbound actions, and the webhook handshake.
//!
//! The protocol is documented at <https://flow.sipgate.io/api/>. Events arrive
//! as JSON; actions are returned in the *response* to the webhook call, not
//! posted to a separate endpoint. This crate supports only the webhook-response
//! channel; the WebSocket channel is not implemented (see
//! <https://github.com/floffel/sipgate-flow/issues/11>). See `docs/contracts.md`
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
    TransferFailedReason, MAX_EVENT_BODY_BYTES,
};
pub use response::FlowResponse;
pub use webhook::WebhookVerifier;
