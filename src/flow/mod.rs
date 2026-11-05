//! sipgate flow: inbound events, outbound actions, and the webhook handshake.
//!
//! The protocol is documented at <https://flow.sipgate.io/api/>. Events arrive
//! as JSON; actions are returned in the *response* to the webhook call, not
//! posted to a separate endpoint. This crate supports only the webhook-response
//! channel; the WebSocket channel is not implemented (see
//! <https://github.com/floffel/sipgate-flow/issues/11>). See
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
pub mod webhook;

pub use crate::error::{Error, Result};

pub use action::{
    Action, ActionKind, Audio, BargeInConfig, BargeInStrategy, ConfigureTranscription, MixAudio,
    SendSms, Speak, TranscriptionProvider, Transfer, Tts, Vad,
};
pub use client::{FlowClient, OutboundCall, OutboundCallReceipt, DEFAULT_BASE_URL};
pub use event::{
    Direction, ErrorCode, Event, EventPayload, Session, Severity, SmsFailureReason,
    TransferFailedReason, MAX_EVENT_BODY_BYTES,
};
pub use response::FlowResponse;
pub use webhook::{
    is_json_content_type, WebhookVerifier, DEFAULT_MAX_BODY_BYTES, SECRET_HEADER,
    SECRET_HEADER_LEGACY,
};
