//! The classic sipgate.io Push API: form-encoded events in, XML responses out.
//!
//! This is the third sipgate protocol, and the oldest one. The reference is
//! <https://en.sipgate.io/push-api/api-references> (retrieved 2026-11-05):
//!
//! * sipgate POSTs an `application/x-www-form-urlencoded` body with an `event`
//!   parameter (`newCall`, `answer`, `hangup`, `dtmf`) to the URL configured
//!   under *sipgate.io → Webhooks*;
//! * the handler answers with an XML `<Response>` containing verbs — `Dial`,
//!   `Play`, `Gather`, `Reject`, `Hangup` — and optionally subscribes to the
//!   follow-up events through `onAnswer`/`onHangup` attributes.
//!
//! Nothing here is JSON and nothing is posted to a separate endpoint, which is
//! why the module lives beside [`crate::flow`] instead of inside it: the Flow
//! [`WebhookVerifier`](crate::WebhookVerifier) refuses a form-encoded request on
//! purpose, and this module is what accepts it.
//!
//! The reference documents **no credential** for this API — no header, token,
//! signature or shared secret. [`PushVerifier`] therefore enforces the content
//! type and the body ceiling and leaves authentication to the deployment; see
//! its module documentation for the consequence.
//!
//! ```rust
//! use sipgate_flow::push::{Gather, Play, PushAction, PushResponse, PushVerifier};
//!
//! let event = PushVerifier::new().verify_and_parse(
//!     Some("application/x-www-form-urlencoded"),
//!     b"event=newCall&direction=in&from=492111234567&to=4915791234567&callId=123456",
//! )?;
//!
//! let response = if event.call_id() == Some("123456") {
//!     PushResponse::new().with_verb(PushAction::gather(
//!         Gather::new("https://example.com/dtmf")?
//!             .with_max_digits(1)?
//!             .with_play(Play::new("https://example.com/menu.wav")?),
//!     ))
//! } else {
//!     PushResponse::new()
//! };
//! assert_eq!(response.status(), 200);
//! assert_eq!(response.content_type(), "application/xml");
//! # Ok::<(), sipgate_flow::Error>(())
//! ```
//!
//! Every submodule stays `pub` so the detailed paths keep working, and this
//! facade re-exports the full public surface — types, constants and the
//! [`Error`]/[`Result`] a failure path matches on.

pub mod event;
pub mod response;
pub mod webhook;

pub use crate::error::{Error, Result};

pub use event::{HangupCause, PushDirection, PushEvent, PushEventKind, MAX_PUSH_BODY_BYTES};
pub use response::{
    Dial, DialTarget, Gather, Play, PushAction, PushResponse, RejectReason,
    DEFAULT_GATHER_MAX_DIGITS, DEFAULT_GATHER_TIMEOUT_MS, MAX_DIAL_TARGETS,
};
pub use webhook::{is_form_content_type, PushVerifier, FORM_CONTENT_TYPE};
