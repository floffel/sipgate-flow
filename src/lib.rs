//! Typed, tolerant client for **sipgate flow** and the **sipgate REST API v2**.
//!
//! sipgate ships two JSON APIs that are easy to confuse, and this crate keeps
//! them apart:
//!
//! * [`flow`] — the real-time voice product. Your webhook **receives** events
//!   (`session_start`, `user_speak`, `dtmf_received`, …) and **returns** actions
//!   (`speak`, `audio`, `transfer`, …) in the HTTP response. There is no
//!   separate "post an action" endpoint. See <https://flow.sipgate.io/api/>.
//! * [`rest`] — the imperative REST API v2 at `https://api.sipgate.com/v2`:
//!   send SMS and fax, start calls, and control a live call (hangup, DTMF,
//!   announcement, recording, hold, mute, transfer). See
//!   <https://api.sipgate.com/v2/doc>.
//!
//! Every shape in this crate was taken from public documentation; `docs/
//! contracts.md` cites the source per shape and names the few that could not be
//! verified. Parsing is tolerant in both directions the wire can drift
//! (unknown fields, unknown event types, unknown enum values, camelCase **and**
//! `snake_case`), while everything sent is validated first.
//!
//! # Receiving an event and answering it
//!
//! ```
//! use sipgate_flow::{Action, Event, EventPayload, FlowResponse, WebhookVerifier};
//!
//! let verifier = WebhookVerifier::new("shared-secret")?;
//! let event = verifier.verify_and_parse(
//!     Some("shared-secret"),
//!     Some("application/json"),
//!     br#"{"type":"user_speak","text":"Ich brauche Hilfe","session":{"id":"s1"}}"#,
//! )?;
//!
//! let response = match event.payload() {
//!     EventPayload::UserSpeak { text, .. } if text.contains("Hilfe") => {
//!         FlowResponse::one(Action::speak(event.session_id().unwrap_or_default(), "Ich verbinde.")?)
//!     }
//!     _ => FlowResponse::none(),
//! };
//! assert_eq!(response.status(), 200);
//! # Ok::<(), sipgate_flow::Error>(())
//! ```
//!
//! # Calling the REST API
//!
//! ```no_run
//! # #[cfg(feature = "http")]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use sipgate_flow::{rest::Sms, PersonalAccessToken, ReqwestTransport, RestClient};
//!
//! // A PAT goes out as `Authorization: Basic base64(id:token)`, as documented.
//! let auth = PersonalAccessToken::new(
//!     std::env::var("SIPGATE_TOKEN_ID")?,
//!     std::env::var("SIPGATE_TOKEN")?,
//! )?;
//! let client = RestClient::new(ReqwestTransport::new(), auth);
//! client.send_sms(&Sms::new("s0", "4915112345678", "Hallo!")?).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Retries never sleep inside the library
//!
//! [`RestClient`] computes a bounded backoff (honouring `Retry-After`) and then
//! awaits a caller-supplied [`Sleeper`]. Pass `FnSleeper::new(tokio::time::sleep)`
//! in production — the wait is then cancellation safe because it is *your*
//! future, not a task the library spawned.
//!
//! # A request is repeated only when a repeat is harmless
//!
//! sipgate documents no idempotency key, so the client retries `429`, `5xx` on
//! an idempotent method and failures that happened before the write — nothing
//! else. A `5xx` (or a timeout, or a reset) after a `POST` may have sent the
//! SMS, started the call or spent the money already, so it surfaces as
//! [`Error::Ambiguous`] with [`Error::is_retryable`] `false` and the decision
//! stays with the caller. [`classify`] is the pure function behind that rule:
//!
//! ```
//! use sipgate_flow::{classify, Method, RetryOutcome};
//!
//! assert_eq!(classify(Method::Post, 503), RetryOutcome::Ambiguous);
//! assert_eq!(classify(Method::Delete, 503), RetryOutcome::Retry);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod auth;
pub mod base64;
pub mod error;
pub mod flow;
pub mod rest;
pub mod retry;
pub mod transport;
pub mod wav;

mod exchange;
mod validate;

pub use auth::{
    ClientCredentials, Clock, OAuth2Client, PersonalAccessToken, StaticToken, SystemClock, Token,
    TokenSource,
};
pub use error::{Error, Result};
pub use flow::action::{
    Action, ActionKind, Audio, BargeInConfig, BargeInStrategy, ConfigureTranscription, MixAudio,
    SendSms, Speak, TranscriptionProvider, Transfer, Tts, Vad,
};
pub use flow::client::{FlowClient, OutboundCall, OutboundCallReceipt};
pub use flow::event::{
    Direction, ErrorCode, Event, EventPayload, Session, Severity, SmsFailureReason,
    TransferFailedReason,
};
pub use flow::response::FlowResponse;
pub use flow::webhook::{self, WebhookVerifier};
pub use rest::RestClient;
pub use retry::{
    classify, parse_retry_after, retry_after_from, FnSleeper, NoSleep, RetryOutcome, RetryPolicy,
    Sleeper,
};
pub use transport::{Method, Request, RequestBody, Response, Security, Transport};

#[cfg(feature = "http")]
pub use transport::ReqwestTransport;
