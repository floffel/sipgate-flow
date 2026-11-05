//! Typed, tolerant client for **sipgate flow**, the classic **sipgate.io Push
//! API** and the **sipgate REST API v2**.
//!
//! sipgate ships three webhook-shaped protocols that are easy to confuse, and
//! this crate keeps them apart:
//!
//! * [`flow`] — the real-time voice product. Your webhook **receives** events
//!   (`session_start`, `user_speak`, `dtmf_received`, …) and **returns** actions
//!   (`speak`, `audio`, `transfer`, …) in the HTTP response. There is no
//!   separate "post an action" endpoint. See <https://flow.sipgate.io/api/>.
//! * [`push`] — the classic sipgate.io Push API: a
//!   `application/x-www-form-urlencoded` event (`newCall`, `answer`, `hangup`,
//!   `dtmf`) arrives and the handler answers with an XML `<Response>`
//!   (`Dial`, `Play`, `Gather`, `Reject`, `Hangup`). See
//!   <https://en.sipgate.io/push-api/api-references>.
//! * [`rest`] — the imperative REST API v2 at `https://api.sipgate.com/v2`:
//!   send SMS and fax, start calls, and control a live call (hangup, DTMF,
//!   announcement, recording, hold, mute, transfer). See
//!   <https://api.sipgate.com/v2/doc>.
//!
//! Every shape in this crate was taken from public documentation;
//! [docs/contracts.md](https://github.com/floffel/sipgate-flow/blob/main/docs/contracts.md)
//! cites the source per shape and names the few that could not be verified.
//! Parsing is tolerant in both directions the wire can drift
//! (unknown fields, unknown event types, unknown enum values, camelCase **and**
//! `snake_case`), while everything sent is validated first.
//!
//! # What "tolerant" means here
//!
//! Unknown *fields* on a known event survive in [`Event::extra`] and come back
//! out of [`Event::to_json`], so a field sipgate adds tomorrow still reaches a
//! caller that inspects the remainder:
//!
//! ```
//! use sipgate_flow::Event;
//!
//! let event = Event::parse(
//!     br#"{"type":"user_speak","text":"hi","confidence":0.97,"session":{"id":"s"}}"#,
//! )?;
//! assert_eq!(event.extra()["confidence"], 0.97);
//! assert_eq!(event.to_json()["confidence"], 0.97);
//! # Ok::<(), sipgate_flow::Error>(())
//! ```
//!
//! An unknown event *type* becomes the catch-all [`EventPayload::Unknown`] with
//! the raw JSON preserved, instead of failing the parse:
//!
//! ```
//! use sipgate_flow::{Event, EventPayload};
//!
//! let event = Event::parse(
//!     br#"{"type":"call_transferred","detail":{"to":"4915112345678"},"session":{"id":"s"}}"#,
//! )?;
//! let EventPayload::Unknown(raw) = event.payload() else {
//!     unreachable!("an unmodelled type must fall back to Unknown");
//! };
//! assert!(raw.get().contains("call_transferred"));
//! # Ok::<(), sipgate_flow::Error>(())
//! ```
//!
//! Both `camelCase` and `snake_case` keys are accepted for the event fields
//! where sipgate uses either, for example `bargedIn` and `durationMs`:
//!
//! ```
//! use sipgate_flow::{Event, EventPayload};
//!
//! let barged = Event::parse(
//!     br#"{"type":"user_speak","text":"Wait","bargedIn":true,"session":{"id":"s"}}"#,
//! )?;
//! assert!(matches!(
//!     barged.payload(),
//!     EventPayload::UserSpeak { barged_in: true, .. }
//! ));
//!
//! let speak = Event::parse(
//!     br#"{"type":"assistant_speak","durationMs":1200,"session":{"id":"s"}}"#,
//! )?;
//! assert!(matches!(
//!     speak.payload(),
//!     EventPayload::AssistantSpeak { duration_ms: Some(1200), .. }
//! ));
//! # Ok::<(), sipgate_flow::Error>(())
//! ```
//!
//! Unknown enum *values* are carried verbatim instead of being rejected, so a
//! new severity or failure reason still reaches the caller:
//!
//! ```
//! use sipgate_flow::{Severity, SmsFailureReason};
//!
//! assert_eq!(Severity::from_wire("notice"), Severity::Other("notice".into()));
//! assert_eq!(
//!     SmsFailureReason::from_wire("provider_quirk"),
//!     SmsFailureReason::Other("provider_quirk".into())
//! );
//! # Ok::<(), sipgate_flow::Error>(())
//! ```
//!
//! "Everything sent is validated first" is the other half of the contract:
//! parsing stays permissive, but an outgoing [`Action`] refuses a value sipgate
//! would reject. A session id an event may still carry parses, yet the action
//! constructor that would interpolate it refuses it with a typed error:
//!
//! ```
//! use sipgate_flow::{Action, Error, Event};
//!
//! // The event parses even without a usable session id: the field is present
//! // but empty, so the event is simply unaddressable ...
//! let event = Event::parse(br#"{"type":"user_speak","text":"hi","session":{"id":""}}"#)?;
//! assert_eq!(event.session().expect("session object").id, "");
//! assert_eq!(event.session_id(), None);
//!
//! // ... but the action that would address it does not.
//! let error = Action::speak("", "hi").expect_err("an empty session id is refused");
//! assert!(matches!(
//!     error,
//!     Error::Validation { field: "session_id", .. }
//! ));
//! # Ok::<(), sipgate_flow::Error>(())
//! ```
//!
//! # Receiving an event and answering it
//!
//! ```
//! use sipgate_flow::{Action, Error, Event, EventPayload, FlowResponse, WebhookVerifier};
//!
//! /// Answers a verified event. A missing session id means the event cannot be
//! /// addressed, so the handler returns `204` instead of substituting a default.
//! fn answer(event: &Event) -> Result<FlowResponse, Error> {
//!     let Some(session) = event.session_id() else {
//!         return Ok(FlowResponse::none());
//!     };
//!     match event.payload() {
//!         EventPayload::UserSpeak { text, .. } if text.contains("Hilfe") => {
//!             Ok(FlowResponse::one(Action::speak(session, "Ich verbinde.")?))
//!         }
//!         _ => Ok(FlowResponse::none()),
//!     }
//! }
//!
//! let verifier = WebhookVerifier::new("shared-secret")?;
//! let event = verifier.verify_and_parse(
//!     Some("shared-secret"),
//!     Some("application/json"),
//!     br#"{"type":"user_speak","text":"Ich brauche Hilfe","session":{"id":"s1"}}"#,
//! )?;
//! assert_eq!(answer(&event)?.status(), 200);
//!
//! // An event without a session id is unactionable, not a reason to guess.
//! let headless = verifier.verify_and_parse(
//!     Some("shared-secret"),
//!     Some("application/json"),
//!     br#"{"type":"user_speak","text":"Ich brauche Hilfe"}"#,
//! )?;
//! assert_eq!(answer(&headless)?.status(), 204);
//! # Ok::<(), sipgate_flow::Error>(())
//! ```
//!
//! # Answering a classic Push API call
//!
//! The classic Push API is a different protocol with its own module. The
//! request is form-encoded and the answer is XML; [`push::PushVerifier`]
//! enforces the content type and the body ceiling, and [`push::PushResponse`]
//! renders the document:
//!
//! ```rust
//! use sipgate_flow::push::{Dial, PushAction, PushResponse, PushVerifier};
//!
//! let event = PushVerifier::new().verify_and_parse(
//!     Some("application/x-www-form-urlencoded"),
//!     b"event=newCall&direction=in&from=492111234567&to=4915791234567&callId=123456",
//! )?;
//! assert_eq!(event.call_id(), Some("123456"));
//!
//! let response = PushResponse::new()
//!     .with_on_hangup("https://example.com/hangup")?
//!     .with_verb(PushAction::dial(Dial::to_number("4915799912345")?));
//! assert_eq!(response.content_type(), "application/xml");
//! # Ok::<(), sipgate_flow::Error>(())
//! ```
//!
//! The reference documents no credential for this API, so `PushVerifier` does
//! not pretend to authenticate a caller; the module documentation states what
//! that means for a deployment.
//!
//! # Calling the REST API
//!
//! [`PersonalAccessToken`] maps to [`transport::Security::Basic`], whose
//! documentation states the PAT wire form:
//! `Authorization: Basic base64(<token id>:<token>)`.
//!
//! [`RestClient`] is generic over the public [`Transport`] trait, so the same
//! client runs against `reqwest`, a test double, or any other HTTP stack. This
//! example drives it with an in-memory mock — no socket, no feature gate — and
//! proves the request the client sends is exactly `POST /v2/sessions/sms` with
//! the PAT rendered as a Basic credential:
//!
//! ```
//! use sipgate_flow::{PersonalAccessToken, Request, Response, RestClient, RestSms};
//! use sipgate_flow::{Result, Transport};
//!
//! #[derive(Clone, Default)]
//! struct Mock(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
//!
//! impl Transport for Mock {
//!     async fn execute(&self, request: Request<'_>) -> Result<Response> {
//!         self.0.lock().unwrap().push(request.url.to_string());
//!         // A 2xx answer with a JSON body is what `send_sms` decodes.
//!         Ok(Response::new(200, std::iter::empty(), b"{}".to_vec()))
//!     }
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().build().expect("runtime").block_on(async {
//! let transport = Mock::default();
//! let auth = PersonalAccessToken::new("token-FQ1V12", "e68ead46")?;
//! let client = RestClient::new(transport.clone(), auth);
//!
//! let sms = RestSms::new("s0", "4915112345678", "Hallo!")?;
//! client.send_sms(&sms).await?;
//!
//! assert_eq!(
//!     *transport.0.lock().unwrap(),
//!     vec!["https://api.sipgate.com/v2/sessions/sms".to_string()],
//! );
//! # Ok::<(), sipgate_flow::Error>(())
//! # });
//! ```
//!
//! Against the real API the only change is the transport; the PAT still goes
//! out as `Authorization: Basic base64(<token id>:<token>)`, as documented.
//! Only the transport choice is feature-gated, so the credential and request
//! build stay compiled (and honest) even with `http` off:
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use sipgate_flow::{PersonalAccessToken, RestClient, RestSms};
//!
//! let auth = PersonalAccessToken::new(
//!     std::env::var("SIPGATE_TOKEN_ID")?,
//!     std::env::var("SIPGATE_TOKEN")?,
//! )?;
//! let sms = RestSms::new("s0", "4915112345678", "Hallo!")?;
//!
//! # #[cfg(feature = "http")]
//! # {
//! use sipgate_flow::ReqwestTransport;
//!
//! let client = RestClient::new(ReqwestTransport::new(), auth);
//! client.send_sms(&sms).await?;
//! # }
//! # #[cfg(not(feature = "http"))]
//! # let _ = (auth, sms);
//! # Ok(())
//! # }
//! ```
//!
//! # Receiving the same events over a WebSocket
//!
//! Flow can also connect *to you* and stream the events over a WebSocket
//! (<https://flow.sipgate.io/api/websocket>, `websocket` feature). Because Flow
//! is the connector, the server half stays yours: adapt your framework's
//! connection to `Connection` and `FlowSocket` turns frames into the same
//! [`Event`] and [`Action`] types the webhook path uses. `user_speech_started`
//! only exists on this transport; every other event is `HTTP + WebSocket`.
//!
//! ```no_run
//! # #[cfg(feature = "websocket")]
//! # async fn demo() -> Result<(), sipgate_flow::Error> {
//! use sipgate_flow::{Action, Connection, EventPayload, FlowResponse, FlowSocket, Frame};
//!
//! # struct MyConnection;
//! # impl Connection for MyConnection {
//! #     async fn recv(&self) -> sipgate_flow::Result<Option<Frame>> { Ok(None) }
//! #     async fn send(&self, _frame: Frame) -> sipgate_flow::Result<()> { Ok(()) }
//! # }
//! let socket = FlowSocket::new(MyConnection);
//!
//! // One connection is one call: drive it until Flow closes the link.
//! let handled = socket.run(|event| async move {
//!     let Some(session) = event.session_id() else {
//!         return Ok(FlowResponse::none());
//!     };
//!     match event.payload() {
//!         EventPayload::UserSpeak { text, .. } if text.contains("Hilfe") => {
//!             Ok(FlowResponse::one(Action::speak(session, "Ich verbinde.")?))
//!         }
//!         _ => Ok(FlowResponse::none()),
//!     }
//! }).await?;
//! # let _ = handled;
//! # Ok(())
//! # }
//! ```
//!
//! A handler is also allowed to speak without being asked: the transport is
//! bidirectional, so `FlowSocket::send_action` sends an action on its own.
//!
//! # Retries never sleep inside the library
//!
//! [`RestClient`] computes a bounded, jittered backoff (honouring
//! `Retry-After`) and then awaits a caller-supplied [`Sleeper`]. Pass
//! `FnSleeper::new(tokio::time::sleep)` in production — the wait is then
//! cancellation safe because it is *your* future, not a task the library
//! spawned.
//!
//! # A request is repeated only when a repeat is harmless
//!
//! sipgate documents no idempotency key, so the client retries `408`, `425`,
//! `429`, retryable `5xx` on an idempotent method, and failures that happened
//! before the write — nothing else. A retryable `5xx` (or a timeout, or a
//! reset) after a `POST` may have sent the SMS, started the call or spent the
//! money already, so it surfaces as [`Error::Ambiguous`] with
//! [`Error::is_retryable`] `false` and the decision stays with the caller.
//! [`classify`] is the pure function behind that rule:
//!
//! ```
//! use sipgate_flow::{classify, Method, RetryOutcome};
//!
//! assert_eq!(classify(Method::Post, 503), RetryOutcome::Ambiguous);
//! assert_eq!(classify(Method::Delete, 503), RetryOutcome::Retry);
//! ```
//!
//! The caller is not left with a coin flip: when the server answered before
//! the failure, the response evidence that decides the question is kept on the
//! error. [`Error::ambiguous_body`] returns the body and
//! [`Error::ambiguous_header`] returns an identifier header such as an SMS id,
//! a call id or a request id, so the caller can check whether sipgate already
//! created the resource instead of guessing. A timeout or reset with no
//! response at all leaves both empty, which is the genuine "unknown" case.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod auth;
pub mod base64;
pub mod error;
pub mod flow;
pub mod push;
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
pub use error::{Base64Error, Error, Result, MAX_RETRY_AFTER};
/// The sipgate Flow `send_sms` action.
///
/// This is the action returned from a Flow webhook response. The REST API v2
/// has a separate request body, [`RestSms`]; the two deliberately do not share
/// a type because their wire shapes and validation differ.
///
/// ```
/// use sipgate_flow::{FlowSendSms, SendSms};
///
/// let action: SendSms = FlowSendSms::new("4915112345678", "hi")?;
/// assert_eq!(action.phone_number(), "4915112345678");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
pub use flow::action::SendSms as FlowSendSms;
pub use flow::action::{
    Action, ActionKind, Audio, BargeInConfig, BargeInStrategy, ConfigureTranscription, MixAudio,
    SendSms, Speak, TranscriptionProvider, Transfer, Tts, Vad,
};
pub use flow::client::{
    AccountRetentionSettings, AgentVoices, AiWebhookConfig, AiWebhookHeader, AiWebhookSettings,
    CurrentVoice, FlowClient, OutboundCall, OutboundCallReceipt, RecordingAnnouncementMode,
    SetAccountRetentionSettings, SynthesizeRequest, SynthesizeStreamRequest, SynthesizedAudio,
    TranscriptionAnnouncementMode, TransferCallerIdSource, TtsSetting, TtsVoice,
    MAX_ACCOUNT_SETTING_TOKEN_BYTES, MAX_EVENT_RETENTION_DAYS, MIN_EVENT_RETENTION_DAYS,
};
pub use flow::event::{
    Direction, ErrorCode, Event, EventPayload, Session, Severity, SmsFailureReason,
    TransferFailedReason, MAX_EVENT_BODY_BYTES,
};
pub use flow::response::FlowResponse;
#[cfg(feature = "websocket")]
pub use flow::socket::{
    AcceptBackoff, Connection, FlowSocket, Frame, MockConnection, MAX_SOCKET_MESSAGE_BYTES,
};
pub use flow::webhook::{self, WebhookVerifier};
pub use rest::RestClient;
/// The sipgate REST API v2 `POST /v2/sessions/sms` request body.
///
/// This is the payload passed to [`RestClient::send_sms`]. It requires a
/// sending device id and keeps the `+` on E.164 recipients, unlike the Flow
/// action [`FlowSendSms`].
///
/// ```
/// use sipgate_flow::{rest::Sms, RestSms};
///
/// let request: Sms = RestSms::new("s0", "4915112345678", "hi")?;
/// assert_eq!(request.recipient(), "+4915112345678");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
pub use rest::Sms as RestSms;
pub use retry::{
    classify, parse_retry_after, retry_after_from, retry_after_from_with_clock, FnSleeper, NoSleep,
    RetryOutcome, RetryPolicy, Sleeper, MIN_RETRY_DELAY,
};
pub use transport::{Method, Request, RequestBody, Response, Security, Transport};

#[cfg(feature = "http")]
pub use transport::ReqwestTransport;
