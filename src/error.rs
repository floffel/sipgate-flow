//! One error type for parsing, verification, authentication and transport.
//!
//! Every variant states what the caller can do about it, and
//! [`Error::is_retryable`] / [`Error::is_ambiguous`] / [`Error::retry_after`]
//! answer the three questions a retry loop asks: may I repeat this, did it
//! already happen, and what bounded wait hint did the server give. The enum is `#[non_exhaustive]`: new failure modes can be
//! added without a breaking release, so match with a `_` arm.
//!
//! ```
//! use sipgate_flow::{Action, Error};
//!
//! let err = Action::speak("session-1", "").unwrap_err();
//! assert!(matches!(err, Error::Validation { field: "text", .. }));
//! assert!(!err.is_retryable());
//! ```

use std::time::Duration;

use base64::DecodeError;
use thiserror::Error;

use crate::transport::Method;

/// Longest remote-controlled string kept in an error.
const SAFE_TEXT_BYTES: usize = 512;

/// Upper bound for a server-supplied `Retry-After` hint.
///
/// A broken proxy or hostile response can put an arbitrarily large
/// delta-seconds value in `Retry-After`. Errors clamp the hint to this ceiling
/// before exposing it through [`Error::retry_after`], so a caller that follows
/// the documented retry-loop pattern cannot be parked for an unbounded time.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::MAX_RETRY_AFTER;
///
/// assert_eq!(MAX_RETRY_AFTER, Duration::from_secs(24 * 60 * 60));
/// ```
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

fn is_http_status(status: u16) -> bool {
    (100..=599).contains(&status)
}

fn bounded_retry_after(retry_after: Option<Duration>) -> Option<Duration> {
    retry_after.map(|hint| hint.min(MAX_RETRY_AFTER))
}

/// The category of a base64 decoding failure.
///
/// This keeps the decoder's typed cause available without rendering the
/// offending byte or offset the way [`base64::DecodeError`] does.
///
/// ```
/// use sipgate_flow::Base64Error;
///
/// let kind = Base64Error::InvalidLength;
/// assert!(matches!(kind, Base64Error::InvalidLength));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Base64Error {
    /// The input contained a byte outside the standard alphabet.
    InvalidByte,
    /// The input length cannot form a canonical base64 suffix.
    InvalidLength,
    /// Padding was missing, misplaced, or non-canonical.
    InvalidPadding,
    /// The final symbol had non-zero trailing bits.
    InvalidLastSymbol,
}

/// Bounds and sanitises remote-controlled text before it reaches a log sink.
fn safe_text(value: &str) -> String {
    let mut sanitised = String::with_capacity(value.len().min(SAFE_TEXT_BYTES));
    for character in value.chars() {
        let character = if character.is_control() {
            '\u{FFFD}'
        } else {
            character
        };
        if sanitised.len() + character.len_utf8() > SAFE_TEXT_BYTES {
            break;
        }
        sanitised.push(character);
    }
    sanitised
}

/// Bounds and sanitises a response body before it reaches a log sink.
fn safe_body(body: &str) -> Vec<u8> {
    safe_text(&crate::retry::truncate_body(body)).into_bytes()
}

/// Bounds and sanitises response headers before they reach an error.
///
/// The value is truncated to [`SAFE_TEXT_BYTES`] and control characters are
/// replaced, mirroring [`safe_body`]. `Authorization`, `Cookie` and
/// `Set-Cookie` are dropped because an error is routinely logged and those
/// headers carry credentials or session material.
fn safe_headers(headers: &[(&str, &str)]) -> Vec<(String, String)> {
    const SENSITIVE: [&str; 3] = ["authorization", "cookie", "set-cookie"];
    headers
        .iter()
        .filter(|(name, _)| !SENSITIVE.contains(&name.to_ascii_lowercase().as_str()))
        .map(|(name, value)| (safe_text(name), safe_text(value)))
        .collect()
}

/// Renders a sanitised response body held as bytes.
fn display_body(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

/// Everything that can go wrong while parsing an event, verifying a webhook or
/// calling an API.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The body was not valid JSON, or a documented required field had the
    /// wrong JSON type. Serde's position information is kept as the source.
    ///
    /// Build this variant with [`Error::json_parse`].
    #[error("invalid JSON payload: {source}")]
    Json {
        /// The underlying serde error.
        source: serde_json::Error,
    },

    /// A value this crate emitted could not be encoded as JSON. This is
    /// distinct from [`Error::Json`]: the failure is on the way out, not a
    /// remote payload that failed to parse.
    ///
    /// Build this variant with [`Error::json_encode`].
    #[error("could not encode JSON body: {source}")]
    JsonEncode {
        /// The underlying serde error.
        source: serde_json::Error,
    },

    /// The body was empty. A webhook call without a body carries no event.
    #[error("empty payload")]
    EmptyBody,

    /// A value would be rejected by the API, or is unsafe to interpolate into
    /// a URL or a log line. Nothing is sent.
    #[error("invalid {field}: {message}")]
    Validation {
        /// Dotted path of the offending field, for example `session_id`.
        field: &'static str,
        /// What is wrong and which range is accepted.
        message: String,
    },

    /// An action was prepared for an event whose contract allows no action
    /// response. `session_end` documents this explicitly, and
    /// `user_speech_started`, `user_barge_in` and `sms_failed` are not in the
    /// documented response table at all, so
    /// [`Event::accepts_actions`](crate::Event::accepts_actions) reports
    /// `false` for them and the `websocket` feature's `FlowSocket::send_response`
    /// refuses to write the message.
    #[error("event `{kind}` accepts no action response")]
    ActionNotAccepted {
        /// The event type the response was addressed to.
        kind: String,
    },

    /// A base64 payload could not be decoded.
    ///
    /// The top-level message stays input-free. The original decoder error is
    /// kept as the source so callers can inspect the typed failure class.
    ///
    /// ```
    /// use sipgate_flow::{base64, Base64Error, Error};
    ///
    /// let err = base64::decode("AB==").unwrap_err();
    /// assert!(matches!(
    ///     err,
    ///     Error::Base64 { kind: Base64Error::InvalidLastSymbol, .. }
    /// ));
    /// assert!(std::error::Error::source(&err).is_some());
    /// ```
    #[non_exhaustive]
    #[error("invalid base64: {message}")]
    Base64 {
        /// The decoder failure class, without offsets or bytes.
        kind: Base64Error,
        /// What is wrong, without echoing the input.
        message: String,
        /// The underlying base64 decoder error.
        #[source]
        source: DecodeError,
    },

    /// The request URL could not be built safely, so no request was sent and
    /// no credential was attached.
    ///
    /// Build this variant with [`Error::invalid_request`].
    #[non_exhaustive]
    #[error("invalid request {field}: {message}")]
    InvalidRequest {
        /// Dotted path of the offending field, for example `path`.
        field: &'static str,
        /// What is wrong and which URL shape is accepted.
        message: String,
    },

    /// A client id or client secret was empty. A request with empty
    /// credentials would be rejected by the token endpoint anyway, so
    /// construction fails closed instead.
    #[error("client id and client secret must not be empty")]
    EmptyCredentials,

    /// A webhook secret was empty: every request would verify.
    #[error("webhook secret must not be empty")]
    EmptySecret,

    /// The webhook request carried no `X-API-TOKEN` header.
    #[error("webhook request carried no shared secret")]
    MissingSecret,

    /// The shared secret did not match the configured one.
    #[error("webhook shared secret does not match")]
    SecretMismatch,

    /// The request body was not JSON. sipgate flow always sends
    /// `application/json`; `application/x-www-form-urlencoded` belongs to the
    /// separate Push API.
    ///
    /// Build this variant with [`Error::unsupported_content_type`].
    #[non_exhaustive]
    #[error("unsupported content type `{content_type}`")]
    UnsupportedContentType {
        /// The value the request carried.
        content_type: String,
    },

    /// The body exceeded the configured limit.
    ///
    /// [`crate::WebhookVerifier::verify_reader`] returns this as soon as
    /// `limit + 1` bytes are observed, so it bounds the read that method
    /// performs. [`crate::WebhookVerifier::verify_and_parse`] receives an
    /// already-buffered body and therefore bounds parsing work only; callers
    /// using that method must enforce their framework's own body limit.
    #[error("payload of {size} bytes exceeds the {limit} byte limit")]
    BodyTooLarge {
        /// Size observed. For [`crate::WebhookVerifier::verify_reader`] this is
        /// `limit + 1`, because the bounded read stops there.
        size: usize,
        /// Configured ceiling.
        limit: usize,
    },

    /// Reading a webhook body from a reader failed.
    #[non_exhaustive]
    #[error("could not read webhook body: {message}")]
    BodyRead {
        /// Reader-supplied description.
        message: String,
        /// The underlying reader error.
        #[source]
        source: std::io::Error,
    },

    /// The token endpoint rejected the client credentials.
    ///
    /// Build this variant with [`Error::auth_rejected`].
    #[non_exhaustive]
    #[error("token endpoint rejected the client credentials (http {status}): {body}")]
    AuthRejected {
        /// HTTP status of the token response.
        status: u16,
        /// Response body, truncated to at most 512 bytes, with control
        /// characters replaced by `U+FFFD`.
        body: String,
    },

    /// The token response could not be used (missing `access_token`, wrong
    /// JSON type, empty value).
    ///
    /// Build this variant with [`Error::token_response`] or
    /// [`Error::token_response_with_source`].
    #[error("unusable token response: {message}")]
    TokenResponse {
        /// What is wrong with the response, without any credential.
        message: String,
        /// The underlying error, when one exists (for example a serde error
        /// from decoding the response).
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// A request was rejected with 401 in a terminal way: the token source
    /// cannot refresh, the method is not idempotent, or a second 401 arrived
    /// after the one allowed refresh.
    ///
    /// Build this variant with [`Error::unauthorized`]. The response body is
    /// truncated to at most 512 bytes at a UTF-8 boundary, and control
    /// characters are replaced by `U+FFFD`, before it is stored on the variant
    /// and rendered by `Display`.
    #[non_exhaustive]
    #[error("unauthorized after refreshing the access token (http {status}): {}", display_body(.body))]
    Unauthorized {
        /// HTTP status of the terminal response.
        status: u16,
        /// Sanitised response body, truncated to at most 512 bytes.
        body: Vec<u8>,
        /// Parsed `Retry-After` header, when the server sent one.
        retry_after: Option<Duration>,
        /// Provider request id, when the server sent one.
        request_id: Option<String>,
    },

    /// The transport failed before a usable response existed. `retryable` is
    /// true only when the failure provably happened before the request was
    /// written (DNS, TLS, connect); post-write timeouts and resets are
    /// [`Error::Ambiguous`].
    #[error("transport error: {message}")]
    Transport {
        /// Transport-supplied description.
        message: String,
        /// The underlying transport error, when one exists. Keeping the real
        /// error preserves the `reqwest` failure that answers
        /// `is_timeout()`/`is_connect()`.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        /// `true` for transient failures (I/O, timeouts), `false` otherwise.
        retryable: bool,
    },

    /// The WebSocket link failed: a frame could not be read or written.
    ///
    /// `retryable` is `true` for a dead connection — a *new* connection can
    /// succeed — and `false` when the failure is terminal for the caller's
    /// setup. It never means this crate re-sends a frame: when an action was
    /// lost with the link, the decision stays with the caller.
    ///
    /// Build this variant with [`Error::socket`], [`Error::socket_terminal`] or
    /// [`Error::socket_with_source`].
    #[non_exhaustive]
    #[error("websocket error: {message}")]
    Socket {
        /// Adapter-supplied description, without credentials.
        message: String,
        /// The underlying socket error, when one exists.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        /// `true` when a new connection could succeed.
        retryable: bool,
    },

    /// The API answered with a non-2xx status.
    ///
    /// Build this variant with [`Error::api`]. The variant is
    /// `#[non_exhaustive]` because its fields are public enum-variant fields,
    /// which Rust does not allow to be private; outside this crate it prevents
    /// literal construction and therefore prevents forging `retryable` or
    /// `ambiguous` into an unsafe combination.
    #[non_exhaustive]
    #[error("api error {status}: {body}")]
    Api {
        /// HTTP status. The constructors reject values outside `100..=599`.
        status: u16,
        /// Response body, truncated to at most 512 bytes, with control
        /// characters replaced by `U+FFFD`.
        body: String,
        /// Parsed `Retry-After` header, when the server sent one, clamped to
        /// [`MAX_RETRY_AFTER`].
        retry_after: Option<Duration>,
        /// `true` for 429, and for 5xx on an idempotent method only.
        retryable: bool,
        /// `true` for 5xx on a non-idempotent method: the request may already
        /// have been applied even though the response was an error.
        ambiguous: bool,
    },

    /// The outbound call request reached sipgate and the call may already be
    /// dialling, but no usable call identifier came back. This happens when a
    /// non-`201` 2xx response is returned, or when the documented `201` body
    /// cannot be decoded.
    ///
    /// The operation is ambiguous: the call may already have been placed.
    /// Retrying it would dial the recipient a second time, so
    /// [`Error::is_retryable`] is `false` and [`Error::is_ambiguous`] is `true`.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::CallStartedUnknown { status: 204, body: String::new() };
    /// assert!(err.is_ambiguous());
    /// assert!(!err.is_retryable());
    /// assert_eq!(err.status(), Some(204));
    /// ```
    #[error("call started but identifier is unknown (http {status}): {body}")]
    CallStartedUnknown {
        /// HTTP status returned for the accepted call request.
        status: u16,
        /// Response body, truncated to at most 512 bytes, with control
        /// characters replaced by `U+FFFD`.
        body: String,
    },

    /// The Flow cannot start an outbound call because it has no phone number.
    ///
    /// sipgate documents `400 Bad Request` for this outcome on
    /// `POST /v3/ai-flows/{aiFlowId}/call`. The failure is terminal: fixing the
    /// Flow configuration is required before another call can succeed.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::call_outcome(400, "no phone number").expect("documented call status");
    /// assert!(matches!(err, Error::FlowNotCallable { status: 400, .. }));
    /// assert_eq!(err.status(), Some(400));
    /// assert!(!err.is_retryable());
    /// ```
    #[non_exhaustive]
    #[error("flow has no phone number (http {status}): {body}")]
    FlowNotCallable {
        /// HTTP status returned for the rejected call request.
        status: u16,
        /// Response body, truncated to at most 512 bytes, with control
        /// characters replaced by `U+FFFD`.
        body: String,
        /// Source context with the same status and sanitized body, so callers
        /// that inspect cause chains do not lose the API details.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The Flow id does not identify an existing Flow.
    ///
    /// sipgate documents `404 Not Found` for this outcome on
    /// `POST /v3/ai-flows/{aiFlowId}/call`. The failure is terminal: retrying
    /// the same id cannot make the Flow appear.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::call_outcome(404, "flow not found").expect("documented call status");
    /// assert!(matches!(err, Error::FlowNotFound { status: 404, .. }));
    /// assert_eq!(err.status(), Some(404));
    /// assert!(!err.is_retryable());
    /// ```
    #[non_exhaustive]
    #[error("flow does not exist (http {status}): {body}")]
    FlowNotFound {
        /// HTTP status returned for the rejected call request.
        status: u16,
        /// Response body, truncated to at most 512 bytes, with control
        /// characters replaced by `U+FFFD`.
        body: String,
        /// Source context with the same status and sanitized body, so callers
        /// that inspect cause chains do not lose the API details.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The account has not been granted access to start calls for this Flow.
    ///
    /// sipgate documents `403 Forbidden` for this outcome on
    /// `POST /v3/ai-flows/{aiFlowId}/call`. The failure is terminal: retrying
    /// without the missing account permission cannot succeed.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::call_outcome(403, "access denied").expect("documented call status");
    /// assert!(matches!(err, Error::AccessNotGranted { status: 403, .. }));
    /// assert_eq!(err.status(), Some(403));
    /// assert!(!err.is_retryable());
    /// ```
    #[non_exhaustive]
    #[error("access to call the flow was not granted (http {status}): {body}")]
    AccessNotGranted {
        /// HTTP status returned for the rejected call request.
        status: u16,
        /// Response body, truncated to at most 512 bytes, with control
        /// characters replaced by `U+FFFD`.
        body: String,
        /// Source context with the same status and sanitized body, so callers
        /// that inspect cause chains do not lose the API details.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The request reached the point where the server could act on it, but no
    /// usable success response came back - a 5xx on a `POST`, or a
    /// timeout/reset while waiting. The operation **may** have happened.
    ///
    /// This is not an error the library can retry: repeating it duplicates an
    /// SMS, a fax, a recording or an outbound call, and sipgate documents no
    /// idempotency key. [`Error::is_retryable`] is therefore `false` and the
    /// decision stays with the caller.
    ///
    /// The information that decides it is kept on the variant: when the
    /// server answered with a body or an identifier header before failing,
    /// [`Error::ambiguous_body`] and [`Error::ambiguous_header`] expose them
    /// so the caller can tell a completed request from one that never
    /// happened. A timeout or reset that arrived with no response at all
    /// leaves both empty, which is the genuine "unknown" case.
    ///
    /// Build this variant with [`Error::ambiguous`] or
    /// [`Error::ambiguous_with_response`].
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::ambiguous_with_response(
    ///     Some(502),
    ///     "bad gateway after POST /v2/sessions/sms",
    ///     "{\"ok\":false}",
    ///     [("x-request-id", "req_123")],
    /// );
    /// assert!(err.is_ambiguous());
    /// assert_eq!(err.ambiguous_body(), Some("{\"ok\":false}"));
    /// assert_eq!(err.ambiguous_header("X-Request-Id"), Some("req_123"));
    /// ```
    #[error("ambiguous outcome: {message}")]
    Ambiguous {
        /// The status that arrived, if one did: a 5xx. `None` when the
        /// connection died after the write (timeout, reset) and no status
        /// exists.
        status: Option<u16>,
        /// What happened, without the request body or any credential.
        message: String,
        /// Response body observed before the failure, bounded and sanitised,
        /// when the server sent one. Empty when no response body existed.
        body: Vec<u8>,
        /// Response headers observed before the failure, bounded, sanitised
        /// and stripped of credential-bearing names. Empty when no response
        /// existed.
        headers: Vec<(String, String)>,
    },
}

#[derive(Debug, Error)]
#[error("api error {status}: {body}")]
struct CallOutcomeContext {
    status: u16,
    body: String,
}

impl Error {
    /// Builds a JSON parse error, keeping serde's position information as the
    /// source.
    ///
    /// This is the only constructor that claims `invalid JSON payload`; a
    /// failure on the way out uses [`Error::json_encode`] instead.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let serde = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
    /// let err = Error::json_parse(serde);
    /// assert!(matches!(err, Error::Json { .. }));
    /// assert!(std::error::Error::source(&err).is_some());
    /// ```
    #[must_use]
    pub fn json_parse(source: serde_json::Error) -> Self {
        Self::Json { source }
    }

    /// Builds a JSON encode error for a value this crate emitted.
    ///
    /// A serialisation failure while building a request body is a bug on our
    /// side, not a bad remote payload, so it never claims
    /// `invalid JSON payload`.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let mut map = std::collections::BTreeMap::new();
    /// map.insert((1_u8, "key"), 1_u8);
    /// let serde = serde_json::to_vec(&map).unwrap_err();
    /// let err = Error::json_encode(serde);
    /// assert!(matches!(err, Error::JsonEncode { .. }));
    /// assert!(std::error::Error::source(&err).is_some());
    /// ```
    #[must_use]
    pub fn json_encode(source: serde_json::Error) -> Self {
        Self::JsonEncode { source }
    }

    /// Builds a token response error with no underlying source.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::token_response("missing or empty access_token");
    /// assert!(matches!(err, Error::TokenResponse { .. }));
    /// assert!(std::error::Error::source(&err).is_none());
    /// ```
    #[must_use]
    pub fn token_response(message: impl Into<String>) -> Self {
        Self::TokenResponse {
            message: message.into(),
            source: None,
        }
    }

    /// Builds a token response error that keeps the underlying failure.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let cause = std::io::Error::other("truncated body");
    /// let err = Error::token_response_with_source("could not decode token", cause);
    /// assert!(std::error::Error::source(&err).is_some());
    /// ```
    #[must_use]
    pub fn token_response_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::TokenResponse {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Builds a validation error. `field` is the dotted path, `message` the
    /// human readable detail.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::validation("message", "must not be empty");
    /// assert_eq!(err.to_string(), "invalid message: must not be empty");
    /// ```
    #[must_use]
    pub fn validation(field: &'static str, message: impl Into<String>) -> Self {
        Self::Validation {
            field,
            message: message.into(),
        }
    }

    /// Builds a terminal request-construction error.
    ///
    /// The request is refused before it can carry an `Authorization` header;
    /// callers should fix the base URL or path rather than retry it.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::invalid_request("path", "must start with /");
    /// assert!(matches!(err, Error::InvalidRequest { field: "path", .. }));
    /// assert!(!err.is_retryable());
    /// ```
    #[must_use]
    pub fn invalid_request(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidRequest {
            field,
            message: safe_text(&message.into()),
        }
    }

    /// Builds a webhook body read error.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::body_read(std::io::Error::other("connection lost"));
    /// assert!(matches!(err, Error::BodyRead { .. }));
    /// assert!(std::error::Error::source(&err).is_some());
    /// ```
    #[must_use]
    pub fn body_read(source: std::io::Error) -> Self {
        Self::BodyRead {
            message: safe_text(&source.to_string()),
            source,
        }
    }

    /// Builds an unsupported content type error with sanitised header text.
    ///
    /// The value is truncated to at most 512 bytes at a UTF-8 boundary, and
    /// control characters are replaced by `U+FFFD`, so a hostile
    /// `Content-Type` header cannot forge log lines.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::unsupported_content_type("text/plain");
    /// assert!(matches!(err, Error::UnsupportedContentType { .. }));
    /// ```
    #[must_use]
    pub fn unsupported_content_type(content_type: impl Into<String>) -> Self {
        Self::UnsupportedContentType {
            content_type: safe_text(&content_type.into()),
        }
    }

    /// Builds an authentication rejection with a sanitised response body.
    ///
    /// The body is truncated to at most 512 bytes at a UTF-8 boundary, and
    /// control characters are replaced by `U+FFFD`.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::auth_rejected(401, "denied");
    /// assert_eq!(err.status(), Some(401));
    /// ```
    #[must_use]
    pub fn auth_rejected(status: u16, body: impl Into<String>) -> Self {
        Self::AuthRejected {
            status,
            body: safe_text(&body.into()),
        }
    }

    /// Builds a terminal 401 error from the rejected response.
    ///
    /// The body is truncated to at most 512 bytes at a UTF-8 boundary, and
    /// control characters are replaced by `U+FFFD`, before it is stored on the
    /// variant and rendered by `Display`. The request id is bounded and
    /// sanitised the same way.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::unauthorized(
    ///     401,
    ///     "account disabled",
    ///     Some(Duration::from_secs(7)),
    ///     Some("req_123".to_string()),
    /// );
    /// assert!(matches!(err, Error::Unauthorized { status: 401, .. }));
    /// assert_eq!(err.status(), Some(401));
    /// assert_eq!(err.retry_after(), Some(Duration::from_secs(7)));
    /// assert!(!err.is_retryable());
    /// assert!(!err.is_ambiguous());
    /// assert_eq!(err.to_string(), "unauthorized after refreshing the access token (http 401): account disabled");
    /// ```
    #[must_use]
    pub fn unauthorized(
        status: u16,
        body: impl AsRef<[u8]>,
        retry_after: Option<Duration>,
        request_id: Option<String>,
    ) -> Self {
        let body = safe_body(&String::from_utf8_lossy(body.as_ref()));
        let request_id = request_id.map(|value| safe_text(&value));
        Self::Unauthorized {
            status,
            body,
            retry_after,
            request_id,
        }
    }

    /// Builds an API error from the request method, status, body and optional
    /// `Retry-After` hint.
    ///
    /// This is the safe constructor for [`Error::Api`]: `retryable` is
    /// `status == 429` or a 5xx on an idempotent method, while `ambiguous` is a
    /// 5xx on a non-idempotent method. The `status` must be in `100..=599`; an
    /// invalid value returns [`Error::Validation`] instead of producing an
    /// [`Error::Api`] with garbage. The `Retry-After` hint is clamped to
    /// [`MAX_RETRY_AFTER`].
    ///
    /// ```
    /// use sipgate_flow::{Error, Method};
    ///
    /// let err = Error::api(Method::Post, 502, "bad gateway", None);
    /// assert!(err.is_ambiguous());
    /// assert!(!err.is_retryable(), "retrying could send the SMS twice");
    /// assert_eq!(err.status(), Some(502));
    ///
    /// let err = Error::api(Method::Get, 503, "maintenance", None);
    /// assert!(err.is_retryable());
    /// assert!(!err.is_ambiguous());
    ///
    /// let invalid = Error::api(Method::Get, 9999, "proxy garbage", None);
    /// assert!(matches!(invalid, Error::Validation { field: "status", .. }));
    /// ```
    #[must_use]
    pub fn api(
        method: Method,
        status: u16,
        body: impl Into<String>,
        retry_after: Option<Duration>,
    ) -> Self {
        if !is_http_status(status) {
            return Self::validation("status", "must be in 100..=599");
        }
        let server_error = (500..600).contains(&status);
        let retryable = status == 429 || (server_error && method.is_idempotent());
        let ambiguous = server_error && !method.is_idempotent();
        Self::Api {
            status,
            body: safe_text(&body.into()),
            retry_after: bounded_retry_after(retry_after),
            retryable,
            ambiguous,
        }
    }

    /// Maps the documented `POST /v3/ai-flows/{aiFlowId}/call` failure statuses
    /// to their typed, terminal outcomes.
    ///
    /// `400` becomes [`Error::FlowNotCallable`], `403` becomes
    /// [`Error::AccessNotGranted`], and `404` becomes [`Error::FlowNotFound`].
    /// Every other status returns [`None`] so callers can keep the existing
    /// [`Error::Api`] or [`Error::Ambiguous`] behavior.
    ///
    /// The response body is truncated to at most 512 bytes at a UTF-8 boundary,
    /// and control characters are replaced by `U+FFFD`, before it is stored on
    /// the variant and on the source chain.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::call_outcome(403, "access denied").expect("documented call status");
    /// assert!(matches!(err, Error::AccessNotGranted { status: 403, .. }));
    /// assert_eq!(err.status(), Some(403));
    /// assert!(!err.is_retryable());
    /// assert!(std::error::Error::source(&err).is_some());
    /// assert!(Error::call_outcome(429, "slow down").is_none());
    /// ```
    #[must_use]
    pub fn call_outcome(status: u16, body: impl Into<String>) -> Option<Self> {
        let body = safe_text(&body.into());
        let context_body = body.clone();
        let context = || {
            Box::new(CallOutcomeContext {
                status,
                body: context_body.clone(),
            }) as Box<dyn std::error::Error + Send + Sync>
        };
        match status {
            400 => Some(Self::FlowNotCallable {
                status,
                body,
                source: context(),
            }),
            403 => Some(Self::AccessNotGranted {
                status,
                body,
                source: context(),
            }),
            404 => Some(Self::FlowNotFound {
                status,
                body,
                source: context(),
            }),
            _ => None,
        }
    }

    /// Builds a sanitised API error that is retryable and not ambiguous.
    ///
    /// This constructor is reserved for side-effect-free API calls such as the
    /// `OAuth2` token request, where a repeated request cannot duplicate work.
    pub(crate) fn api_retryable(
        status: u16,
        body: impl Into<String>,
        retry_after: Option<Duration>,
    ) -> Self {
        if !is_http_status(status) {
            return Self::validation("status", "must be in 100..=599");
        }
        Self::Api {
            status,
            body: safe_text(&body.into()),
            retry_after: bounded_retry_after(retry_after),
            retryable: true,
            ambiguous: false,
        }
    }

    /// Builds an ambiguous transport error when the write phase is unknown.
    ///
    /// This is the fail-closed constructor for transport failures whose write
    /// phase is not known: a timeout, reset or truncated response may have
    /// happened after the request was written, so it must not be retried
    /// automatically. Use [`Error::transport_before_write`] only when the
    /// failure provably happened before the request was written, for example
    /// DNS, TCP connect or TLS handshake failure.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::transport("connection reset");
    /// assert!(err.is_ambiguous());
    /// assert!(!err.is_retryable());
    /// ```
    #[must_use]
    pub fn transport(message: impl Into<String>) -> Self {
        Self::ambiguous(None, message)
    }

    /// Builds a retryable transport error for a failure that provably happened
    /// before the request was written, for example DNS, TCP connect or TLS
    /// handshake failure.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::transport_before_write("connect: refused");
    /// assert!(err.is_retryable());
    /// assert!(!err.is_ambiguous());
    /// ```
    #[must_use]
    pub fn transport_before_write(message: impl Into<String>) -> Self {
        Self::Transport {
            message: message.into(),
            source: None,
            retryable: true,
        }
    }

    /// Builds a terminal transport error (not retryable), for example an
    /// unsupported URL scheme.
    ///
    /// ```
    /// use sipgate_flow::Error;
    /// assert!(!Error::transport_terminal("unsupported scheme").is_retryable());
    /// ```
    #[must_use]
    pub fn transport_terminal(message: impl Into<String>) -> Self {
        Self::Transport {
            message: message.into(),
            source: None,
            retryable: false,
        }
    }

    /// Builds a retryable WebSocket error: the link is gone, a new connection
    /// can succeed.
    ///
    /// A dead link never makes this crate re-send a frame. If an action was
    /// written into a connection that died, only the caller can tell whether
    /// Flow received it, so the outcome is reported, not repaired.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::socket("recv: connection reset");
    /// assert!(err.is_retryable());
    /// assert!(!err.is_ambiguous());
    /// assert_eq!(err.to_string(), "websocket error: recv: connection reset");
    /// ```
    #[must_use]
    pub fn socket(message: impl Into<String>) -> Self {
        Self::Socket {
            message: message.into(),
            source: None,
            retryable: true,
        }
    }

    /// Builds a terminal WebSocket error (not retryable), for example a frame
    /// the adapter could not classify at all.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// assert!(!Error::socket_terminal("unsupported frame mask").is_retryable());
    /// ```
    #[must_use]
    pub fn socket_terminal(message: impl Into<String>) -> Self {
        Self::Socket {
            message: message.into(),
            source: None,
            retryable: false,
        }
    }

    /// Builds a WebSocket error that keeps the underlying failure on the cause
    /// chain, so an adapter does not have to flatten its own error type.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let io = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "peer went away");
    /// let err = Error::socket_with_source("send: broken pipe", true, io);
    /// assert!(err.is_retryable());
    /// assert!(std::error::Error::source(&err).is_some(), "the cause stays reachable");
    /// ```
    #[must_use]
    pub fn socket_with_source(
        message: impl Into<String>,
        retryable: bool,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Socket {
            message: message.into(),
            source: Some(Box::new(source)),
            retryable,
        }
    }

    /// Builds a transport error that keeps the underlying failure.
    ///
    /// This is the crate-internal constructor the `reqwest` adapter uses so the
    /// real transport error, which answers `is_timeout()`/`is_connect()`,
    /// survives on the cause chain. It exists only for that adapter, hence the
    /// `http` gate: without the feature nothing calls it and a
    /// `-D warnings` build of the minimal configuration would fail on dead
    /// code.
    #[cfg(feature = "http")]
    pub(crate) fn transport_with_source(
        message: impl Into<String>,
        retryable: bool,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Transport {
            message: message.into(),
            source: Some(Box::new(source)),
            retryable,
        }
    }

    /// Builds the "it may already have happened" outcome: a 5xx on a
    /// non-idempotent request, or a connection that died after the write.
    ///
    /// `status` is the HTTP status when one arrived, `None` when the request
    /// was cut off without an answer. This constructor carries no response
    /// body or headers; use [`Error::ambiguous_with_response`] when the
    /// server answered before the failure and the caller could use that
    /// evidence to resolve the ambiguity.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::ambiguous(Some(502), "bad gateway after POST /v2/sessions/sms");
    /// assert!(err.is_ambiguous());
    /// assert!(!err.is_retryable(), "a retry would send the SMS a second time");
    /// assert_eq!(err.status(), Some(502));
    /// assert_eq!(err.ambiguous_body(), None);
    /// ```
    #[must_use]
    pub fn ambiguous(status: Option<u16>, message: impl Into<String>) -> Self {
        Self::Ambiguous {
            status,
            message: message.into(),
            body: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Builds the "it may already have happened" outcome while keeping the
    /// response evidence that resolves it.
    ///
    /// The server answered with a status, and possibly a body or identifier
    /// headers, but the request may still have had an effect. An SMS id or a
    /// call id in this response tells the caller the request completed, so the
    /// decision the crate hands back is an informed one rather than a coin
    /// flip.
    ///
    /// The body is truncated to at most 512 bytes at a UTF-8 boundary and
    /// control characters are replaced by `U+FFFD`; header values are bounded
    /// the same way, and `Authorization`, `Cookie` and `Set-Cookie` are
    /// dropped before they are stored.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::ambiguous_with_response(
    ///     Some(503),
    ///     "5xx after POST /v2/sessions/sms",
    ///     "{\"id\":\"sms-42\"}",
    ///     [("x-request-id", "req_9")],
    /// );
    /// assert!(err.is_ambiguous());
    /// assert!(!err.is_retryable());
    /// assert_eq!(err.status(), Some(503));
    /// assert_eq!(err.ambiguous_body(), Some("{\"id\":\"sms-42\"}"));
    /// assert_eq!(err.ambiguous_header("X-Request-Id"), Some("req_9"));
    /// assert_eq!(err.ambiguous_header("x-missing"), None);
    /// ```
    #[must_use]
    pub fn ambiguous_with_response(
        status: Option<u16>,
        message: impl Into<String>,
        body: impl AsRef<[u8]>,
        headers: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        let body = safe_body(&String::from_utf8_lossy(body.as_ref()));
        let owned = headers
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect::<Vec<(String, String)>>();
        let borrowed = owned
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<(&str, &str)>>();
        let headers = safe_headers(&borrowed);
        Self::Ambiguous {
            status,
            message: message.into(),
            body,
            headers,
        }
    }

    /// The response body observed before an [`Error::Ambiguous`] failure, when
    /// the server sent one.
    ///
    /// Returns `None` for every other variant and for an ambiguous failure
    /// where no response body existed (a timeout or reset after the write).
    /// The bytes are bounded and sanitised the same way as
    /// [`Error::ambiguous_with_response`] stores them.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::ambiguous_with_response(
    ///     Some(500),
    ///     "lost the response",
    ///     "boom",
    ///     std::iter::empty::<(&str, &str)>(),
    /// );
    /// assert_eq!(err.ambiguous_body(), Some("boom"));
    /// assert_eq!(Error::transport("reset").ambiguous_body(), None);
    /// ```
    #[must_use]
    pub fn ambiguous_body(&self) -> Option<&str> {
        match self {
            Self::Ambiguous { body, .. } if !body.is_empty() => std::str::from_utf8(body).ok(),
            _ => None,
        }
    }

    /// A response header observed before an [`Error::Ambiguous`] failure,
    /// selected by case-insensitive name.
    ///
    /// Returns `None` for every other variant, for an ambiguous failure with
    /// no response, and when the header was absent. `Authorization`,
    /// `Cookie` and `Set-Cookie` are never retained, so they can never be
    /// returned here.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::ambiguous_with_response(
    ///     Some(500),
    ///     "lost the response",
    ///     "",
    ///     [("x-sipgate-sms-id", "sms-7")],
    /// );
    /// assert_eq!(err.ambiguous_header("X-Sipgate-Sms-Id"), Some("sms-7"));
    /// assert_eq!(err.ambiguous_header("retry-after"), None);
    /// ```
    #[must_use]
    pub fn ambiguous_header(&self, name: &str) -> Option<&str> {
        match self {
            Self::Ambiguous { headers, .. } => headers
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str()),
            _ => None,
        }
    }

    /// Whether another attempt could succeed.
    ///
    /// Only transport failures that provably happened before the request was
    /// written and 429/5xx answers on idempotent methods are retryable;
    /// validation, parsing, authorization errors and every
    /// [`Error::Ambiguous`] outcome are not.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// assert!(Error::transport_before_write("dns").is_retryable());
    /// assert!(!Error::unauthorized(401, "expired", None, None).is_retryable());
    /// assert!(!Error::transport("timeout after write").is_retryable());
    /// assert!(!Error::ambiguous(None, "timeout after write").is_retryable());
    /// ```
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { retryable, .. }
            | Self::Api { retryable, .. }
            | Self::Socket { retryable, .. } => *retryable,
            _ => false,
        }
    }

    /// Whether the request may already have been executed.
    ///
    /// ```rust
    /// use sipgate_flow::Error;
    ///
    /// assert!(Error::ambiguous(Some(500), "5xx after a POST").is_ambiguous());
    /// assert!(Error::CallStartedUnknown { status: 202, body: String::new() }.is_ambiguous());
    /// assert!(!Error::validation("text", "empty").is_ambiguous());
    /// ```
    #[must_use]
    pub fn is_ambiguous(&self) -> bool {
        matches!(
            self,
            Self::Ambiguous { .. }
                | Self::CallStartedUnknown { .. }
                | Self::Api {
                    ambiguous: true,
                    ..
                }
        )
    }

    /// The bounded wait hint the server asked for in a `Retry-After` header.
    ///
    /// Values are clamped to [`MAX_RETRY_AFTER`] when the error is built. This
    /// is still only a hint: callers that sleep directly should apply their own
    /// ceiling, for example through [`crate::RetryPolicy::max_delay`].
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::{Error, Method};
    ///
    /// let err = Error::api(Method::Get, 429, String::new(), Some(Duration::from_secs(7)));
    /// assert_eq!(err.retry_after().unwrap().as_secs(), 7);
    ///
    /// let huge = Error::api(Method::Get, 429, String::new(), Some(Duration::MAX));
    /// assert_eq!(huge.retry_after(), Some(sipgate_flow::MAX_RETRY_AFTER));
    /// ```
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Api { retry_after, .. } | Self::Unauthorized { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// The HTTP status, when the failure came with one.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// assert_eq!(Error::unauthorized(401, "expired", None, None).status(), Some(401));
    /// assert_eq!(Error::validation("x", "y").status(), None);
    /// assert_eq!(Error::ambiguous(Some(503), "after POST").status(), Some(503));
    /// assert_eq!(Error::CallStartedUnknown { status: 202, body: String::new() }.status(), Some(202));
    /// ```
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. }
            | Self::AuthRejected { status, .. }
            | Self::Unauthorized { status, .. }
            | Self::CallStartedUnknown { status, .. }
            | Self::FlowNotCallable { status, .. }
            | Self::FlowNotFound { status, .. }
            | Self::AccessNotGranted { status, .. } => Some(*status),
            Self::Ambiguous { status, .. } => *status,
            _ => None,
        }
    }
}

/// Convenience alias used across the crate.
///
/// ```
/// fn always_ok() -> sipgate_flow::Result<u8> {
///     Ok(1)
/// }
/// assert_eq!(always_ok().unwrap(), 1);
/// ```
pub type Result<T> = std::result::Result<T, Error>;
