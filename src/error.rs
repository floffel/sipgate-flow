//! One error type for parsing, verification, authentication and transport.
//!
//! Every variant states what the caller can do about it, and
//! [`Error::is_retryable`] / [`Error::is_ambiguous`] / [`Error::retry_after`]
//! answer the three questions a retry loop asks: may I repeat this, did it
//! already happen, and how long must I wait. The enum is `#[non_exhaustive]`: new failure modes can be
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

use thiserror::Error;

use crate::transport::Method;

/// Longest remote-controlled string kept in an error.
const SAFE_TEXT_BYTES: usize = 512;

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

/// Everything that can go wrong while parsing an event, verifying a webhook or
/// calling an API.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The body was not valid JSON, or a documented required field had the
    /// wrong JSON type. Serde's position information is kept as the source.
    #[error("invalid JSON payload: {source}")]
    Json {
        /// The underlying serde error.
        #[from]
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

    /// The body exceeded the configured limit, rejected before parsing so an
    /// unauthenticated caller cannot force a large allocation.
    #[error("payload of {size} bytes exceeds the {limit} byte limit")]
    BodyTooLarge {
        /// Size the request delivered.
        size: usize,
        /// Configured ceiling.
        limit: usize,
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
    #[error("unusable token response: {0}")]
    TokenResponse(String),

    /// A request was rejected with 401 even after refreshing the token once.
    #[error("unauthorized after refreshing the access token")]
    Unauthorized,

    /// The transport failed before a usable response existed. `retryable` is
    /// true only when the failure provably happened before the request was
    /// written (DNS, TLS, connect); post-write timeouts and resets are
    /// [`Error::Ambiguous`].
    #[error("transport error: {message}")]
    Transport {
        /// Transport-supplied description.
        message: String,
        /// `true` for transient failures (I/O, timeouts), `false` otherwise.
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
        /// HTTP status.
        status: u16,
        /// Response body, truncated to at most 512 bytes, with control
        /// characters replaced by `U+FFFD`.
        body: String,
        /// Parsed `Retry-After` header, when the server sent one.
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

    /// The request reached the point where the server could act on it, but no
    /// usable response came back - a 5xx on a `POST`, or a timeout/reset while
    /// waiting. The operation **may** have happened.
    ///
    /// This is not an error the library can retry: repeating it duplicates an
    /// SMS, a fax, a recording or an outbound call, and sipgate documents no
    /// idempotency key. [`Error::is_retryable`] is therefore `false`; the
    /// caller decides, usually by checking its own ledger against
    /// [`Error::status`] and the correlation id it stored before the call.
    #[error("ambiguous outcome: {message}")]
    Ambiguous {
        /// The status that arrived, if one did: a 5xx. `None` when the
        /// connection died after the write (timeout, reset) and no status
        /// exists.
        status: Option<u16>,
        /// What happened, without the request body or any credential.
        message: String,
    },
}

impl Error {
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

    /// Builds an API error from the request method, status, body and optional
    /// `Retry-After` hint.
    ///
    /// This is the safe constructor for [`Error::Api`]: `retryable` is
    /// `status == 429` or a 5xx on an idempotent method, while `ambiguous` is a
    /// 5xx on a non-idempotent method.
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
    /// ```
    #[must_use]
    pub fn api(
        method: Method,
        status: u16,
        body: impl Into<String>,
        retry_after: Option<Duration>,
    ) -> Self {
        let server_error = (500..600).contains(&status);
        let retryable = status == 429 || (server_error && method.is_idempotent());
        let ambiguous = server_error && !method.is_idempotent();
        Self::Api {
            status,
            body: safe_text(&body.into()),
            retry_after,
            retryable,
            ambiguous,
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
        Self::Api {
            status,
            body: safe_text(&body.into()),
            retry_after,
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
            retryable: false,
        }
    }

    /// Builds the "it may already have happened" outcome: a 5xx on a
    /// non-idempotent request, or a connection that died after the write.
    ///
    /// `status` is the HTTP status when one arrived, `None` when the request
    /// was cut off without an answer.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::ambiguous(Some(502), "bad gateway after POST /v2/sessions/sms");
    /// assert!(err.is_ambiguous());
    /// assert!(!err.is_retryable(), "a retry would send the SMS a second time");
    /// assert_eq!(err.status(), Some(502));
    /// ```
    #[must_use]
    pub fn ambiguous(status: Option<u16>, message: impl Into<String>) -> Self {
        Self::Ambiguous {
            status,
            message: message.into(),
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
    /// assert!(!Error::Unauthorized.is_retryable());
    /// assert!(!Error::transport("timeout after write").is_retryable());
    /// assert!(!Error::ambiguous(None, "timeout after write").is_retryable());
    /// ```
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { retryable, .. } | Self::Api { retryable, .. } => *retryable,
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

    /// The wait the server asked for in a `Retry-After` header.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::{Error, Method};
    ///
    /// let err = Error::api(Method::Get, 429, String::new(), Some(Duration::from_secs(7)));
    /// assert_eq!(err.retry_after().unwrap().as_secs(), 7);
    /// ```
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Api { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// The HTTP status, when the failure came with one.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// assert_eq!(Error::Unauthorized.status(), None);
    /// assert_eq!(Error::validation("x", "y").status(), None);
    /// assert_eq!(Error::ambiguous(Some(503), "after POST").status(), Some(503));
    /// assert_eq!(Error::CallStartedUnknown { status: 202, body: String::new() }.status(), Some(202));
    /// ```
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. }
            | Self::AuthRejected { status, .. }
            | Self::CallStartedUnknown { status, .. } => Some(*status),
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
