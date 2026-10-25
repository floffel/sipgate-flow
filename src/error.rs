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
    #[error("token endpoint rejected the client credentials (http {status}): {body}")]
    AuthRejected {
        /// HTTP status of the token response.
        status: u16,
        /// Response body, truncated to 512 characters.
        body: String,
    },

    /// The token response could not be used (missing `access_token`, wrong
    /// JSON type, empty value).
    #[error("unusable token response: {0}")]
    TokenResponse(String),

    /// A request was rejected with 401 even after refreshing the token once.
    #[error("unauthorized after refreshing the access token")]
    Unauthorized,

    /// The transport failed before a usable response existed (DNS, TLS,
    /// timeout, reset). `retryable` says whether another attempt could help.
    #[error("transport error: {message}")]
    Transport {
        /// Transport-supplied description.
        message: String,
        /// `true` for transient failures (I/O, timeouts), `false` otherwise.
        retryable: bool,
    },

    /// The API answered with a non-2xx status.
    #[error("api error {status}: {body}")]
    Api {
        /// HTTP status.
        status: u16,
        /// Response body, truncated to 512 characters.
        body: String,
        /// Parsed `Retry-After` header, when the server sent one.
        retry_after: Option<Duration>,
        /// `true` for 429, and for 5xx on an idempotent method only.
        retryable: bool,
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

    /// Builds a transient transport error (retryable).
    ///
    /// ```
    /// use sipgate_flow::Error;
    /// assert!(Error::transport("connection reset").is_retryable());
    /// ```
    #[must_use]
    pub fn transport(message: impl Into<String>) -> Self {
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
    /// assert!(Error::transport("dns").is_retryable());
    /// assert!(!Error::Unauthorized.is_retryable());
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
    /// assert!(!Error::validation("text", "empty").is_ambiguous());
    /// ```
    #[must_use]
    pub fn is_ambiguous(&self) -> bool {
        matches!(self, Self::Ambiguous { .. })
    }

    /// The wait the server asked for in a `Retry-After` header.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::Error;
    ///
    /// let err = Error::Api {
    ///     status: 429,
    ///     body: String::new(),
    ///     retry_after: Some(Duration::from_secs(7)),
    ///     retryable: true,
    /// };
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
    /// ```
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. } | Self::AuthRejected { status, .. } => Some(*status),
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
