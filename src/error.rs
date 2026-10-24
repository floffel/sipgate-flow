//! One error type for parsing, verification, authentication and transport.
//!
//! Every variant states what the caller can do about it, and
//! [`Error::is_retryable`] / [`Error::retry_after`] answer the two questions a
//! retry loop asks. The enum is `#[non_exhaustive]`: new failure modes can be
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
        /// `true` for 429 and 5xx.
        retryable: bool,
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

    /// Whether another attempt could succeed.
    ///
    /// Only transient transport failures and 429/5xx API answers are
    /// retryable; validation, parsing and authorization errors are terminal by
    /// construction.
    ///
    /// ```
    /// use sipgate_flow::Error;
    ///
    /// assert!(Error::transport("dns").is_retryable());
    /// assert!(!Error::Unauthorized.is_retryable());
    /// ```
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { retryable, .. } | Self::Api { retryable, .. } => *retryable,
            _ => false,
        }
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
    /// ```
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. } | Self::AuthRejected { status, .. } => Some(*status),
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
