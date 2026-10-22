//! Errors.

use thiserror::Error;

/// Failures from parsing or the flow API.
#[derive(Debug, Error)]
pub enum Error {
    /// Payload could not be parsed at all.
    #[error("invalid payload: {0}")]
    Payload(String),
    /// Transport failure.
    #[error("transport error: {0}")]
    Transport(String),
    /// The API answered with an error body.
    #[error("api error {status}: {body}")]
    Api {
        /// HTTP status.
        status: u16,
        /// Response body.
        body: String,
    },
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
