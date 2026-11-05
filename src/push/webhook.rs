//! Guarding a Push API request before it is decoded.
//!
//! Unlike Flow, the classic Push API documents **no credential**. The reference
//! (<https://en.sipgate.io/push-api/api-references>) says sipgate.io POSTs the
//! event to the URL configured under *sipgate.io → Webhooks* and describes no
//! header, token, signature or shared secret. [`PushVerifier`] therefore cannot
//! authenticate a caller, and does not pretend to: it enforces the two
//! properties the protocol does document — a form-encoded body and a bounded
//! size — and leaves authentication to the deployment (an unguessable path, a
//! reverse proxy, or a network allow-list). Every request that arrives is
//! untrusted input.
//!
//! ```rust
//! use sipgate_flow::push::PushVerifier;
//!
//! let verifier = PushVerifier::new().with_max_body_bytes(4096)?;
//! let event = verifier.verify_and_parse(
//!     Some("application/x-www-form-urlencoded"),
//!     b"event=newCall&callId=123456",
//! )?;
//! assert_eq!(event.call_id(), Some("123456"));
//!
//! // JSON belongs to Flow and is refused rather than half-parsed.
//! let wrong_product = verifier
//!     .verify_and_parse(Some("application/json"), br#"{"type":"newCall"}"#)
//!     .unwrap_err();
//! assert!(matches!(
//!     wrong_product,
//!     sipgate_flow::Error::UnsupportedContentType { .. }
//! ));
//! # Ok::<(), sipgate_flow::Error>(())
//! ```

use std::io::Read;

use crate::error::{Error, Result};
use crate::push::event::{PushEvent, MAX_PUSH_BODY_BYTES};

/// The media type sipgate.io sends a Push API event as.
///
/// ```rust
/// use sipgate_flow::push::FORM_CONTENT_TYPE;
///
/// assert_eq!(FORM_CONTENT_TYPE, "application/x-www-form-urlencoded");
/// ```
pub const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// Read buffer used by [`PushVerifier::verify_reader`].
const BODY_READ_CHUNK_BYTES: usize = 8 * 1024;

/// Enforces the inbound checks the Push API allows and decodes the event.
///
/// The verifier owns no credential, because the reference documents none; see
/// the [module documentation](self) for what that means for a deployment.
///
/// ```rust
/// use sipgate_flow::push::PushVerifier;
///
/// let verifier = PushVerifier::new();
/// assert_eq!(verifier.max_body_bytes(), sipgate_flow::push::MAX_PUSH_BODY_BYTES);
/// ```
#[derive(Debug, Clone)]
pub struct PushVerifier {
    max_body_bytes: usize,
}

impl Default for PushVerifier {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_PUSH_BODY_BYTES,
        }
    }
}

impl PushVerifier {
    /// A verifier with the default body ceiling.
    ///
    /// ```rust
    /// use sipgate_flow::push::{PushVerifier, MAX_PUSH_BODY_BYTES};
    ///
    /// assert_eq!(PushVerifier::new().max_body_bytes(), MAX_PUSH_BODY_BYTES);
    /// assert_eq!(PushVerifier::default().max_body_bytes(), MAX_PUSH_BODY_BYTES);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the largest body accepted by [`PushVerifier::verify_and_parse`] and
    /// the read bound used by [`PushVerifier::verify_reader`].
    ///
    /// The accepted range is `1..=MAX_PUSH_BODY_BYTES`. `0` is rejected
    /// instead of turning every non-empty request into `BodyTooLarge`, and a
    /// value above the ceiling is rejected because [`PushEvent::parse`] would
    /// refuse the body anyway — a verifier that accepts what the parser rejects
    /// only moves the failure.
    ///
    /// ```rust
    /// use sipgate_flow::push::{PushVerifier, MAX_PUSH_BODY_BYTES};
    /// use sipgate_flow::Error;
    ///
    /// let verifier = PushVerifier::new().with_max_body_bytes(1024)?;
    /// assert_eq!(verifier.max_body_bytes(), 1024);
    ///
    /// assert!(PushVerifier::new().with_max_body_bytes(1).is_ok());
    /// assert!(PushVerifier::new().with_max_body_bytes(MAX_PUSH_BODY_BYTES).is_ok());
    /// assert!(matches!(
    ///     PushVerifier::new().with_max_body_bytes(0),
    ///     Err(Error::Validation { field: "max_body_bytes", .. })
    /// ));
    /// assert!(PushVerifier::new()
    ///     .with_max_body_bytes(MAX_PUSH_BODY_BYTES + 1)
    ///     .is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `limit` is `0` or greater than
    /// [`MAX_PUSH_BODY_BYTES`].
    pub fn with_max_body_bytes(mut self, limit: usize) -> Result<Self> {
        if !(1..=MAX_PUSH_BODY_BYTES).contains(&limit) {
            return Err(Error::validation(
                "max_body_bytes",
                format!("must be between 1 and {MAX_PUSH_BODY_BYTES} bytes"),
            ));
        }
        self.max_body_bytes = limit;
        Ok(self)
    }

    /// The configured body limit.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushVerifier;
    ///
    /// assert_eq!(PushVerifier::new().with_max_body_bytes(64)?.max_body_bytes(), 64);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Enforces the body limit on an already-buffered body and decodes the
    /// event.
    ///
    /// A missing, empty or whitespace-only `Content-Type` is accepted — some
    /// frameworks strip the header — but a present non-form type is refused:
    /// `application/json` means the request came from Flow, not from the Push
    /// API.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushVerifier;
    ///
    /// let verifier = PushVerifier::new();
    /// let body = b"event=newCall&callId=1";
    /// assert!(verifier.verify_and_parse(None, body).is_ok());
    /// assert!(verifier.verify_and_parse(Some("  "), body).is_ok());
    /// assert!(verifier
    ///     .verify_and_parse(Some("application/x-www-form-urlencoded; charset=UTF-8"), body)
    ///     .is_ok());
    /// assert!(verifier
    ///     .verify_and_parse(Some("application/json"), body)
    ///     .is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedContentType`], [`Error::BodyTooLarge`], or whatever
    /// [`PushEvent::parse`] reports.
    pub fn verify_and_parse(&self, content_type: Option<&str>, body: &[u8]) -> Result<PushEvent> {
        Self::check_content_type(content_type)?;
        if body.len() > self.max_body_bytes {
            return Err(Error::BodyTooLarge {
                size: body.len(),
                limit: self.max_body_bytes,
            });
        }
        PushEvent::parse(body)
    }

    /// Reads a bounded body and decodes the event.
    ///
    /// The read stops as soon as `max_body_bytes + 1` bytes have been
    /// observed, returning [`Error::BodyTooLarge`] without draining the
    /// reader, so a caller that streams a request body cannot be made to
    /// buffer more than one byte past the ceiling.
    ///
    /// ```rust
    /// use sipgate_flow::push::PushVerifier;
    ///
    /// let verifier = PushVerifier::new();
    /// let mut body = b"event=newCall&callId=1".as_slice();
    /// let event = verifier.verify_reader(
    ///     Some("application/x-www-form-urlencoded"),
    ///     &mut body,
    /// )?;
    /// assert_eq!(event.event_name(), "newCall");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::BodyTooLarge`] when `max_body_bytes + 1` bytes are observed,
    /// [`Error::BodyRead`] when the reader fails,
    /// [`Error::UnsupportedContentType`], or whatever [`PushEvent::parse`]
    /// reports.
    pub fn verify_reader(&self, content_type: Option<&str>, r: impl Read) -> Result<PushEvent> {
        Self::check_content_type(content_type)?;
        let body = read_bounded_body(r, self.max_body_bytes)?;
        PushEvent::parse(&body)
    }

    /// Refuses a content type that belongs to another product.
    fn check_content_type(content_type: Option<&str>) -> Result<()> {
        if let Some(content_type) = content_type.map(str::trim).filter(|ct| !ct.is_empty()) {
            if !is_form_content_type(content_type) {
                return Err(Error::unsupported_content_type(content_type));
            }
        }
        Ok(())
    }
}

/// Reads at most `limit + 1` bytes from `r`.
fn read_bounded_body(mut r: impl Read, limit: usize) -> Result<Vec<u8>> {
    let read_limit = limit.saturating_add(1);
    let mut body = Vec::new();
    let mut buffer = [0_u8; BODY_READ_CHUNK_BYTES];

    while body.len() < read_limit {
        let remaining = read_limit - body.len();
        let wanted = remaining.min(buffer.len());
        match r.read(&mut buffer[..wanted]) {
            Ok(0) => break,
            Ok(read) => {
                body.extend_from_slice(&buffer[..read]);
                if body.len() > limit {
                    return Err(Error::BodyTooLarge {
                        size: body.len(),
                        limit,
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::body_read(error)),
        }
    }

    Ok(body)
}

/// Whether a `Content-Type` value is `application/x-www-form-urlencoded`,
/// tolerating parameters and casing.
///
/// ```rust
/// use sipgate_flow::push::is_form_content_type;
///
/// assert!(is_form_content_type("application/x-www-form-urlencoded"));
/// assert!(is_form_content_type("Application/X-WWW-Form-Urlencoded; charset=UTF-8"));
/// assert!(!is_form_content_type("application/json"));
/// assert!(!is_form_content_type("not a media type"));
/// ```
#[must_use]
pub fn is_form_content_type(value: &str) -> bool {
    value
        .trim()
        .parse::<mime::Mime>()
        .is_ok_and(|mime| mime.essence_str() == FORM_CONTENT_TYPE)
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn a_missing_or_form_content_type_is_accepted_but_json_is_not() {
        let verifier = PushVerifier::new();
        let body = b"event=newCall&callId=1";
        assert!(verifier.verify_and_parse(None, body).is_ok());
        assert!(verifier.verify_and_parse(Some(""), body).is_ok());
        assert!(verifier
            .verify_and_parse(Some(FORM_CONTENT_TYPE), body)
            .is_ok());
        for foreign in ["application/json", "text/plain", "application/xml"] {
            assert!(
                matches!(
                    verifier.verify_and_parse(Some(foreign), body),
                    Err(Error::UnsupportedContentType { .. })
                ),
                "{foreign}"
            );
        }
    }

    #[test]
    fn the_body_limit_is_exact_for_a_buffered_body() {
        let exact = b"event=newCall&callId=1234567890";
        let verifier = PushVerifier::new()
            .with_max_body_bytes(exact.len())
            .expect("a body-sized limit is inside the accepted range");
        assert!(verifier.verify_and_parse(None, exact).is_ok());

        let one_over = b"event=newCall&callId=12345678901";
        assert_eq!(one_over.len(), exact.len() + 1);
        assert!(matches!(
            verifier.verify_and_parse(None, one_over),
            Err(Error::BodyTooLarge { size, .. }) if size == exact.len() + 1
        ));
    }

    #[test]
    fn the_body_limit_is_exact_for_a_reader_and_stops_reading() {
        let exact = b"event=newCall&callId=1234567890";
        let verifier = PushVerifier::new()
            .with_max_body_bytes(exact.len())
            .expect("a body-sized limit is inside the accepted range");
        assert!(verifier.verify_reader(None, exact.as_slice()).is_ok());

        let error = verifier
            .verify_reader(None, io::repeat(b'a'))
            .expect_err("an endless body is cut off");
        assert!(
            matches!(error, Error::BodyTooLarge { size, .. } if size == exact.len() + 1),
            "{error:?}"
        );
    }

    #[test]
    fn a_failing_reader_is_reported_as_a_body_read_error() {
        struct Broken;
        impl io::Read for Broken {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("connection lost"))
            }
        }

        let error = PushVerifier::new()
            .verify_reader(None, Broken)
            .expect_err("the reader failed");
        assert!(matches!(error, Error::BodyRead { .. }), "{error:?}");
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn an_interrupted_read_is_retried_before_the_body_is_decoded() {
        struct OnceInterrupted {
            interrupted: bool,
            body: &'static [u8],
        }
        impl io::Read for OnceInterrupted {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                let read = self.body.len().min(buffer.len());
                buffer[..read].copy_from_slice(&self.body[..read]);
                self.body = &self.body[read..];
                Ok(read)
            }
        }

        let reader = OnceInterrupted {
            interrupted: false,
            body: b"event=newCall&callId=1",
        };
        let event = PushVerifier::new()
            .verify_reader(None, reader)
            .expect("an interrupted read is not a failure");
        assert_eq!(event.call_id(), Some("1"));
    }

    #[test]
    fn the_reader_path_checks_the_content_type_and_the_empty_body() {
        let verifier = PushVerifier::new();
        let body = b"event=newCall&callId=1".as_slice();
        assert!(matches!(
            verifier.verify_reader(Some("application/json"), body),
            Err(Error::UnsupportedContentType { .. })
        ));
        assert!(matches!(
            verifier.verify_reader(None, b"".as_slice()),
            Err(Error::EmptyBody)
        ));
    }

    #[test]
    fn the_ceiling_cannot_be_set_outside_the_parser_range() {
        assert!(PushVerifier::new().with_max_body_bytes(0).is_err());
        assert!(PushVerifier::new().with_max_body_bytes(1).is_ok());
        assert!(PushVerifier::new()
            .with_max_body_bytes(MAX_PUSH_BODY_BYTES)
            .is_ok());
        assert!(PushVerifier::new()
            .with_max_body_bytes(MAX_PUSH_BODY_BYTES + 1)
            .is_err());
    }
}
