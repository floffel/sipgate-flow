//! Webhook authentication: the shared secret sipgate flow sends in a header.
//!
//! The documentation puts the secret in `X-API-TOKEN`
//! (<https://flow.sipgate.io/api/authentication>); one request example on the
//! Webhooks page spells the header `X-API-Key`. HTTP header names are
//! case-insensitive, so
//! [`WebhookVerifier::verify_headers`] compares against both documented
//! spellings ignoring case and refuses a request that carries both names with
//! different values. The raw names are still exported as
//! [`SECRET_HEADER`]/[`SECRET_HEADER_LEGACY`] for handlers that prefer to look
//! them up themselves; those constants are already lowercased, so match header
//! names case-insensitively (or use `verify_headers`) instead of comparing
//! them byte-for-byte against a framework's map.
//!
//! Verification is constant time ([`subtle::ConstantTimeEq`]) and fails closed:
//! an empty secret is refused at construction, because comparing against an
//! empty secret would authenticate every request that omits the header.
//!
//! ```
//! use sipgate_flow::WebhookVerifier;
//!
//! let verifier = WebhookVerifier::new("shared-secret")?;
//! assert!(verifier.verify(Some("shared-secret")).is_ok());
//! assert!(verifier.verify(Some("wrong")).is_err());
//!
//! // Case-insensitive header lookup, tolerant of either documented spelling.
//! let headers = [("X-API-TOKEN", "shared-secret")];
//! assert!(verifier.verify_headers(headers).is_ok());
//! # Ok::<(), sipgate_flow::Error>(())
//! ```

use std::io::Read;

use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::flow::event::Event;

/// Header carrying the shared secret, per the authentication page.
///
/// The value is lowercased; HTTP header names are case-insensitive, so use
/// [`WebhookVerifier::verify_headers`] or compare with
/// [`str::eq_ignore_ascii_case`] rather than an exact match against a
/// framework's header map.
pub const SECRET_HEADER: &str = "x-api-token";

/// Header name used by the Webhooks page's request example.
///
/// The value is lowercased; see [`SECRET_HEADER`] for the case-insensitive
/// lookup caveat.
pub const SECRET_HEADER_LEGACY: &str = "x-api-key";

/// Default and maximum body limit for [`WebhookVerifier`], in bytes.
///
/// Real events are a few KiB. [`WebhookVerifier::verify_reader`] uses this as a
/// read bound and stops after `limit + 1` bytes, so an unauthenticated caller
/// cannot force an unbounded body allocation through that entry point.
/// [`WebhookVerifier::verify_and_parse`] applies the same ceiling to an already
/// buffered body; it cannot bound the framework's body collection.
/// [`crate::Event::parse`] has its own smaller parser-level ceiling for code
/// that calls it directly.
///
/// [`WebhookVerifier::with_max_body_bytes`] accepts `1..=DEFAULT_MAX_BODY_BYTES`;
/// the verifier can tighten the ceiling but cannot raise it.
///
/// ```
/// assert_eq!(sipgate_flow::webhook::DEFAULT_MAX_BODY_BYTES, 1024 * 1024);
/// ```
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Read buffer used by [`WebhookVerifier::verify_reader`].
const BODY_READ_CHUNK_BYTES: usize = 8 * 1024;

/// Verifies the shared secret and parses the event.
///
/// ```
/// use sipgate_flow::{EventPayload, WebhookVerifier};
///
/// let verifier = WebhookVerifier::new("s3cret")?;
/// let event = verifier.verify_and_parse(
///     Some("s3cret"),
///     Some("application/json; charset=utf-8"),
///     br#"{"type":"session_start","session":{"id":"s1"}}"#,
/// )?;
/// assert!(matches!(event.payload(), EventPayload::SessionStart { .. }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone)]
pub struct WebhookVerifier {
    secret: Vec<u8>,
    max_body_bytes: usize,
}

impl std::fmt::Debug for WebhookVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        f.debug_struct("WebhookVerifier")
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

impl WebhookVerifier {
    /// Creates a verifier for the shared secret configured in the Flow
    /// dashboard.
    ///
    /// ```
    /// use sipgate_flow::WebhookVerifier;
    ///
    /// assert!(WebhookVerifier::new("s").is_ok());
    /// assert!(WebhookVerifier::new("").is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::EmptySecret`] for an empty secret: a missing environment
    /// variable must not turn into "accept everything".
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self> {
        let secret = secret.into();
        if secret.is_empty() {
            return Err(Error::EmptySecret);
        }
        Ok(Self {
            secret,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        })
    }

    /// Sets the largest body accepted by [`WebhookVerifier::verify_and_parse`]
    /// and the read bound used by [`WebhookVerifier::verify_reader`].
    ///
    /// The accepted range is `1..=DEFAULT_MAX_BODY_BYTES`. `0` is rejected
    /// instead of turning every non-empty webhook into `BodyTooLarge`, and
    /// values above [`DEFAULT_MAX_BODY_BYTES`] are rejected instead of making
    /// the reader bound unbounded.
    ///
    /// ```
    /// use sipgate_flow::{webhook::DEFAULT_MAX_BODY_BYTES, Error, WebhookVerifier};
    ///
    /// let verifier = WebhookVerifier::new("s")?.with_max_body_bytes(4096)?;
    /// assert_eq!(verifier.max_body_bytes(), 4096);
    ///
    /// assert!(WebhookVerifier::new("s")?.with_max_body_bytes(1).is_ok());
    /// assert!(WebhookVerifier::new("s")?.with_max_body_bytes(DEFAULT_MAX_BODY_BYTES).is_ok());
    ///
    /// let zero = WebhookVerifier::new("s")?
    ///     .with_max_body_bytes(0)
    ///     .expect_err("zero would reject every non-empty body");
    /// assert!(matches!(zero, Error::Validation { field: "max_body_bytes", .. }));
    ///
    /// let too_large = WebhookVerifier::new("s")?
    ///     .with_max_body_bytes(DEFAULT_MAX_BODY_BYTES + 1)
    ///     .expect_err("the reader bound must stay finite");
    /// assert!(matches!(too_large, Error::Validation { field: "max_body_bytes", .. }));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `limit` is `0` or greater than
    /// [`DEFAULT_MAX_BODY_BYTES`].
    pub fn with_max_body_bytes(mut self, limit: usize) -> Result<Self> {
        if !(1..=DEFAULT_MAX_BODY_BYTES).contains(&limit) {
            return Err(Error::validation(
                "max_body_bytes",
                format!("must be between 1 and {DEFAULT_MAX_BODY_BYTES} bytes"),
            ));
        }
        self.max_body_bytes = limit;
        Ok(self)
    }

    /// The configured body limit.
    ///
    /// ```
    /// use sipgate_flow::WebhookVerifier;
    /// assert_eq!(WebhookVerifier::new("s")?.max_body_bytes(), sipgate_flow::webhook::DEFAULT_MAX_BODY_BYTES);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Checks a `X-API-TOKEN` value in constant time.
    ///
    /// ```
    /// use sipgate_flow::{Error, WebhookVerifier};
    ///
    /// let verifier = WebhookVerifier::new("abc")?;
    /// assert!(matches!(verifier.verify(None), Err(Error::MissingSecret)));
    /// assert!(matches!(verifier.verify(Some("abd")), Err(Error::SecretMismatch)));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingSecret`] when the header is absent or empty,
    /// [`Error::SecretMismatch`] when it does not match.
    pub fn verify(&self, provided: Option<&str>) -> Result<()> {
        let provided = provided.unwrap_or_default();
        if provided.is_empty() {
            return Err(Error::MissingSecret);
        }
        if self
            .secret
            .as_slice()
            .ct_eq(provided.as_bytes())
            .unwrap_u8()
            == 1
        {
            Ok(())
        } else {
            Err(Error::SecretMismatch)
        }
    }

    /// Verifies the shared secret from a request's headers, matching the
    /// documented names case-insensitively.
    ///
    /// HTTP header names are case-insensitive, and a framework may preserve
    /// whichever casing the sender used. This method therefore compares each
    /// header name against both [`SECRET_HEADER`] and [`SECRET_HEADER_LEGACY`]
    /// with [`str::eq_ignore_ascii_case`] instead of indexing a map with the
    /// lowercased constant. When both spellings are present they must agree:
    /// a request that carries two different secrets is refused, because there
    /// is no correct value to accept.
    ///
    /// ```
    /// use sipgate_flow::{Error, WebhookVerifier};
    ///
    /// let verifier = WebhookVerifier::new("abc")?;
    /// assert!(verifier.verify_headers([("X-API-TOKEN", "abc")]).is_ok());
    /// assert!(verifier.verify_headers([("X-Api-Key", "abc")]).is_ok());
    /// assert!(verifier
    ///     .verify_headers([("X-API-TOKEN", "abc"), ("X-API-Key", "abc")])
    ///     .is_ok());
    /// assert!(matches!(
    ///     verifier.verify_headers([("X-API-TOKEN", "abc"), ("X-API-Key", "def")]),
    ///     Err(Error::SecretMismatch)
    /// ));
    /// assert!(matches!(
    ///     verifier.verify_headers([("Authorization", "Bearer abc")]),
    ///     Err(Error::MissingSecret)
    /// ));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingSecret`] when neither documented header is present or
    /// the only matching value is empty, and [`Error::SecretMismatch`] when the
    /// value does not match or two present spellings disagree.
    pub fn verify_headers<'a>(
        &self,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<()> {
        let mut token: Option<&str> = None;
        let mut legacy: Option<&str> = None;

        for (name, value) in headers {
            if name.eq_ignore_ascii_case(SECRET_HEADER) {
                token = Some(value);
            } else if name.eq_ignore_ascii_case(SECRET_HEADER_LEGACY) {
                legacy = Some(value);
            }
        }

        match (token, legacy) {
            (Some(a), Some(b)) => {
                // Only the header *names* are case-insensitive; a shared secret
                // is compared byte-for-byte, so two present spellings must
                // carry the identical value.
                if a == b {
                    self.verify(Some(a))
                } else {
                    Err(Error::SecretMismatch)
                }
            }
            (Some(value), None) | (None, Some(value)) => self.verify(Some(value)),
            (None, None) => Err(Error::MissingSecret),
        }
    }

    /// Verifies, enforces the body limit on an already-buffered body, and parses.
    ///
    /// A missing, empty, or whitespace-only `Content-Type` is accepted — some
    /// frameworks strip it or report the missing header as an empty string, and
    /// the secret is what authenticates the call — but a present non-JSON type
    /// is refused: `application/x-www-form-urlencoded` means the request came
    /// from the Push API, not from Flow.
    ///
    /// ```
    /// use sipgate_flow::{Error, WebhookVerifier};
    ///
    /// let verifier = WebhookVerifier::new("abc")?;
    /// let body = br#"{"type":"session_start","session":{"id":"s1"}}"#;
    /// assert!(verifier.verify_and_parse(Some("abc"), None, body).is_ok());
    /// assert!(verifier.verify_and_parse(Some("abc"), Some(""), body).is_ok());
    /// assert!(verifier.verify_and_parse(Some("abc"), Some("   "), body).is_ok());
    /// let err = verifier
    ///     .verify_and_parse(Some("abc"), Some("application/x-www-form-urlencoded"), b"event=newCall")
    ///     .unwrap_err();
    /// assert!(matches!(err, Error::UnsupportedContentType { .. }));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// This method receives a `&[u8]`, so the caller has already materialised
    /// the body. It therefore bounds parsing work, not the framework's body
    /// collection. Use [`WebhookVerifier::verify_reader`] when the body still
    /// comes from a reader.
    ///
    /// [`Error::MissingSecret`], [`Error::SecretMismatch`],
    /// [`Error::UnsupportedContentType`], [`Error::BodyTooLarge`], or whatever
    /// [`Event::parse`] reports.
    pub fn verify_and_parse(
        &self,
        provided: Option<&str>,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<Event> {
        self.verify(provided)?;
        Self::check_content_type(content_type)?;
        if body.len() > self.max_body_bytes {
            return Err(Error::BodyTooLarge {
                size: body.len(),
                limit: self.max_body_bytes,
            });
        }
        Event::parse(body)
    }

    /// Reads a bounded body, verifies the shared secret, and parses the event.
    ///
    /// The read stops as soon as `max_body_bytes + 1` bytes have been observed,
    /// returning [`Error::BodyTooLarge`] without draining the reader. This
    /// bounds the allocation made by this method; any signature or HMAC scheme
    /// that needs the whole payload still verifies the complete bounded body
    /// before parsing. The secret is checked before JSON parsing.
    ///
    /// ```
    /// use sipgate_flow::{EventPayload, WebhookVerifier};
    ///
    /// let verifier = WebhookVerifier::new("s3cret")?;
    /// let mut body = br#"{"type":"session_start","session":{"id":"s1"}}"#.as_slice();
    /// let event = verifier.verify_reader(
    ///     Some("s3cret"),
    ///     Some("application/json; charset=utf-8"),
    ///     &mut body,
    /// )?;
    /// assert!(matches!(event.payload(), EventPayload::SessionStart { .. }));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::BodyTooLarge`] when `max_body_bytes + 1` bytes are observed,
    /// [`Error::BodyRead`] when the reader fails, [`Error::MissingSecret`],
    /// [`Error::SecretMismatch`], [`Error::UnsupportedContentType`], or
    /// whatever [`Event::parse`] reports.
    pub fn verify_reader(
        &self,
        provided: Option<&str>,
        content_type: Option<&str>,
        r: impl Read,
    ) -> Result<Event> {
        let body = self.read_bounded_body(r)?;
        self.verify(provided)?;
        Self::check_content_type(content_type)?;
        Event::parse(&body)
    }

    /// Reads at most `max_body_bytes + 1` bytes from `r`.
    fn read_bounded_body(&self, mut r: impl Read) -> Result<Vec<u8>> {
        let read_limit = self.max_body_bytes.saturating_add(1);
        let mut body = Vec::new();
        let mut buffer = [0_u8; BODY_READ_CHUNK_BYTES];

        while body.len() < read_limit {
            let remaining = read_limit - body.len();
            let wanted = remaining.min(buffer.len());
            match r.read(&mut buffer[..wanted]) {
                Ok(0) => break,
                Ok(read) => {
                    body.extend_from_slice(&buffer[..read]);
                    if body.len() > self.max_body_bytes {
                        return Err(Error::BodyTooLarge {
                            size: body.len(),
                            limit: self.max_body_bytes,
                        });
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(Error::body_read(error)),
            }
        }

        Ok(body)
    }

    fn check_content_type(content_type: Option<&str>) -> Result<()> {
        if let Some(content_type) = content_type.map(str::trim).filter(|ct| !ct.is_empty()) {
            if !is_json_content_type(content_type) {
                return Err(Error::unsupported_content_type(content_type));
            }
        }
        Ok(())
    }
}

/// Whether a `Content-Type` value is JSON, tolerating parameters and casing.
///
/// ```
/// use sipgate_flow::webhook::is_json_content_type;
///
/// assert!(is_json_content_type("application/json"));
/// assert!(is_json_content_type("Application/JSON; charset=utf-8"));
/// assert!(is_json_content_type("application/vnd.api+json"));
/// assert!(!is_json_content_type("application/x-www-form-urlencoded"));
/// assert!(!is_json_content_type("not+json"));
/// assert!(!is_json_content_type("not a media type"));
/// ```
#[must_use]
pub fn is_json_content_type(value: &str) -> bool {
    value.trim().parse::<mime::Mime>().is_ok_and(|mime| {
        let essence = mime.essence_str();
        essence == "application/json" || essence.ends_with("+json")
    })
}
