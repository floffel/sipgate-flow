//! Webhook authentication: the shared secret sipgate flow sends in a header.
//!
//! The documentation puts the secret in `X-API-TOKEN`
//! (<https://flow.sipgate.io/api/authentication>); one request example on the
//! Webhooks page spells the header `X-API-Key`. Both names are exported as
//! constants so a handler can read whichever its framework shows, and
//! [`WebhookVerifier::verify`] only cares about the value.
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
//! # Ok::<(), sipgate_flow::Error>(())
//! ```

use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::flow::event::Event;

/// Header carrying the shared secret, per the authentication page.
pub const SECRET_HEADER: &str = "x-api-token";

/// Header name used by the Webhooks page's request example.
pub const SECRET_HEADER_LEGACY: &str = "x-api-key";

/// Default body limit: 1 MiB. Real events are a few KiB; the ceiling keeps an
/// unauthenticated caller from forcing a large allocation before the secret is
/// checked.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

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

    /// Sets the largest body accepted by
    /// [`WebhookVerifier::verify_and_parse`].
    ///
    /// ```
    /// use sipgate_flow::WebhookVerifier;
    ///
    /// let verifier = WebhookVerifier::new("s")?.with_max_body_bytes(4096);
    /// assert_eq!(verifier.max_body_bytes(), 4096);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn with_max_body_bytes(mut self, limit: usize) -> Self {
        self.max_body_bytes = limit;
        self
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

    /// Verifies, enforces the body limit and content type, then parses.
    ///
    /// A missing `Content-Type` is accepted — some frameworks strip it, and the
    /// secret is what authenticates the call — but a present non-JSON type is
    /// refused: `application/x-www-form-urlencoded` means the request came from
    /// the Push API, not from Flow.
    ///
    /// ```
    /// use sipgate_flow::{Error, WebhookVerifier};
    ///
    /// let verifier = WebhookVerifier::new("abc")?;
    /// let err = verifier
    ///     .verify_and_parse(Some("abc"), Some("application/x-www-form-urlencoded"), b"event=newCall")
    ///     .unwrap_err();
    /// assert!(matches!(err, Error::UnsupportedContentType { .. }));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
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
        if let Some(content_type) = content_type {
            if !is_json_content_type(content_type) {
                return Err(Error::UnsupportedContentType {
                    content_type: content_type.to_string(),
                });
            }
        }
        if body.len() > self.max_body_bytes {
            return Err(Error::BodyTooLarge {
                size: body.len(),
                limit: self.max_body_bytes,
            });
        }
        Event::parse(body)
    }
}

/// Whether a `Content-Type` value is JSON, tolerating parameters and casing.
///
/// ```
/// use sipgate_flow::webhook::is_json_content_type;
///
/// assert!(is_json_content_type("application/json"));
/// assert!(is_json_content_type("Application/JSON; charset=utf-8"));
/// assert!(!is_json_content_type("application/x-www-form-urlencoded"));
/// ```
#[must_use]
pub fn is_json_content_type(value: &str) -> bool {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}
