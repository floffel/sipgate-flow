//! Pluggable HTTP transport, so every layer above it is testable without a
//! socket.
//!
//! [`Transport::execute`] takes one [`Request`] and returns one [`Response`]
//! regardless of status; classification, authentication, `Retry-After` and JSON
//! decoding all live above it. Tests implement the trait with a recording mock;
//! production uses [`ReqwestTransport`] behind the default `http` feature.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde_json::Value;

use crate::error::{Error, Result};

/// HTTP verb. Only the four the sipgate APIs need.
///
/// ```
/// use sipgate_flow::transport::Method;
///
/// assert_eq!(Method::Post.as_str(), "POST");
/// assert_eq!(Method::Delete.as_str(), "DELETE");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Method {
    /// Read a resource.
    Get,
    /// Create a resource or start an action.
    Post,
    /// Replace a setting such as hold or recording state.
    Put,
    /// End a call.
    Delete,
}

impl Method {
    /// Upper-case name as used on the wire.
    ///
    /// ```
    /// use sipgate_flow::transport::Method;
    /// assert_eq!(Method::Put.as_str(), "PUT");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }

    /// Whether repeating the request is harmless when the outcome is unknown.
    ///
    /// `POST` is not idempotent: every sipgate `POST` either sends a message,
    /// starts a call, plays a recording or spends money, and the API documents
    /// no idempotency key. A 5xx or a timeout after the write therefore may or
    /// may not have taken effect, and a blind retry duplicates the effect.
    ///
    /// ```rust
    /// use sipgate_flow::Method;
    ///
    /// assert!(Method::Get.is_idempotent());
    /// assert!(Method::Put.is_idempotent());
    /// assert!(Method::Delete.is_idempotent());
    /// assert!(!Method::Post.is_idempotent(), "sending an SMS twice is a real second SMS");
    /// ```
    #[must_use]
    pub fn is_idempotent(self) -> bool {
        match self {
            Self::Get | Self::Put | Self::Delete => true,
            Self::Post => false,
        }
    }
}

/// How the request authenticates.
///
/// [`Security::Basic`] covers both the token endpoint (`client_secret_basic`)
/// and a sipgate Personal Access Token (`Basic base64(<token id>:<token>)`);
/// everything else uses [`Security::Bearer`].
///
/// [`fmt::Debug`] prints the user half of a `Basic` credential (it identifies
/// the account, not the secret) and replaces the password or bearer token with
/// `<redacted>`, so a `{:?}` in a log line cannot leak a credential.
///
/// ```
/// use sipgate_flow::transport::Security;
///
/// let bearer = Security::Bearer("token");
/// assert!(matches!(bearer, Security::Bearer(_)));
/// let basic = Security::Basic { username: "id", password: "secret" };
/// assert!(matches!(basic, Security::Basic { .. }));
///
/// let rendered = format!("{basic:?}");
/// assert!(rendered.contains("id"), "{rendered}");
/// assert!(!rendered.contains("secret"), "{rendered}");
/// ```
#[non_exhaustive]
pub enum Security<'a> {
    /// No `Authorization` header.
    None,
    /// `Authorization: Bearer <token>`.
    Bearer(&'a str),
    /// `Authorization: Basic base64(<token id>:<token>)`.
    Basic {
        /// Client id (or PAT id).
        username: &'a str,
        /// Client secret (or PAT).
        password: &'a str,
    },
}

impl<'a> Security<'a> {
    /// The user half of a `Basic` credential, or `None` for every other scheme.
    ///
    /// ```
    /// use sipgate_flow::transport::Security;
    ///
    /// assert_eq!(Security::Bearer("t").basic_username(), None);
    /// assert_eq!(
    ///     Security::Basic { username: "token-FQ1V12", password: "s" }.basic_username(),
    ///     Some("token-FQ1V12")
    /// );
    /// ```
    #[must_use]
    pub fn basic_username(&self) -> Option<&'a str> {
        match self {
            Self::Basic { username, .. } => Some(*username),
            Self::None | Self::Bearer(_) => None,
        }
    }
}

/// What goes into the request body.
///
/// [`fmt::Debug`] renders a `Form` or `Json` body with every field whose name
/// looks like a credential (`password`, `secret`, `token`, `assertion`, `key`,
/// case-insensitive) replaced by `<redacted>`.
///
/// ```
/// use sipgate_flow::transport::{Method, Request, RequestBody, Security};
///
/// let payload = serde_json::json!({"value": true});
/// let json = Request::json(Method::Put, "https://x.test/a", Security::Bearer("t"), &payload);
/// assert!(matches!(json.body, RequestBody::Json(_)));
/// ```
#[non_exhaustive]
pub enum RequestBody<'a> {
    /// No body (GET, DELETE).
    Empty,
    /// `application/json`, already rendered.
    Json(&'a Value),
    /// `application/x-www-form-urlencoded`.
    Form(&'a [(String, String)]),
}

/// A single HTTP call, transport agnostic.
///
/// The credential travels in a header, never in the URL, so it cannot leak
/// through proxy logs or error messages.
///
/// [`fmt::Debug`] is safe to log: verb, URL (which never carries the
/// credential) and timeout are printed, while [`Security`] and the credential
/// fields of the body render as `<redacted>`.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::transport::{Method, Request, Security};
///
/// let request = Request::empty(Method::Delete, "https://api.sipgate.com/v2/calls/1", Security::Bearer("t"))
///     .with_timeout(Some(Duration::from_secs(5)));
/// assert_eq!(request.timeout.unwrap().as_secs(), 5);
/// assert_eq!(request.method, Method::Delete);
///
/// let rendered = format!("{request:?}");
/// assert!(rendered.contains("api.sipgate.com"), "{rendered}");
/// assert!(rendered.contains("<redacted>"), "{rendered}");
/// ```
pub struct Request<'a> {
    /// Verb to use.
    pub method: Method,
    /// Absolute URL.
    pub url: &'a str,
    /// Authentication to apply.
    pub security: Security<'a>,
    /// Per-request timeout; `None` leaves the transport default in place.
    pub timeout: Option<Duration>,
    /// Request body.
    pub body: RequestBody<'a>,
}

impl<'a> Request<'a> {
    /// A request with no body.
    ///
    /// ```
    /// use sipgate_flow::transport::{Method, Request, Security};
    ///
    /// let request = Request::empty(Method::Get, "https://x.test/a", Security::None);
    /// assert!(request.body_is_empty());
    /// ```
    #[must_use]
    pub fn empty(method: Method, url: &'a str, security: Security<'a>) -> Self {
        Self {
            method,
            url,
            security,
            timeout: None,
            body: RequestBody::Empty,
        }
    }

    /// A request with a JSON body.
    ///
    /// ```
    /// use sipgate_flow::transport::{Method, Request, Security};
    ///
    /// let body = serde_json::json!({"value": true});
    /// let request = Request::json(Method::Put, "https://x.test/a", Security::Bearer("t"), &body);
    /// assert!(!request.body_is_empty());
    /// ```
    #[must_use]
    pub fn json(method: Method, url: &'a str, security: Security<'a>, body: &'a Value) -> Self {
        Self {
            method,
            url,
            security,
            timeout: None,
            body: RequestBody::Json(body),
        }
    }

    /// A request with a form-encoded body (the `OAuth2` token call).
    ///
    /// ```
    /// use sipgate_flow::transport::{Method, Request, Security};
    ///
    /// let form = [("grant_type".to_string(), "client_credentials".to_string())];
    /// let request = Request::form(Method::Post, "https://x.test/token", Security::None, &form);
    /// assert!(!request.body_is_empty());
    /// ```
    #[must_use]
    pub fn form(
        method: Method,
        url: &'a str,
        security: Security<'a>,
        body: &'a [(String, String)],
    ) -> Self {
        Self {
            method,
            url,
            security,
            timeout: None,
            body: RequestBody::Form(body),
        }
    }

    /// Attaches a per-request timeout (no-op for `None`).
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::transport::{Method, Request, Security};
    ///
    /// let request = Request::empty(Method::Get, "https://x.test/a", Security::None)
    ///     .with_timeout(Some(Duration::from_secs(2)));
    /// assert_eq!(request.timeout, Some(Duration::from_secs(2)));
    /// ```
    #[must_use]
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Whether the request carries no body.
    ///
    /// ```
    /// use sipgate_flow::transport::{Method, Request, Security};
    ///
    /// assert!(Request::empty(Method::Get, "https://x.test/a", Security::None).body_is_empty());
    /// ```
    #[must_use]
    pub fn body_is_empty(&self) -> bool {
        matches!(self.body, RequestBody::Empty)
    }
}

/// A response as the client needs it: status, headers, body.
///
/// Header names are normalised to lower case on construction, so
/// [`Response::header`] works regardless of the casing the transport saw.
///
/// ```
/// use sipgate_flow::transport::Response;
///
/// let response = Response::new(200, [("Content-Type".to_string(), "application/json".to_string())], br#"{"ok":true}"#.to_vec());
/// assert!(response.is_success());
/// assert_eq!(response.header("content-type"), Some("application/json"));
/// assert_eq!(response.json().unwrap()["ok"], true);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Response {
    /// Builds a response, lower-casing header names.
    ///
    /// ```
    /// use sipgate_flow::transport::Response;
    ///
    /// let response = Response::new(204, std::iter::empty(), Vec::new());
    /// assert_eq!(response.json().unwrap(), serde_json::json!({}));
    /// ```
    pub fn new(
        status: u16,
        headers: impl IntoIterator<Item = (String, String)>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value))
                .collect(),
            body,
        }
    }

    /// HTTP status code.
    ///
    /// ```
    /// use sipgate_flow::transport::Response;
    /// assert_eq!(Response::new(429, std::iter::empty(), Vec::new()).status(), 429);
    /// ```
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Case-insensitive header lookup.
    ///
    /// ```
    /// use sipgate_flow::transport::Response;
    /// let response = Response::new(429, [("Retry-After".into(), "3".into())], Vec::new());
    /// assert_eq!(response.header("retry-after"), Some("3"));
    /// ```
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Every header, lower-cased names, in stable order.
    ///
    /// ```
    /// use sipgate_flow::transport::Response;
    /// let response = Response::new(200, [("X-A".into(), "1".into())], Vec::new());
    /// assert_eq!(response.headers().len(), 1);
    /// ```
    #[must_use]
    pub fn headers(&self) -> Vec<(&str, &str)> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    /// Raw body bytes.
    ///
    /// ```
    /// use sipgate_flow::transport::Response;
    /// assert_eq!(Response::new(200, std::iter::empty(), b"hi".to_vec()).body(), b"hi");
    /// ```
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Whether the status is 2xx.
    ///
    /// ```
    /// use sipgate_flow::transport::Response;
    /// assert!(Response::new(201, std::iter::empty(), Vec::new()).is_success());
    /// assert!(!Response::new(500, std::iter::empty(), Vec::new()).is_success());
    /// ```
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Parses the body as JSON; an empty body becomes `{}` so callers can index
    /// the result unconditionally.
    ///
    /// ```
    /// use sipgate_flow::transport::Response;
    ///
    /// let response = Response::new(200, std::iter::empty(), br#"{"sessionId":"s0"}"#.to_vec());
    /// assert_eq!(response.json().unwrap()["sessionId"], "s0");
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the body is not valid JSON.
    pub fn json(&self) -> Result<Value> {
        if self.body.iter().all(u8::is_ascii_whitespace) {
            return Ok(serde_json::json!({}));
        }
        serde_json::from_slice(&self.body).map_err(Error::from)
    }

    /// The body as UTF-8 text; invalid bytes are replaced, never an error.
    ///
    /// ```
    /// use sipgate_flow::transport::Response;
    /// assert_eq!(Response::new(500, std::iter::empty(), b"boom".to_vec()).text(), "boom");
    /// ```
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Performs one HTTP request. Implement it for your own stack, or use
/// [`ReqwestTransport`].
///
/// Implementations must:
///
/// * send the configured [`Security`] and never log the credential,
/// * return the raw status, headers and body even for non-2xx (the client
///   decides what is retryable),
/// * classify a failure that provably happened **before** the request was
///   written (DNS, TCP connect, TLS) as [`Error::transport`] (retryable), and a
///   failure after the write (timeout, reset while waiting) as
///   [`Error::ambiguous`] for a non-idempotent method,
///   see [`Method::is_idempotent`].
///
/// ```
/// use sipgate_flow::transport::{Request, Response, Transport};
/// use sipgate_flow::Result;
///
/// struct AlwaysOk;
///
/// impl Transport for AlwaysOk {
///     async fn execute(&self, request: Request<'_>) -> Result<Response> {
///         assert!(request.url.starts_with("https://"));
///         Ok(Response::new(200, std::iter::empty(), b"{}".to_vec()))
///     }
/// }
/// ```
pub trait Transport: Send + Sync {
    /// Executes `request` and returns the response, whatever its status.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when no response could be obtained.
    fn execute(
        &self,
        request: Request<'_>,
    ) -> impl std::future::Future<Output = Result<Response>> + Send;
}

/// `reqwest`-based transport, enabled by default via the `http` feature.
///
/// The inner client is cheap to clone and safe to share across tasks.
///
/// ```no_run
/// # #[cfg(feature = "http")]
/// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
///
/// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new("token")?);
/// # let _ = client;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "http")]
#[derive(Debug, Clone, Default)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

#[cfg(feature = "http")]
impl ReqwestTransport {
    /// Creates a transport with a default client (rustls, redirects followed).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// let transport = sipgate_flow::ReqwestTransport::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "http")]
impl Transport for ReqwestTransport {
    async fn execute(&self, request: Request<'_>) -> Result<Response> {
        let mut builder = match request.method {
            Method::Get => self.client.get(request.url),
            Method::Post => self.client.post(request.url),
            Method::Put => self.client.put(request.url),
            Method::Delete => self.client.delete(request.url),
        };
        builder = match request.security {
            Security::None => builder,
            Security::Bearer(token) => builder.bearer_auth(token),
            Security::Basic { username, password } => builder.basic_auth(username, Some(password)),
        };
        if let Some(timeout) = request.timeout {
            builder = builder.timeout(timeout);
        }
        builder = match request.body {
            RequestBody::Empty => builder,
            RequestBody::Json(value) => builder.json(value),
            RequestBody::Form(fields) => builder.form(fields),
        };

        let method = request.method;
        let response = builder
            .send()
            .await
            .map_err(|error| describe_reqwest_error(&error, method))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect::<Vec<_>>();
        let body = response
            .bytes()
            .await
            .map_err(|error| describe_reqwest_error(&error, method))?
            .to_vec();

        Ok(Response::new(status, headers, body))
    }
}

/// Maps a `reqwest` failure to the closest of the two transport outcomes
/// without echoing headers (which carry the credential).
///
/// * `connect` needs a TCP/TLS handshake that never completed: nothing was
///   written, so the attempt is retryable for every method.
/// * `timeout`, `body`, `decode` and `request` mean bytes were on the wire and
///   the peer did not answer. For an idempotent method that is worth another
///   attempt; for `POST` it is [`Error::ambiguous`] - the SMS, fax or call may
///   exist and only the response was lost.
#[cfg(feature = "http")]
fn describe_reqwest_error(error: &reqwest::Error, method: Method) -> Error {
    let kind = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() || error.is_decode() {
        "body"
    } else {
        "request"
    };
    // `reqwest::Error` renders the URL but never the Authorization header.
    let message = format!("{kind}: {error}");
    if error.is_connect() || method.is_idempotent() {
        Error::transport(message)
    } else {
        Error::ambiguous(None, message)
    }
}

impl fmt::Debug for Security<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Bearer(token) => f
                .debug_tuple("Bearer")
                .field(&rendered_secret(token))
                .finish(),
            Self::Basic { username, password } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &rendered_secret(password))
                .finish(),
        }
    }
}

impl fmt::Debug for RequestBody<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Json(value) => f.debug_tuple("Json").field(&redact_json(value)).finish(),
            Self::Form(fields) => f
                .debug_tuple("Form")
                .field(&RedactedFields(fields))
                .finish(),
        }
    }
}

impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("security", &self.security)
            .field("timeout", &self.timeout)
            .field("body", &self.body)
            .finish()
    }
}

/// The placeholder every redacted field renders as.
const REDACTED: &str = "<redacted>";

/// A secret as it may appear in `Debug`: `<redacted>`, or the empty string when
/// it is empty — an empty credential is nothing to leak, and seeing `""` tells
/// the caller the token was never configured.
const fn rendered_secret(secret: &str) -> &str {
    if secret.is_empty() {
        ""
    } else {
        REDACTED
    }
}

/// Whether a form or JSON field name carries a credential, matched
/// case-insensitively as a substring because providers spell them
/// `client_secret`, `X-API-TOKEN`, `refresh_token`, `client_assertion` and
/// `api_key`.
///
/// Over-redaction is deliberate: a field called `hotkey` loses its value in
/// `Debug`, a field called `client_secret` must never keep it.
fn is_credential_field(name: &str) -> bool {
    const NEEDLES: [&str; 5] = ["password", "secret", "token", "assertion", "key"];
    let lowered = name.to_ascii_lowercase();
    NEEDLES.iter().any(|needle| lowered.contains(needle))
}

/// `value` with every credential-bearing field replaced.
///
/// sipgate flow actions carry no credentials, but the transport is public:
/// whoever hands a `client_secret` to [`RequestBody::Json`] or
/// [`RequestBody::Form`] must not see it in a log line because of it.
fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(name, field)| {
                    let field = if is_credential_field(name) {
                        Value::String(REDACTED.to_string())
                    } else {
                        redact_json(field)
                    };
                    (name.clone(), field)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact_json).collect()),
        other => other.clone(),
    }
}

/// `Debug` view of a form body with its credential fields redacted.
struct RedactedFields<'a>(&'a [(String, String)]);

impl fmt::Debug for RedactedFields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (name, value) in self.0 {
            if is_credential_field(name) {
                map.entry(name, &REDACTED);
            } else {
                map.entry(name, value);
            }
        }
        map.finish()
    }
}
