//! `OAuth2` client credentials, with an expiry-aware token cache.
//!
//! sipgate's token endpoint is Keycloak
//! (`https://login.sipgate.com/auth/realms/third-party/protocol/openid-connect/token`).
//! Its discovery document advertises `client_credentials` among the supported
//! grants and both `client_secret_basic` and `client_secret_post` among the
//! token endpoint auth methods; the REST documentation's own examples post
//! `client_id` and `client_secret` as form fields, which is what this crate
//! does.
//!
//! Tokens are cached behind a [`Mutex`] with a refresh margin: a token is
//! reused until it is within [`DEFAULT_REFRESH_MARGIN`] of expiring, then
//! fetched again. Nothing is ever cached in a `static`.
//!
//! ```
//! use sipgate_flow::{ClientCredentials, Token};
//!
//! let credentials = ClientCredentials::new("client-id", "client-secret")?;
//! assert_eq!(credentials.token_request_body()[0].0, "grant_type");
//!
//! let token = Token::from_json(&serde_json::json!({
//!     "access_token": "abc",
//!     "token_type": "bearer",
//!     "expires_in": 300,
//! }))?;
//! assert_eq!(token.access_token(), "abc");
//! # Ok::<(), sipgate_flow::Error>(())
//! ```

use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::error::{Error, Result};
use crate::retry::truncate_body;
use crate::transport::{Method, Request, Security, Transport};

/// Keycloak token endpoint for sipgate's `third-party` realm, as documented at
/// <https://en.sipgate.io/rest-api/authentication> and confirmed by the realm's
/// discovery document.
pub const DEFAULT_TOKEN_URL: &str =
    "https://login.sipgate.com/auth/realms/third-party/protocol/openid-connect/token";

/// How long before expiry a cached token is considered stale.
///
/// The documented lifetime is 300 seconds, so the 60 second default leaves four
/// minutes of usable life and absorbs clock skew between us and the issuer.
pub const DEFAULT_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// Lifetime assumed when a token response omits `expires_in`. Keycloak always
/// sends it (the documentation's example shows 300); this only keeps an
/// unusual response from being cached forever.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(300);

/// A source of "now", so token expiry is testable without waiting.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::Clock;
///
/// struct Fixed;
/// impl Clock for Fixed {
///     fn now(&self) -> Duration {
///         Duration::from_secs(1_700_000_000)
///     }
/// }
/// assert_eq!(Fixed.now().as_secs(), 1_700_000_000);
/// ```
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now(&self) -> Duration;
}

/// Wall clock, reading `SystemTime`.
///
/// ```
/// use sipgate_flow::{Clock, SystemClock};
/// assert!(SystemClock.now().as_secs() > 1_700_000_000);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
    }
}

/// An `OAuth2` client id/secret pair, with optional scopes.
///
/// [`fmt::Debug`] prints the id but never the secret.
///
/// ```
/// use sipgate_flow::ClientCredentials;
///
/// let credentials = ClientCredentials::new("id", "hunter2")?.with_scopes(["sessions:sms:write"]);
/// assert_eq!(credentials.scopes(), ["sessions:sms:write"]);
/// assert!(!format!("{credentials:?}").contains("hunter2"));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone)]
pub struct ClientCredentials {
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
}

impl fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl ClientCredentials {
    /// Fails closed on an empty id or secret.
    ///
    /// ```
    /// use sipgate_flow::ClientCredentials;
    ///
    /// assert!(ClientCredentials::new("id", "secret").is_ok());
    /// assert!(ClientCredentials::new("", "secret").is_err());
    /// assert!(ClientCredentials::new("id", "").is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::EmptyCredentials`] when either half is empty — sending it would
    /// turn a missing environment variable into an anonymous request.
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Result<Self> {
        let client_id = client_id.into();
        let client_secret = client_secret.into();
        if client_id.is_empty() || client_secret.is_empty() {
            return Err(Error::EmptyCredentials);
        }
        Ok(Self {
            client_id,
            client_secret,
            scopes: Vec::new(),
        })
    }

    /// Adds one scope.
    ///
    /// ```
    /// use sipgate_flow::ClientCredentials;
    ///
    /// let credentials = ClientCredentials::new("id", "secret")?.with_scope("rtcm:write");
    /// assert_eq!(credentials.scopes(), ["rtcm:write"]);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Replaces the scopes.
    ///
    /// ```
    /// use sipgate_flow::ClientCredentials;
    ///
    /// let credentials = ClientCredentials::new("id", "secret")?.with_scopes(["a", "b"]);
    /// assert_eq!(credentials.scopes().len(), 2);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// The client id.
    ///
    /// ```
    /// use sipgate_flow::ClientCredentials;
    /// assert_eq!(ClientCredentials::new("id", "secret")?.client_id(), "id");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The requested scopes.
    ///
    /// ```
    /// use sipgate_flow::ClientCredentials;
    /// assert!(ClientCredentials::new("id", "secret")?.scopes().is_empty());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// The complete `application/x-www-form-urlencoded` body for the token
    /// request.
    ///
    /// ```
    /// use sipgate_flow::ClientCredentials;
    ///
    /// let credentials = ClientCredentials::new("id", "secret")?.with_scope("sessions:write");
    /// let body = credentials.token_request_body();
    /// assert_eq!(body[0], ("grant_type".to_string(), "client_credentials".to_string()));
    /// assert_eq!(body[3], ("scope".to_string(), "sessions:write".to_string()));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn token_request_body(&self) -> Vec<(String, String)> {
        let mut body = vec![
            ("grant_type".to_string(), "client_credentials".to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        if !self.scopes.is_empty() {
            body.push(("scope".to_string(), self.scopes.join(" ")));
        }
        body
    }
}

/// An access token as the token endpoint returned it.
///
/// [`fmt::Debug`] redacts the token itself.
///
/// ```
/// use sipgate_flow::Token;
///
/// let token = Token::from_json(&serde_json::json!({"access_token": "abc"}))?;
/// assert_eq!(token.token_type(), "bearer"); // default when omitted
/// assert_eq!(token.expires_in(), None);
/// assert!(!format!("{token:?}").contains("abc"));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
// The field names mirror the token endpoint's JSON; renaming them to satisfy
// the lint would make the mapping harder to check against the documentation.
#[allow(clippy::struct_field_names)]
#[derive(Clone)]
pub struct Token {
    access_token: String,
    token_type: String,
    expires_in: Option<Duration>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .finish()
    }
}

impl Token {
    /// Reads a token response. `access_token` is required and must be
    /// non-empty; `token_type` defaults to `bearer`, as the `OAuth2` RFC allows.
    ///
    /// ```
    /// use sipgate_flow::Token;
    ///
    /// assert!(Token::from_json(&serde_json::json!({})).is_err());
    /// assert!(Token::from_json(&serde_json::json!({"access_token": ""})).is_err());
    /// assert!(Token::from_json(&serde_json::json!({"access_token": "a", "expires_in": 300})).is_ok());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::TokenResponse`] for a missing or empty `access_token`, or a
    /// non-object body.
    pub fn from_json(value: &Value) -> Result<Self> {
        let access_token = value
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| Error::TokenResponse("missing or empty access_token".into()))?;
        Ok(Self {
            access_token: access_token.to_string(),
            token_type: value
                .get("token_type")
                .and_then(Value::as_str)
                .filter(|kind| !kind.is_empty())
                .unwrap_or("bearer")
                .to_string(),
            expires_in: value
                .get("expires_in")
                .and_then(Value::as_u64)
                .map(Duration::from_secs),
            refresh_token: value
                .get("refresh_token")
                .and_then(Value::as_str)
                .map(str::to_string),
            scope: value
                .get("scope")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    /// The bearer token.
    ///
    /// ```
    /// use sipgate_flow::Token;
    /// assert_eq!(Token::from_json(&serde_json::json!({"access_token": "a"}))?.access_token(), "a");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The token type, normally `bearer`.
    ///
    /// ```
    /// use sipgate_flow::Token;
    /// assert_eq!(Token::from_json(&serde_json::json!({"access_token": "a", "token_type": "Bearer"}))?.token_type(), "Bearer");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Lifetime the issuer announced, when it announced one.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::Token;
    ///
    /// let token = Token::from_json(&serde_json::json!({"access_token": "a", "expires_in": 60}))?;
    /// assert_eq!(token.expires_in(), Some(Duration::from_secs(60)));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn expires_in(&self) -> Option<Duration> {
        self.expires_in
    }

    /// The refresh token, for grants that issue one. Client credentials does
    /// not, so this is normally `None`.
    ///
    /// ```
    /// use sipgate_flow::Token;
    /// assert!(Token::from_json(&serde_json::json!({"access_token": "a"}))?.refresh_token().is_none());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// The scopes the issuer granted.
    ///
    /// ```
    /// use sipgate_flow::Token;
    /// let token = Token::from_json(&serde_json::json!({"access_token": "a", "scope": "sessions:write"}))?;
    /// assert_eq!(token.scope(), Some("sessions:write"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
}

/// Anything that can hand out a bearer token: a fixed string for a personal
/// access token, or [`OAuth2Client`] for client credentials.
///
/// `force_refresh` asks for a new token even if the cached one is still valid;
/// it is how a 401 is answered. `invalidate` drops whatever is cached.
///
/// ```
/// use sipgate_flow::{StaticToken, TokenSource};
///
/// # async fn demo() -> sipgate_flow::Result<()> {
/// let token = StaticToken::new("pat")?;
/// assert_eq!(token.access_token(false).await?.access_token(), "pat");
/// # Ok(())
/// # }
/// ```
pub trait TokenSource: Send + Sync {
    /// Returns a token, refreshing (or fetching) as needed.
    ///
    /// # Errors
    ///
    /// Whatever the token endpoint or cache reported.
    fn access_token(
        &self,
        force_refresh: bool,
    ) -> impl std::future::Future<Output = Result<Token>> + Send;

    /// Drops the cached token, so the next call fetches a fresh one.
    fn invalidate(&self);
}

/// A token that never expires — a sipgate Personal Access Token used as a
/// bearer, or a test double.
///
/// ```
/// use sipgate_flow::StaticToken;
///
/// assert!(StaticToken::new("token").is_ok());
/// assert!(StaticToken::new("").is_err());
/// ```
#[derive(Clone)]
pub struct StaticToken(String);

impl fmt::Debug for StaticToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StaticToken").field(&"<redacted>").finish()
    }
}

impl StaticToken {
    /// Wraps a token, refusing an empty one.
    ///
    /// ```
    /// use sipgate_flow::StaticToken;
    /// assert!(StaticToken::new("t").is_ok());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::EmptyCredentials`] for an empty token.
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let token = token.into();
        if token.is_empty() {
            return Err(Error::EmptyCredentials);
        }
        Ok(Self(token))
    }
}

impl TokenSource for StaticToken {
    async fn access_token(&self, _force_refresh: bool) -> Result<Token> {
        Ok(Token {
            access_token: self.0.clone(),
            token_type: "bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: None,
        })
    }

    fn invalidate(&self) {}
}

struct Cached {
    token: Token,
    usable_until: Duration,
}

/// Fetches and caches a client-credentials token.
///
/// Safe to share across tasks: the cache is a [`Mutex`], there is no global
/// state, and concurrent misses each fetch their own token (the issuer grants
/// several; a single-flight lock would serialise every call for no benefit).
///
/// ```
/// use sipgate_flow::{ClientCredentials, OAuth2Client, TokenSource};
/// # use sipgate_flow::{Result, Transport};
/// # use sipgate_flow::transport::{Request, Response};
/// # struct Mock;
/// # impl Transport for Mock {
/// #     async fn execute(&self, _: Request<'_>) -> Result<Response> {
/// #         Ok(Response::new(200, std::iter::empty(), br#"{"access_token":"abc","expires_in":300}"#.to_vec()))
/// #     }
/// # }
/// # async fn demo() -> Result<()> {
/// let auth = OAuth2Client::new(Mock, ClientCredentials::new("id", "secret")?);
/// assert_eq!(auth.access_token(false).await?.access_token(), "abc");
/// // Second call is served from the cache.
/// assert_eq!(auth.access_token(false).await?.access_token(), "abc");
/// # Ok(())
/// # }
/// ```
pub struct OAuth2Client<T: Transport, C: Clock = SystemClock> {
    transport: T,
    clock: C,
    token_url: String,
    credentials: ClientCredentials,
    refresh_margin: Duration,
    timeout: Option<Duration>,
    cache: Mutex<Option<Cached>>,
}

impl<T: Transport> OAuth2Client<T, SystemClock> {
    /// Builds a client for the documented sipgate token endpoint.
    ///
    /// ```
    /// use sipgate_flow::{ClientCredentials, OAuth2Client};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(200, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let auth = OAuth2Client::new(Mock, ClientCredentials::new("id", "secret").unwrap());
    /// assert_eq!(auth.token_url(), sipgate_flow::auth::DEFAULT_TOKEN_URL);
    /// ```
    #[must_use]
    pub fn new(transport: T, credentials: ClientCredentials) -> Self {
        Self {
            transport,
            clock: SystemClock,
            token_url: DEFAULT_TOKEN_URL.to_string(),
            credentials,
            refresh_margin: DEFAULT_REFRESH_MARGIN,
            timeout: None,
            cache: Mutex::new(None),
        }
    }
}

impl<T: Transport, C: Clock> OAuth2Client<T, C> {
    /// Replaces the clock, for tests that need to advance time.
    ///
    /// ```
    /// use sipgate_flow::{ClientCredentials, OAuth2Client, SystemClock};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(200, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let auth = OAuth2Client::new(Mock, ClientCredentials::new("id", "secret").unwrap())
    ///     .with_clock(SystemClock);
    /// assert_eq!(auth.credentials().client_id(), "id");
    /// ```
    #[must_use]
    pub fn with_clock<C2: Clock>(self, clock: C2) -> OAuth2Client<T, C2> {
        OAuth2Client {
            transport: self.transport,
            clock,
            token_url: self.token_url,
            credentials: self.credentials,
            refresh_margin: self.refresh_margin,
            timeout: self.timeout,
            cache: Mutex::new(None),
        }
    }

    /// Overrides the token endpoint (for a proxy or a test server).
    ///
    /// ```
    /// use sipgate_flow::{ClientCredentials, OAuth2Client};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(200, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let auth = OAuth2Client::new(Mock, ClientCredentials::new("id", "secret").unwrap())
    ///     .with_token_url("https://proxy.test/token");
    /// assert_eq!(auth.token_url(), "https://proxy.test/token");
    /// ```
    #[must_use]
    pub fn with_token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = url.into();
        self
    }

    /// Sets how long before expiry the token is refreshed.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::{ClientCredentials, OAuth2Client};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(200, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let auth = OAuth2Client::new(Mock, ClientCredentials::new("id", "secret").unwrap())
    ///     .with_refresh_margin(Duration::from_secs(30));
    /// assert_eq!(auth.refresh_margin(), Duration::from_secs(30));
    /// ```
    #[must_use]
    pub fn with_refresh_margin(mut self, margin: Duration) -> Self {
        self.refresh_margin = margin;
        self
    }

    /// Sets a per-request timeout for the token call.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::{ClientCredentials, OAuth2Client};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(200, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let auth = OAuth2Client::new(Mock, ClientCredentials::new("id", "secret").unwrap())
    ///     .with_timeout(Some(Duration::from_secs(5)));
    /// assert_eq!(auth.timeout(), Some(Duration::from_secs(5)));
    /// ```
    #[must_use]
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// The token endpoint in use.
    ///
    /// ```
    /// use sipgate_flow::{ClientCredentials, OAuth2Client};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(200, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// assert!(OAuth2Client::new(Mock, ClientCredentials::new("id", "secret").unwrap()).token_url().starts_with("https://"));
    /// ```
    #[must_use]
    pub fn token_url(&self) -> &str {
        &self.token_url
    }

    /// The configured refresh margin.
    ///
    /// ```
    /// use sipgate_flow::{ClientCredentials, OAuth2Client};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(200, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let auth = OAuth2Client::new(Mock, ClientCredentials::new("id", "secret").unwrap());
    /// assert_eq!(auth.refresh_margin(), sipgate_flow::auth::DEFAULT_REFRESH_MARGIN);
    /// ```
    #[must_use]
    pub fn refresh_margin(&self) -> Duration {
        self.refresh_margin
    }

    /// The configured timeout.
    ///
    /// ```
    /// use sipgate_flow::{ClientCredentials, OAuth2Client};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(200, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// assert!(OAuth2Client::new(Mock, ClientCredentials::new("id", "secret").unwrap()).timeout().is_none());
    /// ```
    #[must_use]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// The credentials, for inspection (the secret stays redacted in `Debug`).
    ///
    /// ```
    /// use sipgate_flow::{ClientCredentials, OAuth2Client};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(200, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let auth = OAuth2Client::new(Mock, ClientCredentials::new("my-id", "secret").unwrap());
    /// assert_eq!(auth.credentials().client_id(), "my-id");
    /// ```
    #[must_use]
    pub fn credentials(&self) -> &ClientCredentials {
        &self.credentials
    }

    /// Whether a token is cached and still has more than the refresh margin
    /// left.
    ///
    /// ```
    /// use sipgate_flow::{ClientCredentials, OAuth2Client};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(200, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let auth = OAuth2Client::new(Mock, ClientCredentials::new("id", "secret").unwrap());
    /// assert!(!auth.has_valid_token());
    /// ```
    #[must_use]
    pub fn has_valid_token(&self) -> bool {
        self.cached().is_some()
    }

    fn cached(&self) -> Option<Token> {
        let now = self.clock.now();
        let guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .as_ref()
            .filter(|cached| now < cached.usable_until)
            .map(|cached| cached.token.clone())
    }

    fn store(&self, token: Token) {
        let lifetime = token.expires_in().unwrap_or(DEFAULT_LIFETIME);
        let usable_for = lifetime
            .saturating_sub(self.refresh_margin)
            .max(Duration::ZERO);
        let usable_until = self.clock.now() + usable_for;
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(Cached {
            token,
            usable_until,
        });
    }

    async fn fetch(&self) -> Result<Token> {
        let body = self.credentials.token_request_body();
        let request = Request::form(Method::Post, &self.token_url, Security::None, &body)
            .with_timeout(self.timeout);
        let response = self.transport.execute(request).await?;
        if !response.is_success() {
            return Err(Error::AuthRejected {
                status: response.status(),
                body: truncate_body(&response.text()),
            });
        }
        Token::from_json(&response.json()?)
    }
}

impl<T: Transport, C: Clock> TokenSource for OAuth2Client<T, C> {
    async fn access_token(&self, force_refresh: bool) -> Result<Token> {
        if !force_refresh {
            if let Some(token) = self.cached() {
                return Ok(token);
            }
        }
        let token = self.fetch().await?;
        self.store(token.clone());
        Ok(token)
    }

    fn invalidate(&self) {
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = None;
    }
}

impl<T: Transport, C: Clock> fmt::Debug for OAuth2Client<T, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2Client")
            .field("token_url", &self.token_url)
            .field("credentials", &self.credentials)
            .field("refresh_margin", &self.refresh_margin)
            .field("has_valid_token", &self.has_valid_token())
            .finish_non_exhaustive()
    }
}
