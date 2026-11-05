//! Credentials and the expiry-aware token cache.
//!
//! Two shapes, two headers — the distinction sipgate's documentation makes
//! (<https://en.sipgate.io/rest-api/authentication>):
//!
//! * [`PersonalAccessToken`] — `Authorization: Basic base64(<token id>:<token>)`.
//!   This is the documented path for a server integration.
//! * [`OAuth2Client`] — `Authorization: Bearer <access_token>`, fetched with the
//!   `client_credentials` grant and cached until shortly before it expires.
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
use std::task::{Poll, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::retry::retry_after_from;
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

/// The longest token lifetime the crate accepts.
///
/// `Duration::from_secs` builds a duration from any `u64`, but adding one to a
/// clock reading panics on overflow, in release builds as well. A token
/// response of `{"expires_in": 18446744073709551615}` - a broken proxy, a
/// misconfigured realm, or a hostile endpoint - therefore used to take the
/// process down on the cache path. Anything above this ceiling is refused as
/// [`Error::TokenResponse`] instead. No real issuer hands out a token for
/// longer than a day; Keycloak, which serves the sipgate token endpoint, sends
/// 300 seconds.
///
/// ```
/// use sipgate_flow::auth::{MAX_TOKEN_LIFETIME, Token};
/// use sipgate_flow::Error;
///
/// let at_ceiling = Token::from_json(&serde_json::json!({
///     "access_token": "a",
///     "expires_in": MAX_TOKEN_LIFETIME.as_secs(),
/// }))?;
/// assert_eq!(at_ceiling.expires_in(), Some(MAX_TOKEN_LIFETIME));
///
/// let beyond = Token::from_json(&serde_json::json!({
///     "access_token": "a",
///     "expires_in": u64::MAX,
/// }));
/// assert!(matches!(beyond, Err(Error::TokenResponse(_))));
/// # Ok::<(), Error>(())
/// ```
pub const MAX_TOKEN_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// Turns the wire expiry into a duration, refusing a lifetime the clock
/// arithmetic cannot carry.
///
/// A value that is not a non-negative integer is treated as absent, the same
/// tolerance every other field gets; a value above [`MAX_TOKEN_LIFETIME`] is
/// an error, because it cannot be honestly cached.
fn token_lifetime(seconds: u64) -> Result<Duration> {
    let lifetime = Duration::from_secs(seconds);
    if lifetime > MAX_TOKEN_LIFETIME {
        return Err(Error::TokenResponse(format!(
            "expires_in of {seconds} seconds exceeds the accepted maximum of {} seconds",
            MAX_TOKEN_LIFETIME.as_secs()
        )));
    }
    Ok(lifetime)
}

fn cached_lifetime(lifetime: Duration, margin: Duration) -> Result<Duration> {
    if lifetime.is_zero() {
        return Err(Error::TokenResponse(
            "expires_in of 0 seconds leaves no usable token lifetime".into(),
        ));
    }
    // The margin may be validly configured for a long-lived issuer and still be
    // too large for a shorter-lived one. Clamp in that direction so a token is
    // never stored with an expiry at or before the moment it was stored.
    let margin = margin.min(lifetime / 2);
    lifetime
        .checked_sub(margin)
        .ok_or_else(|| Error::TokenResponse("refresh margin leaves no usable lifetime".into()))
}

/// A source of "now", so token expiry is testable without waiting.
///
/// Implementations must report a wall-clock reading since the Unix epoch, or
/// fail when no such reading is available. A failure is treated as terminal:
/// the OAuth cache fails closed instead of guessing a time for token validity.
///
/// ```
/// use std::time::Duration;
/// use sipgate_flow::Clock;
///
/// struct Fixed;
/// impl Clock for Fixed {
///     fn now(&self) -> sipgate_flow::Result<Duration> {
///         Ok(Duration::from_secs(1_700_000_000))
///     }
/// }
/// assert_eq!(Fixed.now()?.as_secs(), 1_700_000_000);
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when the implementation cannot produce a reliable
    /// wall-clock reading. For [`SystemClock`] this is a terminal transport
    /// error when the system time is before the Unix epoch.
    fn now(&self) -> Result<Duration>;
}

/// Wall clock, reading `SystemTime`.
///
/// ```
/// use sipgate_flow::{Clock, SystemClock};
/// assert!(SystemClock.now()?.as_secs() > 1_700_000_000);
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<Duration> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::transport_terminal("system clock is before the Unix epoch"))
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

/// A credential plus the scheme it goes out with.
///
/// The token endpoint returns `token_type` (always `bearer` for sipgate), and a
/// [`PersonalAccessToken`] carries `basic`; [`Token::security`] turns that into
/// the header the transport writes.
///
/// [`fmt::Debug`] redacts the secret.
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
    /// Present only for [`Security::Basic`] credentials: the user half the
    /// transport encodes alongside the secret.
    username: Option<String>,
    expires_in: Option<Duration>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("username", &self.username)
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
    /// An `expires_in` that is not a non-negative integer is treated as absent,
    /// so the assumed [`DEFAULT_LIFETIME`] applies; one above
    /// [`MAX_TOKEN_LIFETIME`] is refused rather than turned into a duration the
    /// cache clock arithmetic cannot add.
    ///
    /// # Errors
    ///
    /// [`Error::TokenResponse`] for a missing or empty `access_token`, a
    /// non-object body, or an `expires_in` above [`MAX_TOKEN_LIFETIME`].
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
            username: None,
            expires_in: value
                .get("expires_in")
                .and_then(Value::as_u64)
                .map(token_lifetime)
                .transpose()?,
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

    /// The `Authorization` header this credential goes out with.
    ///
    /// `bearer` (and every unrecognised scheme, which the transport then sends
    /// as a bearer rather than dropping) maps to [`Security::Bearer`]; a
    /// credential built by [`PersonalAccessToken`] maps to [`Security::Basic`],
    /// which is how sipgate documents a PAT
    /// (<https://en.sipgate.io/rest-api/authentication>).
    ///
    /// ```
    /// use sipgate_flow::{Security, Token};
    ///
    /// let bearer = Token::from_json(&serde_json::json!({"access_token": "abc"}))?;
    /// assert!(matches!(bearer.security(), Security::Bearer("abc")));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// ```
    /// use sipgate_flow::{PersonalAccessToken, Security, TokenSource};
    ///
    /// # async fn demo() -> sipgate_flow::Result<()> {
    /// let pat = PersonalAccessToken::new("token-FQ1V12", "e68ead46")?;
    /// let credential = pat.access_token(false).await?;
    /// assert!(matches!(
    ///     credential.security(),
    ///     Security::Basic { username: "token-FQ1V12", password: "e68ead46" }
    /// ));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn security(&self) -> Security<'_> {
        match &self.username {
            Some(username) if self.token_type.eq_ignore_ascii_case("basic") => Security::Basic {
                username,
                password: &self.access_token,
            },
            _ => Security::Bearer(&self.access_token),
        }
    }
}

/// Anything that can hand out a credential: a fixed string for a test double
/// or an `OAuth2` access token ([`StaticToken`]), a sipgate Personal Access
/// Token ([`PersonalAccessToken`]), or [`OAuth2Client`] for client credentials.
///
/// `force_refresh` asks for a new token even if the cached one is still valid;
/// it is how a 401 is answered. `refresh_after` replaces the credential that
/// was actually rejected, and `invalidate` drops whatever is cached.
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

    /// Replaces `stale` after it was rejected with a 401.
    ///
    /// This is the single-flight refresh path: if another task already stored a
    /// different usable token, that token is returned without contacting the
    /// issuer. Otherwise one caller fetches and concurrent callers await that
    /// same fetch instead of each starting their own.
    ///
    /// ```
    /// use sipgate_flow::{StaticToken, TokenSource};
    ///
    /// # async fn demo() -> sipgate_flow::Result<()> {
    /// let auth = StaticToken::new("pat")?;
    /// let stale = auth.access_token(false).await?;
    /// let fresh = auth.refresh_after(&stale).await?;
    /// assert_eq!(fresh.access_token(), "pat");
    /// # Ok(())
    /// # }
    /// ```
    fn refresh_after(
        &self,
        stale: &Token,
    ) -> impl std::future::Future<Output = Result<Token>> + Send {
        async move {
            let _ = stale;
            self.invalidate();
            self.access_token(true).await
        }
    }

    /// Drops the cached token, so the next call fetches a fresh one.
    fn invalidate(&self);
}

/// A credential that never expires: an `OAuth2` access token, or a test double.
///
/// A sipgate *Personal Access Token* is not a bearer token — use
/// [`PersonalAccessToken`], which sends the documented `Basic` header.
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
    fn access_token(
        &self,
        _force_refresh: bool,
    ) -> impl std::future::Future<Output = Result<Token>> + Send {
        std::future::ready(Ok(Token {
            access_token: self.0.clone(),
            token_type: "bearer".into(),
            username: None,
            expires_in: None,
            refresh_token: None,
            scope: None,
        }))
    }

    fn invalidate(&self) {}
}

/// A sipgate **Personal Access Token**, sent the way sipgate documents it.
///
/// A PAT is *not* a bearer token: the REST API expects
/// `Authorization: Basic base64(<token id>:<token>)`
/// (<https://en.sipgate.io/rest-api/authentication>, and the same construction
/// in sipgate's own `sipgateio` client). [`StaticToken`] stays for `OAuth2`
/// access tokens, which are sent as `Bearer`.
///
/// ```no_run
/// # #[cfg(feature = "http")]
/// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// use sipgate_flow::{PersonalAccessToken, ReqwestTransport, RestClient};
///
/// let auth = PersonalAccessToken::new(
///     std::env::var("SIPGATE_TOKEN_ID")?,
///     std::env::var("SIPGATE_TOKEN")?,
/// )?;
/// let client = RestClient::new(ReqwestTransport::new(), auth);
/// for call in client.calls().await? {
///     println!("{}", call.call_id);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct PersonalAccessToken {
    token_id: String,
    token: String,
}

impl fmt::Debug for PersonalAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token id is an identifier, not a secret; the token is both.
        f.debug_struct("PersonalAccessToken")
            .field("token_id", &self.token_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl PersonalAccessToken {
    /// Wraps a token id and token, refusing either half being empty.
    ///
    /// ```
    /// use sipgate_flow::PersonalAccessToken;
    ///
    /// assert!(PersonalAccessToken::new("token-FQ1V12", "e68ead46").is_ok());
    /// assert!(PersonalAccessToken::new("", "e68ead46").is_err());
    /// assert!(PersonalAccessToken::new("token-FQ1V12", "").is_err());
    /// assert!(PersonalAccessToken::new("token:FQ1V12", "e68ead46").is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::EmptyCredentials`] when either half is empty, and
    /// [`Error::Validation`] when the token id contains a colon — the wire form
    /// is `id:token`, so a colon in the id would silently move the boundary and
    /// send a different credential than the caller configured.
    pub fn new(token_id: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        let token_id = token_id.into();
        let token = token.into();
        if token_id.is_empty() || token.is_empty() {
            return Err(Error::EmptyCredentials);
        }
        if token_id.contains(':') {
            return Err(Error::Validation {
                field: "token_id",
                message: "must not contain ':' (the wire credential is `id:token`)".into(),
            });
        }
        Ok(Self { token_id, token })
    }

    /// The token id (`token-FQ1V12` and friends), which is not a secret.
    ///
    /// ```
    /// use sipgate_flow::PersonalAccessToken;
    /// assert_eq!(PersonalAccessToken::new("token-FQ1V12", "x")?.token_id(), "token-FQ1V12");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn token_id(&self) -> &str {
        &self.token_id
    }
}

impl TokenSource for PersonalAccessToken {
    fn access_token(
        &self,
        _force_refresh: bool,
    ) -> impl std::future::Future<Output = Result<Token>> + Send {
        // `basic` is the scheme; the transport encodes `id:token` from the two
        // halves, so the secret is never concatenated into one string here.
        std::future::ready(Ok(Token {
            access_token: self.token.clone(),
            token_type: "basic".into(),
            username: Some(self.token_id.clone()),
            expires_in: None,
            refresh_token: None,
            scope: None,
        }))
    }

    fn invalidate(&self) {}
}

struct Cached {
    token: Token,
    usable_until: Duration,
}

struct CacheState {
    cached: Option<Cached>,
    generation: u64,
    refresh_generation: Option<u64>,
    refresh_waiters: Vec<Waker>,
}

impl CacheState {
    fn new() -> Self {
        Self {
            cached: None,
            generation: 0,
            refresh_generation: None,
            refresh_waiters: Vec::new(),
        }
    }

    fn next_generation(&mut self) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.generation
    }
}

enum RefreshAttempt {
    Ready(Token),
    Fetch(u64),
    Waiting,
}

fn same_token(left: &Token, right: &Token) -> bool {
    bool::from(
        left.access_token
            .as_bytes()
            .ct_eq(right.access_token.as_bytes()),
    )
}

/// Fetches and caches a client-credentials token.
///
/// Safe to share across tasks: the cache is a [`Mutex`], there is no global
/// state, and concurrent misses each fetch their own token (the issuer grants
/// several; a single-flight lock would serialise every call for no benefit).
/// Each fetch reserves a cache generation, so an `invalidate` call or a fetch
/// started later supersedes an in-flight response instead of letting the older
/// response overwrite newer cache state. A 401 takes the stricter
/// [`TokenSource::refresh_after`] path: only the rejected token is replaced, and
/// concurrent rejections of that same token wait for one fetch.
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
    cache: Mutex<CacheState>,
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
            cache: Mutex::new(CacheState::new()),
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
            cache: Mutex::new(CacheState::new()),
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
    /// A margin at or above the announced lifetime is clamped to half that
    /// lifetime when a token is stored, so a shorter-lived issuer cannot turn
    /// the cache into a no-op. An `expires_in` of zero is refused as
    /// [`Error::TokenResponse`] because the token is unusable.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::auth::MAX_TOKEN_LIFETIME;
    /// use sipgate_flow::{ClientCredentials, Error, OAuth2Client};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(200, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let auth = OAuth2Client::new(Mock, ClientCredentials::new("id", "secret")?)
    ///     .with_refresh_margin(Duration::from_secs(30))?;
    /// assert_eq!(auth.refresh_margin(), Duration::from_secs(30));
    ///
    /// let refused = OAuth2Client::new(Mock, ClientCredentials::new("id", "secret")?)
    ///     .with_refresh_margin(MAX_TOKEN_LIFETIME);
    /// assert!(matches!(refused, Err(Error::Validation { field: "refresh_margin", .. })));
    /// # Ok::<(), Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `margin` is not strictly smaller than
    /// [`MAX_TOKEN_LIFETIME`].
    pub fn with_refresh_margin(mut self, margin: Duration) -> Result<Self> {
        if margin >= MAX_TOKEN_LIFETIME {
            return Err(Error::Validation {
                field: "refresh_margin",
                message: format!(
                    "must be smaller than the accepted maximum token lifetime of {} seconds",
                    MAX_TOKEN_LIFETIME.as_secs()
                ),
            });
        }
        self.refresh_margin = margin;
        Ok(self)
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
        matches!(self.cached(), Ok(Some(_)))
    }

    fn cached(&self) -> Result<Option<Token>> {
        let now = self.clock.now()?;
        let guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(guard
            .cached
            .as_ref()
            .filter(|cached| now < cached.usable_until)
            .map(|cached| cached.token.clone()))
    }

    fn begin_fetch(&self) -> u64 {
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.next_generation()
    }

    fn begin_refresh(&self, stale: &Token) -> Result<RefreshAttempt> {
        let now = self.clock.now()?;
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cached = guard
            .cached
            .as_ref()
            .filter(|cached| now < cached.usable_until);
        match cached {
            Some(cached) if !same_token(&cached.token, stale) => {
                return Ok(RefreshAttempt::Ready(cached.token.clone()));
            }
            _ => {}
        }
        if guard.refresh_generation.is_some() {
            return Ok(RefreshAttempt::Waiting);
        }
        let generation = guard.next_generation();
        guard.refresh_generation = Some(generation);
        Ok(RefreshAttempt::Fetch(generation))
    }

    fn store(&self, token: Token, generation: u64) -> Result<()> {
        let lifetime = token.expires_in().unwrap_or(DEFAULT_LIFETIME);
        let usable_for = cached_lifetime(lifetime, self.refresh_margin)?;
        // `Duration` add panics on overflow (release builds included), so a clock
        // reading near the end of the representable range must surface as a typed
        // error instead of taking the process down.
        let usable_until = self
            .clock
            .now()?
            .checked_add(usable_for)
            .ok_or_else(|| Error::TokenResponse("token expiry overflows the clock".into()))?;
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.generation == generation {
            guard.cached = Some(Cached {
                token,
                usable_until,
            });
        }
        if guard.refresh_generation == Some(generation) {
            guard.refresh_generation = None;
            for waiter in guard.refresh_waiters.drain(..) {
                waiter.wake();
            }
        }
        Ok(())
    }

    fn finish_refresh(&self, generation: u64) {
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.refresh_generation == Some(generation) {
            guard.refresh_generation = None;
            for waiter in guard.refresh_waiters.drain(..) {
                waiter.wake();
            }
        }
    }

    async fn fetch(&self) -> Result<Token> {
        let body = self.credentials.token_request_body();
        let request = Request::form(Method::Post, &self.token_url, Security::None, &body)
            .with_timeout(self.timeout);
        let response = self.transport.execute(request).await?;
        if !response.is_success() {
            let status = response.status();
            // The `client_credentials` POST creates a token and has no
            // business side effect, so a 429 or 5xx can be repeated safely.
            // Only an explicit rejection of the credentials (400/401/403 and
            // other 4xx) is terminal.
            return Err(if status == 429 || (500..600).contains(&status) {
                Error::api_retryable(
                    status,
                    response.text(),
                    retry_after_from(|name| response.header(name)),
                )
            } else {
                Error::auth_rejected(status, response.text())
            });
        }
        Token::from_json(&response.json()?)
    }
}

impl<T: Transport, C: Clock> TokenSource for OAuth2Client<T, C> {
    async fn access_token(&self, force_refresh: bool) -> Result<Token> {
        if !force_refresh {
            if let Some(token) = self.cached()? {
                return Ok(token);
            }
        }
        let generation = self.begin_fetch();
        let token = self.fetch().await?;
        self.store(token.clone(), generation)?;
        Ok(token)
    }

    async fn refresh_after(&self, stale: &Token) -> Result<Token> {
        let generation = loop {
            match self.begin_refresh(stale)? {
                RefreshAttempt::Ready(token) => return Ok(token),
                RefreshAttempt::Fetch(generation) => break generation,
                RefreshAttempt::Waiting => {
                    std::future::poll_fn(|cx| {
                        let mut guard = self
                            .cache
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if guard.refresh_generation.is_none() {
                            return Poll::Ready(());
                        }
                        let waker = cx.waker();
                        if !guard
                            .refresh_waiters
                            .iter()
                            .any(|waiting| waiting.will_wake(waker))
                        {
                            guard.refresh_waiters.push(waker.clone());
                        }
                        Poll::Pending
                    })
                    .await;
                }
            }
        };
        let token = match self.fetch().await {
            Ok(token) => token,
            Err(error) => {
                self.finish_refresh(generation);
                return Err(error);
            }
        };
        if let Err(error) = self.store(token.clone(), generation) {
            self.finish_refresh(generation);
            return Err(error);
        }
        Ok(token)
    }

    fn invalidate(&self) {
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.cached = None;
        guard.next_generation();
        if guard.refresh_generation.is_some() {
            guard.refresh_generation = None;
            for waiter in guard.refresh_waiters.drain(..) {
                waiter.wake();
            }
        }
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
