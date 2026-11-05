//! sipgate REST API v2: SMS, fax, outbound calls and real-time call control.
//!
//! This is the *imperative* half of sipgate — the operations you trigger from
//! your own code rather than return to a Flow — and it is a separate product
//! from [`crate::flow`] events. Every path, method, body field and status code
//! here comes from the public Swagger document at
//! <https://api.sipgate.com/v2/swagger.json> (rendered at
//! <https://api.sipgate.com/v2/doc>);
//! [docs/contracts.md](https://github.com/floffel/sipgate-flow/blob/main/docs/contracts.md)
//! maps each method to its operation.
//!
//! Authentication is a bearer token: an `OAuth2` access token
//! ([`crate::OAuth2Client`]) or a Personal Access Token
//! ([`crate::StaticToken`]).
//!
//! ```no_run
//! # #[cfg(feature = "http")]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use sipgate_flow::{rest::Sms, ReqwestTransport, RestClient, StaticToken};
//!
//! let client = RestClient::new(
//!     ReqwestTransport::new(),
//!     StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?,
//! );
//! client.send_sms(&Sms::new("s0", "4915112345678", "Ihr Code: 4242")?).await?;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::auth::{StaticToken, TokenSource};
use crate::error::{Error, Result};
use crate::exchange;
use crate::retry::{api_error, NoSleep, RetryPolicy, Sleeper};
use crate::transport::{Method, Transport};
use crate::validate;

/// Base URL of the REST API; the Swagger document's `host` plus `basePath`
/// `/v2`.
pub const DEFAULT_BASE_URL: &str = "https://api.sipgate.com";

/// The documented `basePath`.
pub const BASE_PATH: &str = "/v2";

/// Documented `maxLength` for `base64Content` in a fax request (about 21 MiB of
/// PDF, 28.3 MiB encoded).
pub const MAX_FAX_BASE64_LEN: usize = 28_330_000;

/// Client for the sipgate REST API v2.
///
/// Retries, timeouts and pacing are configurable; the client is `Send + Sync`
/// whenever its transport and token source are, so one instance can serve every
/// task.
///
/// ```
/// use sipgate_flow::{RestClient, StaticToken};
/// # use sipgate_flow::{Result, Transport};
/// # use sipgate_flow::transport::{Request, Response};
/// # struct Mock;
/// # impl Transport for Mock {
/// #     async fn execute(&self, _: Request<'_>) -> Result<Response> {
/// #         Ok(Response::new(204, std::iter::empty(), Vec::new()))
/// #     }
/// # }
/// let client = RestClient::new(Mock, StaticToken::new("t").unwrap());
/// assert_eq!(client.base_url(), "https://api.sipgate.com");
/// ```
pub struct RestClient<T: Transport, A: TokenSource = StaticToken, S: Sleeper = NoSleep> {
    transport: T,
    auth: A,
    sleeper: S,
    base_url: String,
    timeout: Option<Duration>,
    retry: RetryPolicy,
}

impl<T: Transport, A: TokenSource> RestClient<T, A, NoSleep> {
    /// Builds a client against the documented base URL.
    ///
    /// ```
    /// use sipgate_flow::{RestClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(204, std::iter::empty(), Vec::new())) }
    /// # }
    /// let client = RestClient::new(Mock, StaticToken::new("t").unwrap());
    /// assert!(client.base_url().starts_with("https://api.sipgate.com"));
    /// ```
    #[must_use]
    pub fn new(transport: T, auth: A) -> Self {
        Self {
            transport,
            auth,
            sleeper: NoSleep,
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout: None,
            retry: RetryPolicy::default(),
        }
    }
}

impl<T: Transport, A: TokenSource, S: Sleeper> RestClient<T, A, S> {
    /// Replaces the sleeper that paces retries. Without one, retries happen
    /// back to back.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::{FnSleeper, RestClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(204, std::iter::empty(), Vec::new())) }
    /// # }
    /// let solver = FnSleeper::new(|d: Duration| std::future::ready(drop(d)));
    /// let client = RestClient::new(Mock, StaticToken::new("t").unwrap()).with_sleeper(solver);
    /// assert!(client.retry().max_attempts >= 1);
    /// ```
    #[must_use]
    pub fn with_sleeper<S2: Sleeper>(self, sleeper: S2) -> RestClient<T, A, S2> {
        RestClient {
            transport: self.transport,
            auth: self.auth,
            sleeper,
            base_url: self.base_url,
            timeout: self.timeout,
            retry: self.retry,
        }
    }

    /// Overrides the base URL (a proxy, a test server, or a regional host).
    ///
    /// ```
    /// use sipgate_flow::{RestClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(204, std::iter::empty(), Vec::new())) }
    /// # }
    /// let client = RestClient::new(Mock, StaticToken::new("t").unwrap())
    ///     .with_base_url("http://localhost:8080/");
    /// assert_eq!(client.base_url(), "http://localhost:8080");
    /// ```
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into().trim_end_matches('/').to_string();
        self
    }

    /// Sets a per-request timeout. `None` leaves the transport's default.
    ///
    /// The value is a total budget for the two attempts of a logical request:
    /// a 401 refresh derives each leg's timeout from the same deadline instead
    /// of granting a fresh one, and the pause before the resend counts against
    /// the budget as well. A caller who sets 10 s to fit a Lambda's remaining
    /// time is therefore not handed 10 s + 10 s for the retried request.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::{RestClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(204, std::iter::empty(), Vec::new())) }
    /// # }
    /// let client = RestClient::new(Mock, StaticToken::new("t").unwrap())
    ///     .with_timeout(Some(Duration::from_secs(5)));
    /// assert_eq!(client.timeout(), Some(Duration::from_secs(5)));
    /// ```
    #[must_use]
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replaces the retry policy (default: three attempts, 250 ms doubling
    /// with equal jitter to an 8 s ceiling, `Retry-After` honoured).
    ///
    /// ```
    /// use sipgate_flow::{RestClient, RetryPolicy, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(204, std::iter::empty(), Vec::new())) }
    /// # }
    /// let client = RestClient::new(Mock, StaticToken::new("t").unwrap())
    ///     .with_retry(RetryPolicy::none());
    /// assert_eq!(client.retry().max_attempts, 1);
    /// ```
    #[must_use]
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// The base URL in use.
    ///
    /// ```
    /// use sipgate_flow::{RestClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(204, std::iter::empty(), Vec::new())) }
    /// # }
    /// assert_eq!(RestClient::new(Mock, StaticToken::new("t").unwrap()).base_url(), "https://api.sipgate.com");
    /// ```
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The configured timeout.
    ///
    /// ```
    /// use sipgate_flow::{RestClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(204, std::iter::empty(), Vec::new())) }
    /// # }
    /// assert!(RestClient::new(Mock, StaticToken::new("t").unwrap()).timeout().is_none());
    /// ```
    #[must_use]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// The retry policy in use.
    ///
    /// ```
    /// use sipgate_flow::{RestClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(204, std::iter::empty(), Vec::new())) }
    /// # }
    /// assert_eq!(RestClient::new(Mock, StaticToken::new("t").unwrap()).retry().max_attempts, 3);
    /// ```
    #[must_use]
    pub fn retry(&self) -> &RetryPolicy {
        &self.retry
    }

    /// The token source, for inspection.
    ///
    /// ```
    /// use sipgate_flow::{RestClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(204, std::iter::empty(), Vec::new())) }
    /// # }
    /// let client = RestClient::new(Mock, StaticToken::new("t").unwrap());
    /// let _: &StaticToken = client.auth();
    /// ```
    #[must_use]
    pub fn auth(&self) -> &A {
        &self.auth
    }

    /// Sends one request with 401 refresh, bounded retries and `Retry-After`
    /// pacing.
    async fn send(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let mut attempts_failed = 0_u32;
        loop {
            let error = match self.attempt(method, path, body).await {
                Ok(value) => return Ok(value),
                Err(error) => error,
            };
            if !error.is_retryable() {
                return Err(error);
            }
            attempts_failed += 1;
            match self.retry.delay(attempts_failed, error.retry_after()) {
                Some(delay) => self.sleeper.sleep(delay).await,
                None => return Err(error),
            }
        }
    }

    /// One logical attempt: refresh the token once on 401, then give up.
    async fn attempt(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: true,
                path,
            },
            exchange::Pacing {
                timeout: self.timeout,
                retry: &self.retry,
                sleeper: &self.sleeper,
            },
            method,
            body,
        )
        .await?;
        if response.is_success() {
            return response.json();
        }
        Err(api_error(
            method,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// `POST /v2/sessions/sms` — send a text message.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::Sms, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let sms = Sms::new("s0", "4915112345678", "Ihr Code: 4242")?;
    /// client.send_sms(&sms).await?; // 204 No Content on success
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Api`] with status 400 (invalid recipient/message) or 402
    /// (insufficient funds), plus anything the transport or auth layers report.
    pub async fn send_sms(&self, sms: &Sms) -> Result<Value> {
        self.send(Method::Post, "/v2/sessions/sms", Some(&sms.to_json()))
            .await
    }

    /// `POST /v2/sessions/fax` — send a fax; answers with `{"sessionId": ...}`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::Fax, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let fax = Fax::new("f0", "4915112345678", "fax.pdf", "JVBERi0xLjQK")?;
    /// client.send_fax(&fax).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Api`] with status 400 or 402, plus transport and auth errors.
    pub async fn send_fax(&self, fax: &Fax) -> Result<Value> {
        self.send(Method::Post, "/v2/sessions/fax", Some(&fax.to_json()))
            .await
    }

    /// `POST /v2/sessions/fax/resend` — resend a previously sent fax.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::ResendFax, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.resend_fax(&ResendFax::new("100018428")).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Api`] with status 402 or 500, plus transport and auth errors.
    pub async fn resend_fax(&self, resend: &ResendFax) -> Result<Value> {
        self.send(
            Method::Post,
            "/v2/sessions/fax/resend",
            Some(&resend.to_json()),
        )
        .await
    }

    /// `POST /v2/sessions/calls` — ring a device and connect it to `callee`
    /// (classic PBX accounts).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::Call, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let call = Call::new("e0", "4915112345678")?;
    /// let created = client.new_call(&call).await?;
    /// println!("{}", created["sessionId"]);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Api`] with status 400, 402 or 403, plus transport and auth
    /// errors.
    pub async fn new_call(&self, call: &Call) -> Result<Value> {
        self.send(Method::Post, "/v2/sessions/calls", Some(&call.to_json()))
            .await
    }

    /// `POST /v2/calls` — start a channel call on a Neo PBX account.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::ChannelCall, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let call = ChannelCall::new("e0", "4915112345678");
    /// client.channel_call(&call).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Api`] with status 400 or 500, plus transport and auth errors.
    pub async fn channel_call(&self, call: &ChannelCall) -> Result<Value> {
        self.send(Method::Post, "/v2/calls", Some(&call.to_json()))
            .await
    }

    /// `POST /v2/sessions/ivr/recording` — dial a device to record an IVR
    /// prompt.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::RecordingSession, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.record_ivr(&RecordingSession::new().with_device_id("e0")).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Api`] with status 400, 402 or 403, plus transport and auth
    /// errors.
    pub async fn record_ivr(&self, request: &RecordingSession) -> Result<Value> {
        self.send(
            Method::Post,
            "/v2/sessions/ivr/recording",
            Some(&request.to_json()),
        )
        .await
    }

    /// `POST /v2/sessions/voicemail/recording` — dial a device to record a
    /// voicemail greeting.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::RecordingSession, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.record_voicemail(&RecordingSession::new().with_device_id("e0")).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Api`] with status 400, 402 or 403, plus transport and auth
    /// errors.
    pub async fn record_voicemail(&self, request: &RecordingSession) -> Result<Value> {
        self.send(
            Method::Post,
            "/v2/sessions/voicemail/recording",
            Some(&request.to_json()),
        )
        .await
    }

    /// `POST /v2/sessions/voicemail/play` — call a device and play a stored
    /// voicemail.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::PlayVoicemail, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.play_voicemail(&PlayVoicemail::new("1000171", "e0")).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Api`] with status 400, 402 or 403, plus transport and auth
    /// errors.
    pub async fn play_voicemail(&self, request: &PlayVoicemail) -> Result<Value> {
        self.send(
            Method::Post,
            "/v2/sessions/voicemail/play",
            Some(&request.to_json()),
        )
        .await
    }

    /// `GET /v2/calls` — every established call, typed.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// for call in client.calls().await? {
    ///     println!("{} on hold: {}", call.call_id, call.hold);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the body is not the documented `{"data": [...]}`
    /// envelope, plus transport and auth errors.
    pub async fn calls(&self) -> Result<Vec<CallInfo>> {
        let value = self.send(Method::Get, "/v2/calls", None).await?;
        Ok(serde_json::from_value::<CallList>(value)
            .map_err(Error::json_parse)?
            .into_entries())
    }

    /// `GET /v2/devices/{deviceId}` — one device, typed.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::DeviceKind, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let device = client.device("e0").await?;
    /// println!("{} is {}", device.id, device.alias);
    /// let _: Option<DeviceKind> = device.kind;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id, [`Error::Json`] when
    /// the body is not a device object, plus transport and auth errors.
    pub async fn device(&self, device_id: &str) -> Result<Device> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}");
        let value = self.send(Method::Get, &path, None).await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `GET /v2/contacts` — every contact visible to the credential, typed.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// for contact in client.contacts().await? {
    ///     println!("{}", contact.name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the body is not the documented `{"items": [...]}`
    /// envelope, plus transport and auth errors.
    pub async fn contacts(&self) -> Result<Vec<Contact>> {
        self.get_items("/v2/contacts").await
    }

    /// `GET /v2/contacts/{contactId}` — one contact, typed.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let contact = client.contact("b3d9af4a-78f9-11e6-8b77-86f30ca893d3").await?;
    /// println!("{}", contact.name);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable contact id, [`Error::Json`] when
    /// the body is not a contact object, plus transport and auth errors.
    pub async fn contact(&self, contact_id: &str) -> Result<Contact> {
        validate::path_segment("contact_id", contact_id)?;
        let path = format!("/v2/contacts/{contact_id}");
        let value = self.send(Method::Get, &path, None).await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `GET /v2/history` — recent calls, faxes, SMS messages and voicemails,
    /// typed.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// for entry in client.history().await? {
    ///     println!("{}", entry.id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the body is not the documented `{"items": [...]}`
    /// envelope, plus transport and auth errors.
    pub async fn history(&self) -> Result<Vec<HistoryEntry>> {
        self.get_items("/v2/history").await
    }

    /// `GET /v2/phonelines` — every phone line of the account, typed.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// for phoneline in client.phonelines().await? {
    ///     println!("{}", phoneline.alias);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the body is not the documented `{"items": [...]}`
    /// envelope, plus transport and auth errors.
    pub async fn phonelines(&self) -> Result<Vec<Phoneline>> {
        self.get_items("/v2/phonelines").await
    }

    async fn get_items<I>(&self, path: &str) -> Result<Vec<I>>
    where
        I: serde::de::DeserializeOwned + Default,
    {
        let value = self.send(Method::Get, path, None).await?;
        Ok(serde_json::from_value::<Items<I>>(value)
            .map_err(Error::json_parse)?
            .into_entries())
    }

    /// `DELETE /v2/calls/{callId}` — hang up.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.hangup("ABCDEF0123456789").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable call id, [`Error::Api`] with 404
    /// for an unknown call.
    pub async fn hangup(&self, call_id: &str) -> Result<Value> {
        validate::path_segment("call_id", call_id)?;
        let path = format!("/v2/calls/{call_id}");
        self.send(Method::Delete, &path, None).await
    }

    /// `POST /v2/calls/{callId}/dtmf` — send DTMF tones to all participants.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::Dtmf, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.send_dtmf("ABCDEF0123456789", &Dtmf::new("1234")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable call id or sequence, [`Error::Api`]
    /// with 404 for an unknown call.
    pub async fn send_dtmf(&self, call_id: &str, dtmf: &Dtmf) -> Result<Value> {
        validate::path_segment("call_id", call_id)?;
        let path = format!("/v2/calls/{call_id}/dtmf");
        self.send(Method::Post, &path, Some(&dtmf.to_json())).await
    }

    /// `POST /v2/calls/{callId}/announcements` — play a WAV file to all
    /// participants (classic PBX only; 8 kHz mono 16-bit).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::Announcement, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let announcement = Announcement::new("https://static.sipgate.com/examples/wav/example.wav")?;
    /// client.announce("ABCDEF0123456789", &announcement).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable call id or URL, [`Error::Api`]
    /// with 404 for an unknown call.
    pub async fn announce(&self, call_id: &str, announcement: &Announcement) -> Result<Value> {
        validate::path_segment("call_id", call_id)?;
        let path = format!("/v2/calls/{call_id}/announcements");
        self.send(Method::Post, &path, Some(&announcement.to_json()))
            .await
    }

    /// `PUT /v2/calls/{callId}/recording` — start or stop recording, optionally
    /// with the announcement the service plays to participants.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::Recording, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.set_recording("ABCDEF0123456789", &Recording::start()).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable call id, [`Error::Api`] with 404
    /// for an unknown call.
    pub async fn set_recording(&self, call_id: &str, recording: &Recording) -> Result<Value> {
        validate::path_segment("call_id", call_id)?;
        let path = format!("/v2/calls/{call_id}/recording");
        self.send(Method::Put, &path, Some(&recording.to_json()))
            .await
    }

    /// `PUT /v2/calls/{callId}/hold` — hold or resume every participant.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.set_hold("ABCDEF0123456789", true).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable call id, [`Error::Api`] with 404 or
    /// 409 (call not yet established).
    pub async fn set_hold(&self, call_id: &str, on_hold: bool) -> Result<Value> {
        validate::path_segment("call_id", call_id)?;
        let path = format!("/v2/calls/{call_id}/hold");
        let body = json!({ "value": on_hold });
        self.send(Method::Put, &path, Some(&body)).await
    }

    /// `PUT /v2/calls/{callId}/muted` — mute or unmute yourself (classic PBX
    /// only).
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.set_muted("ABCDEF0123456789", true).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable call id, [`Error::Api`] with 404
    /// for an unknown call.
    pub async fn set_muted(&self, call_id: &str, muted: bool) -> Result<Value> {
        validate::path_segment("call_id", call_id)?;
        let path = format!("/v2/calls/{call_id}/muted");
        let body = json!({ "value": muted });
        self.send(Method::Put, &path, Some(&body)).await
    }

    /// `POST /v2/calls/{callId}/transfer` — blind or attended transfer.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::TransferRequest, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.transfer("ABCDEF0123456789", &TransferRequest::blind("4915112345678")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable call id, [`Error::Api`] with 404 or
    /// 409 (call still being established).
    pub async fn transfer(&self, call_id: &str, transfer: &TransferRequest) -> Result<Value> {
        validate::path_segment("call_id", call_id)?;
        let path = format!("/v2/calls/{call_id}/transfer");
        self.send(Method::Post, &path, Some(&transfer.to_json()))
            .await
    }
}

/// `POST /v2/sessions/sms` body.
///
/// `sms_id` is the sending device (`s0`, `s1`, …), which the schema marks
/// required — it is not optional even though the Flow `send_sms` action needs
/// no device.
///
/// ```
/// use sipgate_flow::rest::Sms;
///
/// let sms = Sms::new("s0", "+4915112345678", "Hallo")?;
/// assert_eq!(sms.to_json(), serde_json::json!({
///     "smsId": "s0",
///     "recipient": "+4915112345678",
///     "message": "Hallo",
/// }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sms {
    sms_id: String,
    recipient: String,
    message: String,
    send_at: Option<i64>,
}

impl Sms {
    /// Builds the request. The recipient keeps its `+`: this endpoint's
    /// examples send E.164 with the plus, unlike the Flow action.
    ///
    /// ```
    /// use sipgate_flow::rest::Sms;
    ///
    /// assert!(Sms::new("s0", "4915112345678", "hi").is_ok());
    /// assert!(Sms::new("", "4915112345678", "hi").is_err());
    /// assert!(Sms::new("s0", "49 151", "hi").is_err());
    /// assert!(Sms::new("s0", "4915112345678", "").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oversized device id or message, or
    /// a recipient that is not `+`-prefixed E.164 digits.
    pub fn new(
        sms_id: impl Into<String>,
        recipient: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<Self> {
        let sms_id = sms_id.into();
        validate::non_empty("sms_id", &sms_id, validate::MAX_REST_FIELD_BYTES)?;
        let recipient = validate::phone("recipient", &recipient.into())?;
        let message = message.into();
        validate::non_empty("message", &message, validate::MAX_SMS_MESSAGE_BYTES)?;
        Ok(Self {
            sms_id,
            // The schema shows "+49…", so keep the plus the validator stripped.
            recipient: format!("+{recipient}"),
            message,
            send_at: None,
        })
    }

    /// Schedules the send at a Unix timestamp (seconds).
    ///
    /// ```
    /// use sipgate_flow::rest::Sms;
    ///
    /// let sms = Sms::new("s0", "4915112345678", "hi")?.with_send_at(1_546_850_272);
    /// assert_eq!(sms.to_json()["sendAt"], 1_546_850_272);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn with_send_at(mut self, unix_seconds: i64) -> Self {
        self.send_at = Some(unix_seconds);
        self
    }

    /// The recipient, `+`-prefixed.
    ///
    /// ```
    /// use sipgate_flow::rest::Sms;
    /// assert_eq!(Sms::new("s0", "4915112345678", "hi")?.recipient(), "+4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    /// Renders the `SendWebSmsRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::Sms;
    ///
    /// let body = Sms::new("s0", "4915112345678", "hi")?.to_json();
    /// assert_eq!(body["smsId"], "s0");
    /// assert!(body.get("sendAt").is_none());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = json!({
            "smsId": self.sms_id,
            "recipient": self.recipient,
            "message": self.message,
        });
        if let (Some(send_at), Some(object)) = (self.send_at, body.as_object_mut()) {
            object.insert("sendAt".into(), json!(send_at));
        }
        body
    }
}

/// `POST /v2/sessions/fax` body.
///
/// ```
/// use sipgate_flow::rest::Fax;
///
/// let fax = Fax::new("f0", "4915112345678", "fax.pdf", "JVBERi0xLjQK")?;
/// assert_eq!(fax.to_json()["faxlineId"], "f0");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fax {
    faxline_id: String,
    recipient: String,
    filename: String,
    base64_content: String,
}

impl Fax {
    /// Builds the request, checking the documented 28,330,000-character ceiling
    /// **before** anything else touches the content.
    ///
    /// ```
    /// use sipgate_flow::rest::Fax;
    ///
    /// assert!(Fax::new("f0", "4915112345678", "fax.pdf", "JVBERi0=").is_ok());
    /// assert!(Fax::new("f0", "4915112345678", "fax.pdf", "").is_err());
    /// assert!(Fax::new("f0", "4915112345678", "dir/fax.pdf", "JVBERi0=").is_err());
    /// assert!(Fax::new("f0", "4915112345678", "fax.pdf", "not base64!").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oversized faxline id or filename,
    /// a filename containing a path separator, empty or oversized content, or a
    /// recipient that is not E.164 digits.
    pub fn new(
        faxline_id: impl Into<String>,
        recipient: impl Into<String>,
        filename: impl Into<String>,
        base64_content: impl Into<String>,
    ) -> Result<Self> {
        let faxline_id = faxline_id.into();
        validate::non_empty("faxline_id", &faxline_id, validate::MAX_REST_FIELD_BYTES)?;
        let recipient = validate::phone("recipient", &recipient.into())?;
        let filename = filename.into();
        validate::non_empty("filename", &filename, validate::MAX_REST_FIELD_BYTES)?;
        if filename
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
        {
            return Err(Error::validation(
                "filename",
                "must be a bare file name without path separators",
            ));
        }
        let base64_content = base64_content.into();
        validate::non_empty("base64Content", &base64_content, MAX_FAX_BASE64_LEN)?;
        if !crate::base64::is_valid(&base64_content) {
            return Err(Error::validation(
                "base64Content",
                "must be standard base64 (RFC 4648)",
            ));
        }
        Ok(Self {
            faxline_id,
            recipient: format!("+{recipient}"),
            filename,
            base64_content,
        })
    }

    /// The base64 payload.
    ///
    /// ```
    /// use sipgate_flow::rest::Fax;
    /// assert_eq!(Fax::new("f0", "4915112345678", "a.pdf", "JVBERi0=")?.content(), "JVBERi0=");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn content(&self) -> &str {
        &self.base64_content
    }

    /// Renders the `SendFaxRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::Fax;
    ///
    /// let body = Fax::new("f0", "4915112345678", "fax.pdf", "JVBERi0=")?.to_json();
    /// assert_eq!(body["filename"], "fax.pdf");
    /// assert_eq!(body["recipient"], "+4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "faxlineId": self.faxline_id,
            "recipient": self.recipient,
            "filename": self.filename,
            "base64Content": self.base64_content,
        })
    }
}

/// `POST /v2/sessions/fax/resend` body.
///
/// ```
/// use sipgate_flow::rest::ResendFax;
///
/// let resend = ResendFax::new("100018428").with_faxline_id("f0");
/// assert_eq!(resend.to_json()["faxId"], "100018428");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResendFax {
    fax_id: String,
    faxline_id: Option<String>,
}

impl ResendFax {
    /// Resends the fax with this id.
    ///
    /// ```
    /// use sipgate_flow::rest::ResendFax;
    ///
    /// assert!(ResendFax::new("100018428").to_json()["faxId"] == "100018428");
    /// assert!(ResendFax::new("").to_json()["faxId"] == "");
    /// ```
    #[must_use]
    pub fn new(fax_id: impl Into<String>) -> Self {
        Self {
            fax_id: fax_id.into(),
            faxline_id: None,
        }
    }

    /// Restricts the resend to one fax line.
    ///
    /// ```
    /// use sipgate_flow::rest::ResendFax;
    /// assert_eq!(ResendFax::new("1").with_faxline_id("f0").to_json()["faxlineId"], "f0");
    /// ```
    #[must_use]
    pub fn with_faxline_id(mut self, faxline_id: impl Into<String>) -> Self {
        self.faxline_id = Some(faxline_id.into());
        self
    }

    /// Renders the `ResendFaxRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::ResendFax;
    /// assert_eq!(ResendFax::new("1").to_json(), serde_json::json!({"faxId": "1"}));
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = json!({ "faxId": self.fax_id });
        if let (Some(faxline_id), Some(object)) = (&self.faxline_id, body.as_object_mut()) {
            object.insert("faxlineId".into(), json!(faxline_id));
        }
        body
    }
}

/// `POST /v2/sessions/calls` body (`NewCallRequest`).
///
/// `caller` is a device id (`e0`) or a number; when it is a number the schema
/// requires `deviceId` as well.
///
/// ```
/// use sipgate_flow::rest::Call;
///
/// let call = Call::new("e0", "+4915112345678")?;
/// assert_eq!(call.to_json()["callee"], "+4915112345678");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    caller: String,
    callee: String,
    caller_id: Option<String>,
    device_id: Option<String>,
}

impl Call {
    /// Builds the request.
    ///
    /// ```
    /// use sipgate_flow::rest::Call;
    ///
    /// assert!(Call::new("e0", "4915112345678").is_ok());
    /// assert!(Call::new("", "4915112345678").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oversized caller, or a callee that
    /// is not E.164 digits.
    #[allow(clippy::similar_names)] // `caller`/`callee` are the schema's names
    pub fn new(caller: impl Into<String>, callee: impl Into<String>) -> Result<Self> {
        let caller = caller.into();
        validate::non_empty("caller", &caller, validate::MAX_REST_FIELD_BYTES)?;
        let callee = validate::phone("callee", &callee.into())?;
        Ok(Self {
            caller,
            callee: format!("+{callee}"),
            caller_id: None,
            device_id: None,
        })
    }

    /// Sets the number displayed to the callee.
    ///
    /// ```
    /// use sipgate_flow::rest::Call;
    /// let call = Call::new("e0", "4915112345678")?.with_caller_id("4921112345678")?;
    /// assert_eq!(call.to_json()["callerId"], "+4921112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a number that is not E.164 digits.
    pub fn with_caller_id(mut self, number: impl Into<String>) -> Result<Self> {
        self.caller_id = Some(format!("+{}", validate::phone("callerId", &number.into())?));
        Ok(self)
    }

    /// Sets the device the call is placed from, required when `caller` is a
    /// number rather than a device id.
    ///
    /// ```
    /// use sipgate_flow::rest::Call;
    /// let call = Call::new("4915112345678", "4921112345678")?.with_device_id("e0");
    /// assert_eq!(call.to_json()["deviceId"], "e0");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn with_device_id(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    /// Renders the `NewCallRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::Call;
    /// assert_eq!(
    ///     Call::new("e0", "4915112345678")?.to_json(),
    ///     serde_json::json!({"caller": "e0", "callee": "+4915112345678"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        body.insert("caller".into(), json!(self.caller));
        body.insert("callee".into(), json!(self.callee));
        if let Some(caller_id) = &self.caller_id {
            body.insert("callerId".into(), json!(caller_id));
        }
        if let Some(device_id) = &self.device_id {
            body.insert("deviceId".into(), json!(device_id));
        }
        Value::Object(body)
    }
}

/// `POST /v2/calls` body, for Neo PBX channel calls (`CreateCallResponse` →
/// `callSid`).
///
/// ```
/// use sipgate_flow::rest::ChannelCall;
///
/// let call = ChannelCall::new("e0", "+4915112345678").with_caller_id("4921112345678");
/// assert_eq!(call.to_json()["targetNumber"], "+4915112345678");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelCall {
    device_id: String,
    target_number: String,
    caller_id: Option<String>,
    channel_id: Option<String>,
}

impl ChannelCall {
    /// Builds the request. `device_id` and `target_number` are the schema's two
    /// required fields.
    ///
    /// ```
    /// use sipgate_flow::rest::ChannelCall;
    /// assert!(ChannelCall::new("e0", "667").to_json()["targetNumber"] == "667");
    /// ```
    #[must_use]
    pub fn new(device_id: impl Into<String>, target_number: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            target_number: target_number.into(),
            caller_id: None,
            channel_id: None,
        }
    }

    /// Sets the displayed caller id.
    ///
    /// ```
    /// use sipgate_flow::rest::ChannelCall;
    /// assert_eq!(
    ///     ChannelCall::new("e0", "667").with_caller_id("49211").to_json()["callerId"],
    ///     "49211"
    /// );
    /// ```
    #[must_use]
    pub fn with_caller_id(mut self, caller_id: impl Into<String>) -> Self {
        self.caller_id = Some(caller_id.into());
        self
    }

    /// Sets the channel to start from; the device default applies otherwise.
    ///
    /// ```
    /// use sipgate_flow::rest::ChannelCall;
    /// assert_eq!(
    ///     ChannelCall::new("e0", "667").with_channel_id("c0").to_json()["channelId"],
    ///     "c0"
    /// );
    /// ```
    #[must_use]
    pub fn with_channel_id(mut self, channel_id: impl Into<String>) -> Self {
        self.channel_id = Some(channel_id.into());
        self
    }

    /// Renders the request body. `targetNumber` may also be an internal
    /// extension, which is why it is not phone-validated here.
    ///
    /// ```
    /// use sipgate_flow::rest::ChannelCall;
    /// assert_eq!(
    ///     ChannelCall::new("e0", "667").to_json(),
    ///     serde_json::json!({"deviceId": "e0", "targetNumber": "667"})
    /// );
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        body.insert("deviceId".into(), json!(self.device_id));
        body.insert("targetNumber".into(), json!(self.target_number));
        if let Some(caller_id) = &self.caller_id {
            body.insert("callerId".into(), json!(caller_id));
        }
        if let Some(channel_id) = &self.channel_id {
            body.insert("channelId".into(), json!(channel_id));
        }
        Value::Object(body)
    }
}

/// `POST /v2/calls/{callId}/dtmf` body (`DtmfRequest`).
///
/// ```
/// use sipgate_flow::rest::Dtmf;
///
/// assert_eq!(Dtmf::new("1234")?.to_json(), serde_json::json!({"sequence": "1234"}));
/// assert!(Dtmf::new("").is_err());
/// assert!(Dtmf::new("12x4").is_err());
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dtmf {
    sequence: String,
}

impl Dtmf {
    /// Builds the sequence. The DTMF alphabet is `0-9`, `*`, `#` and the
    /// A–D tones.
    ///
    /// ```
    /// use sipgate_flow::rest::Dtmf;
    /// assert!(Dtmf::new("1*2#A").is_ok());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oversized sequence, or a character
    /// outside the DTMF alphabet.
    pub fn new(sequence: impl Into<String>) -> Result<Self> {
        let sequence = sequence.into();
        validate::non_empty("sequence", &sequence, validate::MAX_REST_FIELD_BYTES)?;
        if !sequence
            .bytes()
            .all(|byte| byte.is_ascii_digit() || b"*#ABCD".contains(&byte))
        {
            return Err(Error::validation(
                "sequence",
                "must contain only 0-9, *, # and A-D",
            ));
        }
        Ok(Self { sequence })
    }

    /// The sequence.
    ///
    /// ```
    /// use sipgate_flow::rest::Dtmf;
    /// assert_eq!(Dtmf::new("1234")?.sequence(), "1234");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn sequence(&self) -> &str {
        &self.sequence
    }

    /// Renders the `DtmfRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::Dtmf;
    /// assert_eq!(Dtmf::new("12")?.to_json()["sequence"], "12");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "sequence": self.sequence })
    }
}

/// `POST /v2/calls/{callId}/announcements` body (`AnnouncementRequest`).
///
/// The file behind the URL must be mono 16-bit PCM WAV at 8 kHz — the schema
/// says so explicitly, and the endpoint is unavailable on Neo PBX accounts.
///
/// ```
/// use sipgate_flow::rest::Announcement;
///
/// assert!(Announcement::new("https://example.com/a.wav").is_ok());
/// assert!(Announcement::new("example.com/a.wav").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    url: String,
}

impl Announcement {
    /// Builds the request from an absolute `http(s)` URL.
    ///
    /// ```
    /// use sipgate_flow::rest::Announcement;
    /// assert_eq!(
    ///     Announcement::new("https://example.com/a.wav")?.to_json()["url"],
    ///     "https://example.com/a.wav"
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a relative URL, a non-http scheme, or an empty
    /// value.
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        validate::http_url("url", &url)?;
        Ok(Self { url })
    }

    /// Renders the `AnnouncementRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::Announcement;
    /// assert_eq!(
    ///     Announcement::new("https://x.test/a.wav")?.to_json(),
    ///     serde_json::json!({"url": "https://x.test/a.wav"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "url": self.url })
    }
}

/// `PUT /v2/calls/{callId}/recording` body (`RecordingRequest`).
///
/// `announcement` tells the service whether to play the "recording started"
/// notice. When it is `false` the schema puts the legal duty to inform
/// participants on the caller, so the default here is `true`.
///
/// ```
/// use sipgate_flow::rest::Recording;
///
/// assert_eq!(Recording::start().to_json(), serde_json::json!({"value": true}));
/// assert_eq!(Recording::stop().to_json()["value"], false);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recording {
    value: bool,
    announcement: Option<bool>,
}

impl Recording {
    /// Starts a recording.
    ///
    /// ```
    /// use sipgate_flow::rest::Recording;
    /// assert!(Recording::start().is_starting());
    /// ```
    #[must_use]
    pub fn start() -> Self {
        Self {
            value: true,
            announcement: None,
        }
    }

    /// Stops the recording.
    ///
    /// ```
    /// use sipgate_flow::rest::Recording;
    /// assert!(!Recording::stop().is_starting());
    /// ```
    #[must_use]
    pub fn stop() -> Self {
        Self {
            value: false,
            announcement: None,
        }
    }

    /// Overrides the announcement flag (the schema default is `true`).
    ///
    /// ```
    /// use sipgate_flow::rest::Recording;
    /// assert_eq!(
    ///     Recording::start().with_announcement(false).to_json()["announcement"],
    ///     false
    /// );
    /// ```
    #[must_use]
    pub fn with_announcement(mut self, announce: bool) -> Self {
        self.announcement = Some(announce);
        self
    }

    /// Whether this request starts (rather than stops) a recording.
    ///
    /// ```
    /// use sipgate_flow::rest::Recording;
    /// assert!(Recording::start().is_starting());
    /// ```
    #[must_use]
    pub fn is_starting(&self) -> bool {
        self.value
    }

    /// Renders the `RecordingRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::Recording;
    /// assert_eq!(
    ///     Recording::start().with_announcement(true).to_json(),
    ///     serde_json::json!({"value": true, "announcement": true})
    /// );
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = json!({ "value": self.value });
        if let (Some(announcement), Some(object)) = (self.announcement, body.as_object_mut()) {
            object.insert("announcement".into(), json!(announcement));
        }
        body
    }
}

/// `POST /v2/calls/{callId}/transfer` body (`TransferRequest`).
///
/// ```
/// use sipgate_flow::rest::TransferRequest;
///
/// let blind = TransferRequest::blind("4915112345678")?;
/// assert_eq!(blind.to_json()["attended"], false);
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequest {
    phone_number: String,
    attended: bool,
    caller_id: Option<String>,
}

impl TransferRequest {
    /// A blind transfer: the target is dialled and the caller is released.
    ///
    /// ```
    /// use sipgate_flow::rest::TransferRequest;
    /// assert_eq!(TransferRequest::blind("4915112345678")?.to_json()["phoneNumber"], "+4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a number that is not E.164 digits.
    pub fn blind(phone_number: impl Into<String>) -> Result<Self> {
        Self::new(phone_number, false)
    }

    /// An attended transfer: the caller is put on hold while the target is
    /// consulted.
    ///
    /// ```
    /// use sipgate_flow::rest::TransferRequest;
    /// assert_eq!(TransferRequest::attended("4915112345678")?.to_json()["attended"], true);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a number that is not E.164 digits.
    pub fn attended(phone_number: impl Into<String>) -> Result<Self> {
        Self::new(phone_number, true)
    }

    fn new(phone_number: impl Into<String>, attended: bool) -> Result<Self> {
        let phone_number = validate::phone("phoneNumber", &phone_number.into())?;
        Ok(Self {
            phone_number: format!("+{phone_number}"),
            attended,
            caller_id: None,
        })
    }

    /// Sets the caller id shown to the transfer target.
    ///
    /// ```
    /// use sipgate_flow::rest::TransferRequest;
    ///
    /// let request = TransferRequest::blind("4915112345678")?.with_caller_id("4921112345678")?;
    /// assert_eq!(request.to_json()["callerId"], "+4921112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a number that is not E.164 digits.
    pub fn with_caller_id(mut self, number: impl Into<String>) -> Result<Self> {
        self.caller_id = Some(format!("+{}", validate::phone("callerId", &number.into())?));
        Ok(self)
    }

    /// Renders the `TransferRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::TransferRequest;
    ///
    /// assert_eq!(
    ///     TransferRequest::blind("4915112345678")?.to_json(),
    ///     serde_json::json!({"phoneNumber": "+4915112345678", "attended": false})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = json!({
            "phoneNumber": self.phone_number,
            "attended": self.attended,
        });
        if let (Some(caller_id), Some(object)) = (&self.caller_id, body.as_object_mut()) {
            object.insert("callerId".into(), json!(caller_id));
        }
        body
    }
}

/// `POST /v2/sessions/voicemail/play` body (`PlayRecordingRequest`).
///
/// The schema spells the voicemail id `datadId` — a typo in the published
/// document, preserved here because that is the key the service receives.
///
/// ```
/// use sipgate_flow::rest::PlayVoicemail;
///
/// let request = PlayVoicemail::new("1000171", "e0");
/// assert_eq!(request.to_json()["datadId"], "1000171");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayVoicemail {
    datad_id: String,
    device_id: String,
}

impl PlayVoicemail {
    /// Builds the request from the voicemail (`datadId`) and the device that
    /// should hear it.
    ///
    /// ```
    /// use sipgate_flow::rest::PlayVoicemail;
    /// assert_eq!(PlayVoicemail::new("1000171", "e0").to_json()["deviceId"], "e0");
    /// ```
    #[must_use]
    pub fn new(datad_id: impl Into<String>, device_id: impl Into<String>) -> Self {
        Self {
            datad_id: datad_id.into(),
            device_id: device_id.into(),
        }
    }

    /// Renders the `PlayRecordingRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::PlayVoicemail;
    /// assert_eq!(
    ///     PlayVoicemail::new("1000171", "e0").to_json(),
    ///     serde_json::json!({"datadId": "1000171", "deviceId": "e0"})
    /// );
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "datadId": self.datad_id, "deviceId": self.device_id })
    }
}

/// Body for `POST /v2/sessions/ivr/recording` and
/// `POST /v2/sessions/voicemail/recording`: every field is optional in the
/// schema.
///
/// ```
/// use sipgate_flow::rest::RecordingSession;
///
/// let request = RecordingSession::new().with_device_id("e0").with_target_id("v0");
/// assert_eq!(request.to_json()["targetId"], "v0");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordingSession {
    device_id: Option<String>,
    endpoint: Option<String>,
    target_id: Option<String>,
}

impl RecordingSession {
    /// An empty request; the service falls back to its defaults.
    ///
    /// ```
    /// use sipgate_flow::rest::RecordingSession;
    /// assert_eq!(RecordingSession::new().to_json(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the device that records.
    ///
    /// ```
    /// use sipgate_flow::rest::RecordingSession;
    /// assert_eq!(RecordingSession::new().with_device_id("e0").to_json()["deviceId"], "e0");
    /// ```
    #[must_use]
    pub fn with_device_id(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    /// Sets the endpoint list, for example `"MAIN, a0,a1,a2"`.
    ///
    /// ```
    /// use sipgate_flow::rest::RecordingSession;
    /// assert_eq!(
    ///     RecordingSession::new().with_endpoint("MAIN").to_json()["endpoint"],
    ///     "MAIN"
    /// );
    /// ```
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Sets the voicemail or IVR target id (`v0`).
    ///
    /// ```
    /// use sipgate_flow::rest::RecordingSession;
    /// assert_eq!(RecordingSession::new().with_target_id("v0").to_json()["targetId"], "v0");
    /// ```
    #[must_use]
    pub fn with_target_id(mut self, target_id: impl Into<String>) -> Self {
        self.target_id = Some(target_id.into());
        self
    }

    /// Renders the body, omitting unset fields.
    ///
    /// ```
    /// use sipgate_flow::rest::RecordingSession;
    /// assert_eq!(
    ///     RecordingSession::new().with_device_id("e0").to_json(),
    ///     serde_json::json!({"deviceId": "e0"})
    /// );
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        if let Some(device_id) = &self.device_id {
            body.insert("deviceId".into(), json!(device_id));
        }
        if let Some(endpoint) = &self.endpoint {
            body.insert("endpoint".into(), json!(endpoint));
        }
        if let Some(target_id) = &self.target_id {
            body.insert("targetId".into(), json!(target_id));
        }
        Value::Object(body)
    }
}

#[derive(Deserialize)]
struct CallList {
    // `null` and an absent key both mean "no calls"; only a wrong *type*
    // (`"data": 3`) is an error, and then the caller hears about it once.
    #[serde(default)]
    data: Option<Vec<CallInfo>>,
}

#[derive(Deserialize)]
struct Items<T> {
    // `null` and an absent key both mean "no items"; only a wrong *type* is an
    // error, matching the REST v2 list envelope's permissive direction.
    #[serde(default)]
    items: Option<Vec<T>>,
}

impl<T> Items<T> {
    fn into_entries(self) -> Vec<T> {
        self.items.unwrap_or_default()
    }
}

impl CallList {
    fn into_entries(self) -> Vec<CallInfo> {
        self.data.unwrap_or_default()
    }
}

/// Decodes a `GET /v2/calls` response body — the `{"data": [...]}` envelope —
/// without a client, so a proxy, a fixture test or a fuzz target can use the
/// same decoder the client does.
///
/// Permissive in the documented direction: unknown fields on the envelope and
/// on each entry are ignored, an absent or `null` `data` yields an empty list,
/// and every `Call` field defaults when missing.
///
/// ```
/// use sipgate_flow::rest::parse_calls;
///
/// let calls = parse_calls(br#"{"data":[{"callId":"c1","participants":[]}],"paging":{}}"#)?;
/// assert_eq!(calls.len(), 1);
/// assert_eq!(calls[0].call_id, "c1");
///
/// assert!(parse_calls(br#"{}"#)?.is_empty());
/// assert!(parse_calls(br#"{"data":null}"#)?.is_empty());
/// assert!(parse_calls(b"not json").is_err());
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Json`] when the body is not JSON or `data` is not an array.
pub fn parse_calls(body: &[u8]) -> Result<Vec<CallInfo>> {
    Ok(serde_json::from_slice::<CallList>(body)
        .map_err(Error::json_parse)?
        .into_entries())
}

/// One entry of `GET /v2/calls` (`Call` in the schema).
///
/// ```
/// use sipgate_flow::rest::CallInfo;
///
/// let call: CallInfo = serde_json::from_value(serde_json::json!({
///     "callId": "ABCDEF0123456789",
///     "hold": false,
///     "muted": false,
///     "recording": true,
///     "participants": [],
///     "future_field": 1
/// }))
/// .unwrap();
/// assert_eq!(call.call_id, "ABCDEF0123456789");
/// assert!(call.recording);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CallInfo {
    /// Unique call identifier, the `callId` path parameter.
    #[serde(default)]
    pub call_id: String,
    /// Whether the call is on hold (always `false` on Neo PBX).
    #[serde(default)]
    pub hold: bool,
    /// Whether the call is muted (always `false` on Neo PBX).
    #[serde(default)]
    pub muted: bool,
    /// Whether the call is being recorded.
    #[serde(default)]
    pub recording: bool,
    /// Participants; empty on Neo PBX, which reports none.
    #[serde(default)]
    pub participants: Vec<Participant>,
}

/// One participant of a call (`Participant` in the schema).
///
/// ```
/// use sipgate_flow::rest::Participant;
///
/// let participant: Participant = serde_json::from_value(serde_json::json!({
///     "participantId": "p1",
///     "phoneNumber": "<unknown>",
///     "hold": false,
///     "muted": false,
///     "owner": true
/// }))
/// .unwrap();
/// assert!(participant.owner);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Participant {
    /// Unique participant identifier.
    #[serde(default)]
    pub participant_id: String,
    /// Phone number, or the literal `<unknown>` when sipgate cannot see it.
    #[serde(default)]
    pub phone_number: String,
    /// Whether this participant is on hold.
    #[serde(default)]
    pub hold: bool,
    /// Whether this participant is muted.
    #[serde(default)]
    pub muted: bool,
    /// Whether this participant owns the call.
    #[serde(default)]
    pub owner: bool,
}

macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(#[$first_meta:meta])*
            $first:ident => $first_wire:literal,
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $wire:literal,
            )*
        }
    ) => {
        $(#[$meta])*
        #[doc = concat!(
            "\n```\n",
            "use sipgate_flow::rest::", stringify!($name), ";\n",
            "assert_eq!(", stringify!($name), "::from_wire(", stringify!($first_wire), "), ", stringify!($name), "::", stringify!($first), ");\n",
            "```"
        )]
        #[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
        #[serde(from = "String")]
        #[non_exhaustive]
        $vis enum $name {
            $(#[$first_meta])*
            $first,
            $(
                $(#[$variant_meta])*
                $variant,
            )*
            #[doc = "A value this crate does not model yet, kept verbatim."]
            Other(String),
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                let folded = fold_wire(&value);
                if folded == fold_wire($first_wire) {
                    return Self::$first;
                }
                $(
                    if folded == fold_wire($wire) {
                        return Self::$variant;
                    }
                )*
                Self::Other(value)
            }
        }

        impl $name {
            /// Maps the wire value, keeping unknown values verbatim.
            #[doc = concat!(
                "\n```\n",
                "use sipgate_flow::rest::", stringify!($name), ";\n",
                "assert_eq!(", stringify!($name), "::from_wire(", stringify!($first_wire), "), ", stringify!($name), "::", stringify!($first), ");\n",
                "```"
            )]
            #[must_use]
            pub fn from_wire(value: &str) -> Self {
                Self::from(value.to_string())
            }

            /// The canonical wire value.
            #[doc = concat!(
                "\n```\n",
                "use sipgate_flow::rest::", stringify!($name), ";\n",
                "assert_eq!(", stringify!($name), "::", stringify!($first), ".as_str(), ", stringify!($first_wire), ");\n",
                "```"
            )]
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    Self::$first => $first_wire,
                    $(Self::$variant => $wire,)*
                    Self::Other(value) => value,
                }
            }
        }
    };
}

wire_enum! {
    /// Device kind, from the `type` field of `GET /v2/devices/{deviceId}`.
    pub enum DeviceKind {
        /// A registered SIP device.
        Register => "register",
        /// A mobile phone device.
        Mobile => "mobile",
        /// An external number or endpoint.
        External => "external",
    }
}

wire_enum! {
    /// Contact scope, from the `scope` field.
    pub enum ContactScope {
        /// Visible only to the owning user.
        Private => "private",
        /// Shared with other account users.
        Shared => "shared",
        /// Internal sipgate content.
        Internal => "internal",
    }
}

wire_enum! {
    /// Address verification state, from `emergencyState`.
    pub enum AddressEmergencyState {
        /// No emergency address is configured.
        None => "none",
        /// Emergency-address validation failed.
        Failed => "failed",
        /// Emergency-address validation is pending.
        Pending => "pending",
        /// Emergency address is active.
        Activated => "activated",
        /// The address is being submitted.
        Submit => "submit",
        /// The address is being deleted.
        SubmitDelete => "submit_delete",
        /// Deletion is pending.
        PendingDelete => "pending_delete",
        /// Submission without validation.
        SubmitNoValidate => "submitnovalidate",
    }
}

wire_enum! {
    /// Address type, from `type`.
    pub enum AddressKind {
        /// A verified address.
        Verified => "verified",
        /// A pending address.
        Pending => "pending",
        /// A failed address.
        Failed => "failed",
        /// A blocked address.
        Blocked => "blocked",
        /// No address type is set.
        None => "none",
    }
}

wire_enum! {
    /// Contact number kind, from `type`.
    pub enum ContactNumberKind {
        /// A mobile number.
        Mobile => "mobile",
        /// A landline number.
        Landline => "landline",
        /// A quick-dial number.
        Quickdial => "quickdial",
        /// An international number.
        International => "international",
    }
}

wire_enum! {
    /// History entry kind, from `type`.
    pub enum HistoryEntryKind {
        /// A call.
        Call => "call",
        /// A voicemail.
        Voicemail => "voicemail",
        /// An SMS message.
        Sms => "sms",
        /// A fax.
        Fax => "fax",
    }
}

wire_enum! {
    /// History direction, from `direction`.
    pub enum HistoryDirection {
        /// An incoming event.
        Incoming => "incoming",
        /// An outgoing event.
        Outgoing => "outgoing",
        /// A missed incoming event.
        MissedIncoming => "missedincoming",
        /// A missed outgoing event.
        MissedOutgoing => "missedoutgoing",
    }
}

wire_enum! {
    /// History status, from `status`.
    pub enum HistoryStatus {
        /// The callee did not pick up.
        Nopickup => "nopickup",
        /// The line was busy.
        Busy => "busy",
        /// The call was picked up.
        Pickup => "pickup",
        /// The call was forwarded.
        Forward => "forward",
    }
}

wire_enum! {
    /// Endpoint kind, from `endpoint.type`.
    pub enum EndpointKind {
        /// A channel endpoint.
        Channel => "channel",
        /// A number endpoint.
        Number => "number",
        /// An SMS endpoint.
        Sms => "sms",
        /// A registered device.
        Register => "register",
        /// An external endpoint.
        External => "external",
        /// A fax endpoint.
        Fax => "fax",
        /// A mobile endpoint.
        Mobile => "mobile",
        /// A group endpoint.
        Group => "group",
        /// A voicemail endpoint.
        Voicemail => "voicemail",
        /// A phoneline endpoint.
        Phoneline => "phoneline",
        /// A user endpoint.
        User => "user",
    }
}

wire_enum! {
    /// Routed endpoint kind, from `endpoints[].type`.
    pub enum RoutedEndpointKind {
        /// The event moved to a forwarded endpoint.
        Forwarded => "forwarded",
        /// The event was routed.
        Routed => "routed",
        /// The event was picked up.
        Pickup => "pickup",
    }
}

fn fold_wire(value: &str) -> String {
    value
        .chars()
        .filter(|character| !matches!(character, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

/// One device from `GET /v2/devices/{deviceId}`.
///
/// ```
/// use sipgate_flow::rest::{Device, DeviceKind};
///
/// let device: Device = serde_json::from_value(serde_json::json!({
///     "id": "e0",
///     "alias": "Desk phone",
///     "type": "REGISTER",
///     "online": true,
///     "dnd": false,
///     "futureField": 1
/// }))
/// .unwrap();
/// assert_eq!(device.id, "e0");
/// assert_eq!(device.kind, Some(DeviceKind::Register));
/// assert!(device.online);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Device {
    /// Unique device identifier, the `deviceId` path parameter.
    #[serde(default)]
    pub id: String,
    /// Human-readable device name.
    #[serde(default)]
    pub alias: String,
    /// Device kind. A future value is carried as [`DeviceKind::Other`].
    #[serde(default, rename = "type")]
    pub kind: Option<DeviceKind>,
    /// Whether do-not-disturb is active.
    #[serde(default)]
    pub dnd: bool,
    /// Whether the device is currently online.
    #[serde(default)]
    pub online: bool,
    /// Active routing groups, when the device is registered.
    #[serde(default, alias = "active_groups")]
    pub active_groups: Vec<ActiveRouting>,
    /// Active phone lines, when the device is registered.
    #[serde(default, alias = "active_phonelines")]
    pub active_phonelines: Vec<ActiveRouting>,
}

/// One active routing target on a device.
///
/// ```
/// use sipgate_flow::rest::ActiveRouting;
///
/// let routing: ActiveRouting = serde_json::from_value(serde_json::json!({
///     "id": "w0",
///     "alias": "Ada Lovelace"
/// }))
/// .unwrap();
/// assert_eq!(routing.id, "w0");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ActiveRouting {
    /// Identifier of the routed user, group or endpoint.
    #[serde(default)]
    pub id: String,
    /// Human-readable routing target name.
    #[serde(default)]
    pub alias: String,
}

/// One contact from `GET /v2/contacts` or `GET /v2/contacts/{contactId}`.
///
/// ```
/// use sipgate_flow::rest::Contact;
///
/// let contact: Contact = serde_json::from_value(serde_json::json!({
///     "id": "b3d9af4a-78f9-11e6-8b77-86f30ca893d3",
///     "name": "Ada Lovelace",
///     "givenname": "Ada",
///     "familyname": "Lovelace",
///     "scope": "PRIVATE",
///     "numbers": [],
///     "future_field": true
/// }))
/// .unwrap();
/// assert_eq!(contact.name, "Ada Lovelace");
/// assert_eq!(contact.familyname, "Lovelace");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Contact {
    /// Unique contact identifier.
    #[serde(default)]
    pub id: String,
    /// Display name.
    #[serde(default)]
    pub name: String,
    /// Given name.
    #[serde(default)]
    pub givenname: String,
    /// Family name.
    #[serde(default)]
    pub familyname: String,
    /// Note text.
    #[serde(default)]
    pub note: String,
    /// Base64-encoded contact picture, when one exists.
    #[serde(default)]
    pub picture: String,
    /// Contact scope. A future value is carried as [`ContactScope::Other`].
    #[serde(default)]
    pub scope: Option<ContactScope>,
    /// Postal addresses.
    #[serde(default)]
    pub addresses: Vec<ContactAddress>,
    /// Email addresses.
    #[serde(default)]
    pub emails: Vec<ContactEmail>,
    /// Phone numbers.
    #[serde(default)]
    pub numbers: Vec<ContactNumber>,
    /// Websites.
    #[serde(default)]
    pub websites: Vec<ContactWebsite>,
    /// Structured organization data.
    #[serde(default)]
    pub organization: Vec<Vec<String>>,
}

/// One postal address on a contact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ContactAddress {
    /// Address identifier.
    #[serde(default, alias = "address_id")]
    pub address_id: String,
    /// First address line.
    #[serde(default)]
    pub address1: String,
    /// Second address line.
    #[serde(default)]
    pub address2: String,
    /// City or locality.
    #[serde(default)]
    pub city: String,
    /// Postal code.
    #[serde(default)]
    pub postcode: String,
    /// Street.
    #[serde(default)]
    pub street: String,
    /// State or region.
    #[serde(default)]
    pub state: String,
    /// ISO country code.
    #[serde(default)]
    pub countrycode: String,
    /// House number.
    #[serde(default)]
    pub number: String,
    /// URL for the address' numbers, when sipgate reports one.
    #[serde(default, alias = "numbers_url")]
    pub numbers_url: String,
    /// Address kind. A future value is carried as [`AddressKind::Other`].
    #[serde(default, rename = "type")]
    pub kind: Option<AddressKind>,
    /// Emergency-address state.
    #[serde(default, alias = "emergency_state")]
    pub emergency_state: Option<AddressEmergencyState>,
}

/// One email address on a contact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ContactEmail {
    /// Email address.
    #[serde(default)]
    pub email: String,
    /// Email labels.
    #[serde(default, rename = "type")]
    pub kind: Vec<String>,
}

/// One phone number on a contact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ContactNumber {
    /// Number identifier.
    #[serde(default)]
    pub id: String,
    /// E.164 number.
    #[serde(default)]
    pub number: String,
    /// Locally formatted number.
    #[serde(default)]
    pub localized: String,
    /// Number kind. A future value is carried as [`ContactNumberKind::Other`].
    #[serde(default, rename = "type")]
    pub kind: Option<ContactNumberKind>,
}

/// One website on a contact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ContactWebsite {
    /// Website URL.
    #[serde(default)]
    pub url: String,
    /// Website labels.
    #[serde(default, rename = "type")]
    pub kind: Vec<String>,
}

/// One history entry from `GET /v2/history`.
///
/// ```
/// use sipgate_flow::rest::{HistoryDirection, HistoryEntry, HistoryEntryKind};
///
/// let entry: HistoryEntry = serde_json::from_value(serde_json::json!({
///     "id": "100001234",
///     "type": "CALL",
///     "direction": "INCOMING",
///     "created": "2016-02-10T14:19:39Z",
///     "futureField": 1
/// }))
/// .unwrap();
/// assert_eq!(entry.id, "100001234");
/// assert_eq!(entry.kind, Some(HistoryEntryKind::Call));
/// assert_eq!(entry.direction, Some(HistoryDirection::Incoming));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct HistoryEntry {
    /// Unique history entry identifier.
    #[serde(default)]
    pub id: String,
    /// Entry kind. A future value is carried as [`HistoryEntryKind::Other`].
    #[serde(default, rename = "type")]
    pub kind: Option<HistoryEntryKind>,
    /// Direction. A future value is carried as [`HistoryDirection::Other`].
    #[serde(default)]
    pub direction: Option<HistoryDirection>,
    /// Event status. A future value is carried as [`HistoryStatus::Other`].
    #[serde(default)]
    pub status: Option<HistoryStatus>,
    /// Creation timestamp, as the ISO-8601 string sipgate sends.
    #[serde(default)]
    pub created: String,
    /// Last-modification timestamp, as sipgate sends it.
    #[serde(default, alias = "last_modified")]
    pub last_modified: String,
    /// Source number.
    #[serde(default)]
    pub source: String,
    /// Source alias.
    #[serde(default, alias = "source_alias")]
    pub source_alias: String,
    /// Target number.
    #[serde(default)]
    pub target: String,
    /// Target alias.
    #[serde(default, alias = "target_alias")]
    pub target_alias: String,
    /// User note on the entry.
    #[serde(default)]
    pub note: String,
    /// Whether the entry is archived.
    #[serde(default)]
    pub archived: bool,
    /// Whether the entry was incoming.
    #[serde(default)]
    pub incoming: bool,
    /// Whether the entry is starred.
    #[serde(default)]
    pub starred: bool,
    /// Whether the entry is read.
    #[serde(default)]
    pub read: bool,
    /// Labels applied to the entry.
    #[serde(default)]
    pub labels: Vec<String>,
    /// Connection identifiers attached to the entry.
    #[serde(default, alias = "connection_ids")]
    pub connection_ids: Vec<String>,
    /// Ordered endpoints the event moved through.
    #[serde(default)]
    pub endpoints: Vec<RoutedEndpoint>,
}

/// One endpoint on a history entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RoutedEndpoint {
    /// Routing kind. A future value is carried as [`RoutedEndpointKind::Other`].
    #[serde(default, rename = "type")]
    pub kind: Option<RoutedEndpointKind>,
    /// Endpoint details.
    #[serde(default)]
    pub endpoint: Option<Endpoint>,
}

/// The endpoint a history entry reached.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Endpoint {
    /// Endpoint extension.
    #[serde(default)]
    pub extension: String,
    /// Endpoint kind. A future value is carried as [`EndpointKind::Other`].
    #[serde(default, rename = "type")]
    pub kind: Option<EndpointKind>,
}

/// One phone line from `GET /v2/phonelines`.
///
/// ```
/// use sipgate_flow::rest::Phoneline;
///
/// let phoneline: Phoneline = serde_json::from_value(serde_json::json!({
///     "id": "p0",
///     "alias": "Front desk",
///     "userId": "w0",
///     "futureField": true
/// }))
/// .unwrap();
/// assert_eq!(phoneline.id, "p0");
/// assert_eq!(phoneline.user_id, "w0");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Phoneline {
    /// Unique phoneline identifier.
    #[serde(default)]
    pub id: String,
    /// Human-readable phoneline name.
    #[serde(default)]
    pub alias: String,
    /// Owning user id.
    #[serde(default, alias = "user_id")]
    pub user_id: String,
    /// Voicemail settings, when the account returns them.
    #[serde(default)]
    pub voicemails: Vec<VoicemailSettings>,
}

/// One voicemail configuration on a phoneline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct VoicemailSettings {
    /// Voicemail identifier.
    #[serde(default)]
    pub id: String,
    /// Whether the voicemail is active.
    #[serde(default)]
    pub active: bool,
    /// Ring timeout before voicemail starts.
    #[serde(default)]
    pub timeout: u32,
}
