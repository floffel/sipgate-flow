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

// --- REST v2 history resource (#166) --------------------------------------
//
// This block is intentionally self-contained so sibling REST resource work
// (#164 devices, #165 contacts, #167 phonelines) can be rebased independently.

/// Largest documented `offset` accepted by `GET /v2/history`.
///
/// ```
/// use sipgate_flow::rest::MAX_HISTORY_OFFSET;
///
/// assert_eq!(MAX_HISTORY_OFFSET, 2_147_483_647);
/// ```
pub const MAX_HISTORY_OFFSET: u32 = 2_147_483_647;

/// Largest documented `limit` accepted by `GET /v2/history`.
///
/// ```
/// use sipgate_flow::rest::MAX_HISTORY_LIMIT;
///
/// assert_eq!(MAX_HISTORY_LIMIT, 1000);
/// ```
pub const MAX_HISTORY_LIMIT: u32 = 1000;

/// Largest list accepted by `PUT /v2/history`.
///
/// The upstream operation documents that the list must be less than 150, so
/// this is the largest accepted element count.
///
/// ```
/// use sipgate_flow::rest::MAX_HISTORY_UPDATE_ENTRIES;
///
/// assert_eq!(MAX_HISTORY_UPDATE_ENTRIES, 149);
/// ```
pub const MAX_HISTORY_UPDATE_ENTRIES: usize = 149;

wire_enum! {
    /// History starred filter, from the `starred` query parameter.
    pub enum HistoryStarred {
        /// Only starred entries.
        Starred => "starred",
        /// Only unstarred entries.
        Unstarred => "unstarred",
    }
}

/// Query filters for `GET /v2/history` and `GET /v2/history/export`.
///
/// ```
/// use sipgate_flow::rest::{HistoryEntryKind, HistoryQuery};
///
/// let mut query = HistoryQuery::new();
/// query.types.push(HistoryEntryKind::Call);
/// query.limit = Some(10);
/// assert!(query.to_query()?.contains("types=CALL"));
/// assert!(query.to_query()?.contains("limit=10"));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HistoryQuery {
    /// Filter by entry kind; each value is sent as a repeated `types` query
    /// parameter.
    pub types: Vec<HistoryEntryKind>,
    /// Filter by direction; each value is sent as a repeated `directions`
    /// query parameter.
    pub directions: Vec<HistoryDirection>,
    /// Filter by starred state; each value is sent as a repeated `starred`
    /// query parameter.
    pub starred: Vec<HistoryStarred>,
    /// Pagination offset. The documented range is `0..=MAX_HISTORY_OFFSET`.
    pub offset: Option<u32>,
    /// Page size. The documented range is `0..=MAX_HISTORY_LIMIT`.
    pub limit: Option<u32>,
    /// Whether to show only archived entries.
    pub archived: Option<bool>,
    /// Lower bound as an ISO-8601 date-time string.
    pub from: Option<String>,
    /// Upper bound as an ISO-8601 date-time string.
    pub to: Option<String>,
    /// Filter events to or from this number. This filter is not supported by
    /// [`HistoryExportRequest`].
    pub phone_number: Option<String>,
    /// Whether to include events from all account users. The upstream endpoint
    /// documents this as admin-only.
    pub include_all_users: Option<bool>,
    /// Classic connection IDs or channel UUIDs.
    pub connection_ids: Vec<String>,
}

impl HistoryQuery {
    /// Builds an empty history query.
    ///
    /// ```
    /// use sipgate_flow::rest::HistoryQuery;
    ///
    /// assert_eq!(HistoryQuery::new().to_query()?, "");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Encodes the query string without the leading `?`.
    ///
    /// The documented pagination and field bounds are checked here, so a
    /// caller can validate the request before a client method tries to send
    /// it.
    ///
    /// ```
    /// use sipgate_flow::rest::{HistoryQuery, MAX_HISTORY_LIMIT};
    ///
    /// let mut query = HistoryQuery::new();
    /// query.limit = Some(MAX_HISTORY_LIMIT);
    /// assert_eq!(query.to_query()?, format!("limit={MAX_HISTORY_LIMIT}"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an out-of-range pagination value, an empty
    /// date or phone filter, or a connection id that would escape its slot.
    pub fn to_query(&self) -> Result<String> {
        Ok(encode_history_query(&self.query_pairs(true)?))
    }

    fn query_pairs(&self, include_phone_number: bool) -> Result<Vec<(String, String)>> {
        self.validate(include_phone_number)?;
        let mut pairs = Vec::new();
        for kind in &self.types {
            pairs.push(("types".to_string(), history_kind_query_value(kind)));
        }
        for direction in &self.directions {
            pairs.push((
                "directions".to_string(),
                history_direction_query_value(direction),
            ));
        }
        if let Some(offset) = self.offset {
            pairs.push(("offset".to_string(), offset.to_string()));
        }
        if let Some(limit) = self.limit {
            pairs.push(("limit".to_string(), limit.to_string()));
        }
        if let Some(archived) = self.archived {
            pairs.push(("archived".to_string(), archived.to_string()));
        }
        for starred in &self.starred {
            pairs.push(("starred".to_string(), history_starred_query_value(starred)));
        }
        if let Some(from) = &self.from {
            pairs.push(("from".to_string(), from.clone()));
        }
        if let Some(to) = &self.to {
            pairs.push(("to".to_string(), to.clone()));
        }
        if include_phone_number {
            if let Some(phone_number) = &self.phone_number {
                pairs.push(("phonenumber".to_string(), phone_number.clone()));
            }
        }
        if let Some(include_all_users) = self.include_all_users {
            pairs.push(("includeAllUsers".to_string(), include_all_users.to_string()));
        }
        for connection_id in &self.connection_ids {
            pairs.push(("connectionIds".to_string(), connection_id.clone()));
        }
        Ok(pairs)
    }

    fn validate(&self, include_phone_number: bool) -> Result<()> {
        if let Some(offset) = self.offset {
            if offset > MAX_HISTORY_OFFSET {
                return Err(Error::validation(
                    "offset",
                    format!("must be at most {MAX_HISTORY_OFFSET}"),
                ));
            }
        }
        if let Some(limit) = self.limit {
            if limit > MAX_HISTORY_LIMIT {
                return Err(Error::validation(
                    "limit",
                    format!("must be at most {MAX_HISTORY_LIMIT}"),
                ));
            }
        }
        if let Some(from) = &self.from {
            validate::non_empty("from", from, validate::MAX_REST_FIELD_BYTES)?;
        }
        if let Some(to) = &self.to {
            validate::non_empty("to", to, validate::MAX_REST_FIELD_BYTES)?;
        }
        if include_phone_number {
            if let Some(phone_number) = &self.phone_number {
                validate::non_empty("phonenumber", phone_number, validate::MAX_REST_FIELD_BYTES)?;
            }
        }
        for connection_id in &self.connection_ids {
            validate::path_segment("connectionIds", connection_id)?;
        }
        Ok(())
    }
}

/// Request for `GET /v2/history/export`.
///
/// ```
/// use sipgate_flow::rest::{HistoryExportRequest, HistoryQuery};
///
/// let request = HistoryExportRequest::new(HistoryQuery::new());
/// assert_eq!(request.to_query()?, "");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HistoryExportRequest {
    /// The documented history filters. `phone_number` is refused because the
    /// export operation does not document that query parameter.
    pub query: HistoryQuery,
}

impl HistoryExportRequest {
    /// Builds an export request from the shared history query.
    ///
    /// ```
    /// use sipgate_flow::rest::{HistoryExportRequest, HistoryQuery};
    ///
    /// let request = HistoryExportRequest::new(HistoryQuery::new());
    /// assert_eq!(request.query.limit, None);
    /// ```
    #[must_use]
    pub fn new(query: HistoryQuery) -> Self {
        Self { query }
    }

    /// Encodes the export query string without the leading `?`.
    ///
    /// ```
    /// use sipgate_flow::rest::{HistoryExportRequest, HistoryQuery};
    ///
    /// let mut query = HistoryQuery::new();
    /// query.limit = Some(5);
    /// assert_eq!(HistoryExportRequest::new(query).to_query()?, "limit=5");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for the same bounds as [`HistoryQuery::to_query`]
    /// and for a `phone_number` filter, which `/history/export` does not
    /// document.
    pub fn to_query(&self) -> Result<String> {
        if self.query.phone_number.is_some() {
            return Err(Error::validation(
                "phonenumber",
                "is not supported by /v2/history/export",
            ));
        }
        Ok(encode_history_query(&self.query.query_pairs(false)?))
    }
}

/// Request for `DELETE /v2/history`.
///
/// ```
/// use sipgate_flow::rest::DeleteHistoryEntriesRequest;
///
/// let request = DeleteHistoryEntriesRequest::new(["100001234".to_string()])?;
/// assert_eq!(request.to_query()?, "id=100001234");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteHistoryEntriesRequest {
    /// Entry ids to delete. The list must be non-empty and ids must not repeat.
    pub ids: Vec<String>,
}

impl DeleteHistoryEntriesRequest {
    /// Builds a checked bulk-delete request.
    ///
    /// ```
    /// use sipgate_flow::rest::DeleteHistoryEntriesRequest;
    ///
    /// let request = DeleteHistoryEntriesRequest::new([
    ///     "100001234".to_string(),
    ///     "100001235".to_string(),
    /// ])?;
    /// assert_eq!(request.ids.len(), 2);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the list is empty, an id is empty or too
    /// long, or an id repeats.
    pub fn new(ids: impl IntoIterator<Item = String>) -> Result<Self> {
        let request = Self {
            ids: ids.into_iter().collect(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Encodes the repeated `id` query parameters without the leading `?`.
    ///
    /// ```
    /// use sipgate_flow::rest::DeleteHistoryEntriesRequest;
    ///
    /// let request = DeleteHistoryEntriesRequest::new(["a".to_string(), "b".to_string()])?;
    /// assert_eq!(request.to_query()?, "id=a&id=b");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the request is invalid.
    pub fn to_query(&self) -> Result<String> {
        self.validate()?;
        let pairs = self
            .ids
            .iter()
            .map(|id| ("id".to_string(), id.clone()))
            .collect::<Vec<_>>();
        Ok(encode_history_query(&pairs))
    }

    fn validate(&self) -> Result<()> {
        if self.ids.is_empty() {
            return Err(Error::validation(
                "id",
                "must contain at least one entry id",
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for id in &self.ids {
            validate::path_segment("id", id)?;
            if !seen.insert(id.as_str()) {
                return Err(Error::validation("id", "must not repeat"));
            }
        }
        Ok(())
    }
}

/// One entry update in `PUT /v2/history`.
///
/// ```
/// use sipgate_flow::rest::HistoryEntryUpdate;
///
/// let mut update = HistoryEntryUpdate::new("100001234")?;
/// update.read = Some(true);
/// assert_eq!(update.to_json()["id"], "100001234");
/// assert_eq!(update.to_json()["read"], true);
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HistoryEntryUpdate {
    /// Entry id to update.
    pub id: String,
    /// New archived state, when changing it.
    pub archived: Option<bool>,
    /// New read state, when changing it.
    pub read: Option<bool>,
    /// New starred state, when changing it.
    pub starred: Option<bool>,
}

impl HistoryEntryUpdate {
    /// Builds an update for one entry id.
    ///
    /// ```
    /// use sipgate_flow::rest::HistoryEntryUpdate;
    ///
    /// let update = HistoryEntryUpdate::new("100001234")?;
    /// assert_eq!(update.id, "100001234");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the id is empty or cannot be sent safely.
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let update = Self {
            id: id.into(),
            archived: None,
            read: None,
            starred: None,
        };
        update.validate()?;
        Ok(update)
    }

    /// Renders the documented camel-case update object.
    ///
    /// ```
    /// use sipgate_flow::rest::HistoryEntryUpdate;
    ///
    /// let update = HistoryEntryUpdate::new("100001234")?;
    /// assert_eq!(update.to_json(), serde_json::json!({"id": "100001234"}));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        body.insert("id".to_string(), json!(self.id));
        if let Some(archived) = self.archived {
            body.insert("archived".to_string(), json!(archived));
        }
        if let Some(read) = self.read {
            body.insert("read".to_string(), json!(read));
        }
        if let Some(starred) = self.starred {
            body.insert("starred".to_string(), json!(starred));
        }
        Value::Object(body)
    }

    fn validate(&self) -> Result<()> {
        validate::path_segment("id", &self.id)
    }
}

/// Request for `PUT /v2/history`.
///
/// ```
/// use sipgate_flow::rest::{HistoryEntryUpdate, UpdateHistoryEntriesRequest};
///
/// let update = HistoryEntryUpdate::new("100001234")?;
/// let request = UpdateHistoryEntriesRequest::new([update])?;
/// assert!(request.to_json().is_array());
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpdateHistoryEntriesRequest {
    /// Updates to apply. The documented maximum is
    /// `MAX_HISTORY_UPDATE_ENTRIES`.
    pub entries: Vec<HistoryEntryUpdate>,
}

impl UpdateHistoryEntriesRequest {
    /// Builds a checked bulk-update request.
    ///
    /// ```
    /// use sipgate_flow::rest::{HistoryEntryUpdate, UpdateHistoryEntriesRequest};
    ///
    /// let request = UpdateHistoryEntriesRequest::new([
    ///     HistoryEntryUpdate::new("100001234")?,
    /// ])?;
    /// assert_eq!(request.entries.len(), 1);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the list has 150 or more entries or any
    /// entry id is invalid.
    pub fn new(entries: impl IntoIterator<Item = HistoryEntryUpdate>) -> Result<Self> {
        let request = Self {
            entries: entries.into_iter().collect(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Renders the documented JSON array body.
    ///
    /// ```
    /// use sipgate_flow::rest::{HistoryEntryUpdate, UpdateHistoryEntriesRequest};
    ///
    /// let request = UpdateHistoryEntriesRequest::new([
    ///     HistoryEntryUpdate::new("100001234")?,
    /// ])?;
    /// assert_eq!(request.to_json()[0]["id"], "100001234");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Array(
            self.entries
                .iter()
                .map(HistoryEntryUpdate::to_json)
                .collect(),
        )
    }

    fn validate(&self) -> Result<()> {
        if self.entries.len() > MAX_HISTORY_UPDATE_ENTRIES {
            return Err(Error::validation(
                "entries",
                format!("must contain at most {MAX_HISTORY_UPDATE_ENTRIES} entries"),
            ));
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }
}

/// Request for `PUT /v2/history/{entryId}`.
///
/// ```
/// use sipgate_flow::rest::UpdateHistoryEntryRequest;
///
/// let mut request = UpdateHistoryEntryRequest::new();
/// request.read = Some(true);
/// assert_eq!(request.to_json()["read"], true);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpdateHistoryEntryRequest {
    /// New archived state, when changing it.
    pub archived: Option<bool>,
    /// New read state, when changing it.
    pub read: Option<bool>,
    /// New starred state, when changing it.
    pub starred: Option<bool>,
    /// New note, when changing it.
    pub note: Option<String>,
}

impl UpdateHistoryEntryRequest {
    /// Builds an empty update request.
    ///
    /// ```
    /// use sipgate_flow::rest::UpdateHistoryEntryRequest;
    ///
    /// assert_eq!(UpdateHistoryEntryRequest::new().to_json(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Renders the documented JSON object body.
    ///
    /// ```
    /// use sipgate_flow::rest::UpdateHistoryEntryRequest;
    ///
    /// let mut request = UpdateHistoryEntryRequest::new();
    /// request.note = Some("Customer called back".to_string());
    /// assert_eq!(request.to_json()["note"], "Customer called back");
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        if let Some(archived) = self.archived {
            body.insert("archived".to_string(), json!(archived));
        }
        if let Some(read) = self.read {
            body.insert("read".to_string(), json!(read));
        }
        if let Some(starred) = self.starred {
            body.insert("starred".to_string(), json!(starred));
        }
        if let Some(note) = &self.note {
            body.insert("note".to_string(), json!(note));
        }
        Value::Object(body)
    }

    fn validate(&self) -> Result<()> {
        if let Some(note) = &self.note {
            validate::non_empty("note", note, validate::MAX_REST_FIELD_BYTES)?;
        }
        Ok(())
    }
}

/// Request for `PUT /v2/history/{entryId}/archive`.
///
/// ```
/// use sipgate_flow::rest::SetHistoryEntryArchiveRequest;
///
/// assert_eq!(
///     SetHistoryEntryArchiveRequest::new(true).to_json(),
///     serde_json::json!({"value": true})
/// );
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SetHistoryEntryArchiveRequest {
    /// New archive state.
    pub value: bool,
}

impl SetHistoryEntryArchiveRequest {
    /// Builds an archive-state request.
    ///
    /// ```
    /// use sipgate_flow::rest::SetHistoryEntryArchiveRequest;
    ///
    /// assert!(SetHistoryEntryArchiveRequest::new(false).to_json()["value"] == false);
    /// ```
    #[must_use]
    pub fn new(value: bool) -> Self {
        Self { value }
    }

    /// Renders the documented JSON object body.
    ///
    /// ```
    /// use sipgate_flow::rest::SetHistoryEntryArchiveRequest;
    ///
    /// assert_eq!(SetHistoryEntryArchiveRequest::new(true).to_json()["value"], true);
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({"value": self.value})
    }
}

/// Request for `PUT /v2/history/{entryId}/note`.
///
/// ```
/// use sipgate_flow::rest::SetHistoryEntryNoteRequest;
///
/// let request = SetHistoryEntryNoteRequest::new("Customer called back")?;
/// assert_eq!(request.to_json()["note"], "Customer called back");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SetHistoryEntryNoteRequest {
    /// Note text.
    pub note: String,
}

impl SetHistoryEntryNoteRequest {
    /// Builds a checked note request.
    ///
    /// ```
    /// use sipgate_flow::rest::SetHistoryEntryNoteRequest;
    ///
    /// assert!(SetHistoryEntryNoteRequest::new("done").is_ok());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the note is empty or too long.
    pub fn new(note: impl Into<String>) -> Result<Self> {
        let request = Self { note: note.into() };
        request.validate()?;
        Ok(request)
    }

    /// Renders the documented JSON object body.
    ///
    /// ```
    /// use sipgate_flow::rest::SetHistoryEntryNoteRequest;
    ///
    /// assert_eq!(SetHistoryEntryNoteRequest::new("done")?.to_json(), serde_json::json!({"note": "done"}));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({"note": self.note})
    }

    fn validate(&self) -> Result<()> {
        validate::non_empty("note", &self.note, validate::MAX_REST_FIELD_BYTES)
    }
}

/// Request for `PUT /v2/history/{entryId}/read`.
///
/// ```
/// use sipgate_flow::rest::SetHistoryEntryReadRequest;
///
/// assert_eq!(
///     SetHistoryEntryReadRequest::new(true).to_json(),
///     serde_json::json!({"value": true})
/// );
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SetHistoryEntryReadRequest {
    /// New read state.
    pub value: bool,
}

impl SetHistoryEntryReadRequest {
    /// Builds a read-state request.
    ///
    /// ```
    /// use sipgate_flow::rest::SetHistoryEntryReadRequest;
    ///
    /// assert!(SetHistoryEntryReadRequest::new(false).to_json()["value"] == false);
    /// ```
    #[must_use]
    pub fn new(value: bool) -> Self {
        Self { value }
    }

    /// Renders the documented JSON object body.
    ///
    /// ```
    /// use sipgate_flow::rest::SetHistoryEntryReadRequest;
    ///
    /// assert_eq!(SetHistoryEntryReadRequest::new(true).to_json()["value"], true);
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({"value": self.value})
    }
}

/// Response for `GET /v2/history`.
///
/// ```
/// use sipgate_flow::rest::HistoryResponse;
///
/// let mut response = HistoryResponse::default();
/// response.total_count = Some(0);
/// assert_eq!(response.items, []);
/// assert_eq!(response.total_count, Some(0));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HistoryResponse {
    /// History entries in the requested page.
    pub items: Vec<HistoryEntry>,
    /// Total matching rows reported by the server, when present.
    pub total_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawHistoryResponse {
    #[serde(default)]
    items: Option<Vec<HistoryEntry>>,
    #[serde(default, alias = "total_count")]
    total_count: Option<i64>,
}

impl<T: Transport, A: TokenSource, S: Sleeper> RestClient<T, A, S> {
    /// `GET /v2/history` — one typed page of calls, faxes, SMS messages and
    /// voicemails, with the documented filters applied.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::rest::{HistoryEntryKind, HistoryQuery};
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let mut query = HistoryQuery::new();
    /// query.types.push(HistoryEntryKind::Call);
    /// query.limit = Some(50);
    /// let page = client.history_page(&query).await?;
    /// for entry in page.items {
    ///     println!("{}", entry.id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an invalid query, [`Error::Json`] when the
    /// body is not the documented `{"items": [...]}` envelope, plus transport
    /// and auth errors.
    pub async fn history_page(&self, query: &HistoryQuery) -> Result<HistoryResponse> {
        let query = query.to_query()?;
        let path = history_path("/v2/history", &query);
        let value = self.send(Method::Get, &path, None).await?;
        let response =
            serde_json::from_value::<RawHistoryResponse>(value).map_err(Error::json_parse)?;
        Ok(HistoryResponse {
            items: response.items.unwrap_or_default(),
            total_count: response.total_count,
        })
    }

    /// `GET /v2/history/export` — the documented history export as CSV text.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::rest::{HistoryExportRequest, HistoryQuery};
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let mut query = HistoryQuery::new();
    /// query.limit = Some(50);
    /// let csv = client.history_export_csv(&HistoryExportRequest::new(query)).await?;
    /// println!("{csv}");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an invalid query or an unsupported
    /// `phonenumber` filter, plus transport and auth errors.
    pub async fn history_export_csv(&self, request: &HistoryExportRequest) -> Result<String> {
        let query = request.to_query()?;
        let path = history_path("/v2/history/export", &query);
        let response = self.send_raw(Method::Get, &path, None).await?;
        Ok(response.text())
    }

    /// `GET /v2/history/{entryId}` — one history entry, typed.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let entry = client.history_entry("100001234").await?;
    /// println!("{}", entry.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable entry id, [`Error::Json`] when
    /// the body is not a history entry object, plus transport and auth errors.
    pub async fn history_entry(&self, entry_id: &str) -> Result<HistoryEntry> {
        validate::path_segment("entry_id", entry_id)?;
        let path = format!("/v2/history/{entry_id}");
        let value = self.send(Method::Get, &path, None).await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `DELETE /v2/history` — delete multiple history entries.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::rest::DeleteHistoryEntriesRequest;
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let request = DeleteHistoryEntriesRequest::new(["100001234".to_string()])?;
    /// client.delete_history_entries(&request).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty list or an invalid id, plus
    /// transport and auth errors.
    pub async fn delete_history_entries(
        &self,
        request: &DeleteHistoryEntriesRequest,
    ) -> Result<()> {
        let query = request.to_query()?;
        let path = history_path("/v2/history", &query);
        self.send_empty(Method::Delete, &path, None).await
    }

    /// `DELETE /v2/history/{entryId}` — delete one history entry.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.delete_history_entry("100001234").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable entry id, plus transport and auth
    /// errors.
    pub async fn delete_history_entry(&self, entry_id: &str) -> Result<()> {
        validate::path_segment("entry_id", entry_id)?;
        let path = format!("/v2/history/{entry_id}");
        self.send_empty(Method::Delete, &path, None).await
    }

    /// `PUT /v2/history` — update multiple history entries.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::rest::{HistoryEntryUpdate, UpdateHistoryEntriesRequest};
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let mut update = HistoryEntryUpdate::new("100001234")?;
    /// update.read = Some(true);
    /// client.update_history_entries(&UpdateHistoryEntriesRequest::new([update])?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the list has 150 or more entries or an entry
    /// id is invalid, plus transport and auth errors.
    pub async fn update_history_entries(
        &self,
        request: &UpdateHistoryEntriesRequest,
    ) -> Result<()> {
        request.validate()?;
        let body = request.to_json();
        self.send_empty(Method::Put, "/v2/history", Some(&body))
            .await
    }

    /// `PUT /v2/history/{entryId}` — update one history entry.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::rest::UpdateHistoryEntryRequest;
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let mut request = UpdateHistoryEntryRequest::new();
    /// request.starred = Some(true);
    /// client.update_history_entry("100001234", &request).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable entry id or an empty note, plus
    /// transport and auth errors.
    pub async fn update_history_entry(
        &self,
        entry_id: &str,
        request: &UpdateHistoryEntryRequest,
    ) -> Result<()> {
        validate::path_segment("entry_id", entry_id)?;
        request.validate()?;
        let path = format!("/v2/history/{entry_id}");
        let body = request.to_json();
        self.send_empty(Method::Put, &path, Some(&body)).await
    }

    /// `PUT /v2/history/{entryId}/archive` — set archive state.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::rest::SetHistoryEntryArchiveRequest;
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.set_history_entry_archive("100001234", &SetHistoryEntryArchiveRequest::new(true)).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable entry id, plus transport and auth
    /// errors.
    pub async fn set_history_entry_archive(
        &self,
        entry_id: &str,
        request: &SetHistoryEntryArchiveRequest,
    ) -> Result<()> {
        validate::path_segment("entry_id", entry_id)?;
        let path = format!("/v2/history/{entry_id}/archive");
        let body = request.to_json();
        self.send_empty(Method::Put, &path, Some(&body)).await
    }

    /// `PUT /v2/history/{entryId}/note` — set the note.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::rest::SetHistoryEntryNoteRequest;
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.set_history_entry_note("100001234", &SetHistoryEntryNoteRequest::new("done")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable entry id or an empty note, plus
    /// transport and auth errors.
    pub async fn set_history_entry_note(
        &self,
        entry_id: &str,
        request: &SetHistoryEntryNoteRequest,
    ) -> Result<()> {
        validate::path_segment("entry_id", entry_id)?;
        request.validate()?;
        let path = format!("/v2/history/{entry_id}/note");
        let body = request.to_json();
        self.send_empty(Method::Put, &path, Some(&body)).await
    }

    /// `PUT /v2/history/{entryId}/read` — set read state.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::rest::SetHistoryEntryReadRequest;
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.set_history_entry_read("100001234", &SetHistoryEntryReadRequest::new(true)).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable entry id, plus transport and auth
    /// errors.
    pub async fn set_history_entry_read(
        &self,
        entry_id: &str,
        request: &SetHistoryEntryReadRequest,
    ) -> Result<()> {
        validate::path_segment("entry_id", entry_id)?;
        let path = format!("/v2/history/{entry_id}/read");
        let body = request.to_json();
        self.send_empty(Method::Put, &path, Some(&body)).await
    }

    async fn send_raw(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<crate::transport::Response> {
        let mut attempts_failed = 0_u32;
        loop {
            let error = match self.attempt_raw(method, path, body).await {
                Ok(response) => return Ok(response),
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

    async fn attempt_raw(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<crate::transport::Response> {
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
            return Ok(response);
        }
        Err(api_error(
            method,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    async fn send_empty(&self, method: Method, path: &str, body: Option<&Value>) -> Result<()> {
        self.send_raw(method, path, body).await.map(|_response| ())
    }
}

fn history_path(path: &str, query: &str) -> String {
    if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    }
}

fn encode_history_query(pairs: &[(String, String)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

fn history_kind_query_value(kind: &HistoryEntryKind) -> String {
    match kind {
        HistoryEntryKind::Other(value) => value.clone(),
        _ => kind.as_str().to_ascii_uppercase(),
    }
}

fn history_direction_query_value(direction: &HistoryDirection) -> String {
    match direction {
        HistoryDirection::Other(value) => value.clone(),
        HistoryDirection::Incoming => "INCOMING".to_string(),
        HistoryDirection::Outgoing => "OUTGOING".to_string(),
        HistoryDirection::MissedIncoming => "MISSED_INCOMING".to_string(),
        HistoryDirection::MissedOutgoing => "MISSED_OUTGOING".to_string(),
    }
}

fn history_starred_query_value(starred: &HistoryStarred) -> String {
    match starred {
        HistoryStarred::Other(value) => value.clone(),
        _ => starred.as_str().to_ascii_uppercase(),
    }
}

// ===================================================================
// Issue #164 — REST v2 `devices` resource: types.
// ===================================================================

wire_enum! {
    /// Device-type filter for `GET /v2/{userId}/devices`.
    pub enum DeviceFilter {
        /// Every device kind, the documented `all` token.
        All => "all",
        /// App/toolkit devices.
        App => "app",
        /// Registered SIP devices.
        Register => "register",
        /// Mobile devices.
        Mobile => "mobile",
        /// External numbers or endpoints.
        External => "external",
    }
}

wire_enum! {
    /// Incoming-call display for an external device.
    pub enum IncomingCallDisplay {
        /// Show the number that was called.
        CalledNumber => "CALLED_NUMBER",
        /// Show the caller's number.
        CallerNumber => "CALLER_NUMBER",
    }
}

wire_enum! {
    /// SIM state of a mobile device, from `simState`.
    pub enum SimState {
        /// The SIM is not active.
        Inactive => "INACTIVE",
        /// Activation is in flight.
        Pending => "PENDING",
        /// The SIM is active.
        Active => "ACTIVE",
    }
}

/// `PUT /v2/devices/{deviceId}` body: change device settings.
///
/// Both fields are optional; a body with neither sends an empty object, which
/// the endpoint documents as a no-op update.
///
/// ```
/// use sipgate_flow::rest::ChangeDevice;
///
/// let change = ChangeDevice::new().with_dnd(true).with_emergency_address_id(42);
/// assert_eq!(change.to_json(), serde_json::json!({
///     "dnd": true,
///     "emergencyAddressId": 42,
/// }));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeDevice {
    dnd: Option<bool>,
    emergency_address_id: Option<u32>,
}

impl ChangeDevice {
    /// An empty settings change.
    ///
    /// ```
    /// use sipgate_flow::rest::ChangeDevice;
    ///
    /// assert_eq!(ChangeDevice::new().to_json(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the do-not-disturb flag.
    ///
    /// ```
    /// use sipgate_flow::rest::ChangeDevice;
    ///
    /// assert_eq!(ChangeDevice::new().with_dnd(false).to_json()["dnd"], false);
    /// ```
    #[must_use]
    pub fn with_dnd(mut self, dnd: bool) -> Self {
        self.dnd = Some(dnd);
        self
    }

    /// Sets the emergency address id.
    ///
    /// ```
    /// use sipgate_flow::rest::ChangeDevice;
    ///
    /// assert_eq!(
    ///     ChangeDevice::new().with_emergency_address_id(7).to_json()["emergencyAddressId"],
    ///     7
    /// );
    /// ```
    #[must_use]
    pub fn with_emergency_address_id(mut self, id: u32) -> Self {
        self.emergency_address_id = Some(id);
        self
    }

    /// Renders the `ChangeDeviceRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::ChangeDevice;
    ///
    /// let body = ChangeDevice::new().with_dnd(true).to_json();
    /// assert_eq!(body["dnd"], true);
    /// assert!(body.get("emergencyAddressId").is_none());
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        if let Some(dnd) = self.dnd {
            body.insert("dnd".into(), json!(dnd));
        }
        if let Some(id) = self.emergency_address_id {
            body.insert("emergencyAddressId".into(), json!(id));
        }
        Value::Object(body)
    }
}

/// `POST /v2/{userId}/devices` body: create a device of the given kind.
///
/// The `type` field is required by the schema; a value this crate does not map
/// is refused at construction instead of being sent verbatim.
///
/// ```
/// use sipgate_flow::rest::{CreateDevice, DeviceKind};
///
/// let request = CreateDevice::new(DeviceKind::Register)?.with_alias("Desk phone")?;
/// assert_eq!(request.to_json(), serde_json::json!({
///     "type": "register",
///     "alias": "Desk phone",
/// }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateDevice {
    kind: DeviceKind,
    alias: Option<String>,
}

impl CreateDevice {
    /// Builds the request. The kind must be one of the three documented device
    /// types; [`DeviceKind::Other`] has no wire meaning here.
    ///
    /// ```
    /// use sipgate_flow::rest::{CreateDevice, DeviceKind};
    ///
    /// assert!(CreateDevice::new(DeviceKind::Mobile).is_ok());
    /// assert!(CreateDevice::new(DeviceKind::Other("future".into())).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the kind is not one of `register`, `mobile` or
    /// `external`.
    pub fn new(kind: DeviceKind) -> Result<Self> {
        if let DeviceKind::Other(raw) = &kind {
            return Err(Error::validation(
                "type",
                format!("`{raw}` is not a documented device type"),
            ));
        }
        Ok(Self { kind, alias: None })
    }

    /// Sets the human-readable alias.
    ///
    /// ```
    /// use sipgate_flow::rest::{CreateDevice, DeviceKind};
    ///
    /// let request = CreateDevice::new(DeviceKind::External)?.with_alias("Front door")?;
    /// assert_eq!(request.to_json()["alias"], "Front door");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the alias exceeds the shared REST field
    /// ceiling.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Result<Self> {
        let alias = alias.into();
        validate::non_empty("alias", &alias, validate::MAX_REST_FIELD_BYTES)?;
        self.alias = Some(alias);
        Ok(self)
    }

    /// Renders the `CreateDeviceRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::{CreateDevice, DeviceKind};
    ///
    /// let body = CreateDevice::new(DeviceKind::Register)?.to_json();
    /// assert_eq!(body["type"], "register");
    /// assert!(body.get("alias").is_none());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        body.insert("type".into(), json!(self.kind.as_str()));
        if let Some(alias) = &self.alias {
            body.insert("alias".into(), json!(alias));
        }
        Value::Object(body)
    }
}

/// `POST /v2/{userId}/devices/external` body: create an external device.
///
/// ```
/// use sipgate_flow::rest::CreateExternalDevice;
///
/// let request = CreateExternalDevice::new("4915112345678")?.with_alias("Home")?;
/// assert_eq!(request.to_json(), serde_json::json!({
///     "number": "+4915112345678",
///     "alias": "Home",
/// }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateExternalDevice {
    number: String,
    alias: Option<String>,
}

impl CreateExternalDevice {
    /// Builds the request from the external number (E.164 digits).
    ///
    /// ```
    /// use sipgate_flow::rest::CreateExternalDevice;
    ///
    /// assert!(CreateExternalDevice::new("4915112345678").is_ok());
    /// assert!(CreateExternalDevice::new("4915").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a number that is not E.164 digits.
    pub fn new(number: impl Into<String>) -> Result<Self> {
        let number = validate::phone("number", &number.into())?;
        Ok(Self {
            number: format!("+{number}"),
            alias: None,
        })
    }

    /// Sets the human-readable alias.
    ///
    /// ```
    /// use sipgate_flow::rest::CreateExternalDevice;
    ///
    /// let request = CreateExternalDevice::new("4915112345678")?.with_alias("Home")?;
    /// assert_eq!(request.to_json()["alias"], "Home");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the alias exceeds the shared REST field
    /// ceiling.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Result<Self> {
        let alias = alias.into();
        validate::non_empty("alias", &alias, validate::MAX_REST_FIELD_BYTES)?;
        self.alias = Some(alias);
        Ok(self)
    }

    /// Renders the `CreateExternalDeviceRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::CreateExternalDevice;
    ///
    /// let body = CreateExternalDevice::new("4915112345678")?.to_json();
    /// assert_eq!(body["number"], "+4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        body.insert("number".into(), json!(self.number));
        if let Some(alias) = &self.alias {
            body.insert("alias".into(), json!(alias));
        }
        Value::Object(body)
    }
}

/// `POST /v2/{userId}/devices/mobile` body: create a mobile device.
///
/// ```
/// use sipgate_flow::rest::CreateMobileDevice;
///
/// let request = CreateMobileDevice::new().with_alias("Mobile")?;
/// assert_eq!(request.to_json(), serde_json::json!({ "alias": "Mobile" }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateMobileDevice {
    alias: Option<String>,
}

impl CreateMobileDevice {
    /// An empty create request; the service picks a default alias.
    ///
    /// ```
    /// use sipgate_flow::rest::CreateMobileDevice;
    ///
    /// assert_eq!(CreateMobileDevice::new().to_json(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the human-readable alias.
    ///
    /// ```
    /// use sipgate_flow::rest::CreateMobileDevice;
    ///
    /// let request = CreateMobileDevice::new().with_alias("Mobile")?;
    /// assert_eq!(request.to_json()["alias"], "Mobile");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the alias exceeds the shared REST field
    /// ceiling.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Result<Self> {
        let alias = alias.into();
        validate::non_empty("alias", &alias, validate::MAX_REST_FIELD_BYTES)?;
        self.alias = Some(alias);
        Ok(self)
    }

    /// Renders the `CreateMobileDeviceRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::CreateMobileDevice;
    ///
    /// assert_eq!(CreateMobileDevice::new().to_json(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        if let Some(alias) = &self.alias {
            body.insert("alias".into(), json!(alias));
        }
        Value::Object(body)
    }
}

/// `POST /v2/{userId}/devices/register` body: create a registered device.
///
/// ```
/// use sipgate_flow::rest::CreateRegisterDevice;
///
/// let request = CreateRegisterDevice::new().with_alias("Desk phone")?;
/// assert_eq!(request.to_json(), serde_json::json!({ "alias": "Desk phone" }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateRegisterDevice {
    alias: Option<String>,
}

impl CreateRegisterDevice {
    /// An empty create request; the service picks a default alias.
    ///
    /// ```
    /// use sipgate_flow::rest::CreateRegisterDevice;
    ///
    /// assert_eq!(CreateRegisterDevice::new().to_json(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the human-readable alias.
    ///
    /// ```
    /// use sipgate_flow::rest::CreateRegisterDevice;
    ///
    /// let request = CreateRegisterDevice::new().with_alias("Desk phone")?;
    /// assert_eq!(request.to_json()["alias"], "Desk phone");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the alias exceeds the shared REST field
    /// ceiling.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Result<Self> {
        let alias = alias.into();
        validate::non_empty("alias", &alias, validate::MAX_REST_FIELD_BYTES)?;
        self.alias = Some(alias);
        Ok(self)
    }

    /// Renders the `CreateRegisterDeviceRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::CreateRegisterDevice;
    ///
    /// assert_eq!(CreateRegisterDevice::new().to_json(), serde_json::json!({}));
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        if let Some(alias) = &self.alias {
            body.insert("alias".into(), json!(alias));
        }
        Value::Object(body)
    }
}

/// `PUT /v2/devices/{deviceId}/alias` body: rename a device.
///
/// ```
/// use sipgate_flow::rest::DeviceAlias;
///
/// let alias = DeviceAlias::new("Desk phone")?;
/// assert_eq!(alias.to_json(), serde_json::json!({ "value": "Desk phone" }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAlias {
    value: String,
}

impl DeviceAlias {
    /// Builds the request from the new alias.
    ///
    /// ```
    /// use sipgate_flow::rest::DeviceAlias;
    ///
    /// assert!(DeviceAlias::new("Desk phone").is_ok());
    /// assert!(DeviceAlias::new("").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oversized alias.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate::non_empty("value", &value, validate::MAX_REST_FIELD_BYTES)?;
        Ok(Self { value })
    }

    /// Renders the `SetDeviceAliasRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::DeviceAlias;
    ///
    /// assert_eq!(DeviceAlias::new("x")?.to_json()["value"], "x");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "value": self.value })
    }
}

/// `GET`/`PUT /v2/devices/{deviceId}/callerid` body and response: the device's
/// outbound caller ID.
///
/// ```
/// use sipgate_flow::rest::DeviceCallerId;
///
/// let caller_id = DeviceCallerId::new("4915112345678")?;
/// assert_eq!(caller_id.to_json(), serde_json::json!({ "value": "+4915112345678" }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DeviceCallerId {
    /// The caller ID, `+`-prefixed E.164 digits.
    #[serde(default)]
    pub value: String,
}

impl DeviceCallerId {
    /// Builds the request from an E.164 number (leading `+` optional).
    ///
    /// ```
    /// use sipgate_flow::rest::DeviceCallerId;
    ///
    /// assert_eq!(DeviceCallerId::new("4915112345678")?.value, "+4915112345678");
    /// assert!(DeviceCallerId::new("").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a value that is not E.164 digits.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let digits = validate::phone("value", &value.into())?;
        Ok(Self {
            value: format!("+{digits}"),
        })
    }

    /// Renders the `CallerIdRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::DeviceCallerId;
    ///
    /// assert_eq!(DeviceCallerId::new("4915112345678")?.to_json()["value"], "+4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "value": self.value })
    }
}

/// `PUT /v2/devices/{deviceId}/external/targetnumber` body: the number an
/// external device dials.
///
/// ```
/// use sipgate_flow::rest::ExternalTargetNumber;
///
/// let target = ExternalTargetNumber::new("4915112345678")?;
/// assert_eq!(target.to_json(), serde_json::json!({ "number": "+4915112345678" }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalTargetNumber {
    number: String,
}

impl ExternalTargetNumber {
    /// Builds the request from an E.164 number (leading `+` optional).
    ///
    /// ```
    /// use sipgate_flow::rest::ExternalTargetNumber;
    ///
    /// assert!(ExternalTargetNumber::new("4915112345678").is_ok());
    /// assert!(ExternalTargetNumber::new("abc").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a number that is not E.164 digits.
    pub fn new(number: impl Into<String>) -> Result<Self> {
        let digits = validate::phone("number", &number.into())?;
        Ok(Self {
            number: format!("+{digits}"),
        })
    }

    /// Renders the `ChangeExternalDeviceTargetNumberRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::ExternalTargetNumber;
    ///
    /// assert_eq!(ExternalTargetNumber::new("4915112345678")?.to_json()["number"], "+4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "number": self.number })
    }
}

/// `GET`/`PUT /v2/devices/{deviceId}/localprefix` body and response: the local
/// dialing prefix.
///
/// ```
/// use sipgate_flow::rest::Localprefix;
///
/// let prefix = Localprefix::new(true, "030")?;
/// assert_eq!(prefix.to_json(), serde_json::json!({
///     "active": true,
///     "value": "030",
/// }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Localprefix {
    /// Whether the local prefix is active.
    #[serde(default)]
    pub active: bool,
    /// The prefix digits.
    #[serde(default)]
    pub value: String,
}

impl Localprefix {
    /// Builds the request. The prefix is restricted to ASCII digits; the schema
    /// example is `030`.
    ///
    /// ```
    /// use sipgate_flow::rest::Localprefix;
    ///
    /// assert!(Localprefix::new(false, "0221").is_ok());
    /// assert!(Localprefix::new(false, "02 21").is_err());
    /// assert!(Localprefix::new(false, "").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty, oversized or non-digit prefix.
    pub fn new(active: bool, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate::non_empty("value", &value, validate::MAX_REST_FIELD_BYTES)?;
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::validation("value", "must contain only ASCII digits"));
        }
        Ok(Self { active, value })
    }

    /// Renders the `LocalprefixRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::Localprefix;
    ///
    /// assert_eq!(Localprefix::new(true, "030")?.to_json()["active"], true);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "active": self.active, "value": self.value })
    }
}

/// `GET`/`PUT /v2/devices/{deviceId}/singlerowdisplay` body and response.
///
/// ```
/// use sipgate_flow::rest::SingleRowDisplay;
///
/// let setting = SingleRowDisplay::new(true);
/// assert_eq!(setting.to_json(), serde_json::json!({ "enabled": true }));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SingleRowDisplay {
    /// Whether the single-row display is enabled.
    #[serde(default)]
    pub enabled: bool,
}

impl SingleRowDisplay {
    /// Builds the setting.
    ///
    /// ```
    /// use sipgate_flow::rest::SingleRowDisplay;
    ///
    /// assert_eq!(SingleRowDisplay::new(false).to_json()["enabled"], false);
    /// ```
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Renders the `SingleRowDisplayRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::SingleRowDisplay;
    ///
    /// assert_eq!(SingleRowDisplay::new(true).to_json(), serde_json::json!({ "enabled": true }));
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "enabled": self.enabled })
    }
}

/// `GET`/`PUT /v2/devices/{deviceId}/tariffannouncement` body and response.
///
/// ```
/// use sipgate_flow::rest::TariffAnnouncement;
///
/// let setting = TariffAnnouncement::new(true);
/// assert_eq!(setting.to_json(), serde_json::json!({ "enabled": true }));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct TariffAnnouncement {
    /// Whether the tariff announcement is enabled.
    #[serde(default)]
    pub enabled: bool,
}

impl TariffAnnouncement {
    /// Builds the setting.
    ///
    /// ```
    /// use sipgate_flow::rest::TariffAnnouncement;
    ///
    /// assert_eq!(TariffAnnouncement::new(false).to_json()["enabled"], false);
    /// ```
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Renders the `TariffAnnouncementRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::TariffAnnouncement;
    ///
    /// assert_eq!(TariffAnnouncement::new(true).to_json(), serde_json::json!({ "enabled": true }));
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "enabled": self.enabled })
    }
}

/// `POST /v2/devices/{deviceId}/credentials/password` response: the new SIP
/// password.
///
/// ```
/// use sipgate_flow::rest::DevicePassword;
///
/// let rotated: DevicePassword = serde_json::from_value(serde_json::json!({
///     "password": "s3cr3t"
/// }))
/// .unwrap();
/// assert_eq!(rotated.password, "s3cr3t");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DevicePassword {
    /// The freshly generated password.
    #[serde(default)]
    pub password: String,
}

/// `GET /v2/{userId}/devices/{deviceId}/contingents` response.
///
/// ```
/// use sipgate_flow::rest::DeviceContingents;
///
/// let contingents: DeviceContingents = serde_json::from_value(serde_json::json!({
///     "contingents": [{"type": "DATA_FAST", "amount": 2500, "used": 1000, "left": 1500, "unit": "KILOBYTE"}],
///     "futureField": 1
/// }))
/// .unwrap();
/// assert_eq!(contingents.contingents[0].left, 1500);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DeviceContingents {
    /// The reported contingents.
    #[serde(default)]
    pub contingents: Vec<Contingent>,
}

/// One contingent of a device.
///
/// ```
/// use sipgate_flow::rest::Contingent;
///
/// let contingent: Contingent = serde_json::from_value(serde_json::json!({
///     "type": "DATA_FAST",
///     "amount": 2500,
///     "used": 1000,
///     "left": 1500,
///     "unit": "KILOBYTE",
///     "expires": "2016-02-10T14:19:39Z"
/// }))
/// .unwrap();
/// assert_eq!(contingent.amount, 2500);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Contingent {
    /// Contingent type, for example `DATA_FAST`.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// Total amount granted.
    #[serde(default)]
    pub amount: u32,
    /// Amount already used.
    #[serde(default)]
    pub used: u32,
    /// Amount still available.
    #[serde(default)]
    pub left: u32,
    /// Unit of the amounts, for example `KILOBYTE`.
    #[serde(default)]
    pub unit: String,
    /// Expiry timestamp, as sipgate sends it.
    #[serde(default)]
    pub expires: String,
}

/// `POST /v2/{userId}/devices/external` response.
///
/// ```
/// use sipgate_flow::rest::{ExternalDevice, IncomingCallDisplay};
///
/// let device: ExternalDevice = serde_json::from_value(serde_json::json!({
///     "id": "x0",
///     "alias": "Home",
///     "number": "+4915112345678",
///     "incomingCallDisplayState": "CALLER_NUMBER",
///     "futureField": 1
/// }))
/// .unwrap();
/// assert_eq!(device.number, "+4915112345678");
/// assert_eq!(device.incoming_call_display, Some(IncomingCallDisplay::CallerNumber));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ExternalDevice {
    /// Unique device identifier.
    #[serde(default)]
    pub id: String,
    /// Human-readable alias.
    #[serde(default)]
    pub alias: String,
    /// The external number.
    #[serde(default)]
    pub number: String,
    /// Device kind. A future value is carried as [`DeviceKind::Other`].
    #[serde(default, rename = "type")]
    pub kind: Option<DeviceKind>,
    /// Whether do-not-disturb is active.
    #[serde(default)]
    pub dnd: bool,
    /// Whether the device is currently online.
    #[serde(default)]
    pub online: bool,
    /// What the device shows for an incoming call.
    #[serde(
        default,
        rename = "incomingCallDisplayState",
        alias = "incoming_call_display_state"
    )]
    pub incoming_call_display: Option<IncomingCallDisplay>,
    /// Active routing groups.
    #[serde(default, alias = "active_groups")]
    pub active_groups: Vec<ActiveRouting>,
    /// Active phone lines.
    #[serde(default, alias = "active_phonelines")]
    pub active_phonelines: Vec<ActiveRouting>,
}

/// `POST /v2/{userId}/devices/mobile` response.
///
/// ```
/// use sipgate_flow::rest::{MobileDevice, SimState};
///
/// let device: MobileDevice = serde_json::from_value(serde_json::json!({
///     "id": "m0",
///     "alias": "Mobile",
///     "esim": true,
///     "simState": "ACTIVE",
///     "credentials": {"simId": "1234567", "puk1": "1", "puk2": "2"},
///     "futureField": 1
/// }))
/// .unwrap();
/// assert!(device.esim);
/// assert_eq!(device.sim_state, Some(SimState::Active));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
pub struct MobileDevice {
    /// Unique device identifier.
    #[serde(default)]
    pub id: String,
    /// Human-readable alias.
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
    /// Whether the device uses an eSIM.
    #[serde(default)]
    pub esim: bool,
    /// SIM state. A future value is carried as [`SimState::Other`].
    #[serde(default, alias = "sim_state")]
    pub sim_state: Option<SimState>,
    /// SIM credentials, when the account returns them.
    #[serde(default)]
    pub credentials: Option<MobileCredentials>,
    /// Active routing groups.
    #[serde(default, alias = "active_groups")]
    pub active_groups: Vec<ActiveRouting>,
    /// Active phone lines.
    #[serde(default, alias = "active_phonelines")]
    pub active_phonelines: Vec<ActiveRouting>,
}

/// SIM credentials of a mobile device.
///
/// ```
/// use sipgate_flow::rest::MobileCredentials;
///
/// let credentials: MobileCredentials = serde_json::from_value(serde_json::json!({
///     "simId": "1234567",
///     "puk1": "1",
///     "puk2": "2"
/// }))
/// .unwrap();
/// assert_eq!(credentials.sim_id, "1234567");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct MobileCredentials {
    /// SIM identifier.
    #[serde(default, alias = "sim_id")]
    pub sim_id: String,
    /// First PUK.
    #[serde(default)]
    pub puk1: String,
    /// Second PUK.
    #[serde(default)]
    pub puk2: String,
}

/// `POST /v2/{userId}/devices/register` response.
///
/// ```
/// use sipgate_flow::rest::RegisterDevice;
///
/// let device: RegisterDevice = serde_json::from_value(serde_json::json!({
///     "id": "e0",
///     "alias": "Desk phone",
///     "addressUrl": "/addresses/1234",
///     "emergencyAddressId": "1234",
///     "registered": [{"ip": "10.0.0.1", "port": "5060", "userAgent": "phone/1.0"}],
///     "credentials": {"username": "u", "password": "p", "sipServer": "sip.example", "outboundProxy": "proxy.example", "sipServerWebsocketUrl": "wss://example"},
///     "futureField": 1
/// }))
/// .unwrap();
/// assert_eq!(device.registered[0].ip, "10.0.0.1");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RegisterDevice {
    /// Unique device identifier.
    #[serde(default)]
    pub id: String,
    /// Human-readable alias.
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
    /// URL for the device's emergency address.
    #[serde(default, alias = "address_url")]
    pub address_url: String,
    /// Emergency address identifier.
    #[serde(default, alias = "emergency_address_id")]
    pub emergency_address_id: String,
    /// Current registrations of the device.
    #[serde(default)]
    pub registered: Vec<RegisteredEndpoint>,
    /// SIP credentials, when the account returns them.
    #[serde(default)]
    pub credentials: Option<RegisterCredentials>,
    /// Active routing groups.
    #[serde(default, alias = "active_groups")]
    pub active_groups: Vec<ActiveRouting>,
    /// Active phone lines.
    #[serde(default, alias = "active_phonelines")]
    pub active_phonelines: Vec<ActiveRouting>,
}

/// One SIP registration of a registered device.
///
/// ```
/// use sipgate_flow::rest::RegisteredEndpoint;
///
/// let endpoint: RegisteredEndpoint = serde_json::from_value(serde_json::json!({
///     "ip": "10.0.0.1",
///     "port": "5060",
///     "userAgent": "phone/1.0"
/// }))
/// .unwrap();
/// assert_eq!(endpoint.port, "5060");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RegisteredEndpoint {
    /// Source IP of the registration.
    #[serde(default)]
    pub ip: String,
    /// Source port of the registration.
    #[serde(default)]
    pub port: String,
    /// SIP user agent of the registration.
    #[serde(default, alias = "user_agent")]
    pub user_agent: String,
}

/// SIP credentials of a registered device.
///
/// ```
/// use sipgate_flow::rest::RegisterCredentials;
///
/// let credentials: RegisterCredentials = serde_json::from_value(serde_json::json!({
///     "username": "u",
///     "password": "p",
///     "sipServer": "sip.example",
///     "outboundProxy": "proxy.example",
///     "sipServerWebsocketUrl": "wss://example"
/// }))
/// .unwrap();
/// assert_eq!(credentials.sip_server, "sip.example");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RegisterCredentials {
    /// SIP username.
    #[serde(default)]
    pub username: String,
    /// SIP password.
    #[serde(default)]
    pub password: String,
    /// SIP server host.
    #[serde(default, alias = "sip_server")]
    pub sip_server: String,
    /// Outbound proxy host.
    #[serde(default, alias = "outbound_proxy")]
    pub outbound_proxy: String,
    /// WebSocket URL for the SIP server.
    #[serde(default, alias = "sip_server_websocket_url")]
    pub sip_server_websocket_url: String,
}

/// `POST /v2/{userId}/devices/{deviceId}/sim` body: activate a SIM.
///
/// ```
/// use sipgate_flow::rest::ActivateSim;
///
/// let request = ActivateSim::new("1234567")?;
/// assert_eq!(request.to_json(), serde_json::json!({ "simId": "1234567" }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateSim {
    sim_id: String,
}

impl ActivateSim {
    /// Builds the request from the SIM id.
    ///
    /// ```
    /// use sipgate_flow::rest::ActivateSim;
    ///
    /// assert!(ActivateSim::new("1234567").is_ok());
    /// assert!(ActivateSim::new("").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oversized SIM id.
    pub fn new(sim_id: impl Into<String>) -> Result<Self> {
        let sim_id = sim_id.into();
        validate::non_empty("sim_id", &sim_id, validate::MAX_REST_FIELD_BYTES)?;
        Ok(Self { sim_id })
    }

    /// Renders the `ActivateSimRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::ActivateSim;
    ///
    /// assert_eq!(ActivateSim::new("1234567")?.to_json()["simId"], "1234567");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "simId": self.sim_id })
    }
}

/// `POST /v2/{userId}/devices/{deviceId}/sim/orders` body: order a SIM.
///
/// ```
/// use sipgate_flow::rest::OrderSim;
///
/// let request = OrderSim::new("123456")?;
/// assert_eq!(request.to_json(), serde_json::json!({ "addressId": "123456" }));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderSim {
    address_id: String,
}

impl OrderSim {
    /// Builds the request from the shipping address id.
    ///
    /// ```
    /// use sipgate_flow::rest::OrderSim;
    ///
    /// assert!(OrderSim::new("123456").is_ok());
    /// assert!(OrderSim::new("").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty or oversized address id.
    pub fn new(address_id: impl Into<String>) -> Result<Self> {
        let address_id = address_id.into();
        validate::non_empty("address_id", &address_id, validate::MAX_REST_FIELD_BYTES)?;
        Ok(Self { address_id })
    }

    /// Renders the `OrderSimRequest` body.
    ///
    /// ```
    /// use sipgate_flow::rest::OrderSim;
    ///
    /// assert_eq!(OrderSim::new("123456")?.to_json()["addressId"], "123456");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "addressId": self.address_id })
    }
}

// ===================================================================
// End issue #164 block (types).
// ===================================================================

// ===================================================================
// Issue #164 — REST v2 `devices` resource.
//
// One self-contained block so the sibling resources (#165 contacts,
// #166 history, #167 phonelines) can add their own blocks without
// colliding here. Every path below is a `/devices...` operation from
// the v2 Swagger document, tagged `devices`.
// ===================================================================
impl<T: Transport, A: TokenSource, S: Sleeper> RestClient<T, A, S> {
    /// `DELETE /v2/devices/{deviceId}` — remove a device.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.delete_device("e0").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id, [`Error::Api`] with 403
    /// for an app extension, plus transport and auth errors.
    pub async fn delete_device(&self, device_id: &str) -> Result<Value> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}");
        self.send(Method::Delete, &path, None).await
    }

    /// `PUT /v2/devices/{deviceId}` — change the device's do-not-disturb flag
    /// and/or emergency address.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::ChangeDevice, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.update_device("e0", &ChangeDevice::new().with_dnd(true)).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id, [`Error::Api`] with 403
    /// (DND not allowed) or 404 (unknown device or address), plus transport and
    /// auth errors.
    pub async fn update_device(&self, device_id: &str, change: &ChangeDevice) -> Result<Value> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}");
        self.send(Method::Put, &path, Some(&change.to_json())).await
    }

    /// `PUT /v2/devices/{deviceId}/alias` — rename a device.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::DeviceAlias, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.update_device_alias("e0", &DeviceAlias::new("Desk phone")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id or alias, [`Error::Api`]
    /// with 400 (device not found) or 403 (invalid user context), plus transport
    /// and auth errors.
    pub async fn update_device_alias(&self, device_id: &str, alias: &DeviceAlias) -> Result<Value> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/alias");
        self.send(Method::Put, &path, Some(&alias.to_json())).await
    }

    /// `GET /v2/devices/{deviceId}/callerid` — the device's outbound caller ID.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let caller_id = client.device_caller_id("e0").await?;
    /// println!("{}", caller_id.value);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id, [`Error::Api`] with 403
    /// when the feature is not booked, [`Error::Json`] when the body is not the
    /// documented object, plus transport and auth errors.
    pub async fn device_caller_id(&self, device_id: &str) -> Result<DeviceCallerId> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/callerid");
        let value = self.send(Method::Get, &path, None).await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `PUT /v2/devices/{deviceId}/callerid` — set the device's outbound caller
    /// ID.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::DeviceCallerId, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.update_device_caller_id("e0", &DeviceCallerId::new("4915112345678")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id or caller ID
    /// (`+`-prefixed E.164 digits), [`Error::Api`] with 400 or 403, plus
    /// transport and auth errors.
    pub async fn update_device_caller_id(
        &self,
        device_id: &str,
        caller_id: &DeviceCallerId,
    ) -> Result<Value> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/callerid");
        self.send(Method::Put, &path, Some(&caller_id.to_json()))
            .await
    }

    /// `POST /v2/devices/{deviceId}/credentials/password` — rotate the SIP
    /// password and return the new one.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let rotated = client.reset_device_password("e0").await?;
    /// println!("new password length: {}", rotated.password.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id, [`Error::Api`] with 400,
    /// 403 or 500, [`Error::Json`] when the body is not the documented object,
    /// plus transport and auth errors.
    pub async fn reset_device_password(&self, device_id: &str) -> Result<DevicePassword> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/credentials/password");
        let value = self.send(Method::Post, &path, None).await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `PUT /v2/devices/{deviceId}/external/incomingcalldisplay` — choose what
    /// an external device shows for an incoming call.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::rest::IncomingCallDisplay;
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.update_external_incoming_call_display("x0", IncomingCallDisplay::CallerNumber).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id, [`Error::Api`] with 400
    /// or 500, plus transport and auth errors.
    pub async fn update_external_incoming_call_display(
        &self,
        device_id: &str,
        display: IncomingCallDisplay,
    ) -> Result<Value> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/external/incomingcalldisplay");
        let body = json!({ "incomingCallDisplay": display.as_str() });
        self.send(Method::Put, &path, Some(&body)).await
    }

    /// `PUT /v2/devices/{deviceId}/external/targetnumber` — set the number an
    /// external device dials.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::ExternalTargetNumber, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.update_external_target_number("x0", &ExternalTargetNumber::new("4915112345678")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id or target number,
    /// [`Error::Api`] with 400, plus transport and auth errors.
    pub async fn update_external_target_number(
        &self,
        device_id: &str,
        target: &ExternalTargetNumber,
    ) -> Result<Value> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/external/targetnumber");
        self.send(Method::Put, &path, Some(&target.to_json())).await
    }

    /// `GET /v2/devices/{deviceId}/localprefix` — the device's local prefix.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let prefix = client.device_localprefix("e0").await?;
    /// println!("active: {}, value: {}", prefix.active, prefix.value);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id, [`Error::Json`] when the
    /// body is not the documented object, plus transport and auth errors.
    pub async fn device_localprefix(&self, device_id: &str) -> Result<Localprefix> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/localprefix");
        let value = self.send(Method::Get, &path, None).await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `PUT /v2/devices/{deviceId}/localprefix` — set the device's local prefix.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::Localprefix, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.update_device_localprefix("e0", &Localprefix::new(true, "030")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id or prefix, [`Error::Api`]
    /// with 400, 403 or 503, plus transport and auth errors.
    pub async fn update_device_localprefix(
        &self,
        device_id: &str,
        prefix: &Localprefix,
    ) -> Result<Value> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/localprefix");
        self.send(Method::Put, &path, Some(&prefix.to_json())).await
    }

    /// `GET /v2/devices/{deviceId}/singlerowdisplay` — the single-row display
    /// setting.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let setting = client.device_single_row_display("e0").await?;
    /// println!("enabled: {}", setting.enabled);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id, [`Error::Json`] when the
    /// body is not the documented object, plus transport and auth errors.
    pub async fn device_single_row_display(&self, device_id: &str) -> Result<SingleRowDisplay> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/singlerowdisplay");
        let value = self.send(Method::Get, &path, None).await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `PUT /v2/devices/{deviceId}/singlerowdisplay` — enable or disable the
    /// single-row display.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::SingleRowDisplay, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.update_device_single_row_display("e0", &SingleRowDisplay::new(true)).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id, [`Error::Api`] with 403,
    /// plus transport and auth errors.
    pub async fn update_device_single_row_display(
        &self,
        device_id: &str,
        setting: &SingleRowDisplay,
    ) -> Result<Value> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/singlerowdisplay");
        self.send(Method::Put, &path, Some(&setting.to_json()))
            .await
    }

    /// `GET /v2/devices/{deviceId}/tariffannouncement` — the tariff announcement
    /// setting.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let setting = client.device_tariff_announcement("e0").await?;
    /// println!("enabled: {}", setting.enabled);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id, [`Error::Api`] with 403,
    /// [`Error::Json`] when the body is not the documented object, plus
    /// transport and auth errors.
    pub async fn device_tariff_announcement(&self, device_id: &str) -> Result<TariffAnnouncement> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/tariffannouncement");
        let value = self.send(Method::Get, &path, None).await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `PUT /v2/devices/{deviceId}/tariffannouncement` — enable or disable the
    /// tariff announcement.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::TariffAnnouncement, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.update_device_tariff_announcement("e0", &TariffAnnouncement::new(true)).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable device id, [`Error::Api`] with 403,
    /// 404 or 500, plus transport and auth errors.
    pub async fn update_device_tariff_announcement(
        &self,
        device_id: &str,
        setting: &TariffAnnouncement,
    ) -> Result<Value> {
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/devices/{device_id}/tariffannouncement");
        self.send(Method::Put, &path, Some(&setting.to_json()))
            .await
    }

    /// `GET /v2/{userId}/devices` — every device of a user, optionally filtered
    /// by type.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::rest::DeviceFilter;
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let devices = client.user_devices("w0", &[DeviceFilter::Register, DeviceFilter::Mobile]).await?;
    /// for device in devices {
    ///     println!("{}", device.alias);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable user id or an unknown filter token,
    /// [`Error::Json`] when the body is not the documented `{"items": [...]}`
    /// envelope, plus transport and auth errors.
    pub async fn user_devices(
        &self,
        user_id: &str,
        filter: &[DeviceFilter],
    ) -> Result<Vec<Device>> {
        validate::path_segment("user_id", user_id)?;
        let mut path = format!("/v2/{user_id}/devices");
        if let Some(query) = device_type_query(filter)? {
            path.push('?');
            path.push_str(&query);
        }
        self.get_items(&path).await
    }

    /// `POST /v2/{userId}/devices` — create a device of the given kind.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::CreateDevice, rest::DeviceKind, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let request = CreateDevice::new(DeviceKind::Register)?;
    /// let device = client.create_device("w0", &request).await?;
    /// println!("{}", device.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable user id or alias, [`Error::Api`]
    /// with 500, [`Error::Json`] when the body is not the documented object,
    /// plus transport and auth errors.
    pub async fn create_device(&self, user_id: &str, request: &CreateDevice) -> Result<Device> {
        validate::path_segment("user_id", user_id)?;
        let path = format!("/v2/{user_id}/devices");
        let value = self
            .send(Method::Post, &path, Some(&request.to_json()))
            .await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `POST /v2/{userId}/devices/external` — create an external device.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::CreateExternalDevice, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let request = CreateExternalDevice::new("4915112345678")?;
    /// let device = client.create_external_device("w0", &request).await?;
    /// println!("{}", device.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable user id, alias or number,
    /// [`Error::Api`] with 400 or 500, [`Error::Json`] when the body is not the
    /// documented object, plus transport and auth errors.
    pub async fn create_external_device(
        &self,
        user_id: &str,
        request: &CreateExternalDevice,
    ) -> Result<ExternalDevice> {
        validate::path_segment("user_id", user_id)?;
        let path = format!("/v2/{user_id}/devices/external");
        let value = self
            .send(Method::Post, &path, Some(&request.to_json()))
            .await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `POST /v2/{userId}/devices/mobile` — create a mobile device.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::CreateMobileDevice, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let device = client.create_mobile_device("w0", &CreateMobileDevice::new()).await?;
    /// println!("{}", device.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable user id or alias, [`Error::Api`]
    /// with 500, [`Error::Json`] when the body is not the documented object,
    /// plus transport and auth errors.
    pub async fn create_mobile_device(
        &self,
        user_id: &str,
        request: &CreateMobileDevice,
    ) -> Result<MobileDevice> {
        validate::path_segment("user_id", user_id)?;
        let path = format!("/v2/{user_id}/devices/mobile");
        let value = self
            .send(Method::Post, &path, Some(&request.to_json()))
            .await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `POST /v2/{userId}/devices/register` — create a registered device.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::CreateRegisterDevice, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let device = client.create_register_device("w0", &CreateRegisterDevice::new()).await?;
    /// println!("{}", device.id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable user id or alias, [`Error::Api`]
    /// with 500, [`Error::Json`] when the body is not the documented object,
    /// plus transport and auth errors.
    pub async fn create_register_device(
        &self,
        user_id: &str,
        request: &CreateRegisterDevice,
    ) -> Result<RegisterDevice> {
        validate::path_segment("user_id", user_id)?;
        let path = format!("/v2/{user_id}/devices/register");
        let value = self
            .send(Method::Post, &path, Some(&request.to_json()))
            .await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `GET /v2/{userId}/devices/{deviceId}/contingents` — a device's remaining
    /// SIM contingents.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let contingents = client.device_contingents("w0", "y0").await?;
    /// for contingent in contingents.contingents {
    ///     println!("{} left", contingent.left);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable user or device id, [`Error::Json`]
    /// when the body is not the documented object, plus transport and auth
    /// errors.
    pub async fn device_contingents(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<DeviceContingents> {
        validate::path_segment("user_id", user_id)?;
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/{user_id}/devices/{device_id}/contingents");
        let value = self.send(Method::Get, &path, None).await?;
        serde_json::from_value(value).map_err(Error::json_parse)
    }

    /// `DELETE /v2/{userId}/devices/{deviceId}/sim` — deactivate a device's SIM.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.deactivate_sim("w0", "y0").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable user or device id, [`Error::Api`]
    /// with 400, plus transport and auth errors.
    pub async fn deactivate_sim(&self, user_id: &str, device_id: &str) -> Result<Value> {
        validate::path_segment("user_id", user_id)?;
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/{user_id}/devices/{device_id}/sim");
        self.send(Method::Delete, &path, None).await
    }

    /// `POST /v2/{userId}/devices/{deviceId}/sim` — activate a device's SIM.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::ActivateSim, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.activate_sim("w0", "y0", &ActivateSim::new("1234567")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable user or device id, or sim id,
    /// [`Error::Api`] with 400, plus transport and auth errors.
    pub async fn activate_sim(
        &self,
        user_id: &str,
        device_id: &str,
        request: &ActivateSim,
    ) -> Result<Value> {
        validate::path_segment("user_id", user_id)?;
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/{user_id}/devices/{device_id}/sim");
        self.send(Method::Post, &path, Some(&request.to_json()))
            .await
    }

    /// `POST /v2/{userId}/devices/{deviceId}/sim/orders` — order a replacement
    /// SIM to a shipping address.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{rest::OrderSim, ReqwestTransport, RestClient, StaticToken};
    ///
    /// let client = RestClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.order_sim("w0", "y0", &OrderSim::new("123456")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an unusable user or device id, or address id,
    /// [`Error::Api`] with 400, 403, 404 or 500, plus transport and auth errors.
    pub async fn order_sim(
        &self,
        user_id: &str,
        device_id: &str,
        request: &OrderSim,
    ) -> Result<Value> {
        validate::path_segment("user_id", user_id)?;
        validate::path_segment("device_id", device_id)?;
        let path = format!("/v2/{user_id}/devices/{device_id}/sim/orders");
        self.send(Method::Post, &path, Some(&request.to_json()))
            .await
    }
}

/// Builds the `type=` query for `GET /v2/{userId}/devices`.
///
/// An empty filter means "no query"; an [`DeviceFilter::Other`] token has no
/// documented wire meaning and is refused instead of being sent verbatim.
fn device_type_query(filter: &[DeviceFilter]) -> Result<Option<String>> {
    if filter.is_empty() {
        return Ok(None);
    }
    let mut tokens = Vec::with_capacity(filter.len());
    for value in filter {
        match value {
            DeviceFilter::Other(raw) => {
                return Err(Error::validation(
                    "type",
                    format!("`{raw}` is not a documented device filter"),
                ));
            }
            known => tokens.push(known.as_str()),
        }
    }
    Ok(Some(format!("type={}", tokens.join(","))))
}

// ===================================================================
// End issue #164 block (client methods). Types follow at the end.
// ===================================================================
