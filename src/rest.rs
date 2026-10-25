//! sipgate REST API v2: SMS, fax, outbound calls and real-time call control.
//!
//! This is the *imperative* half of sipgate — the operations you trigger from
//! your own code rather than return to a Flow — and it is a separate product
//! from [`crate::flow`] events. Every path, method, body field and status code
//! here comes from the public Swagger document at
//! <https://api.sipgate.com/v2/swagger.json> (rendered at
//! <https://api.sipgate.com/v2/doc>); `docs/contracts.md` maps each method to
//! its operation.
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

    /// Replaces the retry policy (default: three attempts, 250 ms doubling to
    /// an 8 s ceiling, `Retry-After` honoured).
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
            &self.base_url,
            self.timeout,
            method,
            path,
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
        Ok(serde_json::from_value::<CallList>(value)?.into_entries())
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
    /// [`Error::Validation`] for an empty device id or message, or a recipient
    /// that is not `+`-prefixed E.164 digits.
    pub fn new(
        sms_id: impl Into<String>,
        recipient: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<Self> {
        let sms_id = sms_id.into();
        validate::non_empty("sms_id", &sms_id)?;
        let recipient = validate::phone("recipient", &recipient.into())?;
        let message = message.into();
        validate::non_empty("message", &message)?;
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
    /// [`Error::Validation`] for an empty faxline id or filename, a filename
    /// containing a path separator, empty or oversized content, or a recipient
    /// that is not E.164 digits.
    pub fn new(
        faxline_id: impl Into<String>,
        recipient: impl Into<String>,
        filename: impl Into<String>,
        base64_content: impl Into<String>,
    ) -> Result<Self> {
        let faxline_id = faxline_id.into();
        validate::non_empty("faxline_id", &faxline_id)?;
        let recipient = validate::phone("recipient", &recipient.into())?;
        let filename = filename.into();
        validate::non_empty("filename", &filename)?;
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
        validate::non_empty("base64Content", &base64_content)?;
        if base64_content.len() > MAX_FAX_BASE64_LEN {
            return Err(Error::validation(
                "base64Content",
                format!("must be at most {MAX_FAX_BASE64_LEN} characters"),
            ));
        }
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
    /// [`Error::Validation`] for an empty caller or a callee that is not E.164
    /// digits.
    #[allow(clippy::similar_names)] // `caller`/`callee` are the schema's names
    pub fn new(caller: impl Into<String>, callee: impl Into<String>) -> Result<Self> {
        let caller = caller.into();
        validate::non_empty("caller", &caller)?;
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
    /// [`Error::Validation`] for an empty sequence or a character outside the
    /// DTMF alphabet.
    pub fn new(sequence: impl Into<String>) -> Result<Self> {
        let sequence = sequence.into();
        validate::non_empty("sequence", &sequence)?;
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
    Ok(serde_json::from_slice::<CallList>(body)?.into_entries())
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
