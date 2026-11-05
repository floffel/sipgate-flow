//! Outbound calls into a sipgate Flow.
//!
//! `POST /v3/ai-flows/:aiFlowId/call` dials a number and, once the recipient
//! answers, runs the Flow's normal event/action loop with
//! `session.direction = "outbound"`. The path is documented at
//! <https://flow.sipgate.io/api/guides/outbound-calls>; the base URL is
//! `https://api.sipgate.com`, the default of the official SDK
//! (`AiFlowAssistantOptions.baseUrl`).
//!
//! Access is granted per account by sipgate support; without it the endpoint
//! answers 404 or 403.
//!
//! ```no_run
//! # #[cfg(feature = "http")]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use sipgate_flow::{FlowClient, OutboundCall, ReqwestTransport, StaticToken};
//!
//! let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
//! let call = OutboundCall::new("e3670012-96a3-4ae5-ac42-87abe22015c3", "e2", "+4915112345678")?;
//! client.call(&call).await?; // 201 Created
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::auth::{StaticToken, TokenSource};
use crate::error::{Error, Result};
use crate::exchange;
use crate::retry::{NoSleep, RetryPolicy};
use crate::transport::{Method, Transport};
use crate::validate;

/// Base URL; the same host the SDK defaults to.
pub const DEFAULT_BASE_URL: &str = "https://api.sipgate.com";

/// Client for starting outbound Flow calls.
///
/// ```
/// use sipgate_flow::{FlowClient, StaticToken};
/// # use sipgate_flow::{Result, Transport};
/// # use sipgate_flow::transport::{Request, Response};
/// # struct Mock;
/// # impl Transport for Mock {
/// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(201, std::iter::empty(), b"{}".to_vec())) }
/// # }
/// let client = FlowClient::new(Mock, StaticToken::new("t").unwrap());
/// assert_eq!(client.base_url(), "https://api.sipgate.com");
/// ```
pub struct FlowClient<T: Transport, A: TokenSource = StaticToken> {
    transport: T,
    auth: A,
    base_url: String,
    allow_http_base_url: bool,
    timeout: Option<Duration>,
}

impl<T: Transport, A: TokenSource> FlowClient<T, A> {
    /// Builds a client for the documented host.
    ///
    /// ```
    /// use sipgate_flow::{FlowClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(201, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let client = FlowClient::new(Mock, StaticToken::new("t").unwrap());
    /// assert_eq!(client.base_url(), "https://api.sipgate.com");
    /// ```
    #[must_use]
    pub fn new(transport: T, auth: A) -> Self {
        Self {
            transport,
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
            allow_http_base_url: false,
            timeout: None,
        }
    }

    /// Overrides the base URL with a validated `https://` URL.
    ///
    /// ```
    /// use sipgate_flow::{FlowClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(201, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let client = FlowClient::new(Mock, StaticToken::new("t").unwrap())
    ///     .with_base_url("https://proxy.test/")?;
    /// assert_eq!(client.base_url(), "https://proxy.test");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty value, a relative or host-less URL,
    /// a non-http(s) scheme, credentials, whitespace, control characters or a
    /// plain `http://` URL. Use [`Self::with_base_url_for_local_testing`] only
    /// for local test servers where sending credentials in cleartext is
    /// intentional.
    pub fn with_base_url(self, url: impl Into<String>) -> Result<Self> {
        self.try_with_base_url(url)
    }

    /// Overrides the base URL with a validated `https://` URL.
    ///
    /// This is the explicit fallible form of [`Self::with_base_url`].
    ///
    /// ```
    /// use sipgate_flow::{FlowClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(201, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let client = FlowClient::new(Mock, StaticToken::new("t").unwrap())
    ///     .try_with_base_url("https://proxy.test/")?;
    /// assert_eq!(client.base_url(), "https://proxy.test");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty value, a relative or host-less URL,
    /// a non-http(s) scheme, credentials, whitespace, control characters or a
    /// plain `http://` URL.
    pub fn try_with_base_url(self, url: impl Into<String>) -> Result<Self> {
        self.set_base_url(&url.into(), false)
    }

    /// Overrides the base URL with a validated `http(s)` URL for local testing.
    ///
    /// Prefer [`Self::try_with_base_url`] in production. This method allows
    /// plaintext `http://` so credentials can be sent to a local test server;
    /// TLS remains required unless this method is chosen explicitly.
    ///
    /// ```
    /// use sipgate_flow::{FlowClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(201, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let client = FlowClient::new(Mock, StaticToken::new("t").unwrap())
    ///     .with_base_url_for_local_testing("http://localhost:8080/")?;
    /// assert_eq!(client.base_url(), "http://localhost:8080");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty value, a relative or host-less URL,
    /// a non-http(s) scheme, credentials, whitespace or control characters.
    pub fn with_base_url_for_local_testing(self, url: impl Into<String>) -> Result<Self> {
        self.set_base_url(&url.into(), true)
    }

    fn set_base_url(mut self, url: &str, allow_http: bool) -> Result<Self> {
        validate::http_url("base_url", url)?;
        if !allow_http
            && url
                .get(..7)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
        {
            return Err(Error::validation(
                "base_url",
                "must use https:// unless local testing is explicitly enabled",
            ));
        }
        self.base_url = url.trim_end_matches('/').to_string();
        self.allow_http_base_url = allow_http;
        Ok(self)
    }

    /// Sets a per-request timeout.
    ///
    /// ```
    /// use std::time::Duration;
    /// use sipgate_flow::{FlowClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(201, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// let client = FlowClient::new(Mock, StaticToken::new("t").unwrap())
    ///     .with_timeout(Some(Duration::from_secs(10)));
    /// assert_eq!(client.timeout(), Some(Duration::from_secs(10)));
    /// ```
    #[must_use]
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// The base URL in use.
    ///
    /// ```
    /// use sipgate_flow::{FlowClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(201, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// assert!(FlowClient::new(Mock, StaticToken::new("t").unwrap()).base_url().starts_with("https://"));
    /// ```
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The configured timeout.
    ///
    /// ```
    /// use sipgate_flow::{FlowClient, StaticToken};
    /// # use sipgate_flow::{Result, Transport};
    /// # use sipgate_flow::transport::{Request, Response};
    /// # struct Mock;
    /// # impl Transport for Mock {
    /// #     async fn execute(&self, _: Request<'_>) -> Result<Response> { Ok(Response::new(201, std::iter::empty(), b"{}".to_vec())) }
    /// # }
    /// assert!(FlowClient::new(Mock, StaticToken::new("t").unwrap()).timeout().is_none());
    /// ```
    #[must_use]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Dials `request.to_phone_number` through the Flow. Success is the
    /// documented `201 Created`; a 400 means the Flow has no phone number, 403
    /// means call access was not granted, and 404 means the Flow does not exist.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, OutboundCall, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let call = OutboundCall::new("flow-id", "e2", "4915112345678")?;
    /// let created = client.call(&call).await?;
    /// println!("call sid: {:?}", created.call_sid());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::FlowNotCallable`] for `400`,
    /// [`crate::Error::AccessNotGranted`] for `403`, and
    /// [`crate::Error::FlowNotFound`] for `404`. Other non-2xx answers keep the
    /// generic [`crate::Error::Api`] or [`crate::Error::Ambiguous`] behavior,
    /// plus transport and auth errors. A `201` response with an unparseable
    /// body, or any other `2xx` response, becomes
    /// [`crate::Error::CallStartedUnknown`]: the call may already be dialling,
    /// but no identifier is available. There is no retry: starting a call twice
    /// would dial the number twice.
    pub async fn call(&self, request: &OutboundCall) -> Result<OutboundCallReceipt> {
        let path = format!("/v3/ai-flows/{}/call", request.ai_flow_id());
        let body = request.to_json();
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: &path,
            },
            exchange::Pacing {
                timeout: self.timeout,
                retry: &RetryPolicy::none(),
                sleeper: &NoSleep,
            },
            Method::Post,
            Some(&body),
        )
        .await?;
        if response.status() == 201 {
            return match OutboundCallReceipt::parse(response.body()) {
                Ok(receipt) => Ok(receipt),
                Err(_) => Err(crate::Error::CallStartedUnknown {
                    status: response.status(),
                    body: crate::retry::truncate_body(&response.text()),
                }),
            };
        }
        if response.is_success() {
            return Err(crate::Error::CallStartedUnknown {
                status: response.status(),
                body: crate::retry::truncate_body(&response.text()),
            });
        }
        let body = response.text();
        if let Some(error) = Error::call_outcome(response.status(), body.as_str()) {
            return Err(error);
        }
        Err(crate::retry::api_error(
            Method::Post,
            response.status(),
            &response.headers(),
            &body,
        ))
    }

    /// Registers or replaces the account's AI-assist webhook URL:
    /// `PUT /v3/ai-webhooks`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let settings = sipgate_flow::AiWebhookSettings::new("https://example.com/ai-flow")?;
    /// client.update_ai_webhook(&settings).await?; // 200 or 201
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the URL is empty or is not an
    /// absolute `https://` URL, plus the generic transport, auth and API
    /// errors. Non-idempotent retry handling does not apply: replacement of a
    /// single account-level webhook is idempotent, so a retryable response is
    /// reported on [`crate::Error::Api`].
    pub async fn update_ai_webhook(&self, settings: &AiWebhookSettings) -> Result<Value> {
        let body = settings.to_json();
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/ai-webhooks",
            },
            exchange::Pacing {
                timeout: self.timeout,
                retry: &RetryPolicy::none(),
                sleeper: &NoSleep,
            },
            Method::Put,
            Some(&body),
        )
        .await?;
        if response.is_success() {
            return if response.body().iter().all(u8::is_ascii_whitespace) {
                Ok(Value::Null)
            } else {
                response.json()
            };
        }
        Err(crate::retry::api_error(
            Method::Put,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Reads the account's AI-assist webhook URL: `GET /v3/ai-webhooks`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let settings = client.ai_webhook().await?;
    /// println!("{:?}", settings.webhook_url());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Json`] when the success body is not JSON, plus the
    /// generic transport, auth and API errors. A documented `404` is returned
    /// as [`crate::Error::Api`] so the caller can treat "no webhook configured"
    /// separately without inventing a value.
    pub async fn ai_webhook(&self) -> Result<AiWebhookSettings> {
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/ai-webhooks",
            },
            exchange::Pacing {
                timeout: self.timeout,
                retry: &RetryPolicy::none(),
                sleeper: &NoSleep,
            },
            Method::Get,
            None,
        )
        .await?;
        if response.is_success() {
            return Ok(AiWebhookSettings::from_json(&response.json()?));
        }
        Err(crate::retry::api_error(
            Method::Get,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Lists the TTS voices usable in synthesize requests:
    /// `GET /v3/tts/voices`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// for voice in client.tts_voices().await? {
    ///     println!("{}", voice.id());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the documented `{"items": [...]}`
    /// envelope carries no usable voice entries, [`crate::Error::Json`] when
    /// the body does not use the documented envelope, plus transport, auth and
    /// generic API errors.
    pub async fn tts_voices(&self) -> Result<Vec<TtsVoice>> {
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/tts/voices",
            },
            exchange::Pacing {
                timeout: self.timeout,
                retry: &RetryPolicy::none(),
                sleeper: &NoSleep,
            },
            Method::Get,
            None,
        )
        .await?;
        if response.is_success() {
            return TtsVoiceCatalogue::from_json(response.json()?).into_voices();
        }
        Err(crate::retry::api_error(
            Method::Get,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }
}

impl<T: Transport, A: TokenSource> std::fmt::Debug for FlowClient<T, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowClient")
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// `POST /v3/ai-flows/:aiFlowId/call` body.
///
/// ```
/// use sipgate_flow::OutboundCall;
///
/// let call = OutboundCall::new("flow-1", "e2", "+4915112345678")?;
/// assert_eq!(
///     call.to_json(),
///     serde_json::json!({"billingDevice": "e2", "toPhoneNumber": "4915112345678"})
/// );
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct OutboundCall {
    ai_flow_id: String,
    billing_device: String,
    to_phone_number: String,
}

/// `PUT`/`GET /v3/ai-webhooks` body: the single URL AI assist events are sent to.
///
/// ```
/// use sipgate_flow::AiWebhookSettings;
///
/// let settings = AiWebhookSettings::new("https://example.com/ai-flow")?;
/// assert_eq!(settings.webhook_url(), "https://example.com/ai-flow");
/// assert_eq!(settings.to_json()["webhookUrl"], "https://example.com/ai-flow");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct AiWebhookSettings {
    webhook_url: String,
}

impl std::fmt::Debug for AiWebhookSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiWebhookSettings")
            .field("webhook_url", &RedactedUrl(&self.webhook_url))
            .finish()
    }
}

impl AiWebhookSettings {
    /// Validates the webhook URL before it can reach the wire.
    ///
    /// The v3 document calls the field just `webhookUrl` and requires no secret
    /// for this endpoint, so the URL is the whole contract. This crate accepts
    /// only an absolute `https://` URL: webhook delivery over plaintext HTTP
    /// would expose the event body to the network.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookSettings;
    ///
    /// assert!(AiWebhookSettings::new("https://example.com/ai-flow").is_ok());
    /// assert!(AiWebhookSettings::new("https://example.com").is_ok());
    /// assert!(AiWebhookSettings::new("http://example.com/ai-flow").is_err());
    /// assert!(AiWebhookSettings::new("").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty, is not an absolute URL,
    /// carries credentials, contains whitespace or control characters, or does
    /// not use `https://`.
    pub fn new(webhook_url: impl Into<String>) -> Result<Self> {
        let webhook_url = webhook_url.into();
        validate::http_url("webhook_url", &webhook_url)?;
        if !webhook_url
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
        {
            return Err(Error::validation("webhook_url", "must use https://"));
        }
        Ok(Self { webhook_url })
    }

    /// The configured webhook URL.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookSettings;
    /// assert_eq!(
    ///     AiWebhookSettings::new("https://example.com/hook")?.webhook_url(),
    ///     "https://example.com/hook"
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn webhook_url(&self) -> &str {
        &self.webhook_url
    }

    /// Renders the request body exactly as the `OpenAPI` schema names it.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookSettings;
    /// assert_eq!(
    ///     AiWebhookSettings::new("https://x.test/hook")?.to_json(),
    ///     serde_json::json!({"webhookUrl": "https://x.test/hook"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "webhookUrl": self.webhook_url })
    }

    /// Reads an already-decoded response body.
    ///
    /// Both `webhookUrl` (documented) and `webhook_url` (tolerated) are
    /// accepted. A missing or empty value stays `None`: the API documents no
    /// placeholder, and `Debug` never prints the full URL.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookSettings;
    ///
    /// let settings = AiWebhookSettings::from_json(&serde_json::json!({"webhook_url": "https://x.test/hook"}));
    /// assert_eq!(settings.webhook_url(), "https://x.test/hook");
    /// assert_eq!(
    ///     AiWebhookSettings::from_json(&serde_json::json!({})).webhook_url(),
    ///     ""
    /// );
    /// ```
    #[must_use]
    pub fn from_json(value: &Value) -> Self {
        let webhook_url = value
            .get("webhookUrl")
            .or_else(|| value.get("webhook_url"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        Self { webhook_url }
    }
}

/// One entry of `GET /v3/tts/voices`.
///
/// The current v3 document models each entry as a bare voice-id string. The
/// adjacent frontdesk catalogue returns richer objects with `voiceId`, `name`,
/// `languages`, `previewUrl`, `recommended` and `beta`; this type accepts both
/// shapes so the v3 voice surface does not break when the document converges on
/// the object form.
///
/// ```
/// use sipgate_flow::TtsVoice;
///
/// let plain = TtsVoice::from_json(serde_json::json!("SIPGATE_VOICE"))?;
/// assert_eq!(plain.id(), "SIPGATE_VOICE");
/// assert_eq!(plain.name(), None);
///
/// let object = TtsVoice::from_json(serde_json::json!({
///     "voiceId": "NhQJUmAozCa7BWLiUXy",
///     "name": "Kai",
///     "languages": ["de", "en"],
///     "recommended": true,
///     "beta": false,
///     "previewUrl": "https://example.com/preview.mp3",
/// }))?;
/// assert_eq!(object.id(), "NhQJUmAozCa7BWLiUXy");
/// assert_eq!(object.languages(), ["de", "en"]);
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TtsVoice {
    id: String,
    name: Option<String>,
    languages: Vec<String>,
    preview_url: Option<String>,
    recommended: Option<bool>,
    beta: Option<bool>,
    raw: Value,
}

impl std::fmt::Debug for TtsVoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtsVoice")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("languages", &self.languages)
            .field("recommended", &self.recommended)
            .field("beta", &self.beta)
            .finish_non_exhaustive()
    }
}

impl TtsVoice {
    /// Reads either the documented string entry or the object catalogue entry.
    ///
    /// ```
    /// use sipgate_flow::TtsVoice;
    ///
    /// assert_eq!(TtsVoice::from_json(serde_json::json!("RACHEL"))?.id(), "RACHEL");
    /// assert_eq!(TtsVoice::from_json(serde_json::json!({"voiceId": "v1"}))?.name(), None);
    /// assert!(TtsVoice::from_json(serde_json::json!({})).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the entry is neither a non-empty string nor
    /// an object with a non-empty `voiceId`/`id`/`value` field.
    pub fn from_json(value: Value) -> Result<Self> {
        match value {
            Value::String(id) => {
                if id.is_empty() {
                    return Err(Error::validation(
                        "tts_voice",
                        "must carry a non-empty voice id",
                    ));
                }
                Self::from_id(id, Value::Null, None, Vec::new(), None, None, None)
            }
            Value::Object(object) => {
                let id = string_field(&object, &["voiceId", "voice_id", "id", "value"]);
                let Some(id) = id.filter(|id| !id.is_empty()) else {
                    return Err(Error::validation(
                        "tts_voice",
                        "must carry a non-empty voice id",
                    ));
                };
                let name = string_field(&object, &["name", "label"]).map(str::to_string);
                let languages = string_list_field(&object, &["languages", "language"]);
                let preview_url = string_field(&object, &["previewUrl", "preview_url"])
                    .filter(|url| !url.is_empty())
                    .map(str::to_string);
                let recommended = bool_field(&object, "recommended");
                let beta = bool_field(&object, "beta");
                Self::from_id(
                    id.to_string(),
                    Value::Object(object),
                    name,
                    languages,
                    preview_url,
                    recommended,
                    beta,
                )
            }
            _ => Err(Error::validation(
                "tts_voice",
                "must be a voice-id string or an object with a voice id",
            )),
        }
    }

    fn from_id(
        id: String,
        raw: Value,
        name: Option<String>,
        languages: Vec<String>,
        preview_url: Option<String>,
        recommended: Option<bool>,
        beta: Option<bool>,
    ) -> Result<Self> {
        if id.is_empty() {
            return Err(Error::validation(
                "tts_voice",
                "must carry a non-empty voice id",
            ));
        }
        validate::non_empty("tts_voice", &id, validate::MAX_REST_FIELD_BYTES)?;
        Ok(Self {
            id,
            name,
            languages,
            preview_url,
            recommended,
            beta,
            raw,
        })
    }

    /// The voice id callers pass to a synthesize request.
    ///
    /// ```
    /// use sipgate_flow::TtsVoice;
    /// assert_eq!(TtsVoice::from_json(serde_json::json!("ARIA"))?.id(), "ARIA");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The display name when the catalogue object carried one.
    ///
    /// ```
    /// use sipgate_flow::TtsVoice;
    /// assert_eq!(
    ///     TtsVoice::from_json(serde_json::json!({"voiceId": "v1", "name": "Kai"}))?.name(),
    ///     Some("Kai")
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The supported languages, empty for the bare string entry.
    ///
    /// ```
    /// use sipgate_flow::TtsVoice;
    /// assert_eq!(
    ///     TtsVoice::from_json(serde_json::json!({"voiceId": "v1", "languages": ["de"]}))?.languages(),
    ///     ["de"]
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn languages(&self) -> &[String] {
        &self.languages
    }

    /// The preview URL, when the catalogue object carried one.
    ///
    /// ```
    /// use sipgate_flow::TtsVoice;
    /// let voice = TtsVoice::from_json(serde_json::json!({
    ///     "voiceId": "v1",
    ///     "previewUrl": "https://example.com/a.mp3",
    /// }))?;
    /// assert_eq!(voice.preview_url(), Some("https://example.com/a.mp3"));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn preview_url(&self) -> Option<&str> {
        self.preview_url.as_deref()
    }

    /// Whether the catalogue marked the voice recommended.
    ///
    /// ```
    /// use sipgate_flow::TtsVoice;
    /// assert_eq!(
    ///     TtsVoice::from_json(serde_json::json!({"voiceId": "v1", "recommended": true}))?.recommended(),
    ///     Some(true)
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn recommended(&self) -> Option<bool> {
        self.recommended
    }

    /// Whether the catalogue marked the voice beta.
    ///
    /// ```
    /// use sipgate_flow::TtsVoice;
    /// assert_eq!(
    ///     TtsVoice::from_json(serde_json::json!({"voiceId": "v1", "beta": true}))?.beta(),
    ///     Some(true)
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn beta(&self) -> Option<bool> {
        self.beta
    }

    /// The original catalogue entry, for fields this crate does not model.
    ///
    /// ```
    /// use sipgate_flow::TtsVoice;
    /// let voice = TtsVoice::from_json(serde_json::json!({"voiceId": "v1", "vendor": "x"}))?;
    /// assert_eq!(voice.raw()["vendor"], "x");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn raw(&self) -> &Value {
        &self.raw
    }
}

/// Reads `{"items": [...]}` from `GET /v3/tts/voices`, tolerating catalogues
/// that carry bare ids or object entries.
#[derive(Deserialize)]
struct TtsVoiceCatalogue {
    #[serde(default)]
    items: Vec<Value>,
}

impl TtsVoiceCatalogue {
    fn from_json(value: Value) -> Self {
        serde_json::from_value(value).unwrap_or(Self { items: Vec::new() })
    }

    fn into_voices(self) -> Result<Vec<TtsVoice>> {
        let mut voices = Vec::with_capacity(self.items.len());
        for item in self.items {
            voices.push(TtsVoice::from_json(item)?);
        }
        if voices.is_empty() {
            return Err(Error::validation(
                "tts_voices",
                "must contain at least one voice",
            ));
        }
        Ok(voices)
    }
}

fn string_field<'a>(object: &'a Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_str))
}

fn string_list_field(object: &Map<String, Value>, names: &[&str]) -> Vec<String> {
    for name in names {
        match object.get(*name) {
            Some(Value::Array(values)) => {
                return values
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            Some(Value::String(value)) if !value.is_empty() => return vec![value.clone()],
            _ => {}
        }
    }
    Vec::new()
}

fn bool_field(object: &Map<String, Value>, name: &str) -> Option<bool> {
    object.get(name).and_then(Value::as_bool)
}

impl std::fmt::Debug for OutboundCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundCall")
            .field("ai_flow_id", &self.ai_flow_id)
            .field("billing_device", &self.billing_device)
            .field(
                "to_phone_number",
                &masked_phone_number(&self.to_phone_number),
            )
            .finish()
    }
}

impl OutboundCall {
    /// Builds the request.
    ///
    /// ```
    /// use sipgate_flow::OutboundCall;
    ///
    /// assert!(OutboundCall::new("flow-1", "e2", "4915112345678").is_ok());
    /// assert!(OutboundCall::new("", "e2", "4915112345678").is_err());
    /// assert!(OutboundCall::new("flow-1", "", "4915112345678").is_err());
    /// assert!(OutboundCall::new("flow-1", "E2", "4915112345678").is_err());
    /// assert!(OutboundCall::new("flow-1", "e2", "0151 1234").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] for an empty or path-unsafe Flow id, a
    /// billing device outside the documented short suffix shape, or a number
    /// that is not E.164 digits.
    pub fn new(
        ai_flow_id: impl Into<String>,
        billing_device: impl Into<String>,
        to_phone_number: impl Into<String>,
    ) -> Result<Self> {
        let ai_flow_id = ai_flow_id.into();
        validate::ai_flow_id("ai_flow_id", &ai_flow_id)?;
        let billing_device = billing_device.into();
        validate::billing_device("billing_device", &billing_device)?;
        let digits = validate::phone("to_phone_number", &to_phone_number.into())?;
        Ok(Self {
            ai_flow_id,
            billing_device,
            // The documentation says the leading `+` is optional and added
            // automatically when missing, so the digits go out unchanged.
            to_phone_number: digits,
        })
    }

    /// The Flow id used in the path.
    ///
    /// ```
    /// use sipgate_flow::OutboundCall;
    /// assert_eq!(OutboundCall::new("flow-1", "e2", "4915112345678")?.ai_flow_id(), "flow-1");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn ai_flow_id(&self) -> &str {
        &self.ai_flow_id
    }

    /// The billing device suffix, provided by sipgate during onboarding.
    ///
    /// The value is validated on construction as an ASCII lowercase letter
    /// followed by at most seven more lowercase letters or digits. sipgate
    /// documents it as a short suffix such as `e2` whose `masterSipId` is
    /// prepended automatically, so a small explicit cap is enough and keeps
    /// control characters, whitespace and unicode out of the request body.
    ///
    /// ```
    /// use sipgate_flow::OutboundCall;
    /// assert_eq!(OutboundCall::new("f", "e2", "4915112345678")?.billing_device(), "e2");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn billing_device(&self) -> &str {
        &self.billing_device
    }

    /// The target number, digits only.
    ///
    /// ```
    /// use sipgate_flow::OutboundCall;
    /// assert_eq!(OutboundCall::new("f", "e2", "+4915112345678")?.to_phone_number(), "4915112345678");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_phone_number(&self) -> &str {
        &self.to_phone_number
    }

    /// Renders the request body.
    ///
    /// ```
    /// use sipgate_flow::OutboundCall;
    /// assert_eq!(OutboundCall::new("f", "e2", "4915112345678")?.to_json()["billingDevice"], "e2");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "billingDevice": self.billing_device,
            "toPhoneNumber": self.to_phone_number,
        })
    }
}

/// The `201 Created` body of `POST /v3/ai-flows/{aiFlowId}/call`.
///
/// The v3 `OpenAPI` document defines it as `InitiateOutboundCallResponseDto`
/// with a required `callSid` (`pbx-c-…`), sipgate's `PBXCore` call identifier.
/// Decoding stays permissive: an empty or absent `callSid` is represented as
/// `None` rather than failing, because the call *did* start — the identifier is
/// for logging, not for control flow.
///
/// ```
/// use sipgate_flow::OutboundCallReceipt;
///
/// let receipt = OutboundCallReceipt::parse(br#"{"callSid":"pbx-c-ffff"}"#)?;
/// assert_eq!(receipt.call_sid(), Some("pbx-c-ffff"));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct OutboundCallReceipt {
    call_sid: Option<String>,
    raw: Value,
}

impl std::fmt::Debug for OutboundCallReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundCallReceipt")
            .field("call_sid", &self.call_sid)
            .field("raw", &RedactedRaw(&self.raw))
            .finish()
    }
}

impl OutboundCallReceipt {
    /// Decodes the body bytes.
    ///
    /// ```
    /// use sipgate_flow::OutboundCallReceipt;
    ///
    /// assert!(OutboundCallReceipt::parse(br#"{"callSid":"c1"}"#).is_ok());
    /// assert!(OutboundCallReceipt::parse(b"").is_err());
    /// // Anything that parses is accepted; only the call id is then missing.
    /// assert_eq!(OutboundCallReceipt::parse(b"[]").ok().and_then(|r| r.call_sid().map(str::to_string)), None);
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Json`] when the body is not JSON at all. A body that
    /// parses but is not the documented object is tolerated, because the call
    /// did start either way.
    pub fn parse(body: &[u8]) -> Result<Self> {
        Ok(Self::from_json(
            serde_json::from_slice(body).map_err(Error::json_parse)?,
        ))
    }

    /// Reads an already-decoded body.
    ///
    /// Both `callSid` (documented) and `call_sid` (tolerated) are accepted; an
    /// empty string counts as absent.
    ///
    /// ```
    /// use sipgate_flow::OutboundCallReceipt;
    ///
    /// let receipt = OutboundCallReceipt::from_json(serde_json::json!({"call_sid": "c2"}));
    /// assert_eq!(receipt.call_sid(), Some("c2"));
    /// assert_eq!(receipt.raw()["call_sid"], "c2");
    /// ```
    #[must_use]
    pub fn from_json(value: Value) -> Self {
        let call_sid = value
            .get("callSid")
            .or_else(|| value.get("call_sid"))
            .and_then(Value::as_str)
            .filter(|sid| !sid.is_empty())
            .map(str::to_string);
        Self {
            call_sid,
            raw: value,
        }
    }

    /// The `PBXCore` call identifier, when the body carried one.
    ///
    /// ```
    /// use sipgate_flow::OutboundCallReceipt;
    ///
    /// assert_eq!(OutboundCallReceipt::from_json(serde_json::json!({})).call_sid(), None);
    /// ```
    #[must_use]
    pub fn call_sid(&self) -> Option<&str> {
        self.call_sid.as_deref()
    }

    /// The body exactly as received, for fields this crate does not model.
    ///
    /// ```
    /// use sipgate_flow::OutboundCallReceipt;
    ///
    /// let receipt = OutboundCallReceipt::from_json(serde_json::json!({"callSid": "c1", "x": 1}));
    /// assert_eq!(receipt.raw()["x"], 1);
    /// ```
    #[must_use]
    pub fn raw(&self) -> &Value {
        &self.raw
    }
}

/// A phone number for `Debug` output: keep a short prefix and the last four
/// digits, masking the middle with the same style as error bodies.
fn masked_phone_number(number: &str) -> String {
    const PREFIX: usize = 3;
    const SUFFIX: usize = 4;
    const MASK: &str = "****";

    let prefix_len = PREFIX.min(number.len().saturating_sub(SUFFIX + 1));
    let suffix_start = number.len().saturating_sub(SUFFIX);
    format!(
        "+{}{MASK}{}",
        &number[..prefix_len],
        &number[suffix_start..]
    )
}

/// The raw response body as it may appear in `Debug`: only its serialized size.
struct RedactedRaw<'a>(&'a Value);

impl fmt::Debug for RedactedRaw<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", json_byte_len(self.0))
    }
}

/// A webhook URL as it may appear in `Debug`: never the whole destination.
struct RedactedUrl<'a>(&'a str);

impl fmt::Debug for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match url::Url::parse(self.0) {
            Ok(url) => write!(
                f,
                "{}://{}/<redacted>",
                url.scheme(),
                url.host_str().unwrap_or("")
            ),
            Err(_) => write!(f, "<redacted url>"),
        }
    }
}

/// Counts serialized JSON bytes without allocating the serialized payload.
fn json_byte_len(value: &Value) -> usize {
    let mut counter = JsonByteCounter(0);
    match serde_json::to_writer(&mut counter, value) {
        Ok(()) | Err(_) => counter.0,
    }
}

struct JsonByteCounter(usize);

impl std::io::Write for JsonByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
