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

    /// Removes the account's AI-assist webhook URL:
    /// `DELETE /v3/ai-webhooks`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.delete_ai_webhook().await?; // 204
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The generic transport, auth and API errors. A documented `404` (no
    /// webhook configured) is returned as [`crate::Error::Api`]. `DELETE` is
    /// idempotent, so a retryable non-2xx answer is reported on
    /// [`crate::Error::Api`] rather than [`crate::Error::Ambiguous`].
    pub async fn delete_ai_webhook(&self) -> Result<()> {
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
            Method::Delete,
            None,
        )
        .await?;
        if response.is_success() {
            return Ok(());
        }
        Err(crate::retry::api_error(
            Method::Delete,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Lists the account's AI webhook configurations:
    /// `GET /v3/webhooks`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// for config in client.ai_webhook_configs().await? {
    ///     println!("{:?}", config.name());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Json`] when the success body is not a JSON array of
    /// webhook configs, plus the generic transport, auth and API errors.
    pub async fn ai_webhook_configs(&self) -> Result<Vec<AiWebhookConfig>> {
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/webhooks",
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
            return AiWebhookConfig::list_from_json(response.json()?);
        }
        Err(crate::retry::api_error(
            Method::Get,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Creates an AI webhook configuration: `POST /v3/webhooks`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{AiWebhookConfig, FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let request = AiWebhookConfig::new("prod", true, ["https://example.com/wh"], ["e2"])?;
    /// let created = client.create_ai_webhook_config(&request).await?;
    /// println!("{:?}", created.webhook_id());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the request is built with an invalid
    /// URL or entity id, [`crate::Error::Json`] when the success body is not a
    /// JSON config, plus the generic transport, auth and API errors. A `POST`
    /// is not idempotent, so a retryable `5xx` outcome is reported as
    /// [`crate::Error::Ambiguous`].
    pub async fn create_ai_webhook_config(
        &self,
        request: &AiWebhookConfig,
    ) -> Result<AiWebhookConfig> {
        request.validate_request()?;
        let body = request.to_request_json();
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/webhooks",
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
        if response.is_success() {
            return AiWebhookConfig::from_json(response.json()?);
        }
        Err(crate::retry::api_error(
            Method::Post,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Replaces an AI webhook configuration:
    /// `PUT /v3/webhooks/{configId}`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{AiWebhookConfig, FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let request = AiWebhookConfig::new("prod", true, ["https://example.com/wh"], ["e2"])?;
    /// let updated = client.replace_ai_webhook_config("48f1e8a8-5e4c-4d2f-8f04-1c2a97a4c3de", &request).await?;
    /// println!("{:?}", updated.headers());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when `config_id` is not a UUID or the
    /// request is invalid, [`crate::Error::Json`] when the success body is not
    /// a JSON config, plus the generic transport, auth and API errors.
    pub async fn replace_ai_webhook_config(
        &self,
        config_id: impl Into<String>,
        request: &AiWebhookConfig,
    ) -> Result<AiWebhookConfig> {
        let config_id = config_id.into();
        validate_webhook_config_id("config_id", &config_id)?;
        request.validate_request()?;
        let path = format!("/v3/webhooks/{config_id}");
        let body = request.to_request_json();
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
            Method::Put,
            Some(&body),
        )
        .await?;
        if response.is_success() {
            return AiWebhookConfig::from_json(response.json()?);
        }
        Err(crate::retry::api_error(
            Method::Put,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Deletes an AI webhook configuration:
    /// `DELETE /v3/webhooks/{configId}`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.delete_ai_webhook_config("48f1e8a8-5e4c-4d2f-8f04-1c2a97a4c3de").await?; // 204
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when `config_id` is not a UUID, plus the
    /// generic transport, auth and API errors. `DELETE` is idempotent, so a
    /// retryable non-2xx answer is reported on [`crate::Error::Api`].
    pub async fn delete_ai_webhook_config(&self, config_id: impl Into<String>) -> Result<()> {
        let config_id = config_id.into();
        validate_webhook_config_id("config_id", &config_id)?;
        let path = format!("/v3/webhooks/{config_id}");
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
            Method::Delete,
            None,
        )
        .await?;
        if response.is_success() {
            return Ok(());
        }
        Err(crate::retry::api_error(
            Method::Delete,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Adds a custom header to an AI webhook configuration:
    /// `POST /v3/webhooks/{configId}/headers`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{AiWebhookHeader, FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let header = AiWebhookHeader::new("X-API-Key", "secret")?;
    /// let created = client.add_ai_webhook_header("48f1e8a8-5e4c-4d2f-8f04-1c2a97a4c3de", &header).await?;
    /// println!("{:?}", created.value());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when `config_id` is not a UUID or the
    /// header is invalid, [`crate::Error::Json`] when the success body is not a
    /// JSON header, plus the generic transport, auth and API errors. A `POST`
    /// is not idempotent, so a retryable `5xx` outcome is reported as
    /// [`crate::Error::Ambiguous`].
    pub async fn add_ai_webhook_header(
        &self,
        config_id: impl Into<String>,
        header: &AiWebhookHeader,
    ) -> Result<AiWebhookHeader> {
        let config_id = config_id.into();
        validate_webhook_config_id("config_id", &config_id)?;
        header.validate_request()?;
        let path = format!("/v3/webhooks/{config_id}/headers");
        let body = header.to_json();
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
        if response.is_success() {
            let value = response.json()?;
            return AiWebhookHeader::from_json(&value);
        }
        Err(crate::retry::api_error(
            Method::Post,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Removes a custom header from an AI webhook configuration:
    /// `DELETE /v3/webhooks/{configId}/headers/{headerName}`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.delete_ai_webhook_header("48f1e8a8-5e4c-4d2f-8f04-1c2a97a4c3de", "X-API-Key").await?; // 204
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when `config_id` is not a UUID or
    /// `header_name` is not a valid custom header name, plus the generic
    /// transport, auth and API errors. `DELETE` is idempotent, so a retryable
    /// non-2xx answer is reported on [`crate::Error::Api`].
    pub async fn delete_ai_webhook_header(
        &self,
        config_id: impl Into<String>,
        header_name: impl AsRef<str>,
    ) -> Result<()> {
        let config_id = config_id.into();
        validate_webhook_config_id("config_id", &config_id)?;
        let header_name = header_name.as_ref();
        validate_webhook_header_name("header_name", header_name)?;
        let path = format!("/v3/webhooks/{config_id}/headers/{header_name}");
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
            Method::Delete,
            None,
        )
        .await?;
        if response.is_success() {
            return Ok(());
        }
        Err(crate::retry::api_error(
            Method::Delete,
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

    // -------------------------------------------------------------------
    // v3 account administration (#170)
    //
    // A bounded slice of the documented v3 account-settings resource: the
    // privacy announcement played for recorded and transcribed calls, and the
    // caller ID used when transferring a call. These are the three
    // `/account-settings/*` families the v3 document marks as account level.
    // -------------------------------------------------------------------

    /// Reads which privacy announcement plays for recorded calls:
    /// `GET /v3/account-settings/privacyAnnouncements/recording`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let mode = client.recording_announcement_mode().await?;
    /// println!("{}", mode.as_str());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Json`] when the success body is not JSON, plus the
    /// generic transport, auth and API errors. An unknown `mode` value is kept
    /// in [`RecordingAnnouncementMode::Other`] instead of failing the decode.
    pub async fn recording_announcement_mode(&self) -> Result<RecordingAnnouncementMode> {
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/account-settings/privacyAnnouncements/recording",
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
            return RecordingAnnouncementMode::from_json(&response.json()?);
        }
        Err(crate::retry::api_error(
            Method::Get,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Sets which privacy announcement plays for recorded calls:
    /// `PUT /v3/account-settings/privacyAnnouncements/recording`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken, RecordingAnnouncementMode};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.set_recording_announcement_mode(&RecordingAnnouncementMode::InformOnly).await?; // 204
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when an unmodelled
    /// [`RecordingAnnouncementMode::Other`] value is not a plausible wire token,
    /// plus the generic transport, auth and API errors. The replacement is
    /// idempotent, so a retryable non-2xx answer is reported on
    /// [`crate::Error::Api`] rather than [`crate::Error::Ambiguous`].
    pub async fn set_recording_announcement_mode(
        &self,
        mode: &RecordingAnnouncementMode,
    ) -> Result<()> {
        mode.validate()?;
        let body = mode.to_json();
        self.put_account_setting("/v3/account-settings/privacyAnnouncements/recording", &body)
            .await
    }

    /// Reads which privacy announcement plays for transcribed calls:
    /// `GET /v3/account-settings/privacyAnnouncements/transcription`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let mode = client.transcription_announcement_mode().await?;
    /// println!("{}", mode.as_str());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Json`] when the success body is not JSON, plus the
    /// generic transport, auth and API errors. An unknown `mode` value is kept
    /// in [`TranscriptionAnnouncementMode::Other`] instead of failing.
    pub async fn transcription_announcement_mode(&self) -> Result<TranscriptionAnnouncementMode> {
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/account-settings/privacyAnnouncements/transcription",
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
            return TranscriptionAnnouncementMode::from_json(&response.json()?);
        }
        Err(crate::retry::api_error(
            Method::Get,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Sets which privacy announcement plays for transcribed calls:
    /// `PUT /v3/account-settings/privacyAnnouncements/transcription`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken, TranscriptionAnnouncementMode};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.set_transcription_announcement_mode(&TranscriptionAnnouncementMode::Disabled).await?; // 204
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when an unmodelled
    /// [`TranscriptionAnnouncementMode::Other`] value is not a plausible wire
    /// token, plus the generic transport, auth and API errors.
    pub async fn set_transcription_announcement_mode(
        &self,
        mode: &TranscriptionAnnouncementMode,
    ) -> Result<()> {
        mode.validate()?;
        let body = mode.to_json();
        self.put_account_setting(
            "/v3/account-settings/privacyAnnouncements/transcription",
            &body,
        )
        .await
    }

    /// Reads which caller ID is used when transferring calls:
    /// `GET /v3/account-settings/transferCallerId`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let source = client.transfer_caller_id().await?;
    /// println!("{}", source.as_str());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Json`] when the success body is not JSON, plus the
    /// generic transport, auth and API errors. An unknown `source` value is
    /// kept in [`TransferCallerIdSource::Other`] instead of failing.
    pub async fn transfer_caller_id(&self) -> Result<TransferCallerIdSource> {
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/account-settings/transferCallerId",
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
            return TransferCallerIdSource::from_json(&response.json()?);
        }
        Err(crate::retry::api_error(
            Method::Get,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Sets which caller ID is used when transferring calls:
    /// `PUT /v3/account-settings/transferCallerId`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken, TransferCallerIdSource};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.set_transfer_caller_id(&TransferCallerIdSource::TransferredParty).await?; // 204
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when an unmodelled
    /// [`TransferCallerIdSource::Other`] value is not a plausible wire token,
    /// plus the generic transport, auth and API errors.
    pub async fn set_transfer_caller_id(&self, source: &TransferCallerIdSource) -> Result<()> {
        source.validate()?;
        let body = source.to_json();
        self.put_account_setting("/v3/account-settings/transferCallerId", &body)
            .await
    }

    /// Reads the account's call-event retention setting:
    /// `GET /v3/analytics/call-events/settings/retention`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let settings = client.account_retention().await?;
    /// println!("{:?}", settings.event_retention_days());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Json`] when the success body is not JSON, plus the
    /// generic transport, auth and API errors. A `null` retention value is the
    /// documented "keep indefinitely" answer and decodes to `None`, not an
    /// error.
    pub async fn account_retention(&self) -> Result<AccountRetentionSettings> {
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/analytics/call-events/settings/retention",
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
            return Ok(AccountRetentionSettings::from_json(&response.json()?));
        }
        Err(crate::retry::api_error(
            Method::Get,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Replaces the account's call-event retention setting:
    /// `PUT /v3/analytics/call-events/settings/retention`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, SetAccountRetentionSettings, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let request = SetAccountRetentionSettings::new(90)?;
    /// client.set_account_retention(&request).await?; // 204
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the already-constructed request is
    /// somehow out of range (the type cannot be built out of range), plus the
    /// generic transport, auth and API errors. The replacement is idempotent.
    pub async fn set_account_retention(&self, request: &SetAccountRetentionSettings) -> Result<()> {
        let body = request.to_json();
        self.put_account_setting("/v3/analytics/call-events/settings/retention", &body)
            .await
    }

    /// Removes the account's call-event retention policy, keeping call events
    /// indefinitely: `DELETE /v3/analytics/call-events/settings/retention`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.clear_account_retention().await?; // 204
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The generic transport, auth and API errors. `DELETE` is idempotent, so a
    /// retryable non-2xx answer is reported on [`crate::Error::Api`].
    pub async fn clear_account_retention(&self) -> Result<()> {
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/analytics/call-events/settings/retention",
            },
            exchange::Pacing {
                timeout: self.timeout,
                retry: &RetryPolicy::none(),
                sleeper: &NoSleep,
            },
            Method::Delete,
            None,
        )
        .await?;
        if response.is_success() {
            return Ok(());
        }
        Err(crate::retry::api_error(
            Method::Delete,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Sends one idempotent account-setting replacement and requires the
    /// documented `204 No Content`.
    async fn put_account_setting(&self, path: &str, body: &Value) -> Result<()> {
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path,
            },
            exchange::Pacing {
                timeout: self.timeout,
                retry: &RetryPolicy::none(),
                sleeper: &NoSleep,
            },
            Method::Put,
            Some(body),
        )
        .await?;
        if response.is_success() {
            return Ok(());
        }
        Err(crate::retry::api_error(
            Method::Put,
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

// ===================================================================
// v3 account administration (#170)
//
// Types for the `/v3/account-settings/*` families modelled above and the
// account-level call-event retention setting. Kept in one clearly delimited
// block so the surrounding v3 client (AI webhooks, TTS, and the parallel TTS
// synthesis work) stays easy to extend.
// ===================================================================

/// Longest unmodelled account-setting wire token accepted before sending.
///
/// The v3 document enumerates the values this crate models; a caller can still
/// carry a value from a newer document as `Other`. The cap keeps that
/// forward-compatible value a small, single wire token instead of an
/// unbounded string.
pub const MAX_ACCOUNT_SETTING_TOKEN_BYTES: usize = 64;

/// Which privacy announcement plays for recorded calls:
/// `GET`/`PUT /v3/account-settings/privacyAnnouncements/recording`.
///
/// ```
/// use sipgate_flow::RecordingAnnouncementMode;
///
/// assert_eq!(
///     RecordingAnnouncementMode::from_wire("OPT_OUT"),
///     RecordingAnnouncementMode::OptOut
/// );
/// assert_eq!(
///     RecordingAnnouncementMode::from_wire("FUTURE_MODE").as_str(),
///     "FUTURE_MODE"
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordingAnnouncementMode {
    /// Callers hear an announcement that the call is being recorded.
    InformOnly,
    /// Callers hear an announcement and can opt out of the recording.
    OptOut,
    /// A value this crate does not model yet, kept verbatim.
    Other(String),
}

impl RecordingAnnouncementMode {
    /// Maps a wire value, keeping unknown values verbatim.
    ///
    /// ```
    /// use sipgate_flow::RecordingAnnouncementMode;
    ///
    /// assert_eq!(
    ///     RecordingAnnouncementMode::from_wire("inform_only"),
    ///     RecordingAnnouncementMode::InformOnly
    /// );
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "INFORM_ONLY" => Self::InformOnly,
            "OPT_OUT" => Self::OptOut,
            _ => Self::Other(value.to_string()),
        }
    }

    /// The canonical wire value.
    ///
    /// ```
    /// use sipgate_flow::RecordingAnnouncementMode;
    ///
    /// assert_eq!(RecordingAnnouncementMode::OptOut.as_str(), "OPT_OUT");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::InformOnly => "INFORM_ONLY",
            Self::OptOut => "OPT_OUT",
            Self::Other(value) => value,
        }
    }

    /// Reads the documented `{"mode": "..."}` response body.
    ///
    /// Unknown `mode` values are carried as [`Self::Other`].
    ///
    /// ```
    /// use sipgate_flow::RecordingAnnouncementMode;
    ///
    /// let mode = RecordingAnnouncementMode::from_json(&serde_json::json!({"mode": "OPT_OUT"}))?;
    /// assert_eq!(mode, RecordingAnnouncementMode::OptOut);
    /// assert!(RecordingAnnouncementMode::from_json(&serde_json::json!({})).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `mode` is absent, not a string, or empty.
    pub fn from_json(value: &Value) -> Result<Self> {
        let mode = value
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if mode.is_empty() {
            return Err(Error::validation(
                "recording_announcement_mode",
                "response must carry a non-empty `mode`",
            ));
        }
        Ok(Self::from_wire(mode))
    }

    /// Renders the request body exactly as the `OpenAPI` schema names it.
    ///
    /// ```
    /// use sipgate_flow::RecordingAnnouncementMode;
    ///
    /// assert_eq!(
    ///     RecordingAnnouncementMode::InformOnly.to_json()["mode"],
    ///     "INFORM_ONLY"
    /// );
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "mode": self.as_str() })
    }

    /// Rejects an unmodelled value that is not a plausible wire token.
    ///
    /// ```
    /// use sipgate_flow::RecordingAnnouncementMode;
    ///
    /// assert!(RecordingAnnouncementMode::OptOut.validate().is_ok());
    /// assert!(RecordingAnnouncementMode::Other("FUTURE_MODE".into()).validate().is_ok());
    /// assert!(RecordingAnnouncementMode::Other(String::new()).validate().is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when an unmodelled value is empty, longer than
    /// [`MAX_ACCOUNT_SETTING_TOKEN_BYTES`], or contains anything other than
    /// ASCII letters, digits and underscores.
    pub fn validate(&self) -> Result<()> {
        if let Self::Other(value) = self {
            validate_wire_token("recording_announcement_mode", value)?;
        }
        Ok(())
    }
}

/// Which privacy announcement plays for transcribed calls:
/// `GET`/`PUT /v3/account-settings/privacyAnnouncements/transcription`.
///
/// ```
/// use sipgate_flow::TranscriptionAnnouncementMode;
///
/// assert_eq!(
///     TranscriptionAnnouncementMode::from_wire("NONE"),
///     TranscriptionAnnouncementMode::Disabled
/// );
/// assert_eq!(TranscriptionAnnouncementMode::InformOnly.as_str(), "INFORM_ONLY");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TranscriptionAnnouncementMode {
    /// Callers hear an announcement that the call is being transcribed.
    InformOnly,
    /// No announcement is played for transcribed calls.
    Disabled,
    /// A value this crate does not model yet, kept verbatim.
    Other(String),
}

impl TranscriptionAnnouncementMode {
    /// Maps a wire value, keeping unknown values verbatim.
    ///
    /// ```
    /// use sipgate_flow::TranscriptionAnnouncementMode;
    ///
    /// assert_eq!(
    ///     TranscriptionAnnouncementMode::from_wire("none"),
    ///     TranscriptionAnnouncementMode::Disabled
    /// );
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "INFORM_ONLY" => Self::InformOnly,
            "NONE" => Self::Disabled,
            _ => Self::Other(value.to_string()),
        }
    }

    /// The canonical wire value.
    ///
    /// ```
    /// use sipgate_flow::TranscriptionAnnouncementMode;
    ///
    /// assert_eq!(TranscriptionAnnouncementMode::Disabled.as_str(), "NONE");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::InformOnly => "INFORM_ONLY",
            Self::Disabled => "NONE",
            Self::Other(value) => value,
        }
    }

    /// Reads the documented `{"mode": "..."}` response body.
    ///
    /// ```
    /// use sipgate_flow::TranscriptionAnnouncementMode;
    ///
    /// let mode = TranscriptionAnnouncementMode::from_json(
    ///     &serde_json::json!({"mode": "NONE", "future": 1}),
    /// )?;
    /// assert_eq!(mode, TranscriptionAnnouncementMode::Disabled);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `mode` is absent, not a string, or empty.
    pub fn from_json(value: &Value) -> Result<Self> {
        let mode = value
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if mode.is_empty() {
            return Err(Error::validation(
                "transcription_announcement_mode",
                "response must carry a non-empty `mode`",
            ));
        }
        Ok(Self::from_wire(mode))
    }

    /// Renders the request body exactly as the `OpenAPI` schema names it.
    ///
    /// ```
    /// use sipgate_flow::TranscriptionAnnouncementMode;
    ///
    /// assert_eq!(
    ///     TranscriptionAnnouncementMode::Disabled.to_json()["mode"],
    ///     "NONE"
    /// );
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "mode": self.as_str() })
    }

    /// Rejects an unmodelled value that is not a plausible wire token.
    ///
    /// ```
    /// use sipgate_flow::TranscriptionAnnouncementMode;
    ///
    /// assert!(TranscriptionAnnouncementMode::Disabled.validate().is_ok());
    /// assert!(TranscriptionAnnouncementMode::Other("FUTURE_MODE".into()).validate().is_ok());
    /// assert!(TranscriptionAnnouncementMode::Other("has space".into()).validate().is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when an unmodelled value is empty, longer than
    /// [`MAX_ACCOUNT_SETTING_TOKEN_BYTES`], or contains anything other than
    /// ASCII letters, digits and underscores.
    pub fn validate(&self) -> Result<()> {
        if let Self::Other(value) = self {
            validate_wire_token("transcription_announcement_mode", value)?;
        }
        Ok(())
    }
}

/// Which party's number is shown as caller ID when transferring a call:
/// `GET`/`PUT /v3/account-settings/transferCallerId`.
///
/// ```
/// use sipgate_flow::TransferCallerIdSource;
///
/// assert_eq!(
///     TransferCallerIdSource::from_wire("TRANSFERRED_PARTY"),
///     TransferCallerIdSource::TransferredParty
/// );
/// assert_eq!(
///     TransferCallerIdSource::TransferringParty.as_str(),
///     "TRANSFERRING_PARTY"
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferCallerIdSource {
    /// Show the number of the party the call is transferred to.
    TransferredParty,
    /// Show the number of the party that transfers the call.
    TransferringParty,
    /// A value this crate does not model yet, kept verbatim.
    Other(String),
}

impl TransferCallerIdSource {
    /// Maps a wire value, keeping unknown values verbatim.
    ///
    /// ```
    /// use sipgate_flow::TransferCallerIdSource;
    ///
    /// assert_eq!(
    ///     TransferCallerIdSource::from_wire("transferring_party"),
    ///     TransferCallerIdSource::TransferringParty
    /// );
    /// ```
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "TRANSFERRED_PARTY" => Self::TransferredParty,
            "TRANSFERRING_PARTY" => Self::TransferringParty,
            _ => Self::Other(value.to_string()),
        }
    }

    /// The canonical wire value.
    ///
    /// ```
    /// use sipgate_flow::TransferCallerIdSource;
    ///
    /// assert_eq!(
    ///     TransferCallerIdSource::TransferredParty.as_str(),
    ///     "TRANSFERRED_PARTY"
    /// );
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::TransferredParty => "TRANSFERRED_PARTY",
            Self::TransferringParty => "TRANSFERRING_PARTY",
            Self::Other(value) => value,
        }
    }

    /// Reads the documented `{"source": "..."}` response body.
    ///
    /// ```
    /// use sipgate_flow::TransferCallerIdSource;
    ///
    /// let source = TransferCallerIdSource::from_json(
    ///     &serde_json::json!({"source": "TRANSFERRING_PARTY"}),
    /// )?;
    /// assert_eq!(source, TransferCallerIdSource::TransferringParty);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `source` is absent, not a string, or empty.
    pub fn from_json(value: &Value) -> Result<Self> {
        let source = value
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if source.is_empty() {
            return Err(Error::validation(
                "transfer_caller_id_source",
                "response must carry a non-empty `source`",
            ));
        }
        Ok(Self::from_wire(source))
    }

    /// Renders the request body exactly as the `OpenAPI` schema names it.
    ///
    /// ```
    /// use sipgate_flow::TransferCallerIdSource;
    ///
    /// assert_eq!(
    ///     TransferCallerIdSource::TransferredParty.to_json()["source"],
    ///     "TRANSFERRED_PARTY"
    /// );
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "source": self.as_str() })
    }

    /// Rejects an unmodelled value that is not a plausible wire token.
    ///
    /// ```
    /// use sipgate_flow::TransferCallerIdSource;
    ///
    /// assert!(TransferCallerIdSource::TransferredParty.validate().is_ok());
    /// assert!(TransferCallerIdSource::Other("FUTURE_SOURCE".into()).validate().is_ok());
    /// assert!(TransferCallerIdSource::Other(String::new()).validate().is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when an unmodelled value is empty, longer than
    /// [`MAX_ACCOUNT_SETTING_TOKEN_BYTES`], or contains anything other than
    /// ASCII letters, digits and underscores.
    pub fn validate(&self) -> Result<()> {
        if let Self::Other(value) = self {
            validate_wire_token("transfer_caller_id_source", value)?;
        }
        Ok(())
    }
}

/// Shortest call-event retention accepted by
/// `PUT /v3/analytics/call-events/settings/retention` (the schema's exclusive
/// minimum of `0`).
pub const MIN_EVENT_RETENTION_DAYS: u32 = 1;

/// Longest call-event retention accepted by the same endpoint (the schema's
/// inclusive maximum).
pub const MAX_EVENT_RETENTION_DAYS: u32 = 36_500;

/// The account's call-event retention setting:
/// `GET`/`DELETE /v3/analytics/call-events/settings/retention`.
///
/// The documented response is `{"eventRetentionDays": <days|null>}`. A `null`
/// (or absent) value means call events are kept indefinitely, modelled here as
/// [`Self::event_retention_days`] returning `None`.
///
/// ```
/// use sipgate_flow::AccountRetentionSettings;
///
/// let settings = AccountRetentionSettings::from_json(
///     &serde_json::json!({"eventRetentionDays": 90}),
/// );
/// assert_eq!(settings.event_retention_days(), Some(90));
///
/// let infinite = AccountRetentionSettings::from_json(&serde_json::json!({}));
/// assert_eq!(infinite.event_retention_days(), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct AccountRetentionSettings {
    event_retention_days: Option<u32>,
}

impl AccountRetentionSettings {
    /// Reads the documented response body, tolerating `event_retention_days`
    /// as an alias.
    ///
    /// ```
    /// use sipgate_flow::AccountRetentionSettings;
    ///
    /// assert_eq!(
    ///     AccountRetentionSettings::from_json(
    ///         &serde_json::json!({"event_retention_days": 7, "future": true}),
    ///     )
    ///     .event_retention_days(),
    ///     Some(7)
    /// );
    /// assert_eq!(
    ///     AccountRetentionSettings::from_json(&serde_json::json!({"eventRetentionDays": null}))
    ///         .event_retention_days(),
    ///     None
    /// );
    /// ```
    #[must_use]
    pub fn from_json(value: &Value) -> Self {
        let days = value
            .get("eventRetentionDays")
            .or_else(|| value.get("event_retention_days"))
            .and_then(Value::as_u64)
            .and_then(|days| u32::try_from(days).ok());
        Self {
            event_retention_days: days,
        }
    }

    /// The configured retention in days, or `None` for "keep indefinitely".
    ///
    /// ```
    /// use sipgate_flow::AccountRetentionSettings;
    ///
    /// assert_eq!(
    ///     AccountRetentionSettings::from_json(&serde_json::json!({"eventRetentionDays": 365}))
    ///         .event_retention_days(),
    ///     Some(365)
    /// );
    /// ```
    #[must_use]
    pub fn event_retention_days(&self) -> Option<u32> {
        self.event_retention_days
    }
}

/// The request body of
/// `PUT /v3/analytics/call-events/settings/retention`: the number of days call
/// events are retained.
///
/// ```
/// use sipgate_flow::{SetAccountRetentionSettings, MAX_EVENT_RETENTION_DAYS};
///
/// let request = SetAccountRetentionSettings::new(90)?;
/// assert_eq!(request.event_retention_days(), 90);
/// assert_eq!(request.to_json()["eventRetentionDays"], 90);
///
/// assert!(SetAccountRetentionSettings::new(0).is_err());
/// assert!(SetAccountRetentionSettings::new(MAX_EVENT_RETENTION_DAYS).is_ok());
/// assert!(SetAccountRetentionSettings::new(MAX_EVENT_RETENTION_DAYS + 1).is_err());
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SetAccountRetentionSettings {
    event_retention_days: u32,
}

impl SetAccountRetentionSettings {
    /// Validates the documented retention range
    /// [`MIN_EVENT_RETENTION_DAYS`]`..=`[`MAX_EVENT_RETENTION_DAYS`] before the
    /// value can reach the wire.
    ///
    /// ```
    /// use sipgate_flow::SetAccountRetentionSettings;
    ///
    /// assert!(SetAccountRetentionSettings::new(1).is_ok());
    /// assert!(SetAccountRetentionSettings::new(2).is_ok());
    /// assert!(SetAccountRetentionSettings::new(0).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `days` is `0` (the schema's exclusive
    /// minimum) or above [`MAX_EVENT_RETENTION_DAYS`].
    pub fn new(days: u32) -> Result<Self> {
        if days < MIN_EVENT_RETENTION_DAYS {
            return Err(Error::validation(
                "event_retention_days",
                format!(
                    "must be at least {MIN_EVENT_RETENTION_DAYS} day (0 would mean keep indefinitely)"
                ),
            ));
        }
        if days > MAX_EVENT_RETENTION_DAYS {
            return Err(Error::validation(
                "event_retention_days",
                format!("must be at most {MAX_EVENT_RETENTION_DAYS} days"),
            ));
        }
        Ok(Self {
            event_retention_days: days,
        })
    }

    /// The validated retention in days.
    ///
    /// ```
    /// use sipgate_flow::SetAccountRetentionSettings;
    ///
    /// assert_eq!(SetAccountRetentionSettings::new(30)?.event_retention_days(), 30);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn event_retention_days(&self) -> u32 {
        self.event_retention_days
    }

    /// Renders the request body exactly as the `OpenAPI` schema names it.
    ///
    /// ```
    /// use sipgate_flow::SetAccountRetentionSettings;
    ///
    /// assert_eq!(
    ///     SetAccountRetentionSettings::new(90)?.to_json(),
    ///     serde_json::json!({"eventRetentionDays": 90})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "eventRetentionDays": self.event_retention_days })
    }
}

/// Rejects a value that is not a plausible enum wire token: non-empty, within
/// [`MAX_ACCOUNT_SETTING_TOKEN_BYTES`], and ASCII letters, digits or
/// underscores only.
fn validate_wire_token(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::validation(field, "must not be empty"));
    }
    if value.len() > MAX_ACCOUNT_SETTING_TOKEN_BYTES {
        return Err(Error::validation(
            field,
            format!("must be at most {MAX_ACCOUNT_SETTING_TOKEN_BYTES} bytes"),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(Error::validation(
            field,
            "must contain only ASCII letters, digits and underscores",
        ));
    }
    Ok(())
}

// ===========================================================================
// v3 TTS catalogue and synthesis (#169)
//
// Delimited so concurrent work on the v3 account-administration surface (#170)
// can be merged without touching this block. Everything here belongs to the
// `text-to-speech-controller` resource of the v3 `OpenAPI` document:
// `GET /v3/tts`, `POST /v3/tts`, `POST /v3/tts/stream` and
// `GET /v3/ai-agents/{agentId}/voices`. `GET /v3/tts/voices` stays above,
// modelled by [`TtsVoice`].
// ===========================================================================

/// Longest `voice` id accepted before it reaches the wire.
///
/// The documented voice ids are the `TtsVoice` enum names (`SIPGATE_VOICE`),
/// the composite catalogue ids (`SIPGATE-0`, `NhQJUmAozCa7BWLiUXy`) and the
/// agent-voice ids; the cap keeps an unbounded caller string out of the body.
const MAX_TTS_VOICE_ID_BYTES: usize = 64;

/// Longest announcement `title` accepted, matching the documented `maxLength`.
const MAX_TTS_TITLE_CHARS: usize = 255;

/// Longest synthesis `content` accepted, matching the documented `maxLength`.
const MAX_TTS_CONTENT_CHARS: usize = 1024;

/// Rejects a `voice` id outside the documented `[A-Za-z0-9_-]+` shape.
fn validate_tts_voice(field: &'static str, value: &str) -> Result<()> {
    validate::non_empty(field, value, MAX_TTS_VOICE_ID_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Error::validation(
            field,
            "must contain only ASCII letters, digits, _ or -",
        ));
    }
    Ok(())
}

/// Rejects an announcement id outside the documented UUID shape.
///
/// The identifier goes into a URL query, so the alphabet is narrowed to ASCII
/// letters, digits and `-`: that admits a UUID while keeping the query free of
/// characters [`crate::exchange`] refuses.
fn validate_tts_id(field: &'static str, value: &str) -> Result<()> {
    validate::non_empty(field, value, MAX_TTS_VOICE_ID_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(Error::validation(
            field,
            "must contain only ASCII letters, digits or -",
        ));
    }
    Ok(())
}

/// Rejects empty synthesis text and text past the documented character cap.
///
/// `max_chars` is the JSON Schema `maxLength`, which counts Unicode scalar
/// values, so the check is on `chars()` and not on the UTF-8 byte length.
fn validate_tts_text(field: &'static str, value: &str, max_chars: usize) -> Result<()> {
    if value.is_empty() {
        return Err(Error::validation(field, "must not be empty"));
    }
    if value.chars().count() > max_chars {
        return Err(Error::validation(
            field,
            format!("must be at most {max_chars} characters"),
        ));
    }
    Ok(())
}

/// The `type` token of `POST /v3/tts`.
///
/// The v3 schema declares this as an unconstrained string and gives it no
/// documented meaning, so `Announcement` is only the spelling this crate has
/// seen in examples; it does not claim a wire-side effect. Unknown values stay
/// in [`Self::Other`] and are sent unchanged after token validation.
///
/// ```
/// use sipgate_flow::SynthesizeType;
///
/// assert_eq!(SynthesizeType::parse("ANNOUNCEMENT")?, SynthesizeType::Announcement);
/// assert_eq!(SynthesizeType::parse("future_kind")?, SynthesizeType::Other("future_kind".into()));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SynthesizeType {
    /// The spelling used by the documented announcement examples.
    Announcement,
    /// A value this crate does not model, kept verbatim.
    Other(String),
}

impl SynthesizeType {
    /// Parses and validates an announcement type.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeType;
    ///
    /// assert_eq!(SynthesizeType::parse("announcement")?.as_str(), "ANNOUNCEMENT");
    /// assert!(SynthesizeType::parse("").is_err());
    /// assert!(SynthesizeType::parse("has space").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty, longer than 64 bytes, or
    /// contains anything except ASCII letters, digits and underscores.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate::non_empty("type", &value, MAX_TTS_VOICE_ID_BYTES)?;
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(Error::validation(
                "type",
                "must contain only ASCII letters, digits and underscores",
            ));
        }
        if value.eq_ignore_ascii_case("ANNOUNCEMENT") {
            Ok(Self::Announcement)
        } else {
            Ok(Self::Other(value))
        }
    }

    /// The canonical wire spelling.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeType;
    /// assert_eq!(SynthesizeType::Announcement.as_str(), "ANNOUNCEMENT");
    /// assert_eq!(SynthesizeType::Other("future".into()).as_str(), "future");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Announcement => "ANNOUNCEMENT",
            Self::Other(value) => value,
        }
    }
}

impl<T: Transport, A: TokenSource> FlowClient<T, A> {
    /// Lists the account's stored TTS announcements for one queue:
    /// `GET /v3/tts?acdId=…`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// for setting in client.tts_settings("e0e1e2e3-0000-0000-0000-000000000000").await? {
    ///     println!("{:?}", setting.announcement_id());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when `acd_id` is empty or not the
    /// documented UUID shape, [`crate::Error::Json`] when the success body is
    /// not JSON or carries an entry that is not a TTS setting, plus the generic
    /// transport, auth and API errors.
    pub async fn tts_settings(&self, acd_id: impl Into<String>) -> Result<Vec<TtsSetting>> {
        let acd_id = acd_id.into();
        validate_tts_id("acd_id", &acd_id)?;
        let path = format!("/v3/tts?acdId={acd_id}");
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
            Method::Get,
            None,
        )
        .await?;
        if response.is_success() {
            return TtsSettingList::from_json(response.json()?).into_settings();
        }
        Err(crate::retry::api_error(
            Method::Get,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Synthesizes text into a stored announcement: `POST /v3/tts`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken, SynthesizeRequest};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let request = SynthesizeRequest::new("SIPGATE_VOICE", "Ihr Anliegen wird bearbeitet.")?;
    /// let setting = client.synthesize(&request).await?;
    /// println!("{:?}", setting.announcement_id());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the request is built with an id,
    /// voice or text outside the documented shape, [`crate::Error::Json`] when
    /// the success body is not a JSON TTS setting, plus the generic transport,
    /// auth and API errors. A `POST` is not idempotent, so a `5xx` that leaves
    /// the outcome unknown is reported as [`crate::Error::Ambiguous`] rather
    /// than retried.
    pub async fn synthesize(&self, request: &SynthesizeRequest) -> Result<TtsSetting> {
        let body = request.to_json();
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/tts",
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
        if response.is_success() {
            return TtsSetting::parse(response.body());
        }
        Err(crate::retry::api_error(
            Method::Post,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Synthesizes text and streams the result as base64 audio:
    /// `POST /v3/tts/stream`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken, SynthesizeStreamRequest};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let request = SynthesizeStreamRequest::new("SIPGATE_VOICE", "Bitte warten.")?;
    /// let audio = client.synthesize_stream(&request).await?;
    /// println!("{} bytes", audio.decode()?.len());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when the request is invalid or the success
    /// body is not base64, plus the generic transport, auth and API errors. As
    /// with [`Self::synthesize`], a `5xx` after the `POST` is
    /// [`crate::Error::Ambiguous`].
    pub async fn synthesize_stream(
        &self,
        request: &SynthesizeStreamRequest,
    ) -> Result<SynthesizedAudio> {
        let body = request.to_json();
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            exchange::Target {
                base_url: &self.base_url,
                allow_http_base_url: self.allow_http_base_url,
                path: "/v3/tts/stream",
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
        if response.is_success() {
            return SynthesizedAudio::new(response.text());
        }
        Err(crate::retry::api_error(
            Method::Post,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Reads the voices an agent may select: `GET /v3/ai-agents/{agentId}/voices`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let voices = client.agent_voices("agent-1").await?;
    /// for voice in voices.items() {
    ///     println!("{}", voice.id());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] when `agent_id` is empty or path-unsafe,
    /// [`crate::Error::Json`] when the success body is not JSON or carries an
    /// undecodable voice entry, plus the generic transport, auth and API errors.
    pub async fn agent_voices(&self, agent_id: impl Into<String>) -> Result<AgentVoices> {
        let agent_id = agent_id.into();
        validate::path_segment("agent_id", &agent_id)?;
        let path = format!("/v3/ai-agents/{agent_id}/voices");
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
            Method::Get,
            None,
        )
        .await?;
        if response.is_success() {
            return AgentVoices::from_json(response.json()?);
        }
        Err(crate::retry::api_error(
            Method::Get,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }
}

/// `POST /v3/tts` body: synthesize `content` with `voice` into an announcement.
///
/// The current v3 document carries no separate `language` field on this
/// request; the language is chosen through the `voice` (see
/// [`TtsVoice::languages`] and [`AgentVoices`]). The documented `maxLength` is
/// 1024 characters for `content` and 255 for `title`; both are enforced here
/// before the request can reach the wire.
///
/// ```
/// use sipgate_flow::SynthesizeRequest;
///
/// let request = SynthesizeRequest::new("SIPGATE_VOICE", "Guten Tag.")?
///     .with_title("Begruessung")?;
/// assert_eq!(request.to_json()["voice"], "SIPGATE_VOICE");
/// assert_eq!(request.to_json()["content"], "Guten Tag.");
/// assert_eq!(request.to_json()["title"], "Begruessung");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SynthesizeRequest {
    voice: String,
    content: String,
    title: Option<String>,
    acd_id: Option<String>,
    kind: Option<SynthesizeType>,
}

impl std::fmt::Debug for SynthesizeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SynthesizeRequest")
            .field("voice", &self.voice)
            .field("content", &self.content)
            .field("title", &self.title)
            .field("acd_id", &self.acd_id)
            .field("kind", &self.kind)
            .finish()
    }
}

impl SynthesizeRequest {
    /// Builds the request from the two required fields.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeRequest;
    ///
    /// assert!(SynthesizeRequest::new("SIPGATE_VOICE", "hi").is_ok());
    /// assert!(SynthesizeRequest::new("", "hi").is_err());
    /// assert!(SynthesizeRequest::new("SIPGATE_VOICE", "").is_err());
    /// assert!(SynthesizeRequest::new("has space", "hi").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `voice` is empty or outside `[A-Za-z0-9_-]+`,
    /// or when `content` is empty or longer than 1024 characters.
    pub fn new(voice: impl Into<String>, content: impl Into<String>) -> Result<Self> {
        let voice = voice.into();
        validate_tts_voice("voice", &voice)?;
        let content = content.into();
        validate_tts_text("content", &content, MAX_TTS_CONTENT_CHARS)?;
        Ok(Self {
            voice,
            content,
            title: None,
            acd_id: None,
            kind: None,
        })
    }

    /// Sets the announcement title (`maxLength` 255 characters).
    ///
    /// ```
    /// use sipgate_flow::SynthesizeRequest;
    ///
    /// let request = SynthesizeRequest::new("SIPGATE_VOICE", "hi")?.with_title("T")?;
    /// assert_eq!(request.title(), Some("T"));
    /// assert!(SynthesizeRequest::new("SIPGATE_VOICE", "hi")?.with_title("").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the title is empty or longer than 255
    /// characters.
    pub fn with_title(mut self, title: impl Into<String>) -> Result<Self> {
        let title = title.into();
        validate_tts_text("title", &title, MAX_TTS_TITLE_CHARS)?;
        self.title = Some(title);
        Ok(self)
    }

    /// Sets the queue the announcement belongs to (the `acdId` field).
    ///
    /// ```
    /// use sipgate_flow::SynthesizeRequest;
    ///
    /// let request = SynthesizeRequest::new("SIPGATE_VOICE", "hi")?
    ///     .with_acd_id("e0e1e2e3-0000-0000-0000-000000000000")?;
    /// assert_eq!(request.to_json()["acdId"], "e0e1e2e3-0000-0000-0000-000000000000");
    /// assert!(SynthesizeRequest::new("SIPGATE_VOICE", "hi")?.with_acd_id("a b").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the id is empty or not ASCII letters, digits
    /// and `-`.
    pub fn with_acd_id(mut self, acd_id: impl Into<String>) -> Result<Self> {
        let acd_id = acd_id.into();
        validate_tts_id("acd_id", &acd_id)?;
        self.acd_id = Some(acd_id);
        Ok(self)
    }

    /// Sets the announcement `type` token documented by the API.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeRequest;
    ///
    /// let request = SynthesizeRequest::new("SIPGATE_VOICE", "hi")?.with_kind("ANNOUNCEMENT")?;
    /// assert_eq!(request.to_json()["type"], "ANNOUNCEMENT");
    /// assert!(SynthesizeRequest::new("SIPGATE_VOICE", "hi")?.with_kind("").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the token is empty or longer than 64 bytes.
    pub fn with_kind(mut self, kind: impl Into<String>) -> Result<Self> {
        self.kind = Some(SynthesizeType::parse(kind)?);
        Ok(self)
    }

    /// The selected voice id.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeRequest;
    /// assert_eq!(SynthesizeRequest::new("RACHEL", "hi")?.voice(), "RACHEL");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn voice(&self) -> &str {
        &self.voice
    }

    /// The text to synthesize.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeRequest;
    /// assert_eq!(SynthesizeRequest::new("RACHEL", "hi")?.content(), "hi");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// The announcement title, when one was set.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeRequest;
    /// assert_eq!(SynthesizeRequest::new("RACHEL", "hi")?.title(), None);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// The queue id, when one was set.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeRequest;
    /// assert_eq!(SynthesizeRequest::new("RACHEL", "hi")?.acd_id(), None);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn acd_id(&self) -> Option<&str> {
        self.acd_id.as_deref()
    }

    /// The announcement `type` token, when one was set.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeRequest;
    /// assert_eq!(SynthesizeRequest::new("RACHEL", "hi")?.kind(), None);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn kind(&self) -> Option<&str> {
        self.kind.as_ref().map(SynthesizeType::as_str)
    }

    /// The typed announcement `type`, when one was set.
    ///
    /// sipgate documents the field as a free string and assigns it no
    /// semantics; this crate carries it losslessly and validates the wire
    /// token before sending.
    ///
    /// ```
    /// use sipgate_flow::{SynthesizeRequest, SynthesizeType};
    ///
    /// let request = SynthesizeRequest::new("RACHEL", "hi")?.with_kind("ANNOUNCEMENT")?;
    /// assert_eq!(request.synthesis_type(), Some(&SynthesizeType::Announcement));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn synthesis_type(&self) -> Option<&SynthesizeType> {
        self.kind.as_ref()
    }

    /// Renders the request body under the documented `camelCase` names.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeRequest;
    ///
    /// let request = SynthesizeRequest::new("RACHEL", "hi")?;
    /// assert_eq!(
    ///     request.to_json(),
    ///     serde_json::json!({"voice": "RACHEL", "content": "hi"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("voice".into(), json!(self.voice));
        object.insert("content".into(), json!(self.content));
        if let Some(title) = &self.title {
            object.insert("title".into(), json!(title));
        }
        if let Some(acd_id) = &self.acd_id {
            object.insert("acdId".into(), json!(acd_id));
        }
        if let Some(kind) = &self.kind {
            object.insert("type".into(), json!(kind.as_str()));
        }
        Value::Object(object)
    }
}

/// `POST /v3/tts/stream` body: synthesize `content` with `voice` as audio.
///
/// The endpoint answers with a base64-encoded audio body rather than a stored
/// announcement; see [`SynthesizedAudio`]. The documented `maxLength` for
/// `content` is 1024 characters.
///
/// ```
/// use sipgate_flow::SynthesizeStreamRequest;
///
/// let request = SynthesizeStreamRequest::new("SIPGATE_VOICE", "Guten Tag.")?;
/// assert_eq!(
///     request.to_json(),
///     serde_json::json!({"voice": "SIPGATE_VOICE", "content": "Guten Tag."})
/// );
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SynthesizeStreamRequest {
    voice: String,
    content: String,
}

impl std::fmt::Debug for SynthesizeStreamRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SynthesizeStreamRequest")
            .field("voice", &self.voice)
            .field("content", &self.content)
            .finish()
    }
}

impl SynthesizeStreamRequest {
    /// Builds the streaming request from its two required fields.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeStreamRequest;
    ///
    /// assert!(SynthesizeStreamRequest::new("SIPGATE_VOICE", "hi").is_ok());
    /// assert!(SynthesizeStreamRequest::new("", "hi").is_err());
    /// assert!(SynthesizeStreamRequest::new("SIPGATE_VOICE", "").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `voice` is empty or outside `[A-Za-z0-9_-]+`,
    /// or when `content` is empty or longer than 1024 characters.
    pub fn new(voice: impl Into<String>, content: impl Into<String>) -> Result<Self> {
        let voice = voice.into();
        validate_tts_voice("voice", &voice)?;
        let content = content.into();
        validate_tts_text("content", &content, MAX_TTS_CONTENT_CHARS)?;
        Ok(Self { voice, content })
    }

    /// The selected voice id.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeStreamRequest;
    /// assert_eq!(SynthesizeStreamRequest::new("RACHEL", "hi")?.voice(), "RACHEL");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn voice(&self) -> &str {
        &self.voice
    }

    /// The text to synthesize.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeStreamRequest;
    /// assert_eq!(SynthesizeStreamRequest::new("RACHEL", "hi")?.content(), "hi");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Renders the request body under the documented `camelCase` names.
    ///
    /// ```
    /// use sipgate_flow::SynthesizeStreamRequest;
    ///
    /// let request = SynthesizeStreamRequest::new("RACHEL", "hi")?;
    /// assert_eq!(
    ///     request.to_json(),
    ///     serde_json::json!({"voice": "RACHEL", "content": "hi"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "voice": self.voice, "content": self.content })
    }
}

/// The `200 OK` body of `POST /v3/tts/stream`: base64-encoded audio.
///
/// The v3 document types this response as a bare string, so the payload is
/// validated as canonical base64 on construction instead of being guessed. Use
/// [`Self::decode`] to obtain the audio bytes.
///
/// ```
/// use sipgate_flow::SynthesizedAudio;
///
/// let audio = SynthesizedAudio::new("aGk=")?;
/// assert_eq!(audio.decode()?, b"hi");
/// assert!(SynthesizedAudio::new("not base64!").is_err());
/// assert!(SynthesizedAudio::new("").is_err());
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SynthesizedAudio {
    base64_data: String,
}

impl std::fmt::Debug for SynthesizedAudio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SynthesizedAudio")
            .field("base64_bytes", &self.base64_data.len())
            .finish()
    }
}

impl SynthesizedAudio {
    /// Validates and wraps the base64 audio body.
    ///
    /// ```
    /// use sipgate_flow::SynthesizedAudio;
    ///
    /// assert!(SynthesizedAudio::new("aGk=").is_ok());
    /// assert!(SynthesizedAudio::new("aGk").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the body is empty or not canonical base64.
    pub fn new(base64_data: impl Into<String>) -> Result<Self> {
        let base64_data = base64_data.into();
        if base64_data.is_empty() {
            return Err(Error::validation(
                "tts_audio",
                "must carry a non-empty base64 body",
            ));
        }
        if !crate::base64::is_valid(&base64_data) {
            return Err(Error::validation(
                "tts_audio",
                "must be canonical base64 audio",
            ));
        }
        Ok(Self { base64_data })
    }

    /// The base64 payload exactly as received.
    ///
    /// ```
    /// use sipgate_flow::SynthesizedAudio;
    /// assert_eq!(SynthesizedAudio::new("aGk=")?.base64_data(), "aGk=");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn base64_data(&self) -> &str {
        &self.base64_data
    }

    /// Decodes the audio bytes.
    ///
    /// ```
    /// use sipgate_flow::SynthesizedAudio;
    /// assert_eq!(SynthesizedAudio::new("aGk=")?.decode()?, b"hi");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Base64`] is impossible after [`Self::new`] validated the body;
    /// the signature still returns a [`Result`] so callers do not panic.
    pub fn decode(&self) -> Result<Vec<u8>> {
        crate::base64::decode(&self.base64_data)
    }
}

/// One TTS announcement as modelled by `POST /v3/tts` and `GET /v3/tts`.
///
/// Decoding is permissive: unknown fields stay in [`Self::raw`], and both
/// `announcementId` (documented) and `announcement_id` (tolerated) are read.
///
/// ```
/// use sipgate_flow::TtsSetting;
///
/// let setting = TtsSetting::from_json(serde_json::json!({
///     "announcementId": "a-1",
///     "alias": "greeting",
///     "content": "Guten Tag.",
///     "voice": "SIPGATE_VOICE",
///     "vendor": "future",
/// }));
/// assert_eq!(setting.announcement_id(), Some("a-1"));
/// assert_eq!(setting.voice(), Some("SIPGATE_VOICE"));
/// assert_eq!(setting.raw()["vendor"], "future");
/// ```
#[derive(Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct TtsSetting {
    alias: Option<String>,
    announcement_id: Option<String>,
    content: Option<String>,
    voice: Option<String>,
    raw: Value,
}

impl std::fmt::Debug for TtsSetting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtsSetting")
            .field("alias", &self.alias)
            .field("announcement_id", &self.announcement_id)
            .field("content", &self.content)
            .field("voice", &self.voice)
            .field("raw", &RedactedRaw(&self.raw))
            .finish()
    }
}

impl TtsSetting {
    /// Decodes the JSON body bytes.
    ///
    /// ```
    /// use sipgate_flow::TtsSetting;
    ///
    /// assert!(TtsSetting::parse(br#"{"announcementId":"a-1"}"#).is_ok());
    /// assert!(TtsSetting::parse(b"not json").is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the body is not JSON at all. A body that parses but
    /// omits fields is tolerated; every accessor then stays `None`.
    pub fn parse(body: &[u8]) -> Result<Self> {
        Ok(Self::from_json(
            serde_json::from_slice(body).map_err(Error::json_parse)?,
        ))
    }

    /// Reads an already-decoded body.
    ///
    /// ```
    /// use sipgate_flow::TtsSetting;
    ///
    /// let setting = TtsSetting::from_json(serde_json::json!({"announcement_id": "a-2"}));
    /// assert_eq!(setting.announcement_id(), Some("a-2"));
    /// ```
    #[must_use]
    pub fn from_json(value: Value) -> Self {
        let empty = Map::new();
        let alias =
            string_field(value.as_object().unwrap_or(&empty), &["alias"]).map(str::to_string);
        let announcement_id = value
            .get("announcementId")
            .or_else(|| value.get("announcement_id"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_string);
        let content = value
            .get("content")
            .and_then(Value::as_str)
            .filter(|content| !content.is_empty())
            .map(str::to_string);
        let voice = value
            .get("voice")
            .and_then(Value::as_str)
            .filter(|voice| !voice.is_empty())
            .map(str::to_string);
        Self {
            alias,
            announcement_id,
            content,
            voice,
            raw: value,
        }
    }

    /// The announcement alias, when the body carried one.
    ///
    /// ```
    /// use sipgate_flow::TtsSetting;
    /// assert_eq!(TtsSetting::from_json(serde_json::json!({"alias":"greeting"})).alias(), Some("greeting"));
    /// ```
    #[must_use]
    pub fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    /// The announcement id, when the body carried one.
    ///
    /// ```
    /// use sipgate_flow::TtsSetting;
    /// assert_eq!(TtsSetting::from_json(serde_json::json!({})).announcement_id(), None);
    /// ```
    #[must_use]
    pub fn announcement_id(&self) -> Option<&str> {
        self.announcement_id.as_deref()
    }

    /// The announcement content, when the body carried one.
    ///
    /// ```
    /// use sipgate_flow::TtsSetting;
    /// assert_eq!(TtsSetting::from_json(serde_json::json!({"content":"hi"})).content(), Some("hi"));
    /// ```
    #[must_use]
    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }

    /// The voice id, when the body carried one.
    ///
    /// ```
    /// use sipgate_flow::TtsSetting;
    /// assert_eq!(TtsSetting::from_json(serde_json::json!({})).voice(), None);
    /// ```
    #[must_use]
    pub fn voice(&self) -> Option<&str> {
        self.voice.as_deref()
    }

    /// The body exactly as received, for fields this crate does not model.
    ///
    /// ```
    /// use sipgate_flow::TtsSetting;
    /// assert_eq!(TtsSetting::from_json(serde_json::json!({"vendor":"x"})).raw()["vendor"], "x");
    /// ```
    #[must_use]
    pub fn raw(&self) -> &Value {
        &self.raw
    }
}

/// Reads the `{"items": [...]}` envelope of `GET /v3/tts`.
#[derive(Deserialize)]
struct TtsSettingList {
    #[serde(default)]
    items: Vec<Value>,
}

impl TtsSettingList {
    fn from_json(value: Value) -> Self {
        serde_json::from_value(value).unwrap_or(Self { items: Vec::new() })
    }

    fn into_settings(self) -> Result<Vec<TtsSetting>> {
        let mut settings = Vec::with_capacity(self.items.len());
        for item in self.items {
            if !item.is_object() {
                return Err(Error::validation(
                    "tts_settings",
                    "each entry must be a TTS setting object",
                ));
            }
            settings.push(TtsSetting::from_json(item));
        }
        Ok(settings)
    }
}

// ===========================================================================
// v3 AI webhook configurations (#168)
//
// The current v3 document models the account's AI assist webhook delivery
// through `/v3/webhooks` and its headers sub-resource, while keeping the
// legacy single-URL `/v3/ai-webhooks` resource above for compatibility.
// ===========================================================================

/// Longest webhook config `name` accepted, matching the `maxLength` of the
/// documented request schema.
const MAX_WEBHOOK_CONFIG_NAME_CHARS: usize = 255;

/// Longest webhook entity id accepted before it is placed in the request body.
const MAX_WEBHOOK_ENTITY_ID_BYTES: usize = 255;

/// Longest custom webhook header name accepted.
const MAX_WEBHOOK_HEADER_NAME_BYTES: usize = 256;

/// Longest custom webhook header value accepted by this crate.
///
/// The v3 document sets no explicit upper bound; the generic REST field cap
/// keeps a single header from carrying an unbounded payload.
const MAX_WEBHOOK_HEADER_VALUE_BYTES: usize = validate::MAX_REST_FIELD_BYTES;

/// Rejects a `configId` path parameter outside the documented UUID shape.
fn validate_webhook_config_id(field: &'static str, value: &str) -> Result<()> {
    validate::non_empty(field, value, validate::MAX_SESSION_ID)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(Error::validation(
            field,
            "must contain only ASCII letters, digits or -",
        ));
    }
    Ok(())
}

/// Rejects a custom webhook header name the API would refuse.
///
/// The v3 document requires names to start with `X-` and to avoid `#`; the
/// alphabet is narrowed further to HTTP token characters so the name is safe
/// both in JSON and as a URL path segment.
fn validate_webhook_header_name(field: &'static str, value: &str) -> Result<()> {
    validate::non_empty(field, value, MAX_WEBHOOK_HEADER_NAME_BYTES)?;
    if !value
        .get(..2)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("x-"))
    {
        return Err(Error::validation(field, "must start with X-"));
    }
    if value.contains('#') {
        return Err(Error::validation(field, "must not contain #"));
    }
    if !value.bytes().all(is_webhook_header_name_byte) {
        return Err(Error::validation(
            field,
            "must contain only ASCII letters, digits or -_",
        ));
    }
    Ok(())
}

fn is_webhook_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

/// Rejects a custom webhook header value the API would refuse.
///
/// The v3 document requires a non-blank value without CR or LF, so a header
/// cannot inject a second header line on delivery.
fn validate_webhook_header_value(field: &'static str, value: &str) -> Result<()> {
    validate::non_empty(field, value, MAX_WEBHOOK_HEADER_VALUE_BYTES)?;
    if value.trim().is_empty() {
        return Err(Error::validation(field, "must not be blank"));
    }
    if value.contains('\r') || value.contains('\n') {
        return Err(Error::validation(field, "must not contain CR or LF"));
    }
    Ok(())
}

/// One AI webhook configuration as modelled by `/v3/webhooks`.
///
/// The same type carries the create/replace request (name, `active` flag,
/// target URLs and entity ids) and the response (the same fields plus the
/// server-assigned `webhookId` and custom headers). Unknown response fields
/// stay in [`Self::raw`], and decoding tolerates `webhook_id`/`entity_ids` as
/// aliases.
///
/// ```
/// use sipgate_flow::AiWebhookConfig;
///
/// let request = AiWebhookConfig::new(
///     "prod",
///     true,
///     ["https://example.com/wh"],
///     ["e2"],
/// )?;
/// assert_eq!(request.to_request_json()["name"], "prod");
/// assert_eq!(request.to_request_json()["urls"][0], "https://example.com/wh");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AiWebhookConfig {
    name: String,
    active: bool,
    urls: Vec<String>,
    entity_ids: Vec<String>,
    webhook_id: Option<String>,
    headers: Vec<AiWebhookHeader>,
    raw: Value,
}

impl std::fmt::Debug for AiWebhookConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiWebhookConfig")
            .field("name", &self.name)
            .field("active", &self.active)
            .field("urls", &RedactedUrls(&self.urls))
            .field("entity_ids", &self.entity_ids)
            .field("webhook_id", &self.webhook_id)
            .field("headers", &self.headers)
            .field("raw", &RedactedRaw(&self.raw))
            .finish()
    }
}

/// A list of webhook target URLs as it may appear in `Debug`: host only.
struct RedactedUrls<'a>(&'a [String]);

impl fmt::Debug for RedactedUrls<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for url in self.0 {
            list.entry(&RedactedUrl(url));
        }
        list.finish()
    }
}

impl AiWebhookConfig {
    /// Builds the create/replace body from the documented required fields.
    ///
    /// Every URL must be an absolute `https://` URL without credentials, the
    /// name must be at most 255 characters, and entity ids must be non-empty.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    ///
    /// assert!(AiWebhookConfig::new("prod", true, ["https://example.com/wh"], ["e2"]).is_ok());
    /// assert!(AiWebhookConfig::new("prod", false, Vec::<&str>::new(), Vec::<&str>::new()).is_ok());
    /// assert!(AiWebhookConfig::new("prod", true, ["http://example.com/wh"], Vec::<&str>::new()).is_err());
    /// assert!(AiWebhookConfig::new("prod", true, Vec::<&str>::new(), [""]).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name is longer than 255 characters, a
    /// URL is empty or not an absolute `https://` URL, or an entity id is empty
    /// or over-long.
    pub fn new(
        name: impl Into<String>,
        active: bool,
        urls: impl IntoIterator<Item = impl Into<String>>,
        entity_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        let name = name.into();
        validate_webhook_config_name(&name)?;
        let urls = collect_webhook_urls(urls)?;
        let entity_ids = collect_webhook_entity_ids(entity_ids)?;
        Ok(Self {
            name,
            active,
            urls,
            entity_ids,
            webhook_id: None,
            headers: Vec::new(),
            raw: Value::Null,
        })
    }

    /// Decodes the documented response body.
    ///
    /// Both `webhookId`/`webhook_id` and `entityIds`/`entity_ids` are accepted.
    /// Unknown fields stay in [`Self::raw`].
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    ///
    /// let config = AiWebhookConfig::from_json(serde_json::json!({
    ///     "webhookId": "48f1e8a8-5e4c-4d2f-8f04-1c2a97a4c3de",
    ///     "name": "prod",
    ///     "active": true,
    ///     "urls": ["https://example.com/wh"],
    ///     "entityIds": ["e2"],
    ///     "headers": [],
    ///     "future": true,
    /// }))?;
    /// assert_eq!(config.name(), "prod");
    /// assert_eq!(config.raw()["future"], true);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the body is not an object, or a required
    /// field (`name`, `active`, `urls`, `entityIds`, `headers`) is missing or
    /// has the wrong JSON shape.
    pub fn from_json(value: Value) -> Result<Self> {
        let object = value.as_object().ok_or_else(|| {
            Error::validation("ai_webhook_config", "response must be a JSON object")
        })?;
        let name = required_string(object, "name", "ai_webhook_config.name")?;
        validate_webhook_config_name(&name)
            .map_err(|_| Error::validation("ai_webhook_config.name", "is invalid"))?;
        let active = object
            .get("active")
            .and_then(Value::as_bool)
            .ok_or_else(|| Error::validation("ai_webhook_config.active", "must be a boolean"))?;
        let urls = required_string_list(object, &["urls"], "ai_webhook_config.urls")?;
        let entity_ids = required_string_list(
            object,
            &["entityIds", "entity_ids"],
            "ai_webhook_config.entity_ids",
        )?;
        let webhook_id = optional_string(object, &["webhookId", "webhook_id"])
            .filter(|id| !id.is_empty())
            .map(str::to_string);
        let headers_value = object.get("headers").ok_or_else(|| {
            Error::validation("ai_webhook_config.headers", "must be a JSON array")
        })?;
        let headers = decode_webhook_headers(headers_value)?;
        Ok(Self {
            name,
            active,
            urls,
            entity_ids,
            webhook_id,
            headers,
            raw: value,
        })
    }

    /// Decodes the documented `GET /v3/webhooks` array response.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    ///
    /// let configs = AiWebhookConfig::list_from_json(serde_json::json!([]))?;
    /// assert!(configs.is_empty());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the body is not a JSON array, or any entry is
    /// not a webhook config object.
    pub fn list_from_json(value: Value) -> Result<Vec<Self>> {
        let Value::Array(entries) = value else {
            return Err(Error::validation(
                "ai_webhook_configs",
                "response must be a JSON array",
            ));
        };
        let mut configs = Vec::with_capacity(entries.len());
        for entry in entries {
            configs.push(Self::from_json(entry)?);
        }
        Ok(configs)
    }

    /// Rejects an already-constructed request that is no longer valid.
    ///
    /// The fields are private, so this normally only re-checks values stored by
    /// [`Self::new`]; it is still called before every send so an invariant
    /// break cannot reach the wire.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    ///
    /// let config = AiWebhookConfig::new("prod", true, ["https://example.com/wh"], ["e2"])?;
    /// assert!(config.validate_request().is_ok());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when a stored URL or entity id is no longer valid.
    pub fn validate_request(&self) -> Result<()> {
        validate_webhook_config_name(&self.name)?;
        for url in &self.urls {
            validate_webhook_url("urls", url)?;
        }
        for entity_id in &self.entity_ids {
            validate_webhook_entity_id("entity_ids", entity_id)?;
        }
        Ok(())
    }

    /// The human-readable name.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    /// assert_eq!(AiWebhookConfig::new("prod", true, ["https://example.com/wh"], Vec::<&str>::new())?.name(), "prod");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the config delivers webhooks.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    /// assert!(AiWebhookConfig::new("prod", true, ["https://example.com/wh"], Vec::<&str>::new())?.active());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn active(&self) -> bool {
        self.active
    }

    /// The configured target URLs.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    /// assert_eq!(
    ///     AiWebhookConfig::new("prod", true, ["https://example.com/wh"], Vec::<&str>::new())?.urls(),
    ///     ["https://example.com/wh"]
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// The entity ids the config delivers events for.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    /// assert_eq!(
    ///     AiWebhookConfig::new("prod", true, ["https://example.com/wh"], ["e2"])?.entity_ids(),
    ///     ["e2"]
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn entity_ids(&self) -> &[String] {
        &self.entity_ids
    }

    /// The server-assigned webhook id, when the response carried one.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    /// assert_eq!(AiWebhookConfig::new("prod", true, ["https://example.com/wh"], Vec::<&str>::new())?.webhook_id(), None);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn webhook_id(&self) -> Option<&str> {
        self.webhook_id.as_deref()
    }

    /// The custom headers attached to the config.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    /// assert!(AiWebhookConfig::new("prod", true, ["https://example.com/wh"], Vec::<&str>::new())?.headers().is_empty());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn headers(&self) -> &[AiWebhookHeader] {
        &self.headers
    }

    /// The body exactly as received, for fields this crate does not model.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    /// let config = AiWebhookConfig::from_json(serde_json::json!({
    ///     "name": "prod",
    ///     "active": false,
    ///     "urls": [],
    ///     "entityIds": [],
    ///     "headers": [],
    ///     "future": 1,
    /// }))?;
    /// assert_eq!(config.raw()["future"], 1);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// Renders the create/replace body exactly as the `OpenAPI` schema names it.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookConfig;
    /// let config = AiWebhookConfig::new("prod", true, ["https://example.com/wh"], ["e2"])?;
    /// assert_eq!(
    ///     config.to_request_json(),
    ///     serde_json::json!({
    ///         "name": "prod",
    ///         "active": true,
    ///         "urls": ["https://example.com/wh"],
    ///         "entityIds": ["e2"],
    ///     })
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_request_json(&self) -> Value {
        json!({
            "name": self.name,
            "active": self.active,
            "urls": self.urls,
            "entityIds": self.entity_ids,
        })
    }
}

/// One custom header of an AI webhook configuration:
/// `WebhookHeaderDto<682C6352>`.
///
/// The same type is used for the `POST .../headers` request and the `201`
/// response. The value is treated as a secret: [`Debug`] never prints it.
///
/// ```
/// use sipgate_flow::AiWebhookHeader;
///
/// let header = AiWebhookHeader::new("X-API-Key", "secret")?;
/// assert_eq!(header.name(), "X-API-Key");
/// assert_eq!(header.to_json()["value"], "secret");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AiWebhookHeader {
    name: String,
    value: String,
}

impl std::fmt::Debug for AiWebhookHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiWebhookHeader")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl AiWebhookHeader {
    /// Builds a custom webhook header.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookHeader;
    ///
    /// assert!(AiWebhookHeader::new("X-API-Key", "secret").is_ok());
    /// assert!(AiWebhookHeader::new("Authorization", "secret").is_err());
    /// assert!(AiWebhookHeader::new("X-API-Key", "").is_err());
    /// assert!(AiWebhookHeader::new("X-API-Key", "a\nb").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the name does not start with `X-`, contains
    /// `#` or non-token characters, or when the value is blank or contains CR
    /// or LF.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_webhook_header_name("header_name", &name)?;
        let value = value.into();
        validate_webhook_header_value("header_value", &value)?;
        Ok(Self { name, value })
    }

    /// Decodes the documented response body.
    ///
    /// Both `name` and `key` are accepted as the header name.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookHeader;
    ///
    /// let header = AiWebhookHeader::from_json(&serde_json::json!({"name": "X-Source", "value": "sipgate"}))?;
    /// assert_eq!(header.name(), "X-Source");
    ///
    /// let keyed = AiWebhookHeader::from_json(&serde_json::json!({"key": "X-Source", "value": "sipgate"}))?;
    /// assert_eq!(keyed.name(), "X-Source");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the body is not an object or the name/value
    /// pair is invalid.
    pub fn from_json(value: &Value) -> Result<Self> {
        let object = value.as_object().ok_or_else(|| {
            Error::validation("ai_webhook_header", "response must be a JSON object")
        })?;
        let name = optional_string(object, &["name", "key"])
            .ok_or_else(|| Error::validation("ai_webhook_header.name", "must be a string"))?;
        let value = optional_string(object, &["value"])
            .ok_or_else(|| Error::validation("ai_webhook_header.value", "must be a string"))?;
        Self::new(name, value)
    }

    /// Rejects an already-constructed header that is no longer valid.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookHeader;
    /// assert!(AiWebhookHeader::new("X-API-Key", "secret")?.validate_request().is_ok());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the stored name or value is no longer valid.
    pub fn validate_request(&self) -> Result<()> {
        validate_webhook_header_name("header_name", &self.name)?;
        validate_webhook_header_value("header_value", &self.value)
    }

    /// The header name.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookHeader;
    /// assert_eq!(AiWebhookHeader::new("X-API-Key", "secret")?.name(), "X-API-Key");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The header value.
    ///
    /// The value is commonly a credential; callers should avoid logging it.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookHeader;
    /// assert_eq!(AiWebhookHeader::new("X-API-Key", "secret")?.value(), "secret");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Renders the header body exactly as the `OpenAPI` schema names it.
    ///
    /// ```
    /// use sipgate_flow::AiWebhookHeader;
    /// assert_eq!(
    ///     AiWebhookHeader::new("X-API-Key", "secret")?.to_json(),
    ///     serde_json::json!({"name": "X-API-Key", "value": "secret"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({ "name": self.name, "value": self.value })
    }
}

fn validate_webhook_config_name(name: &str) -> Result<()> {
    if name.chars().count() > MAX_WEBHOOK_CONFIG_NAME_CHARS {
        return Err(Error::validation(
            "name",
            format!("must be at most {MAX_WEBHOOK_CONFIG_NAME_CHARS} characters"),
        ));
    }
    Ok(())
}

fn validate_webhook_url(field: &'static str, url: &str) -> Result<()> {
    validate::http_url(field, url)?;
    if !url
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
    {
        return Err(Error::validation(field, "must use https://"));
    }
    Ok(())
}

fn validate_webhook_entity_id(field: &'static str, value: &str) -> Result<()> {
    validate::non_empty(field, value, MAX_WEBHOOK_ENTITY_ID_BYTES)?;
    if value.contains('\r') || value.contains('\n') {
        return Err(Error::validation(field, "must not contain CR or LF"));
    }
    Ok(())
}

fn collect_webhook_urls(urls: impl IntoIterator<Item = impl Into<String>>) -> Result<Vec<String>> {
    let mut collected = Vec::new();
    for url in urls {
        let url = url.into();
        validate_webhook_url("urls", &url)?;
        collected.push(url);
    }
    Ok(collected)
}

fn collect_webhook_entity_ids(
    entity_ids: impl IntoIterator<Item = impl Into<String>>,
) -> Result<Vec<String>> {
    let mut collected = Vec::new();
    for entity_id in entity_ids {
        let entity_id = entity_id.into();
        validate_webhook_entity_id("entity_ids", &entity_id)?;
        collected.push(entity_id);
    }
    Ok(collected)
}

fn required_string(object: &Map<String, Value>, field: &str, path: &'static str) -> Result<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::validation(path, "must be a string"))
}

fn optional_string<'a>(object: &'a Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_str))
}

fn required_string_list(
    object: &Map<String, Value>,
    names: &[&str],
    path: &'static str,
) -> Result<Vec<String>> {
    let value = names
        .iter()
        .find_map(|name| object.get(*name))
        .ok_or_else(|| Error::validation(path, "must be a JSON array"))?;
    let Value::Array(entries) = value else {
        return Err(Error::validation(path, "must be a JSON array"));
    };
    let mut list = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry = entry
            .as_str()
            .ok_or_else(|| Error::validation(path, "entries must be strings"))?;
        list.push(entry.to_string());
    }
    Ok(list)
}

fn decode_webhook_headers(value: &Value) -> Result<Vec<AiWebhookHeader>> {
    let Value::Array(entries) = value else {
        return Err(Error::validation(
            "ai_webhook_config.headers",
            "must be a JSON array",
        ));
    };
    let mut headers = Vec::with_capacity(entries.len());
    for entry in entries {
        headers.push(AiWebhookHeader::from_json(entry)?);
    }
    Ok(headers)
}

/// The `200 OK` body of `GET /v3/ai-agents/{agentId}/voices`.
///
/// `items` are the catalogue voices the agent may select and are reused as
/// [`TtsVoice`]; `currentVoice` is the voice the agent is configured with, even
/// when it is no longer selectable. Unknown fields stay in [`Self::raw`].
///
/// ```
/// use sipgate_flow::{AgentVoices, CurrentVoice};
///
/// let body = serde_json::json!({
///     "items": [{"voiceId": "SIPGATE-0", "name": "Kai", "languages": ["de"], "recommended": true, "beta": false, "previewUrl": "https://example.com/a.mp3"}],
///     "currentVoice": {"voiceId": "SIPGATE-0", "name": "Kai"},
/// });
/// let voices = AgentVoices::from_json(body)?;
/// assert_eq!(voices.items()[0].id(), "SIPGATE-0");
/// assert_eq!(voices.current_voice().map(CurrentVoice::voice_id), Some("SIPGATE-0"));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct AgentVoices {
    items: Vec<TtsVoice>,
    current_voice: Option<CurrentVoice>,
    raw: Value,
}

impl std::fmt::Debug for AgentVoices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentVoices")
            .field("items", &self.items)
            .field("current_voice", &self.current_voice)
            .field("raw", &RedactedRaw(&self.raw))
            .finish()
    }
}

impl AgentVoices {
    /// Reads an already-decoded body.
    ///
    /// ```
    /// use sipgate_flow::AgentVoices;
    ///
    /// let voices = AgentVoices::from_json(serde_json::json!({"items": [], "currentVoice": serde_json::Value::Null}))?;
    /// assert!(voices.items().is_empty());
    /// assert_eq!(voices.current_voice(), None);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when an `items` entry is not a voice entry or when
    /// `currentVoice` is present but carries no voice id.
    pub fn from_json(value: Value) -> Result<Self> {
        let mut items = Vec::new();
        if let Some(Value::Array(entries)) = value.get("items") {
            items.reserve(entries.len());
            for entry in entries {
                items.push(TtsVoice::from_json(entry.clone())?);
            }
        }
        let current_voice = match value
            .get("currentVoice")
            .or_else(|| value.get("current_voice"))
        {
            None | Some(Value::Null) => None,
            Some(entry) => Some(CurrentVoice::from_json(entry)?),
        };
        Ok(Self {
            items,
            current_voice,
            raw: value,
        })
    }

    /// The catalogue voices the agent may select.
    ///
    /// ```
    /// use sipgate_flow::AgentVoices;
    /// assert!(AgentVoices::from_json(serde_json::json!({"items":[]}))?.items().is_empty());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn items(&self) -> &[TtsVoice] {
        &self.items
    }

    /// The voice the agent is configured with, when the API reported one.
    ///
    /// ```
    /// use sipgate_flow::AgentVoices;
    /// assert_eq!(AgentVoices::from_json(serde_json::json!({"items":[]}))?.current_voice(), None);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn current_voice(&self) -> Option<&CurrentVoice> {
        self.current_voice.as_ref()
    }

    /// The body exactly as received, for fields this crate does not model.
    ///
    /// ```
    /// use sipgate_flow::AgentVoices;
    /// assert_eq!(AgentVoices::from_json(serde_json::json!({"items":[], "x": 1}))?.raw()["x"], 1);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn raw(&self) -> &Value {
        &self.raw
    }
}

/// The `currentVoice` entry of [`AgentVoices`].
///
/// ```
/// use sipgate_flow::CurrentVoice;
///
/// let voice = CurrentVoice::from_json(&serde_json::json!({"voiceId": "SIPGATE-0", "name": "Kai"}))?;
/// assert_eq!(voice.voice_id(), "SIPGATE-0");
/// assert_eq!(voice.name(), Some("Kai"));
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CurrentVoice {
    voice_id: String,
    name: Option<String>,
}

impl std::fmt::Debug for CurrentVoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CurrentVoice")
            .field("voice_id", &self.voice_id)
            .field("name", &self.name)
            .finish()
    }
}

impl CurrentVoice {
    /// Reads an already-decoded body.
    ///
    /// ```
    /// use sipgate_flow::CurrentVoice;
    ///
    /// assert!(CurrentVoice::from_json(&serde_json::json!({"voiceId": "v1"})).is_ok());
    /// assert!(CurrentVoice::from_json(&serde_json::json!({})).is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the entry carries no non-empty `voiceId`.
    pub fn from_json(value: &Value) -> Result<Self> {
        let empty = Map::new();
        let object = value.as_object().unwrap_or(&empty);
        let voice_id = string_field(object, &["voiceId", "voice_id"])
            .filter(|id| !id.is_empty())
            .ok_or_else(|| Error::validation("current_voice", "must carry a non-empty voiceId"))?
            .to_string();
        let name = string_field(object, &["name"])
            .filter(|name| !name.is_empty())
            .map(str::to_string);
        Ok(Self { voice_id, name })
    }

    /// The configured voice id.
    ///
    /// ```
    /// use sipgate_flow::CurrentVoice;
    /// assert_eq!(CurrentVoice::from_json(&serde_json::json!({"voiceId":"v1"}))?.voice_id(), "v1");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn voice_id(&self) -> &str {
        &self.voice_id
    }

    /// The display name, when the entry carried one.
    ///
    /// ```
    /// use sipgate_flow::CurrentVoice;
    /// assert_eq!(CurrentVoice::from_json(&serde_json::json!({"voiceId":"v1"}))?.name(), None);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

// ===========================================================================
// v3 account administration (#180)
// ===========================================================================

/// Longest free-text value accepted by a v3 administration operation.
///
/// The Swagger schemas leave most aliases, names and tags unbounded. This
/// keeps an accidental multi-megabyte payload out of the client without
/// imposing a narrower semantic limit than sipgate publishes.
pub const MAX_V3_ADMIN_TEXT_BYTES: usize = 4096;

/// Largest batch accepted for a routings, opt-in or member operation.
///
/// The v3 schemas do not publish a batch ceiling. This mirrors the crate-wide
/// bounded-request policy and is checked before any list is serialized.
pub const MAX_V3_ADMIN_BATCH_ITEMS: usize = 1000;

/// Which line a v3 event-lifetime setting applies to.
///
/// ```
/// use sipgate_flow::V3EventLifetime;
///
/// assert_eq!(V3EventLifetime::ThirtyDays.as_str(), "THIRTY_DAYS");
/// assert_eq!(V3EventLifetime::parse("future")?.as_str(), "future");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum V3EventLifetime {
    /// No event retention.
    None,
    /// Retain events for thirty days.
    ThirtyDays,
    /// Retain events without a configured expiry.
    Unlimited,
    /// A value from a newer upstream document, kept verbatim.
    Other(String),
}

impl V3EventLifetime {
    /// Parses the documented value, carrying an unknown token verbatim.
    ///
    /// ```
    /// use sipgate_flow::V3EventLifetime;
    ///
    /// assert_eq!(V3EventLifetime::parse("NONE")?, V3EventLifetime::None);
    /// assert!(V3EventLifetime::parse("").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the value is empty, over
    /// [`MAX_ACCOUNT_SETTING_TOKEN_BYTES`], or not an ASCII wire token.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_wire_token("event_lifetime", &value)?;
        Ok(match value.as_str() {
            "NONE" => Self::None,
            "THIRTY_DAYS" => Self::ThirtyDays,
            "UNLIMITED" => Self::Unlimited,
            _ => Self::Other(value),
        })
    }

    /// The canonical wire spelling.
    ///
    /// ```
    /// use sipgate_flow::V3EventLifetime;
    /// assert_eq!(V3EventLifetime::Unlimited.as_str(), "UNLIMITED");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "NONE",
            Self::ThirtyDays => "THIRTY_DAYS",
            Self::Unlimited => "UNLIMITED",
            Self::Other(value) => value,
        }
    }
}

/// One typed operation from the v3 account-administration surface.
///
/// The variants map one-for-one to the documented Swagger operations in
/// <https://api.sipgate.com/v3/swagger.json>. IDs, phone lists and text are
/// validated by [`FlowClient::execute_v3_admin`] before the request is built.
/// The enum is `#[non_exhaustive]`; unknown future operations are not silently
/// sent through a generic verb/path escape hatch.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum V3AdminOperation {
    /// `GET /v3/account/cancellation`.
    AccountCancellation,
    /// `POST /v3/account/cancellation`.
    CreateAccountCancellation {
        /// Account holder, when the schema is used.
        holder: Option<String>,
        /// Refund account IBAN, when supplied.
        iban: Option<String>,
    },
    /// `DELETE /v3/account/cancellation`.
    RevokeAccountCancellation,
    /// `GET /v3/account/event-lifetime`.
    EventLifetime,
    /// `PUT /v3/account/event-lifetime`.
    SetEventLifetime(V3EventLifetime),
    /// `POST /v3/devices/mobile`.
    CreateMobileDevice {
        /// Display alias.
        alias: String,
        /// Owning user id.
        owner: Option<String>,
    },
    /// `POST /v3/devices/register`.
    CreateRegisterDevice {
        /// Display alias.
        alias: String,
        /// Owning user id.
        owner: Option<String>,
    },
    /// `PUT /v3/devices/{deviceId}/alias`.
    SetDeviceAlias {
        /// Device id.
        device_id: String,
        /// Value.
        value: String,
    },
    /// `PUT /v3/devices/{deviceId}/fancyCodec`.
    SetFancyCodec {
        /// Device id.
        device_id: String,
        /// Enabled.
        enabled: bool,
    },
    /// `PUT /v3/devices/{deviceId}/pending-sim`.
    SetPendingSim {
        /// Device id.
        device_id: String,
        /// Intended use.
        intended_use: V3SimIntendedUse,
        /// Alias.
        alias: Option<String>,
        /// Iccid.
        iccid: Option<String>,
        /// Mobile extension.
        mobile_extension: Option<String>,
    },
    /// `POST /v3/devices/{deviceId}/sim`.
    ActivateSim {
        /// Device id.
        device_id: String,
        /// Request.
        request: V3ActivateSimRequest,
    },
    /// `PUT /v3/devices/{deviceId}/sim/{simId}`.
    UpdateSim {
        /// Device id.
        device_id: String,
        /// Sim id.
        sim_id: String,
        /// Request.
        request: V3ActivateSimRequest,
    },
    /// `PUT /v3/devices/{deviceId}/sim/{simId}/intendedUse`.
    SetSimIntendedUse {
        /// Device id.
        device_id: String,
        /// Sim id.
        sim_id: String,
        /// Intended use.
        intended_use: V3SimIntendedUse,
    },
    /// `PUT /v3/devices/{deviceId}/smsSim`.
    SetSmsSim {
        /// Device id.
        device_id: String,
        /// Extension.
        extension: String,
    },
    /// `POST /v3/devices/{deviceId}/contracts`.
    CreateDeviceContract {
        /// Device id.
        device_id: String,
        /// Product id.
        product_id: String,
        /// Accepted tac id.
        accepted_tac_id: Option<String>,
    },
    /// `POST /v3/devices/{deviceId}/contracts/{contractId}/cancellation`.
    CancelDeviceContract {
        /// Device id.
        device_id: String,
        /// Contract id.
        contract_id: String,
        /// Cancellation date.
        cancellation_date: Option<String>,
    },
    /// `DELETE /v3/devices/{deviceId}/contracts/{contractId}/cancellation`.
    RevokeDeviceContractCancellation {
        /// Device id.
        device_id: String,
        /// Contract id.
        contract_id: String,
    },
    /// `PUT /v3/phone-numbers/mobile/opt-in`.
    ReleaseMobileNumbers {
        /// E164 numbers.
        e164_numbers: Vec<String>,
    },
    /// `PUT /v3/routings`.
    CreateRouting {
        /// E164 numbers.
        e164_numbers: Vec<String>,
        /// Extension.
        extension: String,
    },
    /// `DELETE /v3/routings`.
    DeleteRouting {
        /// E164 numbers.
        e164_numbers: Vec<String>,
    },
    /// `PUT /v3/routings/channel`.
    CreateChannelRouting {
        /// E164 numbers.
        e164_numbers: Vec<String>,
        /// Channel id.
        channel_id: String,
    },
    /// `POST /v3/fax`.
    CreateFax {
        /// Alias.
        alias: Option<String>,
        /// Owner id.
        owner_id: Option<String>,
    },
    /// `DELETE /v3/fax/{faxId}`.
    DeleteFax {
        /// Fax id.
        fax_id: String,
    },
    /// `PUT /v3/fax/{faxId}/alias`.
    SetFaxAlias {
        /// Fax id.
        fax_id: String,
        /// Alias.
        alias: String,
    },
    /// `PUT /v3/fax/{faxId}/callerId`.
    SetFaxCallerId {
        /// Fax id.
        fax_id: String,
        /// Anonymous.
        anonymous: Option<bool>,
        /// Caller id.
        caller_id: Option<String>,
    },
    /// `PUT /v3/fax/{faxId}/tagline`.
    SetFaxTagline {
        /// Fax id.
        fax_id: String,
        /// Tagline.
        tagline: String,
    },
    /// `POST /v3/faxlines`.
    CreateFaxline(V3CreateFaxlineRequest),
    /// `PUT /v3/faxlines/{faxId}/members`.
    AddFaxlineMembers {
        /// Fax id.
        fax_id: String,
        /// Member ids.
        member_ids: Vec<String>,
    },
    /// `DELETE /v3/faxlines/{faxId}/members`.
    RemoveFaxlineMembers {
        /// Fax id.
        fax_id: String,
        /// Member ids.
        member_ids: Vec<String>,
    },
    /// `PUT /v3/voicemails/{voicemailId}/activeGreeting`.
    SetVoicemailActiveGreeting {
        /// Voicemail id.
        voicemail_id: String,
        /// Greeting id.
        greeting_id: String,
    },
    /// `PUT /v3/voicemails/{voicemailId}/alias`.
    RenameVoicemail {
        /// Voicemail id.
        voicemail_id: String,
        /// Alias.
        alias: String,
    },
    /// `PUT /v3/voicemails/{voicemailId}/authorizedNumbers`.
    SetVoicemailAuthorizedNumbers {
        /// Voicemail id.
        voicemail_id: String,
        /// User id.
        user_id: Option<String>,
        /// Authorized numbers.
        authorized_numbers: Vec<String>,
    },
    /// `DELETE /v3/voicemails/{voicemailId}/pin`.
    DeleteVoicemailPin {
        /// Voicemail id.
        voicemail_id: String,
        /// User id.
        user_id: Option<String>,
    },
    /// `PUT /v3/voicemails/{voicemailId}/pin`.
    SetVoicemailPin {
        /// Voicemail id.
        voicemail_id: String,
        /// Pin.
        pin: String,
        /// User id.
        user_id: Option<String>,
    },
    /// `PUT /v3/voicemails/{voicemailId}/transcription`.
    SetVoicemailTranscription {
        /// Voicemail id.
        voicemail_id: String,
        /// Enabled.
        enabled: bool,
    },
    /// `PUT /v3/users/{userId}/name`.
    SetUserName {
        /// User id.
        user_id: String,
        /// First name.
        first_name: String,
        /// Last name.
        last_name: String,
    },
    /// `POST /v3/groups`.
    CreateGroup {
        /// Alias.
        alias: String,
    },
    /// `DELETE /v3/groups/{groupId}`.
    DeleteGroup {
        /// Group id.
        group_id: String,
    },
    /// `PUT /v3/groups/{groupId}/alias`.
    SetGroupAlias {
        /// Group id.
        group_id: String,
        /// Value.
        value: String,
    },
    /// `POST /v3/groups/{groupId}/callqueue`.
    CreateGroupCallQueue {
        /// Group id.
        group_id: String,
    },
    /// `DELETE /v3/groups/{groupId}/callqueue`.
    DeleteGroupCallQueue {
        /// Group id.
        group_id: String,
    },
    /// `PUT /v3/groups/{groupId}/callqueue/activeAudioFile`.
    SetGroupCallQueueAudio {
        /// Group id.
        group_id: String,
        /// Audio file id.
        audio_file_id: String,
    },
    /// `POST /v3/groups/{groupId}/contracts/statistics`.
    CreateGroupStatisticsContract {
        /// Group id.
        group_id: String,
        /// Tac accepted.
        tac_accepted: Option<bool>,
    },
    /// `POST /v3/groups/{groupId}/greeting`.
    CreateGroupGreeting {
        /// Group id.
        group_id: String,
    },
    /// `DELETE /v3/groups/{groupId}/greeting`.
    DeleteGroupGreeting {
        /// Group id.
        group_id: String,
    },
    /// `PUT /v3/groups/{groupId}/greeting/activeAudioFile`.
    SetGroupGreetingAudio {
        /// Group id.
        group_id: String,
        /// Audio file id.
        audio_file_id: String,
    },
    /// `PUT /v3/groups/{groupId}/members`.
    SetGroupMembers {
        /// Group id.
        group_id: String,
        /// Member ids.
        member_ids: Vec<String>,
    },
    /// `POST /v3/contracts`.
    BookContract {
        /// Product id.
        product_id: i32,
        /// Tac id.
        tac_id: Option<i32>,
    },
    /// `POST /v3/contracts/{contractId}/cancellation`.
    CancelContract {
        /// Contract id.
        contract_id: String,
        /// Cancellation date.
        cancellation_date: Option<String>,
    },
    /// `DELETE /v3/contracts/{contractId}/cancellation`.
    RevokeContractCancellation {
        /// Contract id.
        contract_id: String,
    },
    /// `POST /v3/trunks/bookMinutes`.
    BookTrunkMinutes {
        /// Product id.
        product_id: String,
        /// Trunk sip id.
        trunk_sip_id: String,
    },
    /// `POST /v3/trunks/contracts`.
    BookTrunkContract {
        /// Product id.
        product_id: Option<i32>,
        /// Alias.
        alias: Option<String>,
        /// Address id.
        address_id: Option<i32>,
    },
    /// `PUT /v3/trunks/contracts`.
    ChangeTrunkContract {
        /// Product id.
        product_id: Option<i32>,
        /// Replaces customer product id.
        replaces_customer_product_id: Option<i32>,
    },
    /// `POST /v3/trunks/contracts/cancellation`.
    CancelTrunkContract {
        /// Customer product id.
        customer_product_id: i32,
    },
    /// `DELETE /v3/trunks/contracts/cancellation`.
    RevokeTrunkContractCancellation {
        /// Customer product id.
        customer_product_id: i32,
    },
    /// `POST /v3/trunks/contracts/extension`.
    CreateTrunkExtension {
        /// Customer product id.
        customer_product_id: Option<i64>,
        /// Alias.
        alias: Option<String>,
        /// Emergency address id.
        emergency_address_id: Option<i32>,
    },
    /// `DELETE /v3/trunks/{trunkId}`.
    DeleteTrunk {
        /// Trunk id.
        trunk_id: String,
    },
    /// `PUT /v3/trunks/{trunkId}/alias`.
    SetTrunkAlias {
        /// Trunk id.
        trunk_id: String,
        /// Value.
        value: String,
    },
    /// `POST /v3/trunks/{trunkId}/credentialsPassword`.
    GenerateSipPassword {
        /// Trunk id.
        trunk_id: String,
    },
    /// `PUT /v3/trunks/{trunkId}/emergencyAddressId`.
    SetTrunkEmergencyAddress {
        /// Trunk id.
        trunk_id: String,
        /// Address id.
        address_id: i32,
    },
    /// `PUT /v3/trunks/{trunkId}/fallbackCallerId`.
    SetTrunkFallbackCallerId {
        /// Trunk id.
        trunk_id: String,
        /// Caller.
        caller: String,
    },
    /// `POST /v3/labels`.
    CreateLabel {
        /// Name.
        name: String,
    },
    /// `PUT /v3/labels/{labelId}`.
    RenameLabel {
        /// Label id.
        label_id: i32,
        /// Name.
        name: String,
    },
    /// `DELETE /v3/labels/{labelId}`.
    DeleteLabel {
        /// Label id.
        label_id: i32,
    },
}
/// The `ActivateSimRequest` body used by the two SIM write operations.
///
/// ```
/// use sipgate_flow::{V3ActivateSimRequest, V3SimIntendedUse};
///
/// let body = V3ActivateSimRequest::new(V3SimIntendedUse::Voice, "i0")?;
/// assert_eq!(body.to_json()["intendedUse"], "VOICE");
/// assert_eq!(body.to_json()["simId"], "i0");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct V3ActivateSimRequest {
    intended_use: V3SimIntendedUse,
    sim_id: Option<String>,
    alias: Option<String>,
}

impl V3ActivateSimRequest {
    /// Builds a request from the required intended use and SIM id.
    ///
    /// ```
    /// use sipgate_flow::{V3ActivateSimRequest, V3SimIntendedUse};
    ///
    /// assert!(V3ActivateSimRequest::new(V3SimIntendedUse::Data, "i0").is_ok());
    /// assert!(V3ActivateSimRequest::new(V3SimIntendedUse::Data, "").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when `sim_id` is empty or outside the path-safe
    /// identifier alphabet.
    pub fn new(intended_use: V3SimIntendedUse, sim_id: impl Into<String>) -> Result<Self> {
        let sim_id = sim_id.into();
        validate::path_segment("sim_id", &sim_id)?;
        Ok(Self {
            intended_use,
            sim_id: Some(sim_id),
            alias: None,
        })
    }

    /// Sets the SIM alias.
    ///
    /// ```
    /// use sipgate_flow::{V3ActivateSimRequest, V3SimIntendedUse};
    ///
    /// let request = V3ActivateSimRequest::new(V3SimIntendedUse::Voice, "i0")?.with_alias("Main SIM")?;
    /// assert_eq!(request.to_json()["alias"], "Main SIM");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the alias is empty or over
    /// [`MAX_V3_ADMIN_TEXT_BYTES`].
    pub fn with_alias(mut self, alias: impl Into<String>) -> Result<Self> {
        let alias = alias.into();
        validate_v3_text("alias", &alias)?;
        self.alias = Some(alias);
        Ok(self)
    }

    /// The documented request body.
    ///
    /// ```
    /// use sipgate_flow::{V3ActivateSimRequest, V3SimIntendedUse};
    ///
    /// assert_eq!(
    ///     V3ActivateSimRequest::new(V3SimIntendedUse::Voice, "i0")?.to_json(),
    ///     serde_json::json!({"intendedUse": "VOICE", "simId": "i0"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        body.insert("intendedUse".into(), json!(self.intended_use.as_str()));
        if let Some(sim_id) = &self.sim_id {
            body.insert("simId".into(), json!(sim_id));
        }
        if let Some(alias) = &self.alias {
            body.insert("alias".into(), json!(alias));
        }
        Value::Object(body)
    }
}

/// SIM intended use accepted by the v3 device endpoints.
///
/// ```
/// use sipgate_flow::V3SimIntendedUse;
///
/// assert_eq!(V3SimIntendedUse::parse("voice")?.as_str(), "VOICE");
/// assert_eq!(V3SimIntendedUse::parse("FUTURE")?.as_str(), "FUTURE");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum V3SimIntendedUse {
    /// Voice use.
    Voice,
    /// Data use.
    Data,
    /// A newer value, kept verbatim.
    Other(String),
}

impl V3SimIntendedUse {
    /// Parses a SIM intended-use value.
    ///
    /// ```
    /// use sipgate_flow::V3SimIntendedUse;
    /// assert_eq!(V3SimIntendedUse::parse("DATA")?, V3SimIntendedUse::Data);
    /// assert!(V3SimIntendedUse::parse("").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the token is empty or malformed.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_wire_token("intended_use", &value)?;
        let upper = value.to_ascii_uppercase();
        Ok(match upper.as_str() {
            "VOICE" => Self::Voice,
            "DATA" => Self::Data,
            _ => Self::Other(value),
        })
    }

    /// The canonical wire spelling.
    ///
    /// ```
    /// use sipgate_flow::V3SimIntendedUse;
    /// assert_eq!(V3SimIntendedUse::Data.as_str(), "DATA");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Voice => "VOICE",
            Self::Data => "DATA",
            Self::Other(value) => value,
        }
    }
}

/// The `CreateFaxlineRequest` body.
///
/// ```
/// use sipgate_flow::V3CreateFaxlineRequest;
///
/// let request = V3CreateFaxlineRequest::new("Support fax")?.with_owner_ids(["w0"])?;
/// assert_eq!(request.to_json()["alias"], "Support fax");
/// assert_eq!(request.to_json()["ownerIds"][0], "w0");
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct V3CreateFaxlineRequest {
    alias: String,
    owner_ids: Vec<String>,
}

impl V3CreateFaxlineRequest {
    /// Builds a faxline request from its required alias.
    ///
    /// ```
    /// use sipgate_flow::V3CreateFaxlineRequest;
    /// assert!(V3CreateFaxlineRequest::new("Support fax").is_ok());
    /// assert!(V3CreateFaxlineRequest::new("").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the alias is empty or over
    /// [`MAX_V3_ADMIN_TEXT_BYTES`].
    pub fn new(alias: impl Into<String>) -> Result<Self> {
        let alias = alias.into();
        validate_v3_text("alias", &alias)?;
        Ok(Self {
            alias,
            owner_ids: Vec::new(),
        })
    }

    /// Sets the owning user ids.
    ///
    /// ```
    /// use sipgate_flow::V3CreateFaxlineRequest;
    ///
    /// let request = V3CreateFaxlineRequest::new("Support fax")?.with_owner_ids(["w0"])?;
    /// assert_eq!(request.to_json()["ownerIds"], serde_json::json!(["w0"]));
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when the list exceeds
    /// [`MAX_V3_ADMIN_BATCH_ITEMS`] or contains a malformed path id.
    pub fn with_owner_ids<I, S>(mut self, owner_ids: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.owner_ids = validate_v3_ids("owner_ids", owner_ids)?;
        Ok(self)
    }

    /// Renders the documented body.
    ///
    /// ```
    /// use sipgate_flow::V3CreateFaxlineRequest;
    /// assert_eq!(
    ///     V3CreateFaxlineRequest::new("Support fax")?.to_json(),
    ///     serde_json::json!({"alias": "Support fax"})
    /// );
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        body.insert("alias".into(), json!(self.alias));
        if !self.owner_ids.is_empty() {
            body.insert("ownerIds".into(), json!(self.owner_ids));
        }
        Value::Object(body)
    }
}

/// A successful v3 administration response.
///
/// JSON bodies are preserved exactly; `204` and other empty success bodies
/// become `null`. Unknown response fields therefore stay available through
/// [`Self::body`] without a second DTO per operation.
///
/// ```
/// use sipgate_flow::V3AdminResponse;
///
/// let response = V3AdminResponse::from_parts(200, br#"{"contractId":"c1","future":true}"#)?;
/// assert_eq!(response.status(), 200);
/// assert_eq!(response.body()["future"], true);
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct V3AdminResponse {
    status: u16,
    body: Value,
}

impl V3AdminResponse {
    /// Builds a response from status and bytes, accepting an empty body.
    ///
    /// ```
    /// use sipgate_flow::V3AdminResponse;
    ///
    /// assert_eq!(V3AdminResponse::from_parts(204, b"")?.body(), &serde_json::Value::Null);
    /// assert!(V3AdminResponse::from_parts(200, b"not json").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the body is non-empty and not valid JSON.
    pub fn from_parts(status: u16, body: &[u8]) -> Result<Self> {
        let body = if body.iter().all(u8::is_ascii_whitespace) {
            Value::Null
        } else {
            serde_json::from_slice(body).map_err(Error::json_parse)?
        };
        Ok(Self { status, body })
    }

    /// The HTTP status.
    ///
    /// ```
    /// use sipgate_flow::V3AdminResponse;
    /// assert_eq!(V3AdminResponse::from_parts(201, b"{}")?.status(), 201);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The decoded response body, or `null` for an empty success.
    ///
    /// ```
    /// use sipgate_flow::V3AdminResponse;
    /// assert_eq!(V3AdminResponse::from_parts(200, br#"{"x":1}"#)?.body()["x"], 1);
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    #[must_use]
    pub fn body(&self) -> &Value {
        &self.body
    }
}

impl<T: Transport, A: TokenSource> FlowClient<T, A> {
    /// Executes one typed v3 account-administration operation.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken, V3AdminOperation};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let response = client.execute_v3_admin(&V3AdminOperation::EventLifetime).await?;
    /// println!("{:?}", response.body());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] when any identifier, text, phone or batch value is
    /// malformed, plus the generic transport, auth, JSON and API errors. The
    /// caller's method decides retry safety: a retryable `POST` failure is
    /// [`Error::Ambiguous`], exactly as elsewhere in the crate.
    pub async fn execute_v3_admin(&self, operation: &V3AdminOperation) -> Result<V3AdminResponse> {
        let (method, path, body) = operation.request_parts()?;
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
            method,
            body.as_ref(),
        )
        .await?;
        if response.is_success() {
            return V3AdminResponse::from_parts(response.status(), response.body());
        }
        Err(crate::retry::api_error(
            method,
            response.status(),
            &response.headers(),
            &response.text(),
        ))
    }

    /// Reads the account cancellation status.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// let status = client.v3_account_cancellation().await?;
    /// println!("{:?}", status.body());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The generic transport, auth, JSON and API errors.
    pub async fn v3_account_cancellation(&self) -> Result<V3AdminResponse> {
        self.execute_v3_admin(&V3AdminOperation::AccountCancellation)
            .await
    }

    /// Marks the account for cancellation and refund.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken, V3AdminOperation};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.execute_v3_admin(&V3AdminOperation::CreateAccountCancellation {
    ///     holder: Some("Example GmbH".into()),
    ///     iban: Some("DE75512108001245126199".into()),
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The generic transport, auth, JSON and API errors. `POST` may have
    /// applied the cancellation if a retryable failure has no usable response.
    pub async fn request_v3_account_cancellation(
        &self,
        holder: Option<String>,
        iban: Option<String>,
    ) -> Result<V3AdminResponse> {
        self.execute_v3_admin(&V3AdminOperation::CreateAccountCancellation { holder, iban })
            .await
    }

    /// Revokes an account cancellation.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.revoke_v3_account_cancellation().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The generic transport, auth, JSON and API errors. `DELETE` is idempotent.
    pub async fn revoke_v3_account_cancellation(&self) -> Result<V3AdminResponse> {
        self.execute_v3_admin(&V3AdminOperation::RevokeAccountCancellation)
            .await
    }

    /// Reads the account event-lifetime setting.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// println!("{:?}", client.v3_event_lifetime().await?.body());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The generic transport, auth, JSON and API errors.
    pub async fn v3_event_lifetime(&self) -> Result<V3AdminResponse> {
        self.execute_v3_admin(&V3AdminOperation::EventLifetime)
            .await
    }

    /// Replaces the account event-lifetime setting.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken, V3EventLifetime};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.set_v3_event_lifetime(V3EventLifetime::ThirtyDays).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The generic transport, auth, JSON and API errors. `PUT` is idempotent.
    pub async fn set_v3_event_lifetime(
        &self,
        lifetime: V3EventLifetime,
    ) -> Result<V3AdminResponse> {
        self.execute_v3_admin(&V3AdminOperation::SetEventLifetime(lifetime))
            .await
    }

    /// Creates a routing to an extension.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.create_v3_routing(["+49211123456"], "g3").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for an empty/oversized batch, a non-E.164 number
    /// or a malformed extension, plus the generic request errors. `PUT` is
    /// idempotent.
    pub async fn create_v3_routing<I, S>(
        &self,
        e164_numbers: I,
        extension: impl Into<String>,
    ) -> Result<V3AdminResponse>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.execute_v3_admin(&V3AdminOperation::CreateRouting {
            e164_numbers: e164_numbers.into_iter().map(Into::into).collect(),
            extension: extension.into(),
        })
        .await
    }

    /// Creates a fax line.
    ///
    /// ```no_run
    /// # #[cfg(feature = "http")]
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// use sipgate_flow::{FlowClient, ReqwestTransport, StaticToken, V3CreateFaxlineRequest};
    ///
    /// let client = FlowClient::new(ReqwestTransport::new(), StaticToken::new(std::env::var("SIPGATE_TOKEN")?)?);
    /// client.create_v3_faxline(&V3CreateFaxlineRequest::new("Support fax")?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The generic transport, auth, JSON and API errors. `POST` is ambiguous if
    /// a retryable failure has no usable response.
    pub async fn create_v3_faxline(
        &self,
        request: &V3CreateFaxlineRequest,
    ) -> Result<V3AdminResponse> {
        self.execute_v3_admin(&V3AdminOperation::CreateFaxline(request.clone()))
            .await
    }
}

impl V3AdminOperation {
    /// The HTTP method this operation uses.
    ///
    /// ```
    /// use sipgate_flow::{Method, V3AdminOperation};
    /// assert_eq!(V3AdminOperation::DeleteTrunk { trunk_id: "t0".into() }.method(), Method::Delete);
    /// ```
    #[must_use]
    pub fn method(&self) -> Method {
        match self {
            Self::AccountCancellation | Self::EventLifetime => Method::Get,
            Self::CreateAccountCancellation { .. }
            | Self::CreateMobileDevice { .. }
            | Self::CreateRegisterDevice { .. }
            | Self::ActivateSim { .. }
            | Self::CreateDeviceContract { .. }
            | Self::CreateFax { .. }
            | Self::CreateFaxline(_)
            | Self::CreateGroup { .. }
            | Self::CreateGroupCallQueue { .. }
            | Self::CreateGroupGreeting { .. }
            | Self::CreateGroupStatisticsContract { .. }
            | Self::BookContract { .. }
            | Self::CancelContract { .. }
            | Self::CancelDeviceContract { .. }
            | Self::BookTrunkMinutes { .. }
            | Self::BookTrunkContract { .. }
            | Self::CancelTrunkContract { .. }
            | Self::CreateTrunkExtension { .. }
            | Self::GenerateSipPassword { .. }
            | Self::CreateLabel { .. } => Method::Post,
            Self::RevokeAccountCancellation
            | Self::DeleteFax { .. }
            | Self::RemoveFaxlineMembers { .. }
            | Self::DeleteVoicemailPin { .. }
            | Self::DeleteGroup { .. }
            | Self::DeleteGroupCallQueue { .. }
            | Self::DeleteGroupGreeting { .. }
            | Self::RevokeContractCancellation { .. }
            | Self::RevokeDeviceContractCancellation { .. }
            | Self::RevokeTrunkContractCancellation { .. }
            | Self::DeleteTrunk { .. }
            | Self::DeleteLabel { .. }
            | Self::DeleteRouting { .. } => Method::Delete,
            Self::SetEventLifetime(_)
            | Self::SetDeviceAlias { .. }
            | Self::SetFancyCodec { .. }
            | Self::SetPendingSim { .. }
            | Self::UpdateSim { .. }
            | Self::SetSimIntendedUse { .. }
            | Self::SetSmsSim { .. }
            | Self::ReleaseMobileNumbers { .. }
            | Self::CreateRouting { .. }
            | Self::CreateChannelRouting { .. }
            | Self::SetFaxAlias { .. }
            | Self::SetFaxCallerId { .. }
            | Self::SetFaxTagline { .. }
            | Self::AddFaxlineMembers { .. }
            | Self::SetVoicemailActiveGreeting { .. }
            | Self::RenameVoicemail { .. }
            | Self::SetVoicemailAuthorizedNumbers { .. }
            | Self::SetVoicemailPin { .. }
            | Self::SetVoicemailTranscription { .. }
            | Self::SetUserName { .. }
            | Self::SetGroupAlias { .. }
            | Self::SetGroupCallQueueAudio { .. }
            | Self::SetGroupGreetingAudio { .. }
            | Self::SetGroupMembers { .. }
            | Self::ChangeTrunkContract { .. }
            | Self::SetTrunkAlias { .. }
            | Self::SetTrunkEmergencyAddress { .. }
            | Self::SetTrunkFallbackCallerId { .. }
            | Self::RenameLabel { .. } => Method::Put,
        }
    }

    /// Validates the operation and returns its method, path and JSON body.
    ///
    /// ```
    /// use sipgate_flow::{Method, V3AdminOperation};
    ///
    /// let (method, path, body) = V3AdminOperation::SetUserName {
    ///     user_id: "w1".into(),
    ///     first_name: "Grace".into(),
    ///     last_name: "Hopper".into(),
    /// }.request_parts()?;
    /// assert_eq!(method, Method::Put);
    /// assert_eq!(path, "/v3/users/w1/name");
    /// assert_eq!(body.expect("body")["firstName"], "Grace");
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for any malformed identifier, phone number, text
    /// or batch value.
    pub fn request_parts(&self) -> Result<(Method, String, Option<Value>)> {
        let method = self.method();
        let (path, body) = if let Some(parts) = self.account_parts()? {
            parts
        } else if let Some(parts) = self.device_parts()? {
            parts
        } else if let Some(parts) = self.sim_parts()? {
            parts
        } else if let Some(parts) = self.device_contract_parts()? {
            parts
        } else if let Some(parts) = self.routing_parts()? {
            parts
        } else if let Some(parts) = self.fax_parts()? {
            parts
        } else if let Some(parts) = self.faxline_parts()? {
            parts
        } else if let Some(parts) = self.voicemail_parts()? {
            parts
        } else if let Some(parts) = self.voicemail_security_parts()? {
            parts
        } else if let Some(parts) = self.user_parts()? {
            parts
        } else if let Some(parts) = self.group_core_parts()? {
            parts
        } else if let Some(parts) = self.group_media_parts()? {
            parts
        } else if let Some(parts) = self.contract_parts()? {
            parts
        } else if let Some(parts) = self.trunk_contract_parts()? {
            parts
        } else if let Some(parts) = self.trunk_contract_admin_parts()? {
            parts
        } else if let Some(parts) = self.trunk_parts()? {
            parts
        } else if let Some(parts) = self.label_parts()? {
            parts
        } else {
            return Err(Error::validation(
                "operation",
                "unsupported v3 administration operation",
            ));
        };
        Ok((method, path, body))
    }

    fn account_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::AccountCancellation | Self::RevokeAccountCancellation => {
                ("/v3/account/cancellation".to_string(), None)
            }
            Self::CreateAccountCancellation { holder, iban } => {
                let mut body = Map::new();
                insert_optional_text(&mut body, "holder", holder.as_deref(), false)?;
                insert_optional_text(&mut body, "iban", iban.as_deref(), false)?;
                (
                    "/v3/account/cancellation".to_string(),
                    Some(Value::Object(body)),
                )
            }
            Self::EventLifetime => ("/v3/account/event-lifetime".to_string(), None),
            Self::SetEventLifetime(lifetime) => (
                "/v3/account/event-lifetime".to_string(),
                Some(json!({ "eventLifetime": lifetime.as_str() })),
            ),
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn device_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::CreateMobileDevice { alias, owner }
            | Self::CreateRegisterDevice { alias, owner } => {
                validate_v3_text("alias", alias)?;
                let path = if matches!(self, Self::CreateMobileDevice { .. }) {
                    "/v3/devices/mobile"
                } else {
                    "/v3/devices/register"
                };
                let mut body = Map::new();
                body.insert("alias".into(), json!(alias));
                insert_optional_id(&mut body, "owner", owner.as_deref())?;
                (path.to_string(), Some(Value::Object(body)))
            }
            Self::SetDeviceAlias { device_id, value } => {
                validate_v3_path_id("device_id", device_id)?;
                validate_v3_text("value", value)?;
                (
                    format!("/v3/devices/{device_id}/alias"),
                    Some(json!({ "value": value })),
                )
            }
            Self::SetFancyCodec { device_id, enabled } => {
                validate_v3_path_id("device_id", device_id)?;
                (
                    format!("/v3/devices/{device_id}/fancyCodec"),
                    Some(json!({ "enabled": enabled })),
                )
            }
            Self::SetPendingSim {
                device_id,
                intended_use,
                alias,
                iccid,
                mobile_extension,
            } => {
                validate_v3_path_id("device_id", device_id)?;
                let mut body = Map::new();
                body.insert("intendedUse".into(), json!(intended_use.as_str()));
                insert_optional_text(&mut body, "alias", alias.as_deref(), false)?;
                insert_optional_text(&mut body, "iccid", iccid.as_deref(), false)?;
                insert_optional_id(&mut body, "mobileExtension", mobile_extension.as_deref())?;
                (
                    format!("/v3/devices/{device_id}/pending-sim"),
                    Some(Value::Object(body)),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn sim_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::ActivateSim { device_id, request } => {
                validate_v3_path_id("device_id", device_id)?;
                validate_activate_sim(request)?;
                (
                    format!("/v3/devices/{device_id}/sim"),
                    Some(request.to_json()),
                )
            }
            Self::UpdateSim {
                device_id,
                sim_id,
                request,
            } => {
                validate_v3_path_id("device_id", device_id)?;
                validate_v3_path_id("sim_id", sim_id)?;
                validate_activate_sim(request)?;
                (
                    format!("/v3/devices/{device_id}/sim/{sim_id}"),
                    Some(request.to_json()),
                )
            }
            Self::SetSimIntendedUse {
                device_id,
                sim_id,
                intended_use,
            } => {
                validate_v3_path_id("device_id", device_id)?;
                validate_v3_path_id("sim_id", sim_id)?;
                (
                    format!("/v3/devices/{device_id}/sim/{sim_id}/intendedUse"),
                    Some(json!({ "value": intended_use.as_str() })),
                )
            }
            Self::SetSmsSim {
                device_id,
                extension,
            } => {
                validate_v3_path_id("device_id", device_id)?;
                validate_v3_path_id("extension", extension)?;
                (
                    format!("/v3/devices/{device_id}/smsSim"),
                    Some(json!({ "simExtension": extension })),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn device_contract_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::CreateDeviceContract {
                device_id,
                product_id,
                accepted_tac_id,
            } => {
                validate_v3_path_id("device_id", device_id)?;
                validate_v3_text("product_id", product_id)?;
                let mut body = Map::new();
                body.insert("productId".into(), json!(product_id));
                insert_optional_text(
                    &mut body,
                    "acceptedTacId",
                    accepted_tac_id.as_deref(),
                    false,
                )?;
                (
                    format!("/v3/devices/{device_id}/contracts"),
                    Some(Value::Object(body)),
                )
            }
            Self::CancelDeviceContract {
                device_id,
                contract_id,
                cancellation_date,
            } => {
                validate_v3_path_id("device_id", device_id)?;
                validate_v3_path_id("contract_id", contract_id)?;
                (
                    format!("/v3/devices/{device_id}/contracts/{contract_id}/cancellation"),
                    cancellation_date_body(cancellation_date.as_deref())?,
                )
            }
            Self::RevokeDeviceContractCancellation {
                device_id,
                contract_id,
            } => {
                validate_v3_path_id("device_id", device_id)?;
                validate_v3_path_id("contract_id", contract_id)?;
                (
                    format!("/v3/devices/{device_id}/contracts/{contract_id}/cancellation"),
                    None,
                )
            }
            Self::ReleaseMobileNumbers { e164_numbers } => (
                "/v3/phone-numbers/mobile/opt-in".to_string(),
                Some(json!({ "e164Numbers": validate_e164_list(e164_numbers)? })),
            ),
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn routing_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::CreateRouting {
                e164_numbers,
                extension,
            } => {
                validate_v3_path_id("extension", extension)?;
                (
                    "/v3/routings".to_string(),
                    Some(json!({
                        "e164Numbers": validate_e164_list(e164_numbers)?,
                        "extension": extension,
                    })),
                )
            }
            Self::DeleteRouting { e164_numbers } => (
                "/v3/routings".to_string(),
                Some(json!({ "e164Numbers": validate_e164_list(e164_numbers)? })),
            ),
            Self::CreateChannelRouting {
                e164_numbers,
                channel_id,
            } => {
                validate_v3_path_id("channel_id", channel_id)?;
                (
                    "/v3/routings/channel".to_string(),
                    Some(json!({
                        "e164Numbers": validate_e164_list(e164_numbers)?,
                        "channelId": channel_id,
                    })),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn fax_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::CreateFax { alias, owner_id } => {
                let mut body = Map::new();
                insert_optional_text(&mut body, "alias", alias.as_deref(), false)?;
                insert_optional_id(&mut body, "ownerId", owner_id.as_deref())?;
                ("/v3/fax".to_string(), Some(Value::Object(body)))
            }
            Self::DeleteFax { fax_id } => (format!("/v3/fax/{}", path_id(fax_id, "fax_id")?), None),
            Self::SetFaxAlias { fax_id, alias } => {
                validate_v3_path_id("fax_id", fax_id)?;
                validate_v3_text("alias", alias)?;
                (
                    format!("/v3/fax/{fax_id}/alias"),
                    Some(json!({ "alias": alias })),
                )
            }
            Self::SetFaxCallerId {
                fax_id,
                anonymous,
                caller_id,
            } => {
                validate_v3_path_id("fax_id", fax_id)?;
                let mut body = Map::new();
                if let Some(anonymous) = anonymous {
                    body.insert("anonymous".into(), json!(anonymous));
                }
                insert_optional_text(&mut body, "callerId", caller_id.as_deref(), false)?;
                (
                    format!("/v3/fax/{fax_id}/callerId"),
                    Some(Value::Object(body)),
                )
            }
            Self::SetFaxTagline { fax_id, tagline } => {
                validate_v3_path_id("fax_id", fax_id)?;
                validate_v3_text("tagline", tagline)?;
                (
                    format!("/v3/fax/{fax_id}/tagline"),
                    Some(json!({ "tagline": tagline })),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn faxline_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::CreateFaxline(request) => ("/v3/faxlines".to_string(), Some(request.to_json())),
            Self::AddFaxlineMembers { fax_id, member_ids }
            | Self::RemoveFaxlineMembers { fax_id, member_ids } => {
                validate_v3_path_id("fax_id", fax_id)?;
                let members = validate_v3_ids("member_ids", member_ids.iter().cloned())?;
                (
                    format!("/v3/faxlines/{fax_id}/members"),
                    Some(json!({ "memberIds": members })),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn voicemail_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::SetVoicemailActiveGreeting {
                voicemail_id,
                greeting_id,
            } => {
                validate_v3_path_id("voicemail_id", voicemail_id)?;
                validate_v3_text("greeting_id", greeting_id)?;
                (
                    format!("/v3/voicemails/{voicemail_id}/activeGreeting"),
                    Some(json!({ "greetingId": greeting_id })),
                )
            }
            Self::RenameVoicemail {
                voicemail_id,
                alias,
            } => {
                validate_v3_path_id("voicemail_id", voicemail_id)?;
                validate_v3_text("alias", alias)?;
                (
                    format!("/v3/voicemails/{voicemail_id}/alias"),
                    Some(json!({ "alias": alias })),
                )
            }
            Self::SetVoicemailAuthorizedNumbers {
                voicemail_id,
                user_id,
                authorized_numbers,
            } => {
                validate_v3_path_id("voicemail_id", voicemail_id)?;
                let numbers = validate_digits_list(authorized_numbers)?;
                let mut body = Map::new();
                body.insert("authorizedNumbers".into(), json!(numbers));
                insert_optional_id(&mut body, "userId", user_id.as_deref())?;
                (
                    format!("/v3/voicemails/{voicemail_id}/authorizedNumbers"),
                    Some(Value::Object(body)),
                )
            }
            Self::SetVoicemailTranscription {
                voicemail_id,
                enabled,
            } => {
                validate_v3_path_id("voicemail_id", voicemail_id)?;
                (
                    format!("/v3/voicemails/{voicemail_id}/transcription"),
                    Some(json!({ "enabled": enabled })),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn voicemail_security_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::DeleteVoicemailPin {
                voicemail_id,
                user_id,
            } => {
                validate_v3_path_id("voicemail_id", voicemail_id)?;
                let mut body = Map::new();
                insert_optional_id(&mut body, "userId", user_id.as_deref())?;
                (
                    format!("/v3/voicemails/{voicemail_id}/pin"),
                    Some(Value::Object(body)),
                )
            }
            Self::SetVoicemailPin {
                voicemail_id,
                pin,
                user_id,
            } => {
                validate_v3_path_id("voicemail_id", voicemail_id)?;
                validate_v3_pin(pin)?;
                let mut body = Map::new();
                body.insert("pin".into(), json!(pin));
                insert_optional_id(&mut body, "userId", user_id.as_deref())?;
                (
                    format!("/v3/voicemails/{voicemail_id}/pin"),
                    Some(Value::Object(body)),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn user_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        match self {
            Self::SetUserName {
                user_id,
                first_name,
                last_name,
            } => {
                validate_v3_path_id("user_id", user_id)?;
                validate_v3_text("first_name", first_name)?;
                validate_v3_text("last_name", last_name)?;
                Ok(Some((
                    format!("/v3/users/{user_id}/name"),
                    Some(json!({ "firstName": first_name, "lastName": last_name })),
                )))
            }
            _ => Ok(None),
        }
    }

    fn group_core_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::CreateGroup { alias } => {
                validate_v3_text("alias", alias)?;
                ("/v3/groups".to_string(), Some(json!({ "alias": alias })))
            }
            Self::DeleteGroup { group_id } => (
                format!("/v3/groups/{}", path_id(group_id, "group_id")?),
                None,
            ),
            Self::SetGroupAlias { group_id, value } => {
                validate_v3_path_id("group_id", group_id)?;
                validate_v3_text("value", value)?;
                (
                    format!("/v3/groups/{group_id}/alias"),
                    Some(json!({ "value": value })),
                )
            }
            Self::CreateGroupCallQueue { group_id } | Self::DeleteGroupCallQueue { group_id } => (
                format!("/v3/groups/{}/callqueue", path_id(group_id, "group_id")?),
                None,
            ),
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn group_media_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::SetGroupCallQueueAudio {
                group_id,
                audio_file_id,
            } => {
                validate_v3_path_id("group_id", group_id)?;
                validate_v3_text("audio_file_id", audio_file_id)?;
                (
                    format!("/v3/groups/{group_id}/callqueue/activeAudioFile"),
                    Some(json!({ "audioFileId": audio_file_id })),
                )
            }
            Self::CreateGroupStatisticsContract {
                group_id,
                tac_accepted,
            } => {
                validate_v3_path_id("group_id", group_id)?;
                let body = tac_accepted
                    .map_or_else(|| json!({}), |accepted| json!({ "tacAccepted": accepted }));
                (
                    format!("/v3/groups/{group_id}/contracts/statistics"),
                    Some(body),
                )
            }
            Self::CreateGroupGreeting { group_id } | Self::DeleteGroupGreeting { group_id } => (
                format!("/v3/groups/{}/greeting", path_id(group_id, "group_id")?),
                None,
            ),
            Self::SetGroupGreetingAudio {
                group_id,
                audio_file_id,
            } => {
                validate_v3_path_id("group_id", group_id)?;
                validate_v3_text("audio_file_id", audio_file_id)?;
                (
                    format!("/v3/groups/{group_id}/greeting/activeAudioFile"),
                    Some(json!({ "audioFileId": audio_file_id })),
                )
            }
            Self::SetGroupMembers {
                group_id,
                member_ids,
            } => {
                validate_v3_path_id("group_id", group_id)?;
                let members = validate_v3_ids("member_ids", member_ids.iter().cloned())?;
                (
                    format!("/v3/groups/{group_id}/members"),
                    Some(json!({ "memberIds": members })),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn contract_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::BookContract { product_id, tac_id } => {
                let mut body = Map::new();
                body.insert("productId".into(), json!(product_id));
                if let Some(tac_id) = tac_id {
                    body.insert("tacId".into(), json!(tac_id));
                }
                ("/v3/contracts".to_string(), Some(Value::Object(body)))
            }
            Self::CancelContract {
                contract_id,
                cancellation_date,
            } => (
                format!(
                    "/v3/contracts/{}/cancellation",
                    path_id(contract_id, "contract_id")?
                ),
                cancellation_date_body(cancellation_date.as_deref())?,
            ),
            Self::RevokeContractCancellation { contract_id } => (
                format!(
                    "/v3/contracts/{}/cancellation",
                    path_id(contract_id, "contract_id")?
                ),
                None,
            ),
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn trunk_contract_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::BookTrunkMinutes {
                product_id,
                trunk_sip_id,
            } => {
                validate_v3_text("product_id", product_id)?;
                validate_v3_text("trunk_sip_id", trunk_sip_id)?;
                (
                    "/v3/trunks/bookMinutes".to_string(),
                    Some(json!({ "productId": product_id, "trunkSipId": trunk_sip_id })),
                )
            }
            Self::BookTrunkContract {
                product_id,
                alias,
                address_id,
            } => {
                let mut body = Map::new();
                if let Some(product_id) = product_id {
                    body.insert("productId".into(), json!(product_id));
                }
                insert_optional_text(&mut body, "alias", alias.as_deref(), false)?;
                if let Some(address_id) = address_id {
                    body.insert("addressId".into(), json!(address_id));
                }
                (
                    "/v3/trunks/contracts".to_string(),
                    Some(Value::Object(body)),
                )
            }
            Self::ChangeTrunkContract {
                product_id,
                replaces_customer_product_id,
            } => {
                let mut body = Map::new();
                if let Some(product_id) = product_id {
                    body.insert("productId".into(), json!(product_id));
                }
                if let Some(id) = replaces_customer_product_id {
                    body.insert("replacesCustomerProductId".into(), json!(id));
                }
                (
                    "/v3/trunks/contracts".to_string(),
                    Some(Value::Object(body)),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn trunk_contract_admin_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::CancelTrunkContract {
                customer_product_id,
            }
            | Self::RevokeTrunkContractCancellation {
                customer_product_id,
            } => (
                "/v3/trunks/contracts/cancellation".to_string(),
                Some(json!({ "customerProductId": customer_product_id })),
            ),
            Self::CreateTrunkExtension {
                customer_product_id,
                alias,
                emergency_address_id,
            } => {
                let mut body = Map::new();
                if let Some(id) = customer_product_id {
                    body.insert("customerProductId".into(), json!(id));
                }
                insert_optional_text(&mut body, "alias", alias.as_deref(), false)?;
                if let Some(id) = emergency_address_id {
                    body.insert("emergencyAddressId".into(), json!(id));
                }
                (
                    "/v3/trunks/contracts/extension".to_string(),
                    Some(Value::Object(body)),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn trunk_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::DeleteTrunk { trunk_id } => (
                format!("/v3/trunks/{}", path_id(trunk_id, "trunk_id")?),
                None,
            ),
            Self::SetTrunkAlias { trunk_id, value } => {
                validate_v3_path_id("trunk_id", trunk_id)?;
                validate_v3_text("value", value)?;
                (
                    format!("/v3/trunks/{trunk_id}/alias"),
                    Some(json!({ "value": value })),
                )
            }
            Self::GenerateSipPassword { trunk_id } => (
                format!(
                    "/v3/trunks/{}/credentialsPassword",
                    path_id(trunk_id, "trunk_id")?
                ),
                None,
            ),
            Self::SetTrunkEmergencyAddress {
                trunk_id,
                address_id,
            } => {
                validate_v3_path_id("trunk_id", trunk_id)?;
                (
                    format!("/v3/trunks/{trunk_id}/emergencyAddressId"),
                    Some(json!({ "addressId": address_id })),
                )
            }
            Self::SetTrunkFallbackCallerId { trunk_id, caller } => {
                validate_v3_path_id("trunk_id", trunk_id)?;
                validate_v3_e164("caller", caller)?;
                (
                    format!("/v3/trunks/{trunk_id}/fallbackCallerId"),
                    Some(json!({ "callerE164Number": caller })),
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }

    fn label_parts(&self) -> Result<Option<(String, Option<Value>)>> {
        let parts = match self {
            Self::CreateLabel { name } => {
                validate_v3_text("name", name)?;
                ("/v3/labels".to_string(), Some(json!({ "name": name })))
            }
            Self::RenameLabel { label_id, name } => {
                validate_v3_label_id(*label_id)?;
                validate_v3_text("name", name)?;
                (
                    format!("/v3/labels/{label_id}"),
                    Some(json!({ "name": name })),
                )
            }
            Self::DeleteLabel { label_id } => {
                validate_v3_label_id(*label_id)?;
                (format!("/v3/labels/{label_id}"), None)
            }
            _ => return Ok(None),
        };
        Ok(Some(parts))
    }
}

fn validate_v3_text(field: &'static str, value: &str) -> Result<()> {
    validate::non_empty(field, value, MAX_V3_ADMIN_TEXT_BYTES)
}

fn validate_v3_path_id(field: &'static str, value: &str) -> Result<()> {
    validate::path_segment(field, value)
}

fn path_id(value: &str, field: &'static str) -> Result<String> {
    validate_v3_path_id(field, value)?;
    Ok(value.to_string())
}

fn validate_v3_label_id(value: i32) -> Result<()> {
    if value <= 0 {
        return Err(Error::validation("label_id", "must be a positive int32"));
    }
    Ok(())
}

fn validate_v3_batch_len<T>(items: &[T]) -> Result<()> {
    if items.is_empty() {
        return Err(Error::validation("items", "must not be empty"));
    }
    if items.len() > MAX_V3_ADMIN_BATCH_ITEMS {
        return Err(Error::validation(
            "items",
            format!("must contain at most {MAX_V3_ADMIN_BATCH_ITEMS} entries"),
        ));
    }
    Ok(())
}

fn validate_v3_ids<I, S>(field: &'static str, values: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let values = values.into_iter().map(Into::into).collect::<Vec<_>>();
    validate_v3_batch_len(&values)?;
    for value in &values {
        validate::path_segment(field, value)?;
    }
    Ok(values)
}

fn validate_v3_e164(field: &'static str, value: &str) -> Result<()> {
    if !value.starts_with('+') {
        return Err(Error::validation(field, "must be E.164 with a leading +"));
    }
    validate::phone(field, value).map(|_| ())
}

fn validate_e164_list(values: &[String]) -> Result<Vec<String>> {
    validate_v3_batch_len(values)?;
    for value in values {
        validate_v3_e164("e164_numbers", value)?;
    }
    Ok(values.to_vec())
}

fn validate_digits_list(values: &[String]) -> Result<Vec<String>> {
    validate_v3_batch_len(values)?;
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        validate::non_empty("authorized_numbers", value, validate::MAX_SESSION_ID)?;
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::validation(
                "authorized_numbers",
                "must contain only digits",
            ));
        }
        out.push(value.clone());
    }
    Ok(out)
}

fn validate_v3_pin(pin: &str) -> Result<()> {
    validate::non_empty("pin", pin, 64)?;
    if !pin.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::validation("pin", "must contain only digits"));
    }
    Ok(())
}

fn validate_activate_sim(request: &V3ActivateSimRequest) -> Result<()> {
    if let Some(sim_id) = &request.sim_id {
        validate_v3_path_id("sim_id", sim_id)?;
    }
    if let Some(alias) = &request.alias {
        validate_v3_text("alias", alias)?;
    }
    Ok(())
}

fn insert_optional_text(
    body: &mut Map<String, Value>,
    name: &'static str,
    value: Option<&str>,
    require_non_empty: bool,
) -> Result<()> {
    if let Some(value) = value {
        if require_non_empty || !value.is_empty() {
            validate_v3_text(name, value)?;
        }
        body.insert(name.into(), json!(value));
    }
    Ok(())
}

fn insert_optional_id(
    body: &mut Map<String, Value>,
    name: &'static str,
    value: Option<&str>,
) -> Result<()> {
    if let Some(value) = value {
        validate_v3_path_id(name, value)?;
        body.insert(name.into(), json!(value));
    }
    Ok(())
}

fn cancellation_date_body(date: Option<&str>) -> Result<Option<Value>> {
    if let Some(date) = date {
        validate_v3_text("cancellation_date", date)?;
        Ok(Some(json!({ "cancellationDate": date })))
    } else {
        Ok(None)
    }
}
