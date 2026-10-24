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

use std::time::Duration;

use serde_json::{json, Value};

use crate::auth::{StaticToken, TokenSource};
use crate::error::Result;
use crate::exchange;
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
            timeout: None,
        }
    }

    /// Overrides the base URL.
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
    ///     .with_base_url("http://localhost:8080/");
    /// assert_eq!(client.base_url(), "http://localhost:8080");
    /// ```
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into().trim_end_matches('/').to_string();
        self
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
    /// documented `201 Created`; a 400 means the Flow has no phone number, 404
    /// means the Flow does not exist.
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
    /// [`crate::Error::Api`] for a non-2xx answer, plus transport and auth errors.
    /// There is no retry: starting a call twice would dial the number twice.
    pub async fn call(&self, request: &OutboundCall) -> Result<OutboundCallReceipt> {
        let path = format!("/v3/ai-flows/{}/call", request.ai_flow_id());
        let body = request.to_json();
        let response = exchange::authorized(
            &self.transport,
            &self.auth,
            &self.base_url,
            self.timeout,
            Method::Post,
            &path,
            Some(&body),
        )
        .await?;
        if response.is_success() {
            return Ok(OutboundCallReceipt::from_json(response.json()?));
        }
        Err(crate::retry::api_error(
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundCall {
    ai_flow_id: String,
    billing_device: String,
    to_phone_number: String,
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
    /// assert!(OutboundCall::new("flow-1", "e2", "0151 1234").is_err());
    /// # Ok::<(), sipgate_flow::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`crate::Error::Validation`] for an empty or path-unsafe Flow id, an empty
    /// billing device, or a number that is not E.164 digits.
    pub fn new(
        ai_flow_id: impl Into<String>,
        billing_device: impl Into<String>,
        to_phone_number: impl Into<String>,
    ) -> Result<Self> {
        let ai_flow_id = ai_flow_id.into();
        validate::path_segment("ai_flow_id", &ai_flow_id)?;
        let billing_device = billing_device.into();
        validate::non_empty("billing_device", &billing_device)?;
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct OutboundCallReceipt {
    call_sid: Option<String>,
    raw: Value,
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
        Ok(Self::from_json(serde_json::from_slice(body)?))
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
