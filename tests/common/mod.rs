//! Shared test doubles: a recording transport, a recording sleeper and a
//! controllable clock. No test in this crate opens a socket.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use sipgate_flow::transport::{Method, Request, RequestBody, Response};
use sipgate_flow::{Clock, Error, Result, Sleeper, StaticToken, Transport};

/// Body as the transport saw it.
#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    /// No body.
    Empty,
    /// `application/json` payload.
    Json(Value),
    /// `application/x-www-form-urlencoded` fields, in order.
    Form(Vec<(String, String)>),
}

/// One recorded call.
#[derive(Clone, Debug, PartialEq)]
pub struct Call {
    /// Verb.
    pub method: Method,
    /// Full URL.
    pub url: String,
    /// Bearer token, or `None` when the request was unauthenticated.
    pub token: Option<String>,
    /// Per-request timeout.
    pub timeout: Option<Duration>,
    /// Request body.
    pub body: Body,
}

/// A scripted reply.
#[derive(Clone)]
pub enum Reply {
    /// Return this response.
    Response(Response),
    /// Fail in the transport layer.
    Failure {
        /// Error message.
        message: String,
        /// Whether a retry could help.
        retryable: bool,
    },
}

/// Records calls and replays scripted replies (default: `200 {}`).
#[derive(Clone, Default)]
pub struct MockTransport {
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    calls: Vec<Call>,
    queue: VecDeque<Reply>,
    fallback: Option<Reply>,
}

impl MockTransport {
    /// A transport that answers `200 {}` forever.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A transport that answers with a fixed JSON body.
    #[must_use]
    pub fn json(value: &Value) -> Self {
        let transport = Self::new();
        transport.push_response(json_response(value));
        transport
    }

    /// Answers every request with the same response, after the queue is empty.
    #[must_use]
    pub fn always(response: Response) -> Self {
        let transport = Self::new();
        transport.lock().fallback = Some(Reply::Response(response));
        transport
    }

    /// Queues a reply.
    pub fn push(&self, reply: Reply) {
        self.lock().queue.push_back(reply);
    }

    /// Queues a response.
    pub fn push_response(&self, response: Response) {
        self.push(Reply::Response(response));
    }

    /// Queues a transient transport failure.
    pub fn push_transient_failure(&self, message: &str) {
        self.push(Reply::Failure {
            message: message.to_string(),
            retryable: true,
        });
    }

    /// Queues a terminal transport failure.
    pub fn push_terminal_failure(&self, message: &str) {
        self.push(Reply::Failure {
            message: message.to_string(),
            retryable: false,
        });
    }

    /// Every recorded call, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.lock().calls.clone()
    }

    /// Number of recorded calls.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.lock().calls.len()
    }

    /// The single recorded call; panics when the count is not exactly one.
    #[must_use]
    pub fn only_call(&self) -> Call {
        let calls = self.calls();
        assert_eq!(calls.len(), 1, "expected exactly one call, got {calls:#?}");
        calls.into_iter().next().expect("length checked above")
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Transport for MockTransport {
    async fn execute(&self, request: Request<'_>) -> Result<Response> {
        // Yield once: keep this a real coroutine so the future has to be Send.
        std::future::ready(()).await;
        let body = match request.body {
            RequestBody::Json(value) => Body::Json(value.clone()),
            RequestBody::Form(fields) => Body::Form(fields.to_vec()),
            _ => Body::Empty,
        };
        let token = match request.security {
            sipgate_flow::Security::Bearer(token) => Some(token.to_string()),
            _ => None,
        };

        let reply = {
            let mut state = self.lock();
            state.calls.push(Call {
                method: request.method,
                url: request.url.to_string(),
                token,
                timeout: request.timeout,
                body,
            });
            state.queue.pop_front().or_else(|| state.fallback.clone())
        };

        match reply {
            Some(Reply::Response(response)) => Ok(response),
            Some(Reply::Failure { message, retryable }) => Err(if retryable {
                Error::transport(message)
            } else {
                Error::transport_terminal(message)
            }),
            None => Ok(json_response(&serde_json::json!({}))),
        }
    }
}

/// Builds a JSON response.
#[must_use]
pub fn json_response(value: &Value) -> Response {
    Response::new(
        200,
        [("Content-Type".to_string(), "application/json".to_string())],
        serde_json::to_vec(value).unwrap_or_default(),
    )
}

/// Builds a response from parts.
#[must_use]
pub fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Response {
    Response::new(
        status,
        headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string())),
        body.to_vec(),
    )
}

/// A `204 No Content` response.
#[must_use]
pub fn no_content() -> Response {
    response(204, &[], b"")
}

/// A token response with a 300 second lifetime.
#[must_use]
pub fn token_response(token: &str) -> Response {
    json_response(&serde_json::json!({
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 300,
    }))
}

/// A static token source for REST tests.
#[must_use]
pub fn static_auth() -> StaticToken {
    StaticToken::new("pat-token").expect("non-empty")
}

/// Records every delay it was asked to wait, without waiting.
#[derive(Clone, Default)]
pub struct RecordingSleeper {
    delays: Arc<Mutex<Vec<Duration>>>,
}

impl RecordingSleeper {
    /// A sleeper with an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every delay requested so far.
    #[must_use]
    pub fn delays(&self) -> Vec<Duration> {
        self.delays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Total time the client would have waited.
    #[must_use]
    pub fn total(&self) -> Duration {
        self.delays().iter().copied().sum()
    }
}

impl Sleeper for RecordingSleeper {
    fn sleep(&self, delay: Duration) -> impl std::future::Future<Output = ()> + Send {
        self.delays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(delay);
        std::future::ready(())
    }
}

/// A clock the test moves by hand.
#[derive(Clone)]
pub struct FakeClock {
    now: Arc<Mutex<Duration>>,
}

impl FakeClock {
    /// Starts at `start`.
    #[must_use]
    pub fn new(start: Duration) -> Self {
        Self {
            now: Arc::new(Mutex::new(start)),
        }
    }

    /// Moves the clock forward.
    pub fn advance(&self, by: Duration) {
        let mut now = self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *now += by;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Duration {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
