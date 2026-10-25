//! The `reqwest` adapter, exercised against a local socket.
//!
//! Everything above [`Transport`] is tested with a mock, so this file exists for
//! the one piece that cannot be faked: the code that turns a [`Request`] into an
//! HTTP/1.1 message and a response back into a [`Response`]. The peer is a
//! hand-written `TcpListener` on `127.0.0.1`, so no test reaches the network.

#![cfg(feature = "http")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use sipgate_flow::transport::{Method, Request, RequestBody, Response, Security, Transport};
use sipgate_flow::{Error, ReqwestTransport};

/// A one-shot HTTP server: it answers with `response` and records the request.
struct TestServer {
    base: String,
    received: Arc<Mutex<Vec<u8>>>,
    handle: Option<JoinHandle<()>>,
}

impl TestServer {
    /// Starts a server that answers the first connection with `response`, after
    /// waiting `delay`.
    fn start(response: &'static str, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let addr: SocketAddr = listener.local_addr().expect("local addr");
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let handle = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            stream
                .set_read_timeout(Some(Duration::from_millis(300)))
                .expect("read timeout");
            let mut buffer = [0_u8; 4096];
            let mut seen_headers = false;
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                {
                    let mut collected = sink.lock().expect("lock");
                    collected.extend_from_slice(&buffer[..read]);
                    seen_headers |= collected.windows(4).any(|w| w == b"\r\n\r\n");
                }
                if seen_headers {
                    break;
                }
            }
            std::thread::sleep(delay);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });
        Self {
            base: format!("http://{addr}"),
            received,
            handle: Some(handle),
        }
    }

    /// The URL to call.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// The bytes the peer saw, after the connection closed.
    fn received(&mut self) -> String {
        if let Some(handle) = self.handle.take() {
            handle.join().expect("server thread");
        }
        let bytes = self.received.lock().expect("lock").clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// A `200` answer with a JSON body and a header worth asserting on.
const OK_JSON: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Trace: abc\r\nContent-Length: 28\r\n\r\n{\"sessionId\":\"s0\",\"ok\":true}";

#[tokio::test]
async fn a_post_carries_the_json_body_and_the_bearer() {
    let mut server = TestServer::start(OK_JSON, Duration::ZERO);
    let url = server.url("/v2/sessions/sms");
    let payload = serde_json::json!({"smsId": "s0"});
    let request = Request::json(
        Method::Post,
        &url,
        Security::Bearer("credential-value"),
        &payload,
    );

    let response = ReqwestTransport::new()
        .execute(request)
        .await
        .expect("request");
    assert_eq!(response.status(), 200);
    assert_eq!(response.header("x-trace"), Some("abc"));
    assert_eq!(response.json().expect("json")["sessionId"], "s0");

    let seen = server.received();
    assert!(seen.starts_with("POST /v2/sessions/sms HTTP/1.1"), "{seen}");
    assert!(
        seen.to_ascii_lowercase()
            .contains("authorization: bearer credential-value"),
        "{seen}"
    );
    assert!(
        seen.to_ascii_lowercase()
            .contains("content-type: application/json"),
        "{seen}"
    );
    assert!(seen.contains(r#""smsId":"s0""#), "{seen}");
}

#[tokio::test]
async fn a_basic_credential_is_base64_encoded() {
    let mut server = TestServer::start(OK_JSON, Duration::ZERO);
    let url = server.url("/v2/calls/c1/hold");
    let payload = serde_json::json!({"value": true});
    let request = Request::json(
        Method::Put,
        &url,
        Security::Basic {
            username: "token-FQ1V12",
            password: "e68ead46",
        },
        &payload,
    );

    ReqwestTransport::new()
        .execute(request)
        .await
        .expect("request");

    let seen = server.received();
    assert!(seen.starts_with("PUT /v2/calls/c1/hold HTTP/1.1"), "{seen}");
    // base64("token-FQ1V12:e68ead46"); only the header *name* is case-insensitive,
    // the credential is not, so the comparison goes through the colon.
    let credential = seen
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        .and_then(|line| line.split_once(':'))
        .map(|(_, value)| value.trim());
    assert_eq!(
        credential,
        Some("Basic dG9rZW4tRlExVjEyOmU2OGVhZDQ2"),
        "{seen}"
    );
}

#[tokio::test]
async fn a_form_body_is_url_encoded_and_none_means_no_header() {
    let mut server = TestServer::start(OK_JSON, Duration::ZERO);
    let url = server.url("/v2/calls/c1");
    let fields = vec![
        ("grant_type".to_string(), "client_credentials".to_string()),
        ("client_id".to_string(), "id with space".to_string()),
    ];
    let request = Request::form(Method::Delete, &url, Security::None, &fields);
    ReqwestTransport::new()
        .execute(request)
        .await
        .expect("request");

    let seen = server.received();
    assert!(seen.starts_with("DELETE /v2/calls/c1 HTTP/1.1"), "{seen}");
    assert!(
        seen.to_ascii_lowercase()
            .contains("content-type: application/x-www-form-urlencoded"),
        "{seen}"
    );
    assert!(seen.contains("grant_type=client_credentials"), "{seen}");
    assert!(seen.contains("client_id=id+with+space"), "{seen}");
    assert!(
        !seen.to_ascii_lowercase().contains("authorization:"),
        "an unauthenticated request sends no header: {seen}"
    );
}

#[tokio::test]
async fn an_empty_body_request_sends_no_payload() {
    let mut server = TestServer::start(OK_JSON, Duration::ZERO);
    let url = server.url("/v2/calls");
    let request = Request::empty(Method::Get, &url, Security::Bearer("t"));
    assert!(matches!(request.body, RequestBody::Empty));

    ReqwestTransport::new()
        .execute(request)
        .await
        .expect("request");

    let seen = server.received();
    assert!(seen.starts_with("GET /v2/calls HTTP/1.1"), "{seen}");
    let body = seen.split_once("\r\n\r\n").map(|(_, body)| body);
    assert_eq!(body, Some(""), "a GET has no body: {seen}");
}

#[tokio::test]
async fn a_refused_connection_is_a_retryable_transport_error() {
    // Bind, read the port, drop the listener: the port is now closed.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);

    let url = format!("http://{addr}/v2/calls");
    let request = Request::empty(Method::Get, &url, Security::Bearer("t"));
    let error = ReqwestTransport::new()
        .execute(request)
        .await
        .expect_err("nothing listens there");
    assert!(error.is_retryable(), "{error:?}");
    match error {
        Error::Transport { message, .. } => assert!(message.starts_with("connect: "), "{message}"),
        other => panic!("expected a transport error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_slow_peer_becomes_a_timeout_error() {
    let server = TestServer::start(OK_JSON, Duration::from_millis(750));
    let url = server.url("/v2/calls");
    let request = Request::empty(Method::Get, &url, Security::Bearer("t"))
        .with_timeout(Some(Duration::from_millis(75)));

    let error = ReqwestTransport::new()
        .execute(request)
        .await
        .expect_err("the peer answers too late");
    assert!(error.is_retryable(), "{error:?}");
    match error {
        Error::Transport { message, .. } => assert!(message.starts_with("timeout: "), "{message}"),
        other => panic!("expected a transport error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_post_timeout_is_ambiguous_because_the_request_was_already_written() {
    let server = TestServer::start(OK_JSON, Duration::from_millis(750));
    let url = server.url("/v2/sessions/sms");
    let body = serde_json::json!({"recipient": "+4915112345678"});
    let request = Request::json(Method::Post, &url, Security::Bearer("t"), &body)
        .with_timeout(Some(Duration::from_millis(75)));

    let error = ReqwestTransport::new()
        .execute(request)
        .await
        .expect_err("the peer answers too late");
    assert!(error.is_ambiguous(), "{error:?}");
    assert!(
        !error.is_retryable(),
        "the SMS may have been sent: {error:?}"
    );
    assert_eq!(error.status(), None, "no status arrived");
    let rendered = error.to_string();
    assert!(rendered.contains("timeout: "), "{rendered}");
    assert!(
        !rendered.to_ascii_lowercase().contains("authorization"),
        "a transport error never echoes the credential: {rendered}"
    );
}

#[tokio::test]
async fn a_post_that_cannot_connect_stays_retryable() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);

    let url = format!("http://{addr}/v2/sessions/sms");
    let body = serde_json::json!({"recipient": "+4915112345678"});
    let request = Request::json(Method::Post, &url, Security::Bearer("t"), &body);
    let error = ReqwestTransport::new()
        .execute(request)
        .await
        .expect_err("nothing listens there");
    assert!(error.is_retryable(), "nothing was written: {error:?}");
    assert!(!error.is_ambiguous(), "{error:?}");
    match error {
        Error::Transport { message, .. } => assert!(message.starts_with("connect: "), "{message}"),
        other => panic!("expected a transport error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_non_success_status_is_returned_rather_than_raised() {
    let mut server = TestServer::start(
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3\r\nContent-Length: 5\r\n\r\nbusy!",
        Duration::ZERO,
    );
    let url = server.url("/v2/calls");
    let request = Request::empty(Method::Get, &url, Security::Bearer("t"));
    let response: Response = ReqwestTransport::new()
        .execute(request)
        .await
        .expect("a 429 is a response, not an error");
    assert_eq!(response.status(), 429);
    assert_eq!(response.header("retry-after"), Some("3"));
    assert_eq!(response.text(), "busy!");
    assert!(!response.is_success());
    let _ = server.received();
}

#[tokio::test]
async fn a_truncated_body_is_reported_as_a_body_error() {
    // The peer promises 100 bytes and closes after two.
    let server = TestServer::start(
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}",
        Duration::ZERO,
    );
    let url = server.url("/v2/calls");
    let request = Request::empty(Method::Get, &url, Security::Bearer("t"));
    let error = ReqwestTransport::new()
        .execute(request)
        .await
        .expect_err("the body is shorter than announced");
    assert!(error.is_retryable(), "{error:?}");
    match error {
        Error::Transport { message, .. } => assert!(message.starts_with("body: "), "{message}"),
        other => panic!("expected a transport error, got {other:?}"),
    }
}

#[tokio::test]
async fn the_transport_is_shareable_across_tasks() {
    let transport = Arc::new(ReqwestTransport::new());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let transport = Arc::clone(&transport);
        // A closed port, so every task fails fast without a server thread.
        handles.push(tokio::spawn(async move {
            let request = Request::empty(
                Method::Get,
                "http://127.0.0.1:1/v2/calls",
                Security::Bearer("t"),
            );
            transport.execute(request).await.is_err()
        }));
    }
    for handle in handles {
        assert!(handle.await.expect("task"));
    }
}
