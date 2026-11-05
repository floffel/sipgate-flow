//! `OAuth2` client credentials: request shape, caching, expiry with a refresh
//! margin, redaction, and fail-closed construction.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{json_response, response, FakeClock, MockTransport, RecordingSleeper};
use serde_json::Value;
use sipgate_flow::auth::{DEFAULT_TOKEN_URL, MAX_TOKEN_LIFETIME};
use sipgate_flow::transport::{Request, Response};
use sipgate_flow::{
    ClientCredentials, Clock, Error, OAuth2Client, PersonalAccessToken, RestClient, Result,
    StaticToken, Token, TokenSource, Transport,
};

fn credentials() -> ClientCredentials {
    ClientCredentials::new("client-id", "hunter2").expect("non-empty")
}

fn client(transport: MockTransport) -> OAuth2Client<MockTransport> {
    OAuth2Client::new(transport, credentials())
}

#[derive(Clone)]
struct DelayedFirstTransport {
    release: Arc<std::sync::atomic::AtomicBool>,
    started: Arc<std::sync::atomic::AtomicBool>,
    calls: Arc<AtomicUsize>,
}

impl DelayedFirstTransport {
    fn new(
        release: Arc<std::sync::atomic::AtomicBool>,
        started: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            release,
            started,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Transport for DelayedFirstTransport {
    async fn execute(&self, request: Request<'_>) -> Result<Response> {
        assert_eq!(request.url, DEFAULT_TOKEN_URL);
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            self.started.store(true, Ordering::SeqCst);
            while !self.release.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            Ok(json_response(&token_value("stale")))
        } else {
            Ok(json_response(&token_value("fresh")))
        }
    }
}

#[derive(Clone)]
struct SwitchableClock {
    now: Arc<Mutex<Option<Duration>>>,
}

impl SwitchableClock {
    fn new(start: Duration) -> Self {
        Self {
            now: Arc::new(Mutex::new(Some(start))),
        }
    }

    fn fail_pre_epoch(&self) {
        *self
            .now
            .lock()
            .expect("not poisoned while no test panics mid-lock") = None;
    }
}

impl Clock for SwitchableClock {
    fn now(&self) -> Result<Duration> {
        self.now
            .lock()
            .expect("not poisoned while no test panics mid-lock")
            .ok_or_else(|| Error::transport_terminal("system clock is before the Unix epoch"))
    }
}

fn token_value(token: &str) -> Value {
    serde_json::json!({
        "access_token": token,
        "expires_in": 300,
    })
}

async fn wait_until(flag: &std::sync::atomic::AtomicBool) {
    for _ in 0..10_000 {
        if flag.load(Ordering::SeqCst) {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert!(flag.load(Ordering::SeqCst), "timed out waiting for flag");
}

#[tokio::test]
async fn an_empty_credential_pair_fails_closed() {
    assert!(matches!(
        ClientCredentials::new("", "secret"),
        Err(Error::EmptyCredentials)
    ));
    assert!(matches!(
        ClientCredentials::new("id", ""),
        Err(Error::EmptyCredentials)
    ));
    assert!(matches!(StaticToken::new(""), Err(Error::EmptyCredentials)));
}

#[test]
fn the_secret_never_appears_in_debug_output() {
    let credentials = credentials();
    let rendered = format!("{credentials:?}");
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(rendered.contains("client-id"));

    let token = Token::from_json(&serde_json::json!({
        "access_token": "secret-token",
        "refresh_token": "secret-refresh",
    }))
    .expect("valid");
    let rendered = format!("{token:?}");
    assert!(!rendered.contains("secret-token"));
    assert!(!rendered.contains("secret-refresh"));
}

#[test]
fn the_token_request_body_follows_the_documented_form() {
    let body = credentials().token_request_body();
    assert_eq!(
        body,
        [
            ("grant_type".to_string(), "client_credentials".to_string()),
            ("client_id".to_string(), "client-id".to_string()),
            ("client_secret".to_string(), "hunter2".to_string()),
        ]
    );

    let with_scope = credentials()
        .with_scope("sessions:sms:write")
        .with_scope("rtcm:write")
        .token_request_body();
    assert_eq!(
        with_scope
            .last()
            .map(|(key, value)| (key.as_str(), value.as_str())),
        Some(("scope", "sessions:sms:write rtcm:write"))
    );
}

#[test]
fn token_responses_are_parsed_leniently_but_not_silently() {
    let missing = Token::from_json(&serde_json::json!({})).expect_err("no access_token");
    assert!(matches!(missing, Error::TokenResponse(_)));

    let empty = Token::from_json(&serde_json::json!({"access_token": ""})).expect_err("empty");
    assert!(matches!(empty, Error::TokenResponse(_)));

    let wrong_type = Token::from_json(&serde_json::json!({"access_token": 5})).expect_err("number");
    assert!(matches!(wrong_type, Error::TokenResponse(_)));

    let minimal = Token::from_json(&serde_json::json!({"access_token": "a"})).expect("valid");
    assert_eq!(minimal.token_type(), "bearer");
    assert_eq!(minimal.expires_in(), None);

    let full = Token::from_json(&serde_json::json!({
        "access_token": "a",
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "sessions:write",
        "refresh_token": "r",
    }))
    .expect("valid");
    assert_eq!(full.expires_in(), Some(Duration::from_secs(300)));
    assert_eq!(full.scope(), Some("sessions:write"));
    assert_eq!(full.refresh_token(), Some("r"));
}

#[tokio::test]
async fn the_token_request_targets_the_documented_endpoint_as_a_form_post() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({
        "access_token": "abc",
        "expires_in": 300,
    })));
    let auth = client(transport.clone()).with_timeout(Some(Duration::from_secs(3)));

    let token = auth.access_token(false).await.expect("fetched");
    assert_eq!(token.access_token(), "abc");

    let call = transport.only_call();
    assert_eq!(call.method.as_str(), "POST");
    assert_eq!(call.url, DEFAULT_TOKEN_URL);
    assert_eq!(
        call.auth,
        common::Auth::None,
        "the token call must not send a credential"
    );
    assert_eq!(call.timeout, Some(Duration::from_secs(3)));
    let common::Body::Form(fields) = &call.body else {
        panic!("expected a form body, got {:?}", call.body);
    };
    assert_eq!(fields[0].0, "grant_type");
    assert_eq!(fields[0].1, "client_credentials");
    assert!(fields.iter().any(|(key, _)| key == "client_secret"));
}

#[tokio::test]
async fn a_cached_token_is_reused_until_it_nears_expiry() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({
        "access_token": "first",
        "expires_in": 300,
    })));
    transport.push_response(json_response(&serde_json::json!({
        "access_token": "second",
        "expires_in": 300,
    })));
    let clock = FakeClock::new(Duration::from_secs(1_700_000_000));
    let auth = client(transport.clone())
        .with_clock(clock.clone())
        .with_refresh_margin(Duration::from_secs(60))
        .expect("valid margin");

    assert_eq!(
        auth.access_token(false).await.unwrap().access_token(),
        "first"
    );
    // 239 seconds in: still 61 seconds of usable life, so the cache answers.
    clock.advance(Duration::from_secs(239));
    assert_eq!(
        auth.access_token(false).await.unwrap().access_token(),
        "first"
    );
    assert_eq!(transport.call_count(), 1);

    // 241 seconds in: inside the refresh margin, fetch again.
    clock.advance(Duration::from_secs(2));
    assert_eq!(
        auth.access_token(false).await.unwrap().access_token(),
        "second"
    );
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_clock_failure_does_not_serve_a_cached_token() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({
        "access_token": "should-not-be-served",
        "expires_in": 300,
    })));
    let clock = SwitchableClock::new(Duration::from_secs(1_700_000_000));
    let auth = client(transport.clone())
        .with_clock(clock.clone())
        .with_refresh_margin(Duration::from_secs(60))
        .expect("valid margin");

    assert_eq!(
        auth.access_token(false)
            .await
            .expect("normal clock caches")
            .access_token(),
        "should-not-be-served"
    );
    assert!(auth.has_valid_token());

    clock.fail_pre_epoch();
    let error = auth
        .access_token(false)
        .await
        .expect_err("a broken clock must fail closed");
    assert!(matches!(
        error,
        Error::Transport {
            retryable: false,
            ..
        }
    ));
    assert!(!auth.has_valid_token());
    assert_eq!(
        transport.call_count(),
        1,
        "the cache path must fail closed, not fetch a replacement"
    );
}

#[tokio::test]
async fn a_normal_clock_still_caches() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({
        "access_token": "cached",
        "expires_in": 300,
    })));
    let clock = FakeClock::new(Duration::from_secs(1_700_000_000));
    let auth = client(transport.clone()).with_clock(clock.clone());

    assert_eq!(
        auth.access_token(false).await.unwrap().access_token(),
        "cached"
    );
    assert_eq!(
        auth.access_token(false).await.unwrap().access_token(),
        "cached"
    );
    assert_eq!(transport.call_count(), 1, "the second call uses the cache");
    assert!(auth.has_valid_token());
}

#[tokio::test]
async fn a_force_refresh_bypasses_the_cache_and_invalidate_drops_it() {
    let transport = MockTransport::new();
    for token in ["one", "two", "three"] {
        transport.push_response(json_response(&serde_json::json!({
            "access_token": token,
            "expires_in": 300,
        })));
    }
    let auth = client(transport.clone());

    assert_eq!(
        auth.access_token(false).await.unwrap().access_token(),
        "one"
    );
    assert!(auth.has_valid_token());
    assert_eq!(auth.access_token(true).await.unwrap().access_token(), "two");
    assert_eq!(transport.call_count(), 2);

    auth.invalidate();
    assert!(!auth.has_valid_token());
    assert_eq!(
        auth.access_token(false).await.unwrap().access_token(),
        "three"
    );
    assert_eq!(transport.call_count(), 3);
}

#[tokio::test]
async fn invalidate_prevents_an_in_flight_fetch_from_repopulating_the_cache() {
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let auth = Arc::new(OAuth2Client::new(
        DelayedFirstTransport::new(Arc::clone(&release), Arc::clone(&started)),
        credentials(),
    ));

    let first = {
        let auth = Arc::clone(&auth);
        tokio::spawn(async move { auth.access_token(false).await })
    };
    wait_until(&started).await;

    auth.invalidate();
    assert!(!auth.has_valid_token());
    release.store(true, Ordering::SeqCst);
    assert_eq!(
        first.await.expect("task").expect("token").access_token(),
        "stale"
    );

    assert!(
        !auth.has_valid_token(),
        "the stale fetch must not repopulate the cache after invalidate"
    );
    assert_eq!(
        auth.access_token(false)
            .await
            .expect("fresh token")
            .access_token(),
        "fresh"
    );
}

#[tokio::test]
async fn a_slower_force_refresh_cannot_clobber_a_newer_cached_token() {
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let auth = Arc::new(OAuth2Client::new(
        DelayedFirstTransport::new(Arc::clone(&release), Arc::clone(&started)),
        credentials(),
    ));

    let stale = {
        let auth = Arc::clone(&auth);
        tokio::spawn(async move { auth.access_token(true).await })
    };
    wait_until(&started).await;

    assert_eq!(
        auth.access_token(true)
            .await
            .expect("fresh token")
            .access_token(),
        "fresh"
    );
    release.store(true, Ordering::SeqCst);
    assert_eq!(
        stale.await.expect("task").expect("token").access_token(),
        "stale"
    );

    assert_eq!(
        auth.access_token(false)
            .await
            .expect("cached token")
            .access_token(),
        "fresh",
        "the slower refresh must not overwrite the newer cached token"
    );
}

#[tokio::test]
async fn refresh_after_reuses_a_peer_token_that_replaced_the_stale_one() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&token_value("stale")));
    transport.push_response(json_response(&token_value("fresh")));
    let auth = client(transport.clone());

    let stale = auth.access_token(false).await.expect("stale token");
    let fresh = auth.access_token(true).await.expect("fresh token");
    assert_eq!(fresh.access_token(), "fresh");

    let reused = auth.refresh_after(&stale).await.expect("peer token reused");
    assert_eq!(reused.access_token(), "fresh");
    assert_eq!(transport.call_count(), 2, "no third token request");
}

#[tokio::test]
async fn refresh_after_replaces_a_genuinely_stale_token_once() {
    let transport = MockTransport::new();
    for token in ["stale", "fresh"] {
        transport.push_response(json_response(&token_value(token)));
    }
    let auth = client(transport.clone());

    let stale = auth.access_token(false).await.expect("stale token");
    let fresh = auth.refresh_after(&stale).await.expect("replacement token");
    assert_eq!(fresh.access_token(), "fresh");
    assert_eq!(transport.call_count(), 2);

    let reused = auth.access_token(false).await.expect("cached replacement");
    assert_eq!(reused.access_token(), "fresh");
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_rejected_credential_pair_is_a_terminal_error_with_the_status() {
    let transport = MockTransport::new();
    transport.push_response(response(
        401,
        &[("Content-Type", "application/json")],
        br#"{"error":"invalid_client"}"#,
    ));
    let auth = client(transport);

    let error = auth.access_token(false).await.expect_err("rejected");
    assert!(matches!(error, Error::AuthRejected { status: 401, .. }));
    assert_eq!(error.status(), Some(401));
    assert!(!error.is_retryable());
    assert!(!auth.has_valid_token(), "a rejected token is not cached");
}

#[tokio::test]
async fn a_transient_token_endpoint_status_is_retryable() {
    for status in [429_u16, 500, 502, 503, 504] {
        let transport = MockTransport::new();
        transport.push_response(response(
            status,
            &[("Retry-After", "7")],
            br#"{"error":"temporarily_unavailable"}"#,
        ));
        let auth = client(transport);

        let error = auth
            .access_token(false)
            .await
            .expect_err("transient token failure");
        assert!(
            matches!(error, Error::Api { status: s, retryable: true, .. } if s == status),
            "expected a retryable Api error for {status}, got {error:?}"
        );
        assert!(error.is_retryable(), "status {status} must be retryable");
        assert_eq!(error.status(), Some(status));
        assert_eq!(
            error.retry_after(),
            Some(Duration::from_secs(7)),
            "the Retry-After header must be carried for {status}"
        );
        assert!(!auth.has_valid_token(), "a failed fetch caches nothing");
    }
}

#[tokio::test]
async fn a_transient_token_endpoint_status_without_retry_after_is_still_retryable() {
    let transport = MockTransport::new();
    transport.push_response(response(503, &[], b"upstream down"));
    let error = client(transport)
        .access_token(false)
        .await
        .expect_err("transient");
    assert!(error.is_retryable());
    assert_eq!(error.retry_after(), None);
}

#[tokio::test]
async fn a_credential_rejection_is_terminal_for_400_401_and_403() {
    for status in [400_u16, 401, 403] {
        let transport = MockTransport::new();
        transport.push_response(response(
            status,
            &[("Retry-After", "7")],
            br#"{"error":"invalid_client"}"#,
        ));
        let auth = client(transport);

        let error = auth
            .access_token(false)
            .await
            .expect_err("terminal token failure");
        assert!(
            matches!(error, Error::AuthRejected { status: s, .. } if s == status),
            "expected AuthRejected for {status}, got {error:?}"
        );
        assert!(!error.is_retryable(), "status {status} must be terminal");
        assert_eq!(error.status(), Some(status));
        assert_eq!(error.retry_after(), None);
        assert!(!auth.has_valid_token(), "a rejected token is not cached");
    }
}

/// Answers the token endpoint with a scripted status the first time it is
/// called, then serves a token; API calls succeed with `204`.
#[derive(Clone)]
struct FlakyTokenTransport {
    token_status: u16,
    token_headers: Vec<(String, String)>,
    calls: Arc<Mutex<Vec<String>>>,
}

impl FlakyTokenTransport {
    fn new(token_status: u16, token_headers: &[(&str, &str)]) -> Self {
        Self {
            token_status,
            token_headers: token_headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn urls(&self) -> Vec<String> {
        self.calls
            .lock()
            .expect("not poisoned while no test panics mid-lock")
            .clone()
    }
}

impl Transport for FlakyTokenTransport {
    async fn execute(&self, request: Request<'_>) -> Result<Response> {
        std::future::ready(()).await;
        let url = request.url.to_string();
        let token_call = {
            let mut calls = self
                .calls
                .lock()
                .expect("not poisoned while no test panics mid-lock");
            calls.push(url.clone());
            calls.iter().filter(|candidate| **candidate == url).count() == 1
        };
        if url == DEFAULT_TOKEN_URL {
            if token_call {
                return Ok(response(
                    self.token_status,
                    &self
                        .token_headers
                        .iter()
                        .map(|(name, value)| (name.as_str(), value.as_str()))
                        .collect::<Vec<_>>(),
                    br#"{"error":"temporarily_unavailable"}"#,
                ));
            }
            return Ok(json_response(&token_value("abc")));
        }
        Ok(common::no_content())
    }
}

#[tokio::test]
async fn a_transient_token_failure_is_retried_by_the_rest_client() {
    let transport = FlakyTokenTransport::new(503, &[("Retry-After", "2")]);
    let sleeper = RecordingSleeper::new();
    let auth = OAuth2Client::new(transport.clone(), credentials());
    let client = RestClient::new(transport.clone(), auth).with_sleeper(sleeper.clone());

    client.calls().await.expect("retried token then succeeded");

    let token_calls = transport
        .urls()
        .into_iter()
        .filter(|url| url == DEFAULT_TOKEN_URL)
        .count();
    assert_eq!(token_calls, 2, "one failed fetch, one retried fetch");
    assert_eq!(
        sleeper.delays(),
        vec![Duration::from_secs(2)],
        "the Retry-After header paces the retry"
    );
}

#[tokio::test]
async fn a_token_body_that_is_not_json_is_a_json_error() {
    let transport = MockTransport::new();
    transport.push_response(response(200, &[], b"<html>proxy</html>"));
    let error = client(transport)
        .access_token(false)
        .await
        .expect_err("not json");
    assert!(matches!(error, Error::Json { .. }));
}

#[tokio::test]
async fn a_transport_failure_is_reported_and_not_cached() {
    let transport = MockTransport::new();
    transport.push_transient_failure("connect: refused");
    let auth = client(transport);
    let error = auth.access_token(false).await.expect_err("failed");
    assert!(error.is_retryable());
    assert!(!auth.has_valid_token());
}

#[tokio::test]
async fn a_token_without_expires_in_is_cached_for_the_assumed_lifetime() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({"access_token": "t"})));
    transport.push_response(json_response(&serde_json::json!({"access_token": "u"})));
    let clock = FakeClock::new(Duration::ZERO);
    let auth = client(transport.clone()).with_clock(clock.clone());

    assert_eq!(auth.access_token(false).await.unwrap().access_token(), "t");
    // 300 s assumed lifetime minus the 60 s default margin leaves 240 s.
    clock.advance(Duration::from_secs(239));
    assert_eq!(auth.access_token(false).await.unwrap().access_token(), "t");
    clock.advance(Duration::from_secs(2));
    assert_eq!(auth.access_token(false).await.unwrap().access_token(), "u");
}

#[tokio::test]
async fn a_margin_just_below_the_lifetime_still_caches() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({
        "access_token": "first",
        "expires_in": 30,
    })));
    transport.push_response(json_response(&serde_json::json!({
        "access_token": "second",
        "expires_in": 30,
    })));
    let clock = FakeClock::new(Duration::ZERO);
    let auth = client(transport.clone())
        .with_clock(clock.clone())
        .with_refresh_margin(Duration::from_secs(29))
        .expect("valid margin");

    assert_eq!(
        auth.access_token(false).await.unwrap().access_token(),
        "first"
    );
    // The margin is below the lifetime but above half of it, so it is clamped
    // to half: 15 seconds usable instead of zero.
    clock.advance(Duration::from_secs(14));
    assert_eq!(
        auth.access_token(false).await.unwrap().access_token(),
        "first"
    );
    assert_eq!(transport.call_count(), 1);

    clock.advance(Duration::from_secs(1));
    assert_eq!(
        auth.access_token(false).await.unwrap().access_token(),
        "second"
    );
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_margin_at_or_above_the_lifetime_is_clamped_to_leave_cache_time() {
    for margin in [Duration::from_secs(30), Duration::from_secs(60)] {
        let transport = MockTransport::new();
        transport.push_response(json_response(&serde_json::json!({
            "access_token": "short",
            "expires_in": 30,
        })));
        transport.push_response(json_response(&serde_json::json!({
            "access_token": "next",
            "expires_in": 30,
        })));
        let clock = FakeClock::new(Duration::ZERO);
        let auth = client(transport.clone())
            .with_clock(clock.clone())
            .with_refresh_margin(margin)
            .expect("valid margin");

        assert_eq!(
            auth.access_token(false).await.unwrap().access_token(),
            "short"
        );
        assert_eq!(transport.call_count(), 1);

        // The margin is clamped to half of the 30 second lifetime, so the token
        // is cached for 15 seconds instead of being stored as already expired.
        clock.advance(Duration::from_secs(14));
        assert_eq!(
            auth.access_token(false).await.unwrap().access_token(),
            "short",
            "margin {margin:?}"
        );
        assert_eq!(transport.call_count(), 1);

        clock.advance(Duration::from_secs(1));
        assert_eq!(
            auth.access_token(false).await.unwrap().access_token(),
            "next",
            "margin {margin:?}"
        );
        assert_eq!(transport.call_count(), 2);
    }
}

#[tokio::test]
async fn an_expires_in_of_zero_is_refused_and_never_cached() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({
        "access_token": "zero",
        "expires_in": 0,
    })));
    let auth = client(transport.clone());

    let error = auth.access_token(false).await.expect_err("zero lifetime");
    let Error::TokenResponse(reason) = &error else {
        panic!("expected TokenResponse, got {error:?}");
    };
    assert!(reason.contains("expires_in of 0"), "{reason}");
    assert_eq!(transport.call_count(), 1);
    assert!(
        !auth.has_valid_token(),
        "a zero-lifetime token must not enter the cache"
    );
}

#[test]
fn an_absurd_refresh_margin_is_a_typed_validation_error() {
    let transport = MockTransport::new();
    let error = client(transport)
        .with_refresh_margin(MAX_TOKEN_LIFETIME)
        .expect_err("the maximum lifetime is not a valid margin");
    let Error::Validation { field, message } = &error else {
        panic!("expected Validation, got {error:?}");
    };
    assert_eq!(*field, "refresh_margin");
    assert!(message.contains("smaller"), "{message}");
}

#[test]
fn the_client_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OAuth2Client<MockTransport>>();
    assert_send_sync::<StaticToken>();
    assert_send_sync::<ClientCredentials>();
    assert_send_sync::<RecordingSleeper>();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_two_tasks_share_one_token_cache_without_corruption() {
    let transport = MockTransport::always(json_response(&serde_json::json!({
        "access_token": "abc",
        "expires_in": 300,
    })));
    let auth = Arc::new(client(transport.clone()));
    let fetches = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..32 {
        let auth = Arc::clone(&auth);
        let fetches = Arc::clone(&fetches);
        handles.push(tokio::spawn(async move {
            for _ in 0..4 {
                let token = auth.access_token(false).await.expect("token");
                assert_eq!(token.access_token(), "abc");
                fetches.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for handle in handles {
        handle.await.expect("task");
    }

    assert_eq!(fetches.load(Ordering::Relaxed), 32 * 4);
    // Concurrent misses may each fetch (the issuer grants several), but the
    // cache must never hand out a mixture or blow up the request count.
    let calls = transport.call_count();
    assert!((1..=32).contains(&calls), "token requests: {calls}");
}

#[tokio::test]
async fn a_static_token_source_ignores_refresh_requests() {
    let token: Result<Token> = static_auth_token().access_token(true).await;
    assert_eq!(token.expect("token").access_token(), "pat-token");
}

fn static_auth_token() -> StaticToken {
    StaticToken::new("pat-token").expect("non-empty")
}

#[tokio::test]
async fn a_personal_access_token_goes_out_as_the_documented_basic_header() {
    let transport = MockTransport::json(&serde_json::json!({"data": []}));
    let auth = PersonalAccessToken::new("token-FQ1V12", "e68ead46").expect("non-empty");
    let client = RestClient::new(transport.clone(), auth);
    client.calls().await.expect("call");

    let recorded = transport.only_call();
    assert_eq!(
        recorded.auth,
        common::Auth::Basic {
            username: "token-FQ1V12".to_string(),
            password: "e68ead46".to_string(),
        },
        "a PAT is Basic id:token, not a bearer"
    );
}

#[tokio::test]
async fn a_pat_credential_carries_the_scheme_the_transport_needs() {
    let pat = PersonalAccessToken::new("token-FQ1V12", "e68ead46").expect("non-empty");
    let credential = pat.access_token(false).await.expect("credential");
    assert_eq!(credential.token_type(), "basic");
    assert_eq!(credential.security().basic_username(), Some("token-FQ1V12"));

    let bearer = Token::from_json(&serde_json::json!({"access_token": "abc"})).expect("token");
    assert_eq!(bearer.security().basic_username(), None);
    // An unknown scheme degrades to a bearer instead of dropping the credential.
    let odd = Token::from_json(&serde_json::json!({"access_token": "abc", "token_type": "MAC"}))
        .expect("token");
    assert_eq!(odd.security().basic_username(), None);
}

#[tokio::test]
async fn an_empty_or_colon_bearing_token_id_fails_closed() {
    assert!(matches!(
        PersonalAccessToken::new("", "token"),
        Err(Error::EmptyCredentials)
    ));
    assert!(matches!(
        PersonalAccessToken::new("id", ""),
        Err(Error::EmptyCredentials)
    ));
    assert!(matches!(
        PersonalAccessToken::new("token:FQ1V12", "token"),
        Err(Error::Validation {
            field: "token_id",
            ..
        })
    ));
}

#[test]
fn a_pat_never_prints_its_token() {
    let pat = PersonalAccessToken::new("token-FQ1V12", "e68ead46").expect("non-empty");
    let rendered = format!("{pat:?}");
    assert!(!rendered.contains("e68ead46"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert_eq!(pat.token_id(), "token-FQ1V12");
}

#[tokio::test]
async fn a_pat_is_never_refreshed_but_a_second_401_is_terminal() {
    let transport = MockTransport::new();
    transport.push_response(response(401, &[], b"{}"));
    transport.push_response(response(401, &[], b"{}"));
    let auth = PersonalAccessToken::new("token-FQ1V12", "e68ead46").expect("non-empty");
    let client = RestClient::new(transport.clone(), auth);

    assert!(matches!(client.calls().await, Err(Error::Unauthorized)));
    assert_eq!(transport.call_count(), 2, "one retry, then stop");
    assert_eq!(transport.calls()[1].auth, transport.calls()[0].auth);
}

#[test]
fn an_expires_in_above_the_ceiling_is_a_typed_error() {
    let at_ceiling = Token::from_json(&serde_json::json!({
        "access_token": "a",
        "expires_in": MAX_TOKEN_LIFETIME.as_secs(),
    }))
    .expect("the ceiling itself is usable");
    assert_eq!(at_ceiling.expires_in(), Some(MAX_TOKEN_LIFETIME));

    for seconds in [
        MAX_TOKEN_LIFETIME.as_secs() + 1,
        u64::MAX / 2,
        u64::MAX - 1,
        u64::MAX,
    ] {
        let refused = Token::from_json(&serde_json::json!({
            "access_token": "a",
            "expires_in": seconds,
        }))
        .expect_err("a lifetime the clock cannot add is refused");
        let Error::TokenResponse(reason) = &refused else {
            panic!("expected TokenResponse for {seconds}, got {refused:?}");
        };
        assert!(
            reason.contains("expires_in") && reason.contains(&seconds.to_string()),
            "{reason}"
        );
    }
}

#[test]
fn a_non_integer_expires_in_is_treated_as_absent() {
    for odd in [
        serde_json::json!(-1),
        serde_json::json!(300.5),
        serde_json::json!("300"),
    ] {
        let token = Token::from_json(&serde_json::json!({
            "access_token": "a",
            "expires_in": odd,
        }))
        .expect("tolerated");
        assert_eq!(token.expires_in(), None, "{odd}");
    }
}

#[tokio::test]
async fn a_clock_add_that_would_overflow_is_a_typed_error_and_never_caches() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({
        "access_token": "t",
        "expires_in": 300,
    })));
    let start = Duration::MAX
        .checked_sub(Duration::from_secs(1))
        .expect("representable");
    let clock = FakeClock::new(start);
    let auth = client(transport.clone()).with_clock(clock);

    let failed = auth
        .access_token(false)
        .await
        .expect_err("overflow is an error");
    let Error::TokenResponse(reason) = &failed else {
        panic!("expected TokenResponse, got {failed:?}");
    };
    assert!(reason.contains("overflow"), "{reason}");
    assert_eq!(transport.call_count(), 1);
    assert!(
        !auth.has_valid_token(),
        "a token whose expiry cannot be computed is not cached"
    );
}
