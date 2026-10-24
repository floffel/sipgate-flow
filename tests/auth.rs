//! `OAuth2` client credentials: request shape, caching, expiry with a refresh
//! margin, redaction, and fail-closed construction.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::{json_response, response, FakeClock, MockTransport, RecordingSleeper};
use sipgate_flow::auth::DEFAULT_TOKEN_URL;
use sipgate_flow::{
    ClientCredentials, Error, OAuth2Client, Result, StaticToken, Token, TokenSource,
};

fn credentials() -> ClientCredentials {
    ClientCredentials::new("client-id", "hunter2").expect("non-empty")
}

fn client(transport: MockTransport) -> OAuth2Client<MockTransport> {
    OAuth2Client::new(transport, credentials())
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
    assert_eq!(call.token, None, "the token call must not send a bearer");
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
        .with_refresh_margin(Duration::from_secs(60));

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
async fn a_margin_longer_than_the_lifetime_still_yields_a_usable_token() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({
        "access_token": "short",
        "expires_in": 30,
    })));
    let clock = FakeClock::new(Duration::ZERO);
    let auth = client(transport.clone())
        .with_clock(clock)
        .with_refresh_margin(Duration::from_secs(60));

    assert_eq!(
        auth.access_token(false).await.unwrap().access_token(),
        "short"
    );
    assert_eq!(transport.call_count(), 1);
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
