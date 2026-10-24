//! Outbound Flow calls: the one documented imperative Flow endpoint.

mod common;

use std::time::Duration;

use common::{json_response, no_content, response, static_auth, Body, MockTransport};
use sipgate_flow::{Error, FlowClient, OutboundCall, Result, StaticToken, Token, TokenSource};

const FLOW_ID: &str = "e3670012-96a3-4ae5-ac42-87abe22015c3";

fn client(transport: MockTransport) -> FlowClient<MockTransport, StaticToken> {
    FlowClient::new(transport, static_auth())
}

#[tokio::test]
async fn a_call_posts_billing_device_and_number_to_the_documented_path() {
    let transport = MockTransport::new();
    transport.push_response(response(201, &[], b""));
    let client = client(transport.clone());

    let call = OutboundCall::new(FLOW_ID, "e2", "+4915112345678").expect("valid");
    let body = client.call(&call).await.expect("started");
    assert_eq!(body, serde_json::json!({}));

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "POST");
    assert_eq!(
        recorded.url,
        format!("https://api.sipgate.com/v3/ai-flows/{FLOW_ID}/call")
    );
    assert_eq!(recorded.token.as_deref(), Some("pat-token"));
    assert_eq!(
        recorded.body,
        Body::Json(serde_json::json!({
            "billingDevice": "e2",
            "toPhoneNumber": "4915112345678",
        }))
    );
}

#[tokio::test]
async fn a_404_means_the_flow_does_not_exist() {
    let transport = MockTransport::new();
    transport.push_response(response(404, &[], b"{\"error\":\"flow not found\"}"));
    let client = client(transport);

    let error = client
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect_err("404");
    match error {
        Error::Api { status, body, .. } => {
            assert_eq!(status, 404);
            assert!(body.contains("flow not found"));
        }
        other => panic!("expected an API error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_400_means_the_flow_has_no_phone_number() {
    let transport = MockTransport::new();
    transport.push_response(response(400, &[], b""));
    let error = client(transport)
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect_err("400");
    assert_eq!(error.status(), Some(400));
}

#[tokio::test]
async fn starting_a_call_is_never_retried() {
    // Dialling twice would ring the recipient twice, so a 500 surfaces at once.
    let transport = MockTransport::new();
    transport.push_response(response(500, &[], b"boom"));
    let error = client(transport.clone())
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect_err("500");
    assert!(matches!(error, Error::Api { status: 500, .. }));
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn the_token_is_refreshed_once_on_401() {
    let transport = MockTransport::new();
    transport.push_response(response(401, &[], b"expired"));
    transport.push_response(response(201, &[], b""));
    let client = FlowClient::new(transport.clone(), Rotating);

    client
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect("retried with a fresh token");

    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].token.as_deref(), Some("t1"));
    assert_eq!(calls[1].token.as_deref(), Some("t2"));
}

#[tokio::test]
async fn base_url_and_timeout_are_configurable() {
    let transport = MockTransport::new();
    transport.push_response(no_content());
    let client = client(transport.clone())
        .with_base_url("http://localhost:8080/")
        .with_timeout(Some(Duration::from_secs(2)));
    assert_eq!(client.base_url(), "http://localhost:8080");
    assert_eq!(client.timeout(), Some(Duration::from_secs(2)));

    client
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect("ok");
    let recorded = transport.only_call();
    assert_eq!(
        recorded.url,
        format!("http://localhost:8080/v3/ai-flows/{FLOW_ID}/call")
    );
    assert_eq!(recorded.timeout, Some(Duration::from_secs(2)));
}

#[test]
fn the_request_validates_its_three_fields() {
    assert!(OutboundCall::new(FLOW_ID, "e2", "+4915112345678").is_ok());
    assert!(OutboundCall::new("", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new("a/b", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "e2", "0151 1234").is_err());
    assert!(OutboundCall::new(FLOW_ID, "e2", "1".repeat(16)).is_err());
    assert!(OutboundCall::new(FLOW_ID, "e2", "1".repeat(15)).is_ok());
}

#[test]
fn accessors_expose_the_normalised_values() {
    let call = OutboundCall::new(FLOW_ID, "e2", "+4915112345678").expect("valid");
    assert_eq!(call.ai_flow_id(), FLOW_ID);
    assert_eq!(call.billing_device(), "e2");
    assert_eq!(call.to_phone_number(), "4915112345678");
    assert_eq!(call.to_json()["toPhoneNumber"], "4915112345678");
}

#[test]
fn debug_never_prints_a_token() {
    let transport = MockTransport::new();
    let client = FlowClient::new(transport, StaticToken::new("secret-token").expect("valid"));
    let rendered = format!("{client:?}");
    assert!(!rendered.contains("secret-token"));
    assert!(rendered.contains("FlowClient"));
}

#[test]
fn the_client_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FlowClient<MockTransport, StaticToken>>();
    let _ = json_response(&serde_json::json!({})); // keeps the import honest
}

/// Hands out `t1`, `t2`, … so a refresh is observable.
struct Rotating;

impl TokenSource for Rotating {
    fn access_token(
        &self,
        force_refresh: bool,
    ) -> impl std::future::Future<Output = Result<Token>> + Send {
        let name = if force_refresh { "t2" } else { "t1" };
        std::future::ready(Token::from_json(
            &serde_json::json!({ "access_token": name }),
        ))
    }

    fn invalidate(&self) {}
}
