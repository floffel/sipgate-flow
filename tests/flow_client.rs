//! Outbound Flow calls: the one documented imperative Flow endpoint.

mod common;

use std::time::Duration;

use common::{json_response, no_content, response, static_auth, Body, MockTransport};
use sipgate_flow::{
    Error, FlowClient, OutboundCall, OutboundCallReceipt, Result, StaticToken, Token, TokenSource,
};

const FLOW_ID: &str = "e3670012-96a3-4ae5-ac42-87abe22015c3";

fn client(transport: MockTransport) -> FlowClient<MockTransport, StaticToken> {
    FlowClient::new(transport, static_auth())
}

#[tokio::test]
async fn a_call_posts_billing_device_and_number_to_the_documented_path() {
    let transport = MockTransport::new();
    transport.push_response(response(
        201,
        &[("Content-Type", "application/json")],
        br#"{"callSid":"pbx-c-ffffffff-abba"}"#,
    ));
    let client = client(transport.clone());

    let call = OutboundCall::new(FLOW_ID, "e2", "+4915112345678").expect("valid");
    let receipt = client.call(&call).await.expect("started");
    assert_eq!(receipt.call_sid(), Some("pbx-c-ffffffff-abba"));
    assert_eq!(receipt.raw()["callSid"], "pbx-c-ffffffff-abba");

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "POST");
    assert_eq!(
        recorded.url,
        format!("https://api.sipgate.com/v3/ai-flows/{FLOW_ID}/call")
    );
    assert_eq!(recorded.auth.bearer(), Some("access-token"));
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
    assert!(matches!(
        error,
        Error::FlowNotFound { status: 404, ref body, .. } if body.contains("flow not found")
    ));
    assert_eq!(error.status(), Some(404));
    assert!(!error.is_retryable());
    assert!(!error.is_ambiguous());
    let source = std::error::Error::source(&error).expect("API context stays on the chain");
    let rendered = source.to_string();
    assert!(rendered.contains("404"), "{rendered}");
    assert!(rendered.contains("flow not found"), "{rendered}");
}

#[tokio::test]
async fn a_201_with_a_valid_body_is_the_only_placed_call_success() {
    let transport = MockTransport::new();
    transport.push_response(response(
        201,
        &[("Content-Type", "application/json")],
        br#"{"callSid":"pbx-c-created"}"#,
    ));

    let receipt = client(transport)
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect("201 with a documented body is a placed call");

    assert_eq!(receipt.call_sid(), Some("pbx-c-created"));
}

#[tokio::test]
async fn a_201_with_an_unparseable_body_is_not_a_plain_json_error() {
    let transport = MockTransport::new();
    transport.push_response(response(201, &[], b"not json"));

    let error = client(transport)
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect_err("the call may have started, but the body is unusable");

    assert!(matches!(
        error,
        Error::CallStartedUnknown { status: 201, ref body } if body == "not json"
    ));
    assert!(error.is_ambiguous(), "{error:?}");
    assert_eq!(error.status(), Some(201));
    assert!(!error.is_retryable());
}

#[tokio::test]
async fn a_non_201_success_is_a_dedicated_ambiguous_call_started_error() {
    for response in [response(202, &[], b"accepted"), response(204, &[], b"")] {
        let transport = MockTransport::new();
        let status = response.status();
        transport.push_response(response);

        let error = client(transport)
            .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
            .await
            .expect_err("only 201 is a placed-call success");

        assert!(matches!(
            error,
            Error::CallStartedUnknown { status: actual, .. } if actual == status
        ));
        assert!(error.is_ambiguous(), "{error:?}");
        assert_eq!(error.status(), Some(status));
        assert!(!error.is_retryable());
    }
}

#[tokio::test]
async fn a_400_means_the_flow_has_no_phone_number() {
    let transport = MockTransport::new();
    transport.push_response(response(400, &[], b"{\"error\":\"no phone number\"}"));
    let error = client(transport)
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect_err("400");
    assert!(matches!(
        error,
        Error::FlowNotCallable { status: 400, ref body, .. } if body.contains("no phone number")
    ));
    assert_eq!(error.status(), Some(400));
    assert!(!error.is_retryable());
    assert!(!error.is_ambiguous());
    let source = std::error::Error::source(&error).expect("API context stays on the chain");
    let rendered = source.to_string();
    assert!(rendered.contains("400"), "{rendered}");
    assert!(rendered.contains("no phone number"), "{rendered}");
}

#[tokio::test]
async fn a_403_means_call_access_was_not_granted() {
    let transport = MockTransport::new();
    transport.push_response(response(403, &[], b"{\"error\":\"access denied\"}"));
    let error = client(transport)
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect_err("403");
    assert!(matches!(
        error,
        Error::AccessNotGranted { status: 403, ref body, .. } if body.contains("access denied")
    ));
    assert_eq!(error.status(), Some(403));
    assert!(!error.is_retryable());
    assert!(!error.is_ambiguous());
    let source = std::error::Error::source(&error).expect("API context stays on the chain");
    let rendered = source.to_string();
    assert!(rendered.contains("403"), "{rendered}");
    assert!(rendered.contains("access denied"), "{rendered}");
}

#[tokio::test]
async fn non_documented_call_failures_keep_the_existing_api_shape() {
    let transport = MockTransport::new();
    transport.push_response(response(402, &[], b"payment required"));
    let error = client(transport)
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect_err("402 remains a generic API failure");
    assert!(matches!(
        error,
        Error::Api { status: 402, ref body, retryable: false, ambiguous: false, .. }
            if body == "payment required"
    ));
    assert_eq!(error.status(), Some(402));
}

#[tokio::test]
async fn starting_a_call_is_never_retried() {
    // Dialling twice would ring the recipient twice, so a 500 surfaces at once
    // - and it surfaces as ambiguous: the Flow may already have dialled.
    let transport = MockTransport::new();
    transport.push_response(response(500, &[], b"boom"));
    let error = client(transport.clone())
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect_err("500");
    assert!(error.is_ambiguous(), "{error:?}");
    assert_eq!(error.status(), Some(500));
    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_rate_limited_call_keeps_its_wait_hint_for_the_caller() {
    // The Flow client never loops, but a 429 did not dial: it stays retryable
    // and carries `Retry-After`, so the caller's own ledger can repeat it.
    let transport = MockTransport::new();
    transport.push_response(response(429, &[("Retry-After", "2")], b"slow down"));
    let error = client(transport.clone())
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect_err("429");
    assert!(error.is_retryable());
    assert!(!error.is_ambiguous());
    assert_eq!(error.retry_after(), Some(std::time::Duration::from_secs(2)));
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn the_token_is_refreshed_once_on_401() {
    let transport = MockTransport::new();
    transport.push_response(response(401, &[], b"expired"));
    transport.push_response(response(201, &[], br#"{"callSid":"pbx-c-retry"}"#));
    let client = FlowClient::new(transport.clone(), Rotating);

    client
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect("retried with a fresh token");

    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].auth.bearer(), Some("t1"));
    assert_eq!(calls[1].auth.bearer(), Some("t2"));
}

#[tokio::test]
async fn base_url_and_timeout_are_configurable() {
    let transport = MockTransport::new();
    transport.push_response(no_content());
    let client = client(transport.clone())
        .with_base_url_for_local_testing("http://localhost:8080/")
        .expect("local test server")
        .with_timeout(Some(Duration::from_secs(2)));
    assert_eq!(client.base_url(), "http://localhost:8080");
    assert_eq!(client.timeout(), Some(Duration::from_secs(2)));

    let error = client
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect_err("204 means the request was accepted but did not return an identifier");
    assert!(matches!(
        error,
        Error::CallStartedUnknown { status: 204, .. }
    ));
    let recorded = transport.only_call();
    assert_eq!(
        recorded.url,
        format!("http://localhost:8080/v3/ai-flows/{FLOW_ID}/call")
    );
    // The per-request timeout is a budget: the attempt gets what is left of it.
    let timeout = recorded.timeout.expect("timeout applied");
    assert!(
        timeout <= Duration::from_secs(2),
        "attempt exceeded the configured timeout: {timeout:?}"
    );
    assert!(
        timeout > Duration::from_millis(1900),
        "attempt was handed a drastically short budget: {timeout:?}"
    );
}

#[test]
fn base_url_override_validates_and_requires_https_by_default() {
    assert_eq!(
        client(MockTransport::new())
            .try_with_base_url("https://proxy.test/")
            .expect("valid https URL")
            .base_url(),
        "https://proxy.test"
    );
    assert_eq!(
        client(MockTransport::new())
            .with_base_url("https://proxy.test/")
            .expect("valid https URL")
            .base_url(),
        "https://proxy.test"
    );
    assert_eq!(
        client(MockTransport::new())
            .with_base_url_for_local_testing("http://localhost:8080/")
            .expect("explicit local-testing opt-in accepts http")
            .base_url(),
        "http://localhost:8080"
    );

    for url in [
        "",
        "api.sipgate.com",
        "/v3/ai-flows",
        "https://",
        "file:///tmp/token",
        "http://api.sipgate.com",
        "HTTP://api.sipgate.com",
        "https://user:secret@proxy.test",
        "https://proxy.test/path with space",
    ] {
        assert!(
            client(MockTransport::new()).try_with_base_url(url).is_err(),
            "{url:?} must be rejected"
        );
        assert!(
            client(MockTransport::new()).with_base_url(url).is_err(),
            "{url:?} must be rejected"
        );
    }

    assert!(client(MockTransport::new())
        .with_base_url_for_local_testing("api.sipgate.com")
        .is_err());
    assert!(client(MockTransport::new())
        .with_base_url_for_local_testing("file:///tmp/token")
        .is_err());
    assert!(client(MockTransport::new())
        .with_base_url_for_local_testing("")
        .is_err());
}

#[test]
fn the_request_validates_its_three_fields() {
    assert!(OutboundCall::new(FLOW_ID, "e2", "+4915112345678").is_ok());
    assert!(OutboundCall::new("AZaz09_-", "e2", "4915112345678").is_ok());
    assert!(OutboundCall::new("", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new(".", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new("..", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new("a.b", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new("a~b", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new("a:b", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new("a@b", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new("a/b", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new("abc\u{202e}gnp.exe", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new("abc\u{200b}def", "e2", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "e1234567", "4915112345678").is_ok());
    assert!(OutboundCall::new(FLOW_ID, "e12345678", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "E2", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "2e", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "e 2", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "e\t2", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "e\n2", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "e2\u{202e}", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "e\u{e9}", "4915112345678").is_err());
    assert!(OutboundCall::new(FLOW_ID, "e2", "0151 1234").is_err());
    assert!(OutboundCall::new(FLOW_ID, "e2", "1".repeat(16)).is_err());
    assert!(OutboundCall::new(FLOW_ID, "e2", "1".repeat(15)).is_ok());
    assert!(OutboundCall::new(FLOW_ID, "e2", "1".repeat(6)).is_err());
    assert!(OutboundCall::new(FLOW_ID, "e2", "1".repeat(7)).is_ok());
    assert!(OutboundCall::new(FLOW_ID, "e2", "0123456").is_err());
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

#[test]
fn a_documented_receipt_body_parses_on_its_own() {
    let receipt = OutboundCallReceipt::parse(br#"{"callSid":"c-42"}"#).expect("documented body");
    assert_eq!(receipt.call_sid(), Some("c-42"));
    assert!(OutboundCallReceipt::parse(b"not json").is_err());
}
