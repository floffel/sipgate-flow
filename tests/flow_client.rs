//! Outbound Flow calls: the one documented imperative Flow endpoint.

mod common;

use std::time::Duration;

use common::{json_response, no_content, response, static_auth, Body, MockTransport};
use sipgate_flow::{
    AccountRetentionSettings, AiWebhookSettings, Error, FlowClient, OutboundCall,
    OutboundCallReceipt, RecordingAnnouncementMode, Result, SetAccountRetentionSettings,
    StaticToken, Token, TokenSource, TranscriptionAnnouncementMode, TransferCallerIdSource,
    TtsVoice, MAX_ACCOUNT_SETTING_TOKEN_BYTES, MAX_EVENT_RETENTION_DAYS,
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
async fn a_post_with_401_is_not_resent() {
    let transport = MockTransport::new();
    transport.push_response(response(
        401,
        &[("Retry-After", "5"), ("X-Request-ID", "req-post-401")],
        b"account disabled",
    ));
    transport.push_response(response(201, &[], br#"{"callSid":"pbx-c-retry"}"#));
    let client = FlowClient::new(transport.clone(), Rotating);

    let error = client
        .call(&OutboundCall::new(FLOW_ID, "e2", "4915112345678").expect("valid"))
        .await
        .expect_err("POST must not be retried after 401");
    assert!(matches!(
        error,
        Error::Unauthorized {
            status: 401,
            ref body,
            retry_after: Some(retry_after),
            request_id: Some(ref request_id),
            ..
        } if body == b"account disabled"
            && retry_after == Duration::from_secs(5)
            && request_id == "req-post-401"
    ));
    assert_eq!(error.retry_after(), Some(Duration::from_secs(5)));

    let calls = transport.calls();
    assert_eq!(calls.len(), 1, "a non-idempotent request is never resent");
    assert_eq!(calls[0].auth.bearer(), Some("t1"));
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
fn billing_device_stays_at_the_documented_suffix_ceiling() {
    assert!(OutboundCall::new(FLOW_ID, "e", "4915112345678").is_ok());
    assert!(OutboundCall::new(FLOW_ID, "e1234567", "4915112345678").is_ok());
    assert!(OutboundCall::new(FLOW_ID, "e12345678", "4915112345678").is_err());
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
    fn refreshable(&self) -> bool {
        true
    }

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

#[tokio::test]
async fn updating_the_ai_webhook_puts_the_documented_body() {
    let transport = MockTransport::new();
    transport.push_response(response(
        200,
        &[("Content-Type", "application/json")],
        br#"{"webhookUrl":"https://example.com/ai-flow"}"#,
    ));
    let client = client(transport.clone());

    let settings = AiWebhookSettings::new("https://example.com/ai-flow").expect("valid");
    let body = client.update_ai_webhook(&settings).await.expect("updated");
    assert_eq!(body["webhookUrl"], "https://example.com/ai-flow");

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "PUT");
    assert_eq!(recorded.url, "https://api.sipgate.com/v3/ai-webhooks");
    assert_eq!(recorded.auth.bearer(), Some("access-token"));
    assert_eq!(
        recorded.body,
        Body::Json(serde_json::json!({"webhookUrl": "https://example.com/ai-flow"}))
    );
}

#[tokio::test]
async fn reading_the_ai_webhook_gets_the_documented_path() {
    let transport = MockTransport::new();
    transport.push_response(response(
        200,
        &[("Content-Type", "application/json")],
        br#"{"webhook_url":"https://example.com/hook"}"#,
    ));
    let client = client(transport.clone());

    let settings = client.ai_webhook().await.expect("read");
    assert_eq!(settings.webhook_url(), "https://example.com/hook");

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "GET");
    assert_eq!(recorded.url, "https://api.sipgate.com/v3/ai-webhooks");
    assert_eq!(recorded.body, Body::Empty);
}

#[tokio::test]
async fn a_missing_ai_webhook_stays_a_documented_404_api_error() {
    let transport = MockTransport::new();
    transport.push_response(response(404, &[], b"not configured"));
    let error = client(transport)
        .ai_webhook()
        .await
        .expect_err("no webhook configured");
    assert!(matches!(
        error,
        Error::Api { status: 404, ref body, retryable: false, ambiguous: false, .. }
            if body == "not configured"
    ));
}

#[tokio::test]
async fn listing_tts_voices_accepts_the_documented_string_catalogue() {
    let transport = MockTransport::new();
    transport.push_response(response(
        200,
        &[("Content-Type", "application/json")],
        br#"{"items":["SIPGATE_VOICE", "RACHEL", "DE_DE_FLORIAN"],"extra":true}"#,
    ));
    let client = client(transport.clone());

    let voices = client.tts_voices().await.expect("voices");
    assert_eq!(
        voices.iter().map(TtsVoice::id).collect::<Vec<_>>(),
        ["SIPGATE_VOICE", "RACHEL", "DE_DE_FLORIAN"]
    );

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "GET");
    assert_eq!(recorded.url, "https://api.sipgate.com/v3/tts/voices");
}

#[tokio::test]
async fn listing_tts_voices_accepts_richer_voice_objects() {
    let transport = MockTransport::new();
    transport.push_response(response(
        200,
        &[("Content-Type", "application/json")],
        br#"{"items":[{"voiceId":"v1","name":"Kai","languages":["de","en"],"previewUrl":"https://example.com/a.mp3","recommended":true,"beta":false,"vendor":"future"}]}"#,
    ));

    let voices = client(transport).tts_voices().await.expect("voices");
    let voice = voices.first().expect("one voice");
    assert_eq!(voice.id(), "v1");
    assert_eq!(voice.name(), Some("Kai"));
    assert_eq!(voice.languages(), ["de", "en"]);
    assert_eq!(voice.preview_url(), Some("https://example.com/a.mp3"));
    assert_eq!(voice.recommended(), Some(true));
    assert_eq!(voice.beta(), Some(false));
    assert_eq!(voice.raw()["vendor"], "future");
}

#[tokio::test]
async fn an_empty_tts_voice_catalogue_is_a_validation_error() {
    let transport = MockTransport::new();
    transport.push_response(response(200, &[], br#"{"items":[]}"#));
    let error = client(transport)
        .tts_voices()
        .await
        .expect_err("empty list");
    assert!(matches!(
        error,
        Error::Validation {
            field: "tts_voices",
            ..
        }
    ));
}

#[test]
fn ai_webhook_settings_validate_the_url_shape() {
    assert_eq!(
        AiWebhookSettings::new("https://example.com/hook")
            .expect("valid")
            .to_json(),
        serde_json::json!({"webhookUrl": "https://example.com/hook"})
    );
    assert!(AiWebhookSettings::new("https://example.com").is_ok());
    assert!(AiWebhookSettings::new("https://example.com/").is_ok());
    assert!(AiWebhookSettings::new("https://example.com/abcdefgh").is_ok());
    assert!(AiWebhookSettings::new("http://example.com/hook").is_err());
    assert!(AiWebhookSettings::new("HTTP://example.com/hook").is_err());
    assert!(AiWebhookSettings::new("").is_err());
    assert!(AiWebhookSettings::new("example.com/hook").is_err());
    assert!(AiWebhookSettings::new("https://").is_err());
    assert!(AiWebhookSettings::new("https://user:secret@example.com").is_err());
    assert!(AiWebhookSettings::new("https://example.com/a b").is_err());
}

#[test]
fn ai_webhook_debug_does_not_reveal_the_whole_url() {
    let settings = AiWebhookSettings::new("https://example.com/secret-hook").expect("valid");
    let rendered = format!("{settings:?}");
    assert!(rendered.contains("example.com"), "{rendered}");
    assert!(!rendered.contains("secret-hook"), "{rendered}");
}

#[test]
fn tts_voice_decodes_the_string_and_object_shapes() {
    assert_eq!(
        TtsVoice::from_json(serde_json::json!("SIPGATE_VOICE"))
            .expect("string entry")
            .id(),
        "SIPGATE_VOICE"
    );
    let voice = TtsVoice::from_json(serde_json::json!({
        "voice_id": "v2",
        "label": "Kai",
        "language": "de",
    }))
    .expect("object entry");
    assert_eq!(voice.id(), "v2");
    assert_eq!(voice.name(), Some("Kai"));
    assert_eq!(voice.languages(), ["de"]);
    assert!(TtsVoice::from_json(serde_json::json!({})).is_err());
    assert!(TtsVoice::from_json(serde_json::json!("")).is_err());
}

#[test]
fn ai_webhook_settings_reads_the_documented_json_body() {
    let settings =
        AiWebhookSettings::from_json(&serde_json::json!({"webhookUrl": "https://x.test/hook"}));
    assert_eq!(settings.webhook_url(), "https://x.test/hook");
    assert_eq!(
        AiWebhookSettings::from_json(&serde_json::json!({})).webhook_url(),
        ""
    );
}

// ---------------------------------------------------------------------------
// v3 TTS catalogue and synthesis (#169)
// ---------------------------------------------------------------------------

use sipgate_flow::{
    AgentVoices, CurrentVoice, SynthesizeRequest, SynthesizeStreamRequest, SynthesizedAudio,
    TtsSetting,
};

#[tokio::test]
async fn synthesizing_posts_the_documented_body_and_parses_the_setting() {
    let transport = MockTransport::new();
    transport.push_response(response(
        200,
        &[("Content-Type", "application/json")],
        br#"{"announcementId":"a-1","alias":"greeting","content":"Guten Tag.","voice":"SIPGATE_VOICE","vendor":"future"}"#,
    ));
    let client = client(transport.clone());

    let request = SynthesizeRequest::new("SIPGATE_VOICE", "Guten Tag.")
        .expect("valid")
        .with_title("Begruessung")
        .expect("valid title")
        .with_acd_id("e0e1e2e3-0000-0000-0000-000000000000")
        .expect("valid id");
    let setting = client.synthesize(&request).await.expect("synthesized");

    assert_eq!(setting.announcement_id(), Some("a-1"));
    assert_eq!(setting.voice(), Some("SIPGATE_VOICE"));
    assert_eq!(setting.alias(), Some("greeting"));
    assert_eq!(setting.content(), Some("Guten Tag."));
    assert_eq!(setting.raw()["vendor"], "future");

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "POST");
    assert_eq!(recorded.url, "https://api.sipgate.com/v3/tts");
    assert_eq!(recorded.auth.bearer(), Some("access-token"));
    assert_eq!(
        recorded.body,
        Body::Json(serde_json::json!({
            "voice": "SIPGATE_VOICE",
            "content": "Guten Tag.",
            "title": "Begruessung",
            "acdId": "e0e1e2e3-0000-0000-0000-000000000000",
        }))
    );
}

#[tokio::test]
async fn a_5xx_after_synthesize_is_ambiguous_not_retried() {
    let transport = MockTransport::new();
    transport.push_response(response(500, &[], b"boom"));
    let error = client(transport)
        .synthesize(&SynthesizeRequest::new("SIPGATE_VOICE", "hi").expect("valid"))
        .await
        .expect_err("5xx after a POST");
    assert!(error.is_ambiguous(), "{error:?}");
    assert!(!error.is_retryable());
    assert_eq!(error.status(), Some(500));
}

#[tokio::test]
async fn listing_tts_settings_queries_the_acd_id_and_parses_the_envelope() {
    let transport = MockTransport::new();
    transport.push_response(response(
        200,
        &[("Content-Type", "application/json")],
        br#"{"items":[{"announcementId":"a-1"},{"announcement_id":"a-2"}]}"#,
    ));
    let client = client(transport.clone());

    let settings = client
        .tts_settings("e0e1e2e3-0000-0000-0000-000000000000")
        .await
        .expect("settings");
    assert_eq!(
        settings
            .iter()
            .map(TtsSetting::announcement_id)
            .collect::<Vec<_>>(),
        [Some("a-1"), Some("a-2")]
    );

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "GET");
    assert_eq!(
        recorded.url,
        "https://api.sipgate.com/v3/tts?acdId=e0e1e2e3-0000-0000-0000-000000000000"
    );
    assert_eq!(recorded.body, Body::Empty);
}

#[tokio::test]
async fn listing_tts_settings_rejects_an_id_that_is_not_a_uuid_shape() {
    let transport = MockTransport::new();
    let error = client(transport.clone())
        .tts_settings("not a uuid")
        .await
        .expect_err("invalid id");
    assert!(matches!(
        error,
        Error::Validation {
            field: "acd_id",
            ..
        }
    ));
    assert_eq!(transport.call_count(), 0, "no request reaches the wire");
}

#[tokio::test]
async fn an_empty_tts_setting_envelope_is_an_empty_list() {
    let transport = MockTransport::new();
    transport.push_response(response(200, &[], br#"{"items":[]}"#));
    let settings = client(transport)
        .tts_settings("e0e1e2e3-0000-0000-0000-000000000000")
        .await
        .expect("settings");
    assert_eq!(settings.len(), 0);
}

#[tokio::test]
async fn streaming_posts_the_documented_body_and_validates_the_audio() {
    let transport = MockTransport::new();
    transport.push_response(response(200, &[], b"aGVsbG8="));
    let client = client(transport.clone());

    let request = SynthesizeStreamRequest::new("SIPGATE_VOICE", "hi").expect("valid");
    let audio = client.synthesize_stream(&request).await.expect("streamed");
    assert_eq!(audio.base64_data(), "aGVsbG8=");
    assert_eq!(audio.decode().expect("canonical"), b"hello");

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "POST");
    assert_eq!(recorded.url, "https://api.sipgate.com/v3/tts/stream");
    assert_eq!(
        recorded.body,
        Body::Json(serde_json::json!({"voice": "SIPGATE_VOICE", "content": "hi"}))
    );
}

#[tokio::test]
async fn a_non_base64_stream_body_is_a_validation_error() {
    let transport = MockTransport::new();
    transport.push_response(response(200, &[], b"not base64!"));
    let error = client(transport)
        .synthesize_stream(&SynthesizeStreamRequest::new("SIPGATE_VOICE", "hi").expect("valid"))
        .await
        .expect_err("not base64");
    assert!(matches!(
        error,
        Error::Validation {
            field: "tts_audio",
            ..
        }
    ));
}

#[tokio::test]
async fn reading_agent_voices_gets_the_documented_path_and_decodes_the_catalogue() {
    let transport = MockTransport::new();
    transport.push_response(response(
        200,
        &[("Content-Type", "application/json")],
        br#"{"items":[{"voiceId":"SIPGATE-0","name":"Kai","languages":["de"],"recommended":true,"beta":false,"previewUrl":"https://example.com/a.mp3"}],"currentVoice":{"voiceId":"SIPGATE-0","name":"Kai"}}"#,
    ));
    let client = client(transport.clone());

    let voices = client.agent_voices("agent-1").await.expect("voices");
    assert_eq!(voices.items()[0].id(), "SIPGATE-0");
    assert_eq!(
        voices.current_voice().map(CurrentVoice::voice_id),
        Some("SIPGATE-0")
    );

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "GET");
    assert_eq!(
        recorded.url,
        "https://api.sipgate.com/v3/ai-agents/agent-1/voices"
    );
}

#[tokio::test]
async fn agent_voices_rejects_a_path_unsafe_agent_id_without_a_request() {
    let transport = MockTransport::new();
    let error = client(transport.clone())
        .agent_voices("../etc")
        .await
        .expect_err("path unsafe");
    assert!(matches!(
        error,
        Error::Validation {
            field: "agent_id",
            ..
        }
    ));
    assert_eq!(transport.call_count(), 0);
}

#[test]
fn synthesize_request_holds_the_documented_character_boundaries() {
    let voice = "V".repeat(64);
    assert!(SynthesizeRequest::new(&voice, "hi").is_ok());
    assert!(SynthesizeRequest::new("V".repeat(65), "hi").is_err());

    let content_at = "a".repeat(1024);
    let content_over = "a".repeat(1025);
    assert!(SynthesizeRequest::new("RACHEL", &content_at).is_ok());
    assert!(SynthesizeRequest::new("RACHEL", &content_over).is_err());

    // The limit is characters, not bytes: 255 multibyte characters still pass.
    let title_at = "ä".repeat(255);
    let title_over = "ä".repeat(256);
    assert!(SynthesizeRequest::new("RACHEL", "hi")
        .expect("valid")
        .with_title(&title_at)
        .is_ok());
    assert!(SynthesizeRequest::new("RACHEL", "hi")
        .expect("valid")
        .with_title(&title_over)
        .is_err());
}

#[test]
fn stream_request_holds_the_content_boundary() {
    assert!(SynthesizeStreamRequest::new("RACHEL", "a".repeat(1024)).is_ok());
    assert!(SynthesizeStreamRequest::new("RACHEL", "a".repeat(1025)).is_err());
}

#[test]
fn synthesized_audio_holds_the_base64_boundary() {
    assert!(SynthesizedAudio::new("aGk=").is_ok());
    assert!(SynthesizedAudio::new("aGk").is_err());
    assert!(SynthesizedAudio::new("").is_err());
}

#[test]
fn agent_voices_tolerates_missing_and_unknown_fields() {
    let voices = AgentVoices::from_json(serde_json::json!({"items": [], "vendor": "future"}))
        .expect("tolerant");
    assert_eq!(voices.items(), []);
    assert_eq!(voices.current_voice(), None);
    assert_eq!(voices.raw()["vendor"], "future");

    let empty_object = AgentVoices::from_json(serde_json::json!({})).expect("tolerant");
    assert_eq!(empty_object.items(), []);

    let current = CurrentVoice::from_json(&serde_json::json!({"voice_id": "v1"})).expect("camel");
    assert_eq!(current.voice_id(), "v1");
    assert!(CurrentVoice::from_json(&serde_json::json!({})).is_err());
}
// v3 account administration (#170)
// ---------------------------------------------------------------------------

fn account_client(transport: MockTransport) -> FlowClient<MockTransport, StaticToken> {
    FlowClient::new(transport, static_auth())
}

#[tokio::test]
async fn recording_announcement_mode_reads_the_documented_path_and_body() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({"mode": "OPT_OUT"})));
    let client = account_client(transport.clone());

    let mode = client.recording_announcement_mode().await.expect("read");
    assert_eq!(mode, RecordingAnnouncementMode::OptOut);

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "GET");
    assert_eq!(
        recorded.url,
        "https://api.sipgate.com/v3/account-settings/privacyAnnouncements/recording"
    );
    assert_eq!(recorded.auth.bearer(), Some("access-token"));
    assert_eq!(recorded.body, Body::Empty);
}

#[tokio::test]
async fn recording_announcement_mode_maps_both_documented_values() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({"mode": "INFORM_ONLY"})));
    let client = account_client(transport);
    assert_eq!(
        client.recording_announcement_mode().await.expect("read"),
        RecordingAnnouncementMode::InformOnly
    );
    assert_eq!(
        RecordingAnnouncementMode::from_wire("opt_out"),
        RecordingAnnouncementMode::OptOut
    );
    assert_eq!(
        RecordingAnnouncementMode::from_wire("future_mode").as_str(),
        "future_mode"
    );
}

#[tokio::test]
async fn a_missing_recording_mode_is_a_typed_validation_error() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({})));
    let client = account_client(transport);
    let error = client
        .recording_announcement_mode()
        .await
        .expect_err("missing mode");
    assert!(matches!(
        error,
        Error::Validation { field, .. } if field == "recording_announcement_mode"
    ));
}

#[tokio::test]
async fn setting_the_recording_announcement_puts_the_documented_body() {
    let transport = MockTransport::new();
    transport.push_response(no_content());
    let client = account_client(transport.clone());

    client
        .set_recording_announcement_mode(&RecordingAnnouncementMode::InformOnly)
        .await
        .expect("204");

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "PUT");
    assert_eq!(
        recorded.url,
        "https://api.sipgate.com/v3/account-settings/privacyAnnouncements/recording"
    );
    assert_eq!(
        recorded.body,
        Body::Json(serde_json::json!({"mode": "INFORM_ONLY"}))
    );
}

#[tokio::test]
async fn an_unmodelled_recording_mode_is_validated_before_the_wire() {
    let transport = MockTransport::new();
    let client = account_client(transport.clone());

    let error = client
        .set_recording_announcement_mode(&RecordingAnnouncementMode::Other("has space".into()))
        .await
        .expect_err("rejected before the wire");
    assert!(matches!(
        error,
        Error::Validation { field, .. } if field == "recording_announcement_mode"
    ));
    assert_eq!(transport.call_count(), 0, "nothing may reach the transport");

    transport.push_response(no_content());
    client
        .set_recording_announcement_mode(&RecordingAnnouncementMode::Other("FUTURE_MODE".into()))
        .await
        .expect("a plausible forward-compatible token is sent");
    assert_eq!(transport.call_count(), 1, "the valid token did go out");
}

#[test]
fn the_recording_mode_token_boundary_is_proven() {
    let inside = format!("M{}", "A".repeat(MAX_ACCOUNT_SETTING_TOKEN_BYTES - 1));
    let outside = format!("M{}", "A".repeat(MAX_ACCOUNT_SETTING_TOKEN_BYTES));
    assert!(RecordingAnnouncementMode::Other(inside).validate().is_ok());
    assert!(RecordingAnnouncementMode::Other(outside)
        .validate()
        .is_err());
    assert!(RecordingAnnouncementMode::OptOut.validate().is_ok());
}

#[tokio::test]
async fn transcription_announcement_mode_round_trips_the_documented_path() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({"mode": "none"})));
    let client = account_client(transport.clone());

    assert_eq!(
        client
            .transcription_announcement_mode()
            .await
            .expect("read"),
        TranscriptionAnnouncementMode::Disabled
    );
    assert_eq!(
        transport.only_call().url,
        "https://api.sipgate.com/v3/account-settings/privacyAnnouncements/transcription"
    );

    let transport = MockTransport::new();
    transport.push_response(no_content());
    let client = account_client(transport.clone());
    client
        .set_transcription_announcement_mode(&TranscriptionAnnouncementMode::InformOnly)
        .await
        .expect("204");
    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "PUT");
    assert_eq!(
        recorded.body,
        Body::Json(serde_json::json!({"mode": "INFORM_ONLY"}))
    );
}

#[test]
fn the_transcription_mode_distinguishes_none_from_unknown() {
    assert_eq!(
        TranscriptionAnnouncementMode::from_wire("NONE"),
        TranscriptionAnnouncementMode::Disabled
    );
    assert_eq!(
        TranscriptionAnnouncementMode::from_wire("SOMETHING_ELSE"),
        TranscriptionAnnouncementMode::Other("SOMETHING_ELSE".into())
    );
    assert!(TranscriptionAnnouncementMode::from_json(&serde_json::json!({"mode": ""})).is_err());
}

#[tokio::test]
async fn transfer_caller_id_reads_and_writes_the_documented_path() {
    let transport = MockTransport::new();
    transport.push_response(json_response(
        &serde_json::json!({"source": "TRANSFERRED_PARTY"}),
    ));
    let client = account_client(transport.clone());
    assert_eq!(
        client.transfer_caller_id().await.expect("read"),
        TransferCallerIdSource::TransferredParty
    );
    assert_eq!(
        transport.only_call().url,
        "https://api.sipgate.com/v3/account-settings/transferCallerId"
    );

    let transport = MockTransport::new();
    transport.push_response(no_content());
    let client = account_client(transport.clone());
    client
        .set_transfer_caller_id(&TransferCallerIdSource::TransferringParty)
        .await
        .expect("204");
    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "PUT");
    assert_eq!(
        recorded.body,
        Body::Json(serde_json::json!({"source": "TRANSFERRING_PARTY"}))
    );
}

#[test]
fn transfer_caller_id_source_keeps_unknown_values_and_validates() {
    assert_eq!(
        TransferCallerIdSource::from_wire("transferring_party"),
        TransferCallerIdSource::TransferringParty
    );
    assert_eq!(
        TransferCallerIdSource::Other("FUTURE".into()).as_str(),
        "FUTURE"
    );
    assert!(TransferCallerIdSource::from_json(&serde_json::json!({"source": ""})).is_err());
    assert!(TransferCallerIdSource::Other(String::new())
        .validate()
        .is_err());
    assert!(TransferCallerIdSource::TransferredParty.validate().is_ok());
}

#[tokio::test]
async fn account_retention_reads_null_as_keep_indefinitely() {
    let transport = MockTransport::new();
    transport.push_response(json_response(
        &serde_json::json!({"eventRetentionDays": null}),
    ));
    let client = account_client(transport.clone());

    let settings = client.account_retention().await.expect("read");
    assert_eq!(settings.event_retention_days(), None);
    assert_eq!(
        transport.only_call().url,
        "https://api.sipgate.com/v3/analytics/call-events/settings/retention"
    );
}

#[tokio::test]
async fn account_retention_reads_a_number_and_tolerates_snake_case() {
    let transport = MockTransport::new();
    transport.push_response(json_response(
        &serde_json::json!({"event_retention_days": 90, "future": true}),
    ));
    let client = account_client(transport);
    assert_eq!(
        client
            .account_retention()
            .await
            .expect("read")
            .event_retention_days(),
        Some(90)
    );
}

#[test]
fn account_retention_tolerates_missing_and_out_of_range_values() {
    assert_eq!(
        AccountRetentionSettings::from_json(&serde_json::json!({})).event_retention_days(),
        None
    );
    assert_eq!(
        AccountRetentionSettings::from_json(&serde_json::json!({"eventRetentionDays": "90"}))
            .event_retention_days(),
        None,
        "a non-number is not silently coerced"
    );
    assert_eq!(
        AccountRetentionSettings::from_json(
            &serde_json::json!({"eventRetentionDays": u64::from(u32::MAX) + 1}),
        )
        .event_retention_days(),
        None
    );
}

#[tokio::test]
async fn setting_account_retention_posts_the_documented_body() {
    let transport = MockTransport::new();
    transport.push_response(no_content());
    let client = account_client(transport.clone());

    let request = SetAccountRetentionSettings::new(90).expect("valid");
    client.set_account_retention(&request).await.expect("204");

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "PUT");
    assert_eq!(
        recorded.url,
        "https://api.sipgate.com/v3/analytics/call-events/settings/retention"
    );
    assert_eq!(
        recorded.body,
        Body::Json(serde_json::json!({"eventRetentionDays": 90}))
    );
}

#[tokio::test]
async fn clearing_account_retention_deletes_the_policy() {
    let transport = MockTransport::new();
    transport.push_response(no_content());
    let client = account_client(transport.clone());
    client.clear_account_retention().await.expect("204");

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "DELETE");
    assert_eq!(
        recorded.url,
        "https://api.sipgate.com/v3/analytics/call-events/settings/retention"
    );
    assert_eq!(recorded.body, Body::Empty);
}

#[test]
fn retention_days_boundary_is_proven_on_both_ends() {
    assert!(
        SetAccountRetentionSettings::new(0).is_err(),
        "exclusive min"
    );
    assert!(SetAccountRetentionSettings::new(1).is_ok(), "just inside");
    assert!(SetAccountRetentionSettings::new(2).is_ok());
    assert!(
        SetAccountRetentionSettings::new(MAX_EVENT_RETENTION_DAYS).is_ok(),
        "inclusive max"
    );
    assert!(
        SetAccountRetentionSettings::new(MAX_EVENT_RETENTION_DAYS + 1).is_err(),
        "just outside"
    );
    let error = SetAccountRetentionSettings::new(0).expect_err("min");
    assert!(matches!(
        error,
        Error::Validation { field, .. } if field == "event_retention_days"
    ));
}

#[tokio::test]
async fn an_unrelated_failure_status_surfaces_as_api_error() {
    let transport = MockTransport::new();
    transport.push_response(response(403, &[], b"{\"error\":\"not allowed\"}"));
    let client = account_client(transport);
    let error = client
        .set_recording_announcement_mode(&RecordingAnnouncementMode::OptOut)
        .await
        .expect_err("403");
    assert_eq!(error.status(), Some(403));
    assert!(!error.is_ambiguous());
}

#[test]
fn account_setting_enums_expose_every_documented_token_and_arm() {
    assert_eq!(TranscriptionAnnouncementMode::Disabled.as_str(), "NONE");
    assert_eq!(
        TranscriptionAnnouncementMode::Other("FUTURE_MODE".into()).as_str(),
        "FUTURE_MODE"
    );
    assert!(TranscriptionAnnouncementMode::Other("FUTURE_MODE".into())
        .validate()
        .is_ok());
    assert!(TranscriptionAnnouncementMode::Other("has space".into())
        .validate()
        .is_err());
    assert_eq!(
        RecordingAnnouncementMode::InformOnly.as_str(),
        "INFORM_ONLY"
    );
    assert_eq!(
        RecordingAnnouncementMode::Other("FUTURE_MODE".into()).as_str(),
        "FUTURE_MODE"
    );
    for unknown in ["TRANSFERRED_PARTY", "UNKNOWN"] {
        if unknown == "UNKNOWN" {
            assert_eq!(
                TransferCallerIdSource::from_wire(unknown),
                TransferCallerIdSource::Other("UNKNOWN".into())
            );
        }
    }
    assert_eq!(
        TransferCallerIdSource::TransferringParty.as_str(),
        "TRANSFERRING_PARTY"
    );
    assert!(TransferCallerIdSource::Other("FUTURE".into())
        .validate()
        .is_ok());
    let request = SetAccountRetentionSettings::new(45).expect("valid");
    assert_eq!(request.event_retention_days(), 45);
}

#[test]
fn tts_request_builders_expose_every_getter_and_debug_impl() {
    let request = SynthesizeRequest::new("RACHEL", "hi")
        .expect("valid")
        .with_title("Greeting")
        .expect("title")
        .with_acd_id("e0e1e2e3-0000-0000-0000-000000000000")
        .expect("acd")
        .with_kind("ANNOUNCEMENT")
        .expect("kind");
    assert_eq!(request.voice(), "RACHEL");
    assert_eq!(request.content(), "hi");
    assert_eq!(request.title(), Some("Greeting"));
    assert_eq!(
        request.acd_id(),
        Some("e0e1e2e3-0000-0000-0000-000000000000")
    );
    assert_eq!(request.kind(), Some("ANNOUNCEMENT"));
    assert_eq!(request.to_json()["type"], "ANNOUNCEMENT");
    assert_ne!(format!("{request:?}"), String::new());

    let stream = SynthesizeStreamRequest::new("RACHEL", "hi").expect("valid");
    assert_eq!(stream.voice(), "RACHEL");
    assert_eq!(stream.content(), "hi");
    assert_ne!(format!("{stream:?}"), String::new());

    let voice = CurrentVoice::from_json(&serde_json::json!({"voiceId": "v1", "name": "Rachel"}))
        .expect("valid");
    assert_eq!(voice.name(), Some("Rachel"));
    assert_ne!(format!("{voice:?}"), String::new());
}
