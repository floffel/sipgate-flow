//! REST v2: documented method/path/body per endpoint, the retry budget, the
//! 401 refresh, and concurrency.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    json_response, no_content, response, static_auth, Body, MockTransport, RecordingSleeper,
};
use sipgate_flow::rest::{
    Announcement, Call, ChannelCall, Dtmf, Fax, PlayVoicemail, Recording, RecordingSession,
    ResendFax, Sms, TransferRequest,
};
use sipgate_flow::{
    Error, RestClient, Result, RetryPolicy, RetryPolicy as Policy, StaticToken, Token, TokenSource,
};

type TestClient = RestClient<MockTransport, StaticToken, RecordingSleeper>;

fn harness() -> (MockTransport, RecordingSleeper, TestClient) {
    let transport = MockTransport::new();
    let sleeper = RecordingSleeper::new();
    let client = RestClient::new(transport.clone(), static_auth()).with_sleeper(sleeper.clone());
    (transport, sleeper, client)
}

fn json_body(body: &Body) -> serde_json::Value {
    match body {
        Body::Json(value) => value.clone(),
        other => panic!("expected a JSON body, got {other:?}"),
    }
}

#[tokio::test]
async fn send_sms_posts_the_documented_body() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    let sms = Sms::new("s0", "4915112345678", "Ihr Code: 4242").expect("valid");
    client.send_sms(&sms).await.expect("sent");

    let call = transport.only_call();
    assert_eq!(call.method.as_str(), "POST");
    assert_eq!(call.url, "https://api.sipgate.com/v2/sessions/sms");
    assert_eq!(call.token.as_deref(), Some("pat-token"));
    assert_eq!(
        json_body(&call.body),
        serde_json::from_str::<serde_json::Value>(include_str!("fixtures/rest/sms_request.json"))
            .expect("fixture")
    );
}

#[tokio::test]
async fn send_fax_posts_content_and_returns_the_session_id() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(
        &serde_json::json!({"sessionId": "f-session-1"}),
    ));
    let fax = Fax::new("f0", "4921112345678", "fax.pdf", "JVBERi0xLjQK").expect("valid");
    let value = client.send_fax(&fax).await.expect("sent");
    assert_eq!(value["sessionId"], "f-session-1");

    let call = transport.only_call();
    assert_eq!(call.url, "https://api.sipgate.com/v2/sessions/fax");
    assert_eq!(
        json_body(&call.body),
        serde_json::from_str::<serde_json::Value>(include_str!("fixtures/rest/fax_request.json"))
            .expect("fixture")
    );
}

#[tokio::test]
async fn a_fax_larger_than_the_documented_ceiling_is_refused_before_sending() {
    let content = "A".repeat(sipgate_flow::rest::MAX_FAX_BASE64_LEN + 4);
    let error = Fax::new("f0", "4915112345678", "big.pdf", content).expect_err("too large");
    assert!(matches!(
        error,
        Error::Validation {
            field: "base64Content",
            ..
        }
    ));
}

#[tokio::test]
async fn resend_fax_uses_its_own_path() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"sessionId": "s"})));
    client
        .resend_fax(&ResendFax::new("100018428").with_faxline_id("f0"))
        .await
        .expect("resent");
    let call = transport.only_call();
    assert_eq!(call.url, "https://api.sipgate.com/v2/sessions/fax/resend");
    assert_eq!(json_body(&call.body)["faxId"], "100018428");
}

#[tokio::test]
async fn new_call_posts_caller_and_callee() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"sessionId": "c-1"})));
    let call = Call::new("e0", "4915112345678").expect("valid");
    client.new_call(&call).await.expect("called");

    let recorded = transport.only_call();
    assert_eq!(recorded.url, "https://api.sipgate.com/v2/sessions/calls");
    assert_eq!(
        json_body(&recorded.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/new_call_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn channel_call_posts_the_neo_pbx_shape() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"callSid": "x"})));
    client
        .channel_call(&ChannelCall::new("e0", "4915790123456"))
        .await
        .expect("called");
    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "POST");
    assert_eq!(recorded.url, "https://api.sipgate.com/v2/calls");
    assert_eq!(
        json_body(&recorded.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/create_call_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn recording_sessions_route_to_their_own_paths() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"sessionId": "r1"})));
    transport.push_response(json_response(&serde_json::json!({"sessionId": "r2"})));
    let request = RecordingSession::new()
        .with_device_id("e0")
        .with_target_id("v0");
    client.record_ivr(&request).await.expect("ivr");
    client.record_voicemail(&request).await.expect("voicemail");

    let calls = transport.calls();
    assert_eq!(
        calls[0].url,
        "https://api.sipgate.com/v2/sessions/ivr/recording"
    );
    assert_eq!(
        calls[1].url,
        "https://api.sipgate.com/v2/sessions/voicemail/recording"
    );
    assert_eq!(json_body(&calls[0].body)["targetId"], "v0");
}

#[tokio::test]
async fn voicemail_playback_keeps_the_documents_datad_id_key() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(&serde_json::json!({"sessionId": "p1"})));
    client
        .play_voicemail(&PlayVoicemail::new("1000171", "e0"))
        .await
        .expect("played");

    let recorded = transport.only_call();
    assert_eq!(
        recorded.url,
        "https://api.sipgate.com/v2/sessions/voicemail/play"
    );
    assert_eq!(
        json_body(&recorded.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/play_voicemail_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn hangup_is_a_delete_without_a_body() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    client.hangup("ABCDEF0123456789").await.expect("hung up");
    let call = transport.only_call();
    assert_eq!(call.method.as_str(), "DELETE");
    assert_eq!(
        call.url,
        "https://api.sipgate.com/v2/calls/ABCDEF0123456789"
    );
    assert_eq!(call.body, Body::Empty);
}

#[tokio::test]
async fn dtmf_posts_the_sequence() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    client
        .send_dtmf("c1", &Dtmf::new("1234").expect("valid"))
        .await
        .expect("sent");
    let call = transport.only_call();
    assert_eq!(call.url, "https://api.sipgate.com/v2/calls/c1/dtmf");
    assert_eq!(
        json_body(&call.body),
        serde_json::json!({"sequence": "1234"})
    );
}

#[tokio::test]
async fn announcements_post_the_url() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    let announcement =
        Announcement::new("https://static.sipgate.com/examples/wav/example.wav").expect("valid");
    client.announce("c1", &announcement).await.expect("played");
    let call = transport.only_call();
    assert_eq!(
        call.url,
        "https://api.sipgate.com/v2/calls/c1/announcements"
    );
    assert_eq!(
        json_body(&call.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/announcement_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn recording_uses_put_and_the_documented_body() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    client
        .set_recording("c1", &Recording::start())
        .await
        .expect("recording");
    let call = transport.only_call();
    assert_eq!(call.method.as_str(), "PUT");
    assert_eq!(call.url, "https://api.sipgate.com/v2/calls/c1/recording");
    assert_eq!(
        json_body(&call.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/recording_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn hold_and_mute_put_a_boolean_value() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    transport.push_response(no_content());
    client.set_hold("c1", true).await.expect("hold");
    client.set_muted("c1", false).await.expect("mute");

    let calls = transport.calls();
    assert_eq!(calls[0].method.as_str(), "PUT");
    assert_eq!(calls[0].url, "https://api.sipgate.com/v2/calls/c1/hold");
    assert_eq!(
        json_body(&calls[0].body),
        serde_json::json!({"value": true})
    );
    assert_eq!(calls[1].url, "https://api.sipgate.com/v2/calls/c1/muted");
    assert_eq!(
        json_body(&calls[1].body),
        serde_json::json!({"value": false})
    );
}

#[tokio::test]
async fn transfer_posts_attend_and_number() {
    let (transport, _, client) = harness();
    transport.push_response(no_content());
    client
        .transfer(
            "c1",
            &TransferRequest::blind("4915112345678").expect("valid"),
        )
        .await
        .expect("transferred");
    let call = transport.only_call();
    assert_eq!(call.url, "https://api.sipgate.com/v2/calls/c1/transfer");
    assert_eq!(
        json_body(&call.body),
        serde_json::from_str::<serde_json::Value>(include_str!(
            "fixtures/rest/transfer_request.json"
        ))
        .expect("fixture")
    );
}

#[tokio::test]
async fn the_call_list_is_parsed_into_types() {
    let (transport, _, client) = harness();
    transport.push_response(json_response(
        &serde_json::from_str(include_str!("fixtures/rest/calls_response.json")).expect("fixture"),
    ));
    let calls = client.calls().await.expect("listed");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].call_id, "ABCDEF0123456789");
    assert!(calls[0].recording);
    assert!(calls[0].participants[0].owner);

    let recorded = transport.only_call();
    assert_eq!(recorded.method.as_str(), "GET");
    assert_eq!(recorded.url, "https://api.sipgate.com/v2/calls");
}

#[tokio::test]
async fn a_call_id_that_would_escape_the_path_is_refused_before_sending() {
    let (transport, _, client) = harness();
    for bad in ["", "a/b", "../calls", "a?b", "a b", "a#b", "a\tb"] {
        let error = client.hangup(bad).await.expect_err(bad);
        assert!(
            matches!(
                error,
                Error::Validation {
                    field: "call_id",
                    ..
                }
            ),
            "{bad:?} produced {error:?}"
        );
    }
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn the_base_url_and_timeout_are_configurable() {
    let transport = MockTransport::new();
    transport.push_response(no_content());
    let client = RestClient::new(transport.clone(), static_auth())
        .with_base_url("http://localhost:8080/")
        .with_timeout(Some(Duration::from_millis(1500)));

    client.hangup("c1").await.expect("hung up");
    let call = transport.only_call();
    assert_eq!(call.url, "http://localhost:8080/v2/calls/c1");
    assert_eq!(call.timeout, Some(Duration::from_millis(1500)));
}

#[tokio::test]
async fn a_429_is_retried_after_the_retry_after_delay() {
    let (transport, sleeper, client) = harness();
    transport.push_response(response(429, &[("Retry-After", "1")], b"slow down"));
    transport.push_response(no_content());

    client.hangup("c1").await.expect("second attempt wins");
    assert_eq!(transport.call_count(), 2);
    assert_eq!(sleeper.delays(), [Duration::from_secs(1)]);
}

#[tokio::test]
async fn retry_after_is_clamped_to_the_ceiling() {
    let (transport, sleeper, client) = harness();
    transport.push_response(response(429, &[("Retry-After", "600")], b"slow down"));
    transport.push_response(no_content());

    client.hangup("c1").await.expect("retried");
    assert_eq!(sleeper.delays(), [Duration::from_secs(8)]);
}

#[tokio::test]
async fn a_server_without_retry_after_falls_back_to_doubling_backoff() {
    let (transport, sleeper, client) = harness();
    for _ in 0..2 {
        transport.push_response(response(503, &[], b"maintenance"));
    }
    transport.push_response(no_content());

    client.hangup("c1").await.expect("third attempt wins");
    assert_eq!(
        sleeper.delays(),
        [Duration::from_millis(250), Duration::from_millis(500)]
    );
    assert_eq!(transport.call_count(), 3);
}

#[tokio::test]
async fn a_persistent_5xx_spends_the_budget_and_surfaces_the_error() {
    let (transport, sleeper, client) = harness();
    for _ in 0..10 {
        transport.push_response(response(500, &[], b"boom"));
    }

    let error = client.hangup("c1").await.expect_err("exhausted");
    assert!(matches!(error, Error::Api { status: 500, .. }));
    assert_eq!(transport.call_count(), 3, "max_attempts is 3");
    assert_eq!(
        sleeper.delays(),
        [Duration::from_millis(250), Duration::from_millis(500)]
    );
    assert_eq!(sleeper.total(), Duration::from_millis(750));
}

#[tokio::test]
async fn a_no_retry_policy_stops_after_the_first_failure() {
    let transport = MockTransport::new();
    transport.push_response(response(503, &[], b"maintenance"));
    let client = RestClient::new(transport.clone(), static_auth())
        .with_sleeper(RecordingSleeper::new())
        .with_retry(RetryPolicy::none());

    assert!(client.hangup("c1").await.is_err());
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn a_4xx_that_is_not_401_is_terminal() {
    let (transport, sleeper, client) = harness();
    transport.push_response(response(404, &[], b"{\"error\":\"call not found\"}"));

    let error = client.hangup("c1").await.expect_err("404");
    assert!(matches!(
        error,
        Error::Api {
            status: 404,
            retryable: false,
            ..
        }
    ));
    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
    assert_eq!(sleeper.delays().len(), 0);
}

#[tokio::test]
async fn an_error_body_is_truncated_for_logs() {
    let (transport, _, client) = harness();
    let huge = "x".repeat(10_000);
    transport.push_response(response(400, &[], huge.as_bytes()));
    let error = client.hangup("c1").await.expect_err("400");
    let rendered = format!("{error}");
    assert!(
        rendered.len() < 1000,
        "body not truncated: {}",
        rendered.len()
    );
}

#[tokio::test]
async fn a_transient_transport_failure_is_retried_and_a_terminal_one_is_not() {
    let (transport, _, client) = harness();
    transport.push_transient_failure("connect: connection refused");
    transport.push_response(no_content());
    client.hangup("c1").await.expect("retried");
    assert_eq!(transport.call_count(), 2);

    let (transport, _, client) = harness();
    transport.push_terminal_failure("unsupported scheme");
    let error = client.hangup("c1").await.expect_err("terminal");
    assert!(!error.is_retryable());
    assert_eq!(transport.call_count(), 1);
}

/// A token source that hands out `t1`, `t2`, … and records every force flag.
struct RotatingToken {
    issued: AtomicUsize,
    forced: Mutex<Vec<bool>>,
}

impl RotatingToken {
    fn new() -> Self {
        Self {
            issued: AtomicUsize::new(0),
            forced: Mutex::new(Vec::new()),
        }
    }

    fn forced(&self) -> Vec<bool> {
        self.forced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl TokenSource for RotatingToken {
    fn access_token(
        &self,
        force_refresh: bool,
    ) -> impl std::future::Future<Output = Result<Token>> + Send {
        self.forced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(force_refresh);
        let issued = self.issued.fetch_add(1, Ordering::Relaxed) + 1;
        std::future::ready(Token::from_json(
            &serde_json::json!({"access_token": format!("t{issued}")}),
        ))
    }

    fn invalidate(&self) {}
}

#[tokio::test]
async fn a_401_refreshes_once_and_then_succeeds() {
    let transport = MockTransport::new();
    transport.push_response(response(401, &[], b"expired"));
    transport.push_response(no_content());
    let sleeper = RecordingSleeper::new();
    let client =
        RestClient::new(transport.clone(), RotatingToken::new()).with_sleeper(sleeper.clone());

    client.hangup("c1").await.expect("refresh worked");
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].token.as_deref(), Some("t1"));
    assert_eq!(calls[1].token.as_deref(), Some("t2"), "second token used");
    assert!(sleeper.delays().is_empty(), "a refresh is not a backoff");
}

#[tokio::test]
async fn a_second_401_is_terminal() {
    let transport = MockTransport::new();
    transport.push_response(response(401, &[], b"no"));
    transport.push_response(response(401, &[], b"still no"));
    let client = RestClient::new(transport.clone(), RotatingToken::new())
        .with_sleeper(RecordingSleeper::new());

    let error = client.hangup("c1").await.expect_err("terminal");
    assert!(matches!(error, Error::Unauthorized));
    assert_eq!(transport.call_count(), 2, "refresh once, never loop");
}

#[tokio::test]
async fn the_refresh_is_requested_forcefully() {
    let transport = MockTransport::new();
    transport.push_response(response(401, &[], b"expired"));
    transport.push_response(no_content());
    let auth = Arc::new(RotatingToken::new());
    let client = RestClient::new(transport, AuthHandle(Arc::clone(&auth)))
        .with_sleeper(RecordingSleeper::new());

    client.hangup("c1").await.expect("ok");
    assert_eq!(auth.forced(), [false, true]);
}

/// A newtype so the test can keep a handle on the same token source.
struct AuthHandle(Arc<RotatingToken>);

impl TokenSource for AuthHandle {
    fn access_token(
        &self,
        force_refresh: bool,
    ) -> impl std::future::Future<Output = Result<Token>> + Send {
        self.0.access_token(force_refresh)
    }

    fn invalidate(&self) {}
}

#[test]
fn the_client_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TestClient>();
    assert_send_sync::<RestClient<MockTransport, RotatingToken, RecordingSleeper>>();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_two_tasks_hammer_one_client() {
    let transport = MockTransport::always(no_content());
    let client = Arc::new(
        RestClient::new(transport.clone(), static_auth()).with_sleeper(RecordingSleeper::new()),
    );

    let mut handles = Vec::new();
    for task in 0..32 {
        let client = Arc::clone(&client);
        handles.push(tokio::spawn(async move {
            for round in 0..8 {
                client
                    .hangup(&format!("call-{task}-{round}"))
                    .await
                    .expect("hung up");
            }
        }));
    }
    for handle in handles {
        handle.await.expect("task");
    }
    assert_eq!(transport.call_count(), 32 * 8);
}

#[tokio::test]
async fn a_custom_retry_policy_is_honoured() {
    let (transport, sleeper, client) = harness();
    for _ in 0..5 {
        transport.push_response(response(502, &[], b"bad gateway"));
    }
    let client = client.with_retry(Policy::new(5).with_base_delay(Duration::from_secs(1)));

    let error = client.hangup("c1").await.expect_err("exhausted");
    assert!(matches!(error, Error::Api { status: 502, .. }));
    assert_eq!(transport.call_count(), 5);
    assert_eq!(
        sleeper.delays(),
        [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8)
        ]
    );
}

#[test]
fn the_documented_host_and_base_path_are_exported() {
    assert_eq!(
        sipgate_flow::rest::DEFAULT_BASE_URL,
        "https://api.sipgate.com"
    );
    assert_eq!(sipgate_flow::rest::BASE_PATH, "/v2");
    assert_eq!(sipgate_flow::rest::MAX_FAX_BASE64_LEN, 28_330_000);
}

#[test]
fn sms_keeps_the_plus_prefix_the_schema_shows() {
    let sms = Sms::new("s0", "4915112345678", "hi").expect("valid");
    assert_eq!(sms.recipient(), "+4915112345678");
    assert_eq!(sms.to_json()["recipient"], "+4915112345678");
    let scheduled = Sms::new("s0", "4915112345678", "hi")
        .expect("valid")
        .with_send_at(1_546_850_272);
    assert_eq!(scheduled.to_json()["sendAt"], 1_546_850_272_i64);
}

#[test]
fn fax_refuses_an_empty_line_a_relative_name_and_bad_base64() {
    assert!(Fax::new("", "4915112345678", "a.pdf", "JVBERi0=").is_err());
    assert!(Fax::new("f0", "4915112345678", "dir/a.pdf", "JVBERi0=").is_err());
    assert!(Fax::new("f0", "4915112345678", "dir\\a.pdf", "JVBERi0=").is_err());
    assert!(Fax::new("f0", "4915112345678", "a.pdf", "not base64").is_err());
    assert!(Fax::new("f0", "4915112345678", "", "JVBERi0=").is_err());
    let fax = Fax::new("f0", "+4915112345678", "a.pdf", "JVBERi0=").expect("valid");
    assert_eq!(fax.content(), "JVBERi0=");
    assert_eq!(fax.to_json()["recipient"], "+4915112345678");
}

#[test]
fn resend_fax_omits_an_unset_line() {
    assert!(ResendFax::new("1").to_json().get("faxlineId").is_none());
    assert_eq!(
        ResendFax::new("1").with_faxline_id("f0").to_json()["faxlineId"],
        "f0"
    );
}

#[test]
fn call_builders_render_the_optional_fields() {
    let call = Call::new("4915112345678", "4921112345678")
        .expect("valid")
        .with_caller_id("+4930112345678")
        .expect("valid")
        .with_device_id("e0");
    let body = call.to_json();
    assert_eq!(body["caller"], "4915112345678");
    assert_eq!(body["callerId"], "+4930112345678");
    assert_eq!(body["deviceId"], "e0");

    assert!(Call::new("4915112345678", "4921112345678")
        .expect("valid")
        .with_caller_id("nope")
        .is_err());
}

#[test]
fn channel_call_builders_render_the_optional_fields() {
    let call = ChannelCall::new("e0", "667")
        .with_caller_id("49211")
        .with_channel_id("c0");
    let body = call.to_json();
    assert_eq!(body["callerId"], "49211");
    assert_eq!(body["channelId"], "c0");
    // An internal extension is a legal target and stays unvalidated.
    assert_eq!(body["targetNumber"], "667");
}

#[test]
fn dtmf_rejects_characters_outside_the_alphabet() {
    assert!(Dtmf::new("1234567890*#ABCD").is_ok());
    for bad in ["12x4", "12 34", "abc", "ä"] {
        assert!(Dtmf::new(bad).is_err(), "{bad:?}");
    }
    assert_eq!(Dtmf::new("1234").expect("valid").sequence(), "1234");
}

#[test]
fn announcements_must_be_absolute_http_urls() {
    assert!(Announcement::new("https://x.test/a.wav").is_ok());
    for bad in [
        "",
        "x.test/a.wav",
        "/a.wav",
        "file:///etc/passwd",
        "https://",
        "https:///path",
        "https://x.test/a b.wav",
    ] {
        assert!(Announcement::new(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn recording_renders_start_stop_and_the_announcement_flag() {
    assert!(Recording::start().is_starting());
    assert!(!Recording::stop().is_starting());
    assert_eq!(Recording::stop().to_json()["value"], false);
    let silent = Recording::start().with_announcement(false);
    assert_eq!(silent.to_json()["announcement"], false);
    assert!(Recording::start().to_json().get("announcement").is_none());
}

#[test]
fn transfer_request_supports_blind_attended_and_a_caller_id() {
    let blind = TransferRequest::blind("4915112345678").expect("valid");
    assert_eq!(blind.to_json()["attended"], false);
    let attended = TransferRequest::attended("4915112345678").expect("valid");
    assert_eq!(attended.to_json()["attended"], true);
    let with_id = TransferRequest::blind("4915112345678")
        .expect("valid")
        .with_caller_id("4921112345678")
        .expect("valid");
    assert_eq!(with_id.to_json()["callerId"], "+4921112345678");
    assert!(TransferRequest::blind("no").is_err());
    assert!(TransferRequest::blind("49")
        .expect("valid")
        .with_caller_id("no")
        .is_err());
}

#[test]
fn recording_session_renders_every_field_it_has() {
    let request = RecordingSession::new()
        .with_device_id("e0")
        .with_endpoint("MAIN")
        .with_target_id("v0");
    assert_eq!(
        request.to_json(),
        serde_json::json!({"deviceId": "e0", "endpoint": "MAIN", "targetId": "v0"})
    );
    assert_eq!(RecordingSession::new().to_json(), serde_json::json!({}));
}

#[test]
fn voicemail_playback_exposes_both_fields() {
    let request = PlayVoicemail::new("1000171", "e0");
    assert_eq!(request.to_json()["datadId"], "1000171");
    assert_eq!(request.to_json()["deviceId"], "e0");
}

#[tokio::test]
async fn an_unexpected_call_list_envelope_is_a_typed_error() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({"data": "nope"})));
    let client = RestClient::new(transport, static_auth()).with_sleeper(RecordingSleeper::new());
    let error = client.calls().await.expect_err("wrong shape");
    assert!(matches!(error, Error::Json { .. }));
}

#[tokio::test]
async fn a_call_without_participants_still_parses() {
    let transport = MockTransport::new();
    transport.push_response(json_response(&serde_json::json!({
        "data": [{
            "callId": "c1", "hold": true, "muted": false, "recording": false,
            "participants": [], "future": {"x": 1}
        }]
    })));
    let client = RestClient::new(transport, static_auth()).with_sleeper(RecordingSleeper::new());
    let calls = client.calls().await.expect("listed");
    assert_eq!(calls[0].call_id, "c1");
    assert!(calls[0].hold);
    assert_eq!(calls[0].participants.len(), 0);
}
