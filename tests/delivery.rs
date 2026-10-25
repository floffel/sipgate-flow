//! The delivery contract: which failures may be repeated automatically and
//! which ones have to be reconciled by the caller.
//!
//! sipgate documents no idempotency key, so the only thing that separates an
//! at-least-once request from a duplicated SMS is the classification here: a
//! `POST` that may have been executed is never repeated, while reads and
//! state-setters (`GET`, `PUT`, `DELETE`) and every `429` are.

mod common;

use std::time::Duration;

use common::{no_content, response, static_auth, MockTransport, RecordingSleeper};
use sipgate_flow::rest::Sms;
use sipgate_flow::{classify, Error, Method, RestClient, RetryOutcome, RetryPolicy, StaticToken};

type TestClient = RestClient<MockTransport, StaticToken, RecordingSleeper>;

fn harness() -> (MockTransport, RecordingSleeper, TestClient) {
    let transport = MockTransport::new();
    let sleeper = RecordingSleeper::new();
    let client = RestClient::new(transport.clone(), static_auth()).with_sleeper(sleeper.clone());
    (transport, sleeper, client)
}

async fn send_sms(client: &TestClient) -> sipgate_flow::Result<serde_json::Value> {
    let sms = Sms::new("s0", "4915112345678", "Ihr Code: 4242")?;
    client.send_sms(&sms).await
}

#[tokio::test]
async fn a_500_after_an_sms_post_is_ambiguous_and_sent_once() {
    let (transport, sleeper, client) = harness();
    for _ in 0..5 {
        transport.push_response(response(500, &[], b"upstream died"));
    }

    let error = send_sms(&client).await.expect_err("500");

    assert!(error.is_ambiguous(), "{error:?}");
    assert!(!error.is_retryable(), "a retry would send a second SMS");
    assert_eq!(error.status(), Some(500));
    assert_eq!(
        error.retry_after(),
        None,
        "no wait hint for a terminal call"
    );
    let rendered = error.to_string();
    assert!(
        rendered.contains("may already have been applied"),
        "the message must say the SMS may exist: {rendered}"
    );
    assert!(
        rendered.contains("POST"),
        "the message must name the method that was not repeated: {rendered}"
    );
    assert_eq!(
        transport.call_count(),
        1,
        "exactly one SMS left the process"
    );
    assert_eq!(sleeper.delays(), Vec::<Duration>::new());
}

#[tokio::test]
async fn every_5xx_after_a_post_is_ambiguous() {
    for status in [500_u16, 502, 503, 504, 599] {
        let (transport, sleeper, client) = harness();
        transport.push_response(response(status, &[], b"boom"));
        transport.push_response(no_content());

        let error = send_sms(&client).await.expect_err("5xx");
        assert!(error.is_ambiguous(), "{status}: {error:?}");
        assert_eq!(error.status(), Some(status));
        assert_eq!(transport.call_count(), 1, "{status} was retried");
        assert_eq!(sleeper.delays(), Vec::<Duration>::new(), "{status}");
    }
}

#[tokio::test]
async fn a_429_after_a_post_is_retried_because_nothing_was_processed() {
    let (transport, sleeper, client) = harness();
    transport.push_response(response(429, &[("Retry-After", "2")], b"slow down"));
    transport.push_response(no_content());

    send_sms(&client).await.expect("second attempt wins");
    assert_eq!(transport.call_count(), 2);
    assert_eq!(sleeper.delays(), [Duration::from_secs(2)]);
}

#[tokio::test]
async fn a_failure_before_the_write_is_retried_for_a_post() {
    // DNS/TCP/TLS happen before a byte of the request reaches the server, so
    // the SMS provably was not sent - a retry cannot duplicate it.
    let (transport, _, client) = harness();
    transport.push_transient_failure("connect: dns failure");
    transport.push_response(no_content());

    send_sms(&client).await.expect("retried");
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn a_5xx_after_a_get_is_retried() {
    let (transport, sleeper, client) = harness();
    transport.push_response(response(503, &[], b"maintenance"));
    transport.push_response(common::json_response(&serde_json::json!({"data": []})));

    let calls = client.calls().await.expect("second attempt");
    assert_eq!(calls.len(), 0, "the list is empty, not an error");
    assert_eq!(transport.call_count(), 2);
    assert_eq!(sleeper.delays(), [Duration::from_millis(250)]);
}

#[tokio::test]
async fn a_5xx_after_a_put_is_retried_because_setting_the_same_state_twice_is_one_state() {
    let (transport, _, client) = harness();
    transport.push_response(response(500, &[], b"boom"));
    transport.push_response(no_content());

    client.set_hold("c1", true).await.expect("retried");
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn the_opt_out_still_holds_for_a_read() {
    // `RetryPolicy::none` disables even the safe repeats.
    let transport = MockTransport::new();
    transport.push_response(response(503, &[], b"maintenance"));
    let client = RestClient::new(transport.clone(), static_auth())
        .with_sleeper(RecordingSleeper::new())
        .with_retry(RetryPolicy::none());

    assert!(client.calls().await.is_err());
    assert_eq!(transport.call_count(), 1);
}

#[test]
fn the_classification_matrix_is_pinned() {
    // One table, every method, the boundaries on both sides of each rule.
    let expected = [
        // (method, status, outcome)
        (Method::Post, 429, RetryOutcome::Retry),
        (Method::Post, 499, RetryOutcome::Terminal),
        (Method::Post, 500, RetryOutcome::Ambiguous),
        (Method::Post, 599, RetryOutcome::Ambiguous),
        (Method::Post, 400, RetryOutcome::Terminal),
        (Method::Post, 200, RetryOutcome::Terminal),
        (Method::Get, 501, RetryOutcome::Retry),
        (Method::Put, 502, RetryOutcome::Retry),
        (Method::Delete, 503, RetryOutcome::Retry),
        (Method::Get, 429, RetryOutcome::Retry),
        (Method::Delete, 404, RetryOutcome::Terminal),
        (Method::Put, 401, RetryOutcome::Terminal),
    ];
    for (method, status, outcome) in expected {
        assert_eq!(
            classify(method, status),
            outcome,
            "{} {status}",
            method.as_str()
        );
    }

    // No non-idempotent request is ever classified as retryable after a 5xx.
    for status in 500..=599 {
        for method in [Method::Get, Method::Put, Method::Delete, Method::Post] {
            let retry = classify(method, status) == RetryOutcome::Retry;
            assert_eq!(
                retry,
                method.is_idempotent(),
                "{} {status}",
                method.as_str()
            );
        }
    }
}

#[test]
fn an_ambiguous_error_is_never_retryable_whatever_it_carries() {
    for status in [None, Some(500_u16), Some(599)] {
        let error = Error::ambiguous(status, "lost the response");
        assert!(!error.is_retryable());
        assert!(error.is_ambiguous());
        assert_eq!(error.status(), status);
        assert_eq!(error.retry_after(), None);
    }
}

#[tokio::test]
async fn a_multibyte_error_body_is_cut_at_a_character_boundary() {
    // `truncate_body` stops at 512 bytes, but only on a UTF-8 boundary: cutting
    // a 3-byte character in half would panic in `format!` on a real 400.
    let (transport, _, client) = harness();
    let body = "ä".repeat(1_000); // 2000 bytes, every char 2 bytes
    transport.push_response(response(400, &[], body.as_bytes()));

    let error = send_sms(&client).await.expect_err("400");
    let rendered = error.to_string();
    assert!(
        rendered.len() < 1000,
        "the body is truncated: {}",
        rendered.len()
    );
    assert!(rendered.contains('ä'), "the cut keeps whole characters");
}
