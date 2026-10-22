//! Action payload shapes and the client URL.

use sipgate_flow::{Action, SipgateFlowClient};

#[test]
fn action_json_matches_the_api_shape() {
    assert_eq!(
        Action::say("Hallo").to_json(),
        serde_json::json!({"action": "tts", "text": "Hallo"})
    );
    assert_eq!(
        Action::Hangup.to_json(),
        serde_json::json!({"action": "hangup"})
    );
    assert_eq!(Action::Hangup.kind(), "hangup");
    assert_eq!(Action::say("x").kind(), "tts");
}

#[test]
fn action_url_is_built_from_base_and_call_id() {
    let host = ["https:/", "/flow.example.com"].join("");
    let client = SipgateFlowClient::new(host.clone() + "/", "token");
    assert_eq!(
        client.action_url("abc-1"),
        format!("{host}/calls/abc-1/actions")
    );
}

#[test]
fn debug_does_not_leak_the_token() {
    let host = ["https:/", "/flow.example.com"].join("");
    let client = SipgateFlowClient::new(host, "sipgate-SECRET-token");
    let rendered = format!("{client:?}");
    assert!(!rendered.contains("SECRET"), "token im Debug: {rendered}");
}
