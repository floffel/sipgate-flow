//! Webhook authentication: fail closed, constant time, and picky about the
//! content type but not about how a framework spells the header.

use sipgate_flow::webhook::{is_json_content_type, DEFAULT_MAX_BODY_BYTES};
use sipgate_flow::{Error, EventPayload, WebhookVerifier};

const BODY: &[u8] = include_bytes!("fixtures/flow/session_start.json");

#[test]
fn an_empty_secret_is_refused_at_construction() {
    assert!(matches!(WebhookVerifier::new(""), Err(Error::EmptySecret)));
    assert!(matches!(
        WebhookVerifier::new(Vec::new()),
        Err(Error::EmptySecret)
    ));
    assert!(WebhookVerifier::new("x").is_ok());
}

#[test]
fn the_debug_output_never_contains_the_secret() {
    let verifier = WebhookVerifier::new("super-secret-value").expect("valid");
    let rendered = format!("{verifier:?}");
    assert!(!rendered.contains("super-secret-value"));
    assert!(rendered.contains("WebhookVerifier"));
}

#[test]
fn a_missing_empty_or_wrong_secret_fails_closed() {
    let verifier = WebhookVerifier::new("s3cret").expect("valid");
    assert!(matches!(verifier.verify(None), Err(Error::MissingSecret)));
    assert!(matches!(
        verifier.verify(Some("")),
        Err(Error::MissingSecret)
    ));
    for wrong in ["s3cre", "s3crets", "S3CRET", "s3cret ", " s3cret"] {
        assert!(
            matches!(verifier.verify(Some(wrong)), Err(Error::SecretMismatch)),
            "{wrong:?} should not verify"
        );
    }
    assert!(verifier.verify(Some("s3cret")).is_ok());
}

#[test]
fn json_content_types_are_accepted_with_parameters_and_casing() {
    for value in [
        "application/json",
        "Application/JSON; charset=utf-8",
        "application/json;charset=UTF-8",
        "application/problem+json",
        " application/json ",
    ] {
        assert!(is_json_content_type(value), "{value:?}");
    }
    for value in [
        "application/x-www-form-urlencoded",
        "text/plain",
        "application/xml",
        "",
    ] {
        assert!(!is_json_content_type(value), "{value:?}");
    }
}

#[test]
fn a_form_encoded_request_is_recognised_as_the_wrong_api() {
    let verifier = WebhookVerifier::new("s").expect("valid");
    let error = verifier
        .verify_and_parse(
            Some("s"),
            Some("application/x-www-form-urlencoded"),
            b"event=newCall&callId=1",
        )
        .expect_err("Push API payload");
    assert!(matches!(
        error,
        Error::UnsupportedContentType { ref content_type } if content_type.contains("form-urlencoded")
    ));
}

#[test]
fn a_missing_content_type_is_tolerated_but_the_secret_is_not() {
    let verifier = WebhookVerifier::new("s").expect("valid");
    assert!(verifier.verify_and_parse(Some("s"), None, BODY).is_ok());
    assert!(verifier.verify_and_parse(None, None, BODY).is_err());
}

#[test]
fn verification_happens_before_parsing() {
    let verifier = WebhookVerifier::new("s").expect("valid");
    let error = verifier
        .verify_and_parse(Some("wrong"), Some("application/json"), b"not json")
        .expect_err("bad secret must win");
    assert!(matches!(error, Error::SecretMismatch));
}

#[test]
fn oversized_bodies_are_rejected_before_parsing() {
    let verifier = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(64);
    assert_eq!(verifier.max_body_bytes(), 64);
    let error = verifier
        .verify_and_parse(Some("s"), Some("application/json"), BODY)
        .expect_err("fixture is larger than 64 bytes");
    assert!(matches!(error, Error::BodyTooLarge { limit: 64, .. }));
}

#[test]
fn the_default_limit_is_one_mebibyte() {
    let verifier = WebhookVerifier::new("s").expect("valid");
    assert_eq!(verifier.max_body_bytes(), DEFAULT_MAX_BODY_BYTES);
    assert_eq!(DEFAULT_MAX_BODY_BYTES, 1024 * 1024);
}

#[test]
fn a_valid_request_yields_a_typed_event() {
    let verifier = WebhookVerifier::new("s").expect("valid");
    let event = verifier
        .verify_and_parse(Some("s"), Some("application/json; charset=utf-8"), BODY)
        .expect("valid");
    assert!(matches!(event.payload(), EventPayload::SessionStart { .. }));
    assert_eq!(
        event.session_id(),
        Some("550e8400-e29b-41d4-a716-446655440000")
    );
}

#[test]
fn the_header_names_the_documentation_uses_are_exported() {
    assert_eq!(sipgate_flow::webhook::SECRET_HEADER, "x-api-token");
    assert_eq!(sipgate_flow::webhook::SECRET_HEADER_LEGACY, "x-api-key");
}
