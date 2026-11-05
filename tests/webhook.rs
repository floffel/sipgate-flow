//! Webhook authentication: fail closed, constant time, and picky about the
//! content type but not about how a framework spells the header.

use std::io::{Cursor, Read};

use proptest::prelude::*;
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
        "application/json; charset=utf-8",
        "Application/JSON; charset=utf-8",
        "application/json;charset=UTF-8",
        "application/vnd.x+json",
        "application/problem+json",
        " application/json ",
    ] {
        assert!(is_json_content_type(value), "{value:?}");
    }
    for value in [
        "application/x-www-form-urlencoded",
        "text/plain",
        "application/xml",
        "not+json",
        "not a media type",
        "",
    ] {
        assert!(!is_json_content_type(value), "{value:?}");
    }
}

#[test]
fn json_suffixes_without_a_media_type_are_not_accepted() {
    for value in ["+json", "foo+json", "json", "application+json"] {
        assert!(!is_json_content_type(value), "{value:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn json_content_type_detection_is_ascii_case_idempotent(value in ".{0,128}") {
        let upper = value.to_ascii_uppercase();
        let lower = value.to_ascii_lowercase();
        prop_assert_eq!(
            is_json_content_type(&value),
            is_json_content_type(&upper),
            "uppercasing {:?} changed the result",
            value
        );
        prop_assert_eq!(
            is_json_content_type(&value),
            is_json_content_type(&lower),
            "lowercasing {:?} changed the result",
            value
        );
    }

    #[test]
    fn application_json_with_arbitrary_parameters_is_json(
        name in "[A-Za-z0-9_.-]{1,24}",
        value in "[A-Za-z0-9_.-]{1,48}",
    ) {
        let content_type = format!("application/json; {name}={value}");
        prop_assert!(
            is_json_content_type(&content_type),
            "{content_type:?} should be JSON"
        );
    }

    #[test]
    fn strings_without_a_slash_are_not_json(content_type in "[^/]{0,96}") {
        prop_assert!(
            !is_json_content_type(&content_type),
            "{content_type:?} has no media type slash"
        );
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
        Error::UnsupportedContentType { ref content_type, .. } if content_type.contains("form-urlencoded")
    ));
}

#[test]
fn a_missing_content_type_is_tolerated_but_the_secret_is_not() {
    let verifier = WebhookVerifier::new("s").expect("valid");
    assert!(verifier.verify_and_parse(Some("s"), None, BODY).is_ok());
    assert!(verifier.verify_and_parse(None, None, BODY).is_err());
}

#[test]
fn empty_or_whitespace_content_type_is_treated_as_absent() {
    let verifier = WebhookVerifier::new("s").expect("valid");
    for content_type in [None, Some(""), Some("   ")] {
        assert!(
            verifier
                .verify_and_parse(Some("s"), content_type, BODY)
                .is_ok(),
            "{content_type:?}"
        );
    }
    for content_type in [
        Some("application/json"),
        Some("application/problem+json; charset=utf-8"),
    ] {
        assert!(
            verifier
                .verify_and_parse(Some("s"), content_type, BODY)
                .is_ok(),
            "{content_type:?}"
        );
    }
    let error = verifier
        .verify_and_parse(Some("s"), Some("text/plain"), BODY)
        .expect_err("non-JSON content type must be rejected");
    assert!(matches!(
        error,
        Error::UnsupportedContentType { ref content_type, .. } if content_type == "text/plain"
    ));
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
fn a_wrong_secret_is_refused_before_content_type_and_size_checks() {
    let verifier = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(4)
        .expect("valid limit");
    let oversized = b"12345";
    let error = verifier
        .verify_and_parse(Some("wrong"), Some("text/plain"), oversized)
        .expect_err("the secret check must run first");
    assert!(matches!(error, Error::SecretMismatch));
}

#[test]
fn oversized_bodies_are_rejected_before_parsing() {
    let verifier = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(64)
        .expect("valid limit");
    assert_eq!(verifier.max_body_bytes(), 64);
    let error = verifier
        .verify_and_parse(Some("s"), Some("application/json"), BODY)
        .expect_err("fixture is larger than 64 bytes");
    assert!(matches!(error, Error::BodyTooLarge { limit: 64, .. }));
}

#[test]
fn buffered_body_limit_accepts_exactly_max_and_rejects_max_plus_one() {
    let limit = BODY.len();
    let verifier = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(limit)
        .expect("valid limit");

    let event = verifier
        .verify_and_parse(Some("s"), Some("application/json"), BODY)
        .expect("exactly the limit is allowed");
    assert!(matches!(event.payload(), EventPayload::SessionStart { .. }));

    let mut oversized = BODY.to_vec();
    oversized.push(b'x');
    let error = verifier
        .verify_and_parse(Some("s"), Some("application/json"), &oversized)
        .expect_err("one byte past the limit must be refused");
    assert!(matches!(
        error,
        Error::BodyTooLarge {
            size,
            limit: refused_limit
        } if size == limit + 1 && refused_limit == limit
    ));
}

#[test]
fn verify_reader_accepts_exactly_the_limit() {
    let verifier = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(BODY.len())
        .expect("valid limit");
    let event = verifier
        .verify_reader(Some("s"), Some("application/json"), Cursor::new(BODY))
        .expect("exactly the limit is allowed");
    assert!(matches!(event.payload(), EventPayload::SessionStart { .. }));
}

#[test]
fn verify_reader_rejects_limit_plus_one_immediately() {
    let limit = BODY.len();
    let verifier = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(limit)
        .expect("valid limit");
    let mut oversized = BODY.to_vec();
    oversized.extend_from_slice(b"x");

    let error = verifier
        .verify_reader(
            Some("s"),
            Some("application/json"),
            OneChunkThenPanic::new(oversized),
        )
        .expect_err("one byte past the limit must be refused");
    assert!(matches!(
        error,
        Error::BodyTooLarge {
            size,
            limit: refused_limit
        } if size == limit + 1 && refused_limit == limit
    ));
}

#[test]
fn verify_reader_rejects_limit_plus_one_without_draining_the_reader() {
    let limit = 4;
    let verifier = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(limit)
        .expect("valid limit");

    let error = verifier
        .verify_reader(
            Some("s"),
            Some("application/json"),
            OneChunkThenPanic::new(b"12345".to_vec()),
        )
        .expect_err("one byte past the limit must be refused");
    assert!(matches!(error, Error::BodyTooLarge { size: 5, limit: 4 }));
}

#[test]
fn verify_reader_maps_reader_failures_to_body_read() {
    let verifier = WebhookVerifier::new("s").expect("valid");
    let error = verifier
        .verify_reader(Some("s"), Some("application/json"), FailingReader)
        .expect_err("reader failure must be reported");
    assert!(matches!(error, Error::BodyRead { .. }));
    assert!(std::error::Error::source(&error).is_some());
}

struct OneChunkThenPanic {
    body: Vec<u8>,
    offset: usize,
}

impl OneChunkThenPanic {
    fn new(body: Vec<u8>) -> Self {
        Self { body, offset: 0 }
    }
}

impl Read for OneChunkThenPanic {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        assert!(
            self.offset < self.body.len(),
            "reader was drained after the limit was already exceeded"
        );
        let remaining = &self.body[self.offset..];
        let read = remaining.len().min(buffer.len());
        buffer[..read].copy_from_slice(&remaining[..read]);
        self.offset += read;
        Ok(read)
    }
}

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("broken body stream"))
    }
}

#[test]
fn the_default_limit_is_one_mebibyte() {
    let verifier = WebhookVerifier::new("s").expect("valid");
    assert_eq!(verifier.max_body_bytes(), DEFAULT_MAX_BODY_BYTES);
    assert_eq!(DEFAULT_MAX_BODY_BYTES, 1024 * 1024);
}

#[test]
fn max_body_bytes_accepts_the_boundaries_and_rejects_outside_them() {
    let smallest = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(1)
        .expect("one byte is the smallest valid body limit");
    assert_eq!(smallest.max_body_bytes(), 1);

    let midpoint = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(DEFAULT_MAX_BODY_BYTES / 2)
        .expect("a mid-range limit is valid");
    assert_eq!(midpoint.max_body_bytes(), DEFAULT_MAX_BODY_BYTES / 2);

    let largest = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(DEFAULT_MAX_BODY_BYTES)
        .expect("the default is also the documented maximum");
    assert_eq!(largest.max_body_bytes(), DEFAULT_MAX_BODY_BYTES);

    let zero = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(0)
        .expect_err("zero would reject every non-empty body");
    assert!(matches!(
        zero,
        Error::Validation {
            field: "max_body_bytes",
            ref message,
        } if message.contains("between 1 and")
    ));

    let too_large = WebhookVerifier::new("s")
        .expect("valid")
        .with_max_body_bytes(DEFAULT_MAX_BODY_BYTES + 1)
        .expect_err("one byte above the maximum is rejected");
    assert!(matches!(
        too_large,
        Error::Validation {
            field: "max_body_bytes",
            ..
        }
    ));
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
