//! No credential survives a `{:?}`: every rendering of a [`Security`] or a
//! [`Request`] replaces the secret with `<redacted>`.
//!
//! The regression these pin: `Security` and `Request` derived `Debug`, so
//! `tracing::debug!("{request:?}")` wrote the bearer token or the `Basic`
//! password into the log - and for the `OAuth2` token call the `client_secret`
//! travelled inside the form body, where the derived render printed it too.

use proptest::prelude::*;
use serde_json::json;
use sipgate_flow::transport::{Method, Request, RequestBody, Security};

/// A value that must never appear in any rendering.
const SECRET: &str = "s3cr3t-B7-cr3dential";

#[test]
fn a_bearer_token_never_appears_in_debug() {
    let token = Security::Bearer(SECRET);
    let rendered = format!("{token:?}");
    assert!(!rendered.contains(SECRET), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(
        rendered.starts_with("Bearer"),
        "the scheme stays readable: {rendered}"
    );
}

#[test]
fn a_basic_credential_keeps_its_id_and_hides_its_password() {
    let basic = Security::Basic {
        username: "token-FQ1V12",
        password: SECRET,
    };
    let rendered = format!("{basic:?}");
    assert!(!rendered.contains(SECRET), "{rendered}");
    assert!(
        rendered.contains("token-FQ1V12"),
        "the user half identifies the account and is not the secret: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[test]
fn an_unauthenticated_request_says_so() {
    assert_eq!(format!("{:?}", Security::None), "None");
    let request = Request::empty(Method::Get, "https://x.test/a", Security::None);
    let rendered = format!("{request:?}");
    assert!(rendered.contains("None"), "{rendered}");
    assert!(
        !rendered.contains("redacted"),
        "nothing to redact: {rendered}"
    );
}

/// The `OAuth2` token request as [`ClientCredentials::token_request_body`] shapes
/// it: the secret sits in a form field, not in a header.
fn token_form() -> Vec<(String, String)> {
    vec![
        ("grant_type".to_string(), "client_credentials".to_string()),
        ("client_id".to_string(), "token-FQ1V12".to_string()),
        ("client_secret".to_string(), SECRET.to_string()),
        ("scope".to_string(), "sessions:write".to_string()),
    ]
}

#[test]
fn a_form_body_hides_the_client_secret_and_keeps_the_rest_readable() {
    let body = token_form();
    let request = Request::form(
        Method::Post,
        "https://login.test/token",
        Security::None,
        &body,
    );
    let rendered = format!("{request:?}");
    assert!(!rendered.contains(SECRET), "{rendered}");
    assert!(rendered.contains("client_credentials"), "{rendered}");
    assert!(rendered.contains("sessions:write"), "{rendered}");
    assert!(
        rendered.contains("token-FQ1V12"),
        "the id is not a secret: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(rendered.contains("login.test"), "{rendered}");

    // The body renders the same way when it is logged on its own.
    let standalone = format!("{:?}", RequestBody::Form(&body));
    assert!(!standalone.contains(SECRET), "{standalone}");
    assert!(standalone.contains("<redacted>"), "{standalone}");
}

#[test]
fn a_json_body_hides_nested_credentials_and_keeps_the_payload() {
    let body = json!({
        "type": "speak",
        "text": "Hallo",
        "auth": {"username": "id", "password": SECRET},
        "sessions": [{"refresh_token": SECRET}, {"text": "ok"}],
    });
    let request = Request::json(
        Method::Put,
        "https://x.test/a",
        Security::Bearer(SECRET),
        &body,
    );
    let rendered = format!("{request:?}");
    assert!(!rendered.contains(SECRET), "{rendered}");
    assert!(
        rendered.contains("Hallo"),
        "the payload stays readable: {rendered}"
    );
    assert!(rendered.contains("\"ok\""), "{rendered}");
}

#[test]
fn every_credential_shaped_field_name_is_redacted() {
    // Case does not matter and the provider spells the same secret differently.
    for name in [
        "password",
        "Password",
        "client_secret",
        "CLIENT_SECRET",
        "refresh_token",
        "X-API-TOKEN",
        "token",
        "client_assertion",
        "api_key",
        "apikey",
        "hotkey",
    ] {
        let body = [(name.to_string(), SECRET.to_string())];
        let rendered = format!("{:?}", RequestBody::Form(&body));
        assert!(
            !rendered.contains(SECRET),
            "field {name} leaked: {rendered}"
        );
        let json_body = json!({name: SECRET});
        let rendered = format!("{:?}", RequestBody::Json(&json_body));
        assert!(
            !rendered.contains(SECRET),
            "json field {name} leaked: {rendered}"
        );
    }

    // The other side of the boundary: an ordinary field keeps its value, or the
    // rendering would be useless for debugging.
    for name in [
        "grant_type",
        "client_id",
        "scope",
        "text",
        "username",
        "sessionId",
    ] {
        let body = [(name.to_string(), SECRET.to_string())];
        let rendered = format!("{:?}", RequestBody::Form(&body));
        assert!(
            rendered.contains(SECRET),
            "field {name} should stay visible: {rendered}"
        );
    }
}

#[test]
fn an_empty_secret_renders_as_the_empty_string() {
    // Nothing to leak, and seeing the empty string tells the caller the token
    // was never configured - the boundary just below a one-character secret.
    assert_eq!(format!("{:?}", Security::Bearer("")), "Bearer(\"\")");
    assert_eq!(
        format!(
            "{:?}",
            Security::Basic {
                username: "",
                password: ""
            }
        ),
        "Basic { username: \"\", password: \"\" }"
    );
    assert_eq!(
        format!("{:?}", Security::Bearer("x")),
        "Bearer(\"<redacted>\")",
        "one character is already a secret"
    );
}

#[test]
fn a_secret_that_looks_like_markup_cannot_break_out_of_the_rendering() {
    // Quotes, braces, control characters and unicode: the secret is replaced,
    // not escaped, so nothing of it reaches the output.
    for secret in [
        "quote\"and\\brace}",
        "line\nbreak",
        "nul\0byte",
        "unicode-\u{1F512}-secret",
        "<redacted>",
    ] {
        let rendered = format!("{:?}", Security::Bearer(secret));
        if secret == "<redacted>" {
            // The placeholder itself is the one value that cannot be told apart;
            // it leaks nothing either way.
            assert_eq!(rendered, "Bearer(\"<redacted>\")");
        } else {
            assert!(
                !rendered.contains(secret),
                "{secret:?} survived: {rendered}"
            );
        }
    }
}

#[test]
fn a_request_with_a_basic_credential_hides_the_password_at_the_request_level() {
    let request = Request::empty(
        Method::Get,
        "https://api.sipgate.com/v2/account",
        Security::Basic {
            username: "token-FQ1V12",
            password: SECRET,
        },
    );
    let rendered = format!("{request:?}");
    assert!(!rendered.contains(SECRET), "{rendered}");
    assert!(rendered.contains("api.sipgate.com"), "{rendered}");
    assert!(rendered.contains("method: Get"), "{rendered}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// No arbitrary bearer token survives a rendering, whatever it contains.
    #[test]
    fn no_bearer_token_survives_debug(token in "[A-Za-z0-9_.~+/-]{8,96}") {
        let rendered = format!("{:?}", Security::Bearer(&token));
        prop_assert!(!rendered.contains(&token), "{}", rendered);
        prop_assert!(rendered.contains("<redacted>"), "{}", rendered);
    }

    /// The same for a secret that travels in a form field, as the `OAuth2`
    /// client secret does.
    #[test]
    fn no_form_secret_survives_debug(secret in "[A-Za-z0-9_.~+/-]{8,96}") {
        let body = vec![("client_secret".to_string(), secret.clone())];
        let rendered = format!("{:?}", RequestBody::Form(&body));
        prop_assert!(!rendered.contains(&secret), "{}", rendered);

        let request = Request::form(Method::Post, "https://login.test/token", Security::None, &body);
        let rendered = format!("{request:?}");
        prop_assert!(!rendered.contains(&secret), "{}", rendered);
    }
}
