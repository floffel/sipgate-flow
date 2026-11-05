//! Field validation shared by the Flow actions and the REST requests.
//!
//! These are the checks that belong on the way *out*: a value that would be
//! rejected by sipgate, or that could escape its slot (a `/` in a session id
//! that is interpolated into a URL path, a newline in a log line), is refused
//! before the request exists. Parsing stays tolerant; sending does not.

use crate::error::{Error, Result};
use url::Url;

/// Longest session id accepted: the documented value is a UUID (36 chars), and
/// the cap keeps a hostile string out of headers and log lines.
pub(crate) const MAX_SESSION_ID: usize = 200;

/// Shortest E.164 number accepted: country code plus subscriber number.
pub(crate) const MIN_PHONE_DIGITS: usize = 7;

/// Longest E.164 number: 15 digits, per ITU-T E.164.
pub(crate) const MAX_PHONE_DIGITS: usize = 15;

/// Longest BCP-47 tag accepted: the registry caps a tag at 35 characters.
pub(crate) const MAX_LANGUAGE_TAG: usize = 35;

/// Longest billing device suffix accepted.
///
/// sipgate documents the field as a short device suffix (for example `e2`)
/// with the account's `masterSipId` prepended automatically, so it never needs
/// to be long. The cap keeps an unbounded caller string out of the JSON body.
pub(crate) const MAX_BILLING_DEVICE: usize = 8;

/// Largest single Flow action string accepted by this crate.
///
/// sipgate does not publish a body-size limit for webhook responses, but the
/// response is the same JSON document this crate receives under the default
/// webhook body ceiling. Keeping one action field below that bound prevents a
/// caller bug from turning a single string into a multi-megabyte allocation.
pub(crate) const MAX_FLOW_ACTION_FIELD_BYTES: usize = 1024 * 1024;

/// Largest SMS body accepted by an action or REST request.
///
/// The Flow documentation says there is no hard service-side length limit for
/// SMS bodies and bills long texts by segment. This crate still refuses a body
/// above the same 1 MiB ceiling used for other action fields, so a caller
/// mistake cannot allocate and send an unbounded payload.
pub(crate) const MAX_SMS_MESSAGE_BYTES: usize = MAX_FLOW_ACTION_FIELD_BYTES;

/// Largest byte length that can represent the documented 200-character
/// vocabulary entry limit in UTF-8 (200 chars * 4 bytes). The exact character
/// limit is still enforced separately below.
pub(crate) const MAX_CUSTOM_VOCABULARY_ENTRY_BYTES: usize = 200 * 4;

/// Largest base64 string accepted for Flow audio.
///
/// This is the encoded length of [`crate::base64::MAX_DECODED_BYTES`], the same
/// ceiling used by [`crate::base64::decode`] and [`crate::base64::is_valid`].
pub(crate) const MAX_AUDIO_BASE64_CHARS: usize =
    match crate::base64::encoded_len(crate::base64::MAX_DECODED_BYTES) {
        Some(len) => len,
        None => usize::MAX,
    };

/// Generic ceiling for request fields without a smaller documented limit.
///
/// This keeps the helper bounded everywhere while preserving the service's
/// permissive acceptance for fields such as device ids, filenames and URLs:
/// only multi-megabyte values are refused.
pub(crate) const MAX_REST_FIELD_BYTES: usize = MAX_FLOW_ACTION_FIELD_BYTES;

/// Rejects empty or over-long string fields.
///
/// `max_bytes` is the field-specific ceiling. The caller supplies it at every
/// call site so a later field cannot accidentally inherit an unbounded helper.
pub(crate) fn non_empty(field: &'static str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() {
        return Err(Error::validation(field, "must not be empty"));
    }
    if value.len() > max_bytes {
        return Err(Error::validation(
            field,
            format!("must be at most {max_bytes} bytes"),
        ));
    }
    Ok(())
}

/// Validates the billing device suffix used by the outbound-call request.
///
/// The documented value is a short device id such as `e2` or `s0`: an ASCII
/// lowercase letter followed by lowercase letters or digits, at most
/// [`MAX_BILLING_DEVICE`] bytes. Enforcing the alphabet and the cap here keeps
/// control characters, whitespace and unbounded unicode out of the JSON body.
/// This is intentionally scoped to the field; the general [`non_empty`]
/// contract is tracked separately.
pub(crate) fn billing_device(field: &'static str, value: &str) -> Result<()> {
    non_empty(field, value, MAX_BILLING_DEVICE)?;
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase()) {
        return Err(Error::validation(
            field,
            "must start with an ASCII lowercase letter",
        ));
    }
    if !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()) {
        return Err(Error::validation(
            field,
            "must contain only ASCII lowercase letters or digits",
        ));
    }
    Ok(())
}

/// Validates an identifier that ends up in a URL path or a log line.
///
/// The accepted alphabet is exactly ASCII `A-Z`, `a-z`, `0-9`, `.`, `_`, `~`,
/// `:`, `@` and `-`. A bare `.` or `..` segment is refused even though its
/// characters are otherwise allowed.
pub(crate) fn path_segment(field: &'static str, value: &str) -> Result<()> {
    non_empty(field, value, MAX_SESSION_ID)?;
    if value == "." || value == ".." {
        return Err(Error::validation(field, "must not be . or .."));
    }
    if !value.bytes().all(is_path_segment_byte) {
        return Err(Error::validation(
            field,
            "must contain only ASCII letters, digits, or . _ ~ : @ -",
        ));
    }
    Ok(())
}

fn is_path_segment_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b':' | b'@' | b'-')
}

/// Validates the documented AI Flow path parameter: a UUID or slug.
///
/// The accepted alphabet is exactly ASCII `A-Z`, `a-z`, `0-9`, `_` and `-`.
/// This is narrower than [`path_segment`] because the endpoint documents a
/// UUID/slug, not an arbitrary URL path segment.
pub(crate) fn ai_flow_id(field: &'static str, value: &str) -> Result<()> {
    path_segment(field, value)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Error::validation(
            field,
            "must contain only ASCII letters, digits, _ or -",
        ));
    }
    Ok(())
}

/// Validates and normalises a phone number: an optional leading `+` followed by
/// 7..=15 digits whose first digit is 1-9. Returns the digits, because
/// sipgate's Flow actions expect E.164 *without* the `+` (it strips one if
/// sent).
pub(crate) fn phone(field: &'static str, value: &str) -> Result<String> {
    let digits = value.strip_prefix('+').unwrap_or(value);
    if digits.is_empty() {
        return Err(Error::validation(field, "must not be empty"));
    }
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::validation(
            field,
            "must be E.164 digits, optionally prefixed with + (no spaces, dashes or parentheses)",
        ));
    }
    if digits.len() < MIN_PHONE_DIGITS {
        return Err(Error::validation(
            field,
            format!("must be at least {MIN_PHONE_DIGITS} digits (E.164 with country code)"),
        ));
    }
    if digits.starts_with('0') {
        return Err(Error::validation(
            field,
            "must be E.164 digits with a country code (leading digit 1-9, no leading 0 or 00)",
        ));
    }
    if digits.len() > MAX_PHONE_DIGITS {
        return Err(Error::validation(
            field,
            format!("must be at most {MAX_PHONE_DIGITS} digits (E.164)"),
        ));
    }
    Ok(digits.to_string())
}

/// Validates an absolute `http(s)` URL with a host and no credentials.
pub(crate) fn http_url(field: &'static str, value: &str) -> Result<()> {
    non_empty(field, value, MAX_REST_FIELD_BYTES)?;

    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::validation(
            field,
            "must not contain whitespace or control characters",
        ));
    }

    let url = Url::parse(value).map_err(|error| {
        Error::validation(
            field,
            format!("must be an absolute http:// or https:// URL: {error}"),
        )
    })?;

    let Some((_scheme, rest)) = value.split_once(':') else {
        return Err(Error::validation(
            field,
            "must be an absolute http:// or https:// URL",
        ));
    };
    let Some(authority_and_path) = rest.strip_prefix("//") else {
        return Err(Error::validation(
            field,
            "must be an absolute http:// or https:// URL",
        ));
    };
    let authority = authority_and_path
        .split_once(['/', '?', '#'])
        .map_or(authority_and_path, |(authority, _)| authority);

    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::validation(field, "must use http:// or https://"));
    }
    if authority.is_empty() || authority.starts_with('/') || url.host_str().is_none() {
        return Err(Error::validation(field, "must include a host"));
    }
    if authority.contains('@') || !url.username().is_empty() || url.password().is_some() {
        return Err(Error::validation(field, "must not include credentials"));
    }

    Ok(())
}

/// Validates a BCP-47 language tag as far as the API cares: non-empty, short,
/// ASCII, with a `-` separator in the common case.
pub(crate) fn language_tag(field: &'static str, value: &str) -> Result<()> {
    non_empty(field, value, MAX_LANGUAGE_TAG)?;
    if !value.is_ascii()
        || value
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '-'))
    {
        return Err(Error::validation(
            field,
            "must be a BCP-47 tag such as en-US",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn path_segment_accepts_the_exact_ascii_alphabet() {
        for value in [
            "A",
            "Z",
            "a",
            "z",
            "0",
            "9",
            "_",
            "~",
            ":",
            "@",
            "-",
            ".x",
            "a.b",
            "AZaz09._~:@-",
        ] {
            assert!(path_segment("id", value).is_ok(), "{value:?}");
        }
        assert!(path_segment("id", &"a".repeat(MAX_SESSION_ID)).is_ok());
    }

    #[test]
    fn path_segment_rejects_outside_the_ascii_alphabet() {
        for value in [
            "/",
            "?",
            "#",
            "\\",
            "%",
            " ",
            "!",
            "\t",
            "\u{7f}",
            "\u{80}",
            "\u{e9}",
            "\u{202e}",
            "\u{200b}",
            "\u{2066}",
            "\u{2069}",
            "abc\u{202e}gnp.exe",
            "abc\u{200b}def",
        ] {
            assert!(path_segment("id", value).is_err(), "{value:?}");
        }
        assert!(path_segment("id", &"a".repeat(MAX_SESSION_ID + 1)).is_err());
    }

    #[test]
    fn path_segment_refuses_dot_segments() {
        assert!(path_segment("id", ".").is_err());
        assert!(path_segment("id", "..").is_err());
        for value in [".a", "a.", "..."] {
            assert!(path_segment("id", value).is_ok(), "{value:?}");
        }
    }

    #[test]
    fn ai_flow_id_accepts_the_documented_uuid_slug_shape() {
        for value in [
            "A",
            "Z",
            "a",
            "z",
            "0",
            "9",
            "_",
            "-",
            "flow-1",
            "e3670012-96a3-4ae5-ac42-87abe22015c3",
            "AZaz09_-",
        ] {
            assert!(ai_flow_id("id", value).is_ok(), "{value:?}");
        }
        assert!(ai_flow_id("id", &"a".repeat(MAX_SESSION_ID)).is_ok());
    }

    #[test]
    fn ai_flow_id_rejects_outside_the_uuid_slug_shape() {
        for value in [
            "",
            ".",
            "..",
            ".a",
            "a.",
            "...",
            "a.b",
            "~",
            ":",
            "@",
            "AZaz09._~:@-",
            "/",
            "?",
            "#",
            "\\",
            "%",
            " ",
            "\t",
            "\u{7f}",
            "\u{80}",
            "\u{e9}",
            "\u{202e}",
            "\u{200b}",
            "abc\u{202e}gnp.exe",
            "abc\u{200b}def",
        ] {
            assert!(ai_flow_id("id", value).is_err(), "{value:?}");
        }
        assert!(ai_flow_id("id", &"a".repeat(MAX_SESSION_ID + 1)).is_err());
    }

    #[test]
    fn billing_device_accepts_the_documented_suffix_shape() {
        for value in ["e2", "s0", "d0", "a", "a1", "z9", "abc123"] {
            assert!(billing_device("id", value).is_ok(), "{value:?}");
        }
    }

    #[test]
    fn billing_device_accepts_the_max_length() {
        let value = format!("a{}", "0".repeat(MAX_BILLING_DEVICE - 1));
        assert_eq!(value.len(), MAX_BILLING_DEVICE);
        assert!(billing_device("id", &value).is_ok());
    }

    #[test]
    fn billing_device_rejects_empty() {
        assert!(billing_device("id", "").is_err());
    }

    #[test]
    fn billing_device_rejects_over_the_max_length() {
        let value = format!("a{}", "0".repeat(MAX_BILLING_DEVICE));
        assert_eq!(value.len(), MAX_BILLING_DEVICE + 1);
        assert!(billing_device("id", &value).is_err());
    }

    #[test]
    fn billing_device_rejects_whitespace_and_control_characters() {
        for value in [
            "e 2",
            "e\t2",
            "e\n2",
            "e\r2",
            " e2",
            "e2 ",
            "\u{0}e2",
            "e2\u{7f}",
            "e2\u{202e}",
            "e2\u{200b}",
            "e\u{e9}",
            "E2",
            "2e",
            "e-2",
            "e_2",
            "e.2",
            "e/2",
        ] {
            assert!(billing_device("id", value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn non_empty_accepts_one_character_and_rejects_empty() {
        assert!(non_empty("field", "x", 1).is_ok());
        assert!(non_empty("field", "", 1).is_err());
    }

    #[test]
    fn non_empty_accepts_the_exact_limit_and_rejects_one_byte_over() {
        let limit = 8;
        assert!(non_empty("field", &"x".repeat(limit), limit).is_ok());
        assert!(non_empty("field", &"x".repeat(limit + 1), limit).is_err());
    }

    #[test]
    fn non_empty_counts_utf8_bytes_not_characters() {
        let limit = 4;
        assert!(non_empty("field", "\u{00e9}\u{00e9}", limit).is_ok());
        assert!(non_empty("field", "\u{00e9}\u{00e9}\u{00e9}", limit).is_err());
    }

    #[test]
    fn non_empty_rejects_a_zero_ceiling_even_for_one_character() {
        assert!(non_empty("field", "x", 0).is_err());
    }

    proptest! {
        #[test]
        fn non_empty_accepts_exactly_the_non_empty_bounded_inputs(
            value in ".{0,64}",
            max_bytes in 0_usize..=64,
        ) {
            let expected = !value.is_empty() && value.len() <= max_bytes;
            prop_assert_eq!(non_empty("field", &value, max_bytes).is_ok(), expected);
        }
    }
}
