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

/// Rejects empty or over-long identifiers.
pub(crate) fn non_empty(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::validation(field, "must not be empty"));
    }
    Ok(())
}

/// Validates an identifier that ends up in a URL path or a log line.
///
/// The accepted alphabet is exactly ASCII `A-Z`, `a-z`, `0-9`, `.`, `_`, `~`,
/// `:`, `@` and `-`. A bare `.` or `..` segment is refused even though its
/// characters are otherwise allowed.
pub(crate) fn path_segment(field: &'static str, value: &str) -> Result<()> {
    non_empty(field, value)?;
    if value.len() > MAX_SESSION_ID {
        return Err(Error::validation(
            field,
            format!("must be at most {MAX_SESSION_ID} bytes"),
        ));
    }
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
    non_empty(field, value)?;

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
    non_empty(field, value)?;
    if value.len() > MAX_LANGUAGE_TAG {
        return Err(Error::validation(
            field,
            format!("must be at most {MAX_LANGUAGE_TAG} characters"),
        ));
    }
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
}
