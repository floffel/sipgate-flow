//! Field validation shared by the Flow actions and the REST requests.
//!
//! These are the checks that belong on the way *out*: a value that would be
//! rejected by sipgate, or that could escape its slot (a `/` in a session id
//! that is interpolated into a URL path, a newline in a log line), is refused
//! before the request exists. Parsing stays tolerant; sending does not.

use crate::error::{Error, Result};

/// Longest session id accepted: the documented value is a UUID (36 chars), and
/// the cap keeps a hostile string out of headers and log lines.
pub(crate) const MAX_SESSION_ID: usize = 200;

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
pub(crate) fn path_segment(field: &'static str, value: &str) -> Result<()> {
    non_empty(field, value)?;
    if value.len() > MAX_SESSION_ID {
        return Err(Error::validation(
            field,
            format!("must be at most {MAX_SESSION_ID} bytes"),
        ));
    }
    if value
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '?' | '#' | '\\' | '%'))
    {
        return Err(Error::validation(
            field,
            "must not contain whitespace, control characters or any of / ? # \\ %",
        ));
    }
    Ok(())
}

/// Validates and normalises a phone number: an optional leading `+` followed by
/// 1..=15 digits. Returns the digits, because sipgate's Flow actions expect
/// E.164 *without* the `+` (it strips one if sent).
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
    if digits.len() > MAX_PHONE_DIGITS {
        return Err(Error::validation(
            field,
            format!("must be at most {MAX_PHONE_DIGITS} digits (E.164)"),
        ));
    }
    Ok(digits.to_string())
}

/// Validates an absolute `http(s)` URL without parsing it, which is enough to
/// reject the mistakes that actually happen (relative paths, `file://`, values
/// with embedded whitespace).
pub(crate) fn http_url(field: &'static str, value: &str) -> Result<()> {
    non_empty(field, value)?;
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| Error::validation(field, "must start with http:// or https://"))?;
    if rest.is_empty() || rest.starts_with('/') {
        return Err(Error::validation(field, "must include a host"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(Error::validation(field, "must not contain whitespace"));
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
