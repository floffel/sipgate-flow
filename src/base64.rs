//! Standard base64 (RFC 4648, with padding), used for the `audio`,
//! `mix_audio` and fax payloads.
//!
//! The codec itself is the maintained [`base64`](https://crates.io/crates/base64)
//! crate — version 0.23.1, last released 2026-08-04 — restricted to its
//! `STANDARD` engine. It already refuses what this crate needs refused:
//! characters outside the alphabet, a length that is not a whole number of
//! four-character groups, misplaced or missing padding, and non-zero trailing
//! bits in the last symbol (`"AB=="` is *not* valid canonical base64).
//!
//! What remains here is the error mapping into [`Error::Validation`] and the
//! `String`-shaped surface the action builders want.
//!
//! ```
//! use sipgate_flow::base64;
//!
//! assert_eq!(base64::encode(b"hi"), "aGk=");
//! assert_eq!(base64::decode("aGk=")?, b"hi");
//! assert!(base64::is_valid("aGk="));
//! assert!(!base64::is_valid("aGk"));
//! # Ok::<(), sipgate_flow::Error>(())
//! ```

use base64::engine::general_purpose::STANDARD;
use base64::engine::Engine as _;
use base64::DecodeError;

use crate::error::{Error, Result};

/// The number of base64 characters `len` bytes encode to, padding included.
///
/// Saturates at [`usize::MAX`] for a length whose encoding cannot be
/// represented; the engine's own capacity arithmetic is the source of truth, so
/// this cannot drift from [`encode`].
///
/// ```
/// assert_eq!(sipgate_flow::base64::encoded_len(0), 0);
/// assert_eq!(sipgate_flow::base64::encoded_len(1), 4);
/// assert_eq!(sipgate_flow::base64::encoded_len(3), 4);
/// assert_eq!(sipgate_flow::base64::encoded_len(4), 8);
/// assert_eq!(
///     sipgate_flow::base64::encoded_len(usize::MAX),
///     usize::MAX,
///     "unrepresentable lengths saturate instead of wrapping"
/// );
/// ```
#[must_use]
pub const fn encoded_len(len: usize) -> usize {
    match base64::encoded_len(len, true) {
        Some(encoded) => encoded,
        None => usize::MAX,
    }
}

/// Encodes bytes with the standard alphabet and padding.
///
/// ```
/// use sipgate_flow::base64;
///
/// assert_eq!(base64::encode(b""), "");
/// assert_eq!(base64::encode(b"f"), "Zg==");
/// assert_eq!(base64::encode(b"fo"), "Zm8=");
/// assert_eq!(base64::encode(b"foo"), "Zm9v");
/// ```
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decodes standard base64, rejecting anything with a foreign character,
/// impossible length, misplaced padding or non-zero trailing bits.
///
/// ```
/// use sipgate_flow::base64;
///
/// assert_eq!(base64::decode("Zm9vYmFy")?, b"foobar");
/// assert!(base64::decode("Zm9vYmFy!").is_err());
/// // Canonical means the unused bits of the last symbol are zero.
/// assert!(base64::decode("AB==").is_err());
/// # Ok::<(), sipgate_flow::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Validation`] with `field = "base64"` and a reason naming the
/// defect. The output buffer is sized from the input through the engine's
/// estimate, so a hostile string cannot make the call allocate more than the
/// input it already occupies.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(input.as_bytes())
        .map_err(|err| Error::validation("base64", reason(&err)))
}

/// Whether `input` is well-formed, canonical standard base64.
///
/// The check *is* a decode (the engine exposes no cheaper validation entry
/// point), so it costs one output-sized buffer. Callers that need the bytes
/// should call [`decode`] once instead of validating and decoding.
///
/// ```
/// use sipgate_flow::base64;
///
/// assert!(base64::is_valid(""));
/// assert!(base64::is_valid("AA=="));
/// assert!(!base64::is_valid("A==="));
/// assert!(!base64::is_valid("A A=="));
/// assert!(!base64::is_valid("AB=="), "trailing bits must be zero");
/// ```
#[must_use]
pub fn is_valid(input: &str) -> bool {
    STANDARD.decode(input.as_bytes()).is_ok()
}

/// A short, input-free reason per decoder error.
///
/// The offending byte is deliberately not echoed: the string comes from a
/// caller (or a webhook) and would otherwise travel into logs verbatim.
const fn reason(err: &DecodeError) -> &'static str {
    match err {
        DecodeError::InvalidByte(..) => "contains a character outside the standard alphabet",
        DecodeError::InvalidLength(_) => "does not end on a four-character group of 2 to 4 symbols",
        DecodeError::InvalidLastSymbol { .. } => "has non-zero trailing bits in its last symbol",
        DecodeError::InvalidPadding => "has misplaced or missing padding",
    }
}

#[cfg(test)]
mod tests {
    use super::reason;
    use base64::DecodeError;

    #[test]
    fn every_decoder_error_maps_to_a_distinct_reason() {
        let reasons = [
            reason(&DecodeError::InvalidByte(0, b'!')),
            reason(&DecodeError::InvalidLength(1)),
            reason(&DecodeError::InvalidLastSymbol {
                offset: 1,
                symbol: b'B',
                symbol_value: 1,
            }),
            reason(&DecodeError::InvalidPadding),
        ];
        let mut unique = reasons.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), reasons.len(), "reasons must be distinct");
        assert!(
            reasons
                .iter()
                .all(|reason| !reason.is_empty() && !reason.contains('!')),
            "a reason never echoes the offending input"
        );
    }
}
