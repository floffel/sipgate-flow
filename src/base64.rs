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
//! What remains here is the error mapping into [`Error::Base64`] and the
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

use crate::error::{Base64Error, Error, Result};

/// The largest decoded payload accepted by [`decode`], in bytes.
///
/// The ceiling is sized from the largest documented caller-controlled payload:
/// fax `base64Content` has a documented `maxLength` of 28,330,000 characters,
/// which decodes to at most 21,247,500 bytes. Flow `audio` and `mix_audio`
/// values are bounded by the 1 MiB webhook body limit. This accepts every
/// documented payload while preventing an arbitrary string from forcing an
/// unbounded output allocation.
///
/// ```
/// use sipgate_flow::base64;
///
/// assert_eq!(base64::MAX_DECODED_BYTES, 21_247_500);
/// assert_eq!(
///     base64::encoded_len(base64::MAX_DECODED_BYTES),
///     Some(28_330_000)
/// );
/// ```
pub const MAX_DECODED_BYTES: usize = 21_247_500;

/// The largest accepted encoded input length, in characters.
const MAX_ENCODED_LEN: usize = saturating_encoded_len(MAX_DECODED_BYTES);

/// The number of base64 characters `len` bytes encode to, padding included.
///
/// Returns [`None`] for a length whose encoded size cannot be represented in
/// [`usize`]. The engine's own capacity arithmetic is the source of truth, so
/// this cannot drift from [`encode`].
///
/// ```
/// assert_eq!(sipgate_flow::base64::encoded_len(0), Some(0));
/// assert_eq!(sipgate_flow::base64::encoded_len(1), Some(4));
/// assert_eq!(sipgate_flow::base64::encoded_len(3), Some(4));
/// assert_eq!(sipgate_flow::base64::encoded_len(4), Some(8));
/// assert_eq!(sipgate_flow::base64::encoded_len(usize::MAX), None);
/// ```
#[must_use]
pub const fn encoded_len(len: usize) -> Option<usize> {
    base64::encoded_len(len, true)
}

/// The encoded size for an in-crate ceiling, saturating only where the ceiling
/// itself has already fixed a small, representable input length.
const fn saturating_encoded_len(len: usize) -> usize {
    match encoded_len(len) {
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
/// [`Error::Base64`] with an input-free reason and the typed decoder cause.
/// Inputs longer than the encoded length of [`MAX_DECODED_BYTES`] are rejected
/// as [`Error::Validation`] before decoding, so a hostile string cannot make
/// the call allocate proportionally more memory than [`MAX_DECODED_BYTES`].
pub fn decode(input: &str) -> Result<Vec<u8>> {
    check_encoded_len(input.len())?;
    STANDARD
        .decode(input.as_bytes())
        .map_err(|source| Error::Base64 {
            kind: kind(&source),
            message: reason(&source).to_string(),
            source,
        })
}

/// Whether `input` is well-formed, canonical standard base64.
///
/// The check *is* a decode, but it uses `Engine::decode_slice` with a
/// fixed-size scratch buffer instead of allocating a decoded payload
/// proportional to `input`. Inputs above the same size ceiling as [`decode`]
/// are rejected before decoding. Callers that need the bytes should still call
/// [`decode`] once instead of validating and decoding.
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
    if check_encoded_len(input.len()).is_err() {
        return false;
    }
    decode_slice_is_valid(input.as_bytes())
}

/// The largest encoded chunk passed to `decode_slice` by [`is_valid`].
///
/// This is a whole number of four-character groups, so decoding any non-final
/// chunk cannot encounter padding or a partial last group.
const VALIDATION_CHUNK_ENCODED_BYTES: usize = 4096;

/// Scratch output for one [`VALIDATION_CHUNK_ENCODED_BYTES`] chunk.
const VALIDATION_CHUNK_DECODED_BYTES: usize = VALIDATION_CHUNK_ENCODED_BYTES / 4 * 3;

/// Validates with `Engine::decode_slice` into a fixed stack buffer.
///
/// Padding is only legal in the final input group. Rejecting `=` in any earlier
/// chunk prevents chunked validation from accepting strings like
/// `"AA==AAAA"`, which are invalid as a whole and rejected by [`decode`].
fn decode_slice_is_valid(mut input: &[u8]) -> bool {
    let mut scratch = [0_u8; VALIDATION_CHUNK_DECODED_BYTES];

    while input.len() > VALIDATION_CHUNK_ENCODED_BYTES {
        let (chunk, remaining) = input.split_at(VALIDATION_CHUNK_ENCODED_BYTES);
        if chunk.contains(&b'=') || STANDARD.decode_slice(chunk, &mut scratch).is_err() {
            return false;
        }
        input = remaining;
    }

    STANDARD.decode_slice(input, &mut scratch).is_ok()
}

/// Rejects an input length above the size ceiling without touching the input
/// bytes, so the check runs before the decoder allocates its output buffer.
fn check_encoded_len(input_len: usize) -> Result<()> {
    if input_len > MAX_ENCODED_LEN {
        return Err(Error::validation(
            "base64",
            format!("must be at most {MAX_ENCODED_LEN} characters"),
        ));
    }
    Ok(())
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

/// The input-free category for a decoder error.
const fn kind(err: &DecodeError) -> Base64Error {
    match err {
        DecodeError::InvalidByte(..) => Base64Error::InvalidByte,
        DecodeError::InvalidLength(_) => Base64Error::InvalidLength,
        DecodeError::InvalidLastSymbol { .. } => Base64Error::InvalidLastSymbol,
        DecodeError::InvalidPadding => Base64Error::InvalidPadding,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        check_encoded_len, decode, encode, encoded_len, is_valid, kind, reason, MAX_ENCODED_LEN,
        VALIDATION_CHUNK_ENCODED_BYTES,
    };
    use crate::{Base64Error, Error};
    use base64::DecodeError;
    use proptest::prelude::*;

    #[test]
    fn every_decoder_error_maps_to_a_distinct_reason() {
        let errors = [
            DecodeError::InvalidByte(0, b'!'),
            DecodeError::InvalidLength(1),
            DecodeError::InvalidLastSymbol {
                offset: 1,
                symbol: b'B',
                symbol_value: 1,
            },
            DecodeError::InvalidPadding,
        ];
        let kinds = [
            Base64Error::InvalidByte,
            Base64Error::InvalidLength,
            Base64Error::InvalidLastSymbol,
            Base64Error::InvalidPadding,
        ];
        let reasons = errors.each_ref().map(reason);
        let mut unique = reasons.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), reasons.len(), "reasons must be distinct");
        for (error, reason) in errors.iter().zip(reasons) {
            assert_ne!(reason, "", "a reason must never be empty");
            assert!(
                !reason.contains('!'),
                "no reason echoes the offending input"
            );
            assert!(kinds.contains(&kind(error)));
        }

        let mapped = errors.each_ref().map(kind);
        let mut unique = mapped.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), mapped.len(), "kinds must be distinct");
        assert_eq!(mapped, kinds);
    }

    #[test]
    fn oversized_lengths_are_rejected_by_the_size_check_alone() {
        assert!(check_encoded_len(MAX_ENCODED_LEN).is_ok());
        match check_encoded_len(MAX_ENCODED_LEN + 1) {
            Err(Error::Validation { field, message }) => {
                assert_eq!(field, "base64");
                assert!(message.contains(&MAX_ENCODED_LEN.to_string()));
            }
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn padding_boundaries_are_exact() {
        let cases: &[(&str, Option<&[u8]>)] = &[
            ("", Some(&[])),
            (">", None),
            ("=", None),
            ("====", None),
            ("Zg==", Some(b"f")),
            ("Zg=", None),
            ("Zg===", None),
            ("Zm8=", Some(b"fo")),
            ("Zm8", None),
            ("Zm9v", Some(b"foo")),
            ("Zm9v=", None),
            ("Zm9vYg==", Some(b"foob")),
            ("Zm9vYg=", None),
            ("Zm9vYmE=", Some(b"fooba")),
            ("Zm9vYmE", None),
            ("AA==", Some(&[0])),
            ("AAA=", Some(&[0, 0])),
            ("AAAA", Some(&[0, 0, 0])),
            ("AB==", None),
            ("AAB=", None),
            ("A", None),
            ("AA", None),
            ("AAA", None),
            ("AAAAA", None),
            ("A===", None),
            ("AA=A", None),
            ("AA==AA==", None),
        ];

        for &(input, expected) in cases {
            assert_eq!(is_valid(input), expected.is_some(), "{input:?}");
            match (decode(input), expected) {
                (Ok(decoded), Some(expected)) => {
                    assert_eq!(decoded, expected, "{input:?}");
                    assert_eq!(encode(&decoded), input, "{input:?}");
                    assert_eq!(encoded_len(decoded.len()), Some(input.len()), "{input:?}");
                }
                (Err(_), None) => {}
                (Ok(decoded), None) => {
                    panic!("{input:?} decoded unexpectedly to {decoded:?}");
                }
                (Err(error), Some(expected)) => {
                    panic!("{input:?} should decode to {expected:?}, got {error:?}");
                }
            }
        }
    }

    #[test]
    fn chunked_validation_agrees_with_decode_across_scratch_boundaries() {
        let prefix = "A".repeat(VALIDATION_CHUNK_ENCODED_BYTES);
        let cases = [
            prefix.clone(),
            format!("{prefix}A"),
            format!("{prefix}AA"),
            format!("{prefix}AAA"),
            format!("{prefix}AAAA"),
            format!("{prefix}AAA="),
            format!("{prefix}AA=="),
            format!("{prefix}AB=="),
            format!("{prefix}===="),
            format!("{prefix}!AAA"),
            format!("{prefix}A==="),
            format!("AA=={prefix}"),
            format!("{prefix}AA==AAAA"),
        ];

        for input in cases {
            assert_eq!(
                is_valid(&input),
                decode(&input).is_ok(),
                "length {}",
                input.len()
            );
        }
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..=8192)) {
            let encoded = encode(&bytes);
            prop_assert!(is_valid(&encoded));
            prop_assert_eq!(encoded.len(), encoded_len(bytes.len()).expect("small length"));
            prop_assert_eq!(decode(&encoded).expect("our own encoding must decode"), bytes);
        }

        #[test]
        fn is_valid_agrees_with_decode(input in ".{0,512}") {
            prop_assert_eq!(is_valid(&input), decode(&input).is_ok());
        }
    }
}
