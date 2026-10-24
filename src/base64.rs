//! Standard base64 (RFC 4648, with padding), used for the `audio`,
//! `mix_audio` and fax payloads.
//!
//! The crate ships its own 60-line codec rather than a dependency: compression
//! and encoder crates are a supply-chain surface for two tables and a bit
//! shift, and the implementation is small enough to test exhaustively.
//!
//! ```
//! use sipgate_flow::base64;
//!
//! assert_eq!(base64::encode(b"hi"), "aGk=");
//! assert_eq!(base64::decode("aGk=").unwrap(), b"hi");
//! assert!(base64::is_valid("aGk="));
//! assert!(!base64::is_valid("aGk"));
//! ```

use crate::error::{Error, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The number of base64 characters `len` bytes encode to, padding included.
///
/// ```
/// assert_eq!(sipgate_flow::base64::encoded_len(0), 0);
/// assert_eq!(sipgate_flow::base64::encoded_len(1), 4);
/// assert_eq!(sipgate_flow::base64::encoded_len(3), 4);
/// assert_eq!(sipgate_flow::base64::encoded_len(4), 8);
/// ```
#[must_use]
pub const fn encoded_len(len: usize) -> usize {
    len.div_ceil(3) * 4
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
    let mut out = String::with_capacity(encoded_len(bytes.len()));
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(char::from(ALPHABET[((triple >> 18) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((triple >> 12) & 0x3f) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(ALPHABET[((triple >> 6) & 0x3f) as usize]));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[(triple & 0x3f) as usize]));
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodes standard base64, rejecting anything with a foreign character,
/// impossible length or misplaced padding.
///
/// ```
/// use sipgate_flow::base64;
///
/// assert_eq!(base64::decode("Zm9vYmFy").unwrap(), b"foobar");
/// assert!(base64::decode("Zm9vYmFy!").is_err());
/// ```
///
/// # Errors
///
/// [`Error::Validation`] for a malformed string. The output buffer is sized
/// from the input length before decoding, so a hostile string cannot make the
/// decoder allocate more than its own size suggests.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();
    if !is_valid(input) {
        return Err(Error::validation(
            "base64",
            "expected standard base64 with padding",
        ));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut triple = 0_u32;
        let mut pad = 0;
        for byte in chunk {
            if let Some(value) = value_of(*byte) {
                triple = (triple << 6) | u32::from(value);
            } else {
                triple <<= 6;
                pad += 1;
            }
        }
        out.push(((triple >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((triple & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Whether `input` is well-formed standard base64.
///
/// ```
/// use sipgate_flow::base64;
///
/// assert!(base64::is_valid(""));
/// assert!(base64::is_valid("AA=="));
/// assert!(!base64::is_valid("A==="));
/// assert!(!base64::is_valid("A A=="));
/// ```
#[must_use]
pub fn is_valid(input: &str) -> bool {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return false;
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return false;
    }
    let body = bytes.len() - padding;
    // Padding may only appear in the last quad, so its presence forces the
    // body to end on a quad boundary.
    bytes[..body].iter().all(|byte| value_of(*byte).is_some())
}

fn value_of(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
