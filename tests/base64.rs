//! The base64 surface: canonical acceptance, the rejections at each rule's
//! boundary, and the error a caller actually sees.
//!
//! The codec is the maintained `base64` crate, so these tests are the contract
//! that pins *which* of its tolerances this crate accepts — nothing here may
//! quietly widen.

use sipgate_flow::{base64, Error};

/// Every byte value survives a round trip, including NUL and 0xFF.
#[test]
fn every_byte_value_round_trips() {
    let bytes: Vec<u8> = (0..=255_u8).collect();
    let encoded = base64::encode(&bytes);
    assert!(base64::is_valid(&encoded));
    assert_eq!(base64::decode(&encoded).expect("decodes"), bytes);
}

/// The three padding cases (none, one `=`, two `=`) and the lengths around
/// them, with `encoded_len` pinned to what `encode` actually emits.
#[test]
fn lengths_cover_all_three_padding_cases() {
    for len in 0..=9_usize {
        let bytes = vec![0xAB_u8; len];
        let encoded = base64::encode(&bytes);
        assert_eq!(encoded.len(), base64::encoded_len(len), "len {len}");
        assert!(encoded.len().is_multiple_of(4), "len {len}");
        let padding = encoded.chars().rev().take_while(|c| *c == '=').count();
        assert_eq!(padding, (3 - len % 3) % 3, "len {len}");
        assert!(base64::is_valid(&encoded), "len {len}");
        assert_eq!(
            base64::decode(&encoded).expect("decodes"),
            bytes,
            "len {len}"
        );
    }
}

/// The empty payload is valid base64, and a lone `=` is not: the boundary sits
/// between them.
#[test]
fn the_empty_string_is_valid_but_a_lone_padding_character_is_not() {
    assert!(base64::is_valid(""));
    assert_eq!(base64::decode("").expect("decodes"), Vec::<u8>::new());
    for input in ["=", "==", "===", "===="] {
        assert!(!base64::is_valid(input), "{input:?}");
        assert!(base64::decode(input).is_err(), "{input:?}");
    }
}

/// Each rule has its just-inside and just-outside value, one pair per rule.
#[test]
fn each_rule_has_its_boundary_pair() {
    // Length: two symbols in the last group are the shortest legal tail.
    assert!(base64::is_valid("AA=="));
    assert!(!base64::is_valid("A"));
    assert!(!base64::is_valid("AAAAA"));
    // Padding: canonical is required, so a bare tail is rejected.
    assert!(base64::is_valid("AAA="));
    assert!(!base64::is_valid("AAA"));
    assert!(!base64::is_valid("A==="));
    // Trailing bits: `AA==` leaves zero unused bits, `AB==` leaves one set.
    assert!(base64::is_valid("AA=="));
    assert!(!base64::is_valid("AB=="));
    assert!(base64::is_valid("AAA="));
    assert!(!base64::is_valid("AAB="));
}

/// Whitespace, line breaks and the URL-safe alphabet are all outside the
/// standard engine's contract — this crate never silently repairs them.
#[test]
fn chars_outside_the_standard_alphabet_are_rejected() {
    for input in [
        " Zm9v", "Zm9v ", "Zm 9v", "Zm9v\n", "Zm9v\r\n", "Zm\t9v", "-_-_", "Zm9v_", "Zm9v-",
        "Zm9v!", "Zm9v?", "Zm9v%2F",
    ] {
        assert!(!base64::is_valid(input), "{input:?}");
        assert!(base64::decode(input).is_err(), "{input:?}");
    }
    // The two symbols that only the standard alphabet has stay accepted.
    assert!(base64::is_valid("+/+/"));
    assert_eq!(base64::decode("+/+/").expect("decodes"), [0xFB, 0xFF, 0xBF]);
}

/// Non-ASCII input is refused by byte, including a string that is valid apart
/// from one multi-byte character and one that carries a NUL.
#[test]
fn non_ascii_and_control_bytes_are_rejected() {
    for input in ["Zm9vé", "日本語", "Zm9v\u{0}", "Zm9v\u{7}", "ΩAAA"] {
        assert!(!base64::is_valid(input), "{input:?}");
        assert!(base64::decode(input).is_err(), "{input:?}");
    }
}

/// A canonical string re-encodes to itself: the engine's decoder and encoder
/// agree on one representation, which is what "canonical" has to mean.
#[test]
fn a_valid_string_re_encodes_to_itself() {
    for input in [
        "",
        "AA==",
        "AAA=",
        "AAAA",
        "UklGRiQAAABXQVZF",
        "+/+/",
        "Zm9vYmFy",
    ] {
        let decoded = base64::decode(input).expect("valid input decodes");
        assert_eq!(base64::encode(&decoded), input, "{input:?}");
    }
}

/// Whatever `decode` reports, the reason travels as `Validation` on the
/// `base64` field and never echoes the offending input back to the caller.
#[test]
fn every_rejection_names_the_field_without_echoing_the_input() {
    for input in ["A", "A===", "AB==", "A A==", "Zm9v\u{0}", "-_-_"] {
        let err = base64::decode(input).expect_err("must be rejected");
        match &err {
            Error::Validation { field, message } => {
                assert_eq!(*field, "base64");
                assert!(!message.is_empty());
                assert!(
                    !message.contains(input) && !message.contains('!'),
                    "message must not echo the input: {message:?}"
                );
            }
            other => panic!("expected Error::Validation, got {other:?}"),
        }
        assert!(!err.is_retryable(), "a malformed string is terminal");
        assert!(err.to_string().starts_with("invalid base64: "), "{err}");
    }
}

/// `encoded_len` is the engine's own arithmetic, so it cannot drift from
/// `encode`; the saturation case is the one value it cannot represent.
#[test]
fn encoded_len_matches_encode() {
    for len in [0, 1, 2, 3, 4, 5, 1_000, 1_000_001] {
        assert_eq!(
            base64::encoded_len(len),
            base64::encode(&vec![0_u8; len]).len(),
            "len {len}"
        );
    }
    assert_eq!(base64::encoded_len(usize::MAX), usize::MAX);
}

/// `is_valid` and `decode` never disagree — the cheap check is the same rule,
/// not an approximation of it.
#[test]
fn is_valid_agrees_with_decode() {
    for input in ["", "AA==", "AB==", "A", "Zm9v", "Zm9v!", "-_-_", "AAA="] {
        assert_eq!(
            base64::is_valid(input),
            base64::decode(input).is_ok(),
            "{input:?}"
        );
    }
}

/// A megabyte of random-looking bytes round-trips without a size surprise.
#[test]
fn a_large_payload_round_trips() {
    let bytes: Vec<u8> = (0_u8..=250).cycle().take(1024 * 1024).collect();
    let encoded = base64::encode(&bytes);
    assert_eq!(encoded.len(), base64::encoded_len(bytes.len()));
    assert_eq!(base64::decode(&encoded).expect("decodes"), bytes);
}
