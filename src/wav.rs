//! Just enough WAV parsing to refuse a clip the service would not play.
//!
//! Both sipgate products demand uncompressed PCM in a RIFF/WAVE container but
//! disagree about the rate: the Flow `audio` action wants 16 kHz mono 16-bit,
//! the REST announcement endpoint wants 8 kHz mono 16-bit. Sending an MP3 or a
//! 44.1 kHz file "works" (it uploads fine) and then plays silence, which is the
//! kind of failure worth catching before the wire.
//!
//! ```
//! use sipgate_flow::wav;
//!
//! let clip = wav::pcm16_wav(&[0, 0, 1, 0], 16_000, 1).expect("a short clip");
//! assert!(wav::validate_pcm16(&clip, 16_000, 1).is_ok());
//! assert!(wav::validate_pcm16(&clip, 8_000, 1).is_err());
//! ```

use crate::error::{Error, Result};

/// What a WAV file's `fmt ` chunk says about its samples.
///
/// ```
/// use sipgate_flow::wav;
///
/// let clip = wav::pcm16_wav(&[0, 0], 16_000, 1).expect("a short clip");
/// let format = wav::format(&clip).unwrap();
/// assert_eq!(format.sample_rate, 16_000);
/// assert_eq!(format.bits_per_sample, 16);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WavFormat {
    /// Samples per second.
    pub sample_rate: u32,
    /// Channel count; 1 is mono.
    pub channels: u16,
    /// Bits per sample; 16 is the documented PCM width.
    pub bits_per_sample: u16,
    /// RIFF format tag; 1 is uncompressed PCM.
    pub format_tag: u16,
}

/// The largest `data` chunk a RIFF/WAVE file can describe.
///
/// Both the `data` size field and the enclosing `RIFF` size field are 32-bit, and
/// the `RIFF` size counts everything after its own four bytes plus the four bytes
/// of the `WAVE` form id: the 24-byte `fmt ` chunk, the 8-byte `data` header and
/// the payload, so `36 + data_len` has to fit a `u32`. [`pcm16_wav`] refuses a
/// larger payload instead of writing a header that disagrees with the body.
///
/// ```
/// use sipgate_flow::wav;
///
/// assert_eq!(wav::MAX_RIFF_DATA_BYTES, (u32::MAX - 36) as usize);
/// ```
pub const MAX_RIFF_DATA_BYTES: usize = (u32::MAX - 36) as usize;

/// Builds a 16-bit PCM WAV file from raw little-endian samples, for tests and
/// for callers that synthesise audio.
///
/// ```
/// use sipgate_flow::wav;
///
/// let clip = wav::pcm16_wav(&[], 16_000, 1).expect("an empty payload fits");
/// assert_eq!(clip.len(), 44); // header only
/// assert_eq!(&clip[..4], b"RIFF");
/// ```
///
/// # Errors
///
/// [`Error::Validation`] when the payload is larger than
/// [`MAX_RIFF_DATA_BYTES`]; the check runs before the output buffer is allocated,
/// so a caller cannot be talked into a multi-gigabyte allocation by a length field.
pub fn pcm16_wav(samples: &[u8], sample_rate: u32, channels: u16) -> Result<Vec<u8>> {
    let data_len = data_len(samples.len())?;
    let channels = channels.max(1);
    let block_align = channels.saturating_mul(2);
    let byte_rate = sample_rate.saturating_mul(u32::from(block_align));
    // `data_len` is capped so that this cannot overflow: 36 + (u32::MAX - 36).
    let riff_len = 36_u32 + data_len;

    let mut out = Vec::with_capacity(44 + samples.len());
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&riff_len.to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16_u32.to_le_bytes()); // fmt chunk size
    out.extend_from_slice(&1_u16.to_le_bytes()); // PCM
    out.extend_from_slice(&channels.to_le_bytes());
    out.extend_from_slice(&sample_rate.to_le_bytes());
    out.extend_from_slice(&byte_rate.to_le_bytes());
    out.extend_from_slice(&block_align.to_le_bytes());
    out.extend_from_slice(&16_u16.to_le_bytes()); // bits per sample
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_len.to_le_bytes());
    out.extend_from_slice(samples);
    Ok(out)
}

/// Rejects a payload the RIFF container cannot describe, before anything is
/// allocated. Split out so the boundary is testable without a 4 GiB slice.
fn data_len(sample_bytes: usize) -> Result<u32> {
    match u32::try_from(sample_bytes) {
        Ok(len) if len <= u32::MAX - 36 => Ok(len),
        _ => Err(Error::validation(
            "audio",
            format!(
                "PCM payload of {sample_bytes} bytes exceeds the RIFF limit of {MAX_RIFF_DATA_BYTES} bytes"
            ),
        )),
    }
}

/// Reads the `fmt ` chunk, if the bytes are a RIFF/WAVE file.
///
/// ```
/// use sipgate_flow::wav;
///
/// assert!(wav::format(b"not a wav file at all").is_none());
/// ```
#[must_use]
pub fn format(bytes: &[u8]) -> Option<WavFormat> {
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return None;
    }
    let mut offset = 12_usize;
    while offset + 8 <= bytes.len() {
        let id = bytes.get(offset..offset + 4)?;
        let size = u32::from_le_bytes(bytes.get(offset + 4..offset + 8)?.try_into().ok()?) as usize;
        let body_start = offset + 8;
        let body_end = body_start.checked_add(size)?;
        if body_end > bytes.len() {
            return None;
        }
        if id == b"fmt " && size >= 16 {
            let body = bytes.get(body_start..body_end)?;
            return Some(WavFormat {
                format_tag: u16::from_le_bytes(body.get(0..2)?.try_into().ok()?),
                channels: u16::from_le_bytes(body.get(2..4)?.try_into().ok()?),
                sample_rate: u32::from_le_bytes(body.get(4..8)?.try_into().ok()?),
                bits_per_sample: u16::from_le_bytes(body.get(14..16)?.try_into().ok()?),
            });
        }
        // Chunks are word aligned: an odd size is followed by a pad byte.
        offset = body_end + (size % 2);
    }
    None
}

/// Checks that `bytes` is uncompressed 16-bit PCM with the expected rate and
/// channel count.
///
/// ```
/// use sipgate_flow::wav;
///
/// let stereo = wav::pcm16_wav(&[0, 0, 0, 0], 16_000, 2).expect("a short clip");
/// assert!(wav::validate_pcm16(&stereo, 16_000, 1).is_err());
/// ```
///
/// # Errors
///
/// [`Error::Validation`] naming what is wrong: container, format tag, bit
/// depth, sample rate or channel count.
pub fn validate_pcm16(bytes: &[u8], expected_rate: u32, expected_channels: u16) -> Result<()> {
    let format = format(bytes).ok_or_else(|| {
        Error::validation("audio", "not a RIFF/WAVE file with a readable fmt chunk")
    })?;
    if format.format_tag != 1 {
        return Err(Error::validation(
            "audio",
            format!(
                "must be uncompressed PCM (format tag 1), found {}",
                format.format_tag
            ),
        ));
    }
    if format.bits_per_sample != 16 {
        return Err(Error::validation(
            "audio",
            format!("must be 16-bit PCM, found {} bits", format.bits_per_sample),
        ));
    }
    if format.channels != expected_channels {
        return Err(Error::validation(
            "audio",
            format!(
                "must have {expected_channels} channel(s), found {}",
                format.channels
            ),
        ));
    }
    if format.sample_rate != expected_rate {
        return Err(Error::validation(
            "audio",
            format!(
                "must be {expected_rate} Hz, found {} Hz",
                format.sample_rate
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{data_len, MAX_RIFF_DATA_BYTES};
    use proptest::prelude::*;

    /// The RIFF `data` field is 32-bit and the enclosing `RIFF` field spends 36
    /// of the same budget on the header, so the last representable payload is
    /// `u32::MAX - 36` - and it must be accepted, not off by one.
    #[test]
    fn the_last_representable_payload_is_accepted() {
        let limit = MAX_RIFF_DATA_BYTES;
        assert_eq!(
            data_len(limit).expect("the limit is representable"),
            u32::MAX - 36
        );
        assert_eq!(data_len(0).expect("an empty payload"), 0);
        assert_eq!(data_len(44).expect("22 samples of 16-bit PCM"), 44);
    }

    /// One byte past it is refused - and this is the case the old code saturated
    /// into `u32::MAX`, writing a header that disagreed with the body.
    #[test]
    fn one_byte_past_the_limit_is_refused() {
        let error = data_len(MAX_RIFF_DATA_BYTES + 1).expect_err("one byte too many");
        let message = error.to_string();
        assert!(message.contains("exceeds the RIFF limit"), "{message}");
        assert!(
            message.contains(&MAX_RIFF_DATA_BYTES.to_string()),
            "{message}"
        );
    }

    /// The refusal happens before allocation, so a `usize::MAX` length handed in
    /// by a caller must come back as an error rather than a request for 18 EB.
    #[test]
    fn an_absurd_length_is_refused_without_allocating() {
        assert!(data_len(usize::MAX).is_err());
        assert!(data_len(u32::MAX as usize).is_err());
    }

    proptest! {
        /// Accepted exactly up to the limit, refused above it - no gaps, no
        /// saturation, and the value is carried through unchanged.
        #[test]
        fn a_payload_is_accepted_iff_it_fits(sample_bytes in 0_usize..=u32::MAX as usize) {
            match data_len(sample_bytes) {
                Ok(len) => {
                    prop_assert!(sample_bytes <= MAX_RIFF_DATA_BYTES);
                    prop_assert_eq!(u64::from(len), sample_bytes as u64);
                }
                Err(_) => prop_assert!(sample_bytes > MAX_RIFF_DATA_BYTES),
            }
        }
    }
}
