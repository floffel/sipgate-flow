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
//! let clip = wav::pcm16_wav(&[0, 0, 1, 0], 16_000, 1);
//! assert!(wav::validate_pcm16(&clip, 16_000, 1).is_ok());
//! assert!(wav::validate_pcm16(&clip, 8_000, 1).is_err());
//! ```

use crate::error::{Error, Result};

/// What a WAV file's `fmt ` chunk says about its samples.
///
/// ```
/// use sipgate_flow::wav;
///
/// let clip = wav::pcm16_wav(&[0, 0], 16_000, 1);
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

/// Builds a 16-bit PCM WAV file from raw little-endian samples, for tests and
/// for callers that synthesise audio.
///
/// ```
/// use sipgate_flow::wav;
///
/// let clip = wav::pcm16_wav(&[], 16_000, 1);
/// assert_eq!(clip.len(), 44); // header only
/// assert_eq!(&clip[..4], b"RIFF");
/// ```
#[must_use]
pub fn pcm16_wav(samples: &[u8], sample_rate: u32, channels: u16) -> Vec<u8> {
    let data_len = u32::try_from(samples.len()).unwrap_or(u32::MAX);
    let channels = channels.max(1);
    let block_align = channels.saturating_mul(2);
    let byte_rate = sample_rate.saturating_mul(u32::from(block_align));
    let riff_len = 36_u32.saturating_add(data_len);

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
    out
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
/// let stereo = wav::pcm16_wav(&[0, 0, 0, 0], 16_000, 2);
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
