//! Payload padding to 256-byte boundaries.
//!
//! Hides the true payload length from an observer who can see the ciphertext
//! size (AES-256-GCM ciphertext = padded_size + 16 bytes GCM tag).
//!
//! # Format
//!
//! ```text
//! [ 4 bytes BE: original length ]
//! [ original payload bytes      ]
//! [ random salt (if short)      ]  ← only when orig_len < SHORT_THRESHOLD
//! [ padding bytes               ]  ← repeating (pad_len % 256) as u8
//! ```
//!
//! ## Short payload defence (< 16 bytes)
//!
//! For payloads shorter than [`SHORT_THRESHOLD`] bytes (e.g. a 4-digit PIN),
//! `(SHORT_THRESHOLD - orig_len)` random bytes are inserted between the
//! payload and the deterministic padding.  This defeats size fingerprinting:
//! a 4-byte PIN is indistinguishable from a 15-byte secret after padding.
//!
//! The trade-off: deduplication is silently disabled for short payloads
//! because two identical PINs produce different padded blobs.  This is
//! acceptable — PINs are rarely duplicated across chain items and the
//! security gain outweighs the lost dedup.
//!
//! ## `unpad` is unchanged
//!
//! Both paths store `orig_len` in the 4-byte prefix.  `unpad` always returns
//! exactly `orig_len` bytes regardless of what follows the payload.

use aes_gcm::aead::OsRng;
use anyhow::{bail, Result};
use rand::RngCore;

/// Payloads shorter than this many bytes get a random salt inserted before
/// the deterministic padding to prevent size fingerprinting.
const SHORT_THRESHOLD: usize = 16;

const BLOCK: usize = 256;
const PREFIX: usize = 4; // u32 big-endian original length

/// Pad `payload` to the next 256-byte boundary.
///
/// Short payloads (`< SHORT_THRESHOLD`) receive random salt bytes first.
pub fn pad(payload: &[u8]) -> Vec<u8> {
    let orig_len = payload.len();

    let salt = if orig_len < SHORT_THRESHOLD {
        let salt_len = SHORT_THRESHOLD - orig_len;
        let mut buf = vec![0u8; salt_len];
        OsRng.fill_bytes(&mut buf);
        buf
    } else {
        vec![]
    };

    let content_len = orig_len + salt.len();
    let min_total = PREFIX + content_len;
    let padded_size = next_block(min_total);
    let pad_len = padded_size - PREFIX - content_len;
    let pad_byte = (pad_len % 256) as u8;

    let mut out = Vec::with_capacity(padded_size);
    out.extend_from_slice(&(orig_len as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&salt);
    out.extend(std::iter::repeat_n(pad_byte, pad_len));
    out
}

/// Remove padding and return the original payload.
///
/// Reads `orig_len` from the 4-byte prefix and returns exactly those bytes.
/// Any salt and padding bytes that follow are discarded.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < PREFIX {
        bail!("padded buffer too short: {} bytes", padded.len());
    }
    if !padded.len().is_multiple_of(BLOCK) {
        bail!(
            "padded buffer length {} is not a multiple of {BLOCK}",
            padded.len()
        );
    }
    let orig_len =
        u32::from_be_bytes(padded[..PREFIX].try_into().expect("slice is 4 bytes")) as usize;
    if PREFIX + orig_len > padded.len() {
        bail!(
            "length field {orig_len} exceeds buffer size {}",
            padded.len()
        );
    }
    Ok(padded[PREFIX..PREFIX + orig_len].to_vec())
}

fn next_block(n: usize) -> usize {
    (n / BLOCK + 1) * BLOCK
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_small() {
        let payload = b"1234";
        let padded = pad(payload);
        assert_eq!(padded.len() % BLOCK, 0);
        assert_eq!(unpad(&padded).unwrap(), payload);
    }

    #[test]
    fn round_trip_empty() {
        let padded = pad(b"");
        assert_eq!(padded.len(), BLOCK);
        assert_eq!(unpad(&padded).unwrap(), b"");
    }

    #[test]
    fn round_trip_exactly_one_block_minus_prefix() {
        let payload = vec![0xAB; BLOCK - PREFIX];
        let padded = pad(&payload);
        assert_eq!(padded.len(), 2 * BLOCK);
        assert_eq!(unpad(&padded).unwrap(), payload);
    }

    #[test]
    fn round_trip_large() {
        let payload = vec![0xFF; 512 + 7];
        let padded = pad(&payload);
        assert_eq!(padded.len() % BLOCK, 0);
        assert_eq!(unpad(&padded).unwrap(), payload);
    }

    #[test]
    fn short_payload_gets_salt() {
        // Two identical short payloads should produce different padded blobs.
        let payload = b"1234";
        let a = pad(payload);
        let b = pad(payload);
        // Both unpad correctly.
        assert_eq!(unpad(&a).unwrap(), payload);
        assert_eq!(unpad(&b).unwrap(), payload);
        // But the blobs differ (salt is random) with overwhelming probability.
        assert_ne!(a, b, "salt randomisation failed — astronomically unlikely");
    }

    #[test]
    fn long_payload_is_deterministic_for_same_input() {
        // Payloads >= SHORT_THRESHOLD have no salt — same input → same padded output.
        let payload = vec![0xCC; SHORT_THRESHOLD];
        let a = pad(&payload);
        let b = pad(&payload);
        assert_eq!(a, b);
    }

    #[test]
    fn padded_size_always_multiple_of_block() {
        for len in 0..=600 {
            let p = pad(&vec![0u8; len]);
            assert_eq!(p.len() % BLOCK, 0, "len={len}");
        }
    }

    #[test]
    fn unpad_rejects_wrong_size() {
        assert!(unpad(&[0u8; 100]).is_err());
    }

    #[test]
    fn unpad_rejects_length_overflow() {
        let mut buf = vec![0u8; BLOCK];
        buf[0..4].copy_from_slice(&(BLOCK as u32).to_be_bytes());
        assert!(unpad(&buf).is_err());
    }
}
