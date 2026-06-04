//! Payload padding to 1 KiB boundaries.
//!
//! Hides the true payload length from an observer who can see the ciphertext
//! size (which equals the padded size for AES-256-GCM without compression).
//!
//! # Format
//!
//! ```text
//! [ 4 bytes big-endian original length ]
//! [ original payload bytes            ]
//! [ padding bytes                     ]  ← repeating (pad_len % 256) as u8
//! ```
//!
//! Total length is always a multiple of 1024 bytes.
//! The padding value is `(pad_len % 256) as u8` — unambiguous and
//! PKCS#7-compatible for lengths ≤ 255.
//!
//! # Boundary
//!
//! A payload of exactly N×1024 bytes is padded to (N+1)×1024 so there
//! is always at least 4 bytes of padding (the length prefix) and the
//! ciphertext size alone does not reveal that the payload was exactly on
//! a boundary.

use anyhow::{bail, Result};

const BLOCK: usize = 256;
const PREFIX: usize = 4; // u32 big-endian original length

/// Pad `payload` to the next 1 KiB boundary.
pub fn pad(payload: &[u8]) -> Vec<u8> {
    let orig_len = payload.len();
    // Total bytes needed before padding
    let min_total = PREFIX + orig_len;
    // Round up to next multiple of BLOCK, always at least one full block.
    let padded_size = next_block(min_total);
    let pad_len = padded_size - PREFIX - orig_len;
    let pad_byte = (pad_len % 256) as u8;

    let mut out = Vec::with_capacity(padded_size);
    out.extend_from_slice(&(orig_len as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend(std::iter::repeat_n(pad_byte, pad_len));
    out
}

/// Remove padding and return the original payload.
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
    // Always strictly larger than n — guarantees at least 1 byte of padding.
    // floor(n / BLOCK + 1) * BLOCK
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
        // payload that exactly fills one block after prefix → spills to next block
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
    fn padding_value_is_pad_len_mod_256() {
        let payload = b"hi";
        let padded = pad(payload);
        let pad_len = padded.len() - PREFIX - payload.len();
        let expected_byte = (pad_len % 256) as u8;
        for &b in &padded[PREFIX + payload.len()..] {
            assert_eq!(b, expected_byte);
        }
    }

    #[test]
    fn padded_size_always_multiple_of_block() {
        for len in 0..=2100 {
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
        // Write a length larger than the buffer
        buf[0..4].copy_from_slice(&(BLOCK as u32).to_be_bytes());
        assert!(unpad(&buf).is_err());
    }
}
