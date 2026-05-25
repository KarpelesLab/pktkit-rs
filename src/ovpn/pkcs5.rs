//! PKCS#5/PKCS#7 padding for AES-CBC data-channel packets.
//!
//! OpenVPN pads the CBC plaintext to the cipher block size (16 for AES) using
//! PKCS#7: the value of each padding byte is the number of bytes added, and a
//! full block of padding is appended when the input is already block-aligned.
//! Ported from the Go `pkcs5.go`.

/// Append PKCS#7 padding so the result is a multiple of `block_size`.
pub fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding = block_size - (data.len() % block_size);
    let mut out = Vec::with_capacity(data.len() + padding);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat(padding as u8).take(padding));
    out
}

/// Strip PKCS#7 padding, returning the unpadded slice.
///
/// Mirrors the Go upstream which trims `data[len-1]` bytes without verifying
/// that the trailing bytes all match (`// TODO ensure trimmed bytes are indeed
/// padding`). Returns the input unchanged if it is empty or the padding length
/// is invalid (zero or larger than the buffer), which is safer than the Go
/// version's unchecked slice.
pub fn trim(data: &[u8]) -> &[u8] {
    if data.is_empty() {
        return data;
    }
    let padding = data[data.len() - 1] as usize;
    if padding == 0 || padding > data.len() {
        return data;
    }
    &data[..data.len() - padding]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_aligned_adds_full_block() {
        let input = [0u8; 16];
        let padded = pad(&input, 16);
        assert_eq!(padded.len(), 32);
        for &b in &padded[16..32] {
            assert_eq!(b, 16);
        }
    }

    #[test]
    fn unaligned() {
        let input = [0u8; 13];
        let padded = pad(&input, 16);
        assert_eq!(padded.len(), 16);
        for &b in &padded[13..16] {
            assert_eq!(b, 3);
        }
    }

    #[test]
    fn trimming_roundtrip() {
        for size in [1usize, 7, 15, 16, 31, 33] {
            let input: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let padded = pad(&input, 16);
            let trimmed = trim(&padded);
            assert_eq!(trimmed.len(), size, "size {size}");
            assert_eq!(trimmed, &input[..], "size {size}");
        }
    }
}
