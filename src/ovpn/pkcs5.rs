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
    out.extend(std::iter::repeat_n(padding as u8, padding));
    out
}

/// Strip PKCS#7 padding, returning the unpadded slice, or `None` if `data`
/// does not end in valid padding for `block_size`: a length of 1 to
/// `block_size`, every padding byte equal to it.
pub fn unpad(data: &[u8], block_size: usize) -> Option<&[u8]> {
    let padding = *data.last()? as usize;
    if padding == 0 || padding > block_size || padding > data.len() {
        return None;
    }
    let (plain, pad) = data.split_at(data.len() - padding);
    pad.iter().all(|&b| b as usize == padding).then_some(plain)
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
            let trimmed = unpad(&padded, 16).unwrap();
            assert_eq!(trimmed.len(), size, "size {size}");
            assert_eq!(trimmed, &input[..], "size {size}");
        }
    }

    #[test]
    fn unpad_rejects_malformed_padding() {
        assert_eq!(unpad(&[], 16), None);
        assert_eq!(unpad(&[1, 2, 0], 16), None); // zero length
        assert_eq!(unpad(&[1, 2, 3, 3, 2, 3], 16), None); // bytes disagree
        assert_eq!(unpad(&[17; 32], 16), None); // longer than a block
        assert_eq!(unpad(&[4, 4, 4], 16), None); // longer than the data
        assert_eq!(unpad(&[9, 2, 2], 16), Some(&[9][..]));
    }
}
