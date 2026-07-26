//! CRC-32C.
//!
//! The `.nostdb` container contract in `nostdb-spec` specifies CRC-32C, the
//! Castagnoli polynomial, reflected, with reversed polynomial `0x82F63B78`, an
//! initial value of `0xFFFFFFFF`, and a final XOR of `0xFFFFFFFF`.
//!
//! This detects container corruption. It is not a tamper-proofing measure: a
//! downloaded graph artifact still receives an independent cryptographic digest
//! before it is opened, which is a separate provider-level requirement.

/// Reversed Castagnoli polynomial.
const POLYNOMIAL_REVERSED: u32 = 0x82F6_3B78;

/// The standard CRC-32C check value for the ASCII bytes `123456789`.
///
/// A known answer matters here: fixtures and reader are both produced by this
/// implementation, so without an external reference they could agree while both
/// being wrong.
pub const CHECK_VALUE: u32 = 0xE306_9283;

/// Computes CRC-32C over `data`.
#[must_use]
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 == 0 {
                crc >>= 1;
            } else {
                crc = (crc >> 1) ^ POLYNOMIAL_REVERSED;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reproduces_the_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), CHECK_VALUE);
    }

    #[test]
    fn the_empty_input_has_a_zero_checksum() {
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn a_single_bit_change_changes_the_checksum() {
        let original = [0x00_u8; 64];
        let baseline = crc32c(&original);
        for index in 0..original.len() {
            let mut mutated = original;
            mutated[index] ^= 0x01;
            assert_ne!(
                crc32c(&mutated),
                baseline,
                "flipping a bit at offset {index} did not change the checksum"
            );
        }
    }

    #[test]
    fn length_is_part_of_the_checksum() {
        // Appending a zero byte must change the result, or trailing truncation
        // would go undetected.
        assert_ne!(crc32c(b"abc"), crc32c(b"abc\0"));
    }
}
