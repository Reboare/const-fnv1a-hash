#![no_std]

const FNV_OFFSET_BASIS_32: u32 = 0x811c9dc5;
const FNV_OFFSET_BASIS_64: u64 = 0xcbf29ce484222325;

const FNV_PRIME_32: u32 = 0x01000193;
const FNV_PRIME_64: u64 = 0x00000100000001B3;

const ASCII_CASE_MASK: u8 = 0b0010_0000;

/// Computes 64-bits fnv1a hash of the given slice, or up-to limit if provided.
/// If limit is zero or exceeds slice length, slice length is used instead.
pub const fn fnv1a_hash_64(bytes: &[u8], limit: Option<usize>, case: bool) -> u64 {
    let mut hash = FNV_OFFSET_BASIS_64;

    let mut i = 0;
    let len = match limit {
        Some(v) => {
            if v <= bytes.len() && v > 0 {
                v
            } else {
                bytes.len()
            }
        }
        None => bytes.len(),
    };

    while i < len {
        let value = if case && (bytes[i] & ASCII_CASE_MASK == ASCII_CASE_MASK) {
            bytes[i] ^ ASCII_CASE_MASK
        }
        else {
            bytes[i]
        };
        hash ^= value as u64;
        hash = hash.wrapping_mul(FNV_PRIME_64);
        i += 1;
    }
    hash
}

/// Computes 32-bits fnv1a hash of the given slice, or up-to limit if provided.
/// If limit is zero or exceeds slice length, slice length is used instead.
pub const fn fnv1a_hash_32(bytes: &[u8], limit: Option<usize>, case: bool) -> u32 {
    let mut hash = FNV_OFFSET_BASIS_32;

    let mut i = 0;
    let len = match limit {
        Some(v) => {
            if v <= bytes.len() && v > 0 {
                v
            } else {
                bytes.len()
            }
        }
        None => bytes.len(),
    };

    while i < len {
        let value = if case && (bytes[i] & ASCII_CASE_MASK == ASCII_CASE_MASK) {
            bytes[i] ^ ASCII_CASE_MASK
        }
        else {
            bytes[i]
        };
        hash ^= value as u32;
        hash = hash.wrapping_mul(FNV_PRIME_32);
        i += 1;
    }
    hash
}

/// Computes 32-bits fnv1a hash and XORs higher and lower 16-bits.
/// This results in a 16-bits hash value.
/// Up to limit if provided, otherwise slice length.
/// If limit is zero or exceeds slice length, slice length is used instead.
#[inline(always)]
pub const fn fnv1a_hash_16_xor(bytes: &[u8], limit: Option<usize>) -> u16 {
    let bytes = fnv1a_hash_32(bytes, limit, false).to_ne_bytes();
    let upper: u16 = u16::from_ne_bytes([bytes[0], bytes[1]]);
    let lower: u16 = u16::from_ne_bytes([bytes[2], bytes[3]]);
    upper ^ lower
}

/// Computes 64-bit fnv1a hash from a str.
#[inline(always)]
pub const fn fnv1a_hash_str_64(input: &str) -> u64 {
    fnv1a_hash_64(input.as_bytes(), None, false)
}

/// Computes 32-bit fnv1a hash from a str.
#[inline(always)]
pub const fn fnv1a_hash_str_32(input: &str) -> u32 {
    fnv1a_hash_32(input.as_bytes(), None, false)
}

/// Computes 16-bit fnv1a hash from a str using XOR folding.
#[inline(always)]
pub const fn fnv1a_hash_str_16_xor(input: &str) -> u16 {
    fnv1a_hash_16_xor(input.as_bytes(), None)
}


#[test]
fn fnv1a_test_case_comparison() {
    let bytes = ['A' as u8, 'B' as u8];
    assert_eq!(fnv1a_hash_64(&bytes, None, false), fnv1a_hash_64(&bytes, None, true));
    assert_eq!(fnv1a_hash_32(&bytes, None, false), fnv1a_hash_32(&bytes, None, true));

    let bytes = ['a' as u8, 'B' as u8];
    assert_ne!(fnv1a_hash_64(&bytes, None, false), fnv1a_hash_64(&bytes, None, true));
    assert_ne!(fnv1a_hash_32(&bytes, None, false), fnv1a_hash_32(&bytes, None, true));

    let bytes = ['a' as u8, 'B' as u8];
    let comparison = ['A' as u8, 'B' as u8];
    assert_eq!(fnv1a_hash_64(&bytes, None, true), fnv1a_hash_64(&comparison, None, true));
    assert_eq!(fnv1a_hash_32(&bytes, None, true), fnv1a_hash_32(&comparison, None, true));


}