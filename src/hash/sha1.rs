//! # SHA-1 Hash Function Implementation
//!
//! This module provides a complete implementation of SHA-1 (Secure Hash Algorithm 1),
//! developed by the NSA and published as a federal standard in 1995. SHA-1 was widely
//! used but is now considered cryptographically weak due to collision vulnerabilities.
//!
//! ⚠️ **Security Warning**: SHA-1 is **deprecated** for cryptographic use due to
//! practical collision attacks demonstrated in 2017. Use SHA-256 or newer algorithms
//! for security-critical applications.
//!
//! ## Algorithm Overview
//!
//! - **Output Size**: 160 bits (20 bytes, 40 hex characters)
//! - **Block Size**: 512 bits (64 bytes)
//! - **Structure**: Merkle-Damgård construction with 80 rounds
//! - **Operations**: Bitwise functions, addition, left rotation
//!
//! ## Security Status
//!
//! SHA-1 vulnerabilities include:
//! - **SHAttered Attack (2017)**: Practical collision attack
//! - **Theoretical Attacks**: Various cryptanalytic techniques
//! - **Deprecation**: Removed from TLS, code signing, and other protocols
//!
//! ## Historical Significance
//!
//! SHA-1 was the foundation for many security protocols and served as a
//! stepping stone to more secure hash functions like SHA-256. Understanding
//! SHA-1 helps in learning modern cryptographic hash design.
//!
//! ## Examples
//!
//! ```rust
//! use ruscrypt::hash::sha1;
//!
//! // Basic SHA-1 hashing
//! let hash = sha1::hash("Hello, World!").unwrap();
//! println!("SHA-1: {}", hash); // Outputs 40 hex characters
//!
//! // Well-known test vectors
//! let abc_hash = sha1::hash("abc").unwrap();
//! assert_eq!(abc_hash, "a9993e364706816aba3e25717850c26c9cd0d89d");
//! ```

use anyhow::Result;

/// Computes the SHA-1 hash of the input text.
///
/// This function processes the input through the SHA-1 algorithm and returns
/// the resulting 160-bit hash as a 40-character hexadecimal string.
///
/// # Arguments
///
/// * `input` - The text to hash
///
/// # Returns
///
/// Returns a 40-character hexadecimal string representing the 160-bit SHA-1 hash.
///
/// # Algorithm Overview
///
/// 1. Convert input to bytes
/// 2. Apply SHA-1 algorithm (padding, length appending, compression)
/// 3. Convert 20-byte result to hexadecimal representation
///
/// # Examples
///
/// ```rust
/// use ruscrypt::hash::sha1;
///
/// // Hash a message
/// let hash = sha1::hash("The quick brown fox").unwrap();
/// println!("SHA-1: {}", hash);
///
/// // Test with known vectors
/// let empty = sha1::hash("").unwrap();
/// assert_eq!(empty, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
///
/// let abc = sha1::hash("abc").unwrap();
/// assert_eq!(abc, "a9993e364706816aba3e25717850c26c9cd0d89d");
/// ```
///
/// # Output Format
///
/// The returned string is exactly 40 characters long, containing only
/// lowercase hexadecimal digits (0-9, a-f).
///
/// # Security Consideration
///
/// While this function correctly implements SHA-1, the algorithm itself
/// is deprecated. Consider using SHA-256 for new applications requiring
/// cryptographic security.
///
/// # Errors
///
/// Currently infallible, but returns `Result` for consistency and
/// potential future error conditions.
pub fn hash(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let hash_bytes = sha1_hash(bytes);

    // Convert to hexadecimal string
    let hex_string = hash_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    Ok(hex_string)
}

/// Core SHA-1 implementation following FIPS PUB 180-1 specification.
///
/// This function implements the complete SHA-1 algorithm including all
/// preprocessing steps and the 80-round compression function.
///
/// # Arguments
///
/// * `input` - Raw bytes to hash
///
/// # Returns
///
/// Returns a 20-byte array containing the SHA-1 hash.
///
/// # Algorithm Structure
///
/// ## Hash Value Initialization
/// Five 32-bit words initialized to specific constants:
/// - H₀ = 0x67452301
/// - H₁ = 0xEFCDAB89  
/// - H₂ = 0x98BADCFE
/// - H₃ = 0x10325476
/// - H₄ = 0xC3D2E1F0
///
/// ## Preprocessing
/// 1. **Padding**: Append '1' bit, then '0' bits until length ≡ 448 (mod 512)
/// 2. **Length**: Append original bit length as 64-bit big-endian integer
/// 3. **Result**: Padded message is multiple of 512 bits
///
/// ## Message Processing
/// - Process in 512-bit chunks
/// - Expand each chunk into 80 32-bit words
/// - Apply compression function with 80 rounds
///
/// # Round Functions
///
/// SHA-1 uses four different functions across its rounds:
/// - **f₀₋₁₉(B,C,D) = (B ∧ C) ∨ (¬B ∧ D)**: Conditional function
/// - **f₂₀₋₃₉(B,C,D) = B ⊕ C ⊕ D**: Parity function  
/// - **f₄₀₋₅₉(B,C,D) = (B ∧ C) ∨ (B ∧ D) ∨ (C ∧ D)**: Majority function
/// - **f₆₀₋₇₉(B,C,D) = B ⊕ C ⊕ D**: Parity function (repeated)
///
/// # Constants
///
/// Four 32-bit constants used in different round ranges:
/// - K₀₋₁₉ = 0x5A827999
/// - K₂₀₋₃₉ = 0x6ED9EBA1
/// - K₄₀₋₅₉ = 0x8F1BBCDC  
/// - K₆₀₋₇₉ = 0xCA62C1D6
///
/// # Word Expansion
///
/// The 16 input words are expanded to 80 words using:
/// W[i] = (W[i-3] ⊕ W[i-8] ⊕ W[i-14] ⊕ W[i-16]) <<<< 1
///
/// This provides better diffusion than the original SHA-0 design.
///
/// # Security Implementation Notes
///
/// This educational implementation prioritizes clarity over performance
/// and includes all specified operations for learning purposes.
fn sha1_hash(input: &[u8]) -> [u8; 20] {
    // Initialize hash values (first 32 bits of the fractional parts of square roots)
    let mut h = [
        0x67452301u32,
        0xEFCDAB89u32,
        0x98BADCFEu32,
        0x10325476u32,
        0xC3D2E1F0u32,
    ];

    // Pre-processing: add padding
    let mut message = input.to_vec();
    let original_len = message.len() as u64;

    // Append '1' bit (plus seven '0' bits, represented as 0x80)
    message.push(0x80);

    // Append '0' bits until message length ≡ 448 (mod 512)
    while (message.len() % 64) != 56 {
        message.push(0);
    }

    // Append original length as 64-bit big-endian
    message.extend_from_slice(&(original_len * 8).to_be_bytes());

    // Process message in 512-bit chunks
    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 80];

        // Break chunk into sixteen 32-bit big-endian words
        for (i, word_bytes) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }

        // Extend the sixteen 32-bit words into eighty 32-bit words
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        // Initialize hash value for this chunk
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];

        // Main loop
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6),
                _ => unreachable!(),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // Add this chunk's hash to result
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    // Convert to bytes (big-endian)
    let mut result = [0u8; 20];
    for (i, &word) in h.iter().enumerate() {
        let bytes = word.to_be_bytes();
        result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    result
}
