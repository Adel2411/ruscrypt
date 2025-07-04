//! # MD5 Hash Function Implementation
//!
//! This module provides a complete implementation of the MD5 (Message-Digest Algorithm 5)
//! cryptographic hash function. MD5 was designed by Ronald Rivest in 1991 as a replacement
//! for MD4, but is now considered cryptographically broken.
//!
//! ⚠️ **Security Warning**: MD5 is **not secure** for cryptographic purposes due to
//! collision vulnerabilities discovered in 2004. Use only for checksums, legacy
//! compatibility, or educational purposes.
//!
//! ## Algorithm Overview
//!
//! - **Output Size**: 128 bits (16 bytes, 32 hex characters)
//! - **Block Size**: 512 bits (64 bytes)
//! - **Structure**: Merkle-Damgård construction with 64 rounds
//! - **Operations**: Bitwise AND, OR, XOR, NOT, addition, left rotation
//!
//! ## Security Status
//!
//! MD5 suffers from several critical vulnerabilities:
//! - **Collision Attacks**: Different inputs can produce the same hash
//! - **Preimage Attacks**: Possible to find inputs for a given hash
//! - **Length Extension**: Vulnerable to length extension attacks
//!
//! ## Acceptable Uses
//!
//! - File integrity checking (non-security critical)
//! - Legacy system compatibility
//! - Educational cryptography study
//! - Checksums for error detection
//!
//! ## Examples
//!
//! ```rust
//! use ruscrypt::hash::md5;
//!
//! // Basic MD5 hashing
//! let hash = md5::hash("Hello, World!").unwrap();
//! println!("MD5: {}", hash); // Outputs 32 hex characters
//!
//! // Empty string
//! let empty_hash = md5::hash("").unwrap();
//! assert_eq!(empty_hash, "d41d8cd98f00b204e9800998ecf8427e");
//! ```

use anyhow::Result;

/// Computes the MD5 hash of the input text.
///
/// This function takes a string input, converts it to bytes, processes it through
/// the MD5 algorithm, and returns the resulting hash as a hexadecimal string.
///
/// # Arguments
///
/// * `input` - The text to hash
///
/// # Returns
///
/// Returns a 32-character hexadecimal string representing the 128-bit MD5 hash.
///
/// # Algorithm Steps
///
/// 1. Convert input string to bytes
/// 2. Apply MD5 algorithm to produce 16-byte hash
/// 3. Convert each byte to 2-digit hexadecimal
/// 4. Concatenate to form final hash string
///
/// # Examples
///
/// ```rust
/// use ruscrypt::hash::md5;
///
/// // Hash a simple message
/// let hash = md5::hash("The quick brown fox").unwrap();
/// println!("Hash: {}", hash);
///
/// // MD5 of empty string is always the same
/// let empty = md5::hash("").unwrap();
/// assert_eq!(empty, "d41d8cd98f00b204e9800998ecf8427e");
///
/// // Different inputs produce different hashes
/// let hash1 = md5::hash("message1").unwrap();
/// let hash2 = md5::hash("message2").unwrap();
/// assert_ne!(hash1, hash2);
/// ```
///
/// # Output Format
///
/// The returned string is always exactly 32 characters long, containing
/// only lowercase hexadecimal digits (0-9, a-f).
///
/// # Errors
///
/// This function is currently infallible and always returns `Ok(hash)`.
/// The `Result` return type is maintained for consistency with other hash
/// functions and potential future error conditions.
pub fn hash(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let hash_bytes = md5_hash(bytes);

    // Convert to hexadecimal string
    let hex_string = hash_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    Ok(hex_string)
}

/// Core MD5 implementation following RFC 1321 specification.
///
/// This function implements the complete MD5 algorithm including message
/// padding, length appending, and the 64-round compression function.
///
/// # Arguments
///
/// * `input` - Raw bytes to hash
///
/// # Returns
///
/// Returns a 16-byte array containing the MD5 hash.
///
/// # Algorithm Details
///
/// ## Initialization
/// - Four 32-bit words initialized to specific constants
/// - These are the fractional parts of square roots of small integers
///
/// ## Preprocessing
/// 1. **Padding**: Append '1' bit followed by '0' bits
/// 2. **Length**: Append original message length as 64-bit little-endian
/// 3. **Result**: Message length ≡ 0 (mod 512)
///
/// ## Processing
/// - Process message in 512-bit (64-byte) chunks
/// - Each chunk undergoes 64 rounds of operations
/// - Four different auxiliary functions used across rounds
///
/// ## Constants
/// - **K[i]**: 64 constants derived from sine function
/// - **S[i]**: Shift amounts for left rotation operations
///
/// # Round Functions
///
/// - **F(B,C,D) = (B ∧ C) ∨ (¬B ∧ D)**: Rounds 0-15
/// - **G(B,C,D) = (D ∧ B) ∨ (¬D ∧ C)**: Rounds 16-31  
/// - **H(B,C,D) = B ⊕ C ⊕ D**: Rounds 32-47
/// - **I(B,C,D) = C ⊕ (B ∨ ¬D)**: Rounds 48-63
///
/// # Security Note
///
/// This implementation is for educational purposes. The MD5 algorithm
/// itself is cryptographically broken and should not be used for
/// security-critical applications.
fn md5_hash(input: &[u8]) -> [u8; 16] {
    // MD5 constants
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    // Shift amounts for each round
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    // Initialize hash values
    let mut h = [0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32];

    // Pre-processing: add padding
    let mut message = input.to_vec();
    let original_len = message.len() as u64;

    // Append '1' bit (plus seven '0' bits, represented as 0x80)
    message.push(0x80);

    // Append '0' bits until message length ≡ 448 (mod 512)
    while (message.len() % 64) != 56 {
        message.push(0);
    }

    // Append original length as 64-bit little-endian
    message.extend_from_slice(&(original_len * 8).to_le_bytes());

    // Process message in 512-bit chunks
    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 16];

        // Break chunk into sixteen 32-bit little-endian words
        for (i, word_bytes) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_le_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }

        // Initialize hash value for this chunk
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];

        // Main loop
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                48..=63 => (c ^ (b | !d), (7 * i) % 16),
                _ => unreachable!(),
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(w[g])).rotate_left(S[i]),
            );
            a = temp;
        }

        // Add this chunk's hash to result
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }

    // Convert to bytes (little-endian)
    let mut result = [0u8; 16];
    for (i, &word) in h.iter().enumerate() {
        let bytes = word.to_le_bytes();
        result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    result
}
