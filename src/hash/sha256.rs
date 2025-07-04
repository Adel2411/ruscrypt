//! # SHA-256 Hash Function Implementation
//!
//! SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function
//! that produces a 256-bit (32-byte) hash value, typically rendered as a
//! 64-character hexadecimal string.
//!
//! ✅ **Security Status**: SHA-256 is considered cryptographically secure
//! and is widely used in modern applications including Bitcoin and TLS.
//!
//! ## Properties
//!
//! - **Deterministic**: Same input always produces same hash
//! - **Fixed size**: Always outputs 256 bits (64 hex characters)
//! - **Avalanche effect**: Small input changes cause large output changes
//! - **One-way**: Computationally infeasible to reverse
//!
//! ## Examples
//!
//! ```rust
//! use ruscrypt::hash::sha256;
//!
//! let hash = sha256::hash("Hello, World!").unwrap();
//! println!("SHA-256: {}", hash);
//! assert_eq!(hash.len(), 64); // Always 64 hex characters
//!
//! // Different inputs produce different hashes
//! let hash1 = sha256::hash("Hello").unwrap();
//! let hash2 = sha256::hash("Hello!").unwrap();
//! assert_ne!(hash1, hash2);
//! ```

use anyhow::Result;

/// Computes the SHA-256 hash of the input text.
///
/// This function implements the complete SHA-256 algorithm including:
/// - Message preprocessing and padding
/// - Processing in 512-bit blocks
/// - 64 rounds of compression per block
/// - Final hash value computation
///
/// # Arguments
///
/// * `input` - The text to hash (any UTF-8 string)
///
/// # Returns
///
/// Returns a 64-character lowercase hexadecimal string representing the
/// 256-bit hash value.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::hash::sha256;
///
/// // Empty string
/// let hash = sha256::hash("").unwrap();
/// assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
///
/// // Simple text
/// let hash = sha256::hash("abc").unwrap();
/// assert_eq!(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
///
/// // Unicode support
/// let hash = sha256::hash("Hello 世界").unwrap();
/// assert_eq!(hash.len(), 64);
///
/// // Consistency check
/// let hash1 = sha256::hash("test").unwrap();
/// let hash2 = sha256::hash("test").unwrap();
/// assert_eq!(hash1, hash2);
/// ```
///
/// # Algorithm Details
///
/// The implementation follows RFC 6234 and includes:
/// - Proper message padding with length encoding
/// - 64 rounds of SHA-256 compression function
/// - Correct handling of endianness
/// - Support for messages of any length
pub fn hash(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let hash_bytes = sha256_hash(bytes);

    // Convert to hexadecimal string
    let hex_string = hash_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    Ok(hex_string)
}

/// Core SHA-256 implementation that processes the padded message.
///
/// This function implements the SHA-256 algorithm as specified in FIPS 180-4.
/// It processes the input in 512-bit chunks and applies the compression function.
///
/// # Arguments
///
/// * `input` - Raw bytes to hash
///
/// # Returns
///
/// Returns a 32-byte array containing the hash value.
///
/// # Implementation Notes
///
/// - Uses the official SHA-256 constants and round functions
/// - Processes message in 512-bit (64-byte) blocks
/// - Applies proper padding according to the standard
/// - Implements the complete message schedule and compression
fn sha256_hash(input: &[u8]) -> [u8; 32] {
    // SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    // Initialize hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    let mut h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
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
        let mut w = [0u32; 64];

        // Break chunk into sixteen 32-bit big-endian words
        for (i, word_bytes) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }

        // Extend the first 16 words into the remaining 48 words
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let mut a: u32 = h[0];
        let mut b: u32 = h[1];
        let mut c: u32 = h[2];
        let mut d: u32 = h[3];
        let mut e: u32 = h[4];
        let mut f: u32 = h[5];
        let mut g: u32 = h[6];
        let mut h_var: u32 = h[7];

        // Main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_var
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_var = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add this chunk's hash to result
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_var);
    }

    // Convert to bytes (big-endian)
    let mut result = [0u8; 32];
    for (i, &word) in h.iter().enumerate() {
        let bytes = word.to_be_bytes();
        result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    result
}
