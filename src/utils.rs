//! # Utility Functions for Cryptographic Operations
//!
//! This module provides common utility functions used throughout the RusCrypt library,
//! including encoding/decoding, padding, and character manipulation functions.
//!
//! ## Features
//!
//! - **Encoding**: Base64 and hexadecimal encoding/decoding
//! - **Padding**: PKCS#7 padding for block ciphers
//! - **Character operations**: Caesar cipher character shifting
//!
//! ## Examples
//!
//! ```rust
//! use ruscrypt::utils::{to_base64, from_base64, to_hex, from_hex};
//!
//! let data = b"Hello, World!";
//! let base64 = to_base64(data);
//! let decoded = from_base64(&base64).unwrap();
//! assert_eq!(data, &decoded[..]);
//! ```

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};

/// Encodes binary data to a Base64 string.
///
/// Uses the standard Base64 alphabet (A-Z, a-z, 0-9, +, /) with padding.
///
/// # Arguments
///
/// * `data` - The binary data to encode
///
/// # Returns
///
/// Returns the Base64-encoded string.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::utils::to_base64;
///
/// let data = b"Hello, World!";
/// let encoded = to_base64(data);
/// println!("Base64: {}", encoded);
/// ```
pub fn to_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decodes a Base64 string to binary data.
///
/// Accepts standard Base64 format with optional padding.
///
/// # Arguments
///
/// * `encoded` - The Base64-encoded string
///
/// # Returns
///
/// Returns the decoded binary data.
///
/// # Errors
///
/// Returns an error if the input is not valid Base64.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::utils::{to_base64, from_base64};
///
/// let original = b"Hello, World!";
/// let encoded = to_base64(original);
/// let decoded = from_base64(&encoded).unwrap();
/// assert_eq!(original, &decoded[..]);
/// ```
pub fn from_base64(encoded: &str) -> Result<Vec<u8>> {
    let decoded = general_purpose::STANDARD.decode(encoded)?;
    Ok(decoded)
}

/// Converts binary data to a lowercase hexadecimal string.
///
/// Each byte is represented as two hexadecimal digits (0-9, a-f).
///
/// # Arguments
///
/// * `data` - The binary data to convert
///
/// # Returns
///
/// Returns the hexadecimal string representation.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::utils::to_hex;
///
/// let data = &[0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello" in ASCII
/// let hex = to_hex(data);
/// assert_eq!(hex, "48656c6c6f");
/// ```
pub fn to_hex(data: &[u8]) -> String {
    data.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

/// Converts a hexadecimal string to binary data.
///
/// Accepts lowercase and uppercase hexadecimal digits (0-9, a-f, A-F).
///
/// # Arguments
///
/// * `hex` - The hexadecimal string (must have even length)
///
/// # Returns
///
/// Returns the binary data as a vector of bytes.
///
/// # Errors
///
/// Returns an error if:
/// - The hex string has odd length
/// - The hex string contains invalid characters
///
/// # Examples
///
/// ```rust
/// use ruscrypt::utils::{to_hex, from_hex};
///
/// let original = &[0x48, 0x65, 0x6c, 0x6c, 0x6f];
/// let hex = to_hex(original);
/// let decoded = from_hex(&hex).unwrap();
/// assert_eq!(original, &decoded[..]);
///
/// // Case insensitive
/// let decoded2 = from_hex("48656C6C6F").unwrap();
/// assert_eq!(original, &decoded2[..]);
/// ```
pub fn from_hex(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(anyhow::anyhow!("Hex string must have even length"));
    }

    hex.chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|chunk| {
            let hex_str: String = chunk.iter().collect();
            u8::from_str_radix(&hex_str, 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex character: {}", e))
        })
        .collect()
}

/// Shifts a single character by the specified amount for Caesar cipher.
///
/// Only alphabetic characters are shifted; others remain unchanged.
/// Shifting wraps around the alphabet (Z shifts to A, z shifts to a).
///
/// # Arguments
///
/// * `c` - The character to shift
/// * `shift` - Number of positions to shift (0-25)
///
/// # Returns
///
/// Returns the shifted character.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::utils::shift_char;
///
/// assert_eq!(shift_char('A', 3), 'D');
/// assert_eq!(shift_char('X', 3), 'A'); // Wraps around
/// assert_eq!(shift_char('a', 1), 'b');
/// assert_eq!(shift_char('!', 5), '!'); // Non-alphabetic unchanged
/// ```
pub fn shift_char(c: char, shift: u8) -> char {
    match c {
        'A'..='Z' => {
            let shifted = ((c as u8 - b'A' + shift) % 26) + b'A';
            shifted as char
        }
        'a'..='z' => {
            let shifted = ((c as u8 - b'a' + shift) % 26) + b'a';
            shifted as char
        }
        _ => c,
    }
}

/// Pads data to 16-byte blocks using PKCS#7 padding.
///
/// This is a convenience function that calls `pad_data_to_size` with
/// a block size of 16 bytes (standard for AES).
///
/// # Arguments
///
/// * `data` - The data to pad
///
/// # Returns
///
/// Returns the padded data.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::utils::pad_data;
///
/// let data = b"Hello"; // 5 bytes
/// let padded = pad_data(data);
/// assert_eq!(padded.len(), 16); // Padded to 16 bytes
/// assert_eq!(padded[15], 11); // Padding value (16 - 5 = 11)
/// ```
pub fn pad_data(data: &[u8]) -> Vec<u8> {
    pad_data_to_size(data, 16) // Default to 16-byte blocks for AES
}

/// Pads data to the specified block size using PKCS#7 padding.
///
/// PKCS#7 padding adds bytes equal to the number of padding bytes needed.
/// Always adds padding, even if the data length is already a multiple
/// of the block size.
///
/// # Arguments
///
/// * `data` - The data to pad
/// * `block_size` - The target block size
///
/// # Returns
///
/// Returns the padded data.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::utils::pad_data_to_size;
///
/// // Pad to 8-byte blocks
/// let data = b"Hello"; // 5 bytes
/// let padded = pad_data_to_size(data, 8);
/// assert_eq!(padded.len(), 8);
/// assert_eq!(padded[7], 3); // 3 padding bytes added
///
/// // Even when data is multiple of block size
/// let data2 = b"12345678"; // 8 bytes (exact fit)
/// let padded2 = pad_data_to_size(data2, 8);
/// assert_eq!(padded2.len(), 16); // Full block of padding added
/// ```
pub fn pad_data_to_size(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut padded = data.to_vec();
    let padding_needed = block_size - (data.len() % block_size);

    // Always add padding, even if data length is multiple of block size
    for _ in 0..padding_needed {
        padded.push(padding_needed as u8);
    }

    padded
}

/// Removes PKCS#7 padding from padded data.
///
/// Validates that the padding is correct before removing it.
/// The padding value indicates how many bytes to remove.
///
/// # Arguments
///
/// * `data` - The padded data
///
/// # Returns
///
/// Returns the original data with padding removed.
///
/// # Errors
///
/// Returns an error if:
/// - The data is empty
/// - The padding length is invalid (0, > 16, or > data length)
/// - The padding bytes are inconsistent
///
/// # Examples
///
/// ```rust
/// use ruscrypt::utils::{pad_data_to_size, remove_padding};
///
/// let original = b"Hello, World!";
/// let padded = pad_data_to_size(original, 16);
/// let unpadded = remove_padding(&padded).unwrap();
/// assert_eq!(original, &unpadded[..]);
/// ```
pub fn remove_padding(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let padding_length = data[data.len() - 1] as usize;

    // Validate padding length
    if padding_length == 0 || padding_length > 16 || padding_length > data.len() {
        return Err(anyhow::anyhow!("Invalid padding"));
    }

    // Verify all padding bytes are correct
    for i in (data.len() - padding_length)..data.len() {
        if data[i] != padding_length as u8 {
            return Err(anyhow::anyhow!("Invalid padding"));
        }
    }

    Ok(data[..data.len() - padding_length].to_vec())
}

