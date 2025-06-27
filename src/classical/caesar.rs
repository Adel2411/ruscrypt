//! # Caesar Cipher Implementation
//! 
//! The Caesar cipher is one of the simplest and most well-known encryption techniques.
//! It is a substitution cipher where each letter is shifted by a fixed number of positions
//! in the alphabet.
//! 
//! ⚠️ **Security Warning**: The Caesar cipher is **not secure** for modern use and should
//! only be used for educational purposes or simple text obfuscation.
//! 
//! ## Examples
//! 
//! ```rust
//! use ruscrypt::classical::caesar;
//! 
//! // Encrypt a message
//! let encrypted = caesar::encrypt("HELLO", 3).unwrap();
//! assert_eq!(encrypted, "KHOOR");
//! 
//! // Decrypt the message
//! let decrypted = caesar::decrypt(&encrypted, 3).unwrap();
//! assert_eq!(decrypted, "HELLO");
//! ```

use anyhow::Result;

use crate::utils::shift_char;

/// Encrypts text using the Caesar cipher algorithm.
/// 
/// Each alphabetic character is shifted forward by the specified number of positions
/// in the alphabet. Non-alphabetic characters remain unchanged.
/// 
/// # Arguments
/// 
/// * `text` - The plaintext to encrypt
/// * `shift` - Number of positions to shift (0-25, values > 25 are automatically reduced)
/// 
/// # Returns
/// 
/// Returns the encrypted text as a `Result<String>`.
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::classical::caesar;
/// 
/// let result = caesar::encrypt("Hello, World!", 3).unwrap();
/// assert_eq!(result, "Khoor, Zruog!");
/// 
/// // Large shift values are automatically reduced modulo 26
/// let result2 = caesar::encrypt("ABC", 29).unwrap(); // 29 % 26 = 3
/// assert_eq!(result2, "DEF");
/// ```
pub fn encrypt(text: &str, shift: u8) -> Result<String> {
    let shift = shift % 26;
    let result = text
        .chars()
        .map(|c| shift_char(c, shift))
        .collect();
    Ok(result)
}

/// Decrypts text encrypted with the Caesar cipher.
/// 
/// Each alphabetic character is shifted backward by the specified number of positions
/// in the alphabet. Non-alphabetic characters remain unchanged.
/// 
/// # Arguments
/// 
/// * `text` - The ciphertext to decrypt
/// * `shift` - Number of positions the original text was shifted (0-25)
/// 
/// # Returns
/// 
/// Returns the decrypted text as a `Result<String>`.
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::classical::caesar;
/// 
/// let encrypted = "Khoor, Zruog!";
/// let result = caesar::decrypt(encrypted, 3).unwrap();
/// assert_eq!(result, "Hello, World!");
/// ```
pub fn decrypt(text: &str, shift: u8) -> Result<String> {
    let shift = shift % 26;
    let reverse_shift = (26 - shift) % 26;
    let result = text
        .chars()
        .map(|c| shift_char(c, reverse_shift))
        .collect();
    Ok(result)
}
