//! # Vigenère Cipher Implementation
//!
//! The Vigenère cipher is a polyalphabetic substitution cipher that uses a keyword
//! to encrypt text. It's more secure than the Caesar cipher but still not suitable
//! for modern cryptographic applications.
//!
//! ⚠️ **Security Warning**: The Vigenère cipher has known vulnerabilities and should
//! only be used for educational purposes.
//!
//! ## How it works
//!
//! 1. Repeat the keyword to match the length of the message
//! 2. For each letter, shift it by the corresponding keyword letter's position
//! 3. Non-alphabetic characters are preserved
//!
//! ## Examples
//!
//! ```rust
//! use ruscrypt::classical::vigenere;
//!
//! let encrypted = vigenere::encrypt("HELLO WORLD", "KEY").unwrap();
//! let decrypted = vigenere::decrypt(&encrypted, "KEY").unwrap();
//! assert_eq!(decrypted, "HELLO WORLD");
//! ```

use anyhow::Result;

use crate::utils::shift_char;

/// Encrypts text using the Vigenère cipher algorithm.
///
/// Uses a keyword to determine the shift amount for each letter. The keyword
/// is repeated cyclically to match the length of the message.
///
/// # Arguments
///
/// * `text` - The plaintext to encrypt
/// * `keyword` - The keyword used for encryption (must contain at least one alphabetic character)
///
/// # Returns
///
/// Returns the encrypted text as a `Result<String>`.
///
/// # Errors
///
/// Returns an error if:
/// - The keyword is empty
/// - The keyword contains no alphabetic characters
///
/// # Examples
///
/// ```rust
/// use ruscrypt::classical::vigenere;
///
/// // Basic encryption
/// let result = vigenere::encrypt("HELLO", "KEY").unwrap();
/// assert_eq!(result, "RIJVS");
///
/// // Mixed case and punctuation
/// let result2 = vigenere::encrypt("Hello, World!", "SECRET").unwrap();
/// // Non-alphabetic characters remain unchanged
/// ```
pub fn encrypt(text: &str, keyword: &str) -> Result<String> {
    if keyword.is_empty() {
        return Err(anyhow::anyhow!("Keyword cannot be empty"));
    }

    let keyword_upper = keyword.to_uppercase();
    let keyword_chars: Vec<char> = keyword_upper
        .chars()
        .filter(|c| c.is_alphabetic())
        .collect();

    if keyword_chars.is_empty() {
        return Err(anyhow::anyhow!(
            "Keyword must contain at least one alphabetic character"
        ));
    }

    let mut key_index = 0;
    let result = text
        .chars()
        .map(|c| {
            if c.is_alphabetic() {
                let key_char = keyword_chars[key_index % keyword_chars.len()];
                let shift = (key_char as u8 - b'A') as u8;
                key_index += 1;
                shift_char(c, shift)
            } else {
                c
            }
        })
        .collect();

    Ok(result)
}

/// Decrypts text encrypted with the Vigenère cipher.
///
/// Uses the same keyword that was used for encryption to reverse the process.
///
/// # Arguments
///
/// * `text` - The ciphertext to decrypt
/// * `keyword` - The keyword used for encryption (must contain at least one alphabetic character)
///
/// # Returns
///
/// Returns the decrypted text as a `Result<String>`.
///
/// # Errors
///
/// Returns an error if:
/// - The keyword is empty
/// - The keyword contains no alphabetic characters
///
/// # Examples
///
/// ```rust
/// use ruscrypt::classical::vigenere;
///
/// let encrypted = "RIJVS";
/// let result = vigenere::decrypt(encrypted, "KEY").unwrap();
/// assert_eq!(result, "HELLO");
/// ```
pub fn decrypt(text: &str, keyword: &str) -> Result<String> {
    if keyword.is_empty() {
        return Err(anyhow::anyhow!("Keyword cannot be empty"));
    }

    let keyword_upper = keyword.to_uppercase();
    let keyword_chars: Vec<char> = keyword_upper
        .chars()
        .filter(|c| c.is_alphabetic())
        .collect();

    if keyword_chars.is_empty() {
        return Err(anyhow::anyhow!(
            "Keyword must contain at least one alphabetic character"
        ));
    }

    let mut key_index = 0;
    let result = text
        .chars()
        .map(|c| {
            if c.is_alphabetic() {
                let key_char = keyword_chars[key_index % keyword_chars.len()];
                let shift = (key_char as u8 - b'A') as u8;
                let reverse_shift = (26 - shift) % 26;
                key_index += 1;
                shift_char(c, reverse_shift)
            } else {
                c
            }
        })
        .collect();

    Ok(result)
}

