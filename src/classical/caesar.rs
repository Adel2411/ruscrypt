use anyhow::Result;

use crate::utils::shift_char;

/// Encrypts text using Caesar cipher
pub fn encrypt(text: &str, shift: u8) -> Result<String> {
    let shift = shift % 26; // Ensure shift is within valid range
    let result = text
        .chars()
        .map(|c| shift_char(c, shift))
        .collect();
    Ok(result)
}

/// Decrypts text using Caesar cipher
pub fn decrypt(text: &str, shift: u8) -> Result<String> {
    let shift = shift % 26;
    let reverse_shift = (26 - shift) % 26;
    let result = text
        .chars()
        .map(|c| shift_char(c, reverse_shift))
        .collect();
    Ok(result)
}
