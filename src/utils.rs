use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};

/// Encode binary data to Base64 string
pub fn to_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decode Base64 string to binary data
pub fn from_base64(encoded: &str) -> Result<Vec<u8>> {
    let decoded = general_purpose::STANDARD.decode(encoded)?;
    Ok(decoded)
}

/// Shifts a single character by the given amount
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