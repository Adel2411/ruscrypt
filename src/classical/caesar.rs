use anyhow::Result;

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

/// Shifts a single character by the given amount
fn shift_char(c: char, shift: u8) -> char {
    match c {
        'A'..='Z' => {
            let shifted = ((c as u8 - b'A' + shift) % 26) + b'A';
            shifted as char
        }
        'a'..='z' => {
            let shifted = ((c as u8 - b'a' + shift) % 26) + b'a';
            shifted as char
        }
        _ => c, // Non-alphabetic characters remain unchanged
    }
}
