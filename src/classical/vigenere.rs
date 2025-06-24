use anyhow::Result;

/// Encrypts text using Vigenère cipher
pub fn encrypt(text: &str, keyword: &str) -> Result<String> {
    if keyword.is_empty() {
        return Err(anyhow::anyhow!("Keyword cannot be empty"));
    }
    
    let keyword_upper = keyword.to_uppercase();
    let keyword_chars: Vec<char> = keyword_upper.chars().filter(|c| c.is_alphabetic()).collect();
    
    if keyword_chars.is_empty() {
        return Err(anyhow::anyhow!("Keyword must contain at least one alphabetic character"));
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

/// Decrypts text using Vigenère cipher
pub fn decrypt(text: &str, keyword: &str) -> Result<String> {
    if keyword.is_empty() {
        return Err(anyhow::anyhow!("Keyword cannot be empty"));
    }
    
    let keyword_upper = keyword.to_uppercase();
    let keyword_chars: Vec<char> = keyword_upper.chars().filter(|c| c.is_alphabetic()).collect();
    
    if keyword_chars.is_empty() {
        return Err(anyhow::anyhow!("Keyword must contain at least one alphabetic character"));
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

/// Shifts a single character by the given amount (reused from Caesar)
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
        _ => c,
    }
}
