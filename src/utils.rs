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

/// Converts bytes to hexadecimal string
pub fn to_hex(data: &[u8]) -> String {
    data.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

/// Converts hex string to bytes
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

/// Pads data to the specified block size using PKCS#7 padding
pub fn pad_data(data: &[u8]) -> Vec<u8> {
    pad_data_to_size(data, 16) // Default to 16-byte blocks for AES
}

/// Pads data to a specific block size using PKCS#7 padding
pub fn pad_data_to_size(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut padded = data.to_vec();
    let padding_needed = block_size - (data.len() % block_size);
    
    // Always add padding, even if data length is multiple of block size
    for _ in 0..padding_needed {
        padded.push(padding_needed as u8);
    }
    
    padded
}

/// Removes PKCS#7 padding from data
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