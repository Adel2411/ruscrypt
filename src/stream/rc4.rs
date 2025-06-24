use anyhow::Result;
use crate::utils::{to_base64, from_base64};

/// Encrypts data using RC4 stream cipher with specified encoding
pub fn encrypt(data: &str, key: &str, encoding: &str) -> Result<String> {
    if key.is_empty() {
        return Err(anyhow::anyhow!("Key cannot be empty"));
    }
    
    let key_bytes = key.as_bytes();
    let data_bytes = data.as_bytes();
    let keystream = generate_keystream(key_bytes, data_bytes.len())?;
    
    let encrypted: Vec<u8> = data_bytes
        .iter()
        .zip(keystream.iter())
        .map(|(d, k)| d ^ k)
        .collect();
    
    // Convert to specified encoding
    match encoding.to_lowercase().as_str() {
        "base64" => Ok(to_base64(&encrypted)),
        "hex" => Ok(to_hex(&encrypted)),
        _ => Err(anyhow::anyhow!("Unsupported encoding: {}. Use 'base64' or 'hex'", encoding))
    }
}

/// Decrypts data using RC4 stream cipher with specified encoding
pub fn decrypt(data: &str, key: &str, encoding: &str) -> Result<String> {
    if key.is_empty() {
        return Err(anyhow::anyhow!("Key cannot be empty"));
    }
    
    // Convert from specified encoding back to bytes
    let encrypted_bytes = match encoding.to_lowercase().as_str() {
        "base64" => from_base64(data)?,
        "hex" => from_hex(data)?,
        _ => return Err(anyhow::anyhow!("Unsupported encoding: {}. Use 'base64' or 'hex'", encoding))
    };
    
    let key_bytes = key.as_bytes();
    let keystream = generate_keystream(key_bytes, encrypted_bytes.len())?;
    
    let decrypted: Vec<u8> = encrypted_bytes
        .iter()
        .zip(keystream.iter())
        .map(|(d, k)| d ^ k)
        .collect();
    
    // Convert back to string
    String::from_utf8(decrypted)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in decrypted data: {}", e))
}

/// Converts bytes to hexadecimal string
fn to_hex(data: &[u8]) -> String {
    data.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}

/// Converts hex string to bytes
fn from_hex(hex: &str) -> Result<Vec<u8>> {
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

/// Generates RC4 keystream
fn generate_keystream(key: &[u8], length: usize) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(anyhow::anyhow!("Key cannot be empty"));
    }
    
    // Key Scheduling Algorithm (KSA)
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: u8 = 0;
    
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    
    // Pseudo-Random Generation Algorithm (PRGA)
    let mut keystream = Vec::with_capacity(length);
    let mut i: u8 = 0;
    j = 0;
    
    for _ in 0..length {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        keystream.push(k);
    }
    
    Ok(keystream)
}
