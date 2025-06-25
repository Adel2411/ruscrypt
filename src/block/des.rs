use anyhow::Result;
use crate::utils::{to_base64, from_base64, to_hex, from_hex, pad_data_to_size, remove_padding};

/// Encrypts data using simplified DES with specified mode and encoding
/// 
/// DES (Data Encryption Standard) requires exactly 8 bytes (64 bits) for the key.
/// This is a fundamental requirement of the DES algorithm specification.
/// 
/// # Key Requirements
/// - Must be exactly 8 characters long (8 bytes = 64 bits)
/// - Each character represents 8 bits of the key
/// - Original DES uses 56 effective bits (8 bits are parity bits)
/// 
/// # Modes
/// - ECB (Electronic Codebook): Each block encrypted independently
/// - CBC (Cipher Block Chaining): Each block XORed with previous ciphertext
pub fn encrypt(data: &str, key: &str, mode: &str, encoding: &str) -> Result<String> {
    if key.len() != 8 {
        return Err(anyhow::anyhow!(
            "DES key must be exactly 8 characters long (64 bits). Current length: {} characters. 
            DES was standardized to use a 64-bit key, where each ASCII character = 8 bits.",
            key.len()
        ));
    }
    
    let key_bytes = key.as_bytes();
    let data_bytes = pad_data_to_size(data.as_bytes(), 8); // Use 8-byte padding for DES
    
    let encrypted = match mode.to_lowercase().as_str() {
        "ecb" => encrypt_ecb(&data_bytes, key_bytes)?,
        "cbc" => encrypt_cbc(&data_bytes, key_bytes)?,
        _ => return Err(anyhow::anyhow!("Unsupported mode: {}. Use 'ECB' or 'CBC'", mode))
    };
    
    // Convert to specified encoding
    match encoding.to_lowercase().as_str() {
        "base64" => Ok(to_base64(&encrypted)),
        "hex" => Ok(to_hex(&encrypted)),
        _ => Err(anyhow::anyhow!("Unsupported encoding: {}. Use 'base64' or 'hex'", encoding))
    }
}

/// Decrypts data using simplified DES with specified mode and encoding
/// 
/// # Key Requirements
/// Same as encrypt() - exactly 8 characters (64 bits) required
pub fn decrypt(data: &str, key: &str, mode: &str, encoding: &str) -> Result<String> {
    if key.len() != 8 {
        return Err(anyhow::anyhow!(
            "DES key must be exactly 8 characters long (64 bits). Current length: {} characters.
            This is a fixed requirement of the DES algorithm specification.",
            key.len()
        ));
    }
    
    // Convert from specified encoding
    let encrypted_bytes = match encoding.to_lowercase().as_str() {
        "base64" => from_base64(data)?,
        "hex" => from_hex(data)?,
        _ => return Err(anyhow::anyhow!("Unsupported encoding: {}. Use 'base64' or 'hex'", encoding))
    };
    
    let key_bytes = key.as_bytes();
    
    let decrypted = match mode.to_lowercase().as_str() {
        "ecb" => decrypt_ecb(&encrypted_bytes, key_bytes)?,
        "cbc" => decrypt_cbc(&encrypted_bytes, key_bytes)?,
        _ => return Err(anyhow::anyhow!("Unsupported mode: {}. Use 'ECB' or 'CBC'", mode))
    };
    
    // Remove padding and convert to string
    let unpadded = remove_padding(&decrypted)?;
    String::from_utf8(unpadded)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in decrypted data: {}", e))
}

/// DES encryption in ECB mode
fn encrypt_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut encrypted = Vec::new();
    
    for chunk in data.chunks(8) {
        let encrypted_block = des_encrypt_block(chunk, key)?;
        encrypted.extend_from_slice(&encrypted_block);
    }
    
    Ok(encrypted)
}

/// DES decryption in ECB mode
fn decrypt_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut decrypted = Vec::new();
    
    for chunk in data.chunks(8) {
        if chunk.len() != 8 {
            return Err(anyhow::anyhow!("Invalid encrypted data length"));
        }
        let decrypted_block = des_decrypt_block(chunk, key)?;
        decrypted.extend_from_slice(&decrypted_block);
    }
    
    Ok(decrypted)
}

/// DES encryption in CBC mode
fn encrypt_cbc(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut encrypted = Vec::new();
    let mut previous_block = [0u8; 8]; // IV (Initialization Vector) - all zeros for simplicity
    
    for chunk in data.chunks(8) {
        // XOR with previous ciphertext (or IV for first block)
        let mut xor_block = [0u8; 8];
        for (i, &byte) in chunk.iter().enumerate() {
            if i < 8 {
                xor_block[i] = byte ^ previous_block[i];
            }
        }
        
        let encrypted_block = des_encrypt_block(&xor_block, key)?;
        encrypted.extend_from_slice(&encrypted_block);
        previous_block = encrypted_block;
    }
    
    Ok(encrypted)
}

/// DES decryption in CBC mode
fn decrypt_cbc(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut decrypted = Vec::new();
    let mut previous_block = [0u8; 8]; // IV (Initialization Vector) - all zeros for simplicity
    
    for chunk in data.chunks(8) {
        if chunk.len() != 8 {
            return Err(anyhow::anyhow!("Invalid encrypted data length"));
        }
        
        let decrypted_block = des_decrypt_block(chunk, key)?;
        
        // XOR with previous ciphertext (or IV for first block)
        let mut final_block = [0u8; 8];
        for i in 0..8 {
            final_block[i] = decrypted_block[i] ^ previous_block[i];
        }
        
        decrypted.extend_from_slice(&final_block);
        previous_block.copy_from_slice(chunk);
    }
    
    Ok(decrypted)
}

/// Simplified DES encryption for educational purposes
fn des_encrypt_block(block: &[u8], key: &[u8]) -> Result<[u8; 8]> {
    let mut state = [0u8; 8];
    
    // Copy input block
    for (i, &byte) in block.iter().enumerate() {
        if i < 8 {
            state[i] = byte;
        }
    }
    
    // Simplified DES rounds (16 rounds normally)
    for round in 0..16 {
        for i in 0..8 {
            state[i] ^= key[round % 8];
            state[i] = state[i].wrapping_add(round as u8);
            state[i] = state[i].rotate_left(1);
        }
        
        // Simple permutation
        state.reverse();
    }
    
    Ok(state)
}

/// Simplified DES decryption
fn des_decrypt_block(block: &[u8], key: &[u8]) -> Result<[u8; 8]> {
    let mut state: [u8; 8] = block.try_into().unwrap();
    
    // Reverse the encryption process
    for round in (0..16).rev() {
        // Reverse permutation
        state.reverse();
        
        for i in 0..8 {
            state[i] = state[i].rotate_right(1);
            state[i] = state[i].wrapping_sub(round as u8);
            state[i] ^= key[round % 8];
        }
    }
    
    Ok(state)
}