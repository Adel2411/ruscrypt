//! # DES (Data Encryption Standard) Implementation
//! 
//! This module provides a simplified educational implementation of the DES block cipher.
//! DES was the standard encryption algorithm from 1977 to 2001 but is now considered
//! cryptographically broken due to its small key size.
//! 
//! ⚠️ **Security Warning**: DES is **not secure** for modern use due to its 56-bit
//! effective key size. It can be broken by brute force in hours with modern hardware.
//! Use only for educational purposes or legacy system compatibility.
//! 
//! ## Algorithm Overview
//! 
//! - **Block Size**: 64 bits (8 bytes)
//! - **Key Size**: 64 bits (8 bytes) with 56 effective bits
//! - **Rounds**: 16 Feistel rounds
//! - **Structure**: Feistel network with substitution and permutation
//! 
//! ## Supported Modes
//! 
//! - **ECB (Electronic Codebook)**: Each block encrypted independently
//! - **CBC (Cipher Block Chaining)**: Each block XORed with previous ciphertext
//! 
//! ## Historical Context
//! 
//! DES was developed by IBM and adopted as a federal standard in 1977. It served
//! as the foundation for modern block cipher design but became vulnerable to
//! brute force attacks as computing power increased.
//! 
//! ## Examples
//! 
//! ```rust
//! use ruscrypt::block::des;
//! 
//! // Encrypt with DES-CBC
//! let encrypted = des::encrypt("Hello World", "password", "CBC", "base64").unwrap();
//! 
//! // Decrypt
//! let decrypted = des::decrypt(&encrypted, "password", "CBC", "base64").unwrap();
//! ```

use anyhow::Result;
use crate::utils::{to_base64, from_base64, to_hex, from_hex, pad_data_to_size, remove_padding};

/// Encrypts data using DES with specified mode and encoding.
/// 
/// This function implements a simplified version of DES for educational purposes.
/// It demonstrates the core concepts of block cipher encryption including
/// padding, mode operations, and output encoding.
/// 
/// # Arguments
/// 
/// * `data` - The plaintext data to encrypt
/// * `key` - Encryption key (must be exactly 8 characters/64 bits)
/// * `mode` - Encryption mode ("ECB" or "CBC")
/// * `encoding` - Output encoding ("base64" or "hex")
/// 
/// # Returns
/// 
/// Returns the encrypted data encoded in the specified format.
/// 
/// # Key Requirements
/// 
/// DES requires exactly 8 bytes (64 bits) for the key:
/// - Each ASCII character = 8 bits
/// - Total: 8 characters × 8 bits = 64 bits
/// - Effective key strength: 56 bits (8 bits used for parity)
/// 
/// # Modes of Operation
/// 
/// - **ECB**: Each 8-byte block encrypted independently
///   - Simple but vulnerable to pattern analysis
///   - Identical plaintext blocks produce identical ciphertext
/// 
/// - **CBC**: Each block XORed with previous ciphertext block
///   - More secure than ECB
///   - Uses zero initialization vector for simplicity
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::block::des;
/// 
/// // Encrypt with CBC mode and base64 encoding
/// let encrypted = des::encrypt("Secret message", "password", "CBC", "base64")?;
/// 
/// // Encrypt with ECB mode and hex encoding  
/// let encrypted = des::encrypt("Test data", "key12345", "ECB", "hex")?;
/// ```
/// 
/// # Errors
/// 
/// Returns an error if:
/// - Key length is not exactly 8 characters
/// - Mode is not "ECB" or "CBC"
/// - Encoding is not "base64" or "hex"
/// - Encryption process fails
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

/// Decrypts data encrypted with DES.
/// 
/// Reverses the DES encryption process using the same key and parameters
/// that were used during encryption. Handles decoding from the specified
/// format and removes padding from the result.
/// 
/// # Arguments
/// 
/// * `data` - The encrypted data in the specified encoding
/// * `key` - Decryption key (must match encryption key, 8 characters)
/// * `mode` - Decryption mode (must match encryption mode)
/// * `encoding` - Input encoding format ("base64" or "hex")
/// 
/// # Returns
/// 
/// Returns the decrypted plaintext as a UTF-8 string.
/// 
/// # Decryption Process
/// 
/// 1. Decode input from specified encoding (base64/hex)
/// 2. Apply reverse DES algorithm with specified mode
/// 3. Remove padding from decrypted blocks
/// 4. Convert result to UTF-8 string
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::block::des;
/// 
/// // Decrypt base64-encoded CBC ciphertext
/// let decrypted = des::decrypt("encrypted_data", "password", "CBC", "base64")?;
/// 
/// // Decrypt hex-encoded ECB ciphertext
/// let decrypted = des::decrypt("hex_data", "key12345", "ECB", "hex")?;
/// ```
/// 
/// # Errors
/// 
/// Returns an error if:
/// - Key length is not exactly 8 characters
/// - Mode is not "ECB" or "CBC"
/// - Encoding is not "base64" or "hex"
/// - Input data cannot be decoded from specified encoding
/// - Decrypted data is not valid UTF-8
/// - Padding removal fails
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

/// Encrypts data using DES in ECB mode.
/// 
/// Electronic Codebook mode encrypts each 8-byte block independently
/// using the same key. This is the simplest mode but has security
/// weaknesses due to pattern preservation.
/// 
/// # Arguments
/// 
/// * `data` - Padded input data (multiple of 8 bytes)
/// * `key` - 8-byte encryption key
/// 
/// # Returns
/// 
/// Returns the encrypted data as a byte vector.
/// 
/// # Security Note
/// 
/// ECB mode is vulnerable to pattern analysis because identical
/// plaintext blocks produce identical ciphertext blocks.
fn encrypt_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut encrypted = Vec::new();
    
    for chunk in data.chunks(8) {
        let encrypted_block = des_encrypt_block(chunk, key)?;
        encrypted.extend_from_slice(&encrypted_block);
    }
    
    Ok(encrypted)
}

/// Decrypts data using DES in ECB mode.
/// 
/// Reverses ECB encryption by decrypting each 8-byte block
/// independently using the same key.
/// 
/// # Arguments
/// 
/// * `data` - Encrypted data (multiple of 8 bytes)
/// * `key` - 8-byte decryption key
/// 
/// # Returns
/// 
/// Returns the decrypted data as a byte vector.
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

/// Encrypts data using DES in CBC mode.
/// 
/// Cipher Block Chaining mode XORs each plaintext block with the
/// previous ciphertext block before encryption. This provides better
/// security than ECB by eliminating patterns.
/// 
/// # Arguments
/// 
/// * `data` - Padded input data (multiple of 8 bytes)
/// * `key` - 8-byte encryption key
/// 
/// # Returns
/// 
/// Returns the encrypted data as a byte vector.
/// 
/// # CBC Process
/// 
/// 1. Initialize with zero IV (Initialization Vector)
/// 2. XOR first plaintext block with IV
/// 3. Encrypt XORed block to get first ciphertext block
/// 4. XOR next plaintext block with previous ciphertext block
/// 5. Repeat until all blocks are processed
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

/// Decrypts data using DES in CBC mode.
/// 
/// Reverses CBC encryption by decrypting each block and XORing
/// with the previous ciphertext block to recover plaintext.
/// 
/// # Arguments
/// 
/// * `data` - Encrypted data (multiple of 8 bytes)
/// * `key` - 8-byte decryption key
/// 
/// # Returns
/// 
/// Returns the decrypted data as a byte vector.
/// 
/// # CBC Decryption Process
/// 
/// 1. Decrypt first ciphertext block
/// 2. XOR result with IV (zero) to get first plaintext block
/// 3. Decrypt next ciphertext block
/// 4. XOR result with previous ciphertext block
/// 5. Repeat until all blocks are processed
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

/// Encrypts a single 8-byte block using simplified DES algorithm.
/// 
/// This is an educational implementation that demonstrates the concepts
/// of block cipher rounds, key mixing, and bit manipulation. It is not
/// the full DES specification but captures the essential ideas.
/// 
/// # Arguments
/// 
/// * `block` - 8-byte input block to encrypt
/// * `key` - 8-byte encryption key
/// 
/// # Returns
/// 
/// Returns the encrypted 8-byte block.
/// 
/// # Simplified DES Process
/// 
/// 1. Copy input block to working state
/// 2. Perform 16 rounds of:
///    - XOR with round key (derived from main key)
///    - Add round number for variation
///    - Rotate bits for diffusion
///    - Reverse array for permutation
/// 
/// # Note
/// 
/// This implementation prioritizes educational clarity over
/// cryptographic accuracy. Real DES uses complex S-boxes,
/// P-boxes, and a sophisticated key schedule.
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

/// Decrypts a single 8-byte block using simplified DES algorithm.
/// 
/// Reverses the encryption process by applying the same operations
/// in reverse order with appropriate inverse transformations.
/// 
/// # Arguments
/// 
/// * `block` - 8-byte encrypted block to decrypt
/// * `key` - 8-byte decryption key (same as encryption key)
/// 
/// # Returns
/// 
/// Returns the decrypted 8-byte block.
/// 
/// # Decryption Process
/// 
/// 1. Copy encrypted block to working state
/// 2. Perform 16 rounds in reverse order (15 down to 0):
///    - Reverse permutation (array reversal)
///    - Reverse rotation (rotate right instead of left)
///    - Subtract round number
///    - XOR with round key
/// 
/// # Symmetric Property
/// 
/// DES is a symmetric cipher, meaning the same key is used for
/// both encryption and decryption. The algorithm structure
/// ensures that decryption reverses encryption exactly.
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