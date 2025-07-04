//! # AES (Advanced Encryption Standard) Implementation
//!
//! This module provides a simplified educational implementation of AES with
//! support for 128, 192, and 256-bit keys in ECB and CBC modes.
//!
//! ✅ **Security Status**: AES is considered secure for modern use, though this
//! implementation is simplified for educational purposes.
//!
//! ## Supported Features
//!
//! - **Key sizes**: 128, 192, 256 bits
//! - **Modes**: ECB (Electronic Codebook), CBC (Cipher Block Chaining)
//! - **Encoding**: Base64, Hexadecimal
//! - **Padding**: PKCS#7 padding for block alignment
//!
//! ## Security Considerations
//!
//! - ECB mode is not recommended for production (reveals patterns)
//! - CBC mode is more secure but uses a fixed IV (not recommended for production)
//! - For production use, consider authenticated encryption modes like GCM
//!
//! ## Examples
//!
//! ```rust
//! use ruscrypt::block::aes;
//!
//! // AES-256 encryption in CBC mode
//! let encrypted = aes::encrypt(
//!     "Hello, World!",
//!     "mypassword",
//!     "256",
//!     "CBC",
//!     "base64"
//! ).unwrap();
//!
//! let decrypted = aes::decrypt(
//!     &encrypted,
//!     "mypassword",
//!     "256",
//!     "CBC",
//!     "base64"
//! ).unwrap();
//!
//! assert_eq!(decrypted, "Hello, World!");
//! ```

use crate::{
    hash::sha256,
    utils::{from_base64, from_hex, pad_data, remove_padding, to_base64, to_hex},
};
use anyhow::Result;

/// Encrypts data using AES with specified parameters.
///
/// This function provides a high-level interface to AES encryption with
/// automatic key derivation from a password using SHA-256.
///
/// # Arguments
///
/// * `data` - The plaintext to encrypt
/// * `password` - Password for key derivation (any non-empty string)
/// * `key_size` - AES key size: "128", "192", or "256" bits
/// * `mode` - Encryption mode: "ECB" or "CBC"
/// * `encoding` - Output encoding: "base64" or "hex"
///
/// # Returns
///
/// Returns the encrypted data in the specified encoding format.
///
/// # Errors
///
/// Returns an error if:
/// - Password is empty
/// - Invalid key size (must be 128, 192, or 256)
/// - Unsupported mode (must be ECB or CBC)
/// - Unsupported encoding (must be base64 or hex)
///
/// # Examples
///
/// ```rust
/// use ruscrypt::block::aes;
///
/// // AES-128 with ECB mode and Base64 output
/// let encrypted = aes::encrypt("Secret", "pass", "128", "ECB", "base64").unwrap();
///
/// // AES-256 with CBC mode and hex output
/// let encrypted = aes::encrypt("Secret", "pass", "256", "CBC", "hex").unwrap();
/// ```
///
/// # Security Notes
///
/// - Key is derived from password using SHA-256
/// - ECB mode should be avoided for sensitive data
/// - CBC mode uses a fixed zero IV (not secure for production)
pub fn encrypt(
    data: &str,
    password: &str,
    key_size: &str,
    mode: &str,
    encoding: &str,
) -> Result<String> {
    if password.is_empty() {
        return Err(anyhow::anyhow!("Password cannot be empty"));
    }

    // Parse key size
    let key_bits: u32 = key_size
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid key size: {}", key_size))?;

    if ![128, 192, 256].contains(&key_bits) {
        return Err(anyhow::anyhow!("Key size must be 128, 192, or 256 bits"));
    }

    // Generate key from password using our SHA-256
    let key = derive_key(password, key_bits)?;
    let data_bytes = pad_data(data.as_bytes()); // Uses 16-byte padding for AES

    let encrypted = match mode.to_lowercase().as_str() {
        "ecb" => encrypt_ecb(&data_bytes, &key, key_bits)?,
        "cbc" => encrypt_cbc(&data_bytes, &key, key_bits)?,
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported mode: {}. Use 'ECB' or 'CBC'",
                mode
            ))
        }
    };

    // Convert to specified encoding
    match encoding.to_lowercase().as_str() {
        "base64" => Ok(to_base64(&encrypted)),
        "hex" => Ok(to_hex(&encrypted)),
        _ => Err(anyhow::anyhow!(
            "Unsupported encoding: {}. Use 'base64' or 'hex'",
            encoding
        )),
    }
}

/// Decrypts AES-encrypted data with specified parameters.
///
/// Reverses the AES encryption process using the same parameters that
/// were used for encryption.
///
/// # Arguments
///
/// * `data` - The encrypted data (in specified encoding)
/// * `password` - Password used for encryption (must match exactly)
/// * `key_size` - AES key size used: "128", "192", or "256" bits
/// * `mode` - Encryption mode used: "ECB" or "CBC"
/// * `encoding` - Input encoding: "base64" or "hex"
///
/// # Returns
///
/// Returns the decrypted plaintext as a UTF-8 string.
///
/// # Errors
///
/// Returns an error if:
/// - Password is empty or incorrect
/// - Invalid key size
/// - Unsupported mode or encoding
/// - Invalid input data for the specified encoding
/// - Decrypted data is not valid UTF-8
/// - Invalid padding in encrypted data
///
/// # Examples
///
/// ```rust
/// use ruscrypt::block::aes;
///
/// let encrypted = "..."; // Previously encrypted data
/// let decrypted = aes::decrypt(encrypted, "pass", "256", "CBC", "base64").unwrap();
/// ```
pub fn decrypt(
    data: &str,
    password: &str,
    key_size: &str,
    mode: &str,
    encoding: &str,
) -> Result<String> {
    if password.is_empty() {
        return Err(anyhow::anyhow!("Password cannot be empty"));
    }

    // Parse key size
    let key_bits: u32 = key_size
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid key size: {}", key_size))?;

    if ![128, 192, 256].contains(&key_bits) {
        return Err(anyhow::anyhow!("Key size must be 128, 192, or 256 bits"));
    }

    // Convert from specified encoding
    let encrypted_bytes = match encoding.to_lowercase().as_str() {
        "base64" => from_base64(data)?,
        "hex" => from_hex(data)?,
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported encoding: {}. Use 'base64' or 'hex'",
                encoding
            ))
        }
    };

    let key = derive_key(password, key_bits)?;

    let decrypted = match mode.to_lowercase().as_str() {
        "ecb" => decrypt_ecb(&encrypted_bytes, &key, key_bits)?,
        "cbc" => decrypt_cbc(&encrypted_bytes, &key, key_bits)?,
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported mode: {}. Use 'ECB' or 'CBC'",
                mode
            ))
        }
    };

    // Remove padding and convert to string
    let unpadded = remove_padding(&decrypted)?;
    String::from_utf8(unpadded)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in decrypted data: {}", e))
}

/// Encrypts data using AES in Electronic Codebook (ECB) mode.
///
/// ECB mode encrypts each 16-byte block independently. This mode is simple
/// but not recommended for sensitive data as it reveals patterns.
///
/// # Arguments
///
/// * `data` - Padded plaintext data (must be multiple of 16 bytes)
/// * `key` - AES key bytes
/// * `key_bits` - Key size in bits (128, 192, or 256)
///
/// # Returns
///
/// Returns the encrypted data as a vector of bytes.
///
/// # Security Warning
///
/// ⚠️ ECB mode is not semantically secure and should not be used for
/// encrypting large amounts of data or data with patterns.
fn encrypt_ecb(data: &[u8], key: &[u8], key_bits: u32) -> Result<Vec<u8>> {
    let mut encrypted = Vec::new();

    for chunk in data.chunks(16) {
        let encrypted_block = aes_encrypt_block(chunk, key, key_bits)?;
        encrypted.extend_from_slice(&encrypted_block);
    }

    Ok(encrypted)
}

/// AES decryption in ECB mode
fn decrypt_ecb(data: &[u8], key: &[u8], key_bits: u32) -> Result<Vec<u8>> {
    let mut decrypted = Vec::new();

    for chunk in data.chunks(16) {
        if chunk.len() != 16 {
            return Err(anyhow::anyhow!("Invalid encrypted data length"));
        }
        let decrypted_block = aes_decrypt_block(chunk, key, key_bits)?;
        decrypted.extend_from_slice(&decrypted_block);
    }

    Ok(decrypted)
}

/// Encrypts data using AES in Cipher Block Chaining (CBC) mode.
///
/// CBC mode XORs each plaintext block with the previous ciphertext block
/// before encryption, providing better security than ECB mode.
///
/// # Arguments
///
/// * `data` - Padded plaintext data (must be multiple of 16 bytes)
/// * `key` - AES key bytes  
/// * `key_bits` - Key size in bits (128, 192, or 256)
///
/// # Returns
///
/// Returns the encrypted data as a vector of bytes.
///
/// # Implementation Note
///
/// This implementation uses a fixed zero IV for simplicity. In production,
/// use a random IV for each encryption operation.
fn encrypt_cbc(data: &[u8], key: &[u8], key_bits: u32) -> Result<Vec<u8>> {
    let mut encrypted = Vec::new();
    let mut previous_block = [0u8; 16]; // IV (Initialization Vector) - all zeros for simplicity

    for chunk in data.chunks(16) {
        // XOR with previous ciphertext (or IV for first block)
        let mut xor_block = [0u8; 16];
        for (i, &byte) in chunk.iter().enumerate() {
            if i < 16 {
                xor_block[i] = byte ^ previous_block[i];
            }
        }

        let encrypted_block = aes_encrypt_block(&xor_block, key, key_bits)?;
        encrypted.extend_from_slice(&encrypted_block);
        previous_block = encrypted_block;
    }

    Ok(encrypted)
}

/// AES decryption in CBC mode
fn decrypt_cbc(data: &[u8], key: &[u8], key_bits: u32) -> Result<Vec<u8>> {
    let mut decrypted = Vec::new();
    let mut previous_block = [0u8; 16]; // IV (Initialization Vector) - all zeros for simplicity

    for chunk in data.chunks(16) {
        if chunk.len() != 16 {
            return Err(anyhow::anyhow!("Invalid encrypted data length"));
        }

        let decrypted_block = aes_decrypt_block(chunk, key, key_bits)?;

        // XOR with previous ciphertext (or IV for first block)
        let mut final_block = [0u8; 16];
        for i in 0..16 {
            final_block[i] = decrypted_block[i] ^ previous_block[i];
        }

        decrypted.extend_from_slice(&final_block);
        previous_block.copy_from_slice(chunk);
    }

    Ok(decrypted)
}

/// Derives an AES key from a password using SHA-256.
///
/// This function uses SHA-256 to convert a password into an AES key of the
/// specified size. For keys larger than 256 bits, it generates additional
/// hash rounds.
///
/// # Arguments
///
/// * `password` - The password string
/// * `key_bits` - Desired key size in bits (128, 192, or 256)
///
/// # Returns
///
/// Returns the derived key as a vector of bytes.
///
/// # Security Note
///
/// This is a simple key derivation function. For production use, consider
/// using proper key derivation functions like PBKDF2 or Argon2.
fn derive_key(password: &str, key_bits: u32) -> Result<Vec<u8>> {
    let hash_hex = sha256::hash(password)?;
    let key_bytes = key_bits / 8;

    // Convert hex string to bytes and truncate/extend as needed
    let mut key = Vec::new();
    for chunk in hash_hex.chars().collect::<Vec<_>>().chunks(2) {
        if key.len() >= key_bytes as usize {
            break;
        }
        let hex_str: String = chunk.iter().collect();
        let byte = u8::from_str_radix(&hex_str, 16)
            .map_err(|e| anyhow::anyhow!("Failed to parse hex: {}", e))?;
        key.push(byte);
    }

    // For key sizes larger than SHA-256 output, repeat the hash
    while key.len() < key_bytes as usize {
        let additional_hash = sha256::hash(&format!("{}{}", password, key.len()))?;
        for chunk in additional_hash.chars().collect::<Vec<_>>().chunks(2) {
            if key.len() >= key_bytes as usize {
                break;
            }
            let hex_str: String = chunk.iter().collect();
            let byte = u8::from_str_radix(&hex_str, 16)
                .map_err(|e| anyhow::anyhow!("Failed to parse hex: {}", e))?;
            key.push(byte);
        }
    }

    key.truncate(key_bytes as usize);
    Ok(key)
}

/// Simplified AES encryption with variable key size
fn aes_encrypt_block(block: &[u8], key: &[u8], key_bits: u32) -> Result<[u8; 16]> {
    let mut state = [0u8; 16];

    // Copy input block
    for (i, &byte) in block.iter().enumerate() {
        if i < 16 {
            state[i] = byte;
        }
    }

    // Number of rounds based on key size
    let rounds = match key_bits {
        128 => 10,
        192 => 12,
        256 => 14,
        _ => return Err(anyhow::anyhow!("Unsupported key size: {}", key_bits)),
    };

    // Simplified round function
    for round in 0..rounds {
        // AddRoundKey (simplified)
        for i in 0..16 {
            state[i] ^= key[round % key.len()];
        }

        // SubBytes (simplified S-box)
        for byte in &mut state {
            *byte = simple_sbox(*byte);
        }

        // ShiftRows (simplified)
        shift_rows(&mut state);

        // MixColumns (simplified) - skip in last round
        if round < rounds - 1 {
            mix_columns(&mut state);
        }
    }

    // Final AddRoundKey
    for i in 0..16 {
        state[i] ^= key[i % key.len()];
    }

    Ok(state)
}

/// Simplified AES decryption with variable key size
fn aes_decrypt_block(block: &[u8], key: &[u8], key_bits: u32) -> Result<[u8; 16]> {
    let mut state: [u8; 16] = block.try_into().unwrap();

    let rounds = match key_bits {
        128 => 10,
        192 => 12,
        256 => 14,
        _ => return Err(anyhow::anyhow!("Unsupported key size: {}", key_bits)),
    };

    // Reverse final AddRoundKey
    for i in 0..16 {
        state[i] ^= key[i % key.len()];
    }

    // Reverse rounds
    for round in (0..rounds).rev() {
        // Reverse MixColumns (simplified) - skip in last round
        if round < rounds - 1 {
            inv_mix_columns(&mut state);
        }

        // Reverse ShiftRows
        inv_shift_rows(&mut state);

        // Reverse SubBytes
        for byte in &mut state {
            *byte = inv_simple_sbox(*byte);
        }

        // Reverse AddRoundKey
        for i in 0..16 {
            state[i] ^= key[round % key.len()];
        }
    }

    Ok(state)
}

/// Simplified S-box substitution
fn simple_sbox(byte: u8) -> u8 {
    // This is a simplified substitution - NOT the real AES S-box
    let sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    sbox[byte as usize]
}

/// Inverse S-box
fn inv_simple_sbox(byte: u8) -> u8 {
    // Simplified inverse - in real AES this would be the proper inverse S-box
    let inv_sbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
        0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
        0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
        0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
        0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
        0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
        0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
        0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
        0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
        0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
        0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
        0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
        0x7d,
    ];

    inv_sbox[byte as usize]
}

/// Simplified ShiftRows
fn shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift left by 1
    let temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2: shift left by 2
    let temp1 = state[2];
    let temp2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = temp1;
    state[14] = temp2;

    // Row 3: shift left by 3 (equivalent to shift right by 1)
    let temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

/// Inverse ShiftRows
fn inv_shift_rows(state: &mut [u8; 16]) {
    // Reverse the operations
    shift_rows(state);
    shift_rows(state);
    shift_rows(state);
}

/// Simplified MixColumns
fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let col_start = col * 4;
        let a = state[col_start];
        let b = state[col_start + 1];
        let c = state[col_start + 2];
        let d = state[col_start + 3];

        state[col_start] = a ^ b ^ c;
        state[col_start + 1] = b ^ c ^ d;
        state[col_start + 2] = c ^ d ^ a;
        state[col_start + 3] = d ^ a ^ b;
    }
}

/// Inverse MixColumns
fn inv_mix_columns(state: &mut [u8; 16]) {
    // Simplified inverse - apply the operation multiple times
    mix_columns(state);
    mix_columns(state);
    mix_columns(state);
}
