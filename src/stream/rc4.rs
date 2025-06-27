//! # RC4 Stream Cipher Implementation
//! 
//! RC4 is a stream cipher that was widely used in protocols like WEP and WPA.
//! This implementation is for educational purposes only.
//! 
//! ⚠️ **Critical Security Warning**: RC4 has serious cryptographic vulnerabilities
//! and should **NEVER** be used in production systems. It's included here for
//! educational purposes only.
//! 
//! ## Algorithm Overview
//! 
//! RC4 consists of two main parts:
//! 1. **Key Scheduling Algorithm (KSA)**: Initializes the state array
//! 2. **Pseudo-Random Generation Algorithm (PRGA)**: Generates the keystream
//! 
//! ## Examples
//! 
//! ```rust
//! use ruscrypt::stream::rc4;
//! 
//! // Encrypt with Base64 encoding
//! let encrypted = rc4::encrypt("Hello, World!", "secretkey", "base64").unwrap();
//! let decrypted = rc4::decrypt(&encrypted, "secretkey", "base64").unwrap();
//! assert_eq!(decrypted, "Hello, World!");
//! 
//! // Encrypt with hexadecimal encoding
//! let encrypted_hex = rc4::encrypt("Hello", "key", "hex").unwrap();
//! let decrypted_hex = rc4::decrypt(&encrypted_hex, "key", "hex").unwrap();
//! assert_eq!(decrypted_hex, "Hello");
//! ```

use anyhow::Result;
use crate::utils::{to_base64, from_base64, to_hex, from_hex};

/// Encrypts data using the RC4 stream cipher with specified output encoding.
/// 
/// RC4 encrypts by XORing the plaintext with a pseudorandom keystream generated
/// from the provided key.
/// 
/// # Arguments
/// 
/// * `data` - The plaintext string to encrypt
/// * `key` - The encryption key (any non-empty string)
/// * `encoding` - Output encoding format: "base64" or "hex"
/// 
/// # Returns
/// 
/// Returns the encrypted data encoded as specified.
/// 
/// # Errors
/// 
/// Returns an error if:
/// - The key is empty
/// - An unsupported encoding is specified
/// 
/// # Security Warning
/// 
/// ⚠️ RC4 has known vulnerabilities and should not be used for secure applications.
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::stream::rc4;
/// 
/// // Base64 output
/// let encrypted = rc4::encrypt("Secret message", "mykey", "base64").unwrap();
/// println!("Encrypted (Base64): {}", encrypted);
/// 
/// // Hexadecimal output  
/// let encrypted_hex = rc4::encrypt("Secret message", "mykey", "hex").unwrap();
/// println!("Encrypted (Hex): {}", encrypted_hex);
/// ```
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

/// Decrypts data encrypted with RC4 stream cipher from specified encoding.
/// 
/// Reverses the RC4 encryption process by generating the same keystream and
/// XORing it with the ciphertext.
/// 
/// # Arguments
/// 
/// * `data` - The encrypted data as a string (in specified encoding)
/// * `key` - The decryption key (must match the encryption key)
/// * `encoding` - Input encoding format: "base64" or "hex"
/// 
/// # Returns
/// 
/// Returns the decrypted plaintext as a UTF-8 string.
/// 
/// # Errors
/// 
/// Returns an error if:
/// - The key is empty
/// - An unsupported encoding is specified
/// - The input data is not valid for the specified encoding
/// - The decrypted data is not valid UTF-8
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::stream::rc4;
/// 
/// // Decrypt from Base64
/// let encrypted = "YWJjZGVm"; // Example Base64 data
/// let decrypted = rc4::decrypt(encrypted, "mykey", "base64");
/// 
/// // Decrypt from hexadecimal
/// let encrypted_hex = "48656c6c6f"; // Example hex data
/// let decrypted_hex = rc4::decrypt(encrypted_hex, "mykey", "hex");
/// ```
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


/// Generates RC4 keystream using the Key Scheduling Algorithm (KSA) and
/// Pseudo-Random Generation Algorithm (PRGA).
/// 
/// This is an internal function that implements the core RC4 algorithm.
/// 
/// # Arguments
/// 
/// * `key` - The key bytes for initialization
/// * `length` - The desired length of the keystream
/// 
/// # Returns
/// 
/// Returns a vector of pseudorandom bytes of the specified length.
/// 
/// # Algorithm Details
/// 
/// 1. **KSA**: Initializes a 256-byte state array using the key
/// 2. **PRGA**: Generates pseudorandom bytes by swapping state elements
/// 
/// # Examples
/// 
/// ```rust
/// // This is an internal function, but here's how it works conceptually:
/// // let keystream = generate_keystream(b"key", 10);
/// // assert_eq!(keystream.len(), 10);
/// ```
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
