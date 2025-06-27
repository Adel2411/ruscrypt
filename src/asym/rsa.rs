//! # RSA Asymmetric Encryption Implementation
//! 
//! This module provides an educational implementation of the RSA public-key
//! cryptosystem for learning purposes.
//! 
//! ⚠️ **Security Warning**: This implementation uses small key sizes and
//! simplified algorithms. It should **NOT** be used for production security.
//! For real applications, use established RSA libraries with proper padding
//! schemes and key sizes of at least 2048 bits.
//! 
//! ## Algorithm Overview
//! 
//! RSA encryption relies on the mathematical difficulty of factoring large
//! composite numbers. The algorithm involves:
//! 
//! 1. **Key Generation**: Create public/private key pairs
//! 2. **Encryption**: Use public key to encrypt data
//! 3. **Decryption**: Use private key to decrypt data
//! 
//! ## Examples
//! 
//! ```rust
//! use ruscrypt::asym::rsa;
//! 
//! // CLI-style encryption (returns encrypted data and private key)
//! let (encrypted, private_key) = rsa::encrypt("Hello", "512", "base64").unwrap();
//! let decrypted = rsa::decrypt(&encrypted, &private_key, "base64").unwrap();
//! assert_eq!(decrypted, "Hello");
//! 
//! // Lower-level key generation and encryption
//! let key_pair = rsa::generate_key_pair(512).unwrap();
//! let encrypted_data = rsa::rsa_encrypt(b"Hello", &key_pair.public_key).unwrap();
//! let decrypted_bytes = rsa::rsa_decrypt(&encrypted_data.ciphertext, &key_pair.private_key).unwrap();
//! ```

use anyhow::Result;
use rand::Rng;
use crate::utils::{to_base64, from_base64, to_hex, from_hex};

/// RSA key pair containing both public and private keys.
/// 
/// In RSA, the public key can be shared openly while the private key
/// must be kept secret by the owner.
#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    /// The public key component (for encryption and signature verification)
    pub public_key: RSAPublicKey,
    /// The private key component (for decryption and signing)
    pub private_key: RSAPrivateKey,
}

/// RSA public key used for encryption and signature verification.
/// 
/// The public key consists of the modulus `n` and public exponent `e`.
/// This key can be shared openly.
#[derive(Debug, Clone)]
pub struct RSAPublicKey {
    /// The modulus (n = p × q where p and q are large primes)
    pub n: u64,
    /// The public exponent (commonly 65537 in practice)
    pub e: u64,
}

/// RSA private key used for decryption and signing.
/// 
/// The private key consists of the same modulus `n` and the private exponent `d`.
/// This key must be kept secret.
#[derive(Debug, Clone)]
pub struct RSAPrivateKey {
    /// The modulus (same as in the public key)
    pub n: u64,
    /// The private exponent (d ≡ e⁻¹ mod φ(n))
    pub d: u64,
}

/// Container for RSA-encrypted data along with metadata.
/// 
/// RSA encryption may split large messages into multiple blocks,
/// so the ciphertext is stored as a vector of encrypted integers.
#[derive(Debug)]
pub struct RSAEncryptedData {
    /// The encrypted data blocks
    pub ciphertext: Vec<u64>,
    /// The public key used for encryption (for reference)
    #[allow(dead_code)]
    pub public_key: RSAPublicKey,
}

/// High-level RSA encryption function for CLI use.
/// 
/// This function generates a new RSA key pair, encrypts the data with the
/// public key, and returns both the encrypted data and the private key
/// (formatted as a string for storage).
/// 
/// # Arguments
/// 
/// * `data` - The plaintext string to encrypt
/// * `key_size` - Key size in bits: "512", "1024", or "2048"
/// * `encoding` - Output encoding: "base64" or "hex"
/// 
/// # Returns
/// 
/// Returns a tuple containing:
/// - Encrypted data as an encoded string
/// - Private key formatted as "n:d" for later decryption
/// 
/// # Errors
/// 
/// Returns an error if:
/// - Invalid key size specified
/// - Unsupported encoding format
/// - Key generation fails (rare, but can happen with small primes)
/// - Message is too large for the key size
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::asym::rsa;
/// 
/// let (encrypted, private_key) = rsa::encrypt("Secret message", "1024", "base64").unwrap();
/// println!("Encrypted: {}", encrypted);
/// println!("Private key (save this!): {}", private_key);
/// 
/// // Later, decrypt with the private key
/// let decrypted = rsa::decrypt(&encrypted, &private_key, "base64").unwrap();
/// assert_eq!(decrypted, "Secret message");
/// ```
/// 
/// # Security Note
/// 
/// ⚠️ The generated keys use small sizes suitable only for educational purposes.
/// Real applications should use at least 2048-bit keys with proper padding.
pub fn encrypt(data: &str, key_size: &str, encoding: &str) -> Result<(String, String)> {
    let key_bits: u32 = key_size.parse()
        .map_err(|_| anyhow::anyhow!("Invalid key size: {}", key_size))?;
    
    if ![512, 1024, 2048].contains(&key_bits) {
        return Err(anyhow::anyhow!("Key size must be 512, 1024, or 2048 bits"));
    }
    
    println!("\n🔑 Generating RSA key pair...");
    let key_pair = generate_key_pair(key_bits)?;
    
    println!("✅ Key pair generated successfully!");
    println!("📋 Public Key (n={}, e={})", key_pair.public_key.n, key_pair.public_key.e);
    
    let encrypted_data = rsa_encrypt(data.as_bytes(), &key_pair.public_key)?;
    
    let encrypted_string = match encoding.to_lowercase().as_str() {
        "base64" => {
            let bytes: Vec<u8> = encrypted_data.ciphertext
                .iter()
                .flat_map(|&num| num.to_be_bytes())
                .collect();
            to_base64(&bytes)
        },
        "hex" => {
            let bytes: Vec<u8> = encrypted_data.ciphertext
                .iter()
                .flat_map(|&num| num.to_be_bytes())
                .collect();
            to_hex(&bytes)
        },
        _ => return Err(anyhow::anyhow!("Unsupported encoding: {}. Use 'base64' or 'hex'", encoding))
    };
    
    let private_key_string = format!("{}:{}", key_pair.private_key.n, key_pair.private_key.d);
    
    Ok((encrypted_string, private_key_string))
}

/// High-level RSA decryption function for CLI use.
/// 
/// Decrypts data that was encrypted with the corresponding public key,
/// using a private key in string format.
/// 
/// # Arguments
/// 
/// * `data` - The encrypted data (in specified encoding)
/// * `private_key_str` - Private key in "n:d" format
/// * `encoding` - Input encoding: "base64" or "hex"
/// 
/// # Returns
/// 
/// Returns the decrypted plaintext as a UTF-8 string.
/// 
/// # Errors
/// 
/// Returns an error if:
/// - Invalid private key format
/// - Unsupported encoding format
/// - Invalid encrypted data for the specified encoding
/// - Decryption produces invalid UTF-8
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::asym::rsa;
/// 
/// let encrypted_data = "..."; // Base64 encrypted data
/// let private_key = "12345:6789"; // n:d format
/// let decrypted = rsa::decrypt(encrypted_data, private_key, "base64").unwrap();
/// ```
pub fn decrypt(data: &str, private_key_str: &str, encoding: &str) -> Result<String> {
    let private_key = parse_private_key(private_key_str)?;
    
    let ciphertext_nums = match encoding.to_lowercase().as_str() {
        "base64" => {
            let bytes = from_base64(data)?;
            if bytes.len() % 8 != 0 {
                return Err(anyhow::anyhow!("Invalid base64 data length"));
            }
            bytes.chunks_exact(8)
                    .map(|chunk| u64::from_be_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3],
                        chunk[4], chunk[5], chunk[6], chunk[7]
                    ]))
                    .collect::<Vec<u64>>()
        },
        "hex" => {
            let bytes = from_hex(data)?;
            if bytes.len() % 8 != 0 {
                return Err(anyhow::anyhow!("Invalid hex data length"));
            }
            bytes.chunks_exact(8)
                .map(|chunk| u64::from_be_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3],
                    chunk[4], chunk[5], chunk[6], chunk[7]
                ]))
                .collect()
        },
        _ => return Err(anyhow::anyhow!("Unsupported encoding: {}. Use 'base64' or 'hex'", encoding))
    };
    
    let decrypted_bytes = rsa_decrypt(&ciphertext_nums, &private_key)?;
    
    String::from_utf8(decrypted_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in decrypted data: {}", e))
}

/// Generates an RSA key pair with the specified key size.
/// 
/// This function implements the basic RSA key generation algorithm:
/// 1. Generate two distinct prime numbers p and q
/// 2. Compute n = p × q (the modulus)
/// 3. Compute φ(n) = (p-1)(q-1) (Euler's totient function)
/// 4. Choose e such that gcd(e, φ(n)) = 1
/// 5. Compute d ≡ e⁻¹ mod φ(n)
/// 
/// # Arguments
/// 
/// * `key_size` - Size of the key in bits (512, 1024, or 2048)
/// 
/// # Returns
/// 
/// Returns an `RSAKeyPair` containing both public and private keys.
/// 
/// # Errors
/// 
/// Returns an error if:
/// - Unsupported key size
/// - Prime generation fails
/// - Key computation encounters mathematical errors
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::asym::rsa;
/// 
/// let key_pair = rsa::generate_key_pair(1024).unwrap();
/// println!("Public key: n={}, e={}", key_pair.public_key.n, key_pair.public_key.e);
/// println!("Private key: n={}, d={}", key_pair.private_key.n, key_pair.private_key.d);
/// ```
/// 
/// # Implementation Details
/// 
/// - Uses simplified prime generation suitable for educational purposes
/// - Key sizes are smaller than production recommendations
/// - No side-channel attack protections
pub fn generate_key_pair(key_size: u32) -> Result<RSAKeyPair> {
    // For educational purposes, we'll use smaller primes
    // In production, you'd use much larger primes
    let bit_size = match key_size {
        512 => 8,   // ~16-bit primes for demonstration
        1024 => 16, // ~32-bit primes
        2048 => 20, // ~40-bit primes
        _ => return Err(anyhow::anyhow!("Unsupported key size")),
    };
    
    let p = generate_prime(bit_size)?;
    let q = generate_prime(bit_size)?;
    
    if p == q {
        return Err(anyhow::anyhow!("Generated primes are identical, try again"));
    }
    
    let n = p * q;
    let phi = (p - 1) * (q - 1);
    
    // Choose e (commonly 65537, but we'll use smaller values for demo)
    let e = find_coprime(phi)?;
    
    // Calculate d (modular multiplicative inverse of e mod phi)
    let d = mod_inverse(e, phi)?;
    
    let public_key = RSAPublicKey { n, e };
    let private_key = RSAPrivateKey { n, d };
    
    Ok(RSAKeyPair { public_key, private_key })
}

/// Encrypts binary data using RSA public key encryption.
/// 
/// This function performs "textbook RSA" encryption without padding.
/// Large messages are split into blocks that fit within the key size.
/// 
/// # Arguments
/// 
/// * `plaintext` - Raw bytes to encrypt
/// * `public_key` - RSA public key for encryption
/// 
/// # Returns
/// 
/// Returns `RSAEncryptedData` containing the encrypted blocks.
/// 
/// # Errors
/// 
/// Returns an error if any message block is larger than the modulus.
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::asym::rsa;
/// 
/// let key_pair = rsa::generate_key_pair(512).unwrap();
/// let encrypted = rsa::rsa_encrypt(b"Hello", &key_pair.public_key).unwrap();
/// let decrypted = rsa::rsa_decrypt(&encrypted.ciphertext, &key_pair.private_key).unwrap();
/// assert_eq!(decrypted, b"Hello");
/// ```
/// 
/// # Security Warning
/// 
/// ⚠️ This implements textbook RSA without padding, which is not semantically
/// secure. Production systems should use OAEP or PKCS#1 v1.5 padding.
pub fn rsa_encrypt(plaintext: &[u8], public_key: &RSAPublicKey) -> Result<RSAEncryptedData> {
    let mut ciphertext = Vec::new();
    
    // Calculate max bytes per block (n should be larger than any single byte value)
    let block_size = calculate_block_size(public_key.n);
    
    for chunk in plaintext.chunks(block_size) {
        // Convert bytes to number
        let mut m = 0u64;
        for &byte in chunk {
            m = m * 256 + byte as u64;
        }
        
        if m >= public_key.n {
            return Err(anyhow::anyhow!("Message block too large for key"));
        }
        
        // Encrypt: c = m^e mod n
        let c = mod_pow(m, public_key.e, public_key.n);
        ciphertext.push(c);
    }
    
    Ok(RSAEncryptedData {
        ciphertext,
        public_key: public_key.clone(),
    })
}

/// Decrypts RSA-encrypted data using the private key.
/// 
/// Reverses the RSA encryption process by applying the private key
/// to each encrypted block and reconstructing the original message.
/// 
/// # Arguments
/// 
/// * `ciphertext` - Vector of encrypted integer blocks
/// * `private_key` - RSA private key for decryption
/// 
/// # Returns
/// 
/// Returns the decrypted data as a vector of bytes.
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::asym::rsa;
/// 
/// let key_pair = rsa::generate_key_pair(512).unwrap();
/// let encrypted = rsa::rsa_encrypt(b"Test", &key_pair.public_key).unwrap();
/// let decrypted = rsa::rsa_decrypt(&encrypted.ciphertext, &key_pair.private_key).unwrap();
/// assert_eq!(decrypted, b"Test");
/// ```
pub fn rsa_decrypt(ciphertext: &[u64], private_key: &RSAPrivateKey) -> Result<Vec<u8>> {
    let mut plaintext = Vec::new();
    let block_size = calculate_block_size(private_key.n);
    
    for &c in ciphertext {
        // Decrypt: m = c^d mod n
        let m = mod_pow(c, private_key.d, private_key.n);
        
        // Convert number back to bytes
        let mut bytes = Vec::new();
        let mut temp = m;
        
        if temp == 0 {
            bytes.push(0);
        } else {
            while temp > 0 {
                bytes.push((temp % 256) as u8);
                temp /= 256;
            }
            bytes.reverse();
        }
        
        // Pad to block size if necessary, but don't add extra bytes
        while bytes.len() < block_size && !bytes.is_empty() && temp != 0 {
            bytes.insert(0, 0);
        }
        
        plaintext.extend(bytes);
    }
    
    // Remove leading and trailing zeros more carefully
    while plaintext.first() == Some(&0) && plaintext.len() > 1 {
        plaintext.remove(0);
    }
    while plaintext.last() == Some(&0) && plaintext.len() > 1 {
        plaintext.pop();
    }
    
    Ok(plaintext)
}

/// Parses a private key from the string format "n:d".
fn parse_private_key(key_str: &str) -> Result<RSAPrivateKey> {
    let parts: Vec<&str> = key_str.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid private key format. Expected 'n:d'"));
    }
    
    let n = parts[0].parse::<u64>()
        .map_err(|_| anyhow::anyhow!("Invalid modulus in private key"))?;
    let d = parts[1].parse::<u64>()
        .map_err(|_| anyhow::anyhow!("Invalid private exponent in private key"))?;
    
    Ok(RSAPrivateKey { n, d })
}

/// Calculates the appropriate block size for RSA operations based on the modulus.
fn calculate_block_size(n: u64) -> usize {
    // Number of bytes that can fit in modulus
    let bits = 64 - n.leading_zeros();
    let bytes = (bits / 8).max(1) as usize;
    
    // Leave some margin for safety
    if bytes > 2 {
        bytes - 1
    } else {
        1
    }
}

/// Generates a prime number using a simple trial division method.
/// 
/// ⚠️ This is a simplified implementation for educational purposes only.
fn generate_prime(bit_size: u32) -> Result<u64> {
    let mut rng = rand::rng();
    let min = 1u64 << (bit_size - 1);
    let max = (1u64 << bit_size) - 1;
    
    for attempt in 0..10000 { // Increased attempts and better distribution
        // Use better distribution to avoid identical primes
        let candidate = rng.random_range(min + attempt..=max - attempt);
        if candidate % 2 == 0 {
            continue; // Skip even numbers
        }
        if is_prime(candidate) {
            return Ok(candidate);
        }
    }
    
    Err(anyhow::anyhow!("Failed to generate prime after 10000 attempts"))
}

/// Simple primality test (for educational purposes)
fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }
    
    let sqrt_n = (n as f64).sqrt() as u64 + 1;
    for i in (3..=sqrt_n).step_by(2) {
        if n % i == 0 {
            return false;
        }
    }
    true
}

/// Find a number coprime to phi (relatively prime)
fn find_coprime(phi: u64) -> Result<u64> {
    // Try common values first
    for e in [3, 17, 257, 65537] {
        if e < phi && gcd(e, phi) == 1 {
            return Ok(e);
        }
    }
    
    // If common values don't work, find one
    for e in 3..phi {
        if gcd(e, phi) == 1 {
            return Ok(e);
        }
    }
    
    Err(anyhow::anyhow!("Could not find coprime to phi"))
}

/// Greatest Common Divisor using Euclidean algorithm
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let temp = b;
        b = a % b;
        a = temp;
    }
    a
}

/// Extended Euclidean Algorithm to find modular multiplicative inverse
fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        return (b, 0, 1);
    }
    
    let (gcd, x1, y1) = extended_gcd(b % a, a);
    let x = y1 - (b / a) * x1;
    let y = x1;
    
    (gcd, x, y)
}

/// Find modular multiplicative inverse
fn mod_inverse(a: u64, m: u64) -> Result<u64> {
    let (gcd, x, _) = extended_gcd(a as i64, m as i64);
    
    if gcd != 1 {
        return Err(anyhow::anyhow!("Modular inverse does not exist"));
    }
    
    let result = ((x % m as i64) + m as i64) % m as i64;
    Ok(result as u64)
}

/// Fast modular exponentiation
fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    
    let mut result = 1;
    base %= modulus;
    
    while exp > 0 {
        if exp % 2 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        exp >>= 1;
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
    }
    
    result
}