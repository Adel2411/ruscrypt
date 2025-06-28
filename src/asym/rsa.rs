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
/// * `key_size_or_pem` - Key size in bits: "512", "1024", or "2048", or a PEM public key string
/// * `encoding` - Output encoding: "base64" or "hex"
/// * `privkey_format` - Output format for private key: "n:d" or "PEM"
/// 
/// # Returns
/// 
/// Returns a tuple containing:
/// - Encrypted data as an encoded string
/// - Private key formatted as requested, or empty string if PEM public key was used
pub fn encrypt(
    data: &str,
    key_size_or_pem: &str,
    encoding: &str,
    privkey_format: &str,
) -> Result<(String, String)> {
    // Check if input is a PEM public key
    let is_pem = key_size_or_pem.trim_start().starts_with("-----BEGIN RSA PUBLIC KEY-----");
    let (public_key, private_key_string) = if is_pem {
        // Parse PEM public key
        let lines: Vec<&str> = key_size_or_pem
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let start = lines.iter().position(|l| l.starts_with("-----BEGIN RSA PUBLIC KEY-----"));
        let end = lines.iter().position(|l| l.starts_with("-----END RSA PUBLIC KEY-----"));
        if let (Some(start), Some(end)) = (start, end) {
            let b64 = lines[start+1..end].join("");
            let decoded = from_base64(&b64)
                .map_err(|_| anyhow::anyhow!("Invalid base64 in PEM"))?;
            let key_str = String::from_utf8(decoded)
                .map_err(|_| anyhow::anyhow!("Invalid UTF-8 in PEM key data"))?;
            let parts: Vec<&str> = key_str.split(':').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid PEM public key format"));
            }
            let n = parts[0].parse::<u64>()
                .map_err(|_| anyhow::anyhow!("Invalid modulus in PEM public key"))?;
            let e = parts[1].parse::<u64>()
                .map_err(|_| anyhow::anyhow!("Invalid exponent in PEM public key"))?;
            (RSAPublicKey { n, e }, String::new())
        } else {
            return Err(anyhow::anyhow!("Invalid PEM format for RSA public key"));
        }
    } else {
        // Parse as key size and generate key pair
        let key_bits: u32 = key_size_or_pem.parse()
            .map_err(|_| anyhow::anyhow!("Invalid key size: {}", key_size_or_pem))?;
        if ![512, 1024, 2048].contains(&key_bits) {
            return Err(anyhow::anyhow!("Key size must be 512, 1024, or 2048 bits"));
        }
        println!("\n🔑 Generating RSA key pair...");
        let key_pair = generate_key_pair(key_bits)?;
        println!("✅ Key pair generated successfully!");
        println!("📋 Public Key (n={}, e={})", key_pair.public_key.n, key_pair.public_key.e);
        let priv_str = match privkey_format.to_lowercase().as_str() {
            "pem" => export_private_key_pem(&key_pair.private_key),
            _ => format!("{}:{}", key_pair.private_key.n, key_pair.private_key.d),
        };
        (key_pair.public_key, priv_str)
    };

    let encrypted_data = rsa_encrypt(data.as_bytes(), &public_key)?;

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
/// * `private_key_str` - Private key in "n:d" format or PEM format
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
    let private_key = if private_key_str.trim_start().starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        import_private_key_pem(private_key_str)?
    } else {
        parse_private_key(private_key_str)?
    };
    
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

/// Exports the RSA public key in "n:e" format as a string.
pub fn export_public_key_ne(public_key: &RSAPublicKey) -> String {
    format!("{}:{}", public_key.n, public_key.e)
}

/// Exports the RSA public key in a simple PEM-like format (not X.509).
pub fn export_public_key_pem(public_key: &RSAPublicKey) -> String {
    let key_data = format!("{}:{}", public_key.n, public_key.e);
    let b64 = to_base64(key_data.as_bytes());
    format!(
        "-----BEGIN RSA PUBLIC KEY-----\n{}\n-----END RSA PUBLIC KEY-----",
        b64
    )
}

/// Exports the RSA private key in a simple PEM-like format (not PKCS#8).
pub fn export_private_key_pem(private_key: &RSAPrivateKey) -> String {
    let key_data = format!("{}:{}", private_key.n, private_key.d);
    let b64 = to_base64(key_data.as_bytes());
    format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
        b64
    )
}

/// Imports an RSA private key from a simple PEM-like format.
/// The PEM format is expected to be:
/// -----BEGIN RSA PRIVATE KEY-----
/// <base64(n:d)>
/// -----END RSA PRIVATE KEY-----
pub fn import_private_key_pem(pem: &str) -> Result<RSAPrivateKey> {
    let lines: Vec<&str> = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let start = lines.iter().position(|l| l.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
    let end = lines.iter().position(|l| l.starts_with("-----END RSA PRIVATE KEY-----"));
    if let (Some(start), Some(end)) = (start, end) {
        let b64 = lines[start+1..end].join("");
        let decoded = from_base64(&b64)
            .map_err(|_| anyhow::anyhow!("Invalid base64 in PEM"))?;
        let key_str = String::from_utf8(decoded)
            .map_err(|_| anyhow::anyhow!("Invalid UTF-8 in PEM key data"))?;
        parse_private_key(&key_str)
    } else {
        Err(anyhow::anyhow!("Invalid PEM format for RSA private key"))
    }
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

/// Generate an RSA key pair and output in the selected format.
/// 
/// # Arguments
/// * `key_size` - Key size in bits (512, 1024, 2048)
/// * `format` - Output format: "n:e" or "PEM"
/// 
/// # Returns
/// Returns (public_key_string, private_key_string)
pub fn keygen_and_export(key_size: u32, format: &str) -> Result<(String, String)> {
    let key_pair = generate_key_pair(key_size)?;
    let (pub_str, priv_str) = match format.to_lowercase().as_str() {
        "n:e" => (
            export_public_key_ne(&key_pair.public_key),
            format!("{}:{}", key_pair.private_key.n, key_pair.private_key.d)
        ),
        "pem" => (
            export_public_key_pem(&key_pair.public_key),
            export_private_key_pem(&key_pair.private_key)
        ),
        _ => return Err(anyhow::anyhow!("Unsupported key output format")),
    };
    Ok((pub_str, priv_str))
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