//! # Asymmetric Cryptography Module
//! 
//! This module provides implementations of public-key cryptographic algorithms and
//! key exchange protocols. Unlike symmetric cryptography, asymmetric algorithms use
//! different keys for encryption and decryption, enabling secure communication
//! without prior key sharing.
//! 
//! ## Available Algorithms
//! 
//! - **RSA**: Public-key encryption and digital signatures
//! - **Diffie-Hellman (DH)**: Key exchange protocol for establishing shared secrets
//! 
//! ## Security Status
//! 
//! ### Secure for Production (with proper parameters)
//! - **RSA**: Secure with key sizes ≥ 2048 bits (4096 bits recommended for long-term use)
//! - **Diffie-Hellman**: Secure with properly chosen parameters and large key sizes
//! 
//! ### Educational Implementations
//! These implementations prioritize clarity over security and performance.
//! For production use, consider well-tested libraries like `ring` or `rustls`.
//! 
//! ## Key Exchange vs. Encryption
//! 
//! - **Key Exchange (DH)**: Establishes a shared secret between parties
//! - **Public-Key Encryption (RSA)**: Encrypts data directly using public/private key pairs
//! 
//! ## Usage Examples
//! 
//! ```rust
//! use ruscrypt::asym::{rsa, dh};
//! 
//! // RSA encryption
//! let (encrypted, private_key) = rsa::encrypt("secret message", "2048", "base64").unwrap();
//! let decrypted = rsa::decrypt(&encrypted, &private_key, "base64").unwrap();
//! 
//! // Diffie-Hellman key exchange (educational demo)
//! let result = dh::key_exchange("demo").unwrap();
//! ```
//! 
//! ## Security Considerations
//! 
//! ### RSA Security
//! - **Key Size**: Use at least 2048 bits, prefer 4096 bits for long-term security
//! - **Padding**: Production implementations should use OAEP or PSS padding
//! - **Random Numbers**: Ensure high-quality entropy for key generation
//! 
//! ### Diffie-Hellman Security
//! - **Parameter Selection**: Use well-known safe parameters (RFC 3526)
//! - **Authentication**: Vulnerable to man-in-the-middle attacks without authentication
//! - **Forward Secrecy**: Ephemeral keys provide forward secrecy
//! 
//! ## Performance Characteristics
//! 
//! - **RSA**: Slow compared to symmetric encryption, typically used for key exchange
//! - **DH**: Expensive modular exponentiation, but only needed once per session
//! - **Hybrid Systems**: Combine asymmetric and symmetric crypto for best performance
//! 
//! ## Educational Value
//! 
//! These implementations demonstrate:
//! - Public-key cryptography principles
//! - Key exchange protocol mechanics
//! - Mathematical foundations (modular arithmetic, prime numbers)
//! - Security trade-offs and considerations

/// RSA asymmetric encryption implementation
/// 
/// ✅ **Conditionally Secure**: Secure with appropriate key sizes (≥2048 bits)
/// and proper implementation. This educational implementation prioritizes
/// clarity over production security.
pub mod rsa;

/// Diffie-Hellman key exchange protocol implementation
/// 
/// ✅ **Conditionally Secure**: Forms the basis for many secure key exchange
/// protocols. Vulnerable to man-in-the-middle attacks without authentication.
/// Educational implementation for learning cryptographic concepts.
pub mod dh;