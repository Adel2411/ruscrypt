//! # Block Cipher Implementations Module
//!
//! This module provides implementations of symmetric block ciphers that encrypt
//! data in fixed-size blocks. Block ciphers are fundamental building blocks
//! for many cryptographic systems.
//!
//! ## Available Block Ciphers
//!
//! - **AES (Advanced Encryption Standard)**: Modern, secure block cipher
//! - **DES (Data Encryption Standard)**: Legacy block cipher (⚠️ **Deprecated**)
//!
//! ## Security Status
//!
//! ### Secure for Production
//! - **AES**: Industry standard with 128, 192, or 256-bit keys
//!   - AES-128: Suitable for most applications
//!   - AES-192: Enhanced security margin
//!   - AES-256: Maximum security, required for some government applications
//!
//! ### Deprecated/Insecure
//! - **DES**: 56-bit effective key size is too small for modern security
//!   - Vulnerable to brute force attacks
//!   - Included only for educational and legacy purposes
//!
//! ## Encryption Modes
//!
//! Both ciphers support multiple modes of operation:
//! - **ECB (Electronic Codebook)**: Simple but less secure
//! - **CBC (Cipher Block Chaining)**: More secure, recommended for most uses
//!
//! ## Usage Examples
//!
//! ```rust
//! use ruscrypt::block::{aes, des};
//!
//! // Modern AES encryption (recommended)
//! let encrypted = aes::encrypt(
//!     "sensitive data",
//!     "password123",
//!     "256",
//!     "CBC",
//!     "base64"
//! ).unwrap();
//!
//! // Legacy DES (educational only)
//! let des_encrypted = des::encrypt(
//!     "test data",
//!     "8charkey",  // Exactly 8 characters
//!     "CBC",
//!     "hex"
//! ).unwrap();
//! ```
//!
//! ## Key Management
//!
//! - **AES**: Derives keys from passwords using PBKDF2
//! - **DES**: Uses exactly 8-character keys (56 effective bits)
//!
//! ## Output Encoding
//!
//! Both ciphers support multiple output encodings:
//! - **Base64**: Standard encoding for text transmission
//! - **Hexadecimal**: Human-readable hex representation
//!
//! ## Performance Considerations
//!
//! These implementations prioritize educational clarity over performance.
//! For high-performance production applications, consider using optimized
//! libraries like `aes` or `ring`.
//!
//! ## Security Recommendations
//!
//! 1. **Use AES-256 with CBC mode** for new applications
//! 2. **Avoid DES** except for legacy compatibility
//! 3. **Use strong passwords** for key derivation
//! 4. **Store and transmit keys securely**
//! 5. **Consider authenticated encryption** modes for additional security

/// AES (Advanced Encryption Standard) block cipher
///
/// ✅ **Secure**: Industry-standard symmetric encryption algorithm.
/// Supports 128, 192, and 256-bit keys with ECB and CBC modes.
pub mod aes;

/// DES (Data Encryption Standard) block cipher
///
/// ⚠️ **Deprecated**: 56-bit effective key size is insufficient for modern security.
/// Included for educational purposes and legacy system compatibility only.
pub mod des;
