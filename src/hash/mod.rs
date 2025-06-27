//! # Cryptographic Hash Functions Module
//! 
//! This module provides implementations of various cryptographic hash functions,
//! ranging from legacy algorithms to modern secure hash functions.
//! 
//! ## Available Hash Functions
//! 
//! - **MD5**: 128-bit hash function (⚠️ **Deprecated** - cryptographically broken)
//! - **SHA-1**: 160-bit hash function (⚠️ **Deprecated** - collision vulnerabilities)
//! - **SHA-256**: 256-bit hash function (✅ **Secure** - recommended for modern use)
//! 
//! ## Security Considerations
//! 
//! ### Secure for Production
//! - **SHA-256**: Part of the SHA-2 family, cryptographically secure and widely adopted
//! 
//! ### Deprecated/Insecure
//! - **MD5**: Vulnerable to collision attacks, should only be used for checksums
//! - **SHA-1**: Deprecated due to collision vulnerabilities, avoid for security purposes
//! 
//! ## Usage Examples
//! 
//! ```rust
//! use ruscrypt::hash::{md5, sha1, sha256};
//! 
//! // Modern secure hashing (recommended)
//! let secure_hash = sha256::hash("sensitive data").unwrap();
//! println!("SHA-256: {}", secure_hash);
//! 
//! // Legacy hashing (for compatibility only)
//! let legacy_hash = md5::hash("legacy data").unwrap();
//! println!("MD5: {}", legacy_hash);
//! ```
//! 
//! ## Output Formats
//! 
//! All hash functions return hexadecimal strings:
//! - MD5: 32 hexadecimal characters (128 bits)
//! - SHA-1: 40 hexadecimal characters (160 bits)
//! - SHA-256: 64 hexadecimal characters (256 bits)
//! 
//! ## Performance
//! 
//! These implementations prioritize educational clarity over performance.
//! For production applications requiring high-performance hashing, consider
//! using optimized libraries like `ring` or `sha2`.

/// MD5 hash function implementation
/// 
/// ⚠️ **Security Warning**: MD5 is cryptographically broken and should not be used
/// for security purposes. Included for educational and legacy compatibility only.
pub mod md5;

/// SHA-1 hash function implementation
/// 
/// ⚠️ **Deprecated**: SHA-1 has known collision vulnerabilities and should not be
/// used for new applications. Use SHA-256 instead.
pub mod sha1;

/// SHA-256 hash function implementation
/// 
/// ✅ **Secure**: SHA-256 is cryptographically secure and recommended for modern
/// applications requiring hash functions.
pub mod sha256;
