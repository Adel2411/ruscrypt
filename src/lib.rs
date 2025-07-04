//! # RusCrypt - Lightning-fast cryptography toolkit
//!
//! RusCrypt is a comprehensive cryptography library and CLI tool built with Rust, featuring:
//!
//! - **Classical ciphers**: Caesar, Vigenère, Playfair, Rail Fence
//! - **Stream ciphers**: RC4
//! - **Block ciphers**: AES (128/192/256-bit), DES
//! - **Asymmetric encryption**: RSA, Diffie-Hellman key exchange
//! - **Hash functions**: MD5, SHA-1, SHA-256
//!
//! ## Library Usage
//!
//! ```rust
//! use ruscrypt::classical::caesar;
//! use ruscrypt::hash::sha256;
//!
//! // Caesar cipher encryption
//! let encrypted = caesar::encrypt("Hello World", 3).unwrap();
//! assert_eq!(encrypted, "Khoor Zruog");
//!
//! // SHA-256 hashing
//! let hash = sha256::hash("password").unwrap();
//! println!("SHA-256: {}", hash);
//! ```
//!
//! ## CLI Usage
//!
//! Install the binary:
//! ```bash
//! cargo install ruscrypt
//! ```
//!
//! Use the CLI:
//! ```bash
//! # Encrypt with Caesar cipher
//! ruscrypt encrypt --caesar
//!
//! # Hash with SHA-256
//! ruscrypt hash --sha256
//!
//! # Key exchange with Diffie-Hellman
//! ruscrypt exchange --dh
//! ```
//!
//! ## Security Warning
//!
//! ⚠️ **Important**: This library is designed for educational purposes and experimentation.
//! Some algorithms (RC4, DES, MD5, SHA-1, classical ciphers) are not cryptographically
//! secure for modern use. For production applications, use AES-256 and RSA with appropriate
//! key sizes.
//!
//! ## Features
//!
//! - **Zero dependencies** for core crypto algorithms (implementations from scratch)
//! - **Memory safe** - leverages Rust's ownership system
//! - **Fast execution** - optimized for performance
//! - **Educational focus** - clean, readable implementations
//! - **CLI and library** - use as a command-line tool or integrate into your project

#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(unsafe_code)]

pub mod cli;
pub mod dispatcher;
pub mod interactive;
pub mod utils;

/// Classical cipher implementations (Caesar, Vigenère, Playfair, Rail Fence)
///
/// These are historical ciphers that are **not secure** for modern use but are
/// excellent for learning cryptographic concepts.
pub mod classical;

/// Stream cipher implementations (RC4)
///
/// ⚠️ **Security Warning**: RC4 has known vulnerabilities and should not be used
/// in production systems.
pub mod stream;

/// Block cipher implementations (AES, DES)
///
/// AES is secure for modern use; DES is deprecated but included for educational purposes.
pub mod block;

/// Asymmetric cryptography (RSA, Diffie-Hellman)
///
/// Implementations for public-key cryptography and key exchange protocols.
pub mod asym;

/// Cryptographic hash functions (MD5, SHA-1, SHA-256)
///
/// SHA-256 is recommended for modern use; MD5 and SHA-1 are deprecated.
pub mod hash;

mod tests;

pub use asym::*;
pub use block::*;
pub use classical::*;
pub use hash::*;
pub use stream::*;

/// Library version information
///
/// This constant contains the version string extracted from Cargo.toml
/// at compile time, ensuring version consistency between the library
/// and its metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get the current library version
///
/// Returns the version string for the RusCrypt library. This can be used
/// by applications to display version information or ensure compatibility.
///
/// # Returns
///
/// Returns a static string slice containing the semantic version number.
///
/// # Examples
///
/// ```rust
/// use ruscrypt;
///
/// println!("RusCrypt version: {}", ruscrypt::version());
/// ```
pub fn version() -> &'static str {
    VERSION
}

/// Quick example demonstrating basic library usage
///
/// This function provides a simple demonstration of core library functionality
/// including classical ciphers and modern hash functions. It exists primarily
/// to ensure documentation examples compile correctly.
///
/// # Examples
///
/// The following example shows basic usage patterns:
///
/// ```rust
/// use ruscrypt::{classical::caesar, hash::sha256};
///
/// // Classical cipher encryption/decryption
/// let encrypted = caesar::encrypt("Hello", 3).unwrap();
/// let decrypted = caesar::decrypt(&encrypted, 3).unwrap();
/// assert_eq!(decrypted, "Hello");
///
/// // Modern hash function
/// let hash = sha256::hash("test").unwrap();
/// assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex characters
/// ```
///
/// # Note
///
/// This function exists to validate documentation examples and does not
/// perform any actual operations when called.
pub fn quick_example() {
    // This function exists to ensure the example in docs compiles
}
