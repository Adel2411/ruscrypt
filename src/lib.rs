//! RusCrypt - Lightning-fast cryptography toolkit
//! 
//! A comprehensive cryptography library built with Rust, featuring:
//! - Classical ciphers (Caesar, Vigenère, Playfair, Rail Fence)
//! - Modern stream ciphers (RC4)
//! - Secure hash functions (MD5, SHA-1, SHA-256)

pub mod cli;
pub mod dispatcher;
pub mod interactive;
pub mod utils;
pub mod classical;
pub mod hash;
pub mod stream;

#[cfg(test)]
mod tests;

// Re-export commonly used items for convenience
pub use classical::*;
pub use hash::*;
pub use stream::*;
