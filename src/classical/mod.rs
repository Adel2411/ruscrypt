//! # Classical Cipher Implementations Module
//! 
//! This module provides implementations of historical cryptographic ciphers that were
//! used before the advent of modern computer-based cryptography. These ciphers are
//! **not secure** for modern use but are excellent for educational purposes.
//! 
//! ## Available Classical Ciphers
//! 
//! - **Caesar Cipher**: Simple substitution cipher with fixed shift
//! - **Vigenère Cipher**: Polyalphabetic substitution using a keyword
//! - **Playfair Cipher**: Digraph substitution using a 5×5 key square
//! - **Rail Fence Cipher**: Transposition cipher using a zigzag pattern
//! 
//! ## Security Warning
//! 
//! ⚠️ **Educational Use Only**: All classical ciphers implemented here are
//! cryptographically weak by modern standards and should never be used to
//! protect sensitive information in real-world applications.
//! 
//! ### Common Vulnerabilities
//! - **Frequency Analysis**: Letter patterns can reveal plaintext
//! - **Small Key Space**: Limited number of possible keys
//! - **Pattern Recognition**: Repeated text creates identifiable patterns
//! - **Known Plaintext Attacks**: Easy to break with sample text
//! 
//! ## Educational Value
//! 
//! These implementations help understand:
//! - Basic cryptographic concepts (substitution vs transposition)
//! - Historical evolution of cryptography
//! - Why modern cryptography is necessary
//! - Common attack methods against weak ciphers
//! 
//! ## Usage Examples
//! 
//! ```rust
//! use ruscrypt::classical::{caesar, vigenere, playfair, rail_fence};
//! 
//! // Caesar cipher (shift by 3)
//! let caesar_encrypted = caesar::encrypt("HELLO", 3).unwrap();
//! assert_eq!(caesar_encrypted, "KHOOR");
//! 
//! // Vigenère cipher with keyword
//! let vigenere_encrypted = vigenere::encrypt("HELLO", "KEY").unwrap();
//! 
//! // Playfair cipher with keyword matrix
//! let playfair_encrypted = playfair::encrypt("HELLO", "SECRET").unwrap();
//! 
//! // Rail fence cipher with 3 rails
//! let railfence_encrypted = rail_fence::encrypt("HELLO", 3).unwrap();
//! ```
//! 
//! ## Implementation Notes
//! 
//! - All implementations prioritize clarity over performance
//! - Input text is typically converted to uppercase
//! - Non-alphabetic characters may be filtered or preserved based on cipher
//! - Error handling provides meaningful feedback for invalid inputs
//!
//! ## Module Overview
//!
//! This module contains implementations of several classical ciphers. Each cipher
//! is implemented in its own submodule, with a public API for encryption and
//! decryption. The ciphers included are:
//! 
//! - **Caesar Cipher**: Implemented in `caesar.rs`
//! - **Vigenère Cipher**: Implemented in `vigenere.rs`
//! - **Playfair Cipher**: Implemented in `playfair.rs`
//! - **Rail Fence Cipher**: Implemented in `rail_fence.rs`
//! 
//! All ciphers can be used by importing the desired submodule. For example, to use
//! the Caesar cipher:
//! 
//! ```rust
//! use ruscrypt::classical::caesar;
//! 
//! let encrypted = caesar::encrypt("HELLO", 3).unwrap();
//! ```
//! 
//! ## Error Handling
//! 
//! Each cipher implementation handles errors in a way that is idiomatic to Rust.
//! Generally, functions will return a `Result` type, with `Ok` containing the
//! ciphertext or plaintext, and `Err` containing an error message. Common errors
//! include invalid characters (non-alphabetic) and incorrect key lengths.
//! 
//! ## Future Work
//! 
//! Potential improvements and additions for the future:
//! 
//! - Implementing more classical ciphers (e.g., Beaufort, Bifid)
//! - Adding automated tests for each implementation
//! - Providing a command-line interface for the module
//! - Creating a comprehensive user manual and documentation

/// Caesar cipher implementation
/// 
/// Simple substitution cipher that shifts each letter by a fixed number of positions
/// in the alphabet. Also known as a shift cipher.
pub mod caesar;

/// Vigenère cipher implementation
/// 
/// Polyalphabetic substitution cipher that uses a repeating keyword to determine
/// the shift for each letter. More secure than Caesar but still breakable.
pub mod vigenere;

/// Playfair cipher implementation
/// 
/// Digraph substitution cipher that encrypts pairs of letters using a 5×5 key square.
/// Historically important and more secure than simple substitution ciphers.
pub mod playfair;

/// Rail Fence cipher implementation
/// 
/// Transposition cipher that arranges plaintext in a zigzag pattern across multiple
/// "rails" then reads the ciphertext row by row.
pub mod rail_fence;