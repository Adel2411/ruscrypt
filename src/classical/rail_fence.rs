//! # Rail Fence Cipher Implementation
//!
//! The Rail Fence cipher is a classical transposition cipher that arranges the plaintext
//! in a zigzag pattern across multiple "rails" (rows), then reads off the ciphertext
//! by concatenating each rail. It's also known as the Zigzag cipher.
//!
//! ⚠️ **Security Warning**: The Rail Fence cipher is **not secure** for modern use and should
//! only be used for educational purposes or simple text obfuscation.
//!
//! ## How It Works
//!
//! 1. **Write**: Arrange plaintext in a zigzag pattern across N rails
//! 2. **Read**: Concatenate characters from each rail to form ciphertext
//! 3. **Decrypt**: Reverse the process by filling the zigzag pattern with ciphertext
//!
//! ## Example with 3 Rails
//!
//! Plaintext: "HELLO WORLD"
//! ```text
//! H   O   O   D
//!  E L   W R L
//!   L     L
//! ```
//! Ciphertext: "HOOD" + "ELWRL" + "LL" = "HOODELWRLLL"
//!
//! ## Examples
//!
//! ```rust
//! use ruscrypt::classical::rail_fence;
//!
//! // Encrypt with 3 rails
//! let encrypted = rail_fence::encrypt("HELLO WORLD", 3).unwrap();
//! println!("Encrypted: {}", encrypted);
//!
//! // Decrypt with same number of rails
//! let decrypted = rail_fence::decrypt(&encrypted, 3).unwrap();
//! println!("Decrypted: {}", decrypted);
//! ```

use anyhow::Result;

/// Encrypts text using the Rail Fence cipher algorithm.
///
/// Arranges the input text in a zigzag pattern across the specified number of rails,
/// then reads the text row by row to create the ciphertext.
///
/// # Arguments
///
/// * `text` - The plaintext to encrypt
/// * `rails` - Number of rails (rows) to use (must be ≥ 2)
///
/// # Returns
///
/// Returns the encrypted text as a `Result<String>`.
///
/// # Algorithm
///
/// 1. Create N empty strings for each rail
/// 2. Traverse the text, placing each character on the appropriate rail
/// 3. Use a direction indicator to create the zigzag pattern
/// 4. Concatenate all rails to form the ciphertext
///
/// # Zigzag Pattern
///
/// - Start at rail 0, move down
/// - When reaching the last rail, change direction to move up
/// - When reaching the first rail, change direction to move down
/// - Continue until all characters are placed
///
/// # Examples
///
/// ```rust
/// use ruscrypt::classical::rail_fence;
///
/// // With 3 rails: "HELLO" becomes "HOELL"
/// let result = rail_fence::encrypt("HELLO", 3).unwrap();
///
/// // With 2 rails: "HELLO" becomes "HLOEL"  
/// let result2 = rail_fence::encrypt("HELLO", 2).unwrap();
/// ```
///
/// # Edge Cases
///
/// - If `rails < 2`, returns the original text unchanged
/// - Preserves all characters including spaces and punctuation
/// - Empty text returns empty string
pub fn encrypt(text: &str, rails: usize) -> Result<String> {
    if rails < 2 {
        return Ok(text.to_string());
    }

    let chars: Vec<char> = text.chars().collect();
    let mut fence = vec![String::new(); rails];
    let mut rail = 0;
    let mut direction = 1; // 1 for down, -1 for up

    for ch in chars {
        fence[rail].push(ch);

        if rail == 0 {
            direction = 1;
        } else if rail == rails - 1 {
            direction = -1;
        }

        rail = (rail as i32 + direction) as usize;
    }

    Ok(fence.join(""))
}

/// Decrypts text encrypted with the Rail Fence cipher.
///
/// Reconstructs the zigzag pattern from the ciphertext by first determining
/// which positions characters should occupy, then filling those positions
/// with the ciphertext characters.
///
/// # Arguments
///
/// * `text` - The ciphertext to decrypt
/// * `rails` - Number of rails used during encryption
///
/// # Returns
///
/// Returns the decrypted text as a `Result<String>`.
///
/// # Algorithm
///
/// 1. Create a 2D grid to represent the rail fence
/// 2. Mark positions where characters should be placed (using '*')
/// 3. Fill marked positions with ciphertext characters row by row
/// 4. Read the grid in zigzag pattern to recover plaintext
///
/// # Grid Reconstruction
///
/// The function recreates the exact zigzag pattern used during encryption:
/// - Simulates the original character placement to mark positions
/// - Fills marked positions with ciphertext characters in rail order
/// - Reads back the filled grid following the same zigzag pattern
///
/// # Examples
///
/// ```rust
/// use ruscrypt::classical::rail_fence;
///
/// let encrypted = "HOELL";
/// let result = rail_fence::decrypt(encrypted, 3).unwrap();
/// assert_eq!(result, "HELLO");
/// ```
///
/// # Validation
///
/// The function assumes the ciphertext was properly encrypted with the
/// specified number of rails. Incorrect rail count will produce garbled output.
///
/// # Edge Cases
///
/// - If `rails < 2`, returns the original text unchanged
/// - Handles empty input gracefully
/// - Preserves character order and type from original text
pub fn decrypt(text: &str, rails: usize) -> Result<String> {
    if rails < 2 {
        return Ok(text.to_string());
    }

    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut fence = vec![vec![' '; len]; rails];

    // Mark the positions where characters should go
    let mut rail = 0;
    let mut direction = 1;

    for col in 0..len {
        fence[rail][col] = '*';

        if rail == 0 {
            direction = 1;
        } else if rail == rails - 1 {
            direction = -1;
        }

        rail = (rail as i32 + direction) as usize;
    }

    // Fill the fence with characters
    let mut char_index = 0;
    for row in fence.iter_mut().take(rails) {
        for col in 0..len {
            if row[col] == '*' {
                row[col] = chars[char_index];
                char_index += 1;
            }
        }
    }

    // Read the fence in zigzag pattern
    let mut result = String::new();
    rail = 0;
    direction = 1;

    for _ in 0..len {
        result.push(fence[rail][result.len()]);

        if rail == 0 {
            direction = 1;
        } else if rail == rails - 1 {
            direction = -1;
        }

        rail = (rail as i32 + direction) as usize;
    }

    Ok(result)
}
