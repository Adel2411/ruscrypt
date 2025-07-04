//! # Playfair Cipher Implementation
//!
//! The Playfair cipher is a digraph substitution cipher invented by Charles Wheatstone
//! in 1854 but popularized by Lord Playfair. It encrypts pairs of letters (digraphs)
//! using a 5×5 key square, making it more secure than simple substitution ciphers.
//!
//! ⚠️ **Security Warning**: The Playfair cipher is **not secure** for modern use and should
//! only be used for educational purposes or historical interest.
//!
//! ## How It Works
//!
//! 1. **Key Square**: Create a 5×5 grid using a keyword (removing duplicates)
//! 2. **Text Preparation**: Convert to uppercase, remove non-letters, treat I/J as same
//! 3. **Pair Creation**: Group letters into pairs, insert 'X' between identical letters
//! 4. **Encryption Rules**:
//!    - Same row: move right (wrap around)
//!    - Same column: move down (wrap around)  
//!    - Rectangle: swap columns
//!
//! ## Examples
//!
//! ```rust
//! use ruscrypt::classical::playfair;
//!
//! // Encrypt a message
//! let encrypted = playfair::encrypt("HELLO WORLD", "SECRET").unwrap();
//! println!("Encrypted: {}", encrypted);
//!
//! // Decrypt the message
//! let decrypted = playfair::decrypt(&encrypted, "SECRET").unwrap();
//! println!("Decrypted: {}", decrypted);
//! ```

use anyhow::Result;

/// Encrypts text using the Playfair cipher algorithm.
///
/// The function creates a 5×5 key matrix from the provided keyword, prepares the
/// input text by removing non-alphabetic characters and handling I/J equivalence,
/// then encrypts pairs of letters according to Playfair rules.
///
/// # Arguments
///
/// * `text` - The plaintext to encrypt
/// * `keyword` - The keyword used to generate the key matrix
///
/// # Returns
///
/// Returns the encrypted text as a `Result<String>`.
///
/// # Encryption Rules
///
/// - **Same row**: Move each letter one position to the right (wrapping around)
/// - **Same column**: Move each letter one position down (wrapping around)
/// - **Rectangle**: Take the letter in the same row but the other letter's column
///
/// # Examples
///
/// ```rust
/// use ruscrypt::classical::playfair;
///
/// let result = playfair::encrypt("HIDE GOLD", "PLAYFAIR").unwrap();
/// // Result will be the encrypted digraphs
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The keyword is empty
/// - Matrix creation fails
/// - Character lookup fails during encryption
pub fn encrypt(text: &str, keyword: &str) -> Result<String> {
    if keyword.is_empty() {
        return Err(anyhow::anyhow!("Keyword cannot be empty"));
    }

    let matrix = create_key_matrix(keyword)?;
    let prepared_text = prepare_text(text);
    let pairs = create_pairs(&prepared_text);

    let result = pairs
        .iter()
        .map(|(a, b)| encrypt_pair(*a, *b, &matrix))
        .collect::<Result<String>>()?;

    Ok(result)
}

/// Decrypts text encrypted with the Playfair cipher.
///
/// Reverses the Playfair encryption process by applying the inverse transformations
/// to each pair of characters in the ciphertext.
///
/// # Arguments
///
/// * `text` - The ciphertext to decrypt
/// * `keyword` - The keyword used during encryption
///
/// # Returns
///
/// Returns the decrypted text as a `Result<String>`.
///
/// # Decryption Rules
///
/// - **Same row**: Move each letter one position to the left (wrapping around)
/// - **Same column**: Move each letter one position up (wrapping around)
/// - **Rectangle**: Take the letter in the same row but the other letter's column
///
/// # Examples
///
/// ```rust
/// use ruscrypt::classical::playfair;
///
/// let encrypted = "BMODZBXDNABEKUDMUIXMMOUVIF";
/// let result = playfair::decrypt(encrypted, "PLAYFAIR").unwrap();
/// // Should recover the original message
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The keyword is empty
/// - The ciphertext has odd length
/// - Matrix creation fails
/// - Character lookup fails during decryption
pub fn decrypt(text: &str, keyword: &str) -> Result<String> {
    if keyword.is_empty() {
        return Err(anyhow::anyhow!("Keyword cannot be empty"));
    }

    let matrix = create_key_matrix(keyword)?;
    let prepared_text = prepare_text(text);
    let pairs = create_pairs_from_cipher(&prepared_text)?;

    let result = pairs
        .iter()
        .map(|(a, b)| decrypt_pair(*a, *b, &matrix))
        .collect::<Result<String>>()?;

    Ok(result)
}

/// Creates a 5×5 key matrix from the given keyword.
///
/// The matrix is constructed by first placing unique letters from the keyword,
/// then filling remaining positions with unused alphabet letters. I and J are
/// treated as the same letter (represented as I).
///
/// # Arguments
///
/// * `keyword` - The keyword to use for matrix generation
///
/// # Returns
///
/// Returns a 5×5 character array representing the key matrix.
///
/// # Matrix Construction
///
/// 1. Convert keyword to uppercase and remove duplicates
/// 2. Place keyword letters in matrix left-to-right, top-to-bottom
/// 3. Fill remaining positions with unused alphabet letters (A-Z except J)
/// 4. Treat I and J as equivalent (use I for both)
///
/// # Examples
///
/// For keyword "PLAYFAIR", the matrix might look like:
/// ```text
/// P L A Y F
/// I R B C D
/// E G H K M
/// N O Q S T
/// U V W X Z
/// ```
///
/// # Errors
///
/// Returns an error if the keyword is empty or matrix construction fails.
fn create_key_matrix(keyword: &str) -> Result<[[char; 5]; 5]> {
    let mut used = std::collections::HashSet::new();
    let mut matrix = [['A'; 5]; 5];
    let mut row = 0;
    let mut col = 0;

    // Add keyword characters (I and J are treated as the same)
    for c in keyword.to_uppercase().chars() {
        if c.is_alphabetic() {
            let ch = if c == 'J' { 'I' } else { c };

            if !used.contains(&ch) && row < 5 {
                used.insert(ch);
                matrix[row][col] = ch;
                col += 1;
                if col == 5 {
                    col = 0;
                    row += 1;
                }
            }
        }
    }

    // Add remaining letters
    for letter in 'A'..='Z' {
        if letter == 'J' {
            continue;
        } // Skip J, use I instead

        if !used.contains(&letter) && row < 5 {
            used.insert(letter);
            matrix[row][col] = letter;
            col += 1;
            if col == 5 {
                col = 0;
                row += 1;
            }
        }
    }

    Ok(matrix)
}

/// Prepares text for Playfair encryption by normalizing the input.
///
/// Removes all non-alphabetic characters, converts to uppercase, and treats
/// J as I since the 5×5 matrix cannot accommodate both letters.
///
/// # Arguments
///
/// * `text` - The input text to prepare
///
/// # Returns
///
/// Returns a normalized string containing only uppercase letters A-Z (no J).
///
/// # Transformations
///
/// - Converts to uppercase
/// - Removes spaces, punctuation, and numbers
/// - Replaces J with I
/// - Keeps only alphabetic characters
///
/// # Examples
///
/// ```rust
/// // "Hello, World!" becomes "HELOWORLD"
/// // "JAVA" becomes "IAVA"
/// ```
fn prepare_text(text: &str) -> String {
    text.to_uppercase()
        .chars()
        .filter(|c| c.is_alphabetic())
        .map(|c| if c == 'J' { 'I' } else { c })
        .collect()
}

/// Creates pairs of characters for Playfair encryption.
///
/// Groups characters into pairs, inserting 'X' between identical adjacent letters
/// and padding with 'X' if the text has odd length.
///
/// # Arguments
///
/// * `text` - The prepared text to pair
///
/// # Returns
///
/// Returns a vector of character tuples representing the pairs.
///
/// # Pairing Rules
///
/// - Normal case: consecutive different letters form a pair
/// - Identical letters: insert 'X' between them
/// - Odd length: append 'X' to make even number of characters
///
/// # Examples
///
/// - "HELLO" → [('H','E'), ('L','X'), ('L','O')]
/// - "BALLOON" → [('B','A'), ('L','X'), ('L','O'), ('O','N')]
/// - "SPEED" → [('S','P'), ('E','X'), ('E','D')]
fn create_pairs(text: &str) -> Vec<(char, char)> {
    let mut pairs = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let first = chars[i];
        let second = if i + 1 < chars.len() {
            let next = chars[i + 1];
            if next == first {
                // Insert X between identical letters
                'X'
            } else {
                i += 1; // Move to next pair
                next
            }
        } else {
            // Odd length, pad with X
            'X'
        };

        pairs.push((first, second));
        i += 1;
    }

    pairs
}

/// Creates pairs from ciphertext for decryption.
///
/// Simply groups consecutive characters into pairs, assuming the ciphertext
/// has even length (as it should from proper Playfair encryption).
///
/// # Arguments
///
/// * `text` - The ciphertext to pair
///
/// # Returns
///
/// Returns a vector of character tuples, or an error if length is odd.
///
/// # Validation
///
/// The function validates that the input has even length, which is required
/// for proper Playfair decryption.
///
/// # Errors
///
/// Returns an error if the text length is odd, indicating corrupted ciphertext.
fn create_pairs_from_cipher(text: &str) -> Result<Vec<(char, char)>> {
    if text.len() % 2 != 0 {
        return Err(anyhow::anyhow!("Cipher text must have even length"));
    }

    let chars: Vec<char> = text.chars().collect();
    let pairs = chars.chunks(2).map(|chunk| (chunk[0], chunk[1])).collect();

    Ok(pairs)
}

/// Finds the position of a character in the key matrix.
///
/// Searches the 5×5 matrix for the specified character and returns its
/// row and column coordinates.
///
/// # Arguments
///
/// * `matrix` - Reference to the 5×5 key matrix
/// * `ch` - The character to find
///
/// # Returns
///
/// Returns `Some((row, col))` if found, `None` if the character is not in the matrix.
///
/// # Search Method
///
/// Performs a linear search through the matrix, checking each position
/// until the character is found or all positions are exhausted.
fn find_position(matrix: &[[char; 5]; 5], ch: char) -> Option<(usize, usize)> {
    for (row, line) in matrix.iter().enumerate() {
        for (col, &c) in line.iter().enumerate() {
            if c == ch {
                return Some((row, col));
            }
        }
    }
    None
}

/// Encrypts a pair of characters using Playfair rules.
///
/// Applies the appropriate Playfair transformation based on the relative
/// positions of the two characters in the key matrix.
///
/// # Arguments
///
/// * `a` - First character of the pair
/// * `b` - Second character of the pair
/// * `matrix` - Reference to the 5×5 key matrix
///
/// # Returns
///
/// Returns the encrypted pair as a `Result<String>`.
///
/// # Encryption Rules
///
/// 1. **Same row**: Move each character one position right (with wrapping)
/// 2. **Same column**: Move each character one position down (with wrapping)
/// 3. **Rectangle**: Swap the columns of the two characters
///
/// # Examples
///
/// If 'H' is at (0,2) and 'E' is at (1,0), they form a rectangle, so:
/// - 'H' becomes the character at (0,0)
/// - 'E' becomes the character at (1,2)
///
/// # Errors
///
/// Returns an error if either character cannot be found in the matrix.
fn encrypt_pair(a: char, b: char, matrix: &[[char; 5]; 5]) -> Result<String> {
    let (row1, col1) = find_position(matrix, a)
        .ok_or_else(|| anyhow::anyhow!("Character not found in matrix: {}", a))?;
    let (row2, col2) = find_position(matrix, b)
        .ok_or_else(|| anyhow::anyhow!("Character not found in matrix: {}", b))?;

    let (new_a, new_b) = if row1 == row2 {
        // Same row: move right
        (matrix[row1][(col1 + 1) % 5], matrix[row2][(col2 + 1) % 5])
    } else if col1 == col2 {
        // Same column: move down
        (matrix[(row1 + 1) % 5][col1], matrix[(row2 + 1) % 5][col2])
    } else {
        // Rectangle: swap columns
        (matrix[row1][col2], matrix[row2][col1])
    };

    Ok(format!("{}{}", new_a, new_b))
}

/// Decrypts a pair of characters using reverse Playfair rules.
///
/// Applies the inverse of the Playfair encryption transformations to
/// recover the original character pair.
///
/// # Arguments
///
/// * `a` - First character of the encrypted pair
/// * `b` - Second character of the encrypted pair
/// * `matrix` - Reference to the 5×5 key matrix
///
/// # Returns
///
/// Returns the decrypted pair as a `Result<String>`.
///
/// # Decryption Rules
///
/// 1. **Same row**: Move each character one position left (with wrapping)
/// 2. **Same column**: Move each character one position up (with wrapping)
/// 3. **Rectangle**: Swap the columns of the two characters (same as encryption)
///
/// # Modular Arithmetic
///
/// Uses `(position + 4) % 5` to move left/up, which is equivalent to
/// subtracting 1 with proper wrapping in a 5-element array.
///
/// # Errors
///
/// Returns an error if either character cannot be found in the matrix.
fn decrypt_pair(a: char, b: char, matrix: &[[char; 5]; 5]) -> Result<String> {
    let (row1, col1) = find_position(matrix, a)
        .ok_or_else(|| anyhow::anyhow!("Character not found in matrix: {}", a))?;
    let (row2, col2) = find_position(matrix, b)
        .ok_or_else(|| anyhow::anyhow!("Character not found in matrix: {}", b))?;

    let (new_a, new_b) = if row1 == row2 {
        // Same row: move left
        (matrix[row1][(col1 + 4) % 5], matrix[row2][(col2 + 4) % 5])
    } else if col1 == col2 {
        // Same column: move up
        (matrix[(row1 + 4) % 5][col1], matrix[(row2 + 4) % 5][col2])
    } else {
        // Rectangle: swap columns
        (matrix[row1][col2], matrix[row2][col1])
    };

    Ok(format!("{}{}", new_a, new_b))
}
