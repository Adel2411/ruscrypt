use anyhow::Result;

/// Encrypts text using Playfair cipher
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

/// Decrypts text using Playfair cipher
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

/// Creates a 5x5 key matrix from the keyword
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
        if letter == 'J' { continue; } // Skip J, use I instead
        
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

/// Prepares text by removing non-alphabetic characters and converting to uppercase
fn prepare_text(text: &str) -> String {
    text.to_uppercase()
        .chars()
        .filter(|c| c.is_alphabetic())
        .map(|c| if c == 'J' { 'I' } else { c })
        .collect()
}

/// Creates pairs of characters, inserting 'X' between identical adjacent letters
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

/// Creates pairs from cipher text (assumes even length)
fn create_pairs_from_cipher(text: &str) -> Result<Vec<(char, char)> > {
    if text.len() % 2 != 0 {
        return Err(anyhow::anyhow!("Cipher text must have even length"));
    }
    
    let chars: Vec<char> = text.chars().collect();
    let pairs = chars
        .chunks(2)
        .map(|chunk| (chunk[0], chunk[1]))
        .collect();
    
    Ok(pairs)
}

/// Finds position of character in matrix
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

/// Encrypts a pair of characters
fn encrypt_pair(a: char, b: char, matrix: &[[char; 5]; 5]) -> Result<String> {
    let (row1, col1) = find_position(matrix, a).ok_or_else(|| anyhow::anyhow!("Character not found in matrix: {}", a))?;
    let (row2, col2) = find_position(matrix, b).ok_or_else(|| anyhow::anyhow!("Character not found in matrix: {}", b))?;
    
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

/// Decrypts a pair of characters
fn decrypt_pair(a: char, b: char, matrix: &[[char; 5]; 5]) -> Result<String> {
    let (row1, col1) = find_position(matrix, a).ok_or_else(|| anyhow::anyhow!("Character not found in matrix: {}", a))?;
    let (row2, col2) = find_position(matrix, b).ok_or_else(|| anyhow::anyhow!("Character not found in matrix: {}", b))?;
    
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
