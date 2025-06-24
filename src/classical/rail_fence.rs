use anyhow::Result;

/// Encrypts text using Rail Fence cipher
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

/// Decrypts text using Rail Fence cipher
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
    for row in 0..rails {
        for col in 0..len {
            if fence[row][col] == '*' {
                fence[row][col] = chars[char_index];
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
