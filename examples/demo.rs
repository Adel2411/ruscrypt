use anyhow::Result;
use colored::*;

// Import the modules from ruscrypt
use ruscrypt::classical::{caesar, rail_fence, vigenere, playfair};
use ruscrypt::stream::rc4;
use ruscrypt::hash::{md5, sha1, sha256};

fn main() -> Result<()> {
    print_demo_banner();
    
    println!("{}", "🔐 Classical Ciphers Demo".cyan().bold());
    println!("{}", "═══════════════════════════".cyan());
    demo_classical_ciphers()?;
    
    println!("\n{}", "🌊 Stream Ciphers Demo".green().bold());
    println!("{}", "══════════════════════".green());
    demo_stream_ciphers()?;
    
    println!("\n{}", "🔢 Hash Functions Demo".magenta().bold());
    println!("{}", "══════════════════════".magenta());
    demo_hash_functions()?;
    
    println!("\n{}", "✨ Demo completed successfully!".bright_green().bold());
    Ok(())
}

fn print_demo_banner() {
    println!("{}", r"
  ____            ____                  _     ____                        
 |  _ \ _   _ ___ / ___|_ __ _   _ _ __ | |_  |  _ \  ___ _ __ ___   ___    
 | |_) | | | / __| |   | '__| | | | '_ \| __| | | | |/ _ \ '_ ` _ \ / _ \   
 |  _ <| |_| \__ \ |___| |  | |_| | |_) | |_  | |_| |  __/ | | | | | (_) |  
 |_| \_\\__,_|___/\____|_|   \__, | .__/ \__| |____/ \___|_| |_| |_|\___/   
                             |___/|_|                                      
    ".yellow());
    
    println!("{}", "🚀 RusCrypt Comprehensive Demo".yellow().bold());
    println!("{}\n", "Showcasing all implemented algorithms".bright_blue().italic());
}

fn demo_classical_ciphers() -> Result<()> {
    let sample_text = "HELLO WORLD";
    
    // Caesar Cipher Demo
    println!("{}", "📜 Caesar Cipher:".yellow());
    let shift = 3;
    let caesar_encrypted = caesar::encrypt(sample_text, shift)?;
    let caesar_decrypted = caesar::decrypt(&caesar_encrypted, shift)?;
    println!("   Original: {}", sample_text.white());
    println!("   Encrypted (shift {}): {}", shift, caesar_encrypted.green());
    println!("   Decrypted: {}", caesar_decrypted.blue());
    
    // Vigenère Cipher Demo
    println!("\n{}", "🔤 Vigenère Cipher:".yellow());
    let keyword = "KEY";
    let vigenere_encrypted = vigenere::encrypt(sample_text, keyword)?;
    let vigenere_decrypted = vigenere::decrypt(&vigenere_encrypted, keyword)?;
    println!("   Original: {}", sample_text.white());
    println!("   Keyword: {}", keyword.cyan());
    println!("   Encrypted: {}", vigenere_encrypted.green());
    println!("   Decrypted: {}", vigenere_decrypted.blue());
    
    // Rail Fence Cipher Demo
    println!("\n{}", "🚂 Rail Fence Cipher:".yellow());
    let rails = 3;
    let railfence_encrypted = rail_fence::encrypt(sample_text, rails)?;
    let railfence_decrypted = rail_fence::decrypt(&railfence_encrypted, rails)?;
    println!("   Original: {}", sample_text.white());
    println!("   Rails: {}", rails.to_string().cyan());
    println!("   Encrypted: {}", railfence_encrypted.green());
    println!("   Decrypted: {}", railfence_decrypted.blue());
    
    // Playfair Cipher Demo
    println!("\n{}", "🎯 Playfair Cipher:".yellow());
    let playfair_key = "MONARCHY";
    let playfair_text = "HELLO";
    let playfair_encrypted = playfair::encrypt(playfair_text, playfair_key)?;
    let playfair_decrypted = playfair::decrypt(&playfair_encrypted, playfair_key)?;
    println!("   Original: {}", playfair_text.white());
    println!("   Key: {}", playfair_key.cyan());
    println!("   Encrypted: {}", playfair_encrypted.green());
    println!("   Decrypted: {}", playfair_decrypted.blue());
    
    Ok(())
}

fn demo_stream_ciphers() -> Result<()> {
    let sample_text = "Hello, World! This is a secret message.";
    
    // RC4 Cipher Demo with Base64
    println!("{}", "🔐 RC4 Stream Cipher (Base64):".yellow());
    let key = "secretkey123";
    let rc4_encrypted_b64 = rc4::encrypt(sample_text, key, "base64")?;
    let rc4_decrypted_b64 = rc4::decrypt(&rc4_encrypted_b64, key, "base64")?;
    println!("   Original: {}", sample_text.white());
    println!("   Key: {}", key.cyan());
    println!("   Encrypted (Base64): {}", rc4_encrypted_b64.green());
    println!("   Decrypted: {}", rc4_decrypted_b64.blue());
    
    // RC4 Cipher Demo with Hex
    println!("\n{}", "🔐 RC4 Stream Cipher (Hex):".yellow());
    let rc4_encrypted_hex = rc4::encrypt(sample_text, key, "hex")?;
    let rc4_decrypted_hex = rc4::decrypt(&rc4_encrypted_hex, key, "hex")?;
    println!("   Original: {}", sample_text.white());
    println!("   Key: {}", key.cyan());
    println!("   Encrypted (Hex): {}", rc4_encrypted_hex.green());
    println!("   Decrypted: {}", rc4_decrypted_hex.blue());
    
    Ok(())
}

fn demo_hash_functions() -> Result<()> {
    let sample_texts = vec![
        "Hello, World!",
        "RusCrypt is awesome!",
        "Secure hashing with Rust",
    ];
    
    for (i, text) in sample_texts.iter().enumerate() {
        println!("{} {}:", "Sample".yellow(), (i + 1).to_string().cyan());
        println!("   Input: {}", text.white());
        
        // MD5 Hash
        let md5_hash = md5::hash(text)?;
        println!("   MD5:    {}", md5_hash.bright_red());
        
        // SHA-1 Hash
        let sha1_hash = sha1::hash(text)?;
        println!("   SHA-1:  {}", sha1_hash.bright_yellow());
        
        // SHA-256 Hash
        let sha256_hash = sha256::hash(text)?;
        println!("   SHA-256: {}", sha256_hash.bright_green());
        
        if i < sample_texts.len() - 1 {
            println!();
        }
    }
    
    // Demonstrate hash consistency
    println!("\n{}", "🔍 Hash Consistency Check:".yellow());
    let test_input = "consistency_test";
    let hash1 = sha256::hash(test_input)?;
    let hash2 = sha256::hash(test_input)?;
    println!("   Input: {}", test_input.white());
    println!("   Hash 1: {}", hash1.green());
    println!("   Hash 2: {}", hash2.green());
    println!("   Match: {}", if hash1 == hash2 { "✅ Yes".bright_green() } else { "❌ No".bright_red() });
    
    Ok(())
}
