use anyhow::Result;
use colored::*;

// Import the modules from ruscrypt
use ruscrypt::classical::caesar;
use ruscrypt::stream::rc4;
use ruscrypt::hash::sha256;

fn main() -> Result<()> {
    print_quick_start_banner();
    
    println!("{}", "Let's get started with some basic examples!\n".bright_blue());
    
    // Quick Caesar cipher example
    println!("{}", "1. 📜 Classical Encryption (Caesar Cipher)".cyan().bold());
    quick_classical_example()?;
    
    // Quick stream cipher example
    println!("\n{}", "2. 🌊 Modern Encryption (RC4 Stream Cipher)".green().bold());
    quick_stream_example()?;
    
    // Quick hash example
    println!("\n{}", "3. 🔢 Secure Hashing (SHA-256)".magenta().bold());
    quick_hash_example()?;
    
    println!("\n{}", "🎉 That's it! You've seen the basics of RusCrypt.".bright_green().bold());
    println!("{}", "Run the full demo with: cargo run --example demo".yellow());
    println!("{}", "Use the CLI with: cargo run -- encrypt --caesar".yellow());
    
    Ok(())
}

fn print_quick_start_banner() {
    println!("{}", r"
  ____            ____                  _   
 |  _ \ _   _ ___ / ___|_ __ _   _ _ __ | |_ 
 | |_) | | | / __| |   | '__| | | | '_ \| __|
 |  _ <| |_| \__ \ |___| |  | |_| | |_) | |_ 
 |_| \_\\__,_|___/\____|_|   \__, | .__/ \__|
                             |___/|_|        
    ".bright_blue());
    
    println!("{}", "🚀 Quick Start Guide".bright_blue().bold());
    println!("{}", "Learn RusCrypt in 3 simple examples".cyan().italic());
    println!();
}

fn quick_classical_example() -> Result<()> {
    println!("{}", "   Caesar cipher shifts each letter by a fixed number.".white());
    
    let message = "HELLO";
    let shift = 3;
    
    // Encrypt
    let encrypted = caesar::encrypt(message, shift)?;
    println!("   📝 Original message: {}", message.yellow());
    println!("   🔢 Shift amount: {}", shift.to_string().cyan());
    println!("   🔒 Encrypted: {} → {}", message.white(), encrypted.green().bold());
    
    // Decrypt
    let decrypted = caesar::decrypt(&encrypted, shift)?;
    println!("   🔓 Decrypted: {} → {}", encrypted.white(), decrypted.blue().bold());
    
    println!("   💡 Try: cargo run -- encrypt --caesar");
    
    Ok(())
}

fn quick_stream_example() -> Result<()> {
    println!("{}", "   RC4 is a stream cipher that encrypts data byte by byte.".white());
    
    let message = "Secret message!";
    let key = "mykey";
    
    // Encrypt
    let encrypted = rc4::encrypt(message, key, "base64")?;
    println!("   📝 Original message: {}", message.yellow());
    println!("   🗝️  Encryption key: {}", key.cyan());
    println!("   🔒 Encrypted (Base64): {}", encrypted.green().bold());
    
    // Decrypt
    let decrypted = rc4::decrypt(&encrypted, key, "base64")?;
    println!("   🔓 Decrypted: {}", decrypted.blue().bold());
    
    println!("   💡 Try: cargo run -- encrypt --rc4");
    
    Ok(())
}

fn quick_hash_example() -> Result<()> {
    println!("{}", "   SHA-256 creates a unique fingerprint for any input.".white());
    
    let messages = vec!["Hello", "Hello!", "hello"];
    
    for message in messages {
        let hash = sha256::hash(message)?;
        println!("   📝 Input: {} → Hash: {}", 
                message.yellow(), 
                format!("{}{}", hash[..16].to_string().green().bold(), "...")
        );
    }
    
    println!("   ✨ Notice how small changes create completely different hashes!");
    println!("   💡 Try: cargo run -- hash --sha256");
    
    Ok(())
}
