use anyhow::Result;
use colored::*;

// Import key modules from ruscrypt
use ruscrypt::classical::caesar;
use ruscrypt::stream::rc4;
use ruscrypt::block::aes;
use ruscrypt::asym::rsa;
use ruscrypt::hash::sha256;

fn main() -> Result<()> {
    print_quick_start_banner();
    
    println!("{}", "Let's explore RusCrypt with 5 essential examples!\n".bright_blue());
    
    // Classical cipher example
    println!("{}", "1. 📜 Classical Cryptography (Caesar Cipher)".cyan().bold());
    quick_classical_example()?;
    
    // Stream cipher example
    println!("\n{}", "2. 🌊 Stream Encryption (RC4)".green().bold());
    quick_stream_example()?;
    
    // Block cipher example
    println!("\n{}", "3. 🛡️  Modern Encryption (AES)".blue().bold());
    quick_block_example()?;
    
    // Asymmetric encryption example
    println!("\n{}", "4. 🔐 Public-Key Cryptography (RSA)".purple().bold());
    quick_asymmetric_example()?;
    
    // Hash function example
    println!("\n{}", "5. 🔢 Secure Hashing (SHA-256)".magenta().bold());
    quick_hash_example()?;
    
    print_next_steps();
    
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
    
    println!("{}", "🚀 RusCrypt Quick Start Guide".bright_blue().bold());
    println!("{}", "Master cryptography in 5 simple examples".cyan().italic());
    println!();
}

fn quick_classical_example() -> Result<()> {
    println!("{}", "   Historical cipher used by Julius Caesar.".white());
    println!("{}", "   🎓 Educational: Shows basic substitution concepts".yellow());
    
    let message = "HELLO WORLD";
    let shift = 3;
    
    // Encrypt
    let encrypted = caesar::encrypt(message, shift)?;
    println!("   📝 Original: {}", message.cyan());
    println!("   🔢 Shift: {} positions", shift.to_string().yellow());
    println!("   🔒 Encrypted: {} → {}", message.white(), encrypted.green().bold());
    
    // Decrypt
    let decrypted = caesar::decrypt(&encrypted, shift)?;
    println!("   🔓 Decrypted: {} → {}", encrypted.white(), decrypted.blue().bold());
    
    println!("   ⚠️  Security: Educational only - easily broken!");
    println!("   💡 Try: {}", "cargo run -- encrypt --caesar".bright_green());
    
    Ok(())
}

fn quick_stream_example() -> Result<()> {
    println!("{}", "   Encrypts data byte-by-byte using a keystream.".white());
    println!("{}", "   ⚠️  Deprecated: Known vulnerabilities, educational use only".yellow());
    
    let message = "Secret message!";
    let key = "mykey123";
    
    // Encrypt
    let encrypted = rc4::encrypt(message, key, "base64")?;
    println!("   📝 Original: {}", message.cyan());
    println!("   🗝️  Key: {}", key.yellow());
    println!("   🔒 Encrypted: {}", encrypted.green().bold());
    
    // Decrypt
    let decrypted = rc4::decrypt(&encrypted, key, "base64")?;
    println!("   🔓 Decrypted: {}", decrypted.blue().bold());
    
    println!("   🔄 Round-trip: {} = {}", message == decrypted, if message == decrypted { "✅" } else { "❌" });
    println!("   💡 Try: {}", "cargo run -- encrypt --rc4".bright_green());
    
    Ok(())
}

fn quick_block_example() -> Result<()> {
    println!("{}", "   Industry-standard symmetric encryption.".white());
    println!("{}", "   ✅ Secure: Recommended for modern applications".green());
    
    let message = "Top secret data!";
    let password = "strongpassword";
    
    // Encrypt with AES-256 CBC
    let encrypted = aes::encrypt(message, password, "256", "CBC", "base64")?;
    println!("   📝 Original: {}", message.cyan());
    println!("   🔑 Password: {}", password.yellow());
    println!("   🔒 Encrypted (AES-256 CBC): {}", encrypted.green().bold());
    
    // Decrypt
    let decrypted = aes::decrypt(&encrypted, password, "256", "CBC", "base64")?;
    println!("   🔓 Decrypted: {}", decrypted.blue().bold());
    
    println!("   🛡️  Security: Bank-grade encryption!");
    println!("   💡 Try: {}", "cargo run -- encrypt --aes".bright_green());
    
    Ok(())
}

fn quick_asymmetric_example() -> Result<()> {
    println!("{}", "   Public-key cryptography for secure communication.".white());
    println!("{}", "   🔐 Concept: Different keys for encryption/decryption".yellow());
    
    let message = "Hello RSA!";
    
    // Encrypt (generates key pair automatically)
    let (encrypted, private_key) = rsa::encrypt(message, "512", "base64", "n:e")?;
    println!("   📝 Original: {}", message.cyan());
    println!("   🔒 Encrypted: {}...", encrypted[..30].green().bold());
    println!("   🔑 Private Key: {}...", private_key[..20].yellow());
    
    // Decrypt
    let decrypted = rsa::decrypt(&encrypted, &private_key, "base64")?;
    println!("   🔓 Decrypted: {}", decrypted.blue().bold());
    
    println!("   🌐 Use case: Secure communication without shared secrets");
    println!("   💡 Try: {}", "cargo run -- encrypt --rsa".bright_green());
    
    Ok(())
}

fn quick_hash_example() -> Result<()> {
    println!("{}", "   Creates unique fingerprints for any data.".white());
    println!("{}", "   ✅ Secure: Perfect for data integrity and passwords".green());
    
    let messages = vec!["Hello", "Hello!", "hello"];
    
    for (i, message) in messages.iter().enumerate() {
        let hash = sha256::hash(message)?;
        println!("   📝 Input {}: {} → Hash: {}...", 
                (i + 1).to_string().white(),
                message.cyan(), 
                hash[..16].green().bold()
        );
    }
    
    // Show consistency
    let test = "consistency";
    let hash1 = sha256::hash(test)?;
    let hash2 = sha256::hash(test)?;
    println!("   🔍 Consistency: {} → {}", 
            if hash1 == hash2 { "✅ Always same result" } else { "❌ Error" },
            if hash1 == hash2 { "Perfect!" } else { "Failed!" }
    );
    
    println!("   ✨ Notice: Small input changes = Completely different hashes!");
    println!("   💡 Try: {}", "cargo run -- hash --sha256".bright_green());
    
    Ok(())
}

fn print_next_steps() {
    println!("\n{}", "🎉 Congratulations! You've mastered RusCrypt basics!".bright_green().bold());
    println!();
    
    println!("{}", "🚀 Next Steps:".yellow().bold());
    println!("   • Run the full demo: {}", "cargo run --example demo".bright_cyan());
    println!("   • Try the CLI tool: {}", "cargo run -- --help".bright_cyan());
    println!("   • Explore algorithms: {}", "cargo run -- encrypt --help".bright_cyan());
    println!();
    
    println!("{}", "📚 Available Algorithms:".yellow().bold());
    println!("   Classical:  Caesar, Vigenère, Playfair, Rail Fence");
    println!("   Stream:     RC4 (educational)");
    println!("   Block:      AES (secure), DES (educational)");
    println!("   Asymmetric: RSA, Diffie-Hellman");
    println!("   Hash:       MD5, SHA-1 (legacy), SHA-256 (secure)");
    println!();
    
    println!("{}", "🔒 Security Reminder:".red().bold());
    println!("   ✅ Production: AES, RSA (≥2048 bits), SHA-256");
    println!("   🎓 Education: All classical ciphers, RC4, DES, MD5, SHA-1");
    println!();
    
    println!("{}", "Built with ❤️  using Rust 🦀".bright_blue().italic());
}
