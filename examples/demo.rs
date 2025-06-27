use anyhow::Result;
use colored::*;

// Import all modules from ruscrypt
use ruscrypt::classical::{caesar, rail_fence, vigenere, playfair};
use ruscrypt::stream::rc4;
use ruscrypt::block::{aes, des};
use ruscrypt::asym::{rsa, dh};
use ruscrypt::hash::{md5, sha1, sha256};

fn main() -> Result<()> {
    print_demo_banner();
    
    println!("{}", "🔐 Classical Ciphers Demo".cyan().bold());
    println!("{}", "═══════════════════════════".cyan());
    demo_classical_ciphers()?;
    
    println!("\n{}", "🌊 Stream Ciphers Demo".green().bold());
    println!("{}", "══════════════════════".green());
    demo_stream_ciphers()?;
    
    println!("\n{}", "🧱 Block Ciphers Demo".blue().bold());
    println!("{}", "═════════════════════".blue());
    demo_block_ciphers()?;
    
    println!("\n{}", "🔑 Asymmetric Cryptography Demo".purple().bold());
    println!("{}", "════════════════════════════════".purple());
    demo_asymmetric_crypto()?;
    
    println!("\n{}", "🔢 Hash Functions Demo".magenta().bold());
    println!("{}", "══════════════════════".magenta());
    demo_hash_functions()?;
    
    println!("\n{}", "✨ Complete RusCrypt Demo Finished!".bright_green().bold());
    println!("{}", "🎓 All algorithms successfully demonstrated.".cyan());
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
    println!("{}\n", "Showcasing ALL implemented cryptographic algorithms".bright_blue().italic());
}

fn demo_classical_ciphers() -> Result<()> {
    let sample_text = "HELLO WORLD";
    
    // Caesar Cipher Demo
    println!("{}", "📜 Caesar Cipher:".yellow());
    let shift = 3;
    let caesar_encrypted = caesar::encrypt(sample_text, shift)?;
    let caesar_decrypted = caesar::decrypt(&caesar_encrypted, shift)?;
    println!("   Original: {}", sample_text.white());
    println!("   Shift: {}", shift.to_string().cyan());
    println!("   Encrypted: {}", caesar_encrypted.green());
    println!("   Decrypted: {}", caesar_decrypted.blue());
    println!("   ⚠️  Security: Educational only - easily broken");
    
    // Vigenère Cipher Demo
    println!("\n{}", "🔤 Vigenère Cipher:".yellow());
    let keyword = "KEY";
    let vigenere_encrypted = vigenere::encrypt(sample_text, keyword)?;
    let vigenere_decrypted = vigenere::decrypt(&vigenere_encrypted, keyword)?;
    println!("   Original: {}", sample_text.white());
    println!("   Keyword: {}", keyword.cyan());
    println!("   Encrypted: {}", vigenere_encrypted.green());
    println!("   Decrypted: {}", vigenere_decrypted.blue());
    println!("   ⚠️  Security: Educational only - vulnerable to frequency analysis");
    
    // Rail Fence Cipher Demo
    println!("\n{}", "🚂 Rail Fence Cipher:".yellow());
    let rails = 3;
    let railfence_encrypted = rail_fence::encrypt(sample_text, rails)?;
    let railfence_decrypted = rail_fence::decrypt(&railfence_encrypted, rails)?;
    println!("   Original: {}", sample_text.white());
    println!("   Rails: {}", rails.to_string().cyan());
    println!("   Encrypted: {}", railfence_encrypted.green());
    println!("   Decrypted: {}", railfence_decrypted.blue());
    println!("   ⚠️  Security: Educational only - simple transposition");
    
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
    println!("   ⚠️  Security: Educational only - digraph substitution");
    
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
    println!("   ⚠️  Security: DEPRECATED - Known vulnerabilities, educational use only");
    
    Ok(())
}

fn demo_block_ciphers() -> Result<()> {
    let sample_text = "This is a block cipher test message!";
    
    // AES Cipher Demo
    println!("{}", "🛡️  AES (Advanced Encryption Standard):".yellow());
    let password = "strongpassword";
    
    // AES-128 ECB
    println!("\n   📌 AES-128 ECB Mode:");
    let aes128_ecb = aes::encrypt(sample_text, password, "128", "ECB", "base64")?;
    let aes128_decrypted = aes::decrypt(&aes128_ecb, password, "128", "ECB", "base64")?;
    println!("      Original: {}", sample_text.white());
    println!("      Password: {}", password.cyan());
    println!("      Encrypted: {}", aes128_ecb.green());
    println!("      Decrypted: {}", aes128_decrypted.blue());
    
    // AES-256 CBC
    println!("\n   📌 AES-256 CBC Mode:");
    let aes256_cbc = aes::encrypt(sample_text, password, "256", "CBC", "hex")?;
    let aes256_decrypted = aes::decrypt(&aes256_cbc, password, "256", "CBC", "hex")?;
    println!("      Original: {}", sample_text.white());
    println!("      Password: {}", password.cyan());
    println!("      Encrypted: {}", aes256_cbc.green());
    println!("      Decrypted: {}", aes256_decrypted.blue());
    println!("      ✅ Security: Modern standard - recommended for production");
    
    // DES Cipher Demo
    println!("\n{}", "🔒 DES (Data Encryption Standard):".yellow());
    let des_key = "8charkey"; // Exactly 8 characters
    
    // DES ECB
    println!("\n   📌 DES ECB Mode:");
    let des_ecb = des::encrypt(sample_text, des_key, "ECB", "base64")?;
    let des_ecb_decrypted = des::decrypt(&des_ecb, des_key, "ECB", "base64")?;
    println!("      Original: {}", sample_text.white());
    println!("      Key: {}", des_key.cyan());
    println!("      Encrypted: {}", des_ecb.green());
    println!("      Decrypted: {}", des_ecb_decrypted.blue());
    
    // DES CBC
    println!("\n   📌 DES CBC Mode:");
    let des_cbc = des::encrypt(sample_text, des_key, "CBC", "hex")?;
    let des_cbc_decrypted = des::decrypt(&des_cbc, des_key, "CBC", "hex")?;
    println!("      Original: {}", sample_text.white());
    println!("      Key: {}", des_key.cyan());
    println!("      Encrypted: {}", des_cbc.green());
    println!("      Decrypted: {}", des_cbc_decrypted.blue());
    println!("      ⚠️  Security: DEPRECATED - 56-bit key too small, educational use only");
    
    Ok(())
}

fn demo_asymmetric_crypto() -> Result<()> {
    let sample_text = "Asymmetric encryption test!";
    
    // RSA Demo
    println!("{}", "🔐 RSA (Rivest-Shamir-Adleman):".yellow());
    
    // RSA with different key sizes
    for key_size in ["512", "1024"] {
        println!("\n   📌 RSA-{} Encryption:", key_size);
        let (encrypted, private_key) = rsa::encrypt(sample_text, key_size, "base64")?;
        let decrypted = rsa::decrypt(&encrypted, &private_key, "base64")?;
        println!("      Original: {}", sample_text.white());
        println!("      Key Size: {} bits", key_size.cyan());
        println!("      Encrypted: {}...", encrypted[..50].green());
        println!("      Private Key: {}...", private_key[..20].yellow());
        println!("      Decrypted: {}", decrypted.blue());
    }
    println!("      ✅ Security: Secure with ≥2048 bits (demo uses smaller for speed)");
    
    // Diffie-Hellman Demo
    println!("\n{}", "🤝 Diffie-Hellman Key Exchange:".yellow());
    println!("   📌 Educational Concept Demonstration:");
    
    // Create two participants manually for demo
    let alice = dh::DHParticipant::new();
    let mut bob = dh::DHParticipant::new();
    
    println!("      👩 Alice generates keys:");
    println!("         Private: {} (secret)", alice.private_key.to_string().red());
    println!("         Public:  {} (shared)", alice.public_key.to_string().green());
    
    println!("      👨 Bob generates keys:");
    println!("         Private: {} (secret)", bob.private_key.to_string().red());
    println!("         Public:  {} (shared)", bob.public_key.to_string().green());
    
    // Compute shared secret
    let shared_secret = bob.compute_shared_secret(alice.public_key)?;
    println!("      🤝 Computed shared secret: {}", shared_secret.to_string().cyan());
    println!("      ✅ Security: Secure with proper parameters and authentication");
    
    Ok(())
}

fn demo_hash_functions() -> Result<()> {
    let sample_texts = vec![
        "Hello, World!",
        "RusCrypt is awesome!",
        "Secure hashing with Rust",
        "Small change", 
        "small change", // Demonstrate avalanche effect
    ];
    
    println!("{}", "Hash Function Comparison:".yellow());
    println!("{}", "═════════════════════════".yellow());
    
    for (i, text) in sample_texts.iter().enumerate() {
        println!("\n{} {}:", "Sample".cyan(), (i + 1).to_string().cyan());
        println!("   Input: {}", text.white());
        
        // MD5 Hash
        let md5_hash = md5::hash(text)?;
        println!("   MD5    (128-bit): {}", md5_hash.bright_red());
        
        // SHA-1 Hash
        let sha1_hash = sha1::hash(text)?;
        println!("   SHA-1  (160-bit): {}", sha1_hash.bright_yellow());
        
        // SHA-256 Hash
        let sha256_hash = sha256::hash(text)?;
        println!("   SHA-256(256-bit): {}", sha256_hash.bright_green());
        
        if i == 3 { // Show avalanche effect
            println!("   💡 Notice how 'Small change' vs 'small change' produces completely different hashes!");
        }
    }
    
    // Security status
    println!("\n{}", "Security Status:".yellow());
    println!("   ❌ MD5:    BROKEN - Collision attacks possible");
    println!("   ⚠️  SHA-1:  DEPRECATED - Use only for legacy compatibility");
    println!("   ✅ SHA-256: SECURE - Recommended for modern applications");
    
    // Demonstrate hash consistency
    println!("\n{}", "🔍 Hash Consistency Verification:".yellow());
    let test_input = "consistency_test";
    let hash1 = sha256::hash(test_input)?;
    let hash2 = sha256::hash(test_input)?;
    println!("   Input: {}", test_input.white());
    println!("   Hash 1: {}", hash1.green());
    println!("   Hash 2: {}", hash2.green());
    println!("   Match: {}", if hash1 == hash2 { "✅ Perfect consistency".bright_green() } else { "❌ Error!".bright_red() });
    
    Ok(())
}
