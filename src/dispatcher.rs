use anyhow::Result;
use colored::*;

use crate::cli::{Args, Commands, EncryptionAlgorithm, HashAlgorithm};
use crate::classical::{caesar, rail_fence, vigenere, playfair};
use crate::interactive;

pub fn dispatch_command(args: Args) -> Result<()> {
    // Print the parsed arguments
    println!("\n{}", "📋 Parsed Command Arguments:".cyan());
    println!("{}", "═════════════════════════════".cyan());
    
    match &args.command {
        Commands::Encrypt { algorithm } => {
            println!("{}: {}", "Command".yellow().bold(), "Encrypt".green());
            print_algorithm_details(algorithm);
        },
        Commands::Decrypt { algorithm } => {
            println!("{}: {}", "Command".yellow().bold(), "Decrypt".blue());
            print_algorithm_details(algorithm);
        },
        Commands::Hash { algorithm } => {
            println!("{}: {}", "Command".yellow().bold(), "Hash".magenta());
            print_hash_algorithm_details(algorithm);
        },
    }
    
    println!("{}\n", "═════════════════════════════".cyan());

    // Original command dispatch logic
    match args.command {
        Commands::Encrypt { algorithm } => {
            let algo_name = crate::cli::get_algorithm_name(&algorithm);
            println!("{} {}", "🔒 Encrypting with".green(), algo_name.yellow().bold());
            handle_encryption(algorithm)?;
        },
        Commands::Decrypt { algorithm } => {
            let algo_name = crate::cli::get_algorithm_name(&algorithm);
            println!("{} {}", "🔓 Decrypting with".blue(), algo_name.yellow().bold());
            handle_decryption(algorithm)?;
        },
        Commands::Hash { algorithm } => {
            let algo_name = crate::cli::get_hash_algorithm_name(&algorithm);
            println!("{} {}", "🔢 Hashing with".magenta(), algo_name.yellow().bold());
            handle_hashing(algorithm)?;
        },
    }

    Ok(())
}

fn print_algorithm_details(algorithm: &EncryptionAlgorithm) {
    let algo_name = crate::cli::get_algorithm_name(algorithm);
    println!("{}: {}", "Algorithm".yellow().bold(), algo_name.white());
    
    // Print algorithm-specific flags
    println!("{}: ", "Details".yellow().bold());
    if algorithm.caesar { println!("  - Caesar cipher selected"); }
    if algorithm.vigenere { println!("  - Vigenère cipher selected"); }
    if algorithm.playfair { println!("  - Playfair cipher selected"); }
    if algorithm.railfence { println!("  - Rail Fence cipher selected"); }
    if algorithm.rc4 { println!("  - RC4 stream cipher selected"); }
    if algorithm.aes { println!("  - AES block cipher selected"); }
    if algorithm.des { println!("  - DES block cipher selected"); }
    if algorithm.rsa { println!("  - RSA asymmetric encryption selected"); }
    if algorithm.dh { println!("  - Diffie-Hellman key exchange selected"); }
}

fn print_hash_algorithm_details(algorithm: &HashAlgorithm) {
    let algo_name = crate::cli::get_hash_algorithm_name(algorithm);
    println!("{}: {}", "Algorithm".yellow().bold(), algo_name.white());
    
    // Print algorithm-specific flags
    println!("{}: ", "Details".yellow().bold());
    if algorithm.md5 { println!("  - MD5 hash function selected"); }
    if algorithm.sha1 { println!("  - SHA-1 hash function selected"); }
    if algorithm.sha256 { println!("  - SHA-256 hash function selected"); }
}

fn handle_encryption(algorithm: EncryptionAlgorithm) -> Result<()> {
    let input = interactive::prompt_for_input("Enter text to encrypt")?;
    
    let result = match true {
        _ if algorithm.caesar => {
            let shift = interactive::prompt_for_number("Enter shift value (1-25)", 1, 25)?;
            let encrypted = caesar::encrypt(&input, shift as u8)?;
            format!("Encrypted text: {}", encrypted)
        },
        _ if algorithm.vigenere => {
            let keyword = interactive::prompt_for_input("Enter keyword")?;
            let encrypted = vigenere::encrypt(&input, &keyword)?;
            format!("Encrypted text: {}", encrypted)
        },
        _ if algorithm.playfair => {
            let keyword = interactive::prompt_for_input("Enter keyword for matrix")?;
            let encrypted = playfair::encrypt(&input, &keyword)?;
            format!("Encrypted text: {}", encrypted)
        },
        _ if algorithm.railfence => {
            let rails = interactive::prompt_for_number("Enter number of rails (2-10)", 2, 10)?;
            let encrypted = rail_fence::encrypt(&input, rails as usize)?;
            format!("Encrypted text: {}", encrypted)
        },
        _ if algorithm.rc4 => {
            let key = interactive::prompt_for_password("Enter encryption key")?;
            format!("RC4 encryption will be implemented soon with key {} for input: {}", key, input)
        },
        _ if algorithm.aes => {
            let password = interactive::prompt_for_password("Enter password")?;
            format!("AES encryption will be implemented soon for password {} for input: {}", password, input)
        },
        _ if algorithm.des => {
            let key = interactive::prompt_for_password("Enter key (8 characters)")?;
            format!("DES encryption will be implemented soon for key {} for input: {}", key, input)
        },
        _ if algorithm.rsa => {
            let key_size = interactive::prompt_for_choices(
                "Select key size", 
                &["1024", "2048", "4096"]
            )?;
            format!("RSA encryption with {} bit key will be implemented soon for input: {}", key_size, input)
        },
        _ if algorithm.dh => {
            format!("Diffie-Hellman key exchange will be implemented soon for input: {}", input)
        },
        _ => return Err(anyhow::anyhow!("Unknown algorithm")),
    };

    println!("\n{} {}", "Result:".cyan().bold(), result.white());
    Ok(())
}

fn handle_decryption(algorithm: EncryptionAlgorithm) -> Result<()> {
    let input = interactive::prompt_for_input("Enter text to decrypt")?;
    
    let result = match true {
        _ if algorithm.caesar => {
            let shift = interactive::prompt_for_number("Enter shift value (1-25)", 1, 25)?;
            let decrypted = caesar::decrypt(&input, shift as u8)?;
            format!("Decrypted text: {}", decrypted)
        },
        _ if algorithm.vigenere => {
            let keyword = interactive::prompt_for_input("Enter keyword")?;
            let decrypted = vigenere::decrypt(&input, &keyword)?;
            format!("Decrypted text: {}", decrypted)
        },
        _ if algorithm.playfair => {
            let keyword = interactive::prompt_for_input("Enter keyword for matrix")?;
            let decrypted = playfair::decrypt(&input, &keyword)?;
            format!("Decrypted text: {}", decrypted)
        },
        _ if algorithm.railfence => {
            let rails = interactive::prompt_for_number("Enter number of rails (2-10)", 2, 10)?;
            let decrypted = rail_fence::decrypt(&input, rails as usize)?;
            format!("Decrypted text: {}", decrypted)
        },
        _ if algorithm.rc4 => {
            let key = interactive::prompt_for_password("Enter decryption key")?;
            format!("RC4 decryption will be implemented soon with key {} for input: {}", key, input)
        },
        _ if algorithm.aes => {
            let password = interactive::prompt_for_password("Enter password")?;
            format!("AES decryption will be implemented soon for password {} for input: {}", password, input)
        },
        _ if algorithm.des => {
            let key = interactive::prompt_for_password("Enter key (8 characters)")?;
            format!("DES decryption will be implemented soon for key {} for input: {}", key, input)
        },
        _ if algorithm.rsa => {
            let private_key = interactive::prompt_for_input("Enter or paste private key")?;
            format!("RSA decryption will be implemented soon with private key {} for input: {}", private_key, input)
        },
        _ if algorithm.dh => {
            format!("Diffie-Hellman key import will be implemented soon for input: {}", input)
        },
        _ => return Err(anyhow::anyhow!("Unknown algorithm")),
    };

    println!("\n{} {}", "Result:".cyan().bold(), result.white());
    Ok(())
}

fn handle_hashing(algorithm: HashAlgorithm) -> Result<()> {
    let input = interactive::prompt_for_input("Enter text to hash")?;
    
    let result = match true {
        _ if algorithm.md5 => {
            format!("MD5 hashing will be implemented soon for input: {}", input)
        },
        _ if algorithm.sha1 => {
            format!("SHA-1 hashing will be implemented soon for input: {}", input)
        },
        _ if algorithm.sha256 => {
            format!("SHA-256 hashing will be implemented soon for input: {}", input)
        },
        _ => return Err(anyhow::anyhow!("Unknown algorithm")),
    };

    println!("\n{} {}", "Result:".blue().bold(), result.white());
    Ok(())
}