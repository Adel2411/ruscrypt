//! # Command Dispatcher Module
//! 
//! This module handles the routing and execution of CLI commands. It takes parsed
//! command-line arguments and dispatches them to the appropriate cryptographic
//! functions while providing user interaction and formatted output.
//! 
//! ## Architecture
//! 
//! The dispatcher follows a pattern where:
//! 1. Commands are parsed and displayed to the user
//! 2. Interactive prompts gather necessary parameters
//! 3. Appropriate cryptographic functions are called
//! 4. Results are formatted and displayed
//! 
//! ## Error Handling
//! 
//! All functions return `Result<()>` to enable proper error propagation
//! and user-friendly error messages.

use anyhow::Result;
use colored::*;

use crate::cli::{Args, Commands, EncryptionAlgorithm, HashAlgorithm, ExchangeProtocol};
use crate::classical::{caesar, rail_fence, vigenere, playfair};
use crate::stream::rc4;
use crate::hash::{md5, sha1, sha256};
use crate::interactive;
use crate::block::{des, aes};
use crate::asym::{dh, rsa};

/// Main command dispatcher function
/// 
/// This is the primary entry point for command execution. It displays the parsed
/// command information to the user and then routes to the appropriate handler
/// function based on the command type.
/// 
/// # Arguments
/// 
/// * `args` - Parsed command-line arguments containing the command and parameters
/// 
/// # Returns
/// 
/// Returns `Ok(())` on successful execution, or an error if the operation fails.
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::{cli, dispatcher};
/// 
/// let args = cli::parse_args();
/// dispatcher::dispatch_command(args)?;
/// ```
/// 
/// # Errors
/// 
/// This function can return errors from:
/// - Invalid algorithm selection
/// - User input validation failures
/// - Cryptographic operation failures
/// - I/O errors during interactive prompts
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
        Commands::Exchange { protocol } => {
            println!("{}: {}", "Command".yellow().bold(), "Key Exchange".purple());
            print_keyexchange_protocol_details(protocol);
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
        Commands::Exchange { protocol } => {
            let protocol_name = crate::cli::get_keyexchange_protocol_name(&protocol);
            println!("{} {}", "🔑 Key Exchange with".purple(), protocol_name.yellow().bold());
            handle_key_exchange(protocol)?;
        },
    }

    Ok(())
}

/// Display detailed information about the selected encryption algorithm
/// 
/// Formats and prints algorithm-specific information including the algorithm
/// name and which specific variant was selected by the user.
/// 
/// # Arguments
/// 
/// * `algorithm` - Reference to the selected encryption algorithm configuration
/// 
/// # Output
/// 
/// Prints formatted information to stdout including:
/// - Algorithm name
/// - Specific variant details
/// - Any relevant security warnings
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
}

/// Display detailed information about the selected hash algorithm
/// 
/// Formats and prints hash algorithm-specific information including the
/// algorithm name and security considerations.
/// 
/// # Arguments
/// 
/// * `algorithm` - Reference to the selected hash algorithm configuration
/// 
/// # Output
/// 
/// Prints formatted information to stdout including:
/// - Hash algorithm name
/// - Output size information
/// - Security status (secure/deprecated)
fn print_hash_algorithm_details(algorithm: &HashAlgorithm) {
    let algo_name = crate::cli::get_hash_algorithm_name(algorithm);
    println!("{}: {}", "Algorithm".yellow().bold(), algo_name.white());
    
    // Print algorithm-specific flags
    println!("{}: ", "Details".yellow().bold());
    if algorithm.md5 { println!("  - MD5 hash function selected"); }
    if algorithm.sha1 { println!("  - SHA-1 hash function selected"); }
    if algorithm.sha256 { println!("  - SHA-256 hash function selected"); }
}

/// Display detailed information about the selected key exchange protocol
/// 
/// Formats and prints protocol-specific information including the protocol
/// name and implementation status.
/// 
/// # Arguments
/// 
/// * `protocol` - Reference to the selected key exchange protocol configuration
/// 
/// # Output
/// 
/// Prints formatted information to stdout including:
/// - Protocol name
/// - Implementation status
/// - Usage recommendations
fn print_keyexchange_protocol_details(protocol: &ExchangeProtocol) {
    let protocol_name = crate::cli::get_keyexchange_protocol_name(protocol);
    println!("{}: {}", "Protocol".yellow().bold(), protocol_name.white());
    
    // Print protocol-specific flags
    println!("{}: ", "Details".yellow().bold());
    if protocol.dh { println!("  - Diffie-Hellman key exchange protocol selected"); }
    if protocol.ecdh { println!("  - ECDH key exchange protocol selected (not implemented)"); }
}

/// Handle encryption operations for all supported algorithms
/// 
/// This function manages the encryption workflow by:
/// 1. Prompting for input text
/// 2. Gathering algorithm-specific parameters (keys, shifts, etc.)
/// 3. Calling the appropriate encryption function
/// 4. Displaying the encrypted result
/// 
/// # Arguments
/// 
/// * `algorithm` - The encryption algorithm configuration specifying which algorithm to use
/// 
/// # Returns
/// 
/// Returns `Ok(())` on successful encryption, or an error if the operation fails.
/// 
/// # Interactive Prompts
/// 
/// Depending on the algorithm, this function may prompt for:
/// - Shift values (Caesar cipher)
/// - Keywords (Vigenère, Playfair)
/// - Keys and passwords (RC4, AES, DES, RSA)
/// - Encoding preferences (base64, hex)
/// - Algorithm parameters (key sizes, modes)
/// 
/// # Errors
/// 
/// Can return errors from:
/// - Invalid user input
/// - Cryptographic operation failures
/// - I/O errors during prompts
/// - Algorithm-specific validation failures
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
            let encoding = interactive::prompt_for_choices(
                "Select output encoding",
                &["base64", "hex"]
            )?;
            let encrypted = rc4::encrypt(&input, &key, &encoding)?;
            format!("Encrypted text ({}): {}", encoding, encrypted)
        },
        _ if algorithm.aes => {
            let password = interactive::prompt_for_password("Enter password")?;
            let key_size = interactive::prompt_for_choices(
                "Select AES key size",
                &["128", "192", "256"]
            )?;
            let mode = interactive::prompt_for_choices(
                "Select encryption mode",
                &["ECB", "CBC"]
            )?;
            let encoding = interactive::prompt_for_choices(
                "Select output encoding",
                &["base64", "hex"]
            )?;
            let encrypted = aes::encrypt(&input, &password, &key_size, &mode, &encoding)?;
            format!("Encrypted text (AES-{}, {}, {}): {}", key_size, mode, encoding, encrypted)
        },
        _ if algorithm.des => {
            let key = interactive::prompt_for_input("Enter key (exactly 8 characters)")?;
            if key.len() != 8 {
                return Err(anyhow::anyhow!("DES key must be exactly 8 characters long"));
            }
            let mode = interactive::prompt_for_choices(
                "Select encryption mode",
                &["ECB", "CBC"]
            )?;
            let encoding = interactive::prompt_for_choices(
                "Select output encoding",
                &["base64", "hex"]
            )?;
            let encrypted = des::encrypt(&input, &key, &mode, &encoding)?;
            format!("Encrypted text (DES, {}, {}): {}", mode, encoding, encrypted)
        },
        _ if algorithm.rsa => {
            let key_size = interactive::prompt_for_choices(
                "Select RSA key size",
                &["512", "1024", "2048"]
            )?;
            let encoding = interactive::prompt_for_choices(
                "Select output encoding",
                &["base64", "hex"]
            )?;
            
            let (encrypted, private_key) = rsa::encrypt(&input, &key_size, &encoding)?;
            
            println!("\n🔐 RSA Encryption Complete!");
            println!("📤 Encrypted data: {}", encrypted);
            println!("🔑 Private key (SAVE THIS!): {}", private_key);
            println!("⚠️  Keep your private key secure - you'll need it for decryption!");
            
            format!("RSA-{} encryption successful. Encrypted data and private key provided above.", key_size)
        },
        _ => return Err(anyhow::anyhow!("Unknown algorithm")),
    };

    println!("\n{} {}", "Result:".cyan().bold(), result.white());
    Ok(())
}

/// Handle decryption operations for all supported algorithms
/// 
/// This function manages the decryption workflow by:
/// 1. Prompting for encrypted text
/// 2. Gathering algorithm-specific parameters (keys, shifts, etc.)
/// 3. Calling the appropriate decryption function
/// 4. Displaying the decrypted result
/// 
/// # Arguments
/// 
/// * `algorithm` - The encryption algorithm configuration specifying which algorithm to use
/// 
/// # Returns
/// 
/// Returns `Ok(())` on successful decryption, or an error if the operation fails.
/// 
/// # Interactive Prompts
/// 
/// Similar to encryption, but may include additional prompts for:
/// - Private keys (RSA)
/// - Initialization vectors (block ciphers)
/// - Input encoding formats (base64, hex)
/// 
/// # Errors
/// 
/// Can return errors from:
/// - Invalid encrypted text format
/// - Incorrect keys or parameters
/// - Cryptographic operation failures
/// - Encoding/decoding errors
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
            let encoding = interactive::prompt_for_choices(
                "Select input encoding",
                &["base64", "hex"]
            )?;
            let decrypted = rc4::decrypt(&input, &key, &encoding)?;
            format!("Decrypted text: {}", decrypted)
        },
        _ if algorithm.aes => {
            let password = interactive::prompt_for_password("Enter password")?;
            let key_size = interactive::prompt_for_choices(
                "Select AES key size",
                &["128", "192", "256"]
            )?;
            let mode = interactive::prompt_for_choices(
                "Select encryption mode",
                &["ECB", "CBC"]
            )?;
            let encoding = interactive::prompt_for_choices(
                "Select input encoding",
                &["base64", "hex"]
            )?;
            let decrypted = aes::decrypt(&input, &password, &key_size, &mode, &encoding)?;
            format!("Decrypted text: {}", decrypted)
        },
        _ if algorithm.des => {
            let key = interactive::prompt_for_input("Enter key (exactly 8 characters)")?;
            if key.len() != 8 {
                return Err(anyhow::anyhow!("DES key must be exactly 8 characters long"));
            }
            let mode = interactive::prompt_for_choices(
                "Select encryption mode",
                &["ECB", "CBC"]
            )?;
            let encoding = interactive::prompt_for_choices(
                "Select input encoding",
                &["base64", "hex"]
            )?;
            let decrypted = des::decrypt(&input, &key, &mode, &encoding)?;
            format!("Decrypted text: {}", decrypted)
        },
        _ if algorithm.rsa => {
            let private_key = interactive::prompt_for_input("Enter private key (format: n:d)")?;
            let encoding = interactive::prompt_for_choices(
                "Select input encoding",
                &["base64", "hex"]
            )?;
            let decrypted = rsa::decrypt(&input, &private_key, &encoding)?;
            format!("Decrypted text: {}", decrypted)
        },
        _ => return Err(anyhow::anyhow!("Unknown algorithm")),
    };

    println!("\n{} {}", "Result:".cyan().bold(), result.white());
    Ok(())
}

/// Handle hashing operations for all supported hash functions
/// 
/// This function manages the hashing workflow by:
/// 1. Prompting for input text
/// 2. Computing the hash using the selected algorithm
/// 3. Displaying the hash value in hexadecimal format
/// 
/// # Arguments
/// 
/// * `algorithm` - The hash algorithm configuration specifying which function to use
/// 
/// # Returns
/// 
/// Returns `Ok(())` on successful hashing, or an error if the operation fails.
/// 
/// # Output Format
/// 
/// Hash values are displayed as hexadecimal strings:
/// - MD5: 32 characters
/// - SHA-1: 40 characters  
/// - SHA-256: 64 characters
/// 
/// # Errors
/// 
/// Can return errors from:
/// - Hash computation failures
/// - I/O errors during prompts
/// - Memory allocation issues for large inputs
fn handle_hashing(algorithm: HashAlgorithm) -> Result<()> {
    let input = interactive::prompt_for_input("Enter text to hash")?;
    
    let result = match true {
        _ if algorithm.md5 => {
            let hash_value = md5::hash(&input)?;
            format!("MD5 hash: {}", hash_value)
        },
        _ if algorithm.sha1 => {
            let hash_value = sha1::hash(&input)?;
            format!("SHA-1 hash: {}", hash_value)
        },
        _ if algorithm.sha256 => {
            let hash_value = sha256::hash(&input)?;
            format!("SHA-256 hash: {}", hash_value)
        },
        _ => return Err(anyhow::anyhow!("Unknown algorithm")),
    };

    println!("\n{} {}", "Result:".blue().bold(), result.white());
    Ok(())
}

/// Handle key exchange protocol operations
/// 
/// This function manages key exchange workflows by:
/// 1. Presenting protocol-specific options
/// 2. Managing interactive or manual exchange modes
/// 3. Facilitating secure key establishment
/// 4. Displaying shared secrets and educational information
/// 
/// # Arguments
/// 
/// * `protocol` - The key exchange protocol configuration
/// 
/// # Returns
/// 
/// Returns `Ok(())` on successful key exchange, or an error if the operation fails.
/// 
/// # Supported Modes
/// 
/// For Diffie-Hellman:
/// - **Interactive Simulation**: Demonstrates Alice & Bob exchange
/// - **Manual Exchange**: Real-world usage with other parties
/// - **Mathematical Demo**: Shows the underlying mathematics
/// 
/// # Security Considerations
/// 
/// The function provides educational warnings about:
/// - Parameter selection importance
/// - Man-in-the-middle attack risks
/// - Proper implementation requirements
/// 
/// # Errors
/// 
/// Can return errors from:
/// - Invalid protocol selection
/// - Mathematical computation failures
/// - User input validation errors
/// - Network communication issues (future implementations)
fn handle_key_exchange(protocol: ExchangeProtocol) -> Result<()> {
    let result = match true {
        _ if protocol.dh => {
            let choice = interactive::prompt_for_choices(
                "Select Diffie-Hellman operation",
                &[
                    "Interactive Simulation (Alice & Bob)", 
                    "Manual Exchange - Start Session", 
                    "Manual Exchange - Complete with Other's Key",
                    "Mathematical Concept Demo"
                ]
            )?;
            
            match choice.as_str() {
                "Interactive Simulation (Alice & Bob)" => {
                    dh::key_exchange("interactive")?
                },
                "Manual Exchange - Start Session" => {
                    println!("\n🚀 Starting manual key exchange session...");
                    dh::key_exchange("manual")?
                },
                "Manual Exchange - Complete with Other's Key" => {
                    let other_public_key = interactive::prompt_for_input("Enter other party's public key")?
                        .parse::<u64>()
                        .map_err(|_| anyhow::anyhow!("Invalid public key format. Must be a number."))?;
                    
                    let my_private_key = interactive::prompt_for_input("Enter your private key")?
                        .parse::<u64>()
                        .map_err(|_| anyhow::anyhow!("Invalid private key format. Must be a number."))?;
                    
                    dh::complete_manual_key_exchange(other_public_key, my_private_key)?
                },
                "Mathematical Concept Demo" => {
                    dh::key_exchange("demo")?
                },
                _ => return Err(anyhow::anyhow!("Invalid choice")),
            }
        },
        _ if protocol.ecdh => {
            "ECDH key exchange is not yet implemented. Coming soon!".to_string()
        },
        _ => return Err(anyhow::anyhow!("Unknown key exchange protocol")),
    };

    println!("\n{} {}", "Result:".cyan().bold(), result.white());
    Ok(())
}