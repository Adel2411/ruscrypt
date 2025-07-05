//! # Command Line Interface Module
//!
//! This module provides the command-line interface structure for RusCrypt using the `clap` crate.
//! It defines all the available commands, algorithms, and their respective arguments.
//!
//! ## Usage
//!
//! The CLI supports four main command categories:
//! - **encrypt**: Encrypt text using various algorithms
//! - **decrypt**: Decrypt text using various algorithms  
//! - **hash**: Hash text using various hash functions
//! - **exchange**: Perform key exchange protocols
//!
//! ## Examples
//!
//! ```bash
//! # Encrypt with Caesar cipher
//! ruscrypt encrypt --caesar
//!
//! # Hash with SHA-256
//! ruscrypt hash --sha256
//!
//! # Diffie-Hellman key exchange
//! ruscrypt exchange --dh
//! ```

use clap::{Args as ClapArgs, Parser, Subcommand};

/// Main CLI arguments structure
///
/// This is the root command structure that contains all subcommands
/// and global configuration for the RusCrypt CLI tool.
#[derive(Parser, Debug)]
#[command(name = "ruscrypt")]
#[command(about = "⚡ Lightning-fast cryptography toolkit built with Rust ⚡")]
#[command(version = "0.2.0")]
#[command(author = "Adel2411")]
pub struct Args {
    /// The subcommand to execute
    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI commands
///
/// Each variant represents a major operation category in the cryptography toolkit.
/// Commands are mutually exclusive - only one can be executed at a time.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt text using various algorithms
    ///
    /// Supports classical ciphers (Caesar, Vigenère, etc.), stream ciphers (RC4),
    /// block ciphers (AES, DES), and asymmetric encryption (RSA).
    ///
    /// # Fields
    ///
    /// * `algorithm` - The encryption algorithm to use (see `EncryptionAlgorithm`)
    ///
    /// # Available Algorithms
    ///
    /// - `--caesar`: Caesar cipher with shift parameter
    /// - `--vigenere`: Vigenère cipher with keyword
    /// - `--playfair`: Playfair cipher with keyword matrix
    /// - `--railfence`: Rail Fence cipher with rail count
    /// - `--rc4`: RC4 stream cipher with key
    /// - `--aes`: AES block cipher (128/192/256-bit)
    /// - `--des`: DES block cipher (56-bit, deprecated)
    /// - `--rsa`: RSA asymmetric encryption
    Encrypt {
        /// The encryption algorithm to use for the operation
        #[command(flatten)]
        algorithm: EncryptionAlgorithm,
    },
    /// Decrypt text using various algorithms
    ///
    /// Reverses encryption operations using the same algorithms available
    /// for encryption. Requires appropriate keys or parameters.
    ///
    /// # Fields
    ///
    /// * `algorithm` - The decryption algorithm to use (same as encryption)
    ///
    /// # Available Algorithms
    ///
    /// - `--caesar`: Caesar cipher decryption with shift parameter
    /// - `--vigenere`: Vigenère cipher decryption with keyword
    /// - `--playfair`: Playfair cipher decryption with keyword matrix
    /// - `--railfence`: Rail Fence cipher decryption with rail count
    /// - `--rc4`: RC4 stream cipher decryption with key
    /// - `--aes`: AES block cipher decryption
    /// - `--des`: DES block cipher decryption
    /// - `--rsa`: RSA asymmetric decryption with private key
    ///
    /// # Note
    ///
    /// Decryption requires the same parameters (keys, shifts, etc.) that were
    /// used during the original encryption process.
    Decrypt {
        /// The decryption algorithm to use for the operation
        #[command(flatten)]
        algorithm: EncryptionAlgorithm,
    },
    /// Hash text using various algorithms
    ///
    /// Computes cryptographic hash values using MD5, SHA-1, or SHA-256.
    /// Hash operations are one-way and cannot be reversed.
    ///
    /// # Fields
    ///
    /// * `algorithm` - The hash algorithm to use (see `HashAlgorithm`)
    ///
    /// # Available Hash Functions
    ///
    /// - `--md5`: MD5 hash function (128-bit, deprecated)
    /// - `--sha1`: SHA-1 hash function (160-bit, deprecated)
    /// - `--sha256`: SHA-256 hash function (256-bit, secure)
    ///
    /// # Output Format
    ///
    /// All hash functions output hexadecimal strings:
    /// - MD5: 32 hex characters
    /// - SHA-1: 40 hex characters
    /// - SHA-256: 64 hex characters
    Hash {
        /// The hash algorithm to use for the operation
        #[command(flatten)]
        algorithm: HashAlgorithm,
    },
    /// Key exchange protocols and demonstrations
    ///
    /// Implements protocols for securely establishing shared keys between parties,
    /// including Diffie-Hellman key exchange.
    ///
    /// # Fields
    ///
    /// * `protocol` - The key exchange protocol to use (see `ExchangeProtocol`)
    ///
    /// # Available Protocols
    ///
    /// - `--dh`: Diffie-Hellman key exchange protocol
    ///   - Interactive simulation mode
    ///   - Manual exchange with other parties
    ///   - Mathematical concept demonstration
    /// - `--ecdh`: Elliptic Curve Diffie-Hellman (not yet implemented)
    ///
    /// # Security Note
    ///
    /// Key exchange protocols are vulnerable to man-in-the-middle attacks
    /// without proper authentication. Use for educational purposes only.
    Exchange {
        /// The key exchange protocol to use for the operation
        #[command(flatten)]
        protocol: ExchangeProtocol,
    },
    /// Generate cryptographic key pairs
    ///
    /// Supports generating keys for supported algorithms (currently RSA).
    /// Prompts for output format (n:e or PEM).
    Keygen {
        /// The key generation algorithm to use
        #[command(flatten)]
        algorithm: KeygenAlgorithm,
    },
    /// Sign data using asymmetric cryptography
    ///
    /// Creates digital signatures using private keys. Currently supports RSA signing
    /// with PKCS#1 v1.5 padding scheme for educational purposes.
    ///
    /// # Fields
    ///
    /// * `algorithm` - The signing algorithm to use (see `SigningAlgorithm`)
    ///
    /// # Available Algorithms
    ///
    /// - `--rsa`: RSA digital signature
    ///   - Uses private key for signing
    ///   - Supports multiple input formats
    ///   - Output in base64 or hex encoding
    ///
    /// # Security Note
    ///
    /// Digital signatures provide authentication and non-repudiation.
    /// Keep private keys secure and use appropriate key sizes.
    Sign {
        /// The signing algorithm to use for the operation
        #[command(flatten)]
        algorithm: SigningAlgorithm,
    },
    /// Verify digital signatures
    ///
    /// Verifies digital signatures using public keys. Currently supports RSA
    /// signature verification with PKCS#1 v1.5 padding scheme.
    ///
    /// # Fields
    ///
    /// * `algorithm` - The verification algorithm to use (see `SigningAlgorithm`)
    ///
    /// # Available Algorithms
    ///
    /// - `--rsa`: RSA signature verification
    ///   - Uses public key for verification
    ///   - Supports multiple input formats
    ///   - Returns verification result (valid/invalid)
    ///
    /// # Security Note
    ///
    /// Always verify signatures from trusted sources and ensure
    /// public key authenticity through proper key distribution.
    Verify {
        /// The verification algorithm to use for the operation
        #[command(flatten)]
        algorithm: SigningAlgorithm,
    },
}

/// Encryption and decryption algorithm selection
///
/// This struct uses clap's group feature to ensure exactly one algorithm
/// is selected. Algorithms range from classical ciphers to modern encryption.
///
/// ## Security Levels
/// - **Educational**: Caesar, Vigenère, Playfair, Rail Fence
/// - **Deprecated**: RC4, DES
/// - **Modern**: AES, RSA
#[derive(ClapArgs, Debug, Default)]
#[group(required = true, multiple = false)]
pub struct EncryptionAlgorithm {
    /// Caesar cipher (classical substitution cipher)
    ///
    /// Simple substitution cipher that shifts each letter by a fixed number
    /// of positions in the alphabet. Not secure for real-world use.
    #[arg(long)]
    pub caesar: bool,

    /// Vigenère cipher (classical polyalphabetic cipher)
    ///
    /// Uses a keyword to create multiple Caesar ciphers. More secure than
    /// Caesar but still cryptographically weak by modern standards.
    #[arg(long)]
    pub vigenere: bool,

    /// Playfair cipher (classical digraph substitution)
    ///
    /// Encrypts pairs of letters using a 5x5 key square. Historically
    /// important but not suitable for modern cryptography.
    #[arg(long)]
    pub playfair: bool,

    /// Rail Fence cipher (classical transposition cipher)
    ///
    /// Writes plaintext in a zigzag pattern across multiple "rails"
    /// then reads off the ciphertext. Easy to break with frequency analysis.
    #[arg(long)]
    pub railfence: bool,

    /// RC4 stream cipher
    ///
    /// ⚠️ **Security Warning**: RC4 has known vulnerabilities and should not
    /// be used in production systems. Included for educational purposes only.
    #[arg(long)]
    pub rc4: bool,

    /// AES block cipher (Advanced Encryption Standard)
    ///
    /// Industry-standard symmetric encryption algorithm. Supports 128, 192,
    /// and 256-bit keys. Secure for modern use when properly implemented.
    #[arg(long)]
    pub aes: bool,

    /// DES block cipher (Data Encryption Standard)
    ///
    /// ⚠️ **Deprecated**: 56-bit key size is too small for modern security.
    /// Included for educational and legacy compatibility purposes only.
    #[arg(long)]
    pub des: bool,

    /// RSA asymmetric encryption
    ///
    /// Public-key cryptography algorithm. Secure with appropriate key sizes
    /// (2048+ bits recommended). Supports digital signatures and key exchange.
    #[arg(long)]
    pub rsa: bool,
}

/// Hash algorithm selection
///
/// Provides options for cryptographic hash functions with varying security levels.
/// Only one algorithm can be selected per operation.
///
/// ## Security Recommendations
/// - **Secure**: SHA-256
/// - **Deprecated**: MD5, SHA-1 (use only for legacy compatibility)
#[derive(ClapArgs, Debug, Default)]
#[group(required = true, multiple = false)]
pub struct HashAlgorithm {
    /// MD5 hash function (128-bit output)
    ///
    /// ⚠️ **Security Warning**: MD5 is cryptographically broken and should not
    /// be used for security purposes. Included for legacy compatibility only.
    #[arg(long)]
    pub md5: bool,

    /// SHA-1 hash function (160-bit output)
    ///
    /// ⚠️ **Deprecated**: SHA-1 has known collision vulnerabilities. Use SHA-256
    /// for new applications. Included for legacy compatibility.
    #[arg(long)]
    pub sha1: bool,

    /// SHA-256 hash function (256-bit output)
    ///
    /// Part of the SHA-2 family. Cryptographically secure and recommended
    /// for modern applications requiring hash functions.
    #[arg(long)]
    pub sha256: bool,
}

/// Key exchange protocol selection
///
/// Implements protocols for establishing shared cryptographic keys between
/// parties over insecure channels.
#[derive(ClapArgs, Debug, Default)]
#[group(required = true, multiple = false)]
pub struct ExchangeProtocol {
    /// Diffie-Hellman key exchange protocol
    ///
    /// Allows two parties to establish a shared secret key over a public channel.
    /// Forms the basis for many modern key agreement protocols.
    #[arg(long)]
    pub dh: bool,

    /// ECDH (Elliptic Curve Diffie-Hellman) key exchange
    ///
    /// More efficient variant of Diffie-Hellman using elliptic curves.
    /// Provides equivalent security with smaller key sizes.
    ///
    /// ⚠️ **Not Implemented**: This feature is planned for future releases.
    #[arg(long)]
    pub ecdh: bool,
}

/// Key generation algorithm selection
///
/// Allows the user to select which algorithm to generate keys for.
/// Currently only RSA is supported.
#[derive(ClapArgs, Debug, Default)]
#[group(required = true, multiple = false)]
pub struct KeygenAlgorithm {
    /// RSA key pair generation
    #[arg(long)]
    pub rsa: bool,
}

/// Signing algorithm selection
///
/// Allows the user to select which algorithm to use for signing operations.
/// Currently only RSA is supported.
#[derive(ClapArgs, Debug, Default)]
#[group(required = true, multiple = false)]
pub struct SigningAlgorithm {
    /// RSA digital signature
    ///
    /// Creates or verifies RSA digital signatures using PKCS#1 v1.5 padding.
    /// Requires appropriate key sizes (2048+ bits recommended for production).
    #[arg(long)]
    pub rsa: bool,
}

/// Parse command line arguments
///
/// Parses the command line arguments using clap and returns the structured
/// `Args` object. This function will exit the program with help text or
/// error messages if argument parsing fails.
///
/// # Returns
///
/// Returns the parsed `Args` structure containing the command and its parameters.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::cli;
///
/// let args = cli::parse_args();
/// match args.command {
///     cli::Commands::Encrypt { .. } => println!("Encryption requested"),
///     _ => println!("Other command requested"),
/// }
/// ```
pub fn parse_args() -> Args {
    Args::parse()
}

/// Get the human-readable name of the selected encryption algorithm
///
/// Converts the boolean flags in `EncryptionAlgorithm` to a readable string
/// representation of the selected algorithm.
///
/// # Arguments
///
/// * `algo` - Reference to the `EncryptionAlgorithm` struct
///
/// # Returns
///
/// Returns a static string slice containing the algorithm name, or "Unknown"
/// if no algorithm is selected (which shouldn't happen due to clap validation).
///
/// # Examples
///
/// ```rust
/// use ruscrypt::cli::{EncryptionAlgorithm, get_algorithm_name};
///
/// let mut algo = EncryptionAlgorithm::default();
/// algo.aes = true;
/// assert_eq!(get_algorithm_name(&algo), "AES");
/// ```
pub fn get_algorithm_name(algo: &EncryptionAlgorithm) -> &'static str {
    if algo.caesar {
        "Caesar"
    } else if algo.vigenere {
        "Vigenère"
    } else if algo.playfair {
        "Playfair"
    } else if algo.railfence {
        "Rail Fence"
    } else if algo.rc4 {
        "RC4"
    } else if algo.aes {
        "AES"
    } else if algo.des {
        "DES"
    } else if algo.rsa {
        "RSA"
    } else {
        "Unknown"
    }
}

/// Get the human-readable name of the selected hash algorithm
///
/// Converts the boolean flags in `HashAlgorithm` to a readable string
/// representation of the selected hash function.
///
/// # Arguments
///
/// * `algo` - Reference to the `HashAlgorithm` struct
///
/// # Returns
///
/// Returns a static string slice containing the hash algorithm name, or "Unknown"
/// if no algorithm is selected.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::cli::{HashAlgorithm, get_hash_algorithm_name};
///
/// let mut algo = HashAlgorithm::default();
/// algo.sha256 = true;
/// assert_eq!(get_hash_algorithm_name(&algo), "SHA-256");
/// ```
pub fn get_hash_algorithm_name(algo: &HashAlgorithm) -> &'static str {
    if algo.md5 {
        "MD5"
    } else if algo.sha1 {
        "SHA-1"
    } else if algo.sha256 {
        "SHA-256"
    } else {
        "Unknown"
    }
}

/// Get the human-readable name of the selected key exchange protocol
///
/// Converts the boolean flags in `ExchangeProtocol` to a readable string
/// representation of the selected protocol.
///
/// # Arguments
///
/// * `protocol` - Reference to the `ExchangeProtocol` struct
///
/// # Returns
///
/// Returns a static string slice containing the protocol name, or "Unknown"
/// if no protocol is selected.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::cli::{ExchangeProtocol, get_keyexchange_protocol_name};
///
/// let mut protocol = ExchangeProtocol::default();
/// protocol.dh = true;
/// assert_eq!(get_keyexchange_protocol_name(&protocol), "Diffie-Hellman");
/// ```
pub fn get_keyexchange_protocol_name(protocol: &ExchangeProtocol) -> &'static str {
    if protocol.dh {
        "Diffie-Hellman"
    } else if protocol.ecdh {
        "ECDH (Not implemented)"
    } else {
        "Unknown"
    }
}

/// Get the human-readable name of the selected keygen algorithm
///
/// Converts the boolean flags in `KeygenAlgorithm` to a readable string
/// representation of the selected key generation algorithm.
///
/// # Arguments
///
/// * `algo` - Reference to the `KeygenAlgorithm` struct
///
/// # Returns
///
/// Returns a static string slice containing the keygen algorithm name, or "Unknown"
/// if no algorithm is selected.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::cli::{KeygenAlgorithm, get_keygen_algorithm_name};
///
/// let mut algo = KeygenAlgorithm::default();
/// algo.rsa = true;
/// assert_eq!(get_keygen_algorithm_name(&algo), "RSA");
///
/// ```
pub fn get_keygen_algorithm_name(algo: &KeygenAlgorithm) -> &'static str {
    if algo.rsa {
        "RSA"
    } else {
        "Unknown"
    }
}

/// Get the human-readable name of the selected signing algorithm
///
/// Converts the boolean flags in `SigningAlgorithm` to a readable string
/// representation of the selected signing algorithm.
///
/// # Arguments
///
/// * `algo` - Reference to the `SigningAlgorithm` struct
///
/// # Returns
///
/// Returns a static string slice containing the signing algorithm name, or "Unknown"
/// if no algorithm is selected.
///
/// # Examples
///
/// ```rust
/// use ruscrypt::cli::{SigningAlgorithm, get_signing_algorithm_name};
///
/// let mut algo = SigningAlgorithm::default();
/// algo.rsa = true;
/// assert_eq!(get_signing_algorithm_name(&algo), "RSA");
/// ```
pub fn get_signing_algorithm_name(algo: &SigningAlgorithm) -> &'static str {
    if algo.rsa {
        "RSA"
    } else {
        "Unknown"
    }
}
