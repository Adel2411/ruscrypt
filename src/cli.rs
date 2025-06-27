use clap::{Parser, Subcommand, Args as ClapArgs};

#[derive(Parser, Debug)]
#[command(name = "ruscrypt")]
#[command(about = "⚡ Lightning-fast cryptography toolkit built with Rust ⚡")]
#[command(version = "0.1.0")]
#[command(author = "Adel2411")]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt text using various algorithms
    Encrypt {
        #[command(flatten)]
        algorithm: EncryptionAlgorithm,
    },
    /// Decrypt text using various algorithms
    Decrypt {
        #[command(flatten)]
        algorithm: EncryptionAlgorithm,
    },
    /// Hash text using various algorithms
    Hash {
        #[command(flatten)]
        algorithm: HashAlgorithm,
    },
    /// Key exchange protocols and demonstrations
    Exchange {
        #[command(flatten)]
        protocol: ExchangeProtocol,
    },
}

#[derive(ClapArgs, Debug)]
#[group(required = true, multiple = false)]
pub struct EncryptionAlgorithm {
    /// Caesar cipher (classical)
    #[arg(long)]
    pub caesar: bool,

    /// Vigenère cipher (classical)
    #[arg(long)]
    pub vigenere: bool,

    /// Playfair cipher (classical)
    #[arg(long)]
    pub playfair: bool,

    /// Rail Fence cipher (classical)
    #[arg(long)]
    pub railfence: bool,

    /// RC4 stream cipher
    #[arg(long)]
    pub rc4: bool,

    /// AES block cipher
    #[arg(long)]
    pub aes: bool,

    /// DES block cipher
    #[arg(long)]
    pub des: bool,

    /// RSA asymmetric encryption
    #[arg(long)]
    pub rsa: bool,
}

#[derive(ClapArgs, Debug)]
#[group(required = true, multiple = false)]
pub struct HashAlgorithm {
    /// MD5 hash function
    #[arg(long)]
    pub md5: bool,

    /// SHA-1 hash function
    #[arg(long)]
    pub sha1: bool,

    /// SHA-256 hash function
    #[arg(long)]
    pub sha256: bool,
}

#[derive(ClapArgs, Debug)]
#[group(required = true, multiple = false)]
pub struct ExchangeProtocol {
    /// Diffie-Hellman key exchange
    #[arg(long)]
    pub dh: bool,

    /// ECDH (Elliptic Curve Diffie-Hellman) - future implementation
    #[arg(long)]
    pub ecdh: bool,
}

pub fn parse_args() -> Args {
    Args::parse()
}

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

pub fn get_keyexchange_protocol_name(protocol: &ExchangeProtocol) -> &'static str {
    if protocol.dh {
        "Diffie-Hellman"
    } else if protocol.ecdh {
        "ECDH (Not implemented)"
    } else {
        "Unknown"
    }
}
