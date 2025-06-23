use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};

/// Encode binary data to Base64 string
pub fn to_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decode Base64 string to binary data
pub fn from_base64(encoded: &str) -> Result<Vec<u8>> {
    let decoded = general_purpose::STANDARD.decode(encoded)?;
    Ok(decoded)
}

/// Helper function to print a separator line
pub fn print_separator() {
    println!("\n{}\n", "─".repeat(50));
}