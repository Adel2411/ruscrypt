use anyhow::Result;

/// Computes SHA-1 hash of input text
pub fn hash(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let hash_bytes = sha1_hash(bytes);
    
    // Convert to hexadecimal string
    let hex_string = hash_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    
    Ok(hex_string)
}

/// Core SHA-1 implementation
fn sha1_hash(input: &[u8]) -> [u8; 20] {
    // Initialize hash values (first 32 bits of the fractional parts of square roots)
    let mut h = [
        0x67452301u32,
        0xEFCDAB89u32,
        0x98BADCFEu32,
        0x10325476u32,
        0xC3D2E1F0u32,
    ];
    
    // Pre-processing: add padding
    let mut message = input.to_vec();
    let original_len = message.len() as u64;
    
    // Append '1' bit (plus seven '0' bits, represented as 0x80)
    message.push(0x80);
    
    // Append '0' bits until message length ≡ 448 (mod 512)
    while (message.len() % 64) != 56 {
        message.push(0);
    }
    
    // Append original length as 64-bit big-endian
    message.extend_from_slice(&(original_len * 8).to_be_bytes());
    
    // Process message in 512-bit chunks
    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 80];
        
        // Break chunk into sixteen 32-bit big-endian words
        for (i, word_bytes) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }
        
        // Extend the sixteen 32-bit words into eighty 32-bit words
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        
        // Initialize hash value for this chunk
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        
        // Main loop
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6),
                _ => unreachable!(),
            };
            
            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        
        // Add this chunk's hash to result
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    
    // Convert to bytes (big-endian)
    let mut result = [0u8; 20];
    for (i, &word) in h.iter().enumerate() {
        let bytes = word.to_be_bytes();
        result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    
    result
}
