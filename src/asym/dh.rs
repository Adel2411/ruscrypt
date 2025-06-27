use anyhow::Result;
use rand::Rng;

/// Represents a Diffie-Hellman key exchange participant
#[derive(Debug)]
pub struct DHParticipant {
    pub private_key: u64,
    pub public_key: u64,
    pub shared_secret: Option<u64>,
    pub prime: u64,
    pub generator: u64,
}

/// Simple Diffie-Hellman parameters for educational purposes
/// Note: These are small values for demonstration only - NOT secure for real use!
const DH_PRIME: u64 = 2147483647; // 2^31 - 1 (Mersenne prime)
const DH_GENERATOR: u64 = 2;

impl DHParticipant {
    /// Create a new participant with a random private key
    pub fn new() -> Self {
        let mut rng = rand::rng();
        let private_key = rng.random_range(2..1000000); // Small range for educational purposes
        
        let public_key = mod_exp(DH_GENERATOR, private_key, DH_PRIME);
        
        DHParticipant {
            private_key,
            public_key,
            shared_secret: None,
            prime: DH_PRIME,
            generator: DH_GENERATOR,
        }
    }
    
    /// Create a participant with a specific private key (for testing and controlled scenarios)
    /// This function is essential for:
    /// - Unit testing with predictable results
    /// - Educational demonstrations with known values
    /// - Debugging and verification scenarios
    #[allow(dead_code)]
    pub fn with_private_key(private_key: u64) -> Self {
        let public_key = mod_exp(DH_GENERATOR, private_key, DH_PRIME);
        
        DHParticipant {
            private_key,
            public_key,
            shared_secret: None,
            prime: DH_PRIME,
            generator: DH_GENERATOR,
        }
    }
    
    /// Compute shared secret using other party's public key
    pub fn compute_shared_secret(&mut self, other_public_key: u64) -> Result<u64> {
        if other_public_key >= self.prime {
            return Err(anyhow::anyhow!("Invalid public key: too large"));
        }
        
        let shared_secret = mod_exp(other_public_key, self.private_key, self.prime);
        self.shared_secret = Some(shared_secret);
        
        Ok(shared_secret)
    }
    
    /// Get the shared secret (if computed)
    /// This function is essential for:
    /// - Retrieving computed shared secrets
    /// - Verification in tests
    /// - State checking in applications
    #[allow(dead_code)]
    pub fn get_shared_secret(&self) -> Option<u64> {
        self.shared_secret
    }
}

/// Main entry point for DH key exchange in CLI
/// This function provides a unified interface for different DH modes:
/// - "interactive": Full simulation with two participants
/// - "demo": Mathematical concept demonstration  
/// - "manual": Returns error directing to manual_key_exchange()
pub fn key_exchange(mode: &str) -> Result<String> {
    match mode.to_lowercase().as_str() {
        "interactive" => interactive_key_exchange(),
        "manual" => start_manual_key_exchange(),
        "demo" => demonstrate_concept(),
        _ => Err(anyhow::anyhow!("Invalid mode. Use 'interactive', 'manual', or 'demo'"))
    }
}

/// Interactive Diffie-Hellman key exchange simulation
pub fn interactive_key_exchange() -> Result<String> {
    println!("\n🔑 Diffie-Hellman Key Exchange Simulation");
    println!("==========================================");
    
    // Create Alice (us)
    let mut alice = DHParticipant::new();
    println!("\n👩 Alice (You):");
    println!("  Prime (p):     {}", alice.prime);
    println!("  Generator (g): {}", alice.generator);
    println!("  Private key:   {} (keep secret!)", alice.private_key);
    println!("  Public key:    {} (share with Bob)", alice.public_key);
    
    // Create Bob (simulated)
    let mut bob = DHParticipant::new();
    println!("\n👨 Bob (Simulated):");
    println!("  Private key:   {} (Bob keeps secret)", bob.private_key);
    println!("  Public key:    {} (Bob shares with you)", bob.public_key);
    
    // Exchange public keys and compute shared secrets
    let alice_shared = alice.compute_shared_secret(bob.public_key)?;
    let bob_shared = bob.compute_shared_secret(alice.public_key)?;
    
    println!("\n🤝 Key Exchange Result:");
    println!("  Alice computed shared secret: {}", alice_shared);
    println!("  Bob computed shared secret:   {}", bob_shared);
    
    if alice_shared == bob_shared {
        println!("  ✅ SUCCESS: Both parties have the same shared secret!");
        Ok(format!("Shared secret established: {}", alice_shared))
    } else {
        println!("  ❌ ERROR: Shared secrets don't match!");
        Err(anyhow::anyhow!("Key exchange failed"))
    }
}

/// Start a manual key exchange session (Step 1 - Generate keys and show public key)
pub fn start_manual_key_exchange() -> Result<String> {
    println!("\n🔑 Diffie-Hellman Manual Key Exchange");
    println!("=====================================");
    println!("📋 Two-Terminal Testing Instructions:");
    println!("   1. Run this command in Terminal 1 to get your public key");
    println!("   2. Copy the public key and share it with Terminal 2");
    println!("   3. In Terminal 2, run: ruscrypt exchange --dh");
    println!("   4. Terminal 2 will show their public key");
    println!("   5. Use complete_manual_key_exchange() with the other terminal's public key");
    println!();
    
    let participant = DHParticipant::new();
    
    println!("🔢 Your DH Parameters:");
    println!("   Prime (p):     {}", participant.prime);
    println!("   Generator (g): {}", participant.generator);
    println!();
    
    println!("🔐 Your Keys:");
    println!("   Private key:   {} (🚨 KEEP THIS SECRET! 🚨)", participant.private_key);
    println!("   Public key:    {} (📤 SHARE THIS)", participant.public_key);
    println!();
    
    println!("📝 Next Steps:");
    println!("   1. Share your public key: {}", participant.public_key);
    println!("   2. Get the other party's public key");
    println!("   3. Run this command to complete the exchange:");
    println!("      ruscrypt exchange --dh --complete <other_public_key> <your_private_key>");
    println!();
    
    Ok(format!(
        "SESSION_DATA: private_key={}, public_key={}, prime={}, generator={}",
        participant.private_key, participant.public_key, participant.prime, participant.generator
    ))
}

/// Complete manual key exchange with other party's public key
pub fn complete_manual_key_exchange(other_public_key: u64, my_private_key: u64) -> Result<String> {
    println!("\n🤝 Completing Diffie-Hellman Key Exchange");
    println!("==========================================");
    
    let mut my_participant = DHParticipant::with_private_key(my_private_key);
    
    println!("📥 Received Information:");
    println!("   Other party's public key: {}", other_public_key);
    println!("   Your private key:         {}", my_private_key);
    println!("   Your public key:          {}", my_participant.public_key);
    println!();
    
    // Compute shared secret
    let shared_secret = my_participant.compute_shared_secret(other_public_key)?;
    
    println!("🔐 Key Exchange Computation:");
    println!("   Formula: shared_secret = other_public_key^my_private_key mod prime");
    println!("   Calculation: {}^{} mod {} = {}", 
             other_public_key, my_private_key, my_participant.prime, shared_secret);
    println!();
    
    println!("🎉 SHARED SECRET COMPUTED: {}", shared_secret);
    println!();
    println!("✅ Success! Both parties should now have the same shared secret.");
    println!("🔒 This shared secret can be used as a key for symmetric encryption.");
    
    Ok(format!("Shared secret: {}", shared_secret))
}


/// Demonstrate the mathematical concept
pub fn demonstrate_concept() -> Result<String> {
    println!("\n📚 Diffie-Hellman Concept Demonstration");
    println!("=======================================");
    println!("🎯 This demonstrates the mathematical concepts with small, easy numbers");
    println!();
    
    // Use small, easy-to-follow numbers
    let p = 23; // Small prime
    let g = 5;  // Generator
    
    let alice_private = 6;
    let bob_private = 15;
    
    println!("🔢 Public Parameters (known to everyone):");
    println!("   Prime (p) = {}", p);
    println!("   Generator (g) = {}", g);
    println!();
    
    println!("👩 Alice's Calculations:");
    println!("   1. Chooses private key (a) = {} (secret)", alice_private);
    let alice_public = mod_exp(g, alice_private, p);
    println!("   2. Computes public key (A) = g^a mod p");
    println!("      A = {}^{} mod {} = {}", g, alice_private, p, alice_public);
    println!("   3. Sends public key {} to Bob", alice_public);
    println!();
    
    println!("👨 Bob's Calculations:");
    println!("   1. Chooses private key (b) = {} (secret)", bob_private);
    let bob_public = mod_exp(g, bob_private, p);
    println!("   2. Computes public key (B) = g^b mod p");
    println!("      B = {}^{} mod {} = {}", g, bob_private, p, bob_public);
    println!("   3. Sends public key {} to Alice", bob_public);
    println!();
    
    println!("🤝 Shared Secret Calculation:");
    println!("   Alice computes: s = B^a mod p");
    let alice_shared = mod_exp(bob_public, alice_private, p);
    println!("   Alice: s = {}^{} mod {} = {}", bob_public, alice_private, p, alice_shared);
    println!();
    
    println!("   Bob computes: s = A^b mod p");
    let bob_shared = mod_exp(alice_public, bob_private, p);
    println!("   Bob: s = {}^{} mod {} = {}", alice_public, bob_private, p, bob_shared);
    println!();
    
    if alice_shared == bob_shared {
        println!("🎉 SUCCESS: Both parties computed the same shared secret: {}", alice_shared);
        println!();
        println!("🔐 Security Insight:");
        println!("   - Public keys {} and {} are known to everyone", alice_public, bob_public);
        println!("   - Private keys {} and {} are kept secret", alice_private, bob_private);
        println!("   - Shared secret {} can only be computed by Alice and Bob", alice_shared);
        println!("   - An eavesdropper would need to solve the discrete logarithm problem");
        
        Ok(format!("Concept demonstration complete. Shared secret: {}", alice_shared))
    } else {
        Err(anyhow::anyhow!("Mathematical error in demonstration"))
    }
}

/// Fast modular exponentiation (a^b mod m)
fn mod_exp(base: u64, exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    
    let mut result = 1;
    let mut base = base % modulus;
    let mut exp = exp;
    
    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mod_exp() {
        assert_eq!(mod_exp(5, 6, 23), 8);
        assert_eq!(mod_exp(5, 15, 23), 19);
        assert_eq!(mod_exp(2, 10, 1000), 24);
    }
    
    #[test]
    fn test_key_exchange() {
        let mut alice = DHParticipant::with_private_key(6);
        let mut bob = DHParticipant::with_private_key(15);
        
        let alice_shared = alice.compute_shared_secret(bob.public_key).unwrap();
        let bob_shared = bob.compute_shared_secret(alice.public_key).unwrap();
        
        assert_eq!(alice_shared, bob_shared);
    }
    
    #[test]
    fn test_participant_creation() {
        let participant = DHParticipant::new();
        assert!(participant.private_key > 0);
        assert!(participant.public_key > 0);
        assert!(participant.shared_secret.is_none());
    }
}
