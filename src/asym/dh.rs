//! # Diffie-Hellman Key Exchange Implementation
//! 
//! This module implements the Diffie-Hellman key exchange protocol, which allows
//! two parties to establish a shared secret over an insecure channel without
//! prior shared secrets.
//! 
//! ✅ **Security Status**: The Diffie-Hellman algorithm itself is secure, but
//! this implementation uses small parameters for educational purposes only.
//! 
//! ## Protocol Overview
//! 
//! 1. **Setup**: Both parties agree on public parameters (prime p, generator g)
//! 2. **Key Generation**: Each party generates a private key and computes a public key
//! 3. **Exchange**: Parties exchange their public keys
//! 4. **Shared Secret**: Each party computes the same shared secret using their private key and the other's public key
//! 
//! ## Examples
//! 
//! ```rust
//! use ruscrypt::asym::dh::DHParticipant;
//! 
//! // Create two participants
//! let mut alice = DHParticipant::new();
//! let mut bob = DHParticipant::new();
//! 
//! // Exchange public keys and compute shared secret
//! let alice_secret = alice.compute_shared_secret(bob.public_key).unwrap();
//! let bob_secret = bob.compute_shared_secret(alice.public_key).unwrap();
//! 
//! assert_eq!(alice_secret, bob_secret);
//! ```

use anyhow::Result;
use rand::Rng;

/// Represents a participant in the Diffie-Hellman key exchange protocol.
/// 
/// Each participant has a private key (kept secret) and a public key (shared openly).
/// The participant can compute a shared secret using their private key and
/// another participant's public key.
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::asym::dh::DHParticipant;
/// 
/// let participant = DHParticipant::new();
/// println!("Private key: {} (keep secret!)", participant.private_key);
/// println!("Public key: {} (share this)", participant.public_key);
/// ```
#[derive(Debug)]
pub struct DHParticipant {
    /// The participant's private key (must be kept secret)
    pub private_key: u64,
    /// The participant's public key (can be shared openly)
    pub public_key: u64,
    /// The computed shared secret (None until computed)
    pub shared_secret: Option<u64>,
    /// The agreed-upon prime modulus
    pub prime: u64,
    /// The agreed-upon generator
    pub generator: u64,
}

/// DH parameters for educational purposes.
/// 
/// ⚠️ **Security Warning**: These values are small for demonstration only.
/// Real applications should use much larger primes (at least 2048 bits).
const DH_PRIME: u64 = 2147483647; // 2^31 - 1 (Mersenne prime)
const DH_GENERATOR: u64 = 2;

impl DHParticipant {
    /// Creates a new DH participant with a randomly generated private key.
    /// 
    /// The private key is generated randomly, and the public key is computed
    /// as g^private_key mod p.
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use ruscrypt::asym::dh::DHParticipant;
    /// 
    /// let alice = DHParticipant::new();
    /// assert!(alice.private_key > 0);
    /// assert!(alice.public_key > 0);
    /// assert!(alice.shared_secret.is_none());
    /// ```
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
    
    /// Creates a DH participant with a specific private key.
    /// 
    /// This function is useful for testing, demonstrations with known values,
    /// and educational purposes where reproducible results are needed.
    /// 
    /// # Arguments
    /// 
    /// * `private_key` - The private key to use (should be between 2 and prime-2)
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use ruscrypt::asym::dh::DHParticipant;
    /// 
    /// let alice = DHParticipant::with_private_key(12345);
    /// assert_eq!(alice.private_key, 12345);
    /// 
    /// // Same private key always generates same public key
    /// let alice2 = DHParticipant::with_private_key(12345);
    /// assert_eq!(alice.public_key, alice2.public_key);
    /// ```
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
    
    /// Computes the shared secret using another participant's public key.
    /// 
    /// This function implements the core DH computation: shared_secret = other_public_key^my_private_key mod p.
    /// Both participants will compute the same shared secret when given each other's public keys.
    /// 
    /// # Arguments
    /// 
    /// * `other_public_key` - The other participant's public key
    /// 
    /// # Returns
    /// 
    /// Returns the computed shared secret.
    /// 
    /// # Errors
    /// 
    /// Returns an error if the other party's public key is invalid (>= prime).
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use ruscrypt::asym::dh::DHParticipant;
    /// 
    /// let mut alice = DHParticipant::with_private_key(6);
    /// let bob = DHParticipant::with_private_key(15);
    /// 
    /// let shared_secret = alice.compute_shared_secret(bob.public_key).unwrap();
    /// assert!(shared_secret > 0);
    /// assert_eq!(alice.get_shared_secret(), Some(shared_secret));
    /// ```
    pub fn compute_shared_secret(&mut self, other_public_key: u64) -> Result<u64> {
        if other_public_key >= self.prime {
            return Err(anyhow::anyhow!("Invalid public key: too large"));
        }
        
        let shared_secret = mod_exp(other_public_key, self.private_key, self.prime);
        self.shared_secret = Some(shared_secret);
        
        Ok(shared_secret)
    }
    
    /// Gets the computed shared secret, if available.
    /// 
    /// Returns `None` if no shared secret has been computed yet.
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use ruscrypt::asym::dh::DHParticipant;
    /// 
    /// let mut participant = DHParticipant::new();
    /// assert_eq!(participant.get_shared_secret(), None);
    /// 
    /// // After computing shared secret...
    /// let other = DHParticipant::new();
    /// participant.compute_shared_secret(other.public_key).unwrap();
    /// assert!(participant.get_shared_secret().is_some());
    /// ```
    #[allow(dead_code)]
    pub fn get_shared_secret(&self) -> Option<u64> {
        self.shared_secret
    }
}

/// Main entry point for Diffie-Hellman key exchange operations.
/// 
/// Provides different modes of operation for various use cases:
/// - Interactive simulation for educational purposes
/// - Manual key exchange for multi-terminal testing
/// - Mathematical concept demonstration
/// 
/// # Arguments
/// 
/// * `mode` - The operation mode: "interactive", "manual", or "demo"
/// 
/// # Returns
/// 
/// Returns a descriptive message about the operation performed.
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::asym::dh;
/// 
/// // Run an interactive simulation
/// let result = dh::key_exchange("interactive").unwrap();
/// println!("{}", result);
/// 
/// // Demonstrate the mathematical concepts
/// let demo = dh::key_exchange("demo").unwrap();
/// println!("{}", demo);
/// ```
pub fn key_exchange(mode: &str) -> Result<String> {
    match mode.to_lowercase().as_str() {
        "interactive" => interactive_key_exchange(),
        "manual" => start_manual_key_exchange(),
        "demo" => demonstrate_concept(),
        _ => Err(anyhow::anyhow!("Invalid mode. Use 'interactive', 'manual', or 'demo'"))
    }
}

/// Runs an interactive Diffie-Hellman key exchange simulation.
/// 
/// This function simulates a complete key exchange between two parties
/// (Alice and Bob) for educational purposes. It shows all the steps
/// including key generation, exchange, and shared secret computation.
/// 
/// # Returns
/// 
/// Returns a success message with the computed shared secret.
/// 
/// # Examples
/// 
/// The function will output detailed information about:
/// - Public parameters (prime and generator)
/// - Each participant's keys
/// - The key exchange process
/// - Verification that both parties computed the same secret
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

/// Starts a manual key exchange session for multi-terminal testing.
/// 
/// This function generates DH parameters for one participant and provides
/// instructions for completing the key exchange with another terminal.
/// Useful for testing the protocol across different processes or machines.
/// 
/// # Returns
/// 
/// Returns session data including the participant's keys and instructions.
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::asym::dh;
/// 
/// let session = dh::start_manual_key_exchange().unwrap();
/// println!("{}", session);
/// // Follow the printed instructions to complete the exchange
/// ```
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

/// Demonstrates the mathematical concepts behind Diffie-Hellman.
/// 
/// Uses small, easy-to-follow numbers to show how the algorithm works
/// mathematically. Perfect for educational purposes and understanding
/// the underlying mathematics.
/// 
/// # Returns
/// 
/// Returns a detailed explanation of the mathematical steps.
/// 
/// # Examples
/// 
/// ```rust
/// use ruscrypt::asym::dh;
/// 
/// let demo = dh::demonstrate_concept().unwrap();
/// println!("{}", demo);
/// ```
/// 
/// This function will show:
/// - Small prime and generator values
/// - Step-by-step calculations
/// - How both parties arrive at the same shared secret
/// - Security insights about the discrete logarithm problem
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

/// Fast modular exponentiation using the square-and-multiply algorithm.
/// 
/// Computes (base^exp) mod modulus efficiently, which is essential for
/// Diffie-Hellman calculations with large numbers.
/// 
/// # Arguments
/// 
/// * `base` - The base number
/// * `exp` - The exponent
/// * `modulus` - The modulus
/// 
/// # Returns
/// 
/// Returns base^exp mod modulus.
/// 
/// # Examples
/// 
/// ```rust
/// // This is an internal function
/// // let result = mod_exp(2, 10, 1000); // 2^10 mod 1000 = 24
/// ```
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