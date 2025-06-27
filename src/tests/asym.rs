#[cfg(test)]
mod tests {

    #[cfg(test)]
    mod dh_tests {
        use crate::asym::dh::{DHParticipant, demonstrate_concept, key_exchange, start_manual_key_exchange, complete_manual_key_exchange};

        #[test]
        fn test_participant_creation() {
            let participant = DHParticipant::new();
            assert!(participant.private_key > 0);
            assert!(participant.public_key > 0);
            assert!(participant.shared_secret.is_none());
            assert_eq!(participant.prime, 2147483647);
            assert_eq!(participant.generator, 2);
        }

        #[test]
        fn test_with_private_key() {
            let private_key = 12345;
            let participant = DHParticipant::with_private_key(private_key);
            assert_eq!(participant.private_key, private_key);
            assert!(participant.public_key > 0);
            assert!(participant.shared_secret.is_none());
        }

        #[test]
        fn test_key_exchange_basic() {
            let mut alice = DHParticipant::with_private_key(6);
            let mut bob = DHParticipant::with_private_key(15);
            
            let alice_shared = alice.compute_shared_secret(bob.public_key).unwrap();
            let bob_shared = bob.compute_shared_secret(alice.public_key).unwrap();
            
            assert_eq!(alice_shared, bob_shared);
            assert_eq!(alice.get_shared_secret(), Some(alice_shared));
            assert_eq!(bob.get_shared_secret(), Some(bob_shared));
        }

        #[test]
        fn test_key_exchange_multiple_participants() {
            let mut alice = DHParticipant::with_private_key(10);
            let mut bob = DHParticipant::with_private_key(20);
            let mut charlie = DHParticipant::with_private_key(30);
            
            // Alice and Bob exchange
            let alice_bob_shared = alice.compute_shared_secret(bob.public_key).unwrap();
            let bob_alice_shared = bob.compute_shared_secret(alice.public_key).unwrap();
            assert_eq!(alice_bob_shared, bob_alice_shared);
            
            // Alice and Charlie exchange  
            let alice_charlie_shared = alice.compute_shared_secret(charlie.public_key).unwrap();
            let charlie_alice_shared = charlie.compute_shared_secret(alice.public_key).unwrap();
            assert_eq!(alice_charlie_shared, charlie_alice_shared);
            
            // Different pairs should have different shared secrets
            assert_ne!(alice_bob_shared, alice_charlie_shared);
        }

        #[test]
        fn test_different_private_keys() {
            let mut alice1 = DHParticipant::with_private_key(10);
            let mut alice2 = DHParticipant::with_private_key(20);
            let bob = DHParticipant::with_private_key(30);
            
            let shared1 = alice1.compute_shared_secret(bob.public_key).unwrap();
            let shared2 = alice2.compute_shared_secret(bob.public_key).unwrap();
            
            // Different private keys should produce different shared secrets
            assert_ne!(shared1, shared2);
        }

        #[test]
        fn test_invalid_public_key() {
            let mut alice = DHParticipant::new();
            // Try to use a public key larger than the prime
            let invalid_key = alice.prime + 1;
            assert!(alice.compute_shared_secret(invalid_key).is_err());
        }

        #[test]
        fn test_invalid_public_key_equal_to_prime() {
            let mut alice = DHParticipant::new();
            // Try to use a public key equal to the prime
            let invalid_key = alice.prime;
            assert!(alice.compute_shared_secret(invalid_key).is_err());
        }

        #[test]
        fn test_demonstrate_concept() {
            // Should not panic and should return a success message
            let result = demonstrate_concept();
            assert!(result.is_ok());
            let message = result.unwrap();
            assert!(message.contains("Concept demonstration complete"));
            assert!(message.contains("Shared secret:"));
        }

        #[test]
        fn test_consistent_key_generation() {
            let alice1 = DHParticipant::with_private_key(100);
            let alice2 = DHParticipant::with_private_key(100);
            
            // Same private key should generate same public key
            assert_eq!(alice1.public_key, alice2.public_key);
            assert_eq!(alice1.private_key, alice2.private_key);
        }

        #[test]
        fn test_get_shared_secret_before_computation() {
            let participant = DHParticipant::new();
            assert_eq!(participant.get_shared_secret(), None);
        }

        #[test]
        fn test_get_shared_secret_after_computation() {
            let mut alice = DHParticipant::with_private_key(50);
            let bob = DHParticipant::with_private_key(75);
            
            let shared = alice.compute_shared_secret(bob.public_key).unwrap();
            assert_eq!(alice.get_shared_secret(), Some(shared));
        }

        #[test]
        fn test_manual_key_exchange_start() {
            let result = start_manual_key_exchange();
            assert!(result.is_ok());
            
            let message = result.unwrap();
            assert!(message.contains("SESSION_DATA:"));
            assert!(message.contains("private_key="));
            assert!(message.contains("public_key="));
            assert!(message.contains("prime="));
            assert!(message.contains("generator="));
        }

        #[test]
        fn test_complete_manual_key_exchange() {
            // Create a participant for testing
            let alice = DHParticipant::with_private_key(12345);
            let bob = DHParticipant::with_private_key(67890);
            
            // Test Alice completing the exchange with Bob's public key
            let result = complete_manual_key_exchange(bob.public_key, alice.private_key);
            assert!(result.is_ok());
            
            let message = result.unwrap();
            assert!(message.contains("Shared secret:"));
            
            // Verify that the shared secret is correct by computing it from Bob's side
            let mut bob_copy = DHParticipant::with_private_key(67890);
            let bob_shared = bob_copy.compute_shared_secret(alice.public_key).unwrap();
            
            // Extract the shared secret from Alice's result
            let alice_shared_str = message.split("Shared secret: ").nth(1).unwrap();
            let alice_shared: u64 = alice_shared_str.parse().unwrap();
            
            assert_eq!(alice_shared, bob_shared);
        }

        #[test]
        fn test_manual_key_exchange_with_invalid_key() {
            // Use a key larger than the prime
            let invalid_key = 2147483648; // Prime + 1
            let my_private_key = 12345;
            let result = complete_manual_key_exchange(invalid_key, my_private_key);
            assert!(result.is_err());
        }

        #[test]
        fn test_manual_key_exchange_workflow() {
            // Test the complete workflow of manual key exchange
            
            // Step 1: Alice starts the exchange
            let alice_session = start_manual_key_exchange().unwrap();
            assert!(alice_session.contains("SESSION_DATA:"));
            
            // Extract Alice's data from session string
            let alice_data: Vec<&str> = alice_session.split(", ").collect();
            let alice_private_str = alice_data[0].split("private_key=").nth(1).unwrap();
            let alice_public_str = alice_data[1].split("public_key=").nth(1).unwrap();
            
            let alice_private: u64 = alice_private_str.parse().unwrap();
            let alice_public: u64 = alice_public_str.parse().unwrap();
            
            // Step 2: Bob also starts (simulated)
            let bob = DHParticipant::with_private_key(98765);
            
            // Step 3: Alice completes with Bob's public key
            let alice_result = complete_manual_key_exchange(bob.public_key, alice_private).unwrap();
            
            // Step 4: Bob completes with Alice's public key
            let bob_result = complete_manual_key_exchange(alice_public, bob.private_key).unwrap();
            
            // Both should have the same shared secret
            let alice_shared_str = alice_result.split("Shared secret: ").nth(1).unwrap();
            let bob_shared_str = bob_result.split("Shared secret: ").nth(1).unwrap();
            
            assert_eq!(alice_shared_str, bob_shared_str);
        }

        #[test]
        fn test_key_exchange_manual_mode_start() {
            let result = key_exchange("manual");
            assert!(result.is_ok());
            assert!(result.unwrap().contains("SESSION_DATA:"));
        }

        #[test]
        fn test_public_key_bounds() {
            let participant = DHParticipant::new();
            // Public key should be less than prime
            assert!(participant.public_key < participant.prime);
            assert!(participant.public_key > 0);
        }

        #[test]
        fn test_private_key_bounds() {
            let participant = DHParticipant::new();
            // Private key should be in reasonable range
            assert!(participant.private_key >= 2);
            assert!(participant.private_key < 1000000);
        }

        #[test]
        fn test_shared_secret_symmetry() {
            // Test that A->B and B->A produce same shared secret
            for i in 1..10 {
                let mut alice = DHParticipant::with_private_key(i * 7);
                let mut bob = DHParticipant::with_private_key(i * 11);
                
                let alice_shared = alice.compute_shared_secret(bob.public_key).unwrap();
                let bob_shared = bob.compute_shared_secret(alice.public_key).unwrap();
                
                assert_eq!(alice_shared, bob_shared, "Failed symmetry test with iteration {}", i);
            }
        }

        #[test]
        fn test_zero_public_key() {
            let mut alice = DHParticipant::new();
            // Zero should be a valid public key (though not secure)
            let result = alice.compute_shared_secret(0);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), 0); // g^0 = 1, and 1^private = 1, 1 mod p = 1
        }

        #[test]
        fn test_one_public_key() {
            let mut alice = DHParticipant::new();
            // One should be a valid public key
            let result = alice.compute_shared_secret(1);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), 1); // 1^private mod p = 1
        }

        #[test]
        fn test_multiple_computations_same_participant() {
            let mut alice = DHParticipant::with_private_key(42);
            let bob1 = DHParticipant::with_private_key(17);
            let bob2 = DHParticipant::with_private_key(23);
            
            let shared1 = alice.compute_shared_secret(bob1.public_key).unwrap();
            let shared2 = alice.compute_shared_secret(bob2.public_key).unwrap();
            
            // Alice should be able to compute multiple shared secrets
            assert_ne!(shared1, shared2);
            // Latest computation should be stored
            assert_eq!(alice.get_shared_secret(), Some(shared2));
        }

        #[test]
        fn test_large_private_keys() {
            let mut alice = DHParticipant::with_private_key(999999);
            let mut bob = DHParticipant::with_private_key(999998);
            
            let alice_shared = alice.compute_shared_secret(bob.public_key).unwrap();
            let bob_shared = bob.compute_shared_secret(alice.public_key).unwrap();
            
            assert_eq!(alice_shared, bob_shared);
        }

        #[test]
        fn test_small_private_keys() {
            let mut alice = DHParticipant::with_private_key(2);
            let mut bob = DHParticipant::with_private_key(3);
            
            let alice_shared = alice.compute_shared_secret(bob.public_key).unwrap();
            let bob_shared = bob.compute_shared_secret(alice.public_key).unwrap();
            
            assert_eq!(alice_shared, bob_shared);
        }
    }
}
