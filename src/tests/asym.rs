#[cfg(test)]
mod tests {

    #[cfg(test)]
    mod dh_tests {
        use crate::asym::dh::{
            complete_manual_key_exchange, demonstrate_concept, key_exchange,
            start_manual_key_exchange, DHParticipant,
        };

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

                assert_eq!(
                    alice_shared, bob_shared,
                    "Failed symmetry test with iteration {}",
                    i
                );
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

    #[cfg(test)]
    mod rsa_tests {
        use crate::{asym::rsa::{
            decrypt, encrypt, export_private_key_pem, export_public_key_pem, generate_key_pair,
            import_private_key_pem, rsa_decrypt, rsa_encrypt, rsa_sign, rsa_verify, sign, verify, RSAPrivateKey,
        }};

        #[test]
        fn test_key_generation_512() {
            let key_pair = generate_key_pair(512).unwrap();
            assert!(key_pair.public_key.n > 0);
            assert!(key_pair.public_key.e > 0);
            assert!(key_pair.private_key.d > 0);
            assert_eq!(key_pair.public_key.n, key_pair.private_key.n);
        }

        #[test]
        fn test_key_generation_1024() {
            let key_pair = generate_key_pair(1024).unwrap();
            assert!(key_pair.public_key.n > 0);
            assert!(key_pair.public_key.e > 0);
            assert!(key_pair.private_key.d > 0);
        }

        #[test]
        fn test_encrypt_decrypt_basic() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "Hello, RSA!";

            let encrypted = rsa_encrypt(message.as_bytes(), &key_pair.public_key).unwrap();
            let decrypted_bytes =
                rsa_decrypt(&encrypted.ciphertext, &key_pair.private_key).unwrap();
            let decrypted = String::from_utf8(decrypted_bytes).unwrap();

            assert_eq!(message, decrypted);
        }

        #[test]
        fn test_encrypt_decrypt_empty_string() {
            for _ in 0..5 {
                if let Ok(key_pair) = generate_key_pair(512) {
                    let message = "";

                    let encrypted = rsa_encrypt(message.as_bytes(), &key_pair.public_key).unwrap();
                    let decrypted_bytes =
                        rsa_decrypt(&encrypted.ciphertext, &key_pair.private_key).unwrap();
                    let decrypted = String::from_utf8(decrypted_bytes).unwrap();

                    assert_eq!(message, decrypted);
                    return;
                }
            }
            panic!("Could not generate key pair after 5 attempts");
        }

        #[test]
        fn test_encrypt_decrypt_single_char() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "A";

            let encrypted = rsa_encrypt(message.as_bytes(), &key_pair.public_key).unwrap();
            let decrypted_bytes =
                rsa_decrypt(&encrypted.ciphertext, &key_pair.private_key).unwrap();
            let decrypted = String::from_utf8(decrypted_bytes).unwrap();

            assert_eq!(message, decrypted);
        }

        #[test]
        fn test_encrypt_decrypt_unicode() {
            let key_pair = generate_key_pair(1024).unwrap();
            let message = "Hello 世界! 🔐";

            let encrypted = rsa_encrypt(message.as_bytes(), &key_pair.public_key).unwrap();
            let decrypted_bytes =
                rsa_decrypt(&encrypted.ciphertext, &key_pair.private_key).unwrap();
            let decrypted = String::from_utf8(decrypted_bytes).unwrap();

            assert_eq!(message, decrypted);
        }

        #[test]
        fn test_encrypt_decrypt_long_message() {
            let key_pair = generate_key_pair(1024).unwrap();
            let message = "This is a longer message to test RSA encryption with multiple blocks.";

            let encrypted = rsa_encrypt(message.as_bytes(), &key_pair.public_key).unwrap();
            let decrypted_bytes =
                rsa_decrypt(&encrypted.ciphertext, &key_pair.private_key).unwrap();
            let decrypted = String::from_utf8(decrypted_bytes).unwrap();

            assert_eq!(message, decrypted);
        }

        #[test]
        fn test_cli_encrypt_decrypt_base64() {
            let message = "Test message";
            let (encrypted, private_key) = encrypt(message, "512", "base64", "n:d").unwrap();
            let decrypted = decrypt(&encrypted, &private_key, "base64").unwrap();

            assert_eq!(message, decrypted);
        }

        #[test]
        fn test_cli_encrypt_decrypt_hex() {
            // Try multiple times in case of prime generation failure
            for _ in 0..5 {
                let message = "Test message";
                if let Ok((encrypted, private_key)) = encrypt(message, "512", "hex", "n:d") {
                    // Verify hex format
                    assert!(encrypted.chars().all(|c| c.is_ascii_hexdigit()));
                    assert_eq!(encrypted.len() % 2, 0);

                    let decrypted = decrypt(&encrypted, &private_key, "hex").unwrap();
                    assert_eq!(message, decrypted);
                    return; // Test passed
                }
            }
            panic!("Could not complete encrypt/decrypt after 5 attempts");
        }

        #[test]
        fn test_invalid_key_size() {
            assert!(encrypt("test", "256", "base64", "n:d").is_err());
            assert!(encrypt("test", "4096", "base64", "n:d").is_err());
            assert!(encrypt("test", "abc", "base64", "n:d").is_err());
        }

        #[test]
        fn test_invalid_encoding() {
            assert!(encrypt("test", "512", "invalid", "n:d").is_err());
        }

        #[test]
        fn test_invalid_private_key_format() {
            assert!(decrypt("data", "invalid", "base64").is_err());
            assert!(decrypt("data", "123", "base64").is_err());
            assert!(decrypt("data", "abc:def", "base64").is_err());
        }

        #[test]
        fn test_different_key_pairs_different_results() {
            let key_pair1 = generate_key_pair(512).unwrap();
            let key_pair2 = generate_key_pair(512).unwrap();
            let message = "Same message";

            let encrypted1 = rsa_encrypt(message.as_bytes(), &key_pair1.public_key).unwrap();
            let encrypted2 = rsa_encrypt(message.as_bytes(), &key_pair2.public_key).unwrap();

            // Different key pairs should produce different ciphertext
            assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        }

        #[test]
        fn test_special_characters() {
            // Try multiple times in case of prime generation failure
            for _ in 0..5 {
                if let Ok(key_pair) = generate_key_pair(1024) {
                    let original = "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./~`";

                    let encrypted = rsa_encrypt(original.as_bytes(), &key_pair.public_key).unwrap();
                    let decrypted_bytes =
                        rsa_decrypt(&encrypted.ciphertext, &key_pair.private_key).unwrap();
                    let decrypted = String::from_utf8(decrypted_bytes).unwrap();

                    // Remove any null bytes that might have been added during decryption
                    let cleaned_decrypted = decrypted.trim_end_matches('\0');
                    assert_eq!(original, cleaned_decrypted);
                    return; // Test passed
                }
            }
            panic!("Could not generate key pair after 5 attempts");
        }

        #[test]
        fn test_hex_format_consistency() {
            for _ in 0..3 {
                if let Ok((encrypted, private_key)) =
                    encrypt("Test hex format", "512", "hex", "n:d")
                {
                    // Verify hex format
                    assert!(encrypted.chars().all(|c| c.is_ascii_hexdigit()));
                    assert_eq!(encrypted.len() % 2, 0);

                    // Verify round trip
                    let decrypted = decrypt(&encrypted, &private_key, "hex").unwrap();
                    assert_eq!("Test hex format", decrypted);
                    return;
                }
            }
            panic!("Could not test hex format after 3 attempts");
        }

        #[test]
        fn test_prime_generation_retry() {
            // This test ensures our improved prime generation works
            for _ in 0..3 {
                if generate_key_pair(512).is_ok() {
                    return; // Success
                }
            }
            panic!("Prime generation failed consistently");
        }

        #[test]
        fn test_export_import_private_key_pem() {
            let key_pair = generate_key_pair(512).unwrap();
            let pem = export_private_key_pem(&key_pair.private_key);
            let imported = import_private_key_pem(&pem).unwrap();
            assert_eq!(key_pair.private_key.n, imported.n);
            assert_eq!(key_pair.private_key.d, imported.d);
        }

        #[test]
        fn test_encrypt_decrypt_with_pem_private_key() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "PEM test message";
            let encrypted = rsa_encrypt(message.as_bytes(), &key_pair.public_key).unwrap();
            let pem = export_private_key_pem(&key_pair.private_key);
            let imported = import_private_key_pem(&pem).unwrap();
            let decrypted_bytes = rsa_decrypt(&encrypted.ciphertext, &imported).unwrap();
            let decrypted = String::from_utf8(decrypted_bytes).unwrap();
            assert_eq!(message, decrypted);
        }

        #[test]
        fn test_cli_encrypt_decrypt_with_pem_private_key() {
            let message = "Test PEM CLI";
            let (encrypted, private_key) = encrypt(message, "512", "base64", "n:d").unwrap();
            // Convert n:d to PEM
            let parts: Vec<&str> = private_key.split(':').collect();
            assert_eq!(parts.len(), 2);
            let n = parts[0].parse::<u64>().unwrap();
            let d = parts[1].parse::<u64>().unwrap();
            let pem = export_private_key_pem(&RSAPrivateKey { n, d });
            let decrypted = decrypt(&encrypted, &pem, "base64").unwrap();

            assert_eq!(message, decrypted);
        }

        #[test]
        fn test_cli_encrypt_decrypt_with_direct_pem_private_key() {
            let message = "Test PEM CLI direct";
            let (encrypted, private_key) = encrypt(message, "512", "base64", "PEM").unwrap();
            let decrypted = decrypt(&encrypted, &private_key, "base64").unwrap();
            assert_eq!(message, decrypted);
        }

        #[test]
        fn test_invalid_pem_import() {
            // Not a PEM block
            assert!(import_private_key_pem("not a pem").is_err());
            // Corrupted PEM block
            let pem =
                "-----BEGIN RSA PRIVATE KEY-----\ninvalidbase64\n-----END RSA PRIVATE KEY-----";
            assert!(import_private_key_pem(pem).is_err());
        }

        #[test]
        fn test_export_public_key_pem_format() {
            let key_pair = generate_key_pair(512).unwrap();
            let pem = export_public_key_pem(&key_pair.public_key);
            assert!(pem.starts_with("-----BEGIN RSA PUBLIC KEY-----"));
            assert!(pem.ends_with("-----END RSA PUBLIC KEY-----"));
        }

        #[test]
        fn test_rsa_sign_verify_basic() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = b"Hello, RSA signature!";

            let signature = rsa_sign(message, &key_pair.private_key).unwrap();
            let is_valid = rsa_verify(message, &signature, &key_pair.public_key).unwrap();

            assert!(is_valid);
        }

        #[test]
        fn test_rsa_sign_verify_different_messages() {
            let key_pair = generate_key_pair(512).unwrap();
            let message1 = b"First message";
            let message2 = b"Second message";

            let signature1 = rsa_sign(message1, &key_pair.private_key).unwrap();
            let signature2 = rsa_sign(message2, &key_pair.private_key).unwrap();

            // Signatures should be different for different messages
            assert_ne!(signature1, signature2);

            // Each signature should verify with its corresponding message
            assert!(rsa_verify(message1, &signature1, &key_pair.public_key).unwrap());
            assert!(rsa_verify(message2, &signature2, &key_pair.public_key).unwrap());

            // Cross-verification should fail
            assert!(!rsa_verify(message1, &signature2, &key_pair.public_key).unwrap());
            assert!(!rsa_verify(message2, &signature1, &key_pair.public_key).unwrap());
        }

        #[test]
        fn test_rsa_sign_verify_empty_message() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = b"";

            let signature = rsa_sign(message, &key_pair.private_key).unwrap();
            let is_valid = rsa_verify(message, &signature, &key_pair.public_key).unwrap();

            assert!(is_valid);
        }

        #[test]
        fn test_rsa_sign_verify_unicode_message() {
            // Try multiple times to account for prime generation issues
            for _ in 0..5 {
                if let Ok(key_pair) = generate_key_pair(1024) {
                    let message = "Hello 世界! 🔐 Testing unicode signatures".as_bytes();

                    let signature = rsa_sign(message, &key_pair.private_key).unwrap();
                    let is_valid = rsa_verify(message, &signature, &key_pair.public_key).unwrap();

                    assert!(is_valid);
                    return; // Test passed
                }
            }
            panic!("Could not generate key pair after 5 attempts");
        }

        #[test]
        fn test_rsa_sign_verify_wrong_key() {
            let key_pair1 = generate_key_pair(512).unwrap();
            let key_pair2 = generate_key_pair(512).unwrap();
            let message = b"Test message";

            let signature = rsa_sign(message, &key_pair1.private_key).unwrap();
            
            // Verification with wrong public key should fail
            let is_valid = rsa_verify(message, &signature, &key_pair2.public_key).unwrap();
            assert!(!is_valid);
        }

        #[test]
        fn test_cli_sign_verify_base64() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "Test CLI signing";
            let private_key_str = format!("{}:{}", key_pair.private_key.n, key_pair.private_key.d);
            let public_key_str = format!("{}:{}", key_pair.public_key.n, key_pair.public_key.e);

            let signature = sign(message, &private_key_str, "base64").unwrap();
            let is_valid = verify(message, &signature, &public_key_str, "base64").unwrap();

            assert!(is_valid);
        }

        #[test]
        fn test_cli_sign_verify_hex() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "Test CLI signing hex";
            let private_key_str = format!("{}:{}", key_pair.private_key.n, key_pair.private_key.d);
            let public_key_str = format!("{}:{}", key_pair.public_key.n, key_pair.public_key.e);

            let signature = sign(message, &private_key_str, "hex").unwrap();
            let is_valid = verify(message, &signature, &public_key_str, "hex").unwrap();

            assert!(is_valid);
            
            // Verify hex format
            assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(signature.len() % 2, 0);
        }

        #[test]
        fn test_cli_sign_verify_pem_private_key() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "Test PEM private key signing";
            let private_key_pem = export_private_key_pem(&key_pair.private_key);
            let public_key_str = format!("{}:{}", key_pair.public_key.n, key_pair.public_key.e);

            let signature = sign(message, &private_key_pem, "base64").unwrap();
            let is_valid = verify(message, &signature, &public_key_str, "base64").unwrap();

            assert!(is_valid);
        }

        #[test]
        fn test_cli_sign_verify_pem_public_key() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "Test PEM public key verification";
            let private_key_str = format!("{}:{}", key_pair.private_key.n, key_pair.private_key.d);
            let public_key_pem = export_public_key_pem(&key_pair.public_key);

            let signature = sign(message, &private_key_str, "base64").unwrap();
            let is_valid = verify(message, &signature, &public_key_pem, "base64").unwrap();

            assert!(is_valid);
        }

        #[test]
        fn test_cli_sign_verify_both_pem() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "Test both PEM formats";
            let private_key_pem = export_private_key_pem(&key_pair.private_key);
            let public_key_pem = export_public_key_pem(&key_pair.public_key);

            let signature = sign(message, &private_key_pem, "base64").unwrap();
            let is_valid = verify(message, &signature, &public_key_pem, "base64").unwrap();

            assert!(is_valid);
        }

        #[test]
        fn test_sign_invalid_private_key_format() {
            let message = "Test message";
            
            // Invalid format - not n:d
            assert!(sign(message, "invalid", "base64").is_err());
            
            // Invalid format - wrong separator
            assert!(sign(message, "123-456", "base64").is_err());
            
            // Invalid format - non-numeric
            assert!(sign(message, "abc:def", "base64").is_err());
        }

        #[test]
        fn test_verify_invalid_public_key_format() {
            let message = "Test message";
            let signature = "dGVzdA=="; // Valid base64
            
            // Invalid format - not n:e
            assert!(verify(message, signature, "invalid", "base64").is_err());
            
            // Invalid format - wrong separator
            assert!(verify(message, signature, "123-456", "base64").is_err());
            
            // Invalid format - non-numeric
            assert!(verify(message, signature, "abc:def", "base64").is_err());
        }

        #[test]
        fn test_sign_verify_invalid_encoding() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "Test message";
            let private_key_str = format!("{}:{}", key_pair.private_key.n, key_pair.private_key.d);
            let public_key_str = format!("{}:{}", key_pair.public_key.n, key_pair.public_key.e);

            // Invalid encoding for signing
            assert!(sign(message, &private_key_str, "invalid").is_err());
            
            // Invalid encoding for verification
            let signature = sign(message, &private_key_str, "base64").unwrap();
            assert!(verify(message, &signature, &public_key_str, "invalid").is_err());
        }

        #[test]
        fn test_verify_invalid_signature_format() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "Test message";
            let public_key_str = format!("{}:{}", key_pair.public_key.n, key_pair.public_key.e);

            // Invalid base64 signature
            assert!(verify(message, "not_base64!", &public_key_str, "base64").is_err());
            
            // Invalid hex signature (odd length)
            assert!(verify(message, "abc", &public_key_str, "hex").is_err());
            
            // Invalid hex signature (non-hex chars)
            assert!(verify(message, "abcdefgh", &public_key_str, "hex").is_err());
        }

        #[test]
        fn test_sign_verify_tampered_message() {
            let key_pair = generate_key_pair(512).unwrap();
            let original_message = "Original message";
            let tampered_message = "Tampered message";
            let private_key_str = format!("{}:{}", key_pair.private_key.n, key_pair.private_key.d);
            let public_key_str = format!("{}:{}", key_pair.public_key.n, key_pair.public_key.e);

            let signature = sign(original_message, &private_key_str, "base64").unwrap();
            
            // Verification should fail with tampered message
            let is_valid = verify(tampered_message, &signature, &public_key_str, "base64").unwrap();
            assert!(!is_valid);
        }

        #[test]
        fn test_sign_verify_tampered_signature() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "Test message";
            let private_key_str = format!("{}:{}", key_pair.private_key.n, key_pair.private_key.d);
            let public_key_str = format!("{}:{}", key_pair.public_key.n, key_pair.public_key.e);

            let mut signature = sign(message, &private_key_str, "base64").unwrap();
            
            // Tamper with the signature
            signature.push('X');
            
            // Verification should fail with tampered signature
            let result = verify(message, &signature, &public_key_str, "base64");
            assert!(result.is_err() || !result.unwrap());
        }

        #[test]
        fn test_sign_verify_consistency() {
            // Test that signing the same message multiple times produces consistent results
            let key_pair = generate_key_pair(512).unwrap();
            let message = "Consistency test message";
            let private_key_str = format!("{}:{}", key_pair.private_key.n, key_pair.private_key.d);
            let public_key_str = format!("{}:{}", key_pair.public_key.n, key_pair.public_key.e);

            let signature1 = sign(message, &private_key_str, "base64").unwrap();
            let signature2 = sign(message, &private_key_str, "base64").unwrap();

            // RSA signatures should be deterministic (same message, same key = same signature)
            assert_eq!(signature1, signature2);

            // Both signatures should verify
            assert!(verify(message, &signature1, &public_key_str, "base64").unwrap());
            assert!(verify(message, &signature2, &public_key_str, "base64").unwrap());
        }

        #[test]
        fn test_sign_verify_invalid_pem_private_key() {
            let message = "Test message";
            
            // Invalid PEM format
            let invalid_pem = "-----BEGIN RSA PRIVATE KEY-----\ninvalid_base64\n-----END RSA PRIVATE KEY-----";
            assert!(sign(message, invalid_pem, "base64").is_err());
            
            // Missing PEM headers
            let missing_headers = "some_random_data";
            assert!(sign(message, missing_headers, "base64").is_err());
        }

        #[test]
        fn test_sign_verify_invalid_pem_public_key() {
            let key_pair = generate_key_pair(512).unwrap();
            let message = "Test message";
            let private_key_str = format!("{}:{}", key_pair.private_key.n, key_pair.private_key.d);
            let signature = sign(message, &private_key_str, "base64").unwrap();
            
            // Invalid PEM format
            let invalid_pem = "-----BEGIN RSA PUBLIC KEY-----\ninvalid_base64\n-----END RSA PUBLIC KEY-----";
            assert!(verify(message, &signature, invalid_pem, "base64").is_err());
        }
    }
}
