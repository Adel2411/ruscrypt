#[cfg(test)]
mod tests {

    #[cfg(test)]
    mod des_tests {
        use crate::block::des;

        #[test]
        fn test_encrypt_basic_base64() {
            let result = des::encrypt("Hello", "12345678", "ECB", "base64").unwrap();
            // Should be valid base64 string
            assert!(crate::utils::from_base64(&result).is_ok());
        }

        #[test]
        fn test_encrypt_basic_hex() {
            let result = des::encrypt("Hello", "12345678", "CBC", "hex").unwrap();
            // Should be hex string
            assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(result.len() % 2, 0); // Even length for hex
        }

        #[test]
        fn test_decrypt_basic_base64() {
            let original = "Hello World";
            let key = "password";
            let encrypted = des::encrypt(original, key, "ECB", "base64").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "ECB", "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_decrypt_basic_hex() {
            let original = "Hello World";
            let key = "testkey1";
            let encrypted = des::encrypt(original, key, "CBC", "hex").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "CBC", "hex").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_round_trip_both_modes() {
            let original = "The Quick Brown Fox Jumps Over The Lazy Dog!";
            let key = "secret12";
            
            // Test ECB mode
            let encrypted_ecb = des::encrypt(original, key, "ECB", "base64").unwrap();
            let decrypted_ecb = des::decrypt(&encrypted_ecb, key, "ECB", "base64").unwrap();
            assert_eq!(decrypted_ecb, original);
            
            // Test CBC mode
            let encrypted_cbc = des::encrypt(original, key, "CBC", "base64").unwrap();
            let decrypted_cbc = des::decrypt(&encrypted_cbc, key, "CBC", "base64").unwrap();
            assert_eq!(decrypted_cbc, original);
            
            // ECB and CBC should produce different ciphertexts
            assert_ne!(encrypted_ecb, encrypted_cbc);
        }

        #[test]
        fn test_invalid_mode() {
            assert!(des::encrypt("Hello", "12345678", "OFB", "base64").is_err());
            assert!(des::decrypt("deadbeef", "12345678", "CFB", "base64").is_err());
        }

        #[test]
        fn test_invalid_key_length() {
            // Too short
            assert!(des::encrypt("Hello", "short", "ECB", "base64").is_err());
            assert!(des::decrypt("data", "short", "ECB", "base64").is_err());
            
            // Too long
            assert!(des::encrypt("Hello", "toolongkey", "ECB", "base64").is_err());
            assert!(des::decrypt("data", "toolongkey", "ECB", "base64").is_err());
            
            // Empty
            assert!(des::encrypt("Hello", "", "ECB", "base64").is_err());
            assert!(des::decrypt("data", "", "ECB", "base64").is_err());
        }

        #[test]
        fn test_valid_key_length() {
            let key = "exactly8"; // Exactly 8 characters
            let original = "Test message";
            
            let encrypted = des::encrypt(original, key, "ECB", "base64").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "ECB", "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_invalid_encoding() {
            assert!(des::encrypt("Hello", "12345678", "ECB", "invalid").is_err());
            assert!(des::decrypt("deadbeef", "12345678", "ECB", "invalid").is_err());
        }

        #[test]
        fn test_empty_string_both_encodings() {
            let key = "testkey1";
            
            let encrypted_b64 = des::encrypt("", key, "ECB", "base64").unwrap();
            let decrypted_b64 = des::decrypt(&encrypted_b64, key, "ECB", "base64").unwrap();
            assert_eq!(decrypted_b64, "");
            
            let encrypted_hex = des::encrypt("", key, "ECB", "hex").unwrap();
            let decrypted_hex = des::decrypt(&encrypted_hex, key, "ECB", "hex").unwrap();
            assert_eq!(decrypted_hex, "");
        }

        #[test]
        fn test_different_keys() {
            let text = "Secret Message";
            let encrypted1 = des::encrypt(text, "key12345", "ECB", "base64").unwrap();
            let encrypted2 = des::encrypt(text, "key54321", "ECB", "base64").unwrap();
            assert_ne!(encrypted1, encrypted2);
        }

        #[test]
        fn test_unicode_text() {
            let original = "Hello 世界! 🔐";
            let key = "unicode1";
            let encrypted = des::encrypt(original, key, "ECB", "base64").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "ECB", "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_long_text() {
            let original = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(10);
            let key = "longtext";
            let encrypted = des::encrypt(&original, key, "ECB", "base64").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "ECB", "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_special_characters() {
            let original = "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./~`";
            let key = "special1";
            let encrypted = des::encrypt(original, key, "ECB", "base64").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "ECB", "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_hex_output_format() {
            let encrypted = des::encrypt("test", "hextest1", "ECB", "hex").unwrap();
            // Should be even length (each byte = 2 hex chars)
            assert_eq!(encrypted.len() % 2, 0);
            // Should only contain hex characters
            assert!(encrypted.chars().all(|c| "0123456789abcdef".contains(c)));
        }

        #[test]
        fn test_base64_output_format() {
            let encrypted = des::encrypt("test", "b64test1", "ECB", "base64").unwrap();
            // Should be valid base64
            assert!(crate::utils::from_base64(&encrypted).is_ok());
            // Should only contain base64 characters
            assert!(encrypted.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='));
        }

        #[test]
        fn test_invalid_hex_input() {
            // Test decryption with invalid hex
            assert!(des::decrypt("invalid_hex", "testkey1", "ECB", "hex").is_err());
            assert!(des::decrypt("zz", "testkey1", "ECB", "hex").is_err());
            assert!(des::decrypt("a", "testkey1", "ECB", "hex").is_err()); // Odd length
        }

        #[test]
        fn test_invalid_base64_input() {
            // Test decryption with invalid base64
            assert!(des::decrypt("invalid_base64!", "testkey1", "ECB", "base64").is_err());
            assert!(des::decrypt("@#$%", "testkey1", "ECB", "base64").is_err());
        }

        #[test]
        fn test_case_sensitivity() {
            let text = "Test Message";
            let encrypted1 = des::encrypt(text, "Key12345", "ECB", "base64").unwrap();
            let encrypted2 = des::encrypt(text, "key12345", "ECB", "base64").unwrap();
            assert_ne!(encrypted1, encrypted2);
        }

        #[test]
        fn test_repeated_calls() {
            let text = "Consistency Test";
            let key = "testkey1";
            let encrypted1 = des::encrypt(text, key, "ECB", "base64").unwrap();
            let encrypted2 = des::encrypt(text, key, "ECB", "base64").unwrap();
            assert_eq!(encrypted1, encrypted2);
        }

        #[test]
        fn test_block_size_padding() {
            // Test various input lengths to verify padding works correctly
            let key = "padtest1";
            
            for length in 1..=20 {
                let input = "a".repeat(length);
                let encrypted = des::encrypt(&input, key, "ECB", "base64").unwrap();
                let decrypted = des::decrypt(&encrypted, key, "ECB", "base64").unwrap();
                assert_eq!(decrypted, input, "Failed at length: {}", length);
            }
        }

        #[test]
        fn test_cross_encoding_compatibility() {
            // Encrypt with one encoding, manually convert, decrypt with other
            let original = "Cross encoding test";
            let key = "crosskey";
            
            let encrypted_hex = des::encrypt(original, key, "ECB", "hex").unwrap();
            let encrypted_b64 = des::encrypt(original, key, "ECB", "base64").unwrap();
            
            // Both should decrypt to same result
            let decrypted_from_hex = des::decrypt(&encrypted_hex, key, "ECB", "hex").unwrap();
            let decrypted_from_b64 = des::decrypt(&encrypted_b64, key, "ECB", "base64").unwrap();
            
            assert_eq!(decrypted_from_hex, original);
            assert_eq!(decrypted_from_b64, original);
            assert_eq!(decrypted_from_hex, decrypted_from_b64);
        }

        #[test]
        fn test_invalid_encrypted_data_length() {
            let key = "testkey1";
            
            // Test with data that's not a multiple of block size when decoded
            let invalid_hex = "deadbe"; // Not multiple of 16 hex chars (8 bytes)
            assert!(des::decrypt(invalid_hex, key, "ECB", "hex").is_err());
        }
    }

    #[cfg(test)]
    mod aes_tests {
        use crate::block::aes;

        #[test]
        fn test_encrypt_basic_base64_128() {
            let result = aes::encrypt("Hello", "password", "128", "ECB", "base64").unwrap();
            // Should be valid base64 string
            assert!(crate::utils::from_base64(&result).is_ok());
        }

        #[test]
        fn test_encrypt_basic_hex_256() {
            let result = aes::encrypt("Hello", "password", "256", "CBC", "hex").unwrap();
            // Should be hex string
            assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(result.len() % 2, 0); // Even length for hex
        }

        #[test]
        fn test_decrypt_basic_base64() {
            let original = "Hello World";
            let password = "testpassword";
            let key_size = "256";
            let encrypted = aes::encrypt(original, password, key_size, "ECB", "base64").unwrap();
            let decrypted = aes::decrypt(&encrypted, password, key_size, "ECB", "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_round_trip_both_modes() {
            let original = "The Quick Brown Fox Jumps Over The Lazy Dog!";
            let password = "securepassword123";
            let key_size = "192";
            
            // Test ECB mode
            let encrypted_ecb = aes::encrypt(original, password, key_size, "ECB", "base64").unwrap();
            let decrypted_ecb = aes::decrypt(&encrypted_ecb, password, key_size, "ECB", "base64").unwrap();
            assert_eq!(decrypted_ecb, original);
            
            // Test CBC mode
            let encrypted_cbc = aes::encrypt(original, password, key_size, "CBC", "base64").unwrap();
            let decrypted_cbc = aes::decrypt(&encrypted_cbc, password, key_size, "CBC", "base64").unwrap();
            assert_eq!(decrypted_cbc, original);
            
            // ECB and CBC should produce different ciphertexts
            assert_ne!(encrypted_ecb, encrypted_cbc);
        }

        #[test]
        fn test_invalid_mode() {
            assert!(aes::encrypt("Hello", "password", "256", "GCM", "base64").is_err());
            assert!(aes::decrypt("data", "password", "128", "CTR", "base64").is_err());
        }

        #[test]
        fn test_all_key_sizes() {
            let original = "Test message for all key sizes";
            let password = "testpassword";
            
            for key_size in ["128", "192", "256"] {
                let encrypted = aes::encrypt(original, password, key_size, "ECB", "base64").unwrap();
                let decrypted = aes::decrypt(&encrypted, password, key_size, "ECB", "base64").unwrap();
                assert_eq!(decrypted, original, "Failed with key size: {}", key_size);
            }
        }

        #[test]
        fn test_invalid_key_size() {
            assert!(aes::encrypt("Hello", "password", "64", "ECB", "base64").is_err());
            assert!(aes::encrypt("Hello", "password", "512", "ECB", "base64").is_err());
            assert!(aes::encrypt("Hello", "password", "abc", "ECB", "base64").is_err());
            assert!(aes::decrypt("data", "password", "invalid", "ECB", "base64").is_err());
        }

        #[test]
        fn test_empty_password() {
            assert!(aes::encrypt("Hello", "", "256", "ECB", "base64").is_err());
            assert!(aes::decrypt("data", "", "128", "ECB", "base64").is_err());
        }

        #[test]
        fn test_different_passwords() {
            let text = "Secret Message";
            let key_size = "256";
            let encrypted1 = aes::encrypt(text, "password1", key_size, "ECB", "base64").unwrap();
            let encrypted2 = aes::encrypt(text, "password2", key_size, "ECB", "base64").unwrap();
            assert_ne!(encrypted1, encrypted2);
        }

        #[test]
        fn test_different_key_sizes_same_password() {
            let text = "Test with different key sizes";
            let password = "samepassword";
            
            let encrypted_128 = aes::encrypt(text, password, "128", "ECB", "base64").unwrap();
            let encrypted_192 = aes::encrypt(text, password, "192", "ECB", "base64").unwrap();
            let encrypted_256 = aes::encrypt(text, password, "256", "ECB", "base64").unwrap();
            
            // Different key sizes should produce different ciphertexts
            assert_ne!(encrypted_128, encrypted_192);
            assert_ne!(encrypted_192, encrypted_256);
            assert_ne!(encrypted_128, encrypted_256);
            
            // But all should decrypt correctly
            assert_eq!(aes::decrypt(&encrypted_128, password, "128", "ECB", "base64").unwrap(), text);
            assert_eq!(aes::decrypt(&encrypted_192, password, "192", "ECB", "base64").unwrap(), text);
            assert_eq!(aes::decrypt(&encrypted_256, password, "256", "ECB", "base64").unwrap(), text);
        }

        #[test]
        fn test_unicode_text() {
            let original = "Hello 世界! 🔐";
            let password = "unicode_password";
            let key_size = "256";
            let encrypted = aes::encrypt(original, password, key_size, "ECB", "base64").unwrap();
            let decrypted = aes::decrypt(&encrypted, password, key_size, "ECB", "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_long_text() {
            let original = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(20);
            let password = "longtext_password";
            let key_size = "128";
            let encrypted = aes::encrypt(&original, password, key_size, "ECB", "base64").unwrap();
            let decrypted = aes::decrypt(&encrypted, password, key_size, "ECB", "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_empty_string() {
            let password = "testpassword";
            let key_size = "192";
            let encrypted = aes::encrypt("", password, key_size, "ECB", "base64").unwrap();
            let decrypted = aes::decrypt(&encrypted, password, key_size, "ECB", "base64").unwrap();
            assert_eq!(decrypted, "");
        }

        #[test]
        fn test_special_characters() {
            let original = "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./~`";
            let password = "special_chars_test";
            let key_size = "256";
            let encrypted = aes::encrypt(original, password, key_size, "ECB", "base64").unwrap();
            let decrypted = aes::decrypt(&encrypted, password, key_size, "ECB", "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_invalid_encoding() {
            assert!(aes::encrypt("Hello", "password", "256", "ECB", "invalid").is_err());
            assert!(aes::decrypt("data", "password", "128", "ECB", "invalid").is_err());
        }

        #[test]
        fn test_hex_output_format() {
            let encrypted = aes::encrypt("test", "password", "256", "ECB", "hex").unwrap();
            // Should be even length (each byte = 2 hex chars)
            assert_eq!(encrypted.len() % 2, 0);
            // Should only contain hex characters
            assert!(encrypted.chars().all(|c| "0123456789abcdef".contains(c)));
        }

        #[test]
        fn test_base64_output_format() {
            let encrypted = aes::encrypt("test", "password", "128", "ECB", "base64").unwrap();
            // Should be valid base64
            assert!(crate::utils::from_base64(&encrypted).is_ok());
            // Should only contain base64 characters
            assert!(encrypted.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='));
        }

        #[test]
        fn test_invalid_hex_input() {
            // Test decryption with invalid hex
            assert!(aes::decrypt("invalid_hex", "password", "256", "ECB", "hex").is_err());
            assert!(aes::decrypt("zz", "password", "192", "ECB", "hex").is_err());
            assert!(aes::decrypt("a", "password", "128", "ECB", "hex").is_err()); // Odd length
        }

        #[test]
        fn test_invalid_base64_input() {
            // Test decryption with invalid base64
            assert!(aes::decrypt("invalid_base64!", "password", "256", "ECB", "base64").is_err());
            assert!(aes::decrypt("@#$%", "password", "128", "ECB", "base64").is_err());
        }

        #[test]
        fn test_case_sensitivity() {
            let text = "Test Message";
            let key_size = "256";
            let encrypted1 = aes::encrypt(text, "Password", key_size, "ECB", "base64").unwrap();
            let encrypted2 = aes::encrypt(text, "password", key_size, "ECB", "base64").unwrap();
            assert_ne!(encrypted1, encrypted2);
        }

        #[test]
        fn test_repeated_calls() {
            let text = "Consistency Test";
            let password = "testpassword";
            let key_size = "192";
            let encrypted1 = aes::encrypt(text, password, key_size, "ECB", "base64").unwrap();
            let encrypted2 = aes::encrypt(text, password, key_size, "ECB", "base64").unwrap();
            assert_eq!(encrypted1, encrypted2);
        }

        #[test]
        fn test_wrong_key_size_for_decryption() {
            let original = "Test message";
            let password = "testpassword";
            
            // Encrypt with 256-bit key
            let encrypted = aes::encrypt(original, password, "256", "ECB", "base64").unwrap();
            
            // Try to decrypt with different key sizes - should fail or produce garbage
            let decrypted_128 = aes::decrypt(&encrypted, password, "128", "ECB", "base64");
            let decrypted_192 = aes::decrypt(&encrypted, password, "192", "ECB", "base64");
            
            // These might succeed but produce wrong results
            if let Ok(result_128) = decrypted_128 {
                assert_ne!(result_128, original);
            }
            if let Ok(result_192) = decrypted_192 {
                assert_ne!(result_192, original);
            }
            
            // Correct key size should work
            let decrypted_correct = aes::decrypt(&encrypted, password, "256", "ECB", "base64").unwrap();
            assert_eq!(decrypted_correct, original);
        }

        #[test]
        fn test_block_size_padding() {
            let password = "padtest";
            let key_size = "128";
            
            // Test various input lengths to verify padding works correctly
            for length in 1..=50 {
                let input = "a".repeat(length);
                let encrypted = aes::encrypt(&input, password, key_size, "ECB", "base64").unwrap();
                let decrypted = aes::decrypt(&encrypted, password, key_size, "ECB", "base64").unwrap();
                assert_eq!(decrypted, input, "Failed at length: {}", length);
            }
        }

        #[test]
        fn test_cross_encoding_compatibility() {
            let original = "Cross encoding test";
            let password = "crosskey";
            let key_size = "256";
            
            let encrypted_hex = aes::encrypt(original, password, key_size, "ECB", "hex").unwrap();
            let encrypted_b64 = aes::encrypt(original, password, key_size, "ECB", "base64").unwrap();
            
            // Both should decrypt to same result
            let decrypted_from_hex = aes::decrypt(&encrypted_hex, password, key_size, "ECB", "hex").unwrap();
            let decrypted_from_b64 = aes::decrypt(&encrypted_b64, password, key_size, "ECB", "base64").unwrap();
            
            assert_eq!(decrypted_from_hex, original);
            assert_eq!(decrypted_from_b64, original);
            assert_eq!(decrypted_from_hex, decrypted_from_b64);
        }
    }
}
