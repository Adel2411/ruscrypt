#[cfg(test)]
mod tests {

    #[cfg(test)]
    mod rc4_tests {
        use crate::stream::rc4;

        #[test]
        fn test_encrypt_basic_base64() {
            let result = rc4::encrypt("Hello", "key", "base64").unwrap();
            // Should be valid base64 string
            assert!(crate::utils::from_base64(&result).is_ok());
        }

        #[test]
        fn test_encrypt_basic_hex() {
            let result = rc4::encrypt("Hello", "key", "hex").unwrap();
            // Should be hex string
            assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(result.len(), 10); // 5 bytes = 10 hex chars
        }

        #[test]
        fn test_decrypt_basic_base64() {
            let original = "Hello World";
            let key = "secret";
            let encrypted = rc4::encrypt(original, key, "base64").unwrap();
            let decrypted = rc4::decrypt(&encrypted, key, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_decrypt_basic_hex() {
            let original = "Hello World";
            let key = "secret";
            let encrypted = rc4::encrypt(original, key, "hex").unwrap();
            let decrypted = rc4::decrypt(&encrypted, key, "hex").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_round_trip_both_encodings() {
            let original = "The Quick Brown Fox Jumps Over The Lazy Dog!";
            let key = "password123";
            
            // Test base64
            let encrypted_b64 = rc4::encrypt(original, key, "base64").unwrap();
            let decrypted_b64 = rc4::decrypt(&encrypted_b64, key, "base64").unwrap();
            assert_eq!(decrypted_b64, original);
            
            // Test hex
            let encrypted_hex = rc4::encrypt(original, key, "hex").unwrap();
            let decrypted_hex = rc4::decrypt(&encrypted_hex, key, "hex").unwrap();
            assert_eq!(decrypted_hex, original);
        }

        #[test]
        fn test_invalid_encoding() {
            assert!(rc4::encrypt("Hello", "key", "invalid").is_err());
            assert!(rc4::decrypt("deadbeef", "key", "invalid").is_err());
        }

        #[test]
        fn test_hex_output_format() {
            let encrypted = rc4::encrypt("test", "key", "hex").unwrap();
            // Should be even length (each byte = 2 hex chars)
            assert_eq!(encrypted.len() % 2, 0);
            // Should only contain hex characters
            assert!(encrypted.chars().all(|c| "0123456789abcdef".contains(c)));
        }

        #[test]
        fn test_base64_output_format() {
            let encrypted = rc4::encrypt("test", "key", "base64").unwrap();
            // Should be valid base64
            assert!(crate::utils::from_base64(&encrypted).is_ok());
            // Should only contain base64 characters
            assert!(encrypted.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='));
        }

        #[test]
        fn test_invalid_hex_input() {
            // Test decryption with invalid hex
            assert!(rc4::decrypt("invalid_hex", "key", "hex").is_err());
            assert!(rc4::decrypt("zz", "key", "hex").is_err());
            assert!(rc4::decrypt("a", "key", "hex").is_err()); // Odd length
        }

        #[test]
        fn test_invalid_base64_input() {
            // Test decryption with invalid base64
            assert!(rc4::decrypt("invalid_base64!", "key", "base64").is_err());
            assert!(rc4::decrypt("@#$%", "key", "base64").is_err());
        }

        #[test]
        fn test_empty_string_both_encodings() {
            let encrypted_b64 = rc4::encrypt("", "key", "base64").unwrap();
            assert_eq!(encrypted_b64, "");
            let decrypted_b64 = rc4::decrypt("", "key", "base64").unwrap();
            assert_eq!(decrypted_b64, "");
            
            let encrypted_hex = rc4::encrypt("", "key", "hex").unwrap();
            assert_eq!(encrypted_hex, "");
            let decrypted_hex = rc4::decrypt("", "key", "hex").unwrap();
            assert_eq!(decrypted_hex, "");
        }

        #[test]
        fn test_empty_key() {
            assert!(rc4::encrypt("Hello", "", "base64").is_err());
            assert!(rc4::encrypt("Hello", "", "hex").is_err());
            assert!(rc4::decrypt("deadbeef", "", "base64").is_err());
            assert!(rc4::decrypt("deadbeef", "", "hex").is_err());
        }

        #[test]
        fn test_different_keys() {
            let text = "Secret Message";
            let encrypted1 = rc4::encrypt(text, "key1", "base64").unwrap();
            let encrypted2 = rc4::encrypt(text, "key2", "base64").unwrap();
            assert_ne!(encrypted1, encrypted2);
        }

        #[test]
        fn test_unicode_text() {
            let original = "Hello 世界! 🔐";
            let key = "unicode_key";
            let encrypted = rc4::encrypt(original, key, "base64").unwrap();
            let decrypted = rc4::decrypt(&encrypted, key, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_long_text() {
            let original = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(100);
            let key = "long_test_key";
            let encrypted = rc4::encrypt(&original, key, "base64").unwrap();
            let decrypted = rc4::decrypt(&encrypted, key, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_special_characters() {
            let original = "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./~`";
            let key = "special";
            let encrypted = rc4::encrypt(original, key, "base64").unwrap();
            let decrypted = rc4::decrypt(&encrypted, key, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_repeated_calls() {
            let text = "Consistency Test";
            let key = "test_key";
            let encrypted1 = rc4::encrypt(text, key, "base64").unwrap();
            let encrypted2 = rc4::encrypt(text, key, "base64").unwrap();
            assert_eq!(encrypted1, encrypted2);
        }

        #[test]
        fn test_variable_key_lengths() {
            let text = "Test with different key lengths";
            
            // Test various key lengths
            let keys = ["a", "ab", "abc", "abcdefghijklmnop", "very_long_key_for_testing_purposes"];
            
            for key in &keys {
                let encrypted = rc4::encrypt(text, key, "base64").unwrap();
                let decrypted = rc4::decrypt(&encrypted, key, "base64").unwrap();
                assert_eq!(decrypted, text, "Failed with key: {}", key);
            }
        }
    }
}
