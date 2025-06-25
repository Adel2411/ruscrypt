#[cfg(test)]
mod tests {

    #[cfg(test)]
    mod des_tests {
        use crate::block::des;

        #[test]
        fn test_encrypt_basic_base64() {
            let result = des::encrypt("Hello", "12345678", "base64").unwrap();
            // Should be valid base64 string
            assert!(crate::utils::from_base64(&result).is_ok());
        }

        #[test]
        fn test_encrypt_basic_hex() {
            let result = des::encrypt("Hello", "12345678", "hex").unwrap();
            // Should be hex string
            assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(result.len() % 2, 0); // Even length for hex
        }

        #[test]
        fn test_decrypt_basic_base64() {
            let original = "Hello World";
            let key = "password";
            let encrypted = des::encrypt(original, key, "base64").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_decrypt_basic_hex() {
            let original = "Hello World";
            let key = "testkey1";
            let encrypted = des::encrypt(original, key, "hex").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "hex").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_round_trip_both_encodings() {
            let original = "The Quick Brown Fox Jumps Over The Lazy Dog!";
            let key = "secret12";
            
            // Test base64
            let encrypted_b64 = des::encrypt(original, key, "base64").unwrap();
            let decrypted_b64 = des::decrypt(&encrypted_b64, key, "base64").unwrap();
            assert_eq!(decrypted_b64, original);
            
            // Test hex
            let encrypted_hex = des::encrypt(original, key, "hex").unwrap();
            let decrypted_hex = des::decrypt(&encrypted_hex, key, "hex").unwrap();
            assert_eq!(decrypted_hex, original);
        }

        #[test]
        fn test_invalid_key_length() {
            // Too short
            assert!(des::encrypt("Hello", "short", "base64").is_err());
            assert!(des::decrypt("data", "short", "base64").is_err());
            
            // Too long
            assert!(des::encrypt("Hello", "toolongkey", "base64").is_err());
            assert!(des::decrypt("data", "toolongkey", "base64").is_err());
            
            // Empty
            assert!(des::encrypt("Hello", "", "base64").is_err());
            assert!(des::decrypt("data", "", "base64").is_err());
        }

        #[test]
        fn test_valid_key_length() {
            let key = "exactly8"; // Exactly 8 characters
            let original = "Test message";
            
            let encrypted = des::encrypt(original, key, "base64").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_invalid_encoding() {
            assert!(des::encrypt("Hello", "12345678", "invalid").is_err());
            assert!(des::decrypt("deadbeef", "12345678", "invalid").is_err());
        }

        #[test]
        fn test_empty_string_both_encodings() {
            let key = "testkey1";
            
            let encrypted_b64 = des::encrypt("", key, "base64").unwrap();
            let decrypted_b64 = des::decrypt(&encrypted_b64, key, "base64").unwrap();
            assert_eq!(decrypted_b64, "");
            
            let encrypted_hex = des::encrypt("", key, "hex").unwrap();
            let decrypted_hex = des::decrypt(&encrypted_hex, key, "hex").unwrap();
            assert_eq!(decrypted_hex, "");
        }

        #[test]
        fn test_different_keys() {
            let text = "Secret Message";
            let encrypted1 = des::encrypt(text, "key12345", "base64").unwrap();
            let encrypted2 = des::encrypt(text, "key54321", "base64").unwrap();
            assert_ne!(encrypted1, encrypted2);
        }

        #[test]
        fn test_unicode_text() {
            let original = "Hello 世界! 🔐";
            let key = "unicode1";
            let encrypted = des::encrypt(original, key, "base64").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_long_text() {
            let original = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(10);
            let key = "longtext";
            let encrypted = des::encrypt(&original, key, "base64").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_special_characters() {
            let original = "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./~`";
            let key = "special1";
            let encrypted = des::encrypt(original, key, "base64").unwrap();
            let decrypted = des::decrypt(&encrypted, key, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_hex_output_format() {
            let encrypted = des::encrypt("test", "hextest1", "hex").unwrap();
            // Should be even length (each byte = 2 hex chars)
            assert_eq!(encrypted.len() % 2, 0);
            // Should only contain hex characters
            assert!(encrypted.chars().all(|c| "0123456789abcdef".contains(c)));
        }

        #[test]
        fn test_base64_output_format() {
            let encrypted = des::encrypt("test", "b64test1", "base64").unwrap();
            // Should be valid base64
            assert!(crate::utils::from_base64(&encrypted).is_ok());
            // Should only contain base64 characters
            assert!(encrypted.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='));
        }

        #[test]
        fn test_invalid_hex_input() {
            // Test decryption with invalid hex
            assert!(des::decrypt("invalid_hex", "testkey1", "hex").is_err());
            assert!(des::decrypt("zz", "testkey1", "hex").is_err());
            assert!(des::decrypt("a", "testkey1", "hex").is_err()); // Odd length
        }

        #[test]
        fn test_invalid_base64_input() {
            // Test decryption with invalid base64
            assert!(des::decrypt("invalid_base64!", "testkey1", "base64").is_err());
            assert!(des::decrypt("@#$%", "testkey1", "base64").is_err());
        }

        #[test]
        fn test_case_sensitivity() {
            let text = "Test Message";
            let encrypted1 = des::encrypt(text, "Key12345", "base64").unwrap();
            let encrypted2 = des::encrypt(text, "key12345", "base64").unwrap();
            assert_ne!(encrypted1, encrypted2);
        }

        #[test]
        fn test_repeated_calls() {
            let text = "Consistency Test";
            let key = "testkey1";
            let encrypted1 = des::encrypt(text, key, "base64").unwrap();
            let encrypted2 = des::encrypt(text, key, "base64").unwrap();
            assert_eq!(encrypted1, encrypted2);
        }

        #[test]
        fn test_block_size_padding() {
            // Test various input lengths to verify padding works correctly
            let key = "padtest1";
            
            for length in 1..=20 {
                let input = "a".repeat(length);
                let encrypted = des::encrypt(&input, key, "base64").unwrap();
                let decrypted = des::decrypt(&encrypted, key, "base64").unwrap();
                assert_eq!(decrypted, input, "Failed at length: {}", length);
            }
        }

        #[test]
        fn test_cross_encoding_compatibility() {
            // Encrypt with one encoding, manually convert, decrypt with other
            let original = "Cross encoding test";
            let key = "crosskey";
            
            let encrypted_hex = des::encrypt(original, key, "hex").unwrap();
            let encrypted_b64 = des::encrypt(original, key, "base64").unwrap();
            
            // Both should decrypt to same result
            let decrypted_from_hex = des::decrypt(&encrypted_hex, key, "hex").unwrap();
            let decrypted_from_b64 = des::decrypt(&encrypted_b64, key, "base64").unwrap();
            
            assert_eq!(decrypted_from_hex, original);
            assert_eq!(decrypted_from_b64, original);
            assert_eq!(decrypted_from_hex, decrypted_from_b64);
        }

        #[test]
        fn test_invalid_encrypted_data_length() {
            let key = "testkey1";
            
            // Test with data that's not a multiple of block size when decoded
            let invalid_hex = "deadbe"; // Not multiple of 16 hex chars (8 bytes)
            assert!(des::decrypt(invalid_hex, key, "hex").is_err());
        }
    }

    #[cfg(test)]
    mod aes_tests {
        use crate::block::aes;

        #[test]
        fn test_encrypt_basic_base64() {
            let result = aes::encrypt("Hello", "password", "base64").unwrap();
            // Should be valid base64 string
            assert!(crate::utils::from_base64(&result).is_ok());
        }

        #[test]
        fn test_encrypt_basic_hex() {
            let result = aes::encrypt("Hello", "password", "hex").unwrap();
            // Should be hex string
            assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(result.len() % 2, 0); // Even length for hex
        }

        #[test]
        fn test_decrypt_basic_base64() {
            let original = "Hello World";
            let password = "testpassword";
            let encrypted = aes::encrypt(original, password, "base64").unwrap();
            let decrypted = aes::decrypt(&encrypted, password, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_round_trip_both_encodings() {
            let original = "The Quick Brown Fox Jumps Over The Lazy Dog!";
            let password = "securepassword123";
            
            // Test base64
            let encrypted_b64 = aes::encrypt(original, password, "base64").unwrap();
            let decrypted_b64 = aes::decrypt(&encrypted_b64, password, "base64").unwrap();
            assert_eq!(decrypted_b64, original);
            
            // Test hex
            let encrypted_hex = aes::encrypt(original, password, "hex").unwrap();
            let decrypted_hex = aes::decrypt(&encrypted_hex, password, "hex").unwrap();
            assert_eq!(decrypted_hex, original);
        }

        #[test]
        fn test_empty_password() {
            assert!(aes::encrypt("Hello", "", "base64").is_err());
            assert!(aes::decrypt("data", "", "base64").is_err());
        }

        #[test]
        fn test_different_passwords() {
            let text = "Secret Message";
            let encrypted1 = aes::encrypt(text, "password1", "base64").unwrap();
            let encrypted2 = aes::encrypt(text, "password2", "base64").unwrap();
            assert_ne!(encrypted1, encrypted2);
        }

        #[test]
        fn test_unicode_text() {
            let original = "Hello 世界! 🔐";
            let password = "unicode_password";
            let encrypted = aes::encrypt(original, password, "base64").unwrap();
            let decrypted = aes::decrypt(&encrypted, password, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_long_text() {
            let original = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(20);
            let password = "longtext_password";
            let encrypted = aes::encrypt(&original, password, "base64").unwrap();
            let decrypted = aes::decrypt(&encrypted, password, "base64").unwrap();
            assert_eq!(decrypted, original);
        }

        #[test]
        fn test_empty_string() {
            let password = "testpassword";
            let encrypted = aes::encrypt("", password, "base64").unwrap();
            let decrypted = aes::decrypt(&encrypted, password, "base64").unwrap();
            assert_eq!(decrypted, "");
        }

        #[test]
        fn test_invalid_encoding() {
            assert!(aes::encrypt("Hello", "password", "invalid").is_err());
            assert!(aes::decrypt("data", "password", "invalid").is_err());
        }
    }
}
