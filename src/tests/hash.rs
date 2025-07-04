#[cfg(test)]
mod tests {

    #[cfg(test)]
    mod md5_tests {
        use crate::hash::md5;

        #[test]
        fn test_empty_string() {
            assert_eq!(md5::hash("").unwrap(), "d41d8cd98f00b204e9800998ecf8427e");
        }

        #[test]
        fn test_single_character() {
            assert_eq!(md5::hash("a").unwrap(), "0cc175b9c0f1b6a831c399e269772661");
        }

        #[test]
        fn test_abc() {
            assert_eq!(
                md5::hash("abc").unwrap(),
                "900150983cd24fb0d6963f7d28e17f72"
            );
        }

        #[test]
        fn test_hello_world() {
            assert_eq!(
                md5::hash("hello world").unwrap(),
                "5eb63bbbe01eeed093cb22bb8f5acdc3"
            );
        }

        #[test]
        fn test_longer_message() {
            assert_eq!(
                md5::hash("The quick brown fox jumps over the lazy dog").unwrap(),
                "9e107d9d372bb6826bd81d3542a419d6"
            );
        }

        #[test]
        fn test_unicode() {
            assert_eq!(
                md5::hash("Hello, 世界").unwrap(),
                "3dbca55819ed79f62e6f770eef640eee"
            );
        }

        #[test]
        fn test_numbers() {
            assert_eq!(
                md5::hash("123456789").unwrap(),
                "25f9e794323b453885f5181f1b624d0b"
            );
        }

        #[test]
        fn test_special_characters() {
            assert_eq!(
                md5::hash("!@#$%^&*()").unwrap(),
                "05b28d17a7b6e7024b6e5d8cc43a8bf7"
            );
        }

        #[test]
        fn test_repeated_calls() {
            let input = "test message";
            let hash1 = md5::hash(input).unwrap();
            let hash2 = md5::hash(input).unwrap();
            assert_eq!(hash1, hash2);
        }

        #[test]
        fn test_case_sensitivity() {
            let hash_lower = md5::hash("hello").unwrap();
            let hash_upper = md5::hash("HELLO").unwrap();
            assert_ne!(hash_lower, hash_upper);
        }
    }

    #[cfg(test)]
    mod sha1_tests {
        use crate::hash::sha1;

        #[test]
        fn test_empty_string() {
            assert_eq!(
                sha1::hash("").unwrap(),
                "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            );
        }

        #[test]
        fn test_single_character() {
            assert_eq!(
                sha1::hash("a").unwrap(),
                "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"
            );
        }

        #[test]
        fn test_abc() {
            assert_eq!(
                sha1::hash("abc").unwrap(),
                "a9993e364706816aba3e25717850c26c9cd0d89d"
            );
        }

        #[test]
        fn test_hello_world() {
            assert_eq!(
                sha1::hash("hello world").unwrap(),
                "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
            );
        }

        #[test]
        fn test_longer_message() {
            assert_eq!(
                sha1::hash("The quick brown fox jumps over the lazy dog").unwrap(),
                "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
            );
        }

        #[test]
        fn test_unicode() {
            assert_eq!(
                sha1::hash("Hello, 世界").unwrap(),
                "ec105952aaab47ed409894bea51b26b641361df7"
            );
        }

        #[test]
        fn test_numbers() {
            assert_eq!(
                sha1::hash("123456789").unwrap(),
                "f7c3bc1d808e04732adf679965ccc34ca7ae3441"
            );
        }

        #[test]
        fn test_special_characters() {
            assert_eq!(
                sha1::hash("!@#$%^&*()").unwrap(),
                "bf24d65c9bb05b9b814a966940bcfa50767c8a8d"
            );
        }

        #[test]
        fn test_repeated_calls() {
            let input = "test message";
            let hash1 = sha1::hash(input).unwrap();
            let hash2 = sha1::hash(input).unwrap();
            assert_eq!(hash1, hash2);
        }

        #[test]
        fn test_case_sensitivity() {
            let hash_lower = sha1::hash("hello").unwrap();
            let hash_upper = sha1::hash("HELLO").unwrap();
            assert_ne!(hash_lower, hash_upper);
        }
    }

    #[cfg(test)]
    mod sha256_tests {
        use crate::hash::sha256;

        #[test]
        fn test_empty_string() {
            assert_eq!(
                sha256::hash("").unwrap(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
        }

        #[test]
        fn test_single_character() {
            assert_eq!(
                sha256::hash("a").unwrap(),
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
            );
        }

        #[test]
        fn test_abc() {
            assert_eq!(
                sha256::hash("abc").unwrap(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }

        #[test]
        fn test_hello_world() {
            assert_eq!(
                sha256::hash("hello world").unwrap(),
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            );
        }

        #[test]
        fn test_longer_message() {
            assert_eq!(
                sha256::hash("The quick brown fox jumps over the lazy dog").unwrap(),
                "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
            );
        }

        #[test]
        fn test_unicode() {
            assert_eq!(
                sha256::hash("Hello, 世界").unwrap(),
                "a281e84c7f61393db702630c2a6807e871cd3b6896c9e56e22982d125696575c"
            );
        }

        #[test]
        fn test_numbers() {
            assert_eq!(
                sha256::hash("123456789").unwrap(),
                "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"
            );
        }

        #[test]
        fn test_special_characters() {
            assert_eq!(
                sha256::hash("!@#$%^&*()").unwrap(),
                "95ce789c5c9d18490972709838ca3a9719094bca3ac16332cfec0652b0236141"
            );
        }

        #[test]
        fn test_repeated_calls() {
            let input = "test message";
            let hash1 = sha256::hash(input).unwrap();
            let hash2 = sha256::hash(input).unwrap();
            assert_eq!(hash1, hash2);
        }

        #[test]
        fn test_case_sensitivity() {
            let hash_lower = sha256::hash("hello").unwrap();
            let hash_upper = sha256::hash("HELLO").unwrap();
            assert_ne!(hash_lower, hash_upper);
        }

        #[test]
        fn test_million_a() {
            // Test with a longer input
            let input = "a".repeat(1000000);
            let result = sha256::hash(&input).unwrap();
            assert_eq!(result.len(), 64); // SHA-256 always produces 64 hex characters
        }
    }
}
