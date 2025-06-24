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
            assert_eq!(md5::hash("abc").unwrap(), "900150983cd24fb0d6963f7d28e17f72");
        }

        #[test]
        fn test_hello_world() {
            assert_eq!(md5::hash("hello world").unwrap(), "5eb63bbbe01eeed093cb22bb8f5acdc3");
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
            assert_eq!(md5::hash("Hello, 世界").unwrap(), "3dbca55819ed79f62e6f770eef640eee");
        }

        #[test]
        fn test_numbers() {
            assert_eq!(md5::hash("123456789").unwrap(), "25f9e794323b453885f5181f1b624d0b");
        }

        #[test]
        fn test_special_characters() {
            assert_eq!(md5::hash("!@#$%^&*()").unwrap(), "05b28d17a7b6e7024b6e5d8cc43a8bf7");
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
            assert_eq!(sha1::hash("").unwrap(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        }

        #[test]
        fn test_single_character() {
            assert_eq!(sha1::hash("a").unwrap(), "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
        }

        #[test]
        fn test_abc() {
            assert_eq!(sha1::hash("abc").unwrap(), "a9993e364706816aba3e25717850c26c9cd0d89d");
        }

        #[test]
        fn test_hello_world() {
            assert_eq!(sha1::hash("hello world").unwrap(), "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
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
            assert_eq!(sha1::hash("Hello, 世界").unwrap(), "ec105952aaab47ed409894bea51b26b641361df7");
        }

        #[test]
        fn test_numbers() {
            assert_eq!(sha1::hash("123456789").unwrap(), "f7c3bc1d808e04732adf679965ccc34ca7ae3441");
        }

        #[test]
        fn test_special_characters() {
            assert_eq!(sha1::hash("!@#$%^&*()").unwrap(), "bf24d65c9bb05b9b814a966940bcfa50767c8a8d");
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
}
