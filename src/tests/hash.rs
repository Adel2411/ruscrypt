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
}
