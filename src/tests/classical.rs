#[cfg(test)]
mod tests {

    #[cfg(test)]
    mod caesar_tests {
        use crate::classical::caesar;

        #[test]
        fn test_encrypt_basic() {
            assert_eq!(caesar::encrypt("HELLO", 3).unwrap(), "KHOOR");
            assert_eq!(caesar::encrypt("hello", 3).unwrap(), "khoor");
        }

        #[test]
        fn test_decrypt_basic() {
            assert_eq!(caesar::decrypt("KHOOR", 3).unwrap(), "HELLO");
            assert_eq!(caesar::decrypt("khoor", 3).unwrap(), "hello");
        }

        #[test]
        fn test_wrap_around() {
            assert_eq!(caesar::encrypt("XYZ", 3).unwrap(), "ABC");
            assert_eq!(caesar::decrypt("ABC", 3).unwrap(), "XYZ");
        }

        #[test]
        fn test_non_alphabetic() {
            assert_eq!(caesar::encrypt("HELLO, WORLD!", 3).unwrap(), "KHOOR, ZRUOG!");
            assert_eq!(caesar::decrypt("KHOOR, ZRUOG!", 3).unwrap(), "HELLO, WORLD!");
        }

        #[test]
        fn test_round_trip() {
            let original = "The Quick Brown Fox Jumps Over The Lazy Dog!";
            let encrypted = caesar::encrypt(original, 13).unwrap();
            let decrypted = caesar::decrypt(&encrypted, 13).unwrap();
            assert_eq!(original, decrypted);
        }
    }

    #[cfg(test)]
    mod rail_fence_tests {
        use crate::classical::rail_fence;

        #[test]
        fn test_encrypt_basic() {
            assert_eq!(rail_fence::encrypt("HELLO", 2).unwrap(), "HLOEL");
            assert_eq!(rail_fence::encrypt("WEAREDISCOVEREDFLEEATONCE", 3).unwrap(), "WECRLTEERDSOEEFEAOCAIVDEN");
        }

        #[test]
        fn test_decrypt_basic() {
            assert_eq!(rail_fence::decrypt("HLOEL", 2).unwrap(), "HELLO");
            assert_eq!(rail_fence::decrypt("WECRLTEERDSOEEFEAOCAIVDEN", 3).unwrap(), "WEAREDISCOVEREDFLEEATONCE");
        }

        #[test]
        fn test_round_trip() {
            let original = "ATTACKATDAWN";
            let encrypted = rail_fence::encrypt(original, 3).unwrap();
            let decrypted = rail_fence::decrypt(&encrypted, 3).unwrap();
            assert_eq!(original, decrypted);
        }

        #[test]
        fn test_single_rail() {
            assert_eq!(rail_fence::encrypt("HELLO", 1).unwrap(), "HELLO");
            assert_eq!(rail_fence::decrypt("HELLO", 1).unwrap(), "HELLO");
        }
    }
}