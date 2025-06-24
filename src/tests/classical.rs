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

    // #[cfg(test)]
    // mod vigenere_tests {
    //     use crate::classical::vigenere;

    //     #[test]
    //     fn test_encrypt_basic() {
    //         // Add vigenere tests when module is implemented
    //     }

    //     #[test]
    //     fn test_decrypt_basic() {
    //         // Add vigenere tests when module is implemented
    //     }
    // }

    // #[cfg(test)]
    // mod playfair_tests {
    //     use crate::classical::playfair;

    //     #[test]
    //     fn test_encrypt_basic() {
    //         // Add playfair tests when module is implemented
    //     }

    //     #[test]
    //     fn test_decrypt_basic() {
    //         // Add playfair tests when module is implemented
    //     }
    // }

    // #[cfg(test)]
    // mod rail_fence_tests {
    //     use crate::classical::rail_fence;

    //     #[test]
    //     fn test_encrypt_basic() {
    //         // Add rail fence tests when module is implemented
    //     }

    //     #[test]
    //     fn test_decrypt_basic() {
    //         // Add rail fence tests when module is implemented
    //     }
    // }
}