# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-06-27

### Added
- New `keygen` subcommand: `ruscrypt keygen --rsa` for generating RSA key pairs.
- RSA encryption and decryption now accept PEM key format in addition to "n:d".
- Added multi-line input support in `interactive.rs` for pasting PEM keys and similar data.

## [0.1.2] - 2025-06-27

### Changed
- Removed banner print for normal commands (banner now only prints for help/version)
- Removed parsed arguments print from CLI output
- Updated README.md with latest usage, screenshot and documentation

## [0.1.1] - 2025-06-27

### Changed
- Updated README.md with improved documentation and formatting
- Enhanced examples folder with better code examples and demonstrations
- Improved code structure and comments in example files

### Documentation
- Better explanation of security considerations
- Enhanced quick start guide
- Improved algorithm descriptions and usage examples

## [0.1.0] - 2025-06-27

### Added
- Initial release of RusCrypt
- Classical ciphers: Caesar, Vigenère, Playfair, Rail Fence
- Stream cipher: RC4
- Block ciphers: AES (128/192/256-bit), DES
- Asymmetric encryption: RSA, Diffie-Hellman key exchange
- Hash functions: MD5, SHA-1, SHA-256
- Interactive CLI interface
- Library API for programmatic use
- Comprehensive test suite
- Documentation and examples
- Both base64 and hexadecimal output encoding
- Multiple encryption modes (ECB, CBC) for block ciphers

### Security
- All algorithms implemented from scratch for educational purposes
- Security warnings for deprecated algorithms (MD5, SHA-1, DES, RC4)
- Memory-safe implementations using Rust

[0.2.0]: https://github.com/Adel2411/ruscrypt/releases/tag/v0.2.0
[0.1.2]: https://github.com/Adel2411/ruscrypt/releases/tag/v0.1.2
[0.1.1]: https://github.com/Adel2411/ruscrypt/releases/tag/v0.1.1
[0.1.0]: https://github.com/Adel2411/ruscrypt/releases/tag/v0.1.0
