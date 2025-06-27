# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/Adel2411/ruscrypt/releases/tag/v0.1.0
