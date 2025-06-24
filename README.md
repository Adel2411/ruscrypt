<div align="center">
  <img src="https://cdn.pixabay.com/photo/2019/10/06/11/40/lock-4529981_1280.png" alt="ruscrypt logo" width="200" height="200">

# RusCrypt

### _⚡ Lightning-fast cryptography toolkit built with Rust ⚡_

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge)](https://github.com/Adel2411/ruscrypt)
[![Version](https://img.shields.io/badge/version-0.1.0-blue?style=for-the-badge)](https://github.com/Adel2411/ruscrypt)

**Modern cryptographic operations made simple and blazingly fast**

[📖 Documentation](#-documentation) • [🚀 Quick Start](#-quick-start) • [💡 Examples](#-examples) • [🤝 Contributing](#-contributing)

</div>

---

## 📑 Table of Contents

- [🎯 Overview](#-overview)
- [✨ Features](#-features)
- [📦 Installation](#-installation)
- [🚀 Quick Start](#-quick-start)
- [📖 Documentation](#-documentation)
- [💡 Examples](#-examples)
- [🧪 Testing](#-testing)
- [🔒 Security](#-security)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🎯 Overview

**ruscrypt** is a powerful command-line cryptography toolkit that brings together classical and modern cryptographic algorithms in one unified interface. Built with Rust for **maximum performance**, **memory safety**, and **security**.

> 🎓 **Perfect for**: Learning cryptography, educational purposes, quick encryption tasks, and understanding algorithm implementations.

### Why ruscrypt?

| Feature             | Description                                              |
| ------------------- | -------------------------------------------------------- |
| ⚡ **Blazing Fast** | Rust's zero-cost abstractions ensure optimal performance |
| 🔒 **Memory Safe**  | No buffer overflows or memory leaks                      |
| 🎯 **Simple API**   | One command format for all algorithms                    |
| 📚 **Educational**  | Clean implementations perfect for learning               |
| 🔧 **Interactive**  | Guided prompts for all required parameters               |

---

## ✨ Features

<div align="center">

| 🏛️ **Classical Ciphers** | 🔐 **Stream & Block Ciphers** | 🔑 **Asymmetric Encryption** | 🔢 **Hash Functions** |
| :----------------------: | :---------------------------: | :--------------------------: | :-------------------: |
|      Caesar Cipher       |              RC4              |             RSA              |          MD5          |
|     Vigenère Cipher      |              AES              |        Diffie-Hellman        |         SHA-1         |
|     Playfair Cipher      |              DES              |              -               |        SHA-256        |
|    Rail Fence Cipher     |               -               |              -               |           -           |

</div>

---

## 🏗️ Project Structure

```
ruscrypt/
├── Cargo.toml                  # Project manifest
├── README.md                   # Documentation
├── LICENSE                     # MIT license
├── src/
│   ├── main.rs                 # Entry point
│   ├── cli.rs                  # CLI parsing
│   ├── dispatcher.rs           # Command routing
│   ├── interactive.rs          # User prompts
│   ├── utils.rs                # Shared utilities
│   │
│   ├── classical/              # Classical ciphers
│   │   ├── mod.rs
│   │   ├── caesar.rs
│   │   ├── vigenere.rs
│   │   ├── playfair.rs
│   │   └── rail_fence.rs
│   │
│   ├── stream/                 # Stream ciphers
│   │   ├── mod.rs
│   │   └── rc4.rs
│   │
│   ├── block/                  # Block ciphers
│   │   ├── mod.rs
│   │   ├── aes.rs
│   │   └── des.rs
│   │
│   ├── asym/                   # Asymmetric crypto
│   │   ├── mod.rs
│   │   ├── rsa.rs
│   │   └── diffie_hellman.rs
│   │
│   ├── hash/                   # Hash functions
│   │   ├── mod.rs
│   │   ├── md5.rs
│   │   ├── sha1.rs
│   │   └── sha256.rs
│   │
│   └── tests/                  # Test modules
│       ├── mod.rs
│       └── integration.rs
│
└── examples/                   # Usage examples
    ├── demo.rs
    └── quick_start.rs
```

---

## 📦 Installation

### Prerequisites

- **Rust**: 1.70.0 or higher
- **Git**: For cloning the repository

### Build from Source

```bash
# 📥 Clone the repository
git clone https://github.com/Adel2411/ruscrypt.git
cd ruscrypt

# 🔨 Build in release mode for optimal performance
cargo build --release

# 🎯 Binary will be available at
./target/release/ruscrypt
```

---

## 🚀 Quick Start

### Command Format

```bash
# For encryption and decryption
ruscrypt <encrypt|decrypt> --<algorithm>

# For hashing operations
ruscrypt hash --<algorithm>
```

### Interactive Experience

All operations are **interactive** - the tool will prompt you for required inputs:

```bash
# Example: Caesar cipher encryption
$ ruscrypt encrypt --caesar
Enter text to encrypt: Hello World
Enter shift value (1-25): 3
Encrypted text: Khoor Zruog

# Example: AES encryption
$ ruscrypt encrypt --aes
Enter text to encrypt: Secret message
Enter password: ********
Encrypted text: [base64 encoded result]

# Example: SHA-256 hashing
$ ruscrypt hash --sha256
Enter text to hash: password123
Hash: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

---

## 📖 Documentation

### Algorithm Reference

#### 🏛️ Classical Ciphers

<details>
<summary><strong>Caesar Cipher</strong> - Simple substitution cipher</summary>

```bash
# Encrypt
ruscrypt encrypt --caesar
# Prompts:
# - Text to encrypt
# - Shift value (1-25)

# Decrypt
ruscrypt decrypt --caesar
# Prompts:
# - Text to decrypt
# - Shift value (1-25)
```

**How it works**: Each letter is shifted by a fixed number of positions in the alphabet.

</details>

<details>
<summary><strong>Vigenère Cipher</strong> - Polyalphabetic substitution</summary>

```bash
# Encrypt
ruscrypt encrypt --vigenere
# Prompts:
# - Text to encrypt
# - Keyword

# Decrypt
ruscrypt decrypt --vigenere
# Prompts:
# - Text to decrypt
# - Keyword
```

**How it works**: Uses a keyword to shift letters by varying amounts.

</details>

<details>
<summary><strong>Playfair Cipher</strong> - Digraph substitution</summary>

```bash
# Encrypt
ruscrypt encrypt --playfair
# Prompts:
# - Text to encrypt
# - Keyword for matrix

# Decrypt
ruscrypt decrypt --playfair
# Prompts:
# - Text to decrypt
# - Keyword for matrix
```

**How it works**: Encrypts pairs of letters using a 5x5 key matrix.

</details>

<details>
<summary><strong>Rail Fence Cipher</strong> - Transposition cipher</summary>

```bash
# Encrypt
ruscrypt encrypt --railfence
# Prompts:
# - Text to encrypt
# - Number of rails (2-10)

# Decrypt
ruscrypt decrypt --railfence
# Prompts:
# - Text to decrypt
# - Number of rails (2-10)
```

**How it works**: Text is written in a zigzag pattern across multiple rails.

</details>

#### 🔐 Stream & Block Ciphers

<details>
<summary><strong>RC4</strong> - Stream cipher</summary>

```bash
# Encrypt
ruscrypt encrypt --rc4
# Prompts:
# - Text to encrypt
# - Key (variable length)

# Decrypt
ruscrypt decrypt --rc4
# Prompts:
# - Text to decrypt
# - Key (same as encryption)
```

**Note**: Legacy algorithm, use for educational purposes only.

</details>

<details>
<summary><strong>AES</strong> - Advanced Encryption Standard</summary>

```bash
# Encrypt
ruscrypt encrypt --aes
# Prompts:
# - Text to encrypt
# - Password

# Decrypt
ruscrypt decrypt --aes
# Prompts:
# - Text to decrypt
# - Password (same as encryption)
```

**Security**: Industry-standard symmetric encryption.

</details>

<details>
<summary><strong>DES</strong> - Data Encryption Standard</summary>

```bash
# Encrypt
ruscrypt encrypt --des
# Prompts:
# - Text to encrypt
# - Key (8 characters)

# Decrypt
ruscrypt decrypt --des
# Prompts:
# - Text to decrypt
# - Key (same as encryption)
```

**Note**: Legacy algorithm, use for educational purposes only.

</details>

#### 🔑 Asymmetric Encryption

<details>
<summary><strong>RSA</strong> - Rivest-Shamir-Adleman</summary>

```bash
# Encrypt
ruscrypt encrypt --rsa
# Prompts:
# - Text to encrypt
# - Key size (1024, 2048, 4096)
# Tool generates key pair automatically

# Decrypt
ruscrypt decrypt --rsa
# Prompts:
# - Text to decrypt
# - Private key (from encryption step)
```

**Use case**: Small data encryption and digital signatures.

</details>

<details>
<summary><strong>Diffie-Hellman</strong> - Key Exchange</summary>

```bash
# Key exchange simulation
ruscrypt encrypt --dh
# Interactive key exchange process:
# - Generates private key
# - Shows public key
# - Prompts for other party's public key
# - Computes shared secret
```

**Use case**: Secure key exchange demonstration.

</details>

#### 🔢 Hash Functions

<details>
<summary><strong>MD5</strong> - Message Digest 5</summary>

```bash
ruscrypt hash --md5
# Prompts:
# - Text to hash
# Output: 32-character hexadecimal hash
```

**Note**: Cryptographically broken, use only for compatibility.

</details>

<details>
<summary><strong>SHA-1</strong> - Secure Hash Algorithm 1</summary>

```bash
ruscrypt hash --sha1
# Prompts:
# - Text to hash
# Output: 40-character hexadecimal hash
```

**Note**: Deprecated, use only for legacy compatibility.

</details>

<details>
<summary><strong>SHA-256</strong> - Secure Hash Algorithm 256</summary>

```bash
ruscrypt hash --sha256
# Prompts:
# - Text to hash
# Output: 64-character hexadecimal hash
```

**Recommended**: Use for all new applications requiring hashing.

</details>

---

## 💡 Examples

### Interactive Session Examples

```bash
# 🎯 Classical cipher example
$ ruscrypt encrypt --caesar
Enter text to encrypt: HELLO WORLD
Enter shift value (1-25): 5
Encrypted text: MJQQT BTWQI

$ ruscrypt decrypt --caesar
Enter text to decrypt: MJQQT BTWQI
Enter shift value (1-25): 5
Decrypted text: HELLO WORLD
```

```bash
# 🔐 Modern encryption example
$ ruscrypt encrypt --aes
Enter text to encrypt: This is a secret message
Enter password: mySecurePassword123
Encrypted text: U2FsdGVkX1+vupppZksvRf5pq5g5XjFRlipRkwB0K1Y96Qsv2Lm+31cmzaAILwyt

$ ruscrypt decrypt --aes
Enter text to decrypt: U2FsdGVkX1+vupppZksvRf5pq5g5XjFRlipRkwB0K1Y96Qsv2Lm+31cmzaAILwyt
Enter password: mySecurePassword123
Decrypted text: This is a secret message
```

```bash
# 🔢 Hash function example
$ ruscrypt hash --sha256
Enter text to hash: password123
Hash: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f

$ ruscrypt hash --md5
Enter text to hash: hello world
Hash: 5d41402abc4b2a76b9719d911017c592
```

### Algorithm Comparison

```bash
# Compare different cipher types with the same input
$ ruscrypt encrypt --caesar
Enter text to encrypt: CRYPTOGRAPHY
Enter shift value (1-25): 3
Encrypted text: FUBSWRJUDSKB

$ ruscrypt encrypt --vigenere
Enter text to encrypt: CRYPTOGRAPHY
Enter keyword: SECRET
Encrypted text: UKWPVQJRAPLI

$ ruscrypt encrypt --aes
Enter text to encrypt: CRYPTOGRAPHY
Enter password: testkey
Encrypted text: [encrypted base64 string]

$ ruscrypt hash --sha256
Enter text to hash: CRYPTOGRAPHY
Hash: 7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730
```

---

## 🧪 Testing

### Run Test Suite

```bash
# 🧪 Run all tests
cargo test

# 📊 Run with detailed output
cargo test -- --nocapture

# ⚡ Run specific algorithm tests
cargo test classical
cargo test modern
cargo test hash
```

### Manual Testing

Test each algorithm interactively:

```bash
# Test classical ciphers
ruscrypt encrypt --caesar
ruscrypt encrypt --vigenere
ruscrypt encrypt --playfair
ruscrypt encrypt --railfence

# Test stream & block ciphers
ruscrypt encrypt --rc4
ruscrypt encrypt --aes
ruscrypt encrypt --des

# Test asymmetric encryption
ruscrypt encrypt --rsa
ruscrypt encrypt --dh

# Test hash functions
ruscrypt hash --md5
ruscrypt hash --sha1
ruscrypt hash --sha256
```

---

## 🔒 Security

### ⚠️ Important Security Considerations

| ⚠️ **Warning**           | **Description**                                                  |
| ------------------------ | ---------------------------------------------------------------- |
| 🎓 **Educational Use**   | This tool is designed for learning and experimentation           |
| 🚫 **Legacy Algorithms** | RC4, DES, MD5, and SHA-1 are **NOT secure** for modern use       |
| 🚫 **Classical Ciphers** | All classical ciphers are **NOT secure** for real-world use      |
| 🔑 **Interactive Input** | Passwords are entered visibly - use only for testing             |
| 🏭 **Production Use**    | Use AES and RSA with proper key management for real applications |

### 🛡️ Recommended Algorithms

```bash
# ✅ Secure for modern use
ruscrypt encrypt --aes      # Symmetric encryption
ruscrypt encrypt --rsa      # Asymmetric encryption
ruscrypt hash --sha256      # Cryptographic hashing

# ❌ Educational/legacy only
ruscrypt encrypt --caesar   # Easily broken
ruscrypt encrypt --des      # 56-bit key, deprecated
ruscrypt encrypt --rc4      # Known vulnerabilities
ruscrypt hash --md5         # Collision attacks possible
ruscrypt hash --sha1        # Deprecated by NIST
```

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### 🚀 Quick Contribution Guide

1. **🍴 Fork** the repository
2. **🌿 Create** a feature branch:
   ```bash
   git checkout -b feature/new-algorithm
   ```
3. **✨ Make** your changes
4. **🧪 Test** thoroughly:
   ```bash
   cargo test
   cargo clippy
   cargo fmt
   ```
5. **📝 Commit** and create a Pull Request

### 🎯 Contribution Areas

| Area                    | Description                   | Difficulty |
| ----------------------- | ----------------------------- | ---------- |
| 🔐 **New Algorithms**   | Implement additional ciphers  | 🟡 Medium  |
| 🎨 **CLI Improvements** | Better interactive experience | 🟢 Easy    |
| 📚 **Documentation**    | Examples and guides           | 🟢 Easy    |
| 🧪 **Testing**          | More comprehensive tests      | 🟡 Medium  |

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

## 🌟 Show Your Support

If you find **ruscrypt** useful, please consider:

[![⭐ Star on GitHub](https://img.shields.io/badge/⭐-Star%20on%20GitHub-yellow?style=for-the-badge)](https://github.com/Adel2411/ruscrypt)

---

**Created with ❤️ by [Adel2411](https://github.com/Adel2411)**

[![GitHub](https://img.shields.io/badge/GitHub-Adel2411-181717?style=for-the-badge&logo=github)](https://github.com/Adel2411)

#### _Built with Rust 🦀 • Secured with Math 🔢 • Crafted with Passion 💎_

</div>
