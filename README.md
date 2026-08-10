# AegisVault

A secure C++-based file encryption and decryption system designed to protect sensitive files using modern cryptographic techniques.

## 📌 Project Overview

AegisVault is a command-line file security application developed in C++. It provides secure file encryption and decryption using the AES-256 encryption algorithm and OpenSSL cryptographic libraries.

The project uses password-based key derivation with PBKDF2 and SHA-256 to derive a cryptographic key from the user's password. A random salt and initialization vector (IV) are used to strengthen the encryption process.

## ✨ Features

- AES-256-CBC file encryption
- Secure file decryption
- Password-based key derivation using PBKDF2
- SHA-256 hashing
- Random salt generation
- Random IV generation
- File extension preservation
- Password verification during decryption
- Command-line interface
- Built using C++ and OpenSSL

## 🔐 How It Works

The basic workflow of AegisVault is:

```text
Plain File
    ↓
Password
    ↓
PBKDF2 + Random Salt
    ↓
Derived Key
    ↓
AES-256-CBC Encryption + IV
    ↓
Encrypted .aegis File
