# SHA-256 Hash Function Implementation

A lightweight C implementation of the SHA-256 cryptographic hash function, following the NIST FIPS 180-4 standard. This command-line tool allows you to generate SHA-256 hashes from text input or files.

### About SHA-256

SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function that generates a fixed-size 256-bit (32-byte) hash value from any input data. It's widely used in digital signatures, blockchain technology, and data integrity verification.

### Features

- Text input hashing from keyboard
- File content hashing (.txt files)
- NIST FIPS 180-4 compliant implementation
- Built-in test suite with standard test vectors

### Installation

```
# Clone the repository
git clone https://github.com/fardellatimothe/Hash-Function-SHA256.git
cd Hash-Function-SHA256

# Compile the project
make
```

### Usage

Run the compiled program:

```
./sha256
```

The program offers two modes:

1. Hash text input directly from keyboard
2. Hash content from a text file

Example

```
$ ./sha256

Keymodes:
[Keymode 1] Hash an input text
[Keymode 2] Hash a text file (.txt)

Enter keymode: 1
Enter the text you want to hash: Hello, World!

Hash Value: 315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
```

### Project Structure

- main.c - Program entry point and user interface
- sha256.c - Core SHA-256 implementation
- test_unitaire.c - Unit tests with NIST test vectors
- Makefile - Build configuration

### Testing

The implementation includes built-in unit tests that verify the hash function against NIST test vectors. These tests run automatically when starting the program.

Test cases include:

- Single block message ("abc")
- Multi-block message (56 characters)
- Long message (one million 'a' characters)

### License

This project is open source and available under the MIT License.

### Build Requirements

- GCC compiler
- Make build system
- Standard C library
- Linux/Unix environment