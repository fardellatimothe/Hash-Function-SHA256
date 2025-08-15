#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>

#include "sha256.h"

char* hash_to_hex(const unsigned char* hash);
int compare_hashes(const unsigned char* hash1, const unsigned char* hash2);
int compare_hex_hashes(const char* hex1, const char* hex2);

/**
 * Main test function for SHA-256 implementation
 * Uses test vectors from NIST FIPS 180-4 standard to verify implementation
 * @return 1 if all tests pass, 0 if any test fails
 * 
 * Test cases:
 * 1. Single block message ("abc")
 * 2. Multi-block message (56 characters)
 * 3. Long message (one million 'a' characters)
 */
int test_u_sha256() {
    
    // Test 1: Single block message : "abc"
    unsigned char* hash = sha256((unsigned char*)"abc");
    if (!hash) {
        fprintf(stderr, "Erreur: sha256() a retourné NULL pour le test 1\n");
        return 0;
    }
    char* hashHexTest = hash_to_hex(hash);
    if (!hashHexTest) {
        fprintf(stderr, "Erreur: hash_to_hex() a retourné NULL pour le test 1\n");
        free(hash);
        return 0;
    }
    if (strcmp(hashHexTest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") != 0) {
        fprintf(stderr, "Erreur lors du test global numéro 1.\n");
        free(hashHexTest);
        free(hash);
        return 0;
    }
    free(hashHexTest);
    free(hash);


    // Test 2: Multi-block message : "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    hash = sha256((unsigned char*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    if (!hash) {
        fprintf(stderr, "Erreur: sha256() a retourné NULL pour le test 2\n");
        return 0;
    }
    hashHexTest = hash_to_hex(hash);
    if (!hashHexTest) {
        fprintf(stderr, "Erreur: hash_to_hex() a retourné NULL pour le test 2\n");
        free(hash);
        return 0;
    }
    if (strcmp(hashHexTest, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") != 0) {
        fprintf(stderr, "Erreur lors du test global numéro 2.\n");
        free(hashHexTest);
        free(hash);
        return 0;
    }
    free(hashHexTest);
    free(hash);


    // Test 3: Long message test : one million 'a' characters
    size_t lengthMillion = 1000000;
    unsigned char *oneMillionA = malloc(lengthMillion + 1);
    if (!oneMillionA) {
        fprintf(stderr, "Erreur allocation mémoire pour le test 3\n");
        return 0;
    }

    memset(oneMillionA, 'a', lengthMillion);
    oneMillionA[lengthMillion] = '\0';

    hash = sha256(oneMillionA);
    if (!hash) {
        fprintf(stderr, "Erreur: sha256() a retourné NULL pour le test 3\n");
        free(oneMillionA);
        return 0;
    }
    hashHexTest = hash_to_hex(hash);
    if (!hashHexTest) {
        fprintf(stderr, "Erreur: hash_to_hex() a retourné NULL pour le test 3\n");
        free(hash);
        free(oneMillionA);
        return 0;
    }
    
    if (strcmp(hashHexTest, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") != 0) {
        fprintf(stderr, "Erreur lors du test global numéro 3.\n");
        free(hashHexTest);
        free(hash);
        free(oneMillionA);
        return 0;
    }
    
    free(hashHexTest);
    free(hash);
    free(oneMillionA);

    return 1;
}

/**
 * Converts a binary SHA-256 hash to its hexadecimal string representation
 * @param hash Pointer to 32-byte binary hash
 * @return Pointer to 65-byte char array (64 hex chars + null terminator), or NULL on error
 * 
 * Each byte of the hash is converted to two hexadecimal characters
 * Memory for the output string is dynamically allocated
 */
char* hash_to_hex(const unsigned char* hash) {
    char* hex = malloc(65); // 32 bytes = 64 chars + null terminator
    if (!hex) return NULL;
    
    for (int i = 0; i < 32; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = '\0';
    return hex;
}

/**
 * Compares two binary SHA-256 hashes
 * @param hash1 Pointer to first 32-byte hash
 * @param hash2 Pointer to second 32-byte hash
 * @return 0 if hashes are identical, non-zero if different, -1 on error
 * 
 * Direct memory comparison of two 32-byte hash values
 */
int compare_hashes(const unsigned char* hash1, const unsigned char* hash2) {
    if (!hash1 || !hash2) return -1;
    return memcmp(hash1, hash2, 32); // Compare exactly 32 bytes
}

/**
 * Compares two hexadecimal SHA-256 hash strings
 * @param hex1 Pointer to first hash string (64 characters)
 * @param hex2 Pointer to second hash string (64 characters)
 * @return 0 if hashes are identical, non-zero if different, -1 on error
 * 
 * Case-insensitive comparison of two 64-character hexadecimal strings
 * Validates input string lengths before comparison
 */
int compare_hex_hashes(const char* hex1, const char* hex2) {
    if (!hex1 || !hex2) return -1;
    if (strlen(hex1) != 64 || strlen(hex2) != 64) return -1;
    return strcasecmp(hex1, hex2); // Case-insensitive comparison
}