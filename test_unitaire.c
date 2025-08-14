#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>

#include "sha256.h"

char* hash_to_hex(const unsigned char* hash);
int compare_hashes(const unsigned char* hash1, const unsigned char* hash2);
int compare_hex_hashes(const char* hex1, const char* hex2);


// Main test function for SHA-256 implementation
int test_u_sha256() {
    // Test vectors from NIST FIPS 180-4
    
    // Test 1: Single block message
    // Expected hash for "abc"
    
    // Test 2: Multi-block message
    // Expected hash for "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    
    // Test 3: Long message test (one million 'a' characters)
    // Tests handling of large input data

    // Test 1: message simple (1 bloc)
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
    
    // Test 2: message plus long
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

    // Test 3: 1 million de a
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

// Convert binary hash to hexadecimal string
// Returns: Null-terminated string of 64 hex chars + null byte
char* hash_to_hex(const unsigned char* hash) {
    char* hex = malloc(65); // 32 bytes = 64 chars + null terminator
    if (!hex) return NULL;
    
    for (int i = 0; i < 32; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = '\0';
    return hex;
}

// Compare two binary hashes
// Returns: 0 if equal, non-zero if different, -1 on error
int compare_hashes(const unsigned char* hash1, const unsigned char* hash2) {
    if (!hash1 || !hash2) return -1;
    return memcmp(hash1, hash2, 32); // Compare exactly 32 bytes
}

// Compare two hexadecimal hash strings (case-insensitive)
// Returns: 0 if equal, non-zero if different, -1 on error
int compare_hex_hashes(const char* hex1, const char* hex2) {
    if (!hex1 || !hex2) return -1;
    if (strlen(hex1) != 64 || strlen(hex2) != 64) return -1;
    return strcasecmp(hex1, hex2); // Case-insensitive comparison
}