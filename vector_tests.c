#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>

#include "sha256.h"

static char* hash_to_hex(const unsigned char* hash);

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
int tests() {
    // Test 1: Single block message : "abc"
    unsigned char* hash = sha256((unsigned char*)"abc");
    if (!hash) {
        fprintf(stderr, "Error: sha256() returned NULL for test 1\n");
        return 0;
    }
    char* hashHexTest = hash_to_hex(hash);
    if (!hashHexTest) {
        fprintf(stderr, "Error: hash_to_hex() returned NULL for test 1\n");
        free(hash);
        return 0;
    }
    if (strcmp(hashHexTest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") != 0) {
        fprintf(stderr, "Error during vector test number 1\n");
        free(hashHexTest);
        free(hash);
        return 0;
    }
    free(hashHexTest);
    free(hash);


    // Test 2: Multi-block message : "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    hash = sha256((unsigned char*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    if (!hash) {
        fprintf(stderr, "Error: sha256() returned NULL for test 2\n");
        return 0;
    }
    hashHexTest = hash_to_hex(hash);
    if (!hashHexTest) {
        fprintf(stderr, "Error: hash_to_hex() returned NULL for test 2\n");
        free(hash);
        return 0;
    }
    if (strcmp(hashHexTest, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") != 0) {
        fprintf(stderr, "Error during vector test number 2\n");
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
        fprintf(stderr, "Error memory allocation for test 3\n");
        return 0;
    }

    memset(oneMillionA, 'a', lengthMillion);
    oneMillionA[lengthMillion] = '\0';

    hash = sha256(oneMillionA);
    if (!hash) {
        fprintf(stderr, "Error: sha256() returned NULL for test 3\n");
        free(oneMillionA);
        return 0;
    }
    hashHexTest = hash_to_hex(hash);
    if (!hashHexTest) {
        fprintf(stderr, "Error: hash_to_hex() returned NULL for test 3\n");
        free(hash);
        free(oneMillionA);
        return 0;
    }
    
    if (strcmp(hashHexTest, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") != 0) {
        fprintf(stderr, "Error during vector test number 3\n");
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
static char* hash_to_hex(const unsigned char* hash) {
    char* hex = malloc(65); // 32 bytes = 64 chars + null terminator
    if (!hex) return NULL;
    
    for (int i = 0; i < 32; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = '\0';
    return hex;
}