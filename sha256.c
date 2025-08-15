#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// SHA-256 rotation and logical operation macros
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b)))) // Circular right rotation

// Logical functions used in SHA-256
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))      // Choice: if x then y else z
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) // Majority function

// SHA-256 compression functions
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))  // Sigma 0 function
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))// Sigma 1 function

// SHA-256 message schedule functions
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))  // Uppercase sigma 0
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))  // Uppercase sigma 1

// SHA-256 constants K - Contains the first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers
uint32_t constK[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// Initial hash values H - Contains the first 32 bits of the fractional parts of the square roots of the first 8 prime numbers
uint32_t H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

// Structure to hold the padded message data
typedef struct {
    unsigned int nb_block;   // Number of 512-bit blocks
    unsigned int length;     // Total length in bytes
    unsigned char *input;    // Padded input data
} padded_message;

// Note on Endianness:
// Big-Endian: Most significant byte first (e.g., 0x1234 stored as [12][34])
// Little-Endian: Least significant byte first (e.g., 0x1234 stored as [34][12])
// SHA-256 uses Big-Endian byte ordering but if your system is little-endian, the program automatically converts

/**
 * Performs the padding process for SHA-256
 * @param text Input text to be padded
 * @return Pointer to padded_message structure containing the processed message
 * 
 * The padding process:
 * 1. Appends a single '1' bit
 * 2. Adds zeros until the message length ≡ 448 (mod 512)
 * 3. Appends the original message length as a 64-bit big-endian integer
 */
padded_message* padding_process(const unsigned char* text) {
    if (!text) {
        fprintf(stderr, "Error: NULL pointer input\n");
        return NULL;
    }

    padded_message* messagePadded = malloc(sizeof(padded_message));
    if (!messagePadded) {
        fprintf(stderr, "Error memory allocation for messagePadded\n");
        return NULL;
    }

    size_t length = strlen((const char*)text);
    uint64_t lengthBit = length * 8;

    if (length > (__UINT64_MAX__ / 8 - 1)) {
        fprintf(stderr, "Error input too long for SHA-256\n");
        free(messagePadded);
        return NULL;
    }

    size_t k = (448 - (lengthBit + 1) % 512) % 512;
    size_t totalLength = (lengthBit + 1 + k + 64) / 8; // Total lenght of the message input

    unsigned char* paddedMessage = calloc(totalLength, sizeof(uint8_t));
    if (!paddedMessage) {
        fprintf(stderr, "Error memory allocation for paddedMessage\n");
        free(messagePadded);
        return NULL;
    }


    if (length >= totalLength) {
        fprintf(stderr, "Error length paddedMessage.\n");
        free(messagePadded);
        return NULL;
    }
    memcpy(paddedMessage, text, length);
    paddedMessage[length] = 0x80;

    for (size_t i = 0; i < 8; i++) {
        paddedMessage[totalLength - 8 + i] = (uint8_t)(lengthBit >> (56 - i * 8)) & 0xFF;
    }

    messagePadded->nb_block = totalLength / 64;
    messagePadded->length = totalLength;
    messagePadded->input = paddedMessage;

    return messagePadded;
}

/**
 * Processes a single 512-bit block for SHA-256 computation
 * @param paddedBlock Pointer to the 512-bit block to process
 * @return 0 on success, non-zero on failure
 * 
 * Steps:
 * 1. Creates message schedule array (w[0..63])
 * 2. Initializes working variables (a-h)
 * 3. Performs main hash computation loop
 * 4. Updates hash values H[0..7]
 */
static int computation_process(const unsigned char* paddedBlock) {
    // Message schedule array
    uint32_t w[64] = {};

    // Convert bytes to words (Big-Endian)
    size_t t = 0;
    for (; t < 16; t++) {
        // Convert 4 bytes to a 32-bit word using Big-Endian ordering
        w[t] = (uint32_t)paddedBlock[t * 4] << 24 | 
               (uint32_t)paddedBlock[t * 4 + 1] << 16 | 
               (uint32_t)paddedBlock[t * 4 + 2] << 8 | 
               (uint32_t)paddedBlock[t * 4 + 3];
    }

    // Extend the first 16 words into the remaining 48 words
    for (; t < 64; t++) {
        w[t] = SIG1(w[t-2]) + w[t-7] + SIG0(w[t-15]) + w[t-16];
    }

    uint32_t a = H[0],
               b = H[1], 
               c = H[2], 
               d = H[3], 
               e = H[4], 
               f = H[5], 
               g = H[6], 
               h = H[7];
    
    for (t = 0; t < 64; t++) {
        uint32_t T1 = h +  EP1(e) + CH(e, f, g) + constK[t] + w[t];
        uint32_t T2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;

    return 0;
}

/**
 * Computes the SHA-256 hash of the input message
 * @param input Input message to hash
 * @return Pointer to 32-byte array containing the hash value, or NULL on error
 * 
 * Process:
 * 1. Initializes hash values
 * 2. Processes the message padding
 * 3. Processes each 512-bit block
 * 4. Produces final hash output in big-endian format
 */
unsigned char* sha256(const unsigned char* input) {
    if (!input) {
        return NULL;
    }

    // Reset H for each call
    uint32_t H_init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(H, H_init, sizeof(H));

    padded_message* paddingProcessMessage = padding_process(input);
    if (!paddingProcessMessage) {
        return NULL;
    }

    for (size_t i = 0; i < paddingProcessMessage->nb_block; i++) {
        if (computation_process(paddingProcessMessage->input + i * 64) != 0) {
            free(paddingProcessMessage->input);
            free(paddingProcessMessage);
            return NULL;
        }
    }

    unsigned char* hashValue = malloc(32);
    if (!hashValue) {
        free(paddingProcessMessage->input);
        free(paddingProcessMessage);
        return NULL;
    }

    for (size_t i = 0; i < 8; i++) {
        hashValue[i * 4] = (H[i] >> 24) & 0xFF;
        hashValue[i * 4 + 1] = (H[i] >> 16) & 0xFF;
        hashValue[i * 4 + 2] = (H[i] >> 8) & 0xFF;
        hashValue[i * 4 + 3] = H[i] & 0xFF;
    }

    free(paddingProcessMessage->input);
    free(paddingProcessMessage);

    return hashValue;
}