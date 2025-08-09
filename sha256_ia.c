#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Macros pour les opérations bitwise
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

// Constantes SHA-256 (64 premières racines cubiques des nombres premiers)
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Valeurs d'initialisation (racines carrées des 8 premiers nombres premiers)
static const uint32_t H_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Structure pour le résultat du padding
typedef struct {
    uint8_t* data;
    size_t length;
    size_t num_blocks;
} padded_message_t;

// Fonction de padding
padded_message_t* sha256_padding(const char* message) {
    size_t message_len = strlen(message);
    uint64_t message_len_bits = message_len * 8;
    
    // Calcul du padding
    size_t k = (448 - ((message_len_bits + 1) % 512)) % 512;
    size_t padded_length = (message_len_bits + 1 + k + 64) / 8;
    
    printf("Message: '%s' (%zu octets, %lu bits)\n", message, message_len, message_len_bits);
    printf("Padding: %zu bits, Longueur finale: %zu octets\n", k, padded_length);
    
    // Allocation
    padded_message_t* result = malloc(sizeof(padded_message_t));
    if (!result) return NULL;
    
    result->data = calloc(padded_length, 1);
    if (!result->data) {
        free(result);
        return NULL;
    }
    
    result->length = padded_length;
    result->num_blocks = padded_length / 64;
    
    // Copie du message original
    memcpy(result->data, message, message_len);
    
    // Ajout du bit '1' (0x80)
    result->data[message_len] = 0x80;
    
    // Ajout de la longueur en big-endian (64 bits)
    for (int i = 0; i < 8; i++) {
        result->data[padded_length - 8 + i] = (message_len_bits >> (56 - i * 8)) & 0xFF;
    }
    
    return result;
}

// Traitement d'un bloc de 512 bits
void sha256_process_block(uint32_t* H, const uint8_t* block) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;
    
    // Préparation des 64 mots (expansion du message)
    // Les 16 premiers mots : conversion big-endian des 16 mots de 32 bits du bloc
    for (int i = 0; i < 16; i++) {
        W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | 
               (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    
    // Les 48 mots suivants : expansion
    for (int i = 16; i < 64; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }
    
    // Initialisation des variables de travail
    a = H[0]; b = H[1]; c = H[2]; d = H[3];
    e = H[4]; f = H[5]; g = H[6]; h = H[7];
    
    // 64 rondes de compression
    for (int i = 0; i < 64; i++) {
        T1 = h + EP1(e) + CH(e, f, g) + K[i] + W[i];
        T2 = EP0(a) + MAJ(a, b, c);
        
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    
    // Mise à jour des valeurs de hash
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

// Fonction principale SHA-256
void sha256(const char* message, uint8_t* hash) {
    // Padding
    padded_message_t* padded = sha256_padding(message);
    if (!padded) return;
    
    // Initialisation des valeurs de hash
    uint32_t H[8];
    memcpy(H, H_INIT, sizeof(H_INIT));
    
    printf("Traitement de %zu bloc(s) de 512 bits\n", padded->num_blocks);
    
    // Traitement de chaque bloc
    for (size_t i = 0; i < padded->num_blocks; i++) {
        sha256_process_block(H, padded->data + i * 64);
    }
    
    // Conversion du résultat en big-endian pour la sortie
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (H[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (H[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (H[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = H[i] & 0xFF;
    }
    
    // Libération mémoire
    free(padded->data);
    free(padded);
}

// Fonction utilitaire pour afficher le hash en hexadécimal
void print_hash(const uint8_t* hash) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// Tests avec des vecteurs connus
void test_sha256() {
    uint8_t hash[32];
    
    printf("=== Tests SHA-256 ===\n\n");
    
    // Test 1: chaîne vide
    printf("Test 1: chaîne vide\n");
    sha256("", hash);
    printf("Résultat: ");
    print_hash(hash);
    printf("Attendu:  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n");
    
    // Test 2: "abc"
    printf("Test 2: 'abc'\n");
    sha256("abc", hash);
    printf("Résultat: ");
    print_hash(hash);
    printf("Attendu:  ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n\n");
    
    // Test 3: message plus long
    printf("Test 3: 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'\n");
    sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hash);
    printf("Résultat: ");
    print_hash(hash);
    printf("Attendu:  248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1\n\n");
}