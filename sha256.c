#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

__uint8_t constK[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

__uint8_t Hash[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

typedef struct {
    unsigned int nb_block;
    unsigned int lenght;
    unsigned char *input;
} padded_message;


padded_message* padding_process(const unsigned char* text) {
    printf("Début de la fonction de padding.");
    // input doit être un multiple de 512
    // pour cela, on met un 1 à la fin, puis on met k 0 bits tel que : l + 1 + k congru 448[512] avec l = longueur de l'input initial ("test")
    // enfin on ajoute la longueur de l'input en binaire, mais en 64 bits (ex: 4 -> 000...0100)
    // à la fin, on devrait avoir un multiple de 512 bit

    if (!text) {
        fprintf(stderr, "Erreur: pointeur null\n");
        return NULL;
    }

    padded_message* messagePadded = malloc(sizeof(padded_message));
    if (!messagePadded) {
        fprintf(stderr, "Erreur: allocation structure\n");
        return NULL;
    }

    size_t lenght = strlen((const char *)text) ;
    __uint64_t lenghtBit = lenght * 8;

    printf("Lenght of the message input = %zu, Lenght of the message input in byte = %lu\n\n", lenght, lenghtBit);

    if (lenght > (__UINT64_MAX__ / 8 - 1)) {
        fprintf(stderr, "Erreur: message trop long pour SHA-256\n");
        free(messagePadded);
        return NULL;
    }

    size_t k = (448 - (lenghtBit + 1) % 512) % 512;
    size_t totalLenght = (lenghtBit + 1 + k + 64) / 8; // Total lenght of the message input

    printf("k (number of 0 byte) = %zu, Total lenght of the message input = %zu\n\n", k, totalLenght);

    unsigned char* paddedMessage = calloc(totalLenght, sizeof(__uint8_t));
    if (!paddedMessage) {
        fprintf(stderr, "Erreur: allocation mémoire\n");
        free(messagePadded);
        return NULL;
    }

    memcpy(paddedMessage, text, lenght);
    paddedMessage[lenght] = 0x80;

    // Big-endian (il faut voir avec little-endian)
    for (int i = 0; i < 8; i = i+1) {
        paddedMessage[totalLenght - 8 + i] = (__uint8_t)(lenghtBit >> (56 - i * 8)) & 0xFF;
    }

    messagePadded->nb_block = totalLenght / 64;
    messagePadded->lenght = totalLenght;
    messagePadded->input = paddedMessage;

    return messagePadded;
}

static int parsing_process() {
    // le message reçu doit être découper en N bloc de 512 bits.
    // puis on doit découper ces blocks de 512 bits en 16 parties de 32 bits
    // les blocs sont M[1]...M[N]
    // et les parties de blocs M[i]0 .. M[i]15

    return 0;
}

static int computation_process() {
    return 0;
}

int sha256(const unsigned char* input) {
    printf("Fonction de hachage sha256 pour %s.", input);

    padding_process(input);

    // transformer l'input en binaire (table ascii)

    return 0;
}