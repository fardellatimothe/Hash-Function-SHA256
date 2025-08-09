#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static int init_process() {
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