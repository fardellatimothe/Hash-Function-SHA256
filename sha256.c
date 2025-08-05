#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int padding_process(char* text) {
    // input doit être un multiple de 512
    // pour cela, on met un 1 à la fin, puis on met k 0 bits tel que : l + 1 + k congru 448[512] avec l = longueur de l'input initial ("test")
    // enfin on ajoute la longueur de l'input en binaire, mais en 64 bits (ex: 4 -> 000...0100)
    // à la fin, on devrait avoir un multiple de 512 bit

    int l = strlen(text) - 1;
    int lbit = (strlen(text) - 1) * 8;

    printf("l = %d, lbit = %d\n\n", l, lbit);

    int k = (448 - (lbit + 1) % 512) % 512;
    int tot_len = (lbit + k + 64) / 8;

    printf("k = %d, tot_len = %d\n\n", k, tot_len);

    unsigned char* padded_input = calloc(tot_len, 1);

    memcpy(padded_input, text, l);

    padded_input[l] = 0x80;

    printf("padded_input = %s", padded_input);

    free(padded_input);

    return 0;
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

int sha256(char* input) {
    printf("Fonction de hachage sha256 pour %s.", input);

    padding_process(input);

    // transformer l'input en binaire (table ascii)

    return 0;
}