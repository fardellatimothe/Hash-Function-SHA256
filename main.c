#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>




int main () {
    printf("Enter the word you want to hash :\n\n");

    unsigned char *input = NULL;
    
    // créer une structure pour lire dynamiquement l'input de l'utilisateur (sans avoir une taille fixe)
    input = malloc(sizeof(char[256]));

    if (input == NULL) {
        perror("Error memory allocation");
        return EXIT_FAILURE;
    }

    if (fgets(input, sizeof(input), stdin) == NULL) {
        perror("Error reading input");
        return EXIT_FAILURE;
    }

    sha256(input);

    free(input);

    return(0);
}
