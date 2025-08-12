#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Gestion des erreurs :

// Ajouter plus de vérifications d'erreur
// Libérer la mémoire dans tous les cas d'erreur
// Documentation :

// Ajouter des commentaires pour expliquer les constantes
// Documenter les fonctions avec leurs paramètres et valeurs de retour
// Constantes symboliques :

// Définir des constantes pour les tailles fixes (32, 64, 256, etc.)
// Exemple : #define SHA256_HASH_SIZE 32
// Sécurité :

// Ajouter une fonction pour effacer les données sensibles de la mémoire
// Vérifier les débordements de buffer
// Tests :

// Ajouter des tests unitaires
// Vérifier avec des vecteurs de test standard SHA-256

int main () {
    printf("Enter the word you want to hash :  "); 

    unsigned char* input = malloc(256);

    if (!input) {
        perror("Error memory allocation");
        return EXIT_FAILURE;
    }

    if (fgets((char*)input, 256, stdin) == NULL) {
        free(input);
        perror("Error reading input");
        return EXIT_FAILURE;
    }

    size_t len = strlen((char*)input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
    }

    __u_char* hashValue = sha256(input);

    if (!hashValue) {
        free(input);
        fprintf(stderr, "Hash computation failed\n");
        return EXIT_FAILURE;
    }

    // printf("%hhn\n", hashValue);

    // Afficher le hash en hexadécimal
    for (int i = 0; i < 32; i++) {
        printf("%02x", hashValue[i]);
    }
    printf("\n");

    free(input);
    free(hashValue);

    return(0);
}
