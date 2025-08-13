#include "sha256.h"
#include "test_unitaire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Gestion des erreurs :
// Ajouter plus de vérifications d'erreur

// Documentation :
// Ajouter des commentaires pour expliquer les constantes
// Documenter les fonctions avec leurs paramètres et valeurs de retour

// Sécurité :
// Fonction pour effacer toute la mémoire
// Vérifier les débordements de buffer

// Fichier :
// Ajouter le hachage pour les fichiers.

int main () {
    // Tests Globaux
    if (!test_u_sha256()) {
        return EXIT_FAILURE;
    }

    printf("Enter the word you want to hash :  "); 

    __u_char* input = malloc(256);

    if (!input) {
        free(input);
        perror("Error memory allocation\n");
        return EXIT_FAILURE;
    }

    if (fgets((char*)input, 256, stdin) == NULL) {
        free(input);
        perror("Error reading input\n");
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

    printf("\n\nHash Value : ");

    // Afficher le hash en hexadécimal
    for (int i = 0; i < 32; i++) {
        printf("%02x", hashValue[i]);
    }
    printf("\n");

    free(input);
    free(hashValue);

    return(0);
}
