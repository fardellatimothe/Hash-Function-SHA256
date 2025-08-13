#include "sha256.h"
#include "test_unitaire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int hashText();
int hashFile();

int fileSize(FILE *f);
unsigned char* extractTextFromFile(const char* path);

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

    char keymode[100000] = {0};

    printf("\nKeymodes:\n");
    printf("[Keymode 1] Hash an input text\n");
    printf("[Keymode 2] Hash a text file (.txt)\n\n");
    printf("Enter keymode: ");

    if (fgets(keymode, sizeof(keymode), stdin) == NULL) {
        perror("Error reading input\n");
        return EXIT_FAILURE;
    }

    keymode[strcspn(keymode, "\n")] = 0;

    if (strcmp(keymode, "1") == 0) {
        hashText();
    } else if (strcmp(keymode, "2") == 0) {
        hashFile();
    } else {
        printf("Enter valid keymode\n");
        return EXIT_FAILURE;
    }
        
    return 0;
}

int hashText() {
    printf("\n==============================================\n\n");
    printf("Enter the text you want to hash : "); 

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

    // enlève le dernier caractère s'il est "\n"
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

int hashFile() {
    printf("\n==============================================\n\n");
    printf("Enter path to file : ");

    char filePath[256] = {0};

    if (fgets(filePath, 256, stdin) == NULL) {
        perror("Error reading file path\n");
        return EXIT_FAILURE;
    }

    filePath[strcspn(filePath, "\n")] = 0;

    unsigned char* text = extractTextFromFile(filePath);

    __u_char* hashValue = sha256(text);

    if (!hashValue) {
        free(text);
        fprintf(stderr, "Hash computation failed\n");
        return EXIT_FAILURE;
    }

    printf("\n\nHash Value : ");

    // Afficher le hash en hexadécimal
    for (int i = 0; i < 32; i++) {
        printf("%02x", hashValue[i]);
    }
    printf("\n");

    free(text);
    free(hashValue);

    return 0;
}

unsigned char* extractTextFromFile(const char* path) {

    if (!path) {
        fprintf(stderr, "Error: NULL input\n");
        return NULL;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
		fclose(f);
		perror("Error while opening file, please check your path");
		return NULL;
	}

    size_t size = (size_t)fileSize(f);

    unsigned char* text = malloc(size + 1);

    int c;
    size_t i = 0;
    while((c = fgetc(f)) != EOF && i < size) {
        text[i] = (uint8_t)c;
        i++;
    }
    text[i] = '\0'; 

    if (ferror(f)) {
		perror("Error while handling the file");
		fclose(f);
        return NULL;
	}
	if (fclose(f) != 0) {
		perror("Error while closing the file");
        return NULL;
	}

    return text;

}

int fileSize(FILE *f) {
    int prev = ftell(f);
    fseek(f, 0L, SEEK_END);
    int size = ftell(f);
    fseek(f, prev, SEEK_SET);
    return size;
}
