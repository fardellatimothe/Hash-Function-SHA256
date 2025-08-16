#include "sha256.h"
#include "vector_tests.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int hashText();
static int hashFile();
static int fileSize(FILE *f);
static unsigned char* extractTextFromFile(const char* path);

/**
 * Main entry point of the SHA-256 hash program
 * Provides two modes of operation:
 * 1. Hash text input from keyboard
 * 2. Hash content from a text file
 * 
 * Runs unit tests before allowing user interaction
 * @return 0 on success, EXIT_FAILURE on error
 */
int main () {
    // Vector Tests
    if (!tests()) {
        return EXIT_FAILURE;
    }

    char keymode[256] = {0};

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

/**
 * Handles text input hashing from keyboard
 * - Allocates a 256-byte buffer for input
 * - Removes trailing newline from input
 * - Validates input size
 * - Computes and displays hash
 * - Performs secure cleanup of sensitive data
 * 
 * @return 0 on success, EXIT_FAILURE on error
 */
static int hashText() {
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

    // Remove last char if it's "\n" 
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

    // Print the hashed text in hexadecimal
    for (int i = 0; i < 32; i++) {
        printf("%02x", hashValue[i]);
    }
    printf("\n");

    free(input);
    free(hashValue);

    return 0;
}

/**
 * Handles file content hashing
 * - Reads file path from user
 * - Extracts file content
 * - Computes and displays hash
 * - Performs secure cleanup of sensitive data
 * 
 * @return 0 on success, EXIT_FAILURE on error
 */
static int hashFile() {
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

    // Afficher le hash en hexadecimal
    for (int i = 0; i < 32; i++) {
        printf("%02x", hashValue[i]);
    }
    printf("\n");

    // Secure cleanup
    free(text);
    free(hashValue);

    return 0;
}

/**
 * Extracts text content from a file into memory
 * @param path Path to the file to read
 * @return Dynamically allocated buffer containing file contents, NULL on error
 * 
 * Notes:
 * - Reads file in binary mode
 * - Adds null terminator to the buffer
 * - Caller must free the returned buffer
 */
static unsigned char* extractTextFromFile(const char* path) {

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
    if (!text) {
        perror("Error memory allocation\n");
        return NULL;
    }

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

/**
 * Determines the size of a file in bytes
 * @param f Pointer to an open file
 * @return Size of the file in bytes
 * 
 * Preserves the current file position pointer
 */
static int fileSize(FILE *f) {
    int prev = ftell(f);
    fseek(f, 0L, SEEK_END);
    int size = ftell(f);
    fseek(f, prev, SEEK_SET);
    return size;
}
