#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// Structure pour retourner le padding
typedef struct {
    unsigned char* data;
    int length;
} padding_result_t;

// Ta fonction de padding (modifiée pour retourner les données)
padding_result_t padding_process(const char* text) {
    int l = strlen(text);
    int lbit = strlen(text) * 8;

    printf("l = %d, lbit = %d\n", l, lbit);

    int k = (448 - (lbit + 1) % 512) % 512;
    int tot_len = (lbit + 1 + k + 64) / 8;

    printf("k = %d, tot_len = %d\n", k, tot_len);

    unsigned char* padded_input = calloc(tot_len, 1);

    memcpy(padded_input, text, l);
    padded_input[l] = 0x80;

    // Ajouter la longueur originale sur les 8 derniers octets
    uint64_t len_bits = (uint64_t)lbit;
    for (int i = 0; i < 8; i++) {
        padded_input[tot_len - 8 + i] = (len_bits >> (56 - i * 8)) & 0xFF;
    }

    printf("padded_input (hex): ");
    for (int i = 0; i < tot_len; i++) {
        printf("%02x ", padded_input[i]);
        if ((i + 1) % 16 == 0) printf("\n                    ");
    }
    printf("\n\n");

    padding_result_t result = {padded_input, tot_len};
    return result;
}

// Fonction utilitaire pour comparer deux tableaux d'octets
int compare_bytes(const unsigned char* a, const unsigned char* b, int length) {
    for (int i = 0; i < length; i++) {
        if (a[i] != b[i]) {
            printf("ERREUR à l'index %d: attendu 0x%02x, obtenu 0x%02x\n", i, b[i], a[i]);
            return 0;
        }
    }
    return 1;
}

// Test 1: Chaîne vide ""
void test_empty_string() {
    printf("=== TEST 1: Chaîne vide ===\n");
    
    padding_result_t result = padding_process("");
    
    // Résultat attendu pour chaîne vide
    unsigned char expected[] = {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Longueur = 0
    };
    
    printf("Vérifications:\n");
    printf("- Longueur: %s (attendu: 64, obtenu: %d)\n", 
           result.length == 64 ? "✓" : "✗", result.length);
    printf("- Multiple de 64: %s\n", result.length % 64 == 0 ? "✓" : "✗");
    printf("- Contenu: %s\n", 
           compare_bytes(result.data, expected, 64) ? "✓" : "✗");
    
    free(result.data);
    printf("\n");
}

// Test 2: "abc"
void test_abc() {
    printf("=== TEST 2: 'abc' ===\n");
    
    padding_result_t result = padding_process("abc");
    
    // Résultat attendu pour "abc" (3 octets = 24 bits)
    unsigned char expected[] = {
        0x61, 0x62, 0x63, 0x80, 0x00, 0x00, 0x00, 0x00,  // "abc" + 0x80 + padding
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18   // Longueur = 24 bits
    };
    
    printf("Vérifications:\n");
    printf("- Longueur: %s (attendu: 64, obtenu: %d)\n", 
           result.length == 64 ? "✓" : "✗", result.length);
    printf("- Multiple de 64: %s\n", result.length % 64 == 0 ? "✓" : "✗");
    printf("- Premier octet: %s (attendu: 0x61='a', obtenu: 0x%02x)\n",
           result.data[0] == 0x61 ? "✓" : "✗", result.data[0]);
    printf("- Bit de padding: %s (attendu: 0x80, obtenu: 0x%02x)\n",
           result.data[3] == 0x80 ? "✓" : "✗", result.data[3]);
    printf("- Longueur finale: %s (attendu: 0x18, obtenu: 0x%02x)\n",
           result.data[63] == 0x18 ? "✓" : "✗", result.data[63]);
    printf("- Contenu complet: %s\n", 
           compare_bytes(result.data, expected, 64) ? "✓" : "✗");
    
    free(result.data);
    printf("\n");
}

// Test 3: Message de 55 octets (cas limite avant 2 blocs)
void test_55_bytes() {
    printf("=== TEST 3: Message de 55 octets (cas limite) ===\n");
    
    char* message_55 = "1234567890123456789012345678901234567890123456789012345";
    padding_result_t result = padding_process(message_55);
    
    printf("Vérifications:\n");
    printf("- Longueur: %s (attendu: 64, obtenu: %d)\n", 
           result.length == 64 ? "✓" : "✗", result.length);
    printf("- Multiple de 64: %s\n", result.length % 64 == 0 ? "✓" : "✗");
    printf("- Bit de padding à position 55: %s (obtenu: 0x%02x)\n",
           result.data[55] == 0x80 ? "✓" : "✗", result.data[55]);
    printf("- Longueur en bits (55*8=440): %s (attendu: 0x01B8)\n",
           (result.data[62] == 0x01 && result.data[63] == 0xB8) ? "✓" : "✗");
    
    free(result.data);
    printf("\n");
}

// Test 4: Message de 56 octets (force 2 blocs)
void test_56_bytes() {
    printf("=== TEST 4: Message de 56 octets (force 2 blocs) ===\n");
    
    char* message_56 = "12345678901234567890123456789012345678901234567890123456";
    padding_result_t result = padding_process(message_56);
    
    printf("Vérifications:\n");
    printf("- Longueur: %s (attendu: 128, obtenu: %d)\n", 
           result.length == 128 ? "✓" : "✗", result.length);
    printf("- Multiple de 64: %s\n", result.length % 64 == 0 ? "✓" : "✗");
    printf("- Bit de padding à position 56: %s (obtenu: 0x%02x)\n",
           result.data[56] == 0x80 ? "✓" : "✗", result.data[56]);
    printf("- Longueur en bits (56*8=448): %s (attendu: 0x01C0)\n",
           (result.data[126] == 0x01 && result.data[127] == 0xC0) ? "✓" : "✗");
    
    free(result.data);
    printf("\n");
}

// Test 5: Message long (test avec de gros nombres)
void test_long_message() {
    printf("=== TEST 5: Message de 1000 octets ===\n");
    
    char* long_message = malloc(1001);
    memset(long_message, 'A', 1000);
    long_message[1000] = '\0';
    
    padding_result_t result = padding_process(long_message);
    
    printf("Vérifications:\n");
    printf("- Multiple de 64: %s (longueur: %d)\n", 
           result.length % 64 == 0 ? "✓" : "✗", result.length);
    printf("- Bit de padding: %s (position 1000, obtenu: 0x%02x)\n",
           result.data[1000] == 0x80 ? "✓" : "✗", result.data[1000]);
    printf("- Longueur en bits (1000*8=8000=0x1F40): %s\n",
           (result.data[result.length-2] == 0x1F && 
            result.data[result.length-1] == 0x40) ? "✓" : "✗");
    
    free(long_message);
    free(result.data);
    printf("\n");
}

// Fonction principale de test
int main() {
    printf("====== TESTS UNITAIRES PADDING SHA-256 ======\n\n");
    
    test_empty_string();
    test_abc();
    test_55_bytes();
    test_56_bytes();
    test_long_message();
    
    printf("====== FIN DES TESTS ======\n");
    return 0;
}