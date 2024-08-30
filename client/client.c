#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/Dilithium/dilithium.h"

// Function to read the private key from a file
uint8_t* read_private_key(const char *filename, size_t *key_len) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Failed to open private key file");
        return NULL;
    }

    // Seek to the end of the file to get its size
    fseek(file, 0, SEEK_END);
    *key_len = ftell(file);
    rewind(file);

    // Allocate memory for the private key
    uint8_t *key = (uint8_t *)malloc(*key_len);
    if (key == NULL) {
        perror("Failed to allocate memory for private key");
        fclose(file);
        return NULL;
    }

    // Read the private key
    if (fread(key, 1, *key_len, file) != *key_len) {
        perror("Failed to read private key");
        free(key);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return key;
}

// Function to sign a message and print the signature in hex
void sign_and_print(const char *private_key_file) {
    // Initialize the Dilithium signature scheme
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == NULL) {
        fprintf(stderr, "Failed to initialize signature scheme.\n");
        return;
    }

    // Read the private key from file
    size_t private_key_len;
    uint8_t *private_key = read_private_key(private_key_file, &private_key_len);
    if (private_key == NULL) {
        OQS_SIG_free(sig);
        return;
    }

    // Message to be signed
    const char *message = "challenge message";
    size_t message_len = strlen(message);

    // Sign the message
    uint8_t *signature;
    size_t sig_len;
    OQS_STATUS status = sign_message(sig, (const uint8_t *)message, message_len, &signature, &sig_len, private_key);
    if (status != OQS_SUCCESS) {
        fprintf(stderr, "Failed to sign the message.\n");
        free(private_key);
        OQS_SIG_free(sig);
        return;
    }

    // Convert signature to hexadecimal
    char *hex_signature = binary_to_hex(signature, sig_len);
    if (hex_signature != NULL) {
        printf("Signature (hex): %s\n", hex_signature);
        free(hex_signature);
    } else {
        fprintf(stderr, "Failed to convert signature to hex.\n");
    }

    // Clean up
    free(signature);
    free(private_key);
    OQS_SIG_free(sig);
}

// Main function
int main() {
    sign_and_print("privkey.txt");
    return 0;
}
