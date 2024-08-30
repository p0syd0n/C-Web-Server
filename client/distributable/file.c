#include "Dilithium/dilithium.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h> // Ensure liboqs is included
#define PRIVKEY_PATH = "privkey.txt"

int generate_print_keypairs() {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2); // Creating the sign object
    if (sig == NULL) {
        fprintf(stderr, "Failed to initialize signature object.\n");
        return -1;
    }
    printf("[+] Created sig\n");

    uint8_t* public_key = malloc(sig->length_public_key); // Allocate enough memory for the public key
    uint8_t* private_key = malloc(sig->length_secret_key); // Allocate enough memory for the private key

    // Ensure memory allocation succeeded
    if (public_key == NULL || private_key == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return -1;
    }


    printf("[+] Allocated memory\n");

    // Generate keypair
    if (OQS_SIG_keypair(sig, public_key, private_key) != OQS_SUCCESS) {
        fprintf(stderr, "Failed to generate keypair.\n");
        return -1;
    }
    printf("[+] Generated keypair\n");

    // Convert binary keys to hex
    char* public_key_hex = binary_to_hex(public_key, 1312);
    char* private_key_hex = binary_to_hex(private_key, 2528);
    printf("[+] Converted keys to hex\n");

    printf("[=] Finished\n_____________\nPublic Key:\n%s\nPrivate Key:\n%s\n_____________\n", public_key_hex, private_key_hex);
    printf("!!!Make Sure To Save Your Keys Safely!!!\n");
    printf("!!!Your Keys Have NOT Been Automatically Saved. You Need To Do This Yourself!!!\n");
    printf("!!!Script is configured to look in 'privkey.txt' for the private key!!!\n");
    // Free allocated memory
    free(public_key);
    free(private_key);
    free(public_key_hex);
    free(private_key_hex);
    OQS_SIG_free(sig); // Free the signature object

    return 0;
}

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
    
    size_t signature_length = 2420;
    uint8_t *signature = malloc(signature_length); // Allocate memory for the signature
    if (signature == NULL) {
        perror("Failed to allocate memory for signature");
        OQS_SIG_free(sig);
        return;
    }

    char *signature_hex = NULL;
    char *public_key_hex = NULL;
    char *private_key_hex = NULL;

    // Standard Challenge Bytes
    char* message_hex = malloc(129);
    if (message_hex == NULL) {
        perror("Failed to allocate memory for message_hex");
        free(signature);
        OQS_SIG_free(sig);
        return;
    }
    strcpy(message_hex, "9712f9098b85eb5b5b27676a257fb85b9e18590fe4a5ebb9cc5e034229b08125a0ae7e3c123fdb71ad6b880d603836a43cfe0fdafc185895cb577dc21de9d50c");

    size_t message_length = 64;
    uint8_t* message = hex_to_binary(message_hex, &message_length);
    if (message == NULL) {
        fprintf(stderr, "Failed to convert message from hex to binary.\n");
        free(message_hex);
        free(signature);
        OQS_SIG_free(sig);
        return;
    }

    // Read the private key from file
    size_t private_key_len;
    uint8_t *private_key = read_private_key(private_key_file, &private_key_len);
    if (private_key == NULL) {
        fprintf(stderr, "Failed to read private key.\n");
        free(message);
        free(message_hex);
        free(signature);
        OQS_SIG_free(sig);
        return;
    }

    // Sign the message
    if (sign_message(sig, message, message_length, &signature, &signature_length, private_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Signing message failed\n");
        free(private_key);
        free(message);
        free(message_hex);
        free(signature);
        OQS_SIG_free(sig);
        return;
    }

    // Convert signature to hexadecimal
    signature_hex = binary_to_hex(signature, signature_length);
    if (signature_hex == NULL) {
        fprintf(stderr, "ERROR: Converting signature to hex failed\n");
        free(private_key);
        free(message);
        free(message_hex);
        free(signature);
        OQS_SIG_free(sig);
        return;
    }
    
    printf("Signature (Hex):\n%s\n", signature_hex);

    // Clean up
    free(private_key);
    free(message);
    free(message_hex);
    free(signature);
    free(signature_hex);
    OQS_SIG_free(sig);
}



int main() {
    printf("Welcome to the House of Hades Suite!! This is where you'll begin account set up, sign challenge messages, and encrypt files.\n\n");
    char* pubkey_path PRIVKEY_PATH;
    printf("Script is configured to use '%s' as the public key.\n\n", pubkey_path);
    printf("Options:\n");
    printf("1) generate keypair\n");
    printf("2) sign a message\n");
    printf("3) encrypt a file (NOT WORKING YET.)\n");
    int option;

    // Prompt the user for input
    printf("Enter an option (1, 2, or 3): ");
    scanf("%d", &option);

    // Use switch-case to handle different options
    switch (option) {
        case 1:
            printf("You selected option 1.\n");
            generate_print_keypairs();
            break;
        case 2:
            printf("You selected option 2.\n");
            sign_and_print(pubkey_path);
            break;
        case 3:
            printf("You selected option 3.\n");
            // Add code for option 3 here
            break;
        default:
            printf("Invalid option. Please enter 1, 2, or 3.\n");
            break;
    }
    return 1;
}
