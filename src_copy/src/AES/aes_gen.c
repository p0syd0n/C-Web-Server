#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 16
#define KEY_IV_FILE "aes_key_iv.bin"

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to encrypt a line of text
void encrypt_aes(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handle_errors();

    // Provide the message to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((const char *)plaintext))) handle_errors();
    ciphertext_len = len;

    // Finalize the encryption. Further ciphertext bytes may be written at this stage.
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handle_errors();
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Null-terminate the encrypted string
    ciphertext[ciphertext_len] = '\0';
}

// Function to decrypt a line of text
void decrypt_aes(const unsigned char *ciphertext, unsigned char *plaintext, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    // Initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handle_errors();

    // Provide the message to be decrypted, and obtain the decrypted output
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, strlen((const char *)ciphertext))) handle_errors();
    plaintext_len = len;

    // Finalize the decryption. Further plaintext bytes may be written at this stage.
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handle_errors();
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Null-terminate the decrypted string
    plaintext[plaintext_len] = '\0';
}

// Function to write key and IV to a file
void write_key_iv_to_file(const unsigned char *key, const unsigned char *iv) {
    FILE *keyfile = fopen(KEY_IV_FILE, "wb");
    if (keyfile == NULL) {
        perror("Error opening key file");
        exit(EXIT_FAILURE);
    }
    fwrite(key, 1, AES_KEY_SIZE / 8, keyfile);
    fwrite(iv, 1, AES_BLOCK_SIZE, keyfile);
    fclose(keyfile);
}

// Function to read key and IV from a file
void read_key_iv_from_file(unsigned char *key, unsigned char *iv) {
    FILE *keyfile = fopen(KEY_IV_FILE, "rb");
    if (keyfile == NULL) {
        perror("Error opening key file");
        exit(EXIT_FAILURE);
    }
    fread(key, 1, AES_KEY_SIZE / 8, keyfile);
    fread(iv, 1, AES_BLOCK_SIZE, keyfile);
    fclose(keyfile);
}

int main() {
    // Define AES key and IV
    unsigned char key[AES_KEY_SIZE / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plaintext[128];
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    // Generate random key and IV
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        handle_errors();
    }

    // Write the key and IV to a file
    write_key_iv_to_file(key, iv);

    // Example plaintext
    strcpy((char *)plaintext, "This is a secret line of text.");

    // Encrypt the plaintext
    encrypt_aes(plaintext, ciphertext, key, iv);
    printf("Encrypted text: ");
    for (int i = 0; i < strlen((const char *)ciphertext); i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Read the key and IV from the file (simulating reloading them for decryption)
    read_key_iv_from_file(key, iv);

    // Decrypt the ciphertext
    decrypt_aes(ciphertext, decryptedtext, key, iv);
    printf("Decrypted text: %s\n", decryptedtext);

    return 0;
}
