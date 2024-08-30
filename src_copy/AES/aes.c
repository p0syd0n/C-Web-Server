#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 16

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

