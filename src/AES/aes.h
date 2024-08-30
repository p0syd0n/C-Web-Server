#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 16

void handle_errors();

// Function to encrypt a line of text
void encrypt_aes(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *key, const unsigned char *iv);

// Function to decrypt a line of text
void decrypt_aes(const unsigned char *ciphertext, unsigned char *plaintext, const unsigned char *key, const unsigned char *iv);
