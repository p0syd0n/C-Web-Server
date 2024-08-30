#include "dilithium.h"
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

uint8_t* text_to_binary(const char* text, size_t* length) {
    *length = strlen(text);
    uint8_t* binary_data = malloc(*length);
    if (binary_data == NULL) {
        perror("Failed to allocate memory");
        return NULL;
    }

    // Copy each character as uint8_t
    for (size_t i = 0; i < *length; i++) {
        binary_data[i] = (uint8_t)text[i];
    }

    return binary_data;
}

uint8_t *hex_to_binary(char *hex_str, size_t *binary_len) {
    if (hex_str == NULL) {
        fprintf(stderr, "NULL pointer provided for hex_str.\n");
        *binary_len = 0;
        return NULL;
    }

    size_t len = strlen(hex_str);
    if (len % 2 != 0) {
        fprintf(stderr, "Invalid hex string length.\n");
        *binary_len = 0;
        return NULL;
    }

    *binary_len = len / 2;
    uint8_t *binary_data = (uint8_t*)malloc(*binary_len);
    if (binary_data == NULL) {
        perror("Failed to allocate memory");
        *binary_len = 0;
        return NULL;
    }

    for (size_t i = 0; i < *binary_len; i++) {
        unsigned int byte;
        if (sscanf(hex_str + 2 * i, "%2x", &byte) != 1) {
            fprintf(stderr, "Failed to parse hex string.\n");
            free(binary_data);
            *binary_len = 0;
            return NULL;
        }
        binary_data[i] = (uint8_t)byte;
    }

    return binary_data;
}

char *binary_to_hex(const uint8_t *binary_data, size_t length) {
    char *hex_string = malloc(2 * length + 1);
    if (hex_string == NULL) {
        perror("Failed to allocate memory");
        return NULL;
    }

    for (size_t i = 0; i < length; i++) {
        sprintf(hex_string + 2 * i, "%02X", binary_data[i]);
    }
    hex_string[2 * length] = '\0';

    return hex_string;
}


// Function to generate a keypair
OQS_STATUS generate_keypair(OQS_SIG *sig, uint8_t **public_key, uint8_t **private_key) {
    OQS_STATUS rv;

    // Allocate memory for the public and private key
    *public_key = malloc(sig->length_public_key);
    *private_key = malloc(sig->length_secret_key);
    if (*public_key == NULL || *private_key == NULL) {
        return OQS_ERROR;
    }

    // Generate key pair
    rv = OQS_SIG_keypair(sig, *public_key, *private_key);
    return rv;
}

// Function to sign a message
OQS_STATUS sign_message(OQS_SIG *sig, const uint8_t *message, size_t message_len, uint8_t **signature, size_t *sig_len, const uint8_t *private_key) {
    OQS_STATUS rv;

    // Allocate memory for the signature based on the scheme's length
    *signature = malloc(sig->length_signature);
    if (*signature == NULL) {
        return OQS_ERROR;
    }

    // Sign the message
    *sig_len = sig->length_signature; // Set sig_len to the length of the signature
    rv = OQS_SIG_sign(sig, *signature, sig_len, message, message_len, private_key);
    if (rv != OQS_SUCCESS) {
        free(*signature);
        return rv;
    }

    return OQS_SUCCESS;
}

// Function to verify a signature
OQS_STATUS verify_signature(OQS_SIG *sig, const uint8_t *message, const uint8_t *signature, const uint8_t *public_key) {
    
    return OQS_SIG_verify(sig, message, strlen((const char *)message), signature, *signature, public_key);
}

// Function to encode data in Base64
char* encode_base64(const uint8_t *data, size_t data_len) {
    BIO *bio, *b64;
    BUF_MEM *bptr;
    char *buff;

    // Base64 encode the data
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data, data_len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';

    BIO_free_all(bio);
    return buff;
}

// Function to decode data from Base64
uint8_t* decode_base64(const char *data) {
    BIO *bio, *b64;
    size_t len = strlen(data);
    uint8_t *decoded_data = (uint8_t *)malloc(len);
    
    // Base64 decode the data
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(data, len);
    bio = BIO_push(b64, bio);
    
    BIO_read(bio, decoded_data, len);
    
    BIO_free_all(bio);
    return decoded_data;
}
