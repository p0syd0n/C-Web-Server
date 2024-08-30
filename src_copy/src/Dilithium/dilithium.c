#include "dilithium.h"
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

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
OQS_STATUS verify_signature(OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t sig_len, const uint8_t *public_key) {
    return OQS_SIG_verify(sig, message, message_len, signature, sig_len, public_key);
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
uint8_t* decode_base64(const char *data, size_t *data_len) {
    BIO *bio, *b64;
    size_t len = strlen(data);
    uint8_t *decoded_data = (uint8_t *)malloc(len);
    
    // Base64 decode the data
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(data, len);
    bio = BIO_push(b64, bio);
    
    *data_len = BIO_read(bio, decoded_data, len);
    
    BIO_free_all(bio);
    return decoded_data;
}
