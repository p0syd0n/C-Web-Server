#ifndef DILITHIUM_H
#define DILITHIUM_H

#include <oqs/oqs.h>
#include <stdint.h>
#include <stdlib.h>

// Function prototypes
uint8_t* text_to_binary(const char* text, size_t* length);
char *binary_to_hex(const uint8_t *binary_data, size_t length);
uint8_t *hex_to_binary(char *hex_str, size_t *binary_len);
OQS_STATUS generate_keypair(OQS_SIG *sig, uint8_t **public_key, uint8_t **private_key);
OQS_STATUS sign_message(OQS_SIG *sig, const uint8_t *message, size_t message_len, uint8_t **signature, size_t *sig_len, const uint8_t *private_key);
OQS_STATUS verify_signature(OQS_SIG *sig, const uint8_t *message, const uint8_t *signature, const uint8_t *public_key);
char* encode_base64(const uint8_t *data, size_t data_len);
uint8_t* decode_base64(const char *data);

#endif // DILITHIUM_H
