#ifndef DILITHIUM_H
#define DILITHIUM_H

#include <oqs/oqs.h>
#include <stdint.h>
#include <stdlib.h>

// Function prototypes
OQS_STATUS generate_keypair(OQS_SIG *sig, uint8_t **public_key, uint8_t **private_key);
OQS_STATUS sign_message(OQS_SIG *sig, const uint8_t *message, size_t message_len, uint8_t **signature, size_t *sig_len, const uint8_t *private_key);
OQS_STATUS verify_signature(OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t sig_len, const uint8_t *public_key);
char* encode_base64(const uint8_t *data, size_t data_len);
uint8_t* decode_base64(const char *data, size_t *data_len);

#endif // DILITHIUM_H
