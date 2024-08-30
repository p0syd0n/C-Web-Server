#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h> // For RAND_bytes()

int main() {
    // Define the length of the random bytes
    const size_t length = 64;
    unsigned char random_bytes[length];

    // Generate 64 random bytes
    if (RAND_bytes(random_bytes, length) != 1) {
        // RAND_bytes() returns 1 on success, 0 on failure
        fprintf(stderr, "Error generating random bytes\n");
        return 1;
    }

    // Print the random bytes in hexadecimal format
    printf("Random Bytes (Hex):\n");
    for (size_t i = 0; i < length; i++) {
        printf("%02x", random_bytes[i]);
        // if (i < length - 1) {
        //     printf(" ");
        // }
    }
    printf("\n");

    return 0;
}