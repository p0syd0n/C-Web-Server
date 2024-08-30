#include <stdio.h>

#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "Routing/routing.h"
#include "Utils/utils.h"
#include "Networking/Server.h"
#include "Users/users.h"
#include "Dilithium/dilithium.h"
#include <oqs/oqs.h>

void launch(struct Server *server) {

    char method[10], url[100], httpVersion[10];
    char *urlStart = NULL, *urlEnd = NULL;
    char buffer[30000];
    
    while (1) {
        printf("==== Waiting for connection ====\n");
        
        int address_length = sizeof(server->address);
        int new_socket = accept(server->socket, (struct sockaddr *)&server->address, (socklen_t *)&address_length);
        
        if (new_socket < 0) {
            perror("Failed to accept connection");
            continue;
        }
        
        // Create an SSL object and associate it with the accepted socket
        SSL *ssl = SSL_new(server->ssl_ctx);
        SSL_set_fd(ssl, new_socket);
        printf("Accepted ssl\n");

        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            printf("ERROR\n");
            close(new_socket);
            SSL_free(ssl);
            continue;
        }

        memset(buffer, 0, sizeof(buffer));
        // Use SSL_read instead of read
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));

        if (bytes_read <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(new_socket);
            continue;
        }

        char *path = malloc(256);
        extract_path(buffer, path);

        char *response_generated = malloc(50000);

        if (strcmp(path, "/") == 0) {
            homeRespond(ssl, buffer);
        } else if (strcmp(path, "/about") == 0) {
            aboutRespond(ssl);
        } else if (strcmp(path, "/cheese") == 0) {
            cheeseRespond(ssl);
        } else if (strcmp(path, "/executeLogin") == 0) {
            executeLoginRespond(ssl, buffer);
        } else if (strcmp(path, "/login") == 0) {
            printf("Log in requested.\n");
            loginRespond(ssl, buffer);
        } else {
            notFoundRespond(ssl);
        }

        // Shutdown SSL connection and free the SSL object

        close(new_socket);
    }
}


int main() {
    OQS_SIG *sig;
    uint8_t *public_key = NULL;
    uint8_t *private_key = NULL;
    char *public_key_b64 = NULL;

    // Initialize the signature scheme
    sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2); // For example, Dilithium-2
    if (sig == NULL) {
        printf("ERROR: Failed to initialize signature scheme\n");
        return 1;
    }

    // Generate key pair
    if (generate_keypair(sig, &public_key, &private_key) != OQS_SUCCESS) {
        printf("ERROR: Generating key pair failed\n");
        OQS_SIG_free(sig);
        return 1;
    }

    // Encode public key to Base64
    public_key_b64 = encode_base64(public_key, sig->length_public_key);
    if (public_key_b64 == NULL) {
        printf("ERROR: Base64 encoding failed\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(private_key);
        return 1;
    }

    // Output the Base64 encoded public key
    printf("Public Key (Base64):\n%s\n", public_key_b64);
    printf("Printed\n");

    // Clean up
    free(public_key);
    free(private_key);
    free(public_key_b64);
    OQS_SIG_free(sig);


    addUser("admin", "pubKey");
    const char *pem_file = "server.pem";

    struct Server server = server_constructor(AF_INET, SOCK_STREAM, 0, INADDR_ANY, 8086, 10, pem_file, pem_file, launch);
    server.launch(&server);
}
