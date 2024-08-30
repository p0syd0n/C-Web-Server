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

    char method[10], url[10000], httpVersion[10];
    char *urlStart = NULL, *urlEnd = NULL;
    char buffer[300000];
    
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
        int bytes_read = SSL_read(ssl , buffer, sizeof(buffer));

        if (bytes_read <= 0) {
            printf("SSL Handshake Failed.\n");
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(new_socket);
            continue;
        }
        printf("SSL Handshake successful\n");

        char *path = malloc(25600);
        extract_path(buffer, path);

        char *response_generated = malloc(50000);
        printf("BUFFER:\n%s", buffer);

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
        } else if (strcmp(path, "/sign_up") == 0) {
            signUpRespond(ssl);
        } else {
            notFoundRespond(ssl);
        }

        // Shutdown SSL connection and free the SSL object

        close(new_socket);
    }
}


int main() {
    // OQS_SIG *sig;

    // uint8_t *public_key = NULL;
    // uint8_t *private_key = NULL;

    // uint8_t *signature = NULL;
    // char *signature_hex = NULL;

    // size_t public_key_len, private_key_len, signature_len, message_len;

    // char *public_key_hex = NULL;
    // char *private_key_hex = NULL;

    // char* message_hex = malloc(129);
    // strcpy(message_hex, "9712f9098b85eb5b5b27676a257fb85b9e18590fe4a5ebb9cc5e034229b08125a0ae7e3c123fdb71ad6b880d603836a43cfe0fdafc185895cb577dc21de9d50c");
    // size_t length = 64;
    // uint8_t* message = hex_to_binary(message_hex, &length);
    
    //  // Initialize the signature scheme
    // sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2); // For example, Dilithium-2
    // if (sig == NULL) {
    //     printf("ERROR: Failed to initialize signature scheme\n");
    //     return 1;
    // }

    // // Generate key pair
    // if (generate_keypair(sig, &public_key, &private_key) != OQS_SUCCESS) {
    //     printf("ERROR: Generating key pair failed\n");
    //     OQS_SIG_free(sig);
    //     return 1;
    // }

    // // Convert public key to hexadecimal
    // public_key_hex = binary_to_hex(public_key, sig->length_public_key);
    // if (public_key_hex == NULL) {
    //     printf("ERROR: Converting public key to hex failed\n");
    //     OQS_SIG_free(sig);
    //     free(public_key);
    //     free(private_key);
    //     return 1;
    // }
    // printf("Public Key (Hex):\n%s\n", public_key_hex);
    // addUser("cheese", public_key_hex);

    // // Convert private key to hexadecimal
    // private_key_hex = binary_to_hex(private_key, sig->length_secret_key);
    // if (private_key_hex == NULL) {
    //     printf("ERROR: Converting private key to hex failed\n");
    //     OQS_SIG_free(sig);
    //     free(public_key);
    //     free(private_key);
    //     free(public_key_hex);
    //     return 1;
    // }
    // printf("Private Key (Hex):\n%s\n", private_key_hex);

    // // Sign the message
    // if (sign_message(sig, message, length, &signature, &signature_len, private_key) != OQS_SUCCESS) {
    //     printf("ERROR: Signing message failed\n");
    //     OQS_SIG_free(sig);
    //     free(public_key);
    //     free(private_key);
    //     free(public_key_hex);
    //     free(private_key_hex);
    //     return 1;
    // }

    // // Convert signature to hexadecimal
    // signature_hex = binary_to_hex(signature, signature_len);
    // if (signature_hex == NULL) {
    //     printf("ERROR: Converting signature to hex failed\n");
    //     OQS_SIG_free(sig);
    //     free(public_key);
    //     free(private_key);
    //     free(public_key_hex);
    //     free(private_key_hex);
    //     free(signature);
    //     return 1;
    // }
    // printf("Signature (Hex):\n%s\n", signature_hex);

    // // Clean up
    // free(public_key);
    // free(private_key);
    // free(signature);
    // free(public_key_hex);
    // free(private_key_hex);
    // free(signature_hex);
    // OQS_SIG_free(sig);

    const char *pem_file = "server.pem";

    struct Server server = server_constructor(AF_INET, SOCK_STREAM, 0, INADDR_ANY, 8086, 10, pem_file, pem_file, launch);
    server.launch(&server);
}
