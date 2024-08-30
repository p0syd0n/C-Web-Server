#include "Server.h"
#include <stdio.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>

// Initialize the SSL context
SSL_CTX *initialize_ssl_context() {
    SSL_CTX *ctx;

    // Load OpenSSL algorithms and error strings
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create an SSL context using TLS method
    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    return ctx;
}

// Configure the SSL context with the server's certificate and private key
void configure_ssl_context(SSL_CTX *ctx, const char *cert_file, const char *key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(1);
    }
}

struct Server server_constructor(int domain, int service, int protocol, u_long interface, int port, int backlog,
                                 const char *cert_file, const char *key_file,
                                 void(*launch)(struct Server *server)) {
    struct Server server;

    server.domain = domain;
    server.service = service;
    server.protocol = protocol;
    server.interface = interface;
    server.port = port;
    server.backlog = backlog;
    
    server.address.sin_family = domain;
    server.address.sin_port = htons(port);
    server.address.sin_addr.s_addr = htonl(interface);

    server.socket = socket(domain, service, protocol);
    int option = 1;
    setsockopt(server.socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    if (server.socket == 0) {
        perror("Failed to create socket ... \n");
        exit(1);
    }

    if (bind(server.socket, (struct sockaddr *)&server.address, sizeof(server.address)) < 0) {
        perror("Failed to bind socket...\n");
        exit(1);
    }

    if (listen(server.socket, server.backlog) < 0) {
        perror("Failed to start listening...\n");
        exit(1);
    }

    // Initialize SSL context and configure with certificates
    server.ssl_ctx = initialize_ssl_context();
    configure_ssl_context(server.ssl_ctx, cert_file, key_file);

    server.launch = launch;

    return server;
}