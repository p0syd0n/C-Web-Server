#ifndef Server_h
#define Server_h

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct  Server 
{
    int domain;
    int protocol;
    int service;
    u_long interface;
    int port;
    int backlog;

    struct sockaddr_in address;

    SSL_CTX *ssl_ctx;  // SSL context
    SSL *ssl;          // SSL structure

    int socket;

    void (*launch)(struct Server *server);
};

struct Server server_constructor(int domain, int service, int protocol, u_long interface, int port, int backlog, const char *cert_file, const char *key_file, void (*launch)(struct Server *server));
#endif /* Server_h */