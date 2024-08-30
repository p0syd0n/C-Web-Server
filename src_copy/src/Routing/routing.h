#ifndef ROUTING_H
#define ROUTING_H

#include <openssl/ssl.h>
#include <openssl/err.h>

int homeRespond(SSL* ssl_socket, char* buffer);
int aboutRespond(SSL* ssl_socket);
int cheeseRespond(SSL* ssl_socket);
int executeLoginRespond(SSL* ssl_socket, char* buffer);
int loginRespond(SSL* ssl_socket, char* buffer);
int notFoundRespond(SSL* ssl_socket);

#endif
