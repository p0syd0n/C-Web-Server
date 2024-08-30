#ifndef UTILS_H
#define UTILS_H

#include <openssl/ssl.h>
#include <openssl/err.h>

void clean_string(char *str);
void extract_path(const char *buffer, char *path);
char* createResponse(const char* text);
char* createCookieRedirectResponse(const char* session_id, const char* redirect_location);
int sendResponse(char* response, SSL* ssl_connection);
void delete_directory_contents(const char *path);

#endif