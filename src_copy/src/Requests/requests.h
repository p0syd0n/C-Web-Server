#ifndef REQUESTS_H
#define REQUESTS_H

#include <openssl/ssl.h>
#include <openssl/err.h>

int parse_get_to_session(char *buffer, char **session_id);
int parse_post_to_creds(char* buffer, char** username, char** password);
char* getFile(char* name);

#endif
