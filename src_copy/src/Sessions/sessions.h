#ifndef SESSION_H
#define SESSION_H

#include <time.h>
#include "../uthash/include/uthash.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../Requests/requests.h"

#define SESSION_ID_LENGTH 64
#define SESSION_DURATION 3600

typedef struct {
    char session_id[SESSION_ID_LENGTH];
    char user_id[64];
    time_t expiration;
    UT_hash_handle hh;
} Session;

int isLoggedIn(char* buffer, char* session_id_);
void list_sessions();
void add_session(Session *session);
Session *create_session(const char *user_id);
Session *get_session(char *session_id);
void remove_session(const char *session_id);
void cleanup_sessions();


#endif
