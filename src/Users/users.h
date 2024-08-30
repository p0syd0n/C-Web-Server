// users.h
#ifndef USERS_H
#define USERS_H

#include "../uthash/include/uthash.h"

typedef struct {
    char username[256];  // Assuming max username length is 255
    char public_key[1024]; // Adjust size as needed
    UT_hash_handle hh; // Makes this structure hashable
} User;

void addUser(char* username, char* public_key);
void refreshUserHashMap();
void read_key_iv_from_file(unsigned char *key, unsigned char *iv);
int get_user_public_key(char *username, char *public_key);

#endif
