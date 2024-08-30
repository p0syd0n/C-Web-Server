// users.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <openssl/aes.h>
#include "users.h"
#include "../AES/aes.h"

#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 16
#define KEY_IV_FILE "/home/posydon/coding/Web Server C/src/AES/aes_key_iv.bin"

static User* users = NULL; // Global hash map

void read_key_iv_from_file(unsigned char *key, unsigned char *iv) {
    FILE *keyfile = fopen(KEY_IV_FILE, "rb");
    if (keyfile == NULL) {
        perror("Error opening key file");
        exit(EXIT_FAILURE);
    }
    fread(key, 1, AES_KEY_SIZE / 8, keyfile);
    fread(iv, 1, AES_BLOCK_SIZE, keyfile);
    fclose(keyfile);
}

void addUser(const char* username, const char* public_key) {
    // Define paths
    char nested_dir[256];
    char filename[256];
    snprintf(nested_dir, sizeof(nested_dir), "/home/posydon/coding/Web Server C/users/%s", username);
    snprintf(filename, sizeof(filename), "/home/posydon/coding/Web Server C/users/%s/data.txt", username);

    // Allocate memory for key and IV
    unsigned char key[AES_KEY_SIZE / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    read_key_iv_from_file(key, iv);

    // Allocate memory for ciphertext
    unsigned char ciphertext_username[256];
    unsigned char ciphertext_public_key[1024];
    memset(ciphertext_username, 0, sizeof(ciphertext_username));
    memset(ciphertext_public_key, 0, sizeof(ciphertext_public_key));

    // Encrypt the username and public key
    encrypt_aes((const unsigned char*)username, ciphertext_username, key, iv);
    encrypt_aes((const unsigned char*)public_key, ciphertext_public_key, key, iv);

    // Create the directory if it doesn't exist
    if (mkdir(nested_dir, 0755) != 0 && errno != EEXIST) {
        perror("Error creating nested directory");
        return;
    }

    // Create and open the file for writing
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Write encrypted data to the file
    fwrite(ciphertext_username, 1, sizeof(ciphertext_username), file);
    fwrite(ciphertext_public_key, 1, sizeof(ciphertext_public_key), file);

    // Close the file
    fclose(file);

    // Add user to hash map
    User* new_user = (User*)malloc(sizeof(User));
    if (new_user == NULL) {
        perror("Error allocating memory");
        return;
    }
    strncpy(new_user->username, username, sizeof(new_user->username) - 1);
    strncpy(new_user->public_key, public_key, sizeof(new_user->public_key) - 1);
    HASH_ADD_STR(users, username, new_user);

    printf("User added and file created successfully.\n");
}

void refreshUserHashMap() {
    // Clear existing hash map
    User *current_user, *tmp;
    HASH_ITER(hh, users, current_user, tmp) {
        HASH_DEL(users, current_user);
        free(current_user);
    }

    // Open directory and process each user
    DIR *dir;
    struct dirent *entry;

    if ((dir = opendir("users")) != NULL) {
        while ((entry = readdir(dir)) != NULL) {
            // Skip . and ..
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            char filename[256];
            snprintf(filename, sizeof(filename), "users/%s/data.txt", entry->d_name);

            // Read and decrypt user data
            FILE *file = fopen(filename, "rb");
            if (file == NULL) {
                perror("Error opening file");
                continue;
            }

            unsigned char key[AES_KEY_SIZE / 8];
            unsigned char iv[AES_BLOCK_SIZE];
            read_key_iv_from_file(key, iv);

            unsigned char encrypted_username[256];
            unsigned char encrypted_public_key[1024];
            memset(encrypted_username, 0, sizeof(encrypted_username));
            memset(encrypted_public_key, 0, sizeof(encrypted_public_key));

            fread(encrypted_username, 1, sizeof(encrypted_username), file);
            fread(encrypted_public_key, 1, sizeof(encrypted_public_key), file);

            fclose(file);

            char decrypted_username[256];
            char decrypted_public_key[1024];
            memset(decrypted_username, 0, sizeof(decrypted_username));
            memset(decrypted_public_key, 0, sizeof(decrypted_public_key));

            decrypt_aes(encrypted_username, decrypted_username, key, iv);
            decrypt_aes(encrypted_public_key, decrypted_public_key, key, iv);

            // Add decrypted user data to hash map
            addUser(decrypted_username, decrypted_public_key);
        }
        closedir(dir);
    } else {
        perror("Error opening directory");
    }
}
