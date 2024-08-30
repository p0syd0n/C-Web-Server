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
#include "../Utils/utils.h"
#include <stdio.h>
#include <unistd.h>

#include <fcntl.h>
#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 16
#define KEY_IV_FILE "AES/aes_key_iv.bin"
#define SEPARATOR ':'
#define USER_DIR "../users/"
#define MAX_PATH_LEN 10024
#define PUBLIC_KEY_LEN 10024

static User* users = NULL; // Global hash map


// Function to check if a user exists and read their public key
int get_user_public_key(char *username, char *public_key) {
    // Construct the full path to the user directory
    char user_dir[256];
    sprintf(user_dir, "../users/%s", username);

    // Check if the user directory exists
    struct stat sb;
    if (stat(user_dir, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
        printf("User directory '%s' does not exist\n", user_dir);
        return -1;
    }

    // Construct the full path to the data file
    char data_file[4096];
    sprintf(data_file, "%s/data.txt", user_dir);

    // Open the data file for reading
    int fd = open(data_file, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open data file");
        return -1;
    }

    // Read the contents of the file
    char buffer[4096];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        perror("Failed to read from data file");
        close(fd);
        return -1;
    }
    buffer[bytes_read] = '\0';

    // Parse the username and public key from the file content
    char *ptr = strtok(buffer, ":");
    if (ptr == NULL || strcmp(ptr, username) != 0) {
        printf("Username mismatch in data file\n");
        close(fd);
        return -1;
    }

    ptr = strtok(NULL, ":");
    if (ptr == NULL) {
        printf("Public key not found in data file\n");
        close(fd);
        return -1;
    }

    strcpy(public_key, ptr);

    // Close the file descriptor
    close(fd);
    return 0;
}




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

/* THIS IS HOT GARBAGE. 
Wrong final block length.
Implementing a plaintext user data storage system for now.



void addUser(char *username, char *public_key) {
    unsigned char key[AES_KEY_SIZE / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plaintext[10024];
    unsigned char ciphertext[10024];
    unsigned char decrypted[10024];
    int ciphertext_len, decrypted_len;
    char directory[256];
    char filepath[256];
    FILE *file;

    // Read key and IV from file
    read_key_iv_from_file(key, iv);

    // Concatenate username and public_key with a separator
    snprintf((char *)plaintext, sizeof(plaintext), "%s%c%s", username, SEPARATOR, public_key);

    // Encrypt the concatenated string
    encrypt_aes(plaintext, ciphertext, key, iv);

    // Create or clean up the directory for the user
    snprintf(directory, sizeof(directory), "%s%s", USER_DIR, username);
    if (access(directory, F_OK) == 0) {
        // Directory exists, delete its contents
        delete_directory_contents(directory);
    } else {
        // Directory does not exist, create it
        if (mkdir(directory, 0700) != 0) {
            perror("Error creating directory");
            exit(EXIT_FAILURE);
        }
    }

    // Write the encrypted data to data.txt
    snprintf(filepath, sizeof(filepath), "%s/data.txt", directory);
    file = fopen(filepath, "wb");
    if (file == NULL) {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);
    }
    ciphertext_len = strlen((const char *)ciphertext); // Determine actual length of ciphertext
    fwrite(ciphertext, 1, ciphertext_len, file);
    fclose(file);

    // Read encrypted data from data.txt
    file = fopen(filepath, "rb");
    if (file == NULL) {
        perror("Error opening file for reading");
        exit(EXIT_FAILURE);
    }
    ciphertext_len = fread(ciphertext, 1, sizeof(ciphertext), file);
    fclose(file);

    // Decrypt the data
    decrypt_aes(ciphertext, decrypted, key, iv);

    // Extract username and public key from decrypted data
    char *sep_pos = strchr((char *)decrypted, SEPARATOR);
    if (sep_pos != NULL) {
        *sep_pos = '\0';
        printf("Decrypted Username: %s\n", decrypted);
        printf("Decrypted Public Key: %s\n", sep_pos + 1);
    } else {
        fprintf(stderr, "Separator not found in decrypted data.\n");
    }

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
*/

void addUser(char *username, char *public_key) {
    char cwd[1024];
    
    // Get the current working directory
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        // Print the current working directory
        printf("Current working directory: %s\n", cwd);
    } else {
        // Handle error
        perror("getcwd() error");
        return ;
    }
    char directory[256];
    char filepath[256];
    FILE *file;
    char data[100024]; // Buffer to hold concatenated data

    // Concatenate username and public_key with a separator
    snprintf(data, sizeof(data), "%s%c%s", username, SEPARATOR, public_key);
    printf("DATA TO BE ADDED TO THE FULE:\n%s\n", data);

    // Create or clean up the directory for the user
    snprintf(directory, sizeof(directory), "%s%s", USER_DIR, username);
    printf("DIRECTORY: \n%s\n", directory);
    // if (access(directory, F_OK) == 0) {
    //     // Directory exists, delete its contents
    //     delete_directory_contents(directory);
    // } else {
        // Directory does not exist, create it
        if (mkdir(directory, 0700) != 0) {
            perror("Error creating directory");
            exit(EXIT_FAILURE);
        }
    // }
    printf("At this point we should have an empty %s directory\n", username);

    // Write the plaintext data to data.txt
    snprintf(filepath, sizeof(filepath), "%s/data.txt", directory);
    printf("FILEPATH: %s\n", filepath);
    file = fopen(filepath, "wb");
    if (file == NULL) {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);
    }
    fwrite(data, 1, strlen(data), file);
    fclose(file);
    printf("Wrote data to file\n");


    // Add user to hash map
    User *new_user = (User*)malloc(sizeof(User));
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
