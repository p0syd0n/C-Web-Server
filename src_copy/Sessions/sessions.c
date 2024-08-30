#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include "sessions.h"
#include "../uthash/include/uthash.h"

#define SESSION_ID_LENGTH 64
#define SESSION_DURATION 3600

// Session related functions

// Define the hash table
Session *sessions = NULL;

int isLoggedIn(char* buffer, char* session_id_) {
    printf("[+] Checking log in status. \n");

    // Allocate memory for the session_id (+1 for null terminator)
    char* session_id = malloc(SESSION_ID_LENGTH + 1);
    if (!session_id) {
        perror("[-] Failed to allocate memory for session ID");
        return -1;
    }

    // Call the parsing function to extract session ID from buffer
    int parse_result = parse_get_to_session(buffer, &session_id);

    // If session_id_ is provided, copy the session ID to it
    if (session_id_ != NULL) {
        strcpy(session_id_, session_id);
    }

    // If the parsing succeeded (session ID was found)
    if (parse_result == 0) {
        printf("[+] User has session in cookies: %s\n", session_id);

        // Check if session exists in the hash table
        Session* user_session = get_session(session_id);
        if (user_session == NULL) {
            printf("[+] Client browser session not found in hash table. Not logged in.\n");
            free(session_id);  // Free allocated memory before returning
            return -1;
        }

        free(session_id);  // Free allocated memory before returning
        return 0;
    } else {
        // If parsing failed or session ID wasn't found
        printf("[+] Session ID not found in cookies. Not logged in.\n");
        free(session_id);  // Free allocated memory before returning
        return -1;
    }
}


// Function to list all sessions
void list_sessions() {
    Session *session, *tmp;

    // Start iterating through the hash table
    printf("Listing all sessions:\n");
    HASH_ITER(hh, sessions, session, tmp) {
        printf("Session ID: %s\n", session->session_id);
        printf("User ID: %s\n", session->user_id);
        printf("Expiration: %s\n", ctime(&(session->expiration)));
        printf("------\n");
    }
}

// Function to generate a random session ID
void generate_session_id(char *session_id, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (RAND_bytes((unsigned char *)session_id, length - 1) != 1) {
        perror("Random number generation failed");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < length - 1; ++i) {
        session_id[i] = charset[session_id[i] % (sizeof(charset) - 1)];
    }
    session_id[length - 1] = '\0';
}

// Function to add a session to the hash table
void add_session(Session *session) {
    Session *entry = (Session *)malloc(sizeof(Session));
    if (entry == NULL) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
    *entry = *session;  // Copy the session data
    HASH_ADD_STR(sessions, session_id, entry);
}

// Function to generate a new session
Session *create_session(const char *user_id) {
    Session *session = (Session *)malloc(sizeof(Session));
    if (session == NULL) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    // Generate a random session_id
    generate_session_id(session->session_id, SESSION_ID_LENGTH);

    // Copy the user_id into the session struct
    strncpy(session->user_id, user_id, sizeof(session->user_id) - 1);
    session->user_id[sizeof(session->user_id) - 1] = '\0'; // Null-terminate

    // Set expiration time to 1 hour from now
    session->expiration = time(NULL) + SESSION_DURATION;
    printf("session ID length (In creation): %zu, ID: %s\n", strlen(session->session_id), session->session_id);
    // Add the session to the hash table
    add_session(session);

    return session;
}

// Function to get a session by ID
Session *get_session(char *session_id) {
    Session *entry;
    HASH_FIND_STR(sessions, session_id, entry);
    return entry; // Returns NULL if not found
}

// Function to remove a session by ID
void remove_session(const char *session_id) {
    Session *entry;
    HASH_FIND_STR(sessions, session_id, entry);
    if (entry) {
        HASH_DEL(sessions, entry);
        free(entry);
    }
}

// Function to clean up expired sessions
void cleanup_sessions() {
    time_t now = time(NULL);
    Session *entry, *tmp;

    HASH_ITER(hh, sessions, entry, tmp) {
        if (entry->expiration < now) {
            HASH_DEL(sessions, entry);
            free(entry);
        }
    }
}