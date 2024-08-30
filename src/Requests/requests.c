#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "requests.h"

// Function to extract the public key from a response buffer
int parse_post_to_signature_username(const char* buffer, char* username, char* signature) {
    // Step 1: Find the start of the request body (after the headers)
    const char *body = strstr(buffer, "\r\n\r\n");
    if (body) {
        body += 4; // Move past the \r\n\r\n to get to the body content
    } else {
        fprintf(stderr, "Error: Could not find the start of the body.\n");
        return -1;
    }

    // Step 2: Find the colon that separates the username and signature
    const char *colon_pos = strchr(body, ':');
    if (!colon_pos) {
        fprintf(stderr, "Error: Could not find a colon in the body.\n");
        return -1;
    }

    // Step 3: Extract username (from body start to colon)
    size_t username_len = colon_pos - body;
    strncpy(username, body, username_len);
    username[username_len] = '\0'; // Null terminate the username string

    // Step 4: Extract signature (from colon to the end of the body)
    const char *signature_start = colon_pos + 1; // Skip past the colon
    strcpy(signature, signature_start); // Copy the rest of the body as the signature
}

int parse_get_to_session(char *buffer, char **session_id) {
    // Find the "Cookie" header in the request
    char *cookie_header = strstr(buffer, "Cookie:");
    if (!cookie_header) return -1;

    // Find the beginning of the session_id inside the Cookie header
    char *session_id_key = "session_id=";
    char *session_id_start = strstr(cookie_header, session_id_key);
    if (!session_id_start) return -1;

    // Move past the session_id key to get the value
    session_id_start += strlen(session_id_key);

    // Find the end of the session_id value (either the end of the cookies or a semicolon separator)
    char *session_id_end = strchr(session_id_start, ';');
    if (!session_id_end) {
        session_id_end = session_id_start + strlen(session_id_start);  // If no semicolon, assume it's the last cookie
    }

    // Calculate the session_id length
    size_t session_id_len = session_id_end - session_id_start;

    // Allocate memory for the session_id
    *session_id = malloc(session_id_len + 1);  // +1 for null terminator
    if (*session_id == NULL) return -1;

    // Copy the session_id value
    strncpy(*session_id, session_id_start, session_id_len);
    (*session_id)[session_id_len] = '\0';  // Null-terminate the string

    // Clean up the session_id to remove unwanted characters
    char *src = *session_id;
    char *dst = *session_id;

    // Remove non-printable characters and trim trailing whitespace
    while (*src) {
        if (isprint((unsigned char)*src)) {
            *dst++ = *src;
        }
        src++;
    }
    
    // Null-terminate the cleaned string
    *dst = '\0';

    // Trim trailing whitespace
    char *end = dst - 1;
    while (end > *session_id && isspace((unsigned char)*end)) end--;

    *(end + 1) = '\0';

    return 0;
}

int parse_post_to_creds(char* buffer, char** username, char** password) {
    printf("BUFFER RECIEVED:\n%s", buffer);
    // Find the beginning of the body after headers (headers end with \r\n\r\n)
    char *body_start = strstr(buffer, "\r\n\r\n");
    if (!body_start) return -1;

    // Move the pointer past the headers
    body_start += 4;  // Skip \r\n\r\n to get to the body

    // Extract the username and password from the POST body (assume format is username=...&password=...)
    char *username_key = "username=";
    char *password_key = "&password=";

    char *username_start = strstr(body_start, username_key);
    char *password_start = strstr(body_start, password_key);

    if (username_start == NULL || password_start == NULL) {
        return -1;
    }

    if (username_start && password_start) {
        // Move past the keys to get the values
        username_start += strlen(username_key);
        password_start += strlen(password_key);

        // Calculate the lengths of username and password
        size_t username_len = password_start - username_start - strlen(password_key);
        size_t password_len = strlen(password_start);

        // Allocate memory for username and password
        *username = malloc(username_len + 1);
        *password = malloc(password_len + 1);

        // Copy the data
        strncpy(*username, username_start, username_len);
        (*username)[username_len] = '\0';  // Null-terminate the string

        strcpy(*password, password_start);  // Copy the password directly
    } else {
        *username = NULL;
        *password = NULL;
    }
    return 0;
}

char* getFile(char* name) {
    FILE *fp = fopen(name, "r");
    if (fp == NULL) {
        perror("Error opening file\n");
        return "1";
    }

    // Determine size of file
    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    rewind(fp);

    // Allocate memory for file content
    char *fileContent = malloc(fileSize +1);
    if (fileContent == NULL) {
        perror("Memory allocation for reading file failed\n");
        return "1";
    }

    // Read entire file to allocated memory
    fread(fileContent, 1, fileSize, fp);
    fileContent[fileSize - 1] = '\0';

    fclose(fp);

    return fileContent;
}