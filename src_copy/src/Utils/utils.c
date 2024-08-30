#include <stdio.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>



void clean_string(char *str) {
    char *src = str;
    char *dst = str;
    char *end;

    // Trim leading whitespace
    while (isspace((unsigned char)*src)) src++;

    if (*src == 0) { // If the string is empty after trimming
        *str = '\0';
        return;
    }

    // Remove non-printable characters and trim trailing whitespace
    while (*src) {
        if (isprint((unsigned char)*src)) {
            *dst++ = *src;
        }
        src++;
    }
    
    // Null-terminate the resulting string
    *dst = '\0';

    // Trim trailing whitespace
    end = dst - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    *(end + 1) = '\0';
}



void extract_path(const char *buffer, char *path) {
    const char *start = strchr(buffer, ' ');
    if (start) {
        start++; // Move past the first space
        const char *end = strchr(start, ' ');
        if (end) {
            size_t len = end - start;
            strncpy(path, start, len < 50 ? len : 50 - 1);
            path[50 - 1] = '\0';  // Ensure null-termination

            path[len] = '\0';
        } else {
            strcpy(path, ""); // No valid path found
        }
    } else {
        strcpy(path, ""); // No method or space found
    }
}

char* createResponse(const char* text) {
    size_t text_len = strlen(text);
    // Base header template
    const char* base_header_template = 
        "HTTP/1.1 200 OK\nDate: Mon, 27 Jul 2009 12:28:53 GMT\nServer: Custom Server\nContent-Length: %zu\nContent-Type: text/html\nConnection: Closed\n\r\n";

    size_t header_len = snprintf(NULL, 0, base_header_template, text_len);
    size_t response_len = header_len + text_len + 1;  // +1 for null terminator

    char* response = malloc(response_len);
    if (response == NULL) {
        perror("Memory allocation failed");
        return NULL;
    }

    snprintf(response, response_len, base_header_template, text_len);
    strcat(response, text);

    return response;
}

// Response with Cookie and Redirection
char* createCookieRedirectResponse(const char* session_id, const char* redirect_location) {
    // Redirect with Set-Cookie header
    const char* redirect_template = 
        "HTTP/1.1 302 Found\nLocation: %s\nSet-Cookie: session_id=%s; HttpOnly; Path=/; Secure; SameSite=Strict\nConnection: Closed\n\r\n";

    size_t header_len = snprintf(NULL, 0, redirect_template, redirect_location, session_id);
    size_t response_len = header_len + 1;  // +1 for null terminator

    char* response = malloc(response_len);
    if (response == NULL) {
        perror("Memory allocation failed");
        return NULL;
    }

    snprintf(response, response_len, redirect_template, redirect_location, session_id);

    return response;
}


int sendResponse(char* response, SSL* ssl_socket) {
    // Calculate the length of the response
    size_t responseLength = strlen(response);
    
    // Attempt to write the response
    ssize_t bytesWritten = SSL_write(ssl_socket, response, responseLength);
    
    if (bytesWritten <= 0) {
        int err = SSL_get_error(ssl_socket, bytesWritten);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            // Retry the operation
            return 0;
        } else {
            ERR_print_errors_fp(stderr);
            return -1;
        }
    } else if ((size_t)bytesWritten != responseLength) {
        printf("Partial write: wrote %zd of %zu bytes.\n", bytesWritten, responseLength);
    } else if ((size_t)bytesWritten == responseLength) {
        printf(" [+] Successful write.\n");
    }
    
    // Close the SSL connection
    SSL_shutdown(ssl_socket);
    SSL_free(ssl_socket);
    return 1;
}
