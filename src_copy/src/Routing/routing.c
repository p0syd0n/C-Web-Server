#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include "routing.h"
#include "../Sessions/sessions.h"
#include "../Requests/requests.h"
#include "../Utils/utils.h"
#include "../Users/users.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

int cheeseRespond(SSL* ssl_socket) {
    char* response = createResponse("Cheeseererere!!!");
    return sendResponse(response, ssl_socket);
}

int homeRespond(SSL* ssl_socket, char* buffer) {
    int clientLoggedIn = isLoggedIn(buffer, NULL);
    if (clientLoggedIn == 0) {
        // Proceed with the response
        char* response = createResponse(getFile("Static/home.html"));
        int result = sendResponse(response, ssl_socket);
    } else if (clientLoggedIn == -1) {
        sendResponse(createCookieRedirectResponse("", "/login"), ssl_socket);
    }
}


int aboutRespond(SSL* ssl_socket) {
    char* fileContent = getFile("Static/about.html");
    char* response = createResponse(fileContent);
    free(fileContent);
    return sendResponse(response, ssl_socket);
}

int loginRespond(SSL* ssl_socket, char* buffer) { 
    char* session_id = malloc(SESSION_ID_LENGTH + 1);

    int clientLoggedIn = isLoggedIn(buffer, session_id);

    if (clientLoggedIn == 0) {
        // Proceed with the response
        return sendResponse(createCookieRedirectResponse(session_id, "/"), ssl_socket);

    } else if (clientLoggedIn == -1) {
        // Redirect to /login with empty session cookie
        char* response = createResponse(getFile("Static/login.html"));
        return sendResponse(response, ssl_socket);    
    }
}

int executeLoginRespond(SSL* ssl_socket, char* buffer) {
    char* username = NULL;
    char* password = NULL;
    if (parse_post_to_creds(buffer, &username, &password) == -1) {
        return sendResponse(createResponse("400 - Bad Request"), ssl_socket);
    };

    printf("Creds recieved: %s %s \n", username, password);
    
    if ((strcmp(username, "admin") == 0) && strcmp(password, "admin") == 0) {
        printf("Passed verificiation.\n");
        Session* new_session = create_session("admin");
        list_sessions();
        printf("Created session with session id %s\n", new_session->session_id);
        printf("Generated session ID length: %zu, ID: %s\n", strlen(new_session->session_id), new_session->session_id);
        char* generated_response = createCookieRedirectResponse(new_session->session_id, "/");
        printf("Generated Response.: \n %s\n", generated_response);
        sendResponse(generated_response, ssl_socket);

    } else {
        sendResponse(createResponse("Invalid Credentials."), ssl_socket);
    }
    
    free(username);
    free(password);
    return 0;
}

int notFoundRespond(SSL* ssl_socket) {
    char* response = createResponse(getFile("Static/404.html"));
    return sendResponse(response, ssl_socket);
}