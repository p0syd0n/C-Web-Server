#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include "routing.h"
#include "../Sessions/sessions.h"
#include "../Requests/requests.h"
#include "../Utils/utils.h"
#include "../Dilithium/dilithium.h"
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

int signUpRespond(SSL* ssl_socket) {
    char* fileContent = getFile("Static/sign_up.html");
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
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);

    uint8_t* public_key;
    char* public_key_hex = malloc(50000);

    char* signature_hex = malloc(50000);
    uint8_t* signature = malloc(50000);

    char* message_hex = malloc(129);
    printf("BOUTA STRCPY>\n");
    strcpy(message_hex, "9712f9098b85eb5b5b27676a257fb85b9e18590fe4a5ebb9cc5e034229b08125a0ae7e3c123fdb71ad6b880d603836a43cfe0fdafc185895cb577dc21de9d50c");
    printf("strcpied.\n");
    size_t message_length = 64;
    uint8_t* message = hex_to_binary(message_hex, &message_length);
    printf("hex to binaried.\n");

    char* username = malloc(50000);


    //printf("BUFFER:\n%s\n", buffer);
    parse_post_to_creds(buffer, &username, &signature_hex);
    printf("\nPArsed psot to signature and username. Results: \n usernamefrickyouarthur:\n%s\nsignature:\n%s\n", username, signature_hex);
    size_t signature_length = 2420;
    signature = hex_to_binary(signature_hex, &signature_length);
    get_user_public_key(username, public_key_hex);
    printf("Got user public key.\n");
    size_t public_key_length = 1312;
    public_key = hex_to_binary(public_key_hex, &public_key_length);
    printf("binarified public key\n");
    printf("result: %d\n", OQS_SIG_verify(sig, message, message_length, signature, signature_length, public_key));
    if (OQS_SIG_verify(sig, message, message_length, signature, signature_length, public_key) == OQS_SUCCESS) {
        
        printf("Passed verificiation.\n");
        Session* new_session = create_session(username);
        char* generated_response = createCookieRedirectResponse(new_session->session_id, "/");
        sendResponse(generated_response, ssl_socket);
    } else {
        sendResponse(createResponse("Invalid Credentials."), ssl_socket);
    }
    printf("done");

    OQS_SIG_free(sig);
    return 0;
}

int notFoundRespond(SSL* ssl_socket) {
    char* response = createResponse(getFile("Static/404.html"));
    return sendResponse(response, ssl_socket);
}