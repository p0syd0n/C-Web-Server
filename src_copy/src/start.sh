gcc -o main main.c AES/aes.c Networking/Server.c Users/users.c Sessions/sessions.c Routing/routing.c Requests/requests.c Utils/utils.c Dilithium/dilithium.c -I src -I Networking -I Dilithium -I Sessions -I Routing -I Requests -I Utils -I AES -I Users -I liboqs/build/include -L liboqs/build/lib -lssl -lcrypto -loqs