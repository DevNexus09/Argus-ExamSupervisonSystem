#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <ctime>
#include "../../Common/include/protocol.h"

using namespace std;

#define PORT 8080
#define MAX_CLIENTS 30

int main() {
    // 1. Setup Connection
    int master_socket, new_socket, client_socket[MAX_CLIENTS], max_sd, sd, valread;
    struct sockaddr_in address;
    char buffer[1025]; 

    for (int i = 0; i < MAX_CLIENTS; i++) client_socket[i] = 0;

    if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Force reuse of port 8080 (Fixes "Address already in use" errors)
    int opt = 1;
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    address.sin_port = htons(PORT);

    if (::bind(master_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed (Port 8080 might be busy)");
        exit(EXIT_FAILURE);
    }

    if (listen(master_socket, 5) < 0) {
        perror("Listen");
        exit(EXIT_FAILURE);
    }

    cout << "--- SUPERVISOR SERVER STARTED ---" << endl;
    cout << "Listening for Student connections on 127.0.0.1:" << PORT << endl;

    fd_set readfds;
    int addrlen = sizeof(address);

    // 2. Main Loop
    while (true) {
        FD_ZERO(&readfds);
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        // Wait for activity
        select(max_sd + 1, &readfds, NULL, NULL, NULL);

        // New Connection
        if (FD_ISSET(master_socket, &readfds)) {
            if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }
            
            // Add to list
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_socket[i] == 0) {
                    client_socket[i] = new_socket;
                    cout << "[System] Student connected from Local Machine." << endl;
                    break;
                }
            }
        }

        // IO Operation on Clients
        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];
            if (FD_ISSET(sd, &readfds)) {
                if ((valread = read(sd, buffer, 1024)) == 0) {
                    getpeername(sd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                    close(sd);
                    client_socket[i] = 0;
                    cout << "[System] Student disconnected." << endl;
                } else {
                    Message msg;
                    deserialize(buffer, &msg);

                    if (VerifyChecksum(msg) && msg.msgType == msgViolation) {
                        time_t now = (time_t)msg.timestamp;
                        char* dt = ctime(&now);
                        if (dt) dt[strlen(dt) - 1] = '\0'; 

                        // PRINT ALERT
                        cout << "\n\033[1;31m[!!! VIOLATION ALERT !!!]\033[0m" << endl;
                        cout << "Student ID : " << msg.studentID << endl;
                        cout << "Website    : " << msg.data << endl;
                        cout << "Time       : " << (dt ? dt : "Unknown") << endl;
                        cout << "-------------------------" << endl;
                    }
                }
            }
        }
    }
    return 0;
}