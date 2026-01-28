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
#include "../include/dashboard.h" // Include the separate dashboard module

using namespace std;

#define PORT 8080
#define MAX_CLIENTS 30

int main() {
    // Initialize Dashboard
    Dashboard dashboard;

    // 1. Setup Connection
    int master_socket, new_socket, client_socket[MAX_CLIENTS], max_sd, sd, valread;
    struct sockaddr_in address;
    char buffer[1025]; 

    for (int i = 0; i < MAX_CLIENTS; i++) client_socket[i] = 0;

    if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Force reuse of port
    int opt = 1;
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(PORT);

    if (::bind(master_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed (Port 8080 might be busy)");
        exit(EXIT_FAILURE);
    }

    if (listen(master_socket, 5) < 0) {
        perror("Listen");
        exit(EXIT_FAILURE);
    }

    fd_set readfds;
    int addrlen = sizeof(address);

    // Initial render
    dashboard.render();

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

        // Timeout for select (1 second) to allow non-blocking dashboard refresh
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int activity = select(max_sd + 1, &readfds, NULL, NULL, &tv);

        // Check dashboard refresh timer
        if (dashboard.shouldRefresh()) {
            dashboard.render();
        }

        if ((activity < 0) && (errno != EINTR)) {
            perror("select error");
        }
        
        // If timeout occurred (activity == 0), just continue loop to check timer again
        if (activity == 0) continue;

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
                    // Update Dashboard: Connection Added
                    dashboard.updateConnection(true, inet_ntoa(address.sin_addr));
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
                    
                    // Update Dashboard: Connection Removed
                    dashboard.updateConnection(false);
                } else {
                    Message msg;
                    // We deserialize to get the raw message data
                    deserialize(buffer, &msg);

                    if (VerifyChecksum(msg) && msg.msgType == msgViolation) {
                        // Ensure null termination for the website string
                        if (msg.dataLength < 512) msg.data[msg.dataLength] = '\0';
                        string website(msg.data);
                        
                        // Update Dashboard: Violation Recorded
                        dashboard.recordViolation(msg.studentID, website);
                        
                        // Force immediate render on violation? 
                        // Optional, but user asked for 5 sec refresh. 
                        // We stick to timer, but update log immediately if we wanted.
                    }
                }
            }
        }
    }
    return 0;
}