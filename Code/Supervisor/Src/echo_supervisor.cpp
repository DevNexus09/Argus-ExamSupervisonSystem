#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <ctime>
#include <map>      // Added for tracking violations
#include <fstream>  // Added for file I/O
#include "../../Common/include/protocol.h"
#include "../include/dashboard.h" 

using namespace std;

#define PORT 8080
#define MAX_CLIENTS 30
#define REPORT_FILE "violation_report.txt"

// Structure to hold student stats
struct StudentStats {
    string name;
    int totalViolations;
};

// Map to store stats by Student ID
map<uint32_t, StudentStats> violationRecords;

// Function to save the report to a text file
void saveReport() {
    ofstream file(REPORT_FILE);
    if (file.is_open()) {
        file << "Student Name, Student ID, Total Violations" << endl;
        for (const auto& entry : violationRecords) {
            file << entry.second.name << ", " 
                 << entry.first << ", " 
                 << entry.second.totalViolations << endl;
        }
        file.close();
        // Optional: cout << "[System] Violation report updated." << endl;
    } else {
        cerr << "[Error] Unable to write to " << REPORT_FILE << endl;
    }
}

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
                        
                        // --- NEW FEATURE IMPLEMENTATION ---
                        // 1. Update In-Memory Records
                        // Ensure null termination for student name (safety)
                        msg.studentName[31] = '\0'; 
                        string sName(msg.studentName);

                        violationRecords[msg.studentID].name = sName;
                        violationRecords[msg.studentID].totalViolations++;

                        // 2. Save to File
                        saveReport();
                        // ----------------------------------

                        // Update Dashboard: Violation Recorded
                        dashboard.recordViolation(msg.studentID, website);
                    }
                }
            }
        }
    }
    return 0;
}