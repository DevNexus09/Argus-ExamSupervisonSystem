#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <ctime>
#include <map>      
#include <fstream>  
#include "../../Common/include/protocol.h"
#include "../include/dashboard.h" 

using namespace std;

#define PORT 8080
#define MAX_CLIENTS 100 // Increased from 30 for better capacity
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
                    
                    dashboard.updateConnection(false);
                } else {
                    // Feature: Handle multiple messages in one packet (coalescing)
                    int offset = 0;
                    while (offset < valread) {
                        Message msg;
                        // deserialize returns bytes processed
                        int bytesProcessed = deserialize(buffer + offset, &msg);
                        
                        // Prevent infinite loop if deserialize fails or returns 0
                        if (bytesProcessed <= 0 || (offset + bytesProcessed > valread)) break;
                        
                        offset += bytesProcessed;

                        if (!VerifyChecksum(msg)) {
                            // Checksum failed, skip this message
                            continue;
                        }

                        // Ensure Safety
                        msg.studentName[31] = '\0';
                        if (msg.dataLength < 512) msg.data[msg.dataLength] = '\0';
                        
                        string sName(msg.studentName);

                        // --- FEATURE: Handle different message types ---
                        switch (msg.msgType) {
                            case msgViolation: {
                                string website(msg.data);
                                violationRecords[msg.studentID].name = sName;
                                violationRecords[msg.studentID].totalViolations++;
                                saveReport();
                                dashboard.recordViolation(msg.studentID, website);
                                break;
                            }
                            case msgHeartbeat: {
                                // Just update dashboard log/status
                                dashboard.updateHeartbeat(msg.studentID);
                                break;
                            }
                            case msgTamper: {
                                string alert(msg.data);
                                violationRecords[msg.studentID].name = sName;
                                // Tampering is serious, we count it
                                violationRecords[msg.studentID].totalViolations++;
                                saveReport();
                                dashboard.recordTampering(msg.studentID);
                                break;
                            }
                            default:
                                break;
                        }
                    }
                }
            }
        }
    }
    return 0;
}