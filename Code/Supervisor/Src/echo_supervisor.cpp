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
#define MAX_CLIENTS 100
#define REPORT_FILE "violation_report.txt"

struct StudentStats {
    string name;
    int totalViolations;
};

// Security Context for each client
struct ClientSession {
    bool isHandshakeComplete;
    string sessionKey;      // RC4 Key
    long long privateKeyD;  // RSA Private Key
    long long publicKeyN;   // RSA Public Key
};

map<uint32_t, StudentStats> violationRecords;
map<int, ClientSession> clientContext; // Maps Socket FD -> Session

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
    }
}

int main() {
    srand(time(0)); // Seed for RSA prime generation

    Dashboard dashboard;
    int master_socket, new_socket, client_socket[MAX_CLIENTS], max_sd, sd, valread;
    struct sockaddr_in address;
    char buffer[1025]; 

    for (int i = 0; i < MAX_CLIENTS; i++) client_socket[i] = 0;

    if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(PORT);

    if (::bind(master_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(master_socket, 5) < 0) {
        perror("Listen");
        exit(EXIT_FAILURE);
    }

    fd_set readfds;
    int addrlen = sizeof(address);

    dashboard.render();

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int activity = select(max_sd + 1, &readfds, NULL, NULL, &tv);

        if (dashboard.shouldRefresh()) dashboard.render();
        
        if (activity < 0 && errno != EINTR) perror("select error");
        if (activity == 0) continue;

        if (FD_ISSET(master_socket, &readfds)) {
            if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_socket[i] == 0) {
                    client_socket[i] = new_socket;
                    
                    // Initialize Client Context
                    clientContext[new_socket].isHandshakeComplete = false;
                    clientContext[new_socket].sessionKey = "";
                    
                    dashboard.updateConnection(true, inet_ntoa(address.sin_addr));
                    break;
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];
            if (FD_ISSET(sd, &readfds)) {
                if ((valread = read(sd, buffer, 1024)) == 0) {
                    close(sd);
                    client_socket[i] = 0;
                    clientContext.erase(sd); // Cleanup context
                    dashboard.updateConnection(false);
                } else {
                    int offset = 0;
                    while (offset < valread) {
                        Message msg;
                        
                        // Determine which key to use for deserialization
                        // If handshake not complete, we expect plaintext (key="")
                        // If handshake response, we expect plaintext wrapper, encrypted payload (key="")
                        // Once complete, we use the specific session key.
                        string decryptKey = clientContext[sd].isHandshakeComplete ? clientContext[sd].sessionKey : "";
                        
                        int bytesProcessed = deserialize(buffer + offset, &msg, decryptKey);
                        if (bytesProcessed <= 0 || (offset + bytesProcessed > valread)) break;
                        
                        offset += bytesProcessed;

                        msg.studentName[31] = '\0';
                        if (msg.dataLength < 512) msg.data[msg.dataLength] = '\0';
                        string sName(msg.studentName);

                        bool sendAck = false;
                        
                        switch (msg.msgType) {
                            // --- HANDSHAKE PROTOCOL START ---
                            case msgHandshakeInit: {
                                long long n, e, d;
                                GenerateRSAKeys(n, e, d);
                                
                                clientContext[sd].privateKeyD = d;
                                clientContext[sd].publicKeyN = n;
                                
                                // Send Public Key (N, E)
                                char payload[16];
                                memcpy(payload, &n, sizeof(long long));
                                memcpy(payload + sizeof(long long), &e, sizeof(long long));
                                
                                Message keyMsg = CreateMsg(msgHandshakeKey, msg.studentID, time(0), 0, payload, 16);
                                char respBuffer[1024];
                                int respSize = serialize(keyMsg, respBuffer, ""); // Plaintext
                                send(sd, respBuffer, respSize, 0);
                                break;
                            }
                            case msgHandshakeResponse: {
                                // Decrypt RSA Payload (msg.data contains sequence of long longs)
                                string recoveredKey = "";
                                int numChars = msg.dataLength / sizeof(long long);
                                char* ptr = msg.data;
                                
                                long long d = clientContext[sd].privateKeyD;
                                long long n = clientContext[sd].publicKeyN;

                                for(int k=0; k<numChars; k++) {
                                    long long encryptedChar;
                                    memcpy(&encryptedChar, ptr, sizeof(long long));
                                    ptr += sizeof(long long);
                                    
                                    char decryptedChar = (char)Power(encryptedChar, d, n);
                                    recoveredKey += decryptedChar;
                                }
                                
                                clientContext[sd].sessionKey = recoveredKey;
                                clientContext[sd].isHandshakeComplete = true;
                                
                                // Send ACK (Encrypted with new key)
                                Message ackMsg = CreateMsg(msgACK, msg.studentID, time(0), msg.sequenceNumber, NULL, 0);
                                char ackBuffer[1024];
                                int ackSize = serialize(ackMsg, ackBuffer, recoveredKey);
                                send(sd, ackBuffer, ackSize, 0);
                                break;
                            }
                            // --- HANDSHAKE PROTOCOL END ---

                            case msgViolation: {
                                string website(msg.data);
                                violationRecords[msg.studentID].name = sName;
                                violationRecords[msg.studentID].totalViolations++;
                                saveReport();
                                dashboard.recordViolation(msg.studentID, website);
                                sendAck = true;
                                break;
                            }
                            case msgHeartbeat: {
                                dashboard.updateHeartbeat(msg.studentID);
                                break;
                            }
                            case msgTamper: {
                                string alert(msg.data);
                                violationRecords[msg.studentID].name = sName;
                                violationRecords[msg.studentID].totalViolations++;
                                saveReport();
                                dashboard.recordTampering(msg.studentID);
                                sendAck = true;
                                break;
                            }
                            case msgTimeRequest: {
                                time_t serverTime = time(0);
                                string timeStr = to_string(serverTime);
                                
                                Message response = CreateMsg(msgTimeResponse, msg.studentID, serverTime, 0, timeStr.c_str(), timeStr.length());
                                
                                char respBuffer[1024];
                                int respSize = serialize(response, respBuffer, clientContext[sd].sessionKey);
                                send(sd, respBuffer, respSize, 0);
                                break;
                            }
                        }

                        if (sendAck) {
                            Message ackMsg = CreateMsg(msgACK, msg.studentID, time(0), msg.sequenceNumber, NULL, 0);
                            char ackBuffer[1024];
                            int ackSize = serialize(ackMsg, ackBuffer, clientContext[sd].sessionKey);
                            send(sd, ackBuffer, ackSize, 0);
                        }
                    }
                }
            }
        }
    }
    return 0;
}