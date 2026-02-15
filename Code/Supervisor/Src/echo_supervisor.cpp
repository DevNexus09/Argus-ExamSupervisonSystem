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

map<uint32_t, StudentStats> violationRecords;

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
                    dashboard.updateConnection(false);
                } else {
                    int offset = 0;
                    while (offset < valread) {
                        Message msg;
                        int bytesProcessed = deserialize(buffer + offset, &msg);
                        if (bytesProcessed <= 0 || (offset + bytesProcessed > valread)) break;
                        
                        offset += bytesProcessed;

                        if (!VerifyChecksum(msg)) {
                            // DEBUGGING LINE: UNCOMMENT IF STILL FAILING
                            // cerr << "[DEBUG] Checksum Failed! MsgType: " << (int)msg.msgType << endl;
                            continue;
                        }

                        msg.studentName[31] = '\0';
                        if (msg.dataLength < 512) msg.data[msg.dataLength] = '\0';
                        string sName(msg.studentName);

                        bool sendAck = false;
                        switch (msg.msgType) {
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
                        }

                        if (sendAck) {
                            Message ackMsg = CreateMsg(msgACK, msg.studentID, time(0), msg.sequenceNumber, NULL, 0);
                            char ackBuffer[1024];
                            int ackSize = serialize(ackMsg, ackBuffer);
                            send(sd, ackBuffer, ackSize, 0);
                        }
                    }
                }
            }
        }
    }
    return 0;
}