#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <fcntl.h>
#include <ctime>
#include "../../Common/include/protocol.h"

using namespace std;

#define maxStudents 56

int main() {
    int master_socket = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    bind(master_socket, (struct sockaddr*)&address, sizeof(address));
    listen(master_socket, 5);

    int client_sockets[maxStudents];
    for (int i = 0; i < maxStudents; i++) client_sockets[i] = 0;

    fd_set readfds;

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(master_socket, &readfds);
        int max_sd = master_socket;

        for (int i = 0; i < maxStudents; i++) {
            int sd = client_sockets[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if (FD_ISSET(master_socket, &readfds)) {
            int new_socket = accept(master_socket, NULL, NULL);
            for (int i = 0; i < maxStudents; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    break;
                }
            }
        }

        for (int i = 0; i < maxStudents; i++) {
            int sd = client_sockets[i];

            if (FD_ISSET(sd, &readfds)) {
                char buffer[1024];
                int valread = recv(sd, buffer, 1024, 0);

                if (valread == 0) {
                    close(sd);
                    client_sockets[i] = 0;
                } else {
                    Message msg;
                    deserialize(buffer, &msg);

                    if (VerifyChecksum(msg)) {
                        if (msg.msgType == msgViolation) {
                            cout << "VIOLATION ALERT" << endl;
                            cout << "Student ID: " << msg.studentID << endl;
                            cout << "Website: " << msg.data << endl;
                            cout << "Time: " << msg.timestamp << endl;
                        } 
                    } else {
                        cout << "Raw Message: " << buffer << endl;
                    }
                }
            }
        }
    }

    return 0;
}