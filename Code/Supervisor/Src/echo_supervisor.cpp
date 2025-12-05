#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <fcntl.h>

using namespace std;

#define maxStudents 56

int main() {
    int superSoc = socket(AF_INET, SOCK_STREAM, 0);
    if (superSoc < 0) {
        cout << "Socket creation failed" << endl;
        return 1;
    }

    int opt = 1;
    if (setsockopt(superSoc, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cout << "setsockopt failed" << endl;
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8080);

    int bind_result = ::bind(superSoc, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (bind_result < 0) {
        cout << "Error binding socket to port 8080" << endl;
        close(superSoc);
        return 1;
    }

    int listen_result = listen(superSoc, 5);
    if (listen_result < 0) {
        cout << "Error listening on socket" << endl;
        close(superSoc);
        return 1;
    }
    cout << "Listening for connections on port 8080..." << endl;
    cout << "Type 'quit' and press Enter to close server" << endl;

    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

    int studentSoc[maxStudents];
    for (int i = 0; i < maxStudents; i++) {
        studentSoc[i] = 0;
    }

    fd_set readfds;
    char buffer[1024];
    bool server_running = true;

    while (server_running) {
        string input;
        getline(cin, input);
        if (input == "quit") {
            cout << "Shutting down server..." << endl;
            server_running = false;
            break;
        }

        FD_ZERO(&readfds);
        FD_SET(superSoc, &readfds);
        int max_sd = superSoc;

        for (int i = 0; i < maxStudents; i++) {
            int sd = studentSoc[i];

            if (sd > 0) {
                FD_SET(sd, &readfds);
            }

            if (sd > max_sd) {
                max_sd = sd;
            }
        }

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        int activity = select(max_sd + 1, &readfds, NULL, NULL, &timeout);

        if (activity < 0) {
            cout << "select error" << endl;
        }

        if (FD_ISSET(superSoc, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int new_socket = accept(superSoc, (struct sockaddr*)&client_addr, &client_len);

            if (new_socket < 0) {
                cout << "Error accepting connection" << endl;
                continue;
            }

            cout << "New student connected, socket fd: " << new_socket << endl;

            const char* welcome = "You are successfully connected to Argus.";
            send(new_socket, welcome, strlen(welcome), 0);

            for (int i = 0; i < maxStudents; i++) {
                if (studentSoc[i] == 0) {
                    studentSoc[i] = new_socket;
                    break;
                }
            }
        }

        for (int i = 0; i < maxStudents; i++) {
            int sd = studentSoc[i];

            if (FD_ISSET(sd, &readfds)) {
                memset(buffer, 0, sizeof(buffer));
                ssize_t bytes_read = recv(sd, buffer, sizeof(buffer) - 1, 0);

                if (bytes_read == 0) {
                    cout << "Student disconnected, socket fd: " << sd << endl;
                    close(sd);
                    studentSoc[i] = 0;
                } else if (bytes_read < 0) {
                    cout << "Error reading from socket " << sd << endl;
                    close(sd);
                    studentSoc[i] = 0;
                } else {
                    buffer[bytes_read] = '\0';
                    cout << "Message from socket " << sd << ": " << buffer << endl;
                    send(sd, buffer, bytes_read, 0);
                }
            }
        }
    }

    for (int i = 0; i < maxStudents; i++) {
        if (studentSoc[i] > 0) {
            close(studentSoc[i]);
        }
    }

    close(superSoc);

    return 0;
}
