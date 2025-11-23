#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace std;

int main() {
    int superSoc = socket(AF_INET, SOCK_STREAM, 0);
    if (superSoc < 0) {
        cout << "Socket creation failed" << endl;
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
    cout << "Listening for connections..." << endl;

    struct sockaddr_in student_addr;
    socklen_t student_addrLen = sizeof(student_addr);
    int client_socket = accept(superSoc, (struct sockaddr*)&student_addr, &student_addrLen);
    if (client_socket < 0) {
        cout << "Error accepting connection" << endl;
        close(superSoc);
        return 1;
    }
    cout << "Student connected successfully" << endl;

    char buffer[1024] = {0};
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        cout << "Error receiving message" << endl;
    } else {
        buffer[bytes_received] = '\0';
        cout << buffer << endl;
    }

    const char* response = "You are successfully connected to Argus.";
    ssize_t bytes_sent = send(client_socket, response, strlen(response), 0);
    if (bytes_sent < 0) {
        cout << "Error sending message" << endl;
    } else {
        cout << response << endl;
    }

    close(client_socket);
    close(superSoc);

    return 0;
}
