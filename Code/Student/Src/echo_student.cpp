#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

int main() {
    string studentName, studentID;
    cout << " Enter Your Name: ";
    getline(cin, studentName);
    cout << " Enter Your Student Id No: ";
    getline(cin, studentID);

    
    int studentsSoc = socket(AF_INET, SOCK_STREAM, 0);
    if (studentsSoc < 0) {
        cout << "Error creating socket" << endl;
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    
    string serverIP = "127.0.0.1";
    int ptonResult = inet_pton(AF_INET, serverIP.c_str(), &server_addr.sin_addr);
    
    if (ptonResult <= 0) {
        cout << "Invalid address" << endl;
        return -1;
    }

    if (connect(studentsSoc, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cout << "Connection failed" << endl;
        close(studentsSoc);
        return 1;
    }
    cout << "Connected to Supervisor server" << endl;

    string messageStr = "Good Morning Sir, I am " + studentName + " " + studentID;
    const char* message = messageStr.c_str();
    ssize_t bytes_sent = send(studentsSoc, message, strlen(message), 0);
    if (bytes_sent < 0) {
        cout << "Error sending message" << endl;
    }

    char buffer[1024] = {0};
    ssize_t bytes_received = recv(studentsSoc, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        cout << "Error receiving response" << endl;
    } else {
        buffer[bytes_received] = '\0';
        cout << "Response from server: " << buffer << endl;
    }

    cin.get();
    close(studentsSoc);

    return 0;
}
