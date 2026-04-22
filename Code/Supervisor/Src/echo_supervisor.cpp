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
#include <thread>
#include <atomic>

#include <GLFW/glfw3.h>
#include "../../Common/imgui/imgui.h"
#include "../../Common/imgui/backends/imgui_impl_glfw.h"
#include "../../Common/imgui/backends/imgui_impl_opengl3.h"

#include "../../Common/include/protocol.h"
#include "../include/dashboard.h"

using namespace std;
#define PORT 8080
#define MAX_CLIENTS 100
#define REPORT_FILE "violation_report_raw.txt"

struct StudentStats {
    string name;
    int totalViolations;
};

struct ClientSession {
    bool isHandshakeComplete;
    string sessionKey;
    long long privateKeyD;
    long long publicKeyN;
    uint32_t studentID;
};

map<uint32_t, StudentStats> violationRecords;
map<int, ClientSession> clientContext;

HuffmanCoding supervisorHuffman;

std::atomic<bool> isServerRunning(true);

void NetworkLoop(Dashboard& dashboard) {
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

    while (isServerRunning) {
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
                    clientContext[new_socket].isHandshakeComplete = false;
                    clientContext[new_socket].sessionKey = "";
                    clientContext[new_socket].studentID = 0; 
                    dashboard.updateConnection(true, inet_ntoa(address.sin_addr));
                    break;
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];
            if (FD_ISSET(sd, &readfds)) {
                if ((valread = read(sd, buffer, 1024)) == 0) {
                    
                    if (clientContext[sd].studentID != 0) {
                        dashboard.setStudentConnection(clientContext[sd].studentID, false);
                    }
                    
                    close(sd);
                    client_socket[i] = 0;
                    clientContext.erase(sd);
                    dashboard.updateConnection(false);
                } else {
                    int offset = 0;
                    while (offset < valread) {
                        Message msg;
                        string decryptKey = clientContext[sd].isHandshakeComplete ? clientContext[sd].sessionKey : "";
                        int bytesProcessed = deserialize(buffer + offset, &msg, decryptKey);
                        if (bytesProcessed <= 0 || (offset + bytesProcessed > valread)) break;
                        
                        offset += bytesProcessed;
                        msg.studentName[31] = '\0';
                        if (msg.dataLength < 512) msg.data[msg.dataLength] = '\0';
                        string sName(msg.studentName);
                        bool sendAck = false;
                        
                        switch (msg.msgType) {
                            case msgHandshakeInit: {
                                long long n, e, d;
                                GenerateRSAKeys(n, e, d);
                                clientContext[sd].privateKeyD = d;
                                clientContext[sd].publicKeyN = n;
                                char payload[16];
                                memcpy(payload, &n, sizeof(long long));
                                memcpy(payload + sizeof(long long), &e, sizeof(long long));
                                Message keyMsg = CreateMsg(msgHandshakeKey, msg.studentID, time(0), 0, payload, 16);
                                char respBuffer[1024];
                                int respSize = serialize(keyMsg, respBuffer, "");
                                send(sd, respBuffer, respSize, 0);
                                break;
                            }
                            case msgHandshakeResponse: {
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
                                
                                clientContext[sd].studentID = msg.studentID; 
                                dashboard.registerStudent(msg.studentID, sName); 
                                
                                Message ackMsg = CreateMsg(msgACK, msg.studentID, time(0), msg.sequenceNumber, NULL, 0);
                                char ackBuffer[1024];
                                int ackSize = serialize(ackMsg, ackBuffer, recoveredKey);
                                send(sd, ackBuffer, ackSize, 0);
                                break;
                            }
                            case msgViolation: {
                                string website(msg.data);
                                violationRecords[msg.studentID].name = sName;
                                violationRecords[msg.studentID].totalViolations++;
                                dashboard.recordViolation(msg.studentID, website);
                                sendAck = true;
                                break;
                            }
                            case msgViolationCompressed: {
                            char decompressedBuffer[1024]; 
                            int decompressedLen = 0;
                        
                            supervisorHuffman.Decompress(msg.data, msg.dataLength, decompressedBuffer, decompressedLen);
                            decompressedBuffer[decompressedLen] = '\0';
                            
                            string website(decompressedBuffer);
                            
                            violationRecords[msg.studentID].name = sName;
                            violationRecords[msg.studentID].totalViolations++;
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
}

void SetupImGuiStyle() {
    ImGuiStyle& style = ImGui::GetStyle();
    
    style.WindowRounding    = 8.0f;
    style.FrameRounding     = 6.0f;
    style.PopupRounding     = 6.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding      = 6.0f;
    style.TabRounding       = 6.0f;

    style.WindowPadding     = ImVec2(16, 16);
    style.FramePadding      = ImVec2(10, 8);
    style.ItemSpacing       = ImVec2(12, 12);
    style.CellPadding       = ImVec2(8, 8);

    ImVec4* colors = style.Colors;
    colors[ImGuiCol_WindowBg]             = ImVec4(0.08f, 0.08f, 0.09f, 1.00f);
    colors[ImGuiCol_TitleBg]              = ImVec4(0.12f, 0.12f, 0.14f, 1.00f);
    colors[ImGuiCol_TitleBgActive]        = ImVec4(0.16f, 0.16f, 0.19f, 1.00f);
    colors[ImGuiCol_FrameBg]              = ImVec4(0.14f, 0.14f, 0.16f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]       = ImVec4(0.20f, 0.20f, 0.24f, 1.00f);
    colors[ImGuiCol_FrameBgActive]        = ImVec4(0.28f, 0.28f, 0.32f, 1.00f);
    colors[ImGuiCol_Header]               = ImVec4(0.18f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_HeaderHovered]        = ImVec4(0.24f, 0.24f, 0.28f, 1.00f);
    colors[ImGuiCol_HeaderActive]         = ImVec4(0.32f, 0.32f, 0.38f, 1.00f);
    colors[ImGuiCol_Text]                 = ImVec4(0.92f, 0.92f, 0.95f, 1.00f);
    colors[ImGuiCol_CheckMark]            = ImVec4(0.10f, 0.60f, 0.90f, 1.00f);
    colors[ImGuiCol_Button]               = ImVec4(0.16f, 0.16f, 0.20f, 1.00f);
    colors[ImGuiCol_ButtonHovered]        = ImVec4(0.22f, 0.22f, 0.28f, 1.00f);
    colors[ImGuiCol_ButtonActive]         = ImVec4(0.28f, 0.28f, 0.36f, 1.00f);
    colors[ImGuiCol_Border]               = ImVec4(0.18f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_BorderShadow]         = ImVec4(0.00f, 0.00f, 0.00f, 0.20f);
    
    colors[ImGuiCol_TableHeaderBg]        = ImVec4(0.14f, 0.14f, 0.16f, 1.00f);
    colors[ImGuiCol_TableBorderStrong]    = ImVec4(0.22f, 0.22f, 0.26f, 1.00f);
    colors[ImGuiCol_TableBorderLight]     = ImVec4(0.18f, 0.18f, 0.20f, 1.00f);
    colors[ImGuiCol_TableRowBg]           = ImVec4(0.08f, 0.08f, 0.09f, 1.00f);
    colors[ImGuiCol_TableRowBgAlt]        = ImVec4(0.11f, 0.11f, 0.12f, 1.00f);
}

int main() {
    srand(time(0)); 

    if (!glfwInit()) return -1;
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif

    GLFWwindow* window = glfwCreateWindow(900, 750, "Argus Supervisor - Control Center", NULL, NULL);
    if (!window) { glfwTerminate(); return -1; }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); 

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    SetupImGuiStyle();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 150");

    Dashboard dashboard;
    std::thread netThread(NetworkLoop, std::ref(dashboard));
    netThread.detach(); 

    while (!glfwWindowShouldClose(window) && !dashboard.systemShouldExit) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        dashboard.renderGUI();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        
        glClearColor(0.05f, 0.05f, 0.06f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    isServerRunning = false; 

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}