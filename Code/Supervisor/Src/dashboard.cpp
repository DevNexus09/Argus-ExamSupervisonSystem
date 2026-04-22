#include "../include/dashboard.h"
#include "../../Common/imgui/imgui.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <cstdio>

using namespace std;

Dashboard::Dashboard() {
    activeConnections = 0;
    totalViolations = 0;
    lastRefreshTime = time(0);
    studentPQ = new PriorityQueue();
    latestLog = "System Started. Awaiting connections...";
    showAttendancePopup = false;
    systemShouldExit = false;
}

Dashboard::~Dashboard() {
    delete studentPQ;
}

void Dashboard::updateConnection(bool connected, const string& ip) {
    std::lock_guard<std::mutex> lock(dataMutex);
    if (connected) {
        activeConnections++;
        latestLog = "[INFO] New connection established" + (ip.empty() ? "." : " from " + ip);
    } else {
        if (activeConnections > 0) activeConnections--;
        latestLog = "[INFO] Student disconnected.";
    }
}

void Dashboard::registerStudent(uint32_t studentID, const string& name) {
    std::lock_guard<std::mutex> lock(dataMutex);
    studentRegistry[studentID].name = name;
    studentRegistry[studentID].isConnected = true;
}

void Dashboard::setStudentConnection(uint32_t studentID, bool status) {
    std::lock_guard<std::mutex> lock(dataMutex);
    if (studentRegistry.find(studentID) != studentRegistry.end()) {
        studentRegistry[studentID].isConnected = status;
    }
}

void Dashboard::recordViolation(uint32_t studentID, const string& website) {
    std::lock_guard<std::mutex> lock(dataMutex);
    totalViolations++;
    
    string idStr = to_string(studentID);
    studentViolationCounts[idStr]++;
    
    Insert(studentPQ, idStr, studentViolationCounts[idStr]);
    websiteViolationCounts[website]++;
    latestLog = "[VIOLATION] Student " + idStr + " accessed restricted site: " + website;
}

void Dashboard::updateHeartbeat(uint32_t studentID) {
    std::lock_guard<std::mutex> lock(dataMutex);
}

void Dashboard::recordTampering(uint32_t studentID) {
    std::lock_guard<std::mutex> lock(dataMutex);
    totalViolations++;
    
    string idStr = to_string(studentID);
    studentViolationCounts[idStr]++;
    Insert(studentPQ, idStr, studentViolationCounts[idStr]);
    latestLog = "[CRITICAL ALERT] TAMPERING DETECTED: Student " + idStr;
}

bool Dashboard::shouldRefresh() {
    time_t now = time(0);
    if (difftime(now, lastRefreshTime) >= 5.0) {
        lastRefreshTime = now;
        return true;
    }
    return false;
}

void Dashboard::renderGUI() {
    std::lock_guard<std::mutex> lock(dataMutex);

    ImGuiWindowFlags winFlags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize;
    ImVec2 winSize = ImVec2(400, 300);

    ImGui::SetNextWindowSize(winSize, ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(40, 40), ImGuiCond_FirstUseEver); 
    ImGui::Begin("📊 System Overview", nullptr, winFlags);
    
    ImGui::Spacing(); ImGui::Spacing();
    ImGui::TextColored(ImVec4(0.4f, 0.8f, 0.4f, 1.0f), "● SYSTEM ONLINE AND MONITORING");
    ImGui::Separator();
    ImGui::Spacing(); ImGui::Spacing();

    ImGui::SetWindowFontScale(1.2f); 
    ImGui::Text("Active Connections:");
    ImGui::SameLine(250);
    ImGui::TextColored(ImVec4(0.0f, 0.7f, 1.0f, 1.0f), "%d", activeConnections);
    
    ImGui::Spacing(); ImGui::Spacing();
    
    ImGui::Text("Total Violations:");
    ImGui::SameLine(250);
    ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%d", totalViolations);
    ImGui::SetWindowFontScale(1.0f); 

    ImGui::End();
    ImGui::SetNextWindowSize(winSize, ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(460, 40), ImGuiCond_FirstUseEver);
    ImGui::Begin("⚠️ Top Violators", nullptr, winFlags);
    
    if (ImGui::BeginTable("ViolatorsTable", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV)) {
        ImGui::TableSetupColumn("Rank", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableSetupColumn("Student ID");
        ImGui::TableSetupColumn("Count", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableHeadersRow();

        vector<Student> topStudents = GetTop(studentPQ, 10);
        if (topStudents.empty()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("-");
            ImGui::TableSetColumnIndex(1); ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "No violations recorded");
            ImGui::TableSetColumnIndex(2); ImGui::Text("-");
        } else {
            for (size_t i = 0; i < topStudents.size(); i++) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::Text("%zu", i + 1);
                ImGui::TableSetColumnIndex(1); ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "%s", topStudents[i].studentID.c_str());
                ImGui::TableSetColumnIndex(2); ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%d", topStudents[i].violationCount);
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();

    ImGui::SetNextWindowSize(winSize, ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(40, 360), ImGuiCond_FirstUseEver);
    ImGui::Begin("🚫 Restricted Sites Accessed", nullptr, winFlags);
    
    if (ImGui::BeginTable("SitesTable", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV)) {
        ImGui::TableSetupColumn("Rank", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableSetupColumn("Website Domain");
        ImGui::TableSetupColumn("Hits", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableHeadersRow();

        vector<pair<string, int>> sites(websiteViolationCounts.begin(), websiteViolationCounts.end());
        sort(sites.begin(), sites.end(), [](const pair<string, int>& a, const pair<string, int>& b) { return a.second > b.second; });

        int limit = min((int)sites.size(), 8); 
        if (limit == 0) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("-");
            ImGui::TableSetColumnIndex(1); ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "Clean traffic");
            ImGui::TableSetColumnIndex(2); ImGui::Text("-");
        } else {
            for (int i = 0; i < limit; i++) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::Text("%d", i + 1);
                ImGui::TableSetColumnIndex(1); ImGui::Text("%s", sites[i].first.c_str());
                ImGui::TableSetColumnIndex(2); ImGui::Text("%d", sites[i].second);
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();

    ImGui::SetNextWindowSize(winSize, ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(460, 360), ImGuiCond_FirstUseEver);
    ImGui::Begin("📝 Live Event Log", nullptr, winFlags);
    
    ImGui::Spacing();
    ImVec4 logColor = ImVec4(0.9f, 0.9f, 0.9f, 1.0f); 
    if (latestLog.find("[ALERT]") != string::npos || latestLog.find("[CRITICAL") != string::npos) {
        logColor = ImVec4(1.0f, 0.2f, 0.2f, 1.0f); 
    } else if (latestLog.find("[VIOLATION]") != string::npos) {
        logColor = ImVec4(1.0f, 0.6f, 0.0f, 1.0f); 
    } else if (latestLog.find("[INFO]") != string::npos) {
        logColor = ImVec4(0.4f, 0.8f, 1.0f, 1.0f); 
    }

    ImGui::TextWrapped("Latest System Event:");
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextColored(logColor, "%s", latestLog.c_str());
    ImGui::End();

    ImGuiWindowFlags controlFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    
    ImGui::SetNextWindowPos(ImVec2(0, viewport->WorkSize.y - 60));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, 60));
    
    ImGui::Begin("ControlBar", nullptr, controlFlags);
    
    float btnWidth = 180.0f;
    float spacing = 20.0f;
    float totalWidth = (btnWidth * 2) + spacing;
    
    ImGui::SetCursorPosX((viewport->WorkSize.x - totalWidth) * 0.5f);
    
    // View Attendance Button
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.1f, 0.4f, 0.8f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.5f, 0.9f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.1f, 0.3f, 0.7f, 1.0f));
    if (ImGui::Button("📋 View Attendance", ImVec2(btnWidth, 40))) {
        showAttendancePopup = true;
    }
    ImGui::PopStyleColor(3);

    ImGui::SameLine(0, spacing);

    // Exit Button - Saves to Text Files directly and exits
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.7f, 0.1f, 0.1f, 1.0f));
    if (ImGui::Button("🛑 Exit System", ImVec2(btnWidth, 40))) {
        
        // 1. Generate text-based Attendance Sheet
        ofstream attFile("Attendance_Sheet.txt");
        if (attFile.is_open()) {
            attFile << "Serial\tStudent ID\tStudent Name\n";
            attFile << "--------------------------------------------------\n";
            int serial = 1;
            for (const auto& pair : studentRegistry) {
                if (pair.second.isConnected) {
                    attFile << serial++ << "\t" << pair.first << "\t\t" << pair.second.name << "\n";
                }
            }
            attFile.close();
        }

        // 2. Generate text-based Violation Report
        ofstream vioFile("Violation_Report.txt");
        if (vioFile.is_open()) {
            vioFile << "Serial\tStudent ID\tStudent Name\t\tViolations\n";
            vioFile << "------------------------------------------------------------------\n";
            int serial = 1;
            for (const auto& pair : studentViolationCounts) {
                uint32_t sid = std::stoul(pair.first);
                string name = studentRegistry.count(sid) ? studentRegistry[sid].name : "Unknown";
                vioFile << serial++ << "\t" << pair.first << "\t\t" << name << "\t\t" << pair.second << "\n";
            }
            vioFile.close();
        }

        systemShouldExit = true; 
    }
    ImGui::PopStyleColor(3);

    ImGui::End();

    if (showAttendancePopup) {
        ImGui::SetNextWindowSize(ImVec2(500, 400), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowPos(ImVec2(viewport->WorkSize.x * 0.5f, viewport->WorkSize.y * 0.5f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        
        if (ImGui::Begin("📋 Active Attendence List", &showAttendancePopup, ImGuiWindowFlags_NoCollapse)) {
            ImGui::Text("Students currently connected to the monitoring server:");
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            
            if (ImGui::BeginTable("AttendanceTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Serial", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                ImGui::TableSetupColumn("Student ID", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                ImGui::TableSetupColumn("Student Name");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();

                int serial = 1;
                for (const auto& pair : studentRegistry) {
                    if (pair.second.isConnected) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0); ImGui::Text("%d", serial++);
                        ImGui::TableSetColumnIndex(1); ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "%u", pair.first);
                        ImGui::TableSetColumnIndex(2); ImGui::Text("%s", pair.second.name.c_str());
                    }
                }
                ImGui::EndTable();
            }
        }
        ImGui::End();
    }
}