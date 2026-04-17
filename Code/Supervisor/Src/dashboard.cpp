#include "../include/dashboard.h"
#include "../../Common/imgui/imgui.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <cstdio>

using namespace std;

static void GeneratePDF(const string& title, const vector<string>& headers, const vector<vector<string>>& data, const string& filename) {
    ofstream file(filename, ios::binary);
    if(!file.is_open()) return;

    int rowHeight = 20;
    int headerHeight = 100;
    int totalHeight = std::max(842, headerHeight + (int)data.size() * rowHeight + 50);

    file << "%PDF-1.4\n";
    vector<long> xrefs;
    xrefs.push_back(0);

    auto startObj = [&]() {
        xrefs.push_back(file.tellp());
        file << xrefs.size() - 1 << " 0 obj\n";
        return xrefs.size() - 1;
    };

    int catalog = startObj();
    file << "<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

    int pages = startObj();
    file << "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";

    int page = startObj();
    file << "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 " << totalHeight << "] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n";

    int contents = startObj();
    stringstream stream;
    
    auto esc = [](const string& s) {
        string r;
        for(char c : s) {
            if(c=='('||c==')'||c=='\\') r+='\\';
            r+=c;
        }
        return r;
    };

    auto pad = [](string s, size_t w) {
        if(s.length() < w) s.append(w - s.length(), ' ');
        return s;
    };

    stream << "BT\n/F1 18 Tf\n50 " << totalHeight - 50 << " Td\n(" << esc(title) << ") Tj\nET\n";
    
    stream << "BT\n/F1 12 Tf\n";
    int y = totalHeight - 90;
    
    string headerLine = pad(headers[0], 10) + pad(headers[1], 20) + pad(headers[2], 40);
    if(headers.size() > 3) headerLine += pad(headers[3], 20);

    stream << "50 " << y << " Td\n(" << esc(headerLine) << ") Tj\n";
    
    for(auto& row : data) {
        string rowLine = pad(row[0], 10) + pad(row[1], 20) + pad(row[2], 40);
        if(row.size() > 3) rowLine += pad(row[3], 20);
        
        stream << "0 -20 Td\n(" << esc(rowLine) << ") Tj\n";
    }
    stream << "ET\n";

    string streamStr = stream.str();
    file << "<< /Length " << streamStr.length() << " >>\nstream\n" << streamStr << "\nendstream\nendobj\n";

    int font = startObj();
    file << "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n"; 

    long xrefOffset = file.tellp();
    file << "xref\n0 " << xrefs.size() << "\n0000000000 65535 f \n";
    for(size_t i = 1; i < xrefs.size(); i++) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%010ld 00000 n \n", xrefs[i]);
        file << buf;
    }

    file << "trailer\n<< /Size " << xrefs.size() << " /Root 1 0 R >>\n";
    file << "startxref\n" << xrefOffset << "\n%%EOF\n";
    file.close();
}


Dashboard::Dashboard() {
    activeConnections = 0;
    totalViolations = 0;
    lastRefreshTime = time(0);
    studentPQ = new PriorityQueue();
    latestLog = "System Started. Awaiting connections...";
    showAttendancePopup = false;
    showViolationPopup = false;
    showExitPopup = false;
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
    float totalWidth = (btnWidth * 3) + (spacing * 2);
    
    ImGui::SetCursorPosX((viewport->WorkSize.x - totalWidth) * 0.5f);
    
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.1f, 0.4f, 0.8f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.5f, 0.9f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.1f, 0.3f, 0.7f, 1.0f));
    if (ImGui::Button("📋 View Attendance", ImVec2(btnWidth, 40))) {
        showAttendancePopup = true;
    }
    ImGui::PopStyleColor(3);

    ImGui::SameLine(0, spacing);
    
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.3f, 0.2f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.4f, 0.3f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.7f, 0.2f, 0.1f, 1.0f));
    if (ImGui::Button("⚠️ View Violations", ImVec2(btnWidth, 40))) {
        showViolationPopup = true;
    }
    ImGui::PopStyleColor(3);

    ImGui::SameLine(0, spacing);

    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.7f, 0.1f, 0.1f, 1.0f));
    if (ImGui::Button("🛑 Exit System", ImVec2(btnWidth, 40))) {
        showExitPopup = true;
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

    if (showViolationPopup) {
        ImGui::SetNextWindowSize(ImVec2(500, 400), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowPos(ImVec2(viewport->WorkSize.x * 0.5f, viewport->WorkSize.y * 0.5f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        
        if (ImGui::Begin("⚠️ Violation Records List", &showViolationPopup, ImGuiWindowFlags_NoCollapse)) {
            ImGui::Text("All violations recorded during this session:");
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            
            if (ImGui::BeginTable("ViolationReportTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Serial", ImGuiTableColumnFlags_WidthFixed, 50.0f);
                ImGui::TableSetupColumn("Student ID", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                ImGui::TableSetupColumn("Student Name");
                ImGui::TableSetupColumn("Violations", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();

                int serial = 1;
                for (const auto& pair : studentViolationCounts) {
                    uint32_t sid = std::stoul(pair.first);
                    string name = studentRegistry.count(sid) ? studentRegistry[sid].name : "Unknown";

                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::Text("%d", serial++);
                    ImGui::TableSetColumnIndex(1); ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "%s", pair.first.c_str());
                    ImGui::TableSetColumnIndex(2); ImGui::Text("%s", name.c_str());
                    ImGui::TableSetColumnIndex(3); ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%d", pair.second);
                }
                ImGui::EndTable();
            }
        }
        ImGui::End();
    }

    static float attSaveTimer = 0.0f;
    static float vioSaveTimer = 0.0f;

    if (showExitPopup) {
        ImGui::OpenPopup("System Shutdown & Reports");
        showExitPopup = false; 
    }

    ImGui::SetNextWindowSize(ImVec2(450, 300), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkSize.x * 0.5f, viewport->WorkSize.y * 0.5f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    
    if (ImGui::BeginPopupModal("System Shutdown & Reports", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse)) {
        
        ImGui::TextWrapped("Before turning off the server, please download your official PDF reports.");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
        
        if (ImGui::Button("⬇️ Download Final Attendance PDF", ImVec2(-1, 40))) {
            vector<string> headers = {"Serial", "Student ID", "Student Name"};
            vector<vector<string>> pdfData;
            int serial = 1;
            for (const auto& pair : studentRegistry) {
                if (pair.second.isConnected) {
                    pdfData.push_back({to_string(serial++), to_string(pair.first), pair.second.name});
                }
            }
            GeneratePDF("ARGUS Official Exam Attendance", headers, pdfData, "Attendance_Sheet.pdf");
            attSaveTimer = 3.0f; 
        }
        if (attSaveTimer > 0.0f) {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Attendance_Sheet.pdf successfully saved!");
            attSaveTimer -= ImGui::GetIO().DeltaTime;
        }

        ImGui::Spacing();

        if (ImGui::Button("⬇️ Download Final Violations PDF", ImVec2(-1, 40))) {
            vector<string> headers = {"Serial", "Student ID", "Student Name", "Violations"};
            vector<vector<string>> pdfData;
            int serial = 1;
            for (const auto& pair : studentViolationCounts) {
                uint32_t sid = std::stoul(pair.first);
                string name = studentRegistry.count(sid) ? studentRegistry[sid].name : "Unknown";
                pdfData.push_back({to_string(serial++), pair.first, name, to_string(pair.second)});
            }
            GeneratePDF("ARGUS Official Violation Report", headers, pdfData, "Violation_Report.pdf");
            vioSaveTimer = 3.0f;
        }
        if (vioSaveTimer > 0.0f) {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Violation_Report.pdf successfully saved!");
            vioSaveTimer -= ImGui::GetIO().DeltaTime;
        }

        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
        
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
        if (ImGui::Button("Confirm Power Off", ImVec2(200, 40))) {
            systemShouldExit = true; 
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(2);
        
        ImGui::SameLine();
        
        if (ImGui::Button("Cancel", ImVec2(200, 40))) {
            ImGui::CloseCurrentPopup();
        }
        
        ImGui::EndPopup();
    }
}