#include "../include/dashboard.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sstream>

using namespace std;

Dashboard::Dashboard() {
    activeConnections = 0;
    totalViolations = 0;
    lastRefreshTime = time(0);
    studentPQ = new PriorityQueue();
    latestLog = "System Started.";
}

Dashboard::~Dashboard() {
    delete studentPQ;
}

void Dashboard::updateConnection(bool connected, const string& ip) {
    if (connected) {
        activeConnections++;
        latestLog = "New connection established" + (ip.empty() ? "." : " from " + ip);
    } else {
        if (activeConnections > 0) activeConnections--;
        latestLog = "Student disconnected.";
    }
}

void Dashboard::recordViolation(uint32_t studentID, const string& website) {
    totalViolations++;
    
    // Update Student Stats
    string idStr = to_string(studentID);
    studentViolationCounts[idStr]++;
    
    // Insert/Update in PriorityQueue
    Insert(studentPQ, idStr, studentViolationCounts[idStr]);

    // Update Website Stats
    websiteViolationCounts[website]++;

    latestLog = "Violation detected: Student " + idStr + " on " + website;
}

// --- Feature: Heartbeat Logging ---
void Dashboard::updateHeartbeat(uint32_t studentID) {
    // We don't spam the log, just maybe update internally or show occasionally
    // For now, we update the log to show activity
    latestLog = "Heartbeat received from Student " + to_string(studentID);
}

// --- Feature: Tampering Alert ---
void Dashboard::recordTampering(uint32_t studentID) {
    totalViolations++; // Count tampering as a violation
    
    string idStr = to_string(studentID);
    studentViolationCounts[idStr]++;
    Insert(studentPQ, idStr, studentViolationCounts[idStr]);

    latestLog = "[ALERT] TAMPERING DETECTED: Student " + idStr;
}

bool Dashboard::shouldRefresh() {
    time_t now = time(0);
    if (difftime(now, lastRefreshTime) >= 5.0) {
        lastRefreshTime = now;
        return true;
    }
    return false;
}

void Dashboard::render() {
    // Clear screen and move cursor to top-left
    cout << "\033[2J\033[1;1H";

    cout << "==============================================================" << endl;
    cout << "                  ARGUS SUPERVISOR DASHBOARD                  " << endl;
    cout << "==============================================================" << endl;
    
    // General Stats
    cout << left << setw(30) << "Active Connections:" << activeConnections << endl;
    cout << left << setw(30) << "Total Violations:" << totalViolations << endl;
    cout << "--------------------------------------------------------------" << endl;

    // Top 10 Violators
    cout << "\n [TOP 10 VIOLATORS]" << endl;
    cout << left << setw(10) << "Rank" << setw(20) << "Student ID" << setw(15) << "Violations" << endl;
    cout << "--------------------------------------------------------------" << endl;
    
    vector<Student> topStudents = GetTop(studentPQ, 10);
    if (topStudents.empty()) {
        cout << " No violations recorded yet." << endl;
    } else {
        for (size_t i = 0; i < topStudents.size(); i++) {
            cout << left << setw(10) << (i + 1) 
                 << setw(20) << topStudents[i].studentID 
                 << setw(15) << topStudents[i].violationCount << endl;
        }
    }

    // Top 5 Violation Websites
    cout << "\n [TOP 5 RESTRICTED SITES ACCESSED]" << endl;
    cout << left << setw(10) << "Rank" << setw(35) << "Website" << setw(10) << "Count" << endl;
    cout << "--------------------------------------------------------------" << endl;

    // Convert map to vector for sorting
    vector<pair<string, int>> sites(websiteViolationCounts.begin(), websiteViolationCounts.end());
    sort(sites.begin(), sites.end(), [](const pair<string, int>& a, const pair<string, int>& b) {
        return a.second > b.second; // Descending order
    });

    int limit = min((int)sites.size(), 5);
    if (limit == 0) {
        cout << " No data available." << endl;
    } else {
        for (int i = 0; i < limit; i++) {
            cout << left << setw(10) << (i + 1) 
                 << setw(35) << sites[i].first 
                 << setw(10) << sites[i].second << endl;
        }
    }

    cout << "\n--------------------------------------------------------------" << endl;
    cout << " Log: " << latestLog << endl;
    cout << "--------------------------------------------------------------" << endl;
    cout << " Refreshing every 5s... (Press Ctrl+C to exit)" << endl;
}