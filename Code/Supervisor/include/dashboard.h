#ifndef DASHBOARD_H
#define DASHBOARD_H

#include <string>
#include <map>
#include <vector>
#include <cstdint>
#include <ctime>
#include <mutex>
#include "../../Common/include/priorityqueue.h"

struct StudentData {
    std::string name;
    bool isConnected;
};

class Dashboard {
private:
    int activeConnections;
    int totalViolations;
    std::time_t lastRefreshTime;
    
    std::map<std::string, int> studentViolationCounts;
    std::map<std::string, int> websiteViolationCounts;
    PriorityQueue* studentPQ;
    std::string latestLog;
    
    std::map<uint32_t, StudentData> studentRegistry; 
    bool showAttendancePopup;

    std::mutex dataMutex;

public:
    bool systemShouldExit;

    Dashboard();
    ~Dashboard();

    void updateConnection(bool connected, const std::string& ip = "");
    void registerStudent(uint32_t studentID, const std::string& name); 
    void setStudentConnection(uint32_t studentID, bool status);        
    
    void recordViolation(uint32_t studentID, const std::string& website);
    void updateHeartbeat(uint32_t studentID);
    void recordTampering(uint32_t studentID);
    
    bool shouldRefresh();
    void renderGUI();
};

#endif