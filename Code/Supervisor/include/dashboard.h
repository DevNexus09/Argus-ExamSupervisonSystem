#ifndef DASHBOARD_H
#define DASHBOARD_H

#include <string>
#include <map>
#include <vector>
#include <cstdint>
#include <ctime>
#include "../../Common/include/priorityqueue.h"

class Dashboard {
private:
    int activeConnections;
    int totalViolations;
    std::time_t lastRefreshTime;
    
    // Data storage
    std::map<std::string, int> studentViolationCounts; // Helper to track counts before inserting to PQ
    std::map<std::string, int> websiteViolationCounts;
    PriorityQueue* studentPQ; // Using the project's custom Priority Queue
    
    std::string latestLog; // To display the last system event

public:
    Dashboard();
    ~Dashboard();

    // Data Updates
    void updateConnection(bool connected, const std::string& ip = "");
    void recordViolation(uint32_t studentID, const std::string& website);
    
    // Rendering
    void render();
    bool shouldRefresh(); // Checks if 5 seconds have passed
};

#endif