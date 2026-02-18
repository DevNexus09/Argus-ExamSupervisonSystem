#include <iostream>
#include <fstream> 
#include <string>
#include <vector>
#include <algorithm>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <signal.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <limits.h>
#include <map> 
#include <ctime>
#include <sstream>
#include <sys/wait.h> // Required for waitpid()
#include <chrono>     // Required for Monotonic Clock
#include "../../Common/include/protocol.h"
#include "../../Common/include/trie.h"

using namespace std;

// --- Config ---
#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define DNS_PORT 53
#define WHITELIST_PATH "../config/whitelist.txt" 
#define HEARTBEAT_INTERVAL 30

// --- Globals ---
int sock = 0;
pcap_t *handle = nullptr;
uint32_t currentStudentID = 0;
char currentStudentName[32];
Trie whitelistTrie;
bool running = true;

// Reliability Globals
map<uint32_t, pair<Message, time_t>> pendingACKs; 
uint32_t globalSequenceNum = 0;
time_t lastHeartbeatTime = 0;
time_t lastCheckTime = 0;

// Time Synchronization Globals (Cristian's Algorithm)
int64_t clockOffset = 0; // Offset = ServerTime - StudentTime
time_t serverSyncTime = 0;
std::chrono::steady_clock::time_point monotonicSyncTime;
bool isTimeSynced = false;

// --- FORWARD DECLARATIONS ---
void signalHandler(int signum);
bool connectToServer();
void sendMessage(Message& msg);
void handleIncomingACKs();
void processPendingMessages();
void checkHeartbeat();
void checkTampering();
void synchronizeClock(); // New: Cristian's Algorithm
string findActiveInterface();
string parseDNSName(const u_char* packet, int& offset);
string trim(const string& str);
void loadWhitelist();
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void run_student_logic();   // Encapsulated logic for the worker process
void sendWatchdogAlert();   // Alert function for the watchdog

// --- Implementations ---

void signalHandler(int signum) {
    cout << "\n[System] Stopping Student Client..." << endl;
    running = false;
    if (handle) pcap_breakloop(handle);
}

// Helper function for the Watchdog to send an alert when Child dies
void sendWatchdogAlert() {
    int alert_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (alert_sock < 0) return;

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        close(alert_sock); return;
    }
    if (connect(alert_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(alert_sock); return;
    }

    string alertStr = "Watchdog: Student Process Killed Manually!";
    Message msg = CreateMsg(msgTamper, currentStudentID, time(0), 0, alertStr.c_str(), alertStr.length());
    
    char buffer[1024];
    int msgSize = serialize(msg, buffer);
    send(alert_sock, buffer, msgSize, 0);
    close(alert_sock);
}

bool connectToServer() {
    if (sock > 0) return true;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        sock = 0;
        return false;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        close(sock); sock = 0; return false;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock); sock = 0; return false;
    }
    
    cout << "[System] Connected to Supervisor!" << endl;
    return true;
}

// New: Robust Time Synchronization using Cristian's Algorithm
void synchronizeClock() {
    if (sock == 0) connectToServer();
    if (sock == 0) {
        cerr << "[Error] Cannot sync time: Offline." << endl;
        return;
    }

    cout << "[System] Synchronizing time with Supervisor..." << endl;

    long long bestRTT = LLONG_MAX;
    time_t bestServerTime = 0;
    std::chrono::steady_clock::time_point bestT3;
    bool success = false;

    // "Best of 3" Strategy
    for (int i = 0; i < 3; i++) {
        Message req = CreateMsg(msgTimeRequest, currentStudentID, time(0), 0, NULL, 0);
        
        auto t0 = std::chrono::steady_clock::now(); // T0 (Monotonic)
        
        // Send Request
        char buffer[1024];
        int msgSize = serialize(req, buffer);
        if (send(sock, buffer, msgSize, 0) < 0) continue;

        // Wait for Response
        // Note: Using a blocking recv here for the handshake phase is acceptable
        int len = recv(sock, buffer, 1024, 0);
        auto t3 = std::chrono::steady_clock::now(); // T3 (Monotonic)

        if (len > 0) {
            Message res;
            deserialize(buffer, &res);
            if (res.msgType == msgTimeResponse) {
                // Parse Server Time from data payload
                time_t tServer = (time_t)atoll(res.data);
                
                long long rtt = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t0).count();
                
                if (rtt < bestRTT) {
                    bestRTT = rtt;
                    bestServerTime = tServer;
                    bestT3 = t3;
                    success = true;
                }
            }
        }
    }

    if (success) {
        long long latency = bestRTT / 2; // Estimated One-Way Latency
        
        // Derived Server Time at the moment of T3
        time_t predictedServerTime = bestServerTime + (latency / 1000); // convert ms to seconds
        
        // Calculate Offset: Offset = ServerTime - StudentTime
        // This offset allows us to convert local time(0) to Server Time: Trusted = Local + Offset
        clockOffset = predictedServerTime - time(0);
        
        // Store Monotonic Reference for Tamper Checking
        serverSyncTime = predictedServerTime;
        monotonicSyncTime = bestT3;
        isTimeSynced = true;

        cout << "[System] Time Synced. RTT: " << bestRTT << "ms. Offset: " << clockOffset << "s." << endl;
    } else {
        cerr << "[Error] Time Sync Failed! Proceeding with local time (Risky)." << endl;
    }
}

void sendMessage(Message& msg) {
    if (msg.sequenceNumber == 0) {
        msg.sequenceNumber = ++globalSequenceNum;
    }
    
    // Apply Trusted Time to Message Timestamp
    if (isTimeSynced) {
        msg.timestamp = time(0) + clockOffset;
    } else {
        msg.timestamp = time(0);
    }
    
    msg.checksum = CalculateChecksum(msg);

    if (msg.msgType == msgViolation || msg.msgType == msgTamper) {
        pendingACKs[msg.sequenceNumber] = make_pair(msg, time(0));
    }

    if (sock > 0) {
        char buffer[1024];
        int msgSize = serialize(msg, buffer); 
        
        if (send(sock, buffer, msgSize, 0) < 0) { 
            cout << "[Error] Send failed. Connection lost." << endl;
            close(sock);
            sock = 0;
        }
    } else {
        cout << "[System] Offline. Message queued (Seq: " << msg.sequenceNumber << ")." << endl;
    }
}

void handleIncomingACKs() {
    if (sock <= 0) return;
    
    char buffer[1024];
    int len = recv(sock, buffer, 1024, MSG_DONTWAIT);
    
    if (len > 0) {
        Message msg;
        deserialize(buffer, &msg);
        if (msg.msgType == msgACK) {
            cout << "[System] ACK Received for Msg #" << msg.sequenceNumber << endl;
            pendingACKs.erase(msg.sequenceNumber);
        }
    }
}

void processPendingMessages() {
    if (sock == 0) {
        if (!connectToServer()) return; 
    }

    time_t now = time(0);
    for (auto it = pendingACKs.begin(); it != pendingACKs.end(); ++it) {
        if (difftime(now, it->second.second) >= 5) {
            cout << "[Retry] Resending Msg #" << it->first << "..." << endl;
            
            char buffer[1024];
            int msgSize = serialize(it->second.first, buffer); 
            
            if (send(sock, buffer, msgSize, 0) < 0) {
                close(sock); sock = 0;
                break;
            }
            
            it->second.second = now; 
        }
    }
}

void checkHeartbeat() {
    time_t now = time(0);
    if (difftime(now, lastHeartbeatTime) >= HEARTBEAT_INTERVAL) {
        Message msg = CreateMsg(msgHeartbeat, currentStudentID, now, 0, NULL, 0);
        sendMessage(msg);
        lastHeartbeatTime = now;
    }
}

void checkTampering() {
    if (!isTimeSynced) return;

    // 1. Calculate Trusted Time using Monotonic Clock (Independent of System Clock)
    auto nowMono = std::chrono::steady_clock::now();
    long long elapsedSecs = std::chrono::duration_cast<std::chrono::seconds>(nowMono - monotonicSyncTime).count();
    time_t trustedTime = serverSyncTime + elapsedSecs;

    // 2. Get Current System Time + Offset
    time_t currentSystemTimeTrusted = time(0) + clockOffset;

    // 3. Compare
    // If user changes OS clock, 'time(0)' changes, so 'currentSystemTimeTrusted' changes.
    // 'trustedTime' (Monotonic) does NOT change.
    long long drift = abs(trustedTime - currentSystemTimeTrusted);

    if (drift > 30) { // Threshold: 30 seconds
        cout << "[ALERT] System time manipulation detected! Drift: " << drift << "s" << endl;
        string alertMsg = "System Time Mismatch (Drift: " + to_string(drift) + "s)";
        
        // Note: sendMessage will use (time(0) + offset). We might want to force the trusted timestamp?
        // sendMessage handles using the offset, but here we explicitly found the offset is wrong relative to reality.
        // We send the alert anyway.
        Message msg = CreateMsg(msgTamper, currentStudentID, trustedTime, 0, alertMsg.c_str(), alertMsg.length());
        sendMessage(msg);
        
        // Optional: Re-sync or force exit?
        // For now, we alert.
        lastCheckTime = time(0); 
    }
}

string findActiveInterface() {
    ifstream routeFile("/proc/net/route");
    if (routeFile.is_open()) {
        string line;
        getline(routeFile, line);
        while (getline(routeFile, line)) {
            stringstream ss(line);
            string iface, dest;
            ss >> iface >> dest;
            if (dest == "00000000") {
                routeFile.close();
                return iface;
            }
        }
        routeFile.close();
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    string selected = "";
    bool foundPreferred = false;

    if (pcap_findalldevs(&alldevs, errbuf) != -1) {
        for (d = alldevs; d; d = d->next) {
            if (string(d->name) == "en0") {
                selected = "en0";
                foundPreferred = true;
                break;
            }
        }

        if (!foundPreferred) {
            for (d = alldevs; d; d = d->next) {
                string name = d->name;
                if (name.find("lo") == string::npos && 
                    name.find("bridge") == string::npos && 
                    name.find("p2p") == string::npos && 
                    name.find("utun") == string::npos &&
                    name.find("ap") == string::npos &&    
                    name.find("awdl") == string::npos) {  
                    selected = name;
                    break;
                }
            }
        }
        pcap_freealldevs(alldevs);
    }
    return selected;
}

string parseDNSName(const u_char* packet, int& offset) {
    string name = "";
    int len = packet[offset++];
    
    while (len != 0) {
        if (len >= 192) {
            offset++;
            return name;
        }
        for (int i = 0; i < len; i++) {
            name += (char)packet[offset++];
        }
        len = packet[offset++];
        if (len != 0) name += ".";
    }
    return name;
}

string trim(const string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (string::npos == first) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

void loadWhitelist() {
    const char* paths[] = {
        "Code/Student/config/whitelist.txt",
        "../config/whitelist.txt",
        "whitelist.txt"
    };

    ifstream file;
    string loadedPath = "";

    for (const char* path : paths) {
        file.open(path);
        if (file.is_open()) {
            loadedPath = path;
            break;
        }
        file.clear();
    }

    if (!file.is_open()) {
        cerr << "\n[ERROR] Whitelist file NOT found! Blocklist might be aggressive." << endl;
        Insert(&whitelistTrie, "google.com");
        return;
    }

    string line;
    int count = 0;
    while (getline(file, line)) {
        string domain = trim(line);
        if (domain.empty() || domain[0] == '#' || domain[0] == '[') continue;
        Insert(&whitelistTrie, domain);
        count++;
    }
    file.close();
    cout << "[System] Whitelist loaded from " << loadedPath << " (" << count << " entries)." << endl;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int ip_header_offset = 14; 
    struct ip *iph = (struct ip *)(packet + ip_header_offset);
    int ip_header_len = iph->ip_hl * 4;
    
    struct udphdr *udph = (struct udphdr *)(packet + ip_header_offset + ip_header_len);
    
    #ifdef __APPLE__
        if (ntohs(udph->uh_dport) != DNS_PORT) return;
    #else
        if (ntohs(udph->dest) != DNS_PORT) return;
    #endif

    int dns_offset = ip_header_offset + ip_header_len + 8;
    int query_offset = dns_offset + 12;
    string website = parseDNSName(packet, query_offset);

    if (website.empty()) return;

    string tempCheck = website;
    bool isAllowed = false;

    while (!tempCheck.empty()) {
        if (Search(&whitelistTrie, tempCheck)) {
            isAllowed = true;
            break;
        }
        
        size_t firstDot = tempCheck.find('.');
        if (firstDot == string::npos) break;
        
        tempCheck = tempCheck.substr(firstDot + 1);
    }

    if (!isAllowed) {
        cout << "[UNAUTHORIZED] " << website << " detected!" << endl;
        Message msg;
        msg.msgType = msgViolation;
        msg.studentID = currentStudentID;
        strncpy(msg.studentName, currentStudentName, 31);
        
        // Use Trusted Time
        if (isTimeSynced) msg.timestamp = time(0) + clockOffset;
        else msg.timestamp = time(0);

        msg.sequenceNumber = 0; 
        strncpy(msg.data, website.c_str(), sizeof(msg.data) - 1);
        msg.dataLength = website.length();
        sendMessage(msg);
    }
}

void run_student_logic() {
    signal(SIGINT, signalHandler);

    connectToServer();
    loadWhitelist();
    
    // PERFORM CLOCK SYNC
    synchronizeClock();

    lastHeartbeatTime = time(0);
    lastCheckTime = time(0);

    string dev = findActiveInterface();
    if (dev.empty()) {
        cerr << "[Error] No active network interface found. (Try running with sudo)" << endl;
        if (sock > 0) close(sock);
        exit(EXIT_FAILURE);
    }
    cout << "[System] Auto-selected interface: " << dev << endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev.c_str(), 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Couldn't open device: " << errbuf << endl;
        if (sock > 0) close(sock);
        exit(EXIT_FAILURE);
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) exit(EXIT_FAILURE);
    if (pcap_setfilter(handle, &fp) == -1) exit(EXIT_FAILURE);

    cout << "[System] Monitoring DNS traffic..." << endl;
    
    while (running) {
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        int res = pcap_next_ex(handle, &header, &pkt_data);
        
        if (res == 1) {
            packet_handler(NULL, header, pkt_data);
        } else if (res == -1) {
            cerr << "Error reading packet: " << pcap_geterr(handle) << endl;
            break;
        } else if (res == -2) {
            break;
        }
        
        handleIncomingACKs();
        checkHeartbeat();
        checkTampering(); // Now checks for Time Manipulation
        processPendingMessages();
    }

    pcap_close(handle);
    if (sock > 0) close(sock);
}

int main() {
    cout << "--- ARGUS STUDENT CLIENT ---" << endl;
    cout << "Enter Student ID: ";
    cin >> currentStudentID;
    cout << "Enter Student Name: ";
    cin.ignore();
    cin.getline(currentStudentName, 32);

    while(true) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("Fork failed");
            exit(1);
        }
        else if (pid == 0) {
            run_student_logic();
            exit(0); 
        }
        else {
            cout << "[Watchdog] Monitoring Worker Process (PID: " << pid << ")..." << endl;
            signal(SIGINT, SIG_IGN);

            int status;
            waitpid(pid, &status, 0); 

            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                cout << "[Watchdog] Worker finished normally. Exiting." << endl;
                break; 
            }
            else {
                cout << "\n[ALERT] Worker Process killed! Sending Tamper Alert and Restarting..." << endl;
                sendWatchdogAlert(); 
                sleep(1); 
                continue; 
            }
        }
    }

    return 0;
}