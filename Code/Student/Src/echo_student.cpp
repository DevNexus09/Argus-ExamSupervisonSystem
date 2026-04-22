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
#include <netinet/tcp.h> 
#include <cmath>         
#include <limits.h>
#include <map> 
#include <ctime>
#include <sstream>
#include <sys/wait.h> 
#include <chrono>     
#include <thread>
#include <atomic>
#include <mutex>

#include <GLFW/glfw3.h>
#include "../../Common/imgui/imgui.h"
#include "../../Common/imgui/backends/imgui_impl_glfw.h"
#include "../../Common/imgui/backends/imgui_impl_opengl3.h"

#include "../../Common/include/protocol.h"
#include "../../Common/include/trie.h"
#include "../../Common/include/huffman.h"

using namespace std;

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define DNS_PORT 53
#define WHITELIST_PATH "../config/whitelist.txt" 
#define HEARTBEAT_INTERVAL 30

int sock = 0;
pcap_t *handle = nullptr;
uint32_t currentStudentID = 0;
char currentStudentName[32];
Trie whitelistTrie;
string currentSessionKey = ""; 

HuffmanCoding studentHuffman;

map<uint32_t, pair<Message, time_t>> pendingACKs; 
uint32_t globalSequenceNum = 0;
time_t lastHeartbeatTime = 0;
time_t lastCheckTime = 0;
int64_t clockOffset = 0; 
time_t serverSyncTime = 0;
std::chrono::steady_clock::time_point monotonicSyncTime;
bool isTimeSynced = false;
std::atomic<bool> isMonitoring(false);
std::atomic<bool> running(true);
std::atomic<bool> threadCrashed(false); // Thread-based watchdog trigger
std::string studentStatus = "Awaiting Login...";
std::mutex statusMutex;

void setStatus(const std::string& status) {
    std::lock_guard<std::mutex> lock(statusMutex);
    studentStatus = status;
}

std::string getStatus() {
    std::lock_guard<std::mutex> lock(statusMutex);
    return studentStatus;
}

struct FlowData {
    int packetCount = 0;
    double totalEntropy = 0.0;
    bool alerted = false;
};
map<string, FlowData> activeFlows;


void signalHandler(int signum) {
    cout << "\n[System] Stopping Student Client..." << endl;
    running = false;
    if (handle) {
        pcap_breakloop(handle);
    }
}

// Standalone Watchdog Alert Function
void sendWatchdogAlert() {
    int alert_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (alert_sock < 0) return;

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        close(alert_sock); 
        return;
    }
    if (connect(alert_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(alert_sock); 
        return;
    }

    string alertStr = "Watchdog: Student Monitoring Thread/Process Killed!";
    Message msg = CreateMsg(msgTamper, currentStudentID, time(0), 0, alertStr.c_str(), alertStr.length());
    strncpy(msg.studentName, currentStudentName, 31); // BUG 1 FIX: Attach name
    
    char buffer[1024];
    int msgSize = serialize(msg, buffer, ""); 
    send(alert_sock, buffer, msgSize, 0);
    close(alert_sock);
}

bool performHandshake() {
    cout << "[Security] Initiating Secure Handshake..." << endl;
    
    Message initMsg = CreateMsg(msgHandshakeInit, currentStudentID, time(0), 0, NULL, 0);
    strncpy(initMsg.studentName, currentStudentName, 31);
    char buffer[1024];
    int size = serialize(initMsg, buffer, ""); 
    if (send(sock, buffer, size, 0) < 0) {
        return false;
    }

    size = recv(sock, buffer, 1024, 0);
    if (size <= 0) {
        return false;
    }
    
    Message keyMsg;
    deserialize(buffer, &keyMsg, ""); 
    
    if (keyMsg.msgType != msgHandshakeKey) {
        cerr << "[Error] Handshake failed: Expected Public Key." << endl;
        return false;
    }

    long long serverN, serverE;
    memcpy(&serverN, keyMsg.data, sizeof(long long));
    memcpy(&serverE, keyMsg.data + sizeof(long long), sizeof(long long));

    string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    currentSessionKey = "";
    srand(time(0));
    for (int i = 0; i < 16; ++i) {
        currentSessionKey += chars[rand() % chars.length()];
    }

    char encryptedPayload[512];
    int payloadOffset = 0;
    
    for (char c : currentSessionKey) {
        long long encryptedChar = Power((long long)c, serverE, serverN);
        memcpy(encryptedPayload + payloadOffset, &encryptedChar, sizeof(long long));
        payloadOffset += sizeof(long long);
    }

    Message responseMsg = CreateMsg(msgHandshakeResponse, currentStudentID, time(0), 0, encryptedPayload, payloadOffset);
    strncpy(responseMsg.studentName, currentStudentName, 31);
    size = serialize(responseMsg, buffer, ""); 
    send(sock, buffer, size, 0);

    size = recv(sock, buffer, 1024, 0);
    if (size > 0) {
        Message ackMsg;
        deserialize(buffer, &ackMsg, currentSessionKey); 
        if (ackMsg.msgType == msgACK) {
            cout << "[Security] Handshake Successful! Secure Tunnel Established." << endl;
            return true;
        }
    }
    
    return false;
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
        close(sock); 
        sock = 0; 
        return false;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock); 
        sock = 0; 
        return false;
    }
    
    if (!performHandshake()) {
        cerr << "[Error] Security Handshake Failed. Disconnecting." << endl;
        close(sock);
        sock = 0;
        return false;
    }
    
    return true;
}

// Time Synchronization Using Christian's Algorithm
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

    for (int i = 0; i < 3; i++) {
        Message req = CreateMsg(msgTimeRequest, currentStudentID, time(0), 0, NULL, 0);
        strncpy(req.studentName, currentStudentName, 31); // BUG 1 FIX
        
        auto t0 = std::chrono::steady_clock::now(); 
        
        char buffer[1024];
        int msgSize = serialize(req, buffer, currentSessionKey);
        if (send(sock, buffer, msgSize, 0) < 0) {
            continue;
        }

        int len = recv(sock, buffer, 1024, 0);
        auto t3 = std::chrono::steady_clock::now(); 

        if (len > 0) {
            Message res;
            deserialize(buffer, &res, currentSessionKey);
            if (res.msgType == msgTimeResponse) {
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
        long long latency = bestRTT / 2; 
        time_t predictedServerTime = bestServerTime + (latency / 1000); 
        clockOffset = predictedServerTime - time(0);
        
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
    
    if (isTimeSynced) {
        msg.timestamp = time(0) + clockOffset;
    } else {
        msg.timestamp = time(0);
    }
    
    if (msg.msgType == msgViolation || msg.msgType == msgTamper || msg.msgType == msgViolationCompressed) {
        pendingACKs[msg.sequenceNumber] = make_pair(msg, time(0));
    }

    if (sock > 0) {
        char buffer[1024];
        int msgSize = serialize(msg, buffer, currentSessionKey); 
        
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
        deserialize(buffer, &msg, currentSessionKey);
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
            int msgSize = serialize(it->second.first, buffer, currentSessionKey); 
            
            if (send(sock, buffer, msgSize, 0) < 0) {
                close(sock); 
                sock = 0;
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
        strncpy(msg.studentName, currentStudentName, 31);
        sendMessage(msg);
        lastHeartbeatTime = now;
    }
}

void checkTampering() {
    if (!isTimeSynced) return;

    auto nowMono = std::chrono::steady_clock::now();
    long long elapsedSecs = std::chrono::duration_cast<std::chrono::seconds>(nowMono - monotonicSyncTime).count();
    time_t trustedTime = serverSyncTime + elapsedSecs;

    time_t currentSystemTimeTrusted = time(0) + clockOffset;
    long long drift = abs(trustedTime - currentSystemTimeTrusted);

    if (drift > 30) { 
        cout << "[ALERT] System time manipulation detected! Drift: " << drift << "s" << endl;
        string alertMsg = "System Time Mismatch (Drift: " + to_string(drift) + "s)";
        
        Message msg = CreateMsg(msgTamper, currentStudentID, trustedTime, 0, alertMsg.c_str(), alertMsg.length());
        strncpy(msg.studentName, currentStudentName, 31);
        sendMessage(msg);
        
        lastCheckTime = time(0); 
    }
}

string findActiveInterface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    
    if (pcap_findalldevs(&alldevs, errbuf) != -1) {
        for (d = alldevs; d; d = d->next) {
            if (string(d->name) == "eno2" || string(d->name) == "en0") {
                string selected = d->name;
                pcap_freealldevs(alldevs);
                return selected;
            }
        }
        for (d = alldevs; d; d = d->next) {
            string name = d->name;
            if (name.find("lo") == string::npos && 
                name.find("bridge") == string::npos && 
                name.find("p2p") == string::npos && 
                name.find("utun") == string::npos) {  
                
                string selected = d->name;
                pcap_freealldevs(alldevs);
                return selected;
            }
        }
        pcap_freealldevs(alldevs);
    }
    
    return "eno2"; 
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

// Shannon Entropy for VPN Detection
double calculateShannonEntropy(const u_char* data, int length) {
    if (length <= 0) return 0.0;
    int counts[256] = {0};
    
    for (int i = 0; i < length; ++i) {
        counts[data[i]]++;
    }
    
    double entropy = 0.0;
    
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / length;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

string extractSNI(const u_char* payload, int payload_len) {
    if (payload_len < 43) return ""; 
    if (payload[0] != 0x16 || payload[1] != 0x03) return ""; 

    int pos = 5;
    if (pos >= payload_len || payload[pos] != 0x01) return ""; 

    pos += 38;
    if (pos >= payload_len) return "";

    int session_id_len = payload[pos++];
    pos += session_id_len;
    if (pos >= payload_len - 2) return "";

    int cipher_suites_len = (payload[pos] << 8) | payload[pos+1];
    pos += 2 + cipher_suites_len;
    if (pos >= payload_len - 1) return "";

    int comp_methods_len = payload[pos++];
    pos += comp_methods_len;
    if (pos >= payload_len - 2) return "";

    int ext_total_len = (payload[pos] << 8) | payload[pos+1];
    pos += 2;

    int end_pos = pos + ext_total_len;
    if (end_pos > payload_len) end_pos = payload_len;

    while (pos < end_pos - 4) {
        int ext_type = (payload[pos] << 8) | payload[pos+1];
        int ext_len = (payload[pos+2] << 8) | payload[pos+3];
        pos += 4;

        if (ext_type == 0x0000) { 
            if (pos + 2 > end_pos) break;
            int list_len = (payload[pos] << 8) | payload[pos+1];
            pos += 2;
            if (pos + 1 > end_pos) break;
            int name_type = payload[pos++];
            if (name_type == 0x00) { 
                if (pos + 2 > end_pos) break;
                int name_len = (payload[pos] << 8) | payload[pos+1];
                pos += 2;
                if (pos + name_len > end_pos) break;
                string sni((const char*)(payload + pos), name_len);
                return sni;
            }
        } else {
            pos += ext_len; 
        }
    }
    return "";
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int ip_header_offset = 14; 
    if (header->caplen < ip_header_offset + sizeof(struct ip)) return;
    
    struct ip *iph = (struct ip *)(packet + ip_header_offset);
    int ip_header_len = iph->ip_hl * 4;
    
    if (header->caplen < ip_header_offset + ip_header_len) return;

    uint16_t sport = 0, dport = 0;
    const u_char* payload = nullptr;
    int payload_len = 0;

    if (iph->ip_p == IPPROTO_UDP) {
        if (header->caplen < ip_header_offset + ip_header_len + sizeof(struct udphdr)) return;
        struct udphdr *udph = (struct udphdr *)(packet + ip_header_offset + ip_header_len);
        
        #ifdef __APPLE__
            sport = ntohs(udph->uh_sport);
            dport = ntohs(udph->uh_dport);
            payload_len = ntohs(udph->uh_ulen) - 8;
        #else
            sport = ntohs(udph->source);
            dport = ntohs(udph->dest);
            payload_len = ntohs(udph->len) - 8;
        #endif
        
        if (header->caplen >= ip_header_offset + ip_header_len + 8) {
            payload = packet + ip_header_offset + ip_header_len + 8;
        }

        if (dport == DNS_PORT) {
            int dns_offset = ip_header_offset + ip_header_len + 8;
            int query_offset = dns_offset + 12;
            
            if (header->caplen > query_offset) {
                int offset = query_offset;
                string website = parseDNSName(packet, offset);

                if (!website.empty()) {
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
                        cout << "[UNAUTHORIZED DNS] " << website << " detected!" << endl;
                        
                        Message msg = {}; 
                        msg.studentID = currentStudentID;
                        strncpy(msg.studentName, currentStudentName, 31);
                        if (isTimeSynced) msg.timestamp = time(0) + clockOffset;
                        else msg.timestamp = time(0);
                        msg.sequenceNumber = 0; 

                        msg.msgType = msgViolation;
                        strncpy(msg.data, website.c_str(), sizeof(msg.data) - 1);
                        msg.dataLength = website.length();
                        
                        sendMessage(msg);
                    }
                }
            }
        }
    } 
    else if (iph->ip_p == IPPROTO_TCP) {
        if (header->caplen < ip_header_offset + ip_header_len + sizeof(struct tcphdr)) return;
        struct tcphdr *tcph = (struct tcphdr *)(packet + ip_header_offset + ip_header_len);
        
        #ifdef __APPLE__
            sport = ntohs(tcph->th_sport);
            dport = ntohs(tcph->th_dport);
            int tcp_header_len = tcph->th_off * 4;
        #else
            sport = ntohs(tcph->source);
            dport = ntohs(tcph->dest);
            int tcp_header_len = tcph->doff * 4;
        #endif

        if (header->caplen >= ip_header_offset + ip_header_len + tcp_header_len) {
            payload = packet + ip_header_offset + ip_header_len + tcp_header_len;
            payload_len = header->caplen - (ip_header_offset + ip_header_len + tcp_header_len);
        }
    }

    if (payload_len > 0 && payload != nullptr) {
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(iph->ip_dst), dest_ip, INET_ADDRSTRLEN);
        
        if (Search(&whitelistTrie, string(dest_ip))) {
            return;
        }

        if (iph->ip_p == IPPROTO_TCP && (dport == 443 || sport == 443)) {
            
            if (dport == 443) {
                string sni = extractSNI(payload, payload_len);
                if (!sni.empty()) {
                    string tempCheck = sni;
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
                        cout << "[UNAUTHORIZED HTTPS SNI] " << sni << " detected!" << endl;
                        Message msg = {}; 
                        msg.studentID = currentStudentID;
                        strncpy(msg.studentName, currentStudentName, 31);
                        if (isTimeSynced) msg.timestamp = time(0) + clockOffset;
                        else msg.timestamp = time(0);
                        msg.sequenceNumber = 0; 

                        msg.msgType = msgViolation;
                        strncpy(msg.data, sni.c_str(), sizeof(msg.data) - 1);
                        msg.dataLength = sni.length();
                        
                        sendMessage(msg);
                    }
                }
            }
        }

        string flowKey = string(dest_ip) + ":" + to_string(dport);
        double entropy = calculateShannonEntropy(payload, payload_len);
        FlowData& flow = activeFlows[flowKey];
        
        if (!flow.alerted && flow.packetCount < 20) {
            flow.packetCount++;
            flow.totalEntropy += entropy;
            
            if (flow.packetCount >= 10) {
                double avgEntropy = flow.totalEntropy / flow.packetCount;
                if (avgEntropy > 7.8) {
                    flow.alerted = true; 
                    string alertMsg = "Potential VPN/Encrypted Tunnel Detected. Destination: " + string(dest_ip) + ". Sustained Entropy: " + to_string(avgEntropy);
                    cout << "\n[SECURITY ALERT] " << alertMsg << endl;
                    
                    Message msg = CreateMsg(msgViolation, currentStudentID, time(0), 0, alertMsg.c_str(), alertMsg.length());
                    strncpy(msg.studentName, currentStudentName, 31);
                    sendMessage(msg);
                }
            }
        }
    }
}

void run_student_logic_thread() {
    try {
        setStatus("Connecting to Server...");
        if (!connectToServer()) {
            setStatus("Connection Failed. Retrying...");
        } else {
            setStatus("Synchronizing Time...");
            synchronizeClock();
        }

        loadWhitelist();
        
        lastHeartbeatTime = time(0);
        lastCheckTime = time(0);

        string dev = findActiveInterface();
        if (dev.empty()) {
            cerr << "[Error] No active network interface found. (Try running with sudo)" << endl;
            setStatus("Error: No Interface found.");
            if (sock > 0) close(sock);
            return;
        }
        cout << "[System] Auto-selected interface: " << dev << endl;

        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(dev.c_str(), 65536, 1, 1000, errbuf);
        if (handle == NULL) {
            cerr << "Couldn't open device: " << errbuf << endl;
            setStatus("Error: Cannot open pcap device.");
            if (sock > 0) close(sock);
            return;
        }

        struct bpf_program fp;
        string bpf_filter = "ip and not (host " + string(SERVER_IP) + " and port " + to_string(PORT) + ")";
        
        if (pcap_compile(handle, &fp, bpf_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) return;
        if (pcap_setfilter(handle, &fp) == -1) return;

        cout << "[System] Monitoring Network Traffic (DNS, SNI, DPI & Entropy)..." << endl;
        setStatus("Monitoring Network Traffic securely...");
        
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
            checkTampering(); 
            processPendingMessages();
        }

        pcap_close(handle);
        if (sock > 0) close(sock);
    } catch (...) {
        threadCrashed = true; 
    }
}

void WatchdogThread() {
    while (running) {
        if (threadCrashed) {
            cout << "\n[ALERT] Worker Thread killed! Sending Tamper Alert..." << endl;
            sendWatchdogAlert(); 
            threadCrashed = false;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// UI
char inputName[256] = "";
char inputId[256] = "";

void RenderStudentLoginWindow() {
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.5f); 
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 0.0f);   

    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.0f, 0.0f, 0.0f, 1.0f)); 
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));     
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.0f, 0.0f, 0.0f, 1.0f));  
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));   

    ImGui::Begin("StudentLogin", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar);

    ImVec2 windowSize = ImGui::GetWindowSize();
    float contentWidth = 350.0f; 

    ImGui::SetCursorPosY(windowSize.y * 0.25f); 

    ImGui::SetWindowFontScale(2.0f); 
    const char* title = "Student Dashboard";
    ImGui::SetCursorPosX((windowSize.x - ImGui::CalcTextSize(title).x) * 0.5f);
    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "%s", title); 
    ImGui::SetWindowFontScale(1.2f); 

    ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

    ImGui::SetCursorPosX((windowSize.x - contentWidth) * 0.5f);
    ImGui::Text("Name :");
    ImGui::SameLine();
    ImGui::SetCursorPosX((windowSize.x - contentWidth) * 0.5f + 80);
    ImGui::SetNextItemWidth(contentWidth - 80);
    ImGui::InputText("##name", inputName, IM_ARRAYSIZE(inputName));

    ImGui::Spacing(); ImGui::Spacing();

    ImGui::SetCursorPosX((windowSize.x - contentWidth) * 0.5f);
    ImGui::Text("Id   :");
    ImGui::SameLine();
    ImGui::SetCursorPosX((windowSize.x - contentWidth) * 0.5f + 80);
    ImGui::SetNextItemWidth(contentWidth - 80);
    ImGui::InputText("##id", inputId, IM_ARRAYSIZE(inputId));

    ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();

    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 1.0f, 0.0f, 1.0f));        
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.0f, 0.8f, 0.0f, 1.0f)); 
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.0f, 0.6f, 0.0f, 1.0f));  
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));          

    float buttonWidth = 120.0f;
    ImGui::SetCursorPosX((windowSize.x - buttonWidth) * 0.5f);
    
    if (ImGui::Button("Enter", ImVec2(buttonWidth, 40))) {
        if (strlen(inputName) > 0 && strlen(inputId) > 0) {
            currentStudentID = std::stoi(inputId);
            strncpy(currentStudentName, inputName, 31);
            isMonitoring = true;
            std::thread(run_student_logic_thread).detach();
        }
    }

    ImGui::PopStyleColor(4); 
    ImGui::End();
    ImGui::PopStyleColor(4); 
    ImGui::PopStyleVar(4);   
}


// MAIN UI
int main() {
    cout << "--- ARGUS STUDENT CLIENT (SECURE) ---" << endl;

    if (!glfwInit()) return -1;
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif

    GLFWwindow* window = glfwCreateWindow(600, 400, "Argus Student Agent", NULL, NULL);
    if (!window) { glfwTerminate(); return -1; }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 150");

    std::thread watchdog(WatchdogThread);
    watchdog.detach();

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        if (!isMonitoring) {
            RenderStudentLoginWindow();
        } else {
            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
            ImGui::Begin("Active Monitoring", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);
            
            ImGui::Text("Logged in as:");
            ImGui::SetWindowFontScale(1.5f);
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "%s", currentStudentName);
            ImGui::SetWindowFontScale(1.0f);
            ImGui::Text("ID: %d", currentStudentID);
            
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            
            std::string currentStatus = getStatus();
            ImGui::Text("System Status:");
            ImGui::TextColored(ImVec4(0.0f, 0.8f, 1.0f, 1.0f), "%s", currentStatus.c_str());
            
            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();
            ImGui::TextWrapped("WARNING: Do not close this application. Secure exam monitoring is currently active in the background. Exiting will trigger a tamper alert to the supervisor.");
            
            ImGui::SetCursorPosY(ImGui::GetWindowSize().y - 60);
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.7f, 0.1f, 0.1f, 1.0f));
            if (ImGui::Button("🛑 Exit Secure Session", ImVec2(ImGui::GetContentRegionAvail().x, 40))) {
                running = false;
                glfwSetWindowShouldClose(window, true);
            }
            ImGui::PopStyleColor(3);

            ImGui::End();
        }

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    running = false;
    if (sock > 0) {
        std::string alertStr = "Watchdog: Student Process Killed Manually!";
        Message msg = CreateMsg(msgTamper, currentStudentID, time(0), 0, alertStr.c_str(), alertStr.length());
        char buffer[1024];
        int msgSize = serialize(msg, buffer, currentSessionKey);
        send(sock, buffer, msgSize, 0);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}