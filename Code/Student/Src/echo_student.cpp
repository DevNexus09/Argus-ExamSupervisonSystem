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
#include "../../Common/include/protocol.h"
#include "../../Common/include/trie.h"
#include "../../Common/include/huffman.h"

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
Trie blacklistTrie; // NEW: Trie for Deep Packet Inspection keywords
bool running = true;
string currentSessionKey = ""; 

HuffmanCoding studentHuffman;

// Reliability Globals
map<uint32_t, pair<Message, time_t>> pendingACKs; 
uint32_t globalSequenceNum = 0;
time_t lastHeartbeatTime = 0;
time_t lastCheckTime = 0;

// Time Synchronization Globals
int64_t clockOffset = 0; 
time_t serverSyncTime = 0;
std::chrono::steady_clock::time_point monotonicSyncTime;
bool isTimeSynced = false;

// --- Flow-Based Analysis Data Structures ---
struct FlowData {
    int packetCount = 0;
    double totalEntropy = 0.0;
    bool alerted = false;
};
map<string, FlowData> activeFlows;

// --- FORWARD DECLARATIONS ---
void signalHandler(int signum);
bool connectToServer();
bool performHandshake();
void sendMessage(Message& msg);
void handleIncomingACKs();
void processPendingMessages();
void checkHeartbeat();
void checkTampering();
void synchronizeClock(); 
string findActiveInterface();
string parseDNSName(const u_char* packet, int& offset);
string trim(const string& str);
void loadWhitelist();
void loadBlacklist(); // NEW
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void run_student_logic();   
void sendWatchdogAlert();   
double calculateShannonEntropy(const u_char* data, int length);
string extractSNI(const u_char* payload, int payload_len); // NEW

// --- Implementations ---

void signalHandler(int signum) {
    cout << "\n[System] Stopping Student Client..." << endl;
    running = false;
    if (handle) pcap_breakloop(handle);
}

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
    int msgSize = serialize(msg, buffer, ""); 
    send(alert_sock, buffer, msgSize, 0);
    close(alert_sock);
}

bool performHandshake() {
    cout << "[Security] Initiating Secure Handshake..." << endl;
    
    Message initMsg = CreateMsg(msgHandshakeInit, currentStudentID, time(0), 0, NULL, 0);
    char buffer[1024];
    int size = serialize(initMsg, buffer, ""); 
    if (send(sock, buffer, size, 0) < 0) return false;

    size = recv(sock, buffer, 1024, 0);
    if (size <= 0) return false;
    
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
    for (int i = 0; i < 16; ++i) currentSessionKey += chars[rand() % chars.length()];

    cout << "[Security] Generated Session Key: " << currentSessionKey << endl;

    char encryptedPayload[512];
    int payloadOffset = 0;
    
    for (char c : currentSessionKey) {
        long long encryptedChar = Power((long long)c, serverE, serverN);
        memcpy(encryptedPayload + payloadOffset, &encryptedChar, sizeof(long long));
        payloadOffset += sizeof(long long);
    }

    Message responseMsg = CreateMsg(msgHandshakeResponse, currentStudentID, time(0), 0, encryptedPayload, payloadOffset);
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
        close(sock); sock = 0; return false;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock); sock = 0; return false;
    }
    
    if (!performHandshake()) {
        cerr << "[Error] Security Handshake Failed. Disconnecting." << endl;
        close(sock);
        sock = 0;
        return false;
    }
    
    return true;
}

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
        
        auto t0 = std::chrono::steady_clock::now(); 
        
        char buffer[1024];
        int msgSize = serialize(req, buffer, currentSessionKey);
        if (send(sock, buffer, msgSize, 0) < 0) continue;

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

    auto nowMono = std::chrono::steady_clock::now();
    long long elapsedSecs = std::chrono::duration_cast<std::chrono::seconds>(nowMono - monotonicSyncTime).count();
    time_t trustedTime = serverSyncTime + elapsedSecs;

    time_t currentSystemTimeTrusted = time(0) + clockOffset;
    long long drift = abs(trustedTime - currentSystemTimeTrusted);

    if (drift > 30) { 
        cout << "[ALERT] System time manipulation detected! Drift: " << drift << "s" << endl;
        string alertMsg = "System Time Mismatch (Drift: " + to_string(drift) + "s)";
        
        Message msg = CreateMsg(msgTamper, currentStudentID, trustedTime, 0, alertMsg.c_str(), alertMsg.length());
        sendMessage(msg);
        
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

// --- NEW: Load Blacklist for Deep Packet Inspection (Aho-Corasick) ---
void loadBlacklist() {
    const char* paths[] = {
        "Code/Student/config/blacklist.txt",
        "../config/blacklist.txt",
        "blacklist.txt"
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
        cout << "[System] Blacklist file not found, loading defaults for DPI." << endl;
        Insert(&blacklistTrie, "chatgpt");
        Insert(&blacklistTrie, "facebook");
        Insert(&blacklistTrie, "tiktok");
        Insert(&blacklistTrie, "instagram");
        Insert(&blacklistTrie, "discord");
    } else {
        string line;
        int count = 0;
        while (getline(file, line)) {
            string keyword = trim(line);
            if (keyword.empty() || keyword[0] == '#' || keyword[0] == '[') continue;
            Insert(&blacklistTrie, keyword);
            count++;
        }
        file.close();
        cout << "[System] Blacklist loaded from " << loadedPath << " (" << count << " entries)." << endl;
    }

    // Build failure links for Aho-Corasick Automaton
    BuildFailureLinks(&blacklistTrie);
    cout << "[System] Aho-Corasick Automaton Built for DPI Payload Scanning." << endl;
}

// --- Calculates Shannon Entropy formula for the given payload ---
double calculateShannonEntropy(const u_char* data, int length) {
    if (length <= 0) return 0.0;
    int counts[256] = {0};
    
    // Step 1: Frequency Analysis
    for (int i = 0; i < length; ++i) {
        counts[data[i]]++;
    }
    
    double entropy = 0.0;
    
    // Step 2 & 3: Probability and Entropy Summation
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / length;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// --- NEW: TLS Deep Packet Inspection (Extract Server Name Indication) ---
string extractSNI(const u_char* payload, int payload_len) {
    if (payload_len < 43) return ""; // Minimum size for ClientHello
    if (payload[0] != 0x16 || payload[1] != 0x03) return ""; // Not a TLS Handshake

    // Skip Record Header (5 bytes)
    int pos = 5;
    if (pos >= payload_len || payload[pos] != 0x01) return ""; // Not ClientHello

    // Skip Handshake Header (4 bytes) + Client Version (2 bytes) + Random (32 bytes)
    pos += 38;
    if (pos >= payload_len) return "";

    // Session ID length
    int session_id_len = payload[pos++];
    pos += session_id_len;
    if (pos >= payload_len - 2) return "";

    // Cipher Suites length
    int cipher_suites_len = (payload[pos] << 8) | payload[pos+1];
    pos += 2 + cipher_suites_len;
    if (pos >= payload_len - 1) return "";

    // Compression Methods length
    int comp_methods_len = payload[pos++];
    pos += comp_methods_len;
    if (pos >= payload_len - 2) return "";

    // Extensions Length
    int ext_total_len = (payload[pos] << 8) | payload[pos+1];
    pos += 2;

    int end_pos = pos + ext_total_len;
    if (end_pos > payload_len) end_pos = payload_len;

    while (pos < end_pos - 4) {
        int ext_type = (payload[pos] << 8) | payload[pos+1];
        int ext_len = (payload[pos+2] << 8) | payload[pos+3];
        pos += 4;

        if (ext_type == 0x0000) { // Server Name (SNI)
            if (pos + 2 > end_pos) break;
            int list_len = (payload[pos] << 8) | payload[pos+1];
            pos += 2;
            if (pos + 1 > end_pos) break;
            int name_type = payload[pos++];
            if (name_type == 0x00) { // host_name
                if (pos + 2 > end_pos) break;
                int name_len = (payload[pos] << 8) | payload[pos+1];
                pos += 2;
                if (pos + name_len > end_pos) break;
                string sni((const char*)(payload + pos), name_len);
                return sni;
            }
        } else {
            pos += ext_len; // Skip this extension
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

    // --- Protocol Agnostic Payload Extraction ---
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

        // --- Original DNS Checking Logic ---
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
                        
                        char compressedBuffer[512];
                        int compressedLen = 0;
                        studentHuffman.Compress(website.c_str(), website.length(), compressedBuffer, compressedLen);

                        Message msg;
                        msg.studentID = currentStudentID;
                        strncpy(msg.studentName, currentStudentName, 31);
                        if (isTimeSynced) msg.timestamp = time(0) + clockOffset;
                        else msg.timestamp = time(0);
                        msg.sequenceNumber = 0; 

                        if (compressedLen > 0 && compressedLen < website.length()) {
                            cout << "  -> Compressing violation data (" << website.length() << "B -> " << compressedLen << "B)" << endl;
                            msg.msgType = msgViolationCompressed;
                            memcpy(msg.data, compressedBuffer, compressedLen);
                            msg.dataLength = compressedLen;
                        } else {
                            msg.msgType = msgViolation;
                            strncpy(msg.data, website.c_str(), sizeof(msg.data) - 1);
                            msg.dataLength = website.length();
                        }
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
        
        // Exemption: If Dest IP is manually whitelisted, ignore
        if (Search(&whitelistTrie, string(dest_ip))) {
            return;
        }

        // --- NEW: Deep Packet Inspection & Aho-Corasick Analysis ---
        if (iph->ip_p == IPPROTO_TCP && (dport == 443 || sport == 443)) {
            
            // 1. SNI Extraction (TLS ClientHello Parsing)
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
                        char compressedBuffer[512];
                        int compressedLen = 0;
                        studentHuffman.Compress(sni.c_str(), sni.length(), compressedBuffer, compressedLen);
                        Message msg;
                        msg.studentID = currentStudentID;
                        strncpy(msg.studentName, currentStudentName, 31);
                        if (isTimeSynced) msg.timestamp = time(0) + clockOffset;
                        else msg.timestamp = time(0);
                        msg.sequenceNumber = 0; 

                        if (compressedLen > 0 && compressedLen < sni.length()) {
                            msg.msgType = msgViolationCompressed;
                            memcpy(msg.data, compressedBuffer, compressedLen);
                            msg.dataLength = compressedLen;
                        } else {
                            msg.msgType = msgViolation;
                            strncpy(msg.data, sni.c_str(), sizeof(msg.data) - 1);
                            msg.dataLength = sni.length();
                        }
                        sendMessage(msg);
                    }
                }
            }

            // 2. Aho-Corasick O(n) Payload Automaton Scanning
            if (AhoCorasickSearch(&blacklistTrie, (const char*)payload, payload_len)) {
                string alertMsg = "DPI Blocked Content. Dest IP: " + string(dest_ip);
                cout << "\n[SECURITY ALERT] Deep Packet Inspection Flagged Raw Payload Content!" << endl;
                Message msg = CreateMsg(msgViolation, currentStudentID, time(0), 0, alertMsg.c_str(), alertMsg.length());
                strncpy(msg.studentName, currentStudentName, 31);
                sendMessage(msg);
            }
        }

        // --- Shannon Entropy & Flow-Based Analysis Engine (Existing) ---
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

void run_student_logic() {
    signal(SIGINT, signalHandler);

    connectToServer();
    loadWhitelist();
    loadBlacklist(); // NEW: Load DPI keyword blacklist
    
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
    string bpf_filter = "ip and not (host " + string(SERVER_IP) + " and port " + to_string(PORT) + ")";
    
    if (pcap_compile(handle, &fp, bpf_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) exit(EXIT_FAILURE);
    if (pcap_setfilter(handle, &fp) == -1) exit(EXIT_FAILURE);

    cout << "[System] Monitoring Network Traffic (DNS, SNI, DPI & Entropy)..." << endl;
    
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
}

int main() {
    cout << "--- ARGUS STUDENT CLIENT (SECURE) ---" << endl;
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