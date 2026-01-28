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
#include <queue> 
#include <ctime>
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

// Feature Globals
queue<Message> offlineQueue;
time_t lastHeartbeatTime = 0;
time_t lastCheckTime = 0;

// --- Helper: Clean Exit ---
void signalHandler(int signum) {
    cout << "\n[System] Stopping Student Client..." << endl;
    running = false;
    if (handle) pcap_breakloop(handle);
}

// --- Helper: Connection Management ---
bool connectToServer() {
    if (sock > 0) return true; // Already connected

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

// --- Helper: Send or Queue Message ---
void sendMessage(Message& msg) {
    // Ensure checksum is calculated
    msg.checksum = CalculateChecksum(msg);

    bool sent = false;
    if (sock > 0) {
        char buffer[1024];
        serialize(msg, buffer);
        
        // Using sizeof(Message) to match original protocol expectations
        if (send(sock, buffer, sizeof(Message), 0) >= 0) {
            sent = true;
        } else {
            cout << "[Error] Send failed. Connection lost." << endl;
            close(sock);
            sock = 0;
        }
    }

    if (!sent) {
        cout << "[System] Offline. Message queued." << endl;
        offlineQueue.push(msg);
    }
}

// --- Feature: Flush Offline Queue ---
void processQueue() {
    // Try to reconnect if disconnected
    if (sock == 0) {
        if (!connectToServer()) return; // Still offline
    }

    while (!offlineQueue.empty()) {
        if (sock == 0) break; // Lost connection while flushing

        Message msg = offlineQueue.front();
        char buffer[1024];
        serialize(msg, buffer);

        if (send(sock, buffer, sizeof(Message), 0) < 0) {
             cout << "[Error] Send failed during flush. Stopping." << endl;
             close(sock);
             sock = 0;
             break;
        } else {
            cout << "[Queue] Sent buffered message." << endl;
            offlineQueue.pop();
        }
    }
}

// --- Feature: Heartbeat ---
void checkHeartbeat() {
    time_t now = time(0);
    if (difftime(now, lastHeartbeatTime) >= HEARTBEAT_INTERVAL) {
        // Create and send heartbeat
        Message msg = CreateMsg(msgHeartbeat, currentStudentID, now, NULL, 0);
        sendMessage(msg);
        lastHeartbeatTime = now;
    }
}

// --- Feature: Anti-Tampering ---
void checkTampering() {
    time_t now = time(0);
    // If system time is earlier than the last check, time was moved backwards
    if (now < lastCheckTime) {
        cout << "[ALERT] System time manipulation detected!" << endl;
        string alertMsg = "System Time Moved Backwards";
        Message msg = CreateMsg(msgTamper, currentStudentID, now, alertMsg.c_str(), alertMsg.length());
        sendMessage(msg);
    }
    lastCheckTime = now;
}

// --- Helper: Parse DNS Name ---
string parseDNSName(const u_char* packet, int& offset) {
    string name = "";
    int len = packet[offset++];
    
    while (len != 0) {
        if (len >= 192) { // Compression pointer
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

// --- Helper: Trim String ---
string trim(const string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (string::npos == first) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// --- Helper: Load Whitelist ---
void loadWhitelist() {
    ifstream file(WHITELIST_PATH);
    if (!file.is_open()) {
        cerr << "[Error] Could not open whitelist at: " << WHITELIST_PATH << endl;
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
    cout << "[System] Whitelist loaded (" << count << " entries)." << endl;
}

// --- Packet Handler Logic ---
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int ip_header_offset = 14;
    struct ip *iph = (struct ip *)(packet + ip_header_offset);
    int ip_header_len = iph->ip_hl * 4;

    struct udphdr *udph = (struct udphdr *)(packet + ip_header_offset + ip_header_len);
    
    if (ntohs(udph->uh_sport) != DNS_PORT && ntohs(udph->uh_dport) != DNS_PORT) return;

    int dns_offset = ip_header_offset + ip_header_len + 8;
    int query_offset = dns_offset + 12;
    string website = parseDNSName(packet, query_offset);

    if (website.empty()) return;

    // Check Violation
    if (!Search(&whitelistTrie, website)) {
        cout << "[UNAUTHORIZED] " << website << " detected!" << endl;
        
        Message msg;
        msg.msgType = msgViolation;
        msg.studentID = currentStudentID;
        strncpy(msg.studentName, currentStudentName, 31);
        msg.timestamp = time(0); 
        strncpy(msg.data, website.c_str(), sizeof(msg.data) - 1);
        msg.dataLength = website.length();
        
        // Use new send function with queue support
        sendMessage(msg);
    }
}

int main() {
    signal(SIGINT, signalHandler);

    cout << "--- ARGUS STUDENT CLIENT ---" << endl;
    cout << "Enter Student ID: ";
    cin >> currentStudentID;
    cout << "Enter Student Name: ";
    cin.ignore();
    cin.getline(currentStudentName, 32);

    // 1. Initial Connect
    connectToServer();

    // 2. Load Whitelist
    loadWhitelist();

    // Initialize Timers
    lastHeartbeatTime = time(0);
    lastCheckTime = time(0);

    // 3. Select Interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    cout << "\nAvailable Interfaces:" << endl;
    int i = 0;
    for (d = alldevs; d; d = d->next) {
        cout << ++i << ". " << d->name;
        if (d->description) cout << " (" << d->description << ")";
        cout << endl;
    }

    if (i == 0) {
        cout << "No interfaces found! (Did you run with sudo?)" << endl;
        return 1;
    }

    int choice;
    cout << "Select Interface (Recommended: 'lo0' for test, 'en0' for wifi): ";
    cin >> choice;

    if (choice < 1 || choice > i) return 1;

    d = alldevs;
    for (int j = 1; j < choice; j++) d = d->next;
    
    string dev = d->name;
    cout << "Selected device: " << dev << endl;
    pcap_freealldevs(alldevs);

    // 4. Open PCAP
    // 1000ms timeout is important for the main loop to tick
    handle = pcap_open_live(dev.c_str(), 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Couldn't open device: " << errbuf << endl;
        if (sock > 0) close(sock);
        return 2;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) return 2;
    if (pcap_setfilter(handle, &fp) == -1) return 2;

    cout << "[System] Monitoring DNS traffic..." << endl;
    
    // Main Loop (Replaced pcap_loop for periodic tasks)
    while (running) {
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        
        // pcap_next_ex returns: 1 (packet), 0 (timeout), -1 (error), -2 (break)
        int res = pcap_next_ex(handle, &header, &pkt_data);
        
        if (res == 1) {
            packet_handler(NULL, header, pkt_data);
        } else if (res == -1) {
            cerr << "Error reading packet: " << pcap_geterr(handle) << endl;
            break;
        } else if (res == -2) {
            break; // Loop broken
        }
        
        // Periodic Tasks
        checkHeartbeat();
        checkTampering();
        processQueue();
    }

    pcap_close(handle);
    if (sock > 0) close(sock);
    return 0;
}