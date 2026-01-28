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
#include "../../Common/include/protocol.h"
#include "../../Common/include/trie.h"

using namespace std;

// --- Config ---
#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define DNS_PORT 53
#define WHITELIST_PATH "../config/whitelist.txt" 

// --- Globals ---
int sock = 0;
pcap_t *handle = nullptr;
uint32_t currentStudentID = 0;
Trie whitelistTrie;

// --- Helper: Clean Exit ---
void signalHandler(int signum) {
    cout << "\n[System] Stopping Student Client..." << endl;
    if (handle) pcap_breakloop(handle);
    if (sock > 0) close(sock);
    exit(signum);
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

// --- Helper: Trim String (Removes \r, \n, spaces) ---
// This is critical for reading files created on Windows/Different OS
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
        cerr << "        (Ensure you are running from ARGUS/Code/Student/Src/)" << endl;
        // Fallback default
        Insert(&whitelistTrie, "google.com");
        return;
    }

    string line;
    int count = 0;
    while (getline(file, line)) {
        string domain = trim(line);
        // Skip empty lines or comments
        if (domain.empty() || domain[0] == '#' || domain[0] == '[') continue;
        
        Insert(&whitelistTrie, domain);
        count++;
    }
    file.close();
    cout << "[System] Whitelist loaded (" << count << " entries)." << endl;
}

// --- Packet Handler ---
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int ip_header_offset = 14;
    struct ip *iph = (struct ip *)(packet + ip_header_offset);
    int ip_header_len = iph->ip_hl * 4;

    struct udphdr *udph = (struct udphdr *)(packet + ip_header_offset + ip_header_len);
    
    // Check ports (Using macOS compatible names uh_sport/uh_dport)
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
        msg.timestamp = time(0); 
        strncpy(msg.data, website.c_str(), sizeof(msg.data) - 1);
        msg.dataLength = website.length();
        
        // Critical Fix: Calculate checksum AND assign it
        msg.checksum = CalculateChecksum(msg); 

        char buffer[1024];
        serialize(msg, buffer); 
        
        if (send(sock, buffer, sizeof(Message), 0) < 0) {
            // Silently ignore send errors to avoid spam
        } else {
             cout << " [Reported] Violation sent to supervisor." << endl;
        }
    } else {
        // Optional: Uncomment to see allowed traffic
        // cout << "[ALLOWED] " << website << endl;
    }
}

int main() {
    signal(SIGINT, signalHandler);

    cout << "--- ARGUS STUDENT CLIENT ---" << endl;
    cout << "Enter Student ID: ";
    cin >> currentStudentID;

    // 1. Connect
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        return -1;
    }
    cout << "[Success] Connected to Supervisor!" << endl;

    // 2. Load Whitelist
    loadWhitelist();

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

    if (choice < 1 || choice > i) {
        cout << "Invalid choice." << endl;
        return 1;
    }

    d = alldevs;
    for (int j = 1; j < choice; j++) d = d->next;
    
    string dev = d->name;
    cout << "Selected device: " << dev << endl;
    
    pcap_freealldevs(alldevs);

    // 4. Open PCAP
    handle = pcap_open_live(dev.c_str(), 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Couldn't open device " << dev << ": " << errbuf << endl;
        close(sock);
        return 2;
    }

    struct bpf_program fp;
    // Filter for DNS traffic only
    if (pcap_compile(handle, &fp, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Filter compile error" << endl;
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Filter set error" << endl;
        return 2;
    }

    cout << "[System] Monitoring DNS traffic..." << endl;
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    close(sock);
    return 0;
}