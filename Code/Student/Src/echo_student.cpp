#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include "../../Common/include/protocol.h"
#include "../../Common/include/trie.h"

using namespace std;

struct pseudo_iphdr {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct pseudo_udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

void GetDomainName(unsigned char* dns, unsigned char* buffer, string& domain) {
    int i = 0;
    while (dns[i] != 0) {
        int length = dns[i];
        for (int j = 0; j < length; j++) {
            i++;
            domain += (char)dns[i];
        }
        i++;
        if (dns[i] != 0) {
            domain += '.';
        }
    }
}

int main() {
    string studentName, studentIDStr;
    cout << " Enter Your Name: ";
    getline(cin, studentName);
    cout << " Enter Your Student Id No: ";
    getline(cin, studentIDStr);
    
    uint32_t myID = 0;
    try {
        myID = stoi(studentIDStr);
    } catch(...) {
        myID = 99999;
    }

    Trie* whitelist = new Trie();
    if (Load(whitelist, "../config/whitelist.txt")) {
        cout << "Whitelist loaded" << endl;
    } else {
        cout << "Could not load whitelist" << endl;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cout << "Could not connect to Supervisor" << endl;
    } else {
        cout << "Connected to Supervisor" << endl;
    }

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_sock < 0) {
        cout << "ERROR: Could not create raw socket" << endl;
        return 1;
    }
    
    unsigned char buffer[65536];

    while (true) {
        memset(buffer, 0, 65536);
        
        int data_size = recvfrom(raw_sock, buffer, 65536, 0, NULL, NULL);
        if (data_size < 0) continue;

        struct pseudo_iphdr *ip_header = (struct pseudo_iphdr*)buffer;
        int ip_len = (ip_header->version_ihl & 0x0F) * 4;

        struct pseudo_udphdr *udp_header = (struct pseudo_udphdr*)(buffer + ip_len);

        if (ntohs(udp_header->dest) == 53) {
            unsigned char* dns_part = buffer + ip_len + sizeof(struct udphdr);
            unsigned char* dns_question = dns_part + 12;

            string website = "";
            GetDomainName(dns_question, buffer, website);

            cout << "Found DNS Request: " << website << endl;

            bool isAllowed = WildcardMatch(whitelist, website);

            if (!isAllowed) {
                cout << "VIOLATION! Sending alert..." << endl;
                Message msg = CreateMsg(msgViolation, myID, time(0), website.c_str(), website.length());
                
                char sendBuffer[1024];
                int bytesToSend = serialize(msg, sendBuffer);
                
                send(sock, sendBuffer, bytesToSend, 0);
            } else {
                cout << "ALLOWED" << endl;
            }
        }
    }

    close(sock);
    close(raw_sock);
    return 0;
}