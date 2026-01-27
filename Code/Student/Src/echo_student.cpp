#include <iostream>
#include <string>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <time.h>
#include <cerrno>
#include "../../Common/include/protocol.h"
#include "../../Common/include/trie.h"

using namespace std;

Trie* whitelist = nullptr;
int supervisor_socket = -1; 
uint32_t myStudentID = 0;

void GetDomainName(const u_char* dns, const u_char* packet_end, string& domain) {
    int i = 0;
    while (dns + i < packet_end && dns[i] != 0) {
        int length = dns[i];
        if (dns + i + length + 1 >= packet_end) return; 
        for (int j = 0; j < length; j++) {
            i++;
            domain += (char)dns[i];
        }
        i++;
        if (dns[i] != 0) domain += '.';
    }
}

void SendAlert(string website) {
    if (supervisor_socket < 0) return;

    Message msg = CreateMsg(msgViolation, myStudentID, time(0), website.c_str(), website.length());
    
    char sendBuffer[1024];
    int bytesToSend = serialize(msg, sendBuffer);
    
    int bytesSent = send(supervisor_socket, sendBuffer, bytesToSend, 0);
    if (bytesSent < 0) {
        close(supervisor_socket);
        supervisor_socket = -1;
        cout << "\033[1;33m[Error] Supervisor disconnected.\033[0m" << endl;
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;

    struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    const struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    int ip_len = ip_header->ip_hl * 4;

    if (ip_header->ip_p != IPPROTO_UDP) return;

    const struct udphdr *udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_len);
    
    if (ntohs(udp_header->uh_dport) == 53) {
        const u_char* dns_part = packet + sizeof(struct ether_header) + ip_len + sizeof(struct udphdr);
        const u_char* dns_question = dns_part + 12; 
        const u_char* packet_end = packet + header->caplen;

        if (dns_question > packet_end) return;

        string website = "";
        GetDomainName(dns_question, packet_end, website);

        if (!website.empty()) {
            bool isAllowed = WildcardMatch(whitelist, website);
            if (!isAllowed) {
                cout << "\033[1;31m[UNAUTHORIZED] " << website << "\033[0m" << endl;
                SendAlert(website); 
            } else {
                cout << "\033[1;32m[ALLOWED] " << website << "\033[0m" << endl;
            }
        }
    }
}

int main() {
    setbuf(stdout, NULL);

    cout << "--- MacOS DNS Monitor (Student Client) ---" << endl;
    
    string idStr;
    cout << "Enter Student ID: ";
    getline(cin, idStr);
    try { myStudentID = stoi(idStr); } catch(...) { myStudentID = 99999; }

    cout << "[System] Connecting to Supervisor (127.0.0.1:8080)..." << endl;
    
    supervisor_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    int attempts = 0;
    while (connect(supervisor_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        attempts++;
        cout << "   ... Connection attempt " << attempts << " failed. Retrying in 1s..." << endl;
        sleep(1);
        if (attempts >= 3) {
            cout << "\033[1;33m[Warning] Supervisor NOT FOUND. Running in Offline Mode.\033[0m" << endl;
            supervisor_socket = -1;
            break;
        }
    }
    
    if (supervisor_socket != -1) {
        cout << "\033[1;32m[Success] Connected to Supervisor!\033[0m" << endl;
    }

    whitelist = new Trie();
    if (!Load(whitelist, "../config/whitelist.txt")) {
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) return 1;

    cout << "\nSelect Interface:" << endl;
    int i = 0;
    vector<string> devNames;
    for(pcap_if_t *d = alldevs; d; d = d->next) {
        cout << ++i << ". " << d->name << (d->description ? d->description : "") << endl;
        devNames.push_back(d->name);
    }

    int choice;
    cout << "Choice: ";
    cin >> choice;
    if (choice < 1 || choice > i) return 1;
    
    string dev = devNames[choice-1];
    pcap_freealldevs(alldevs);


    pcap_t *handle = pcap_create(dev.c_str(), errbuf);
    
    pcap_set_timeout(handle, 1);
    pcap_set_snaplen(handle, 65536);
    pcap_set_promisc(handle, 1);
    pcap_set_immediate_mode(handle, 1);
    pcap_activate(handle);

    struct bpf_program fp;
    pcap_compile(handle, &fp, "udp dst port 53", 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    cout << "[System] Monitoring active on " << dev << "..." << endl;
    pcap_loop(handle, 0, packet_handler, NULL);

    close(supervisor_socket);
    pcap_close(handle);
    delete whitelist;
    return 0;
}