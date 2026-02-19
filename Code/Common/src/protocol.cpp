#include "../include/protocol.h"
#include <cstring>
#include <arpa/inet.h>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <ctime>

using namespace std;

// --- Encryption Logic (RC4) ---
void RC4_Logic(char* data, int length, const string& key) {
    if (key.empty()) return; // Skip if no key provided (Handshake messages)

    vector<int> S(256);
    for(int i=0; i<256; i++) S[i] = i;
    
    int j = 0;
    for(int i=0; i<256; i++) {
        j = (j + S[i] + key[i % key.length()]) % 256;
        swap(S[i], S[j]);
    }

    int i = 0; j = 0;
    for (int k = 0; k < length; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(S[i], S[j]);
        int rnd = S[(S[i] + S[j]) % 256];
        data[k] ^= rnd;
    }
}

void SecureEncrypt(char* data, int length, const string& key) {
    RC4_Logic(data, length, key);
}

void SecureDecrypt(char* data, int length, const string& key) {
    RC4_Logic(data, length, key);
}

// --- RSA Math Implementations ---

long long Power(long long base, long long exp, long long mod) {
    long long res = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) res = (res * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return res;
}

long long GCD(long long a, long long b) {
    return b == 0 ? a : GCD(b, a % b);
}

long long ExtendedGCD(long long a, long long b, long long &x, long long &y) {
    if (a == 0) {
        x = 0; y = 1;
        return b;
    }
    long long x1, y1;
    long long gcd = ExtendedGCD(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return gcd;
}

long long ModInverse(long long e, long long phi) {
    long long x, y;
    long long g = ExtendedGCD(e, phi, x, y);
    if (g != 1) return -1;
    return (x % phi + phi) % phi;
}

bool IsPrime(long long n) {
    if (n <= 1) return false;
    for (long long i = 2; i * i <= n; i++) {
        if (n % i == 0) return false;
    }
    return true;
}

void GenerateRSAKeys(long long& n, long long& e, long long& d) {
    // 1. Generate Primes (Small range for demo performance, e.g., 100-1000)
    // In production, these should be much larger.
    vector<long long> primes;
    for (int i = 100; i < 500; i++) {
        if (IsPrime(i)) primes.push_back(i);
    }
    
    long long p = primes[rand() % primes.size()];
    long long q = primes[rand() % primes.size()];
    while (p == q) q = primes[rand() % primes.size()];

    n = p * q;
    long long phi = (p - 1) * (q - 1);

    // 2. Choose E
    e = 3;
    while (GCD(e, phi) != 1) {
        e += 2;
    }

    // 3. Compute D
    d = ModInverse(e, phi);
}

// --- Serialization ---
int serialize(const Message& msg, char* buffer, const std::string& key) {
    int offset = 0;
    
    buffer[offset++] = msg.msgType;
    
    uint32_t stuID = htonl(msg.studentID);
    memcpy(buffer + offset, &stuID, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(buffer + offset, msg.studentName, 32);
    offset += 32;

    uint32_t timestp = htonl(msg.timestamp);
    memcpy(buffer + offset, &timestp, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    uint32_t seq = htonl(msg.sequenceNumber);
    memcpy(buffer + offset, &seq, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    uint16_t dataLen = htons(msg.dataLength);
    memcpy(buffer + offset, &dataLen, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    
    int dataSize = msg.dataLength < 512 ? msg.dataLength : 512;
    memcpy(buffer + offset, msg.data, dataSize);
    
    // Encrypt ONLY payload with the specific session key
    // If key is empty (handshake), this does nothing
    SecureEncrypt(buffer + offset, dataSize, key);
    
    offset += dataSize;
    
    return offset; // Return EXACT size
}

int deserialize(const char* buffer, Message* msg, const std::string& key) {
    int offset = 0;
    
    msg->msgType = buffer[offset++];
    
    uint32_t stuID;
    memcpy(&stuID, buffer + offset, sizeof(uint32_t));
    msg->studentID = ntohl(stuID);
    offset += sizeof(uint32_t);

    memcpy(msg->studentName, buffer + offset, 32);
    offset += 32;
    
    uint32_t timestp;
    memcpy(&timestp, buffer + offset, sizeof(uint32_t));
    msg->timestamp = ntohl(timestp);
    offset += sizeof(uint32_t);

    uint32_t seq;
    memcpy(&seq, buffer + offset, sizeof(uint32_t));
    msg->sequenceNumber = ntohl(seq);
    offset += sizeof(uint32_t);

    uint16_t dataLen;
    memcpy(&dataLen, buffer + offset, sizeof(uint16_t));
    msg->dataLength = ntohs(dataLen);
    offset += sizeof(uint16_t);
    
    int dataSize = msg->dataLength < 512 ? msg->dataLength : 512;
    memcpy(msg->data, buffer + offset, dataSize);

    // Decrypt ONLY payload
    SecureDecrypt(msg->data, dataSize, key);
    
    offset += dataSize;
    
    if (dataSize < 512) {
        msg->data[dataSize] = '\0';
    }
    
    return offset;
}

Message CreateMsg(uint8_t msgType, uint32_t studentID, uint32_t timestamp, 
                  uint32_t sequenceNumber, const char* data, uint16_t dataLength) {
    Message msg;
    msg.msgType = msgType;
    msg.studentID = studentID;
    msg.timestamp = timestamp;
    msg.sequenceNumber = sequenceNumber;
    msg.dataLength = dataLength < 512 ? dataLength : 512;

    memset(msg.data, 0, 512);
    if (data != nullptr && dataLength > 0) {
        memcpy(msg.data, data, msg.dataLength);
    }
    return msg;
}