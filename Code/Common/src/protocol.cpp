#include "../include/protocol.h"
#include <cstring>
#include <arpa/inet.h>
#include <vector>

using namespace std;

// --- Improved Security: Stream Cipher Implementation ---
// This acts like RC4. It generates a pseudo-random stream based on the key
// and combines it with the data. 

void RC4_Logic(char* data, int length, const string& key) {
    // 1. Key Scheduling Algorithm (KSA)
    vector<int> S(256);
    for(int i=0; i<256; i++) S[i] = i;
    
    int j = 0;
    for(int i=0; i<256; i++) {
        j = (j + S[i] + key[i % key.length()]) % 256;
        swap(S[i], S[j]);
    }

    // 2. Pseudo-Random Generation Algorithm (PRGA)
    int i = 0;
    j = 0;
    for (int k = 0; k < length; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(S[i], S[j]);
        
        int rnd = S[(S[i] + S[j]) % 256];
        data[k] ^= rnd; // XOR with the generated stream, not a static key
    }
}

void SecureEncrypt(char* data, int length, const string& key) {
    RC4_Logic(data, length, key);
}

void SecureDecrypt(char* data, int length, const string& key) {
    RC4_Logic(data, length, key); // Symmetric operation
}
// -------------------------------------------------------

uint32_t CalculateChecksum(const Message& msg) {
    uint32_t sum = 0;
    sum += msg.msgType;
    
    sum += (msg.studentID >> 24) & 0xFF;
    sum += (msg.studentID >> 16) & 0xFF;
    sum += (msg.studentID >> 8) & 0xFF;
    sum += msg.studentID & 0xFF;
    
    sum += (msg.timestamp >> 24) & 0xFF;
    sum += (msg.timestamp >> 16) & 0xFF;
    sum += (msg.timestamp >> 8) & 0xFF;
    sum += msg.timestamp & 0xFF;
    
    sum += (msg.dataLength >> 8) & 0xFF;
    sum += msg.dataLength & 0xFF;

    for(int i = 0; i < 32; i++) sum += (unsigned char)msg.studentName[i];
    
    for (int i = 0; i < msg.dataLength && i < 512; i++) {
        sum += (unsigned char)msg.data[i];
    }

    return sum % 256;
}

bool VerifyChecksum(const Message& msg) {
    uint32_t calculated = CalculateChecksum(msg);
    return calculated == msg.checksum;
}

int serialize(const Message& msg, char* buffer) {
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
    
    uint16_t dataLen = htons(msg.dataLength);
    memcpy(buffer + offset, &dataLen, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    
    int dataSize = msg.dataLength < 512 ? msg.dataLength : 512;
    memcpy(buffer + offset, msg.data, dataSize);
    
    // REPLACE EncryptXor WITH SecureEncrypt
    SecureEncrypt(buffer + offset, dataSize, SECRET_KEY);
    
    offset += dataSize;
    
    uint32_t chksum = htonl(msg.checksum);
    memcpy(buffer + offset, &chksum, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    return offset;
}

int deserialize(const char* buffer, Message* msg) {
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

    uint16_t dataLen;
    memcpy(&dataLen, buffer + offset, sizeof(uint16_t));
    msg->dataLength = ntohs(dataLen);
    offset += sizeof(uint16_t);
    
    int dataSize = msg->dataLength < 512 ? msg->dataLength : 512;
    memcpy(msg->data, buffer + offset, dataSize);
    
    // REPLACE DecryptXor WITH SecureDecrypt
    SecureDecrypt(msg->data, dataSize, SECRET_KEY);
    
    offset += dataSize;
    
    if (dataSize < 512) {
        msg->data[dataSize] = '\0';
    }

    uint32_t chksum;
    memcpy(&chksum, buffer + offset, sizeof(uint32_t));
    msg->checksum = ntohl(chksum);
    offset += sizeof(uint32_t);
    
    return offset;
}

Message CreateMsg(uint8_t msgType, uint32_t studentID, uint32_t timestamp, const char* data, uint16_t dataLength) {
    Message msg;
    msg.msgType = msgType;
    msg.studentID = studentID;
    msg.timestamp = timestamp;
    msg.dataLength = dataLength < 512 ? dataLength : 512;

    memset(msg.data, 0, 512);
    if (data != nullptr && dataLength > 0) {
        memcpy(msg.data, data, msg.dataLength);
    }
    msg.checksum = CalculateChecksum(msg);
    
    return msg;
}