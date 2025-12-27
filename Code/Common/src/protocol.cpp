#include "../include/protocol.h"
#include <cstring>
#include <arpa/inet.h>

using namespace std;

#define ENCRYPTION_KEY 0x5A

void EncryptXor(char* data, int length, char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

void DecryptXor(char* data, int length, char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

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
    
    for (int i = 0; i < msg.dataLength && i < 512; i++) {
        sum += (unsigned char)msg.data[i];
    }

    return sum % 256;
}

bool verify_checksum(const Message& msg) {
    uint32_t calculated = CalculateChecksum(msg);
    return calculated == msg.checksum;
}

int serialize(const Message& msg, char* buffer) {
    int offset = 0;
    
    buffer[offset++] = msg.msgType;
    
    uint32_t stuID = htonl(msg.studentID);
    memcpy(buffer + offset, &stuID, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    uint32_t timestp = htonl(msg.timestamp);
    memcpy(buffer + offset, &timestp, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    uint16_t dataLen = htons(msg.dataLength);
    memcpy(buffer + offset, &dataLen, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    
    int dataSize = msg.dataLength < 512 ? msg.dataLength : 512;
    memcpy(buffer + offset, msg.data, dataSize);
    
    EncryptXor(buffer + offset, dataSize, ENCRYPTION_KEY);
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
    
    DecryptXor(msg->data, dataSize, ENCRYPTION_KEY);
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