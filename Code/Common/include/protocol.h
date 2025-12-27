#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>

#define msgConnected 1
#define msgViolation 2
#define msgACK 3

struct Message {
    uint8_t msgType;       
    uint32_t studentID;
    uint32_t timestamp;
    uint16_t dataLength;
    char data[512];
    uint32_t checksum;
};


uint32_t CalculateChecksum(const Message& msg);
bool VerifyChecksum(const Message& msg);
int serialize(const Message& msg, char* buffer);
int deserialize(const char* buffer, Message* msg);
Message CreateMsg(uint8_t msgType, uint32_t studentID, uint32_t timestamp, 
                      const char* data, uint16_t dataLength);
void EncryptXor(char* data, int length, char key);
void DecryptXor(char* data, int length, char key);

#endif