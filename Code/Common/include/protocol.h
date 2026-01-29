#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <vector>
#include <string>

#define msgConnected 1
#define msgViolation 2
#define msgACK 3
#define msgHeartbeat 4  
#define msgTamper 5     


static const std::string SECRET_KEY = "cIpHer.aRsx2025";

struct Message {
    uint8_t msgType;       
    uint32_t studentID;
    char studentName[32];
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

// Updated Security Functions
void SecureEncrypt(char* data, int length, const std::string& key);
void SecureDecrypt(char* data, int length, const std::string& key);

#endif