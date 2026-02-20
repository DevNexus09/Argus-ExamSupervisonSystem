#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <vector>
#include <string>
#include <utility>
#include "huffman.h" // INCLUDE ADDED

// Message Types
#define msgConnected 1
#define msgViolation 2
#define msgACK 3
#define msgHeartbeat 4  
#define msgTamper 5     
#define msgTimeRequest 6
#define msgTimeResponse 7

// NEW: Compressed Message Type
#define msgViolationCompressed 20 

// Handshake Message Types
#define msgHandshakeInit 10
#define msgHandshakeKey 11       
#define msgHandshakeResponse 12  

struct Message {
    uint8_t msgType;       
    uint32_t studentID;
    char studentName[32];
    uint32_t timestamp;
    uint32_t sequenceNumber;
    uint16_t dataLength;
    char data[512];
};

// Function Prototypes
int serialize(const Message& msg, char* buffer, const std::string& key);
int deserialize(const char* buffer, Message* msg, const std::string& key);
Message CreateMsg(uint8_t msgType, uint32_t studentID, uint32_t timestamp, 
                  uint32_t sequenceNumber, const char* data, uint16_t dataLength);

void SecureEncrypt(char* data, int length, const std::string& key);
void SecureDecrypt(char* data, int length, const std::string& key);

long long Power(long long base, long long exp, long long mod);
long long ModInverse(long long e, long long phi);
void GenerateRSAKeys(long long& n, long long& e, long long& d);

#endif