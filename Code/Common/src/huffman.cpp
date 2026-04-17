#include "../include/huffman.h"
#include <queue>
#include <iostream>
#include <cstring>
#include <bitset>

using namespace std;

HuffmanCoding::HuffmanCoding() {
    root = nullptr;
    Init();
}

HuffmanCoding::~HuffmanCoding() {
    deleteTree(root);
}

void HuffmanCoding::deleteTree(HuffmanNode* node) {
    if (node == nullptr) return;
    deleteTree(node->left);
    deleteTree(node->right);
    delete node;
}

void HuffmanCoding::Init() {
    frequencies[' '] = 20; frequencies['e'] = 15; frequencies['t'] = 12;
    frequencies['a'] = 10; frequencies['o'] = 10; frequencies['i'] = 10;
    frequencies['n'] = 10; frequencies['s'] = 10; frequencies['r'] = 8;
    frequencies['h'] = 8;  frequencies['l'] = 7;  frequencies['c'] = 6;
    frequencies['d'] = 6;  frequencies['u'] = 5;  frequencies['m'] = 5;
    frequencies['.'] = 15; 
    frequencies['/'] = 10; 
    frequencies[':'] = 5;  
    frequencies['w'] = 5;
    
    for (int i = 0; i < 256; i++) {
        if (frequencies.find((char)i) == frequencies.end()) {
            frequencies[(char)i] = 1;
        }
    }

    buildTree();
}

void HuffmanCoding::buildTree() {
    priority_queue<HuffmanNode*, vector<HuffmanNode*>, Compare> pq;

    for (auto const& [key, val] : frequencies) {
        pq.push(new HuffmanNode(key, val));
    }

    while (pq.size() != 1) {
        HuffmanNode* left = pq.top(); pq.pop();
        HuffmanNode* right = pq.top(); pq.pop();

        int sum = left->freq + right->freq;
        HuffmanNode* top = new HuffmanNode('\0', sum);
        top->left = left;
        top->right = right;

        pq.push(top);
    }

    root = pq.top();
    generateCodes(root, "");
}

void HuffmanCoding::generateCodes(HuffmanNode* node, string str) {
    if (!node) return;

    if (!node->left && !node->right) {
        huffmanCodes[node->data] = str;
    }

    generateCodes(node->left, str + "0");
    generateCodes(node->right, str + "1");
}

void HuffmanCoding::Compress(const char* input, int inputLen, char* output, int& outputLen) {
    string bitStream = "";
    
    for (int i = 0; i < inputLen; i++) {
        bitStream += huffmanCodes[input[i]];
    }

    outputLen = 0;
    unsigned char currentByte = 0;
    int bitIndex = 0;

    for (char bit : bitStream) {
        if (bit == '1') {
            currentByte |= (1 << (7 - bitIndex));
        }
        
        bitIndex++;
        if (bitIndex == 8) {
            output[outputLen++] = currentByte;
            currentByte = 0;
            bitIndex = 0;
        }
    }


    if (bitIndex > 0) {
        output[outputLen++] = currentByte;
    }
}

void HuffmanCoding::Decompress(const char* input, int inputLen, char* output, int& outputLen) {
    outputLen = 0;
    HuffmanNode* curr = root;

    for (int i = 0; i < inputLen; i++) {
        unsigned char byte = input[i];
        
        for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
        
            bool isOne = (byte >> (7 - bitIndex)) & 1;

            if (isOne) curr = curr->right;
            else       curr = curr->left;

            if (!curr->left && !curr->right) {
                output[outputLen++] = curr->data;
                curr = root; 
                
                if (outputLen >= 511) return; 
            }
        }
    }
    output[outputLen] = '\0';
}