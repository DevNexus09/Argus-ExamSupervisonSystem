#ifndef HUFFMAN_H
#define HUFFMAN_H

#include <string>
#include <vector>
#include <map>

// Struct for Huffman Tree Nodes
struct HuffmanNode {
    char data;
    int freq;
    HuffmanNode *left, *right;

    HuffmanNode(char data, int freq) : data(data), freq(freq), left(nullptr), right(nullptr) {}
};

// Comparison object for the Priority Queue
struct Compare {
    bool operator()(HuffmanNode* l, HuffmanNode* r) {
        return l->freq > r->freq; // Min Heap
    }
};

// Main Huffman Class
class HuffmanCoding {
private:
    HuffmanNode* root;
    std::map<char, std::string> huffmanCodes;
    std::map<char, int> frequencies;

    void generateCodes(HuffmanNode* root, std::string str);
    void deleteTree(HuffmanNode* node);
    void buildTree();

public:
    HuffmanCoding();
    ~HuffmanCoding();

    // Compresses raw bytes into packed bits
    void Compress(const char* input, int inputLen, char* output, int& outputLen);
    
    // Decompresses packed bits back to raw bytes
    void Decompress(const char* input, int inputLen, char* output, int& outputLen);
    
    // Initialize the static frequency table (Universal Tree)
    void Init();
};

#endif