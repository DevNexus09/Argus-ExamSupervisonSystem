#ifndef HUFFMAN_H
#define HUFFMAN_H

#include <string>
#include <vector>
#include <map>

struct HuffmanNode {
    char data;
    int freq;
    HuffmanNode *left, *right;

    HuffmanNode(char data, int freq) : data(data), freq(freq), left(nullptr), right(nullptr) {}
};

struct Compare {
    bool operator()(HuffmanNode* l, HuffmanNode* r) {
        return l->freq > r->freq; // Min Heap
    }
};

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

    void Compress(const char* input, int inputLen, char* output, int& outputLen);
    void Decompress(const char* input, int inputLen, char* output, int& outputLen);
    void Init();
};

#endif