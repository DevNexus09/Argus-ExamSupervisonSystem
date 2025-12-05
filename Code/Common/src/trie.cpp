#include "../include/trie.h"
#include <iostream>
#include <fstream>
#include <cctype>

using namespace std;

int CharToIndex(char c) {
    if (c >= 'a' && c <= 'z') return c - 'a';
    else if (c >= 'A' && c <= 'Z') return c - 'A';
    else if (c >= '0' && c <= '9') return 26 + (c - '0');
    else if (c == '*') return 36;
    
    return -1;
}

void Insert(Trie* trie, const string& domain) {
    TrieNode* current = trie->root;
    
    for (char c : domain) {
        int index = CharToIndex(c);
        if (index == -1) continue;
        
        if (current->children[index] == nullptr) {
            current->children[index] = new TrieNode();
        } 
        current = current->children[index];
    }
    
    current->isEnd = true;
}

bool Search(Trie* trie, const string& domain) {
    TrieNode* current = trie->root;
    
    for (char c : domain) {
        int index = CharToIndex(c);
        if (index == -1) continue;
        
        if (current->children[index] == nullptr) {
            return false;
        }
        
        current = current->children[index];
    }
    
    return current->isEnd;
}

bool WildcardMatcher(TrieNode* node, const string& domain, int pos) {
    if (node == nullptr) return false;
    if (pos == domain.length()) return node->isEnd;
    
    char c = domain[pos];
    int index = CharToIndex(c);
    
    if (c == '*') {
        if (WildcardMatcher(node, domain, pos + 1)) {
            return true;
        }
        
        for (int i = 0; i < alphabetSize; i++) {
            if (node->children[i] != nullptr) {
                if (WildcardMatcher(node->children[i], domain, pos)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    if (index == -1) {
        return WildcardMatcher(node, domain, pos + 1);
    }
    
    return WildcardMatcher(node->children[index], domain, pos + 1);
}

bool WildcardMatch(Trie* trie, const string& domain) {
    return WildcardMatcher(trie->root, domain, 0);
}

bool Load(Trie* trie, const string& filename) {
    ifstream file(filename);
    
    if (!file.is_open()) {
        cout << "Error: Could not open file " << filename << endl;
        return false;
    }
    
    string domain;
    int count = 0;
    
    while (getline(file, domain)) {
        if (!domain.empty()) {
            Insert(trie, domain);
            count++;
        }
    }
    
    file.close();
    return true;
}

void destroy(TrieNode* node) {
    if (node == nullptr) return;
    
    for (int i = 0; i < alphabetSize; i++) {
        destroy(node->children[i]);
    }
    
    delete node;
}

void Destroy(Trie* trie) {
    destroy(trie->root);
    trie->root = nullptr;
}