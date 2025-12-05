#ifndef TRIE_H
#define TRIE_H

#include <string>
using namespace std;
#define alphabetSize 37

struct TrieNode {
    TrieNode* children[alphabetSize];
    bool isEnd;       
    
    TrieNode() {
        for (int i=0;i<alphabetSize;i++) {
            children[i]=nullptr;
        }
        isEnd=false;
    }
};

struct Trie {
    TrieNode* root;
    
    Trie() {
        root=new TrieNode();
    }
};

int CharToIndex(char c);
void Insert(Trie* trie, const string& domain);
bool Search(Trie* trie, const string& domain);
bool WildcardMatch(Trie* trie, const string& domain);
bool Load(Trie* trie, const string& filename);
void Destroy(Trie* trie);

#endif