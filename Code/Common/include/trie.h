#ifndef TRIE_H
#define TRIE_H

#include <string>
#include <queue> // NEW: For Aho-Corasick BFS queue
using namespace std;
#define alphabetSize 37

struct TrieNode {
    TrieNode* children[alphabetSize];
    bool isEnd;       
    TrieNode* fail; // NEW: Failure link for Aho-Corasick
    
    TrieNode() {
        for (int i=0;i<alphabetSize;i++) {
            children[i]=nullptr;
        }
        isEnd=false;
        fail=nullptr; // NEW
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

// --- NEW: Aho-Corasick Algorithm Functions ---
void BuildFailureLinks(Trie* trie);
bool AhoCorasickSearch(Trie* trie, const char* text, int len);

#endif