#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <string>

using namespace std;

#define TABLE_SIZE 101

struct Node {
    string domainName;
    Node* next;
};

struct HashTable {
    Node* table[TABLE_SIZE];
};

#endif
