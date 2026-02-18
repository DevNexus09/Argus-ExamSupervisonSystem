#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <string>
#include <iostream>

using namespace std;

// Define the table size used in hashtable.cpp
#define TABLE_SIZE 101

// Define the Node structure expected by hashtable.cpp
struct Node {
    string domainName;
    Node* next;
};

// Define the HashTable structure expected by hashtable.cpp
struct HashTable {
    Node* table[TABLE_SIZE];
};

// Function prototypes for the functions implemented in hashtable.cpp
int hashFunction(string domain);
HashTable* createTable();
void insert(HashTable* ht, string domain);
bool search(HashTable* ht, string domain);
void loadFile(HashTable* ht, string filename);
void destroyTable(HashTable* ht);

#endif