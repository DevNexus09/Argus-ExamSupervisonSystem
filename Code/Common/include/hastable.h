#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <string>
#include <iostream>

using namespace std;

#define TABLE_SIZE 101

struct Node {
    string domainName;
    Node* next;
};

struct HashTable {
    Node* table[TABLE_SIZE];
};

int hashFunction(string domain);
HashTable* createTable();
void insert(HashTable* ht, string domain);
bool search(HashTable* ht, string domain);
void loadFile(HashTable* ht, string filename);
void destroyTable(HashTable* ht);

#endif