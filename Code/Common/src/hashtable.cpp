#include "../include/hastable.h"
#include <iostream>
#include <fstream>

using namespace std;

int hashFunction(string domain) {
    int hash=0;
    for(int i=0;i<domain.length();i++){
        hash=(hash * 31 + domain[i])%TABLE_SIZE;
    }
    return hash;
}

void insert(HashTable* ht, string domain) {
    int index=hashFunction(domain);
    
    Node* current=ht->table[index];
    while(current != NULL) {
        if(current->domainName==domain) {
            return;
        }
        current=current->next;
    }
    Node* newNode=new Node;
    newNode->domainName=domain;
    newNode->next=ht->table[index];
    ht->table[index]=newNode;
}

bool search(HashTable* ht, string domain) {
    int index=hashFunction(domain);
    
    Node* current=ht->table[index];
    while(current!=NULL) {
        if(current->domainName==domain) {
            return true;
        }
        current=current->next;
    }
    
    return false;
}

void loadFile(HashTable* ht, string filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        cout<<"Error opening file: " <<filename<<endl;
        return;
    }
    
    string domain;
    while (getline(file, domain)) {
        if (!domain.empty()) {
            insert(ht, domain);
        }
    }
    
    file.close();
    cout<<"Domains loaded from "<<filename<< endl;
}

HashTable* createTable() {
    HashTable* ht = new HashTable;
    for (int i=0;i<TABLE_SIZE;i++) {
        ht->table[i]=NULL;
    }
    return ht;
}

void destroyTable(HashTable* ht) {
    for (int i=0;i<TABLE_SIZE;i++) {
        Node* current=ht->table[i];
        while(current!=NULL) {
            Node* temp=current;
            current=current->next;
            delete temp;
        }
    }
    delete ht;
}
