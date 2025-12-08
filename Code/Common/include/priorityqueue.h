#ifndef PRIORITY_QUEUE_H
#define PRIORITY_QUEUE_H

#include <string>
#include <vector>

using namespace std;

#define maxHeapSize 1000

struct Student {
    string studentID;
    int violationCount;
    
    Student() : studentID(""), violationCount(0) {}
    Student(const string& id, int count) : studentID(id), violationCount(count) {}
};


struct PriorityQueue {
    Student heap[maxHeapSize];
    int size;                      
    
    PriorityQueue() : size(0) {}
};


void Insert(PriorityQueue* pq, const string& student_id, int count);
vector<Student> GetTop(PriorityQueue* pq, int n);
void heapify(PriorityQueue* pq);
void heapify_up(PriorityQueue* pq, int index);
void heapify_down(PriorityQueue* pq, int index);
Student max(PriorityQueue* pq);
void print_queue(PriorityQueue* pq);
void clear_queue(PriorityQueue* pq);

#endif