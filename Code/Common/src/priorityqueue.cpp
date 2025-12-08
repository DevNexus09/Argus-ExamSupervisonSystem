#include "../include/priorityqueue.h"
#include <iostream>
#include <vector>
#include <algorithm>

using namespace std;

int parent(int i) {
    return (i - 1) / 2;
}

int left_child(int i) {
    return 2 * i + 1;
}

int right_child(int i) {
    return 2 * i + 2;
}

void swap_students(Student& a, Student& b) {
    Student temp = a;
    a = b;
    b = temp;
}

void heapify_up(PriorityQueue* pq, int index) {
    while (index > 0 && pq->heap[parent(index)].violationCount < pq->heap[index].violationCount) {
        swap_students(pq->heap[parent(index)], pq->heap[index]);
        index = parent(index);
    }
}

void heapify_down(PriorityQueue* pq, int index) {
    int largest = index;
    int left = left_child(index);
    int right = right_child(index);
    
    if (left < pq->size && pq->heap[left].violationCount > pq->heap[largest].violationCount) {
        largest = left;
    }
    
    if (right < pq->size && pq->heap[right].violationCount > pq->heap[largest].violationCount) {
        largest = right;
    }
    
    if (largest != index) {
        swap_students(pq->heap[index], pq->heap[largest]);
        heapify_down(pq, largest);
    }
}

void heapify(PriorityQueue* pq) {
    for (int i = pq->size / 2 - 1; i >= 0; i--) {
        heapify_down(pq, i);
    }
}

void insert(PriorityQueue* pq, const string& student_id, int count) {
    for (int i = 0; i < pq->size; i++) {
        if (pq->heap[i].studentID == student_id) {
            pq->heap[i].violationCount = count;
            heapify(pq);
            return;
        }
    }
    
    if (pq->size >= maxHeapSize) {
        cout << "Error: Priority queue is full" << endl;
        return;
    }
    
    pq->heap[pq->size] = Student(student_id, count);
    pq->size++;
    
    heapify_up(pq, pq->size - 1);
}

Student max(PriorityQueue* pq) {
    if (pq->size == 0) {
        cerr << "Error: Priority queue is empty" << endl;
        return Student();
    }
    
    Student max_student = pq->heap[0];
    
    pq->heap[0] = pq->heap[pq->size - 1];
    pq->size--;
    
    if (pq->size > 0) {
        heapify_down(pq, 0);
    }
    
    return max_student;
}

vector<Student> GetTop(PriorityQueue* pq, int n) {
    vector<Student> topViolators;
    
    PriorityQueue tempPq;
    tempPq.size = pq->size;
    for (int i = 0; i < pq->size; i++) {
        tempPq.heap[i] = pq->heap[i];
    }
    
    int count = min(n, tempPq.size);
    for (int i = 0; i < count; i++) {
        Student top = max(&tempPq);
        topViolators.push_back(top);
    }
    
    return topViolators;
}

void print_queue(PriorityQueue* pq) {
    cout << "Priority Queue (Size: " << pq->size << "):" << endl;
    vector<Student> all = GetTop(pq, pq->size);
    for (int i = 0; i < all.size(); i++) {
        cout << i + 1 << ". " << all[i].studentID 
             << " - " << all[i].violationCount << " violations" << endl;
    }
}

void clear_queue(PriorityQueue* pq) {
    pq->size = 0;
}