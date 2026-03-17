#ifndef ARTEMIS_WORKQUEUE_H
#define ARTEMIS_WORKQUEUE_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

typedef struct {
    char**          paths;         // dynamic array of path strings
    int             count;
    int             capacity;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    atomic_int      active_threads;
    bool            shutdown;
} WorkQueue;

// Initialize work queue with initial capacity.
void wq_init(WorkQueue* wq, int initial_capacity);

// Push a single path. Thread-safe.
void wq_push(WorkQueue* wq, const char* path);

// Push a batch of paths. More efficient (single lock acquisition).
void wq_push_batch(WorkQueue* wq, const char** paths, int count);

// Pop a path to scan. Blocks if queue is empty and work is still in progress.
// Returns false when termination is detected (queue empty AND active_threads==0).
bool wq_pop(WorkQueue* wq, const char** out_path);

// Get current queue size (for starvation detection). Thread-safe.
int  wq_size(WorkQueue* wq);

// Destroy work queue resources.
void wq_destroy(WorkQueue* wq);

#endif // ARTEMIS_WORKQUEUE_H
