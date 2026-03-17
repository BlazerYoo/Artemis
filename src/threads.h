#ifndef ARTEMIS_THREADS_H
#define ARTEMIS_THREADS_H

#include "types.h"
#include "workqueue.h"

typedef struct {
    int           num_threads;   // P-core count
    pthread_t*    thread_ids;
    ThreadState*  thread_states;
    WorkQueue*    queue;
} ThreadPool;

// Detect P-core count, create pool, allocate per-thread arenas.
ThreadPool* threadpool_create(WorkQueue* queue);

// Start all worker threads.
void threadpool_start(ThreadPool* pool);

// Wait for all workers to finish (called after seeding queue).
void threadpool_join(ThreadPool* pool);

// Clean up thread pool (does NOT destroy arenas — they persist for Phase B).
void threadpool_destroy(ThreadPool* pool);

#endif // ARTEMIS_THREADS_H
