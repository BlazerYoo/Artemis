#include "workqueue.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void wq_init(WorkQueue* wq, int initial_capacity) {
    wq->paths    = malloc(sizeof(char*) * (size_t)initial_capacity);
    wq->count    = 0;
    wq->capacity = initial_capacity;
    wq->shutdown = false;
    atomic_store(&wq->active_threads, 0);
    pthread_mutex_init(&wq->mutex, NULL);
    pthread_cond_init(&wq->cond, NULL);
}

static void wq_grow(WorkQueue* wq) {
    int new_cap = wq->capacity * 2;
    wq->paths = realloc(wq->paths, sizeof(char*) * (size_t)new_cap);
    wq->capacity = new_cap;
}

void wq_push(WorkQueue* wq, const char* path) {
    pthread_mutex_lock(&wq->mutex);
    if (wq->count >= wq->capacity) wq_grow(wq);
    wq->paths[wq->count++] = (char*)path;
    pthread_cond_signal(&wq->cond);
    pthread_mutex_unlock(&wq->mutex);
}

void wq_push_batch(WorkQueue* wq, const char** paths, int count) {
    if (count <= 0) return;
    pthread_mutex_lock(&wq->mutex);
    while (wq->count + count > wq->capacity) wq_grow(wq);
    memcpy(&wq->paths[wq->count], paths, sizeof(char*) * (size_t)count);
    wq->count += count;
    // Wake all waiters — there may be multiple items available
    pthread_cond_broadcast(&wq->cond);
    pthread_mutex_unlock(&wq->mutex);
}

bool wq_pop(WorkQueue* wq, const char** out_path) {
    pthread_mutex_lock(&wq->mutex);

    for (;;) {
        // If there's work, take it
        if (wq->count > 0) {
            *out_path = wq->paths[--wq->count];
            atomic_fetch_add(&wq->active_threads, 1);
            pthread_mutex_unlock(&wq->mutex);
            return true;
        }

        // No work in queue — check if all threads are also idle
        if (atomic_load(&wq->active_threads) == 0 || wq->shutdown) {
            // Termination: queue is empty AND no threads are actively scanning.
            // Broadcast to wake any other sleeping threads so they can also exit.
            pthread_cond_broadcast(&wq->cond);
            pthread_mutex_unlock(&wq->mutex);
            return false;
        }

        // Queue is empty but some thread is still scanning — wait for new work
        pthread_cond_wait(&wq->cond, &wq->mutex);
    }
}

int wq_size(WorkQueue* wq) {
    pthread_mutex_lock(&wq->mutex);
    int size = wq->count;
    pthread_mutex_unlock(&wq->mutex);
    return size;
}

void wq_destroy(WorkQueue* wq) {
    pthread_mutex_destroy(&wq->mutex);
    pthread_cond_destroy(&wq->cond);
    free(wq->paths);
    wq->paths = NULL;
}
