#include "threads.h"
#include "scanner.h"
#include "arena.h"
#include "safety.h"

#include <sys/sysctl.h>
#include <pthread/qos.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Arena sizes (virtual — lazily committed, so this is cheap)
#define RECORD_ARENA_SIZE  ((size_t)10ULL * 1024 * 1024 * 1024) // 10 GB
#define STRING_ARENA_SIZE  ((size_t)10ULL * 1024 * 1024 * 1024) // 10 GB

// Max subdirectories discovered per scan_directory call
#define MAX_SUBDIRS_PER_DIR 4096

static int get_pcore_count(void) {
    int pcore_count = 0;
    size_t size = sizeof(pcore_count);
    if (sysctlbyname("hw.perflevel0.physicalcpu", &pcore_count, &size, NULL, 0) != 0) {
        // Fallback: use total physical CPUs if perflevel query fails (e.g., Intel Mac)
        sysctlbyname("hw.physicalcpu", &pcore_count, &size, NULL, 0);
    }
    if (pcore_count < 1) pcore_count = 1;
    return pcore_count;
}

typedef struct {
    ThreadPool* pool;
    int         thread_index;
} WorkerArg;

// Helper: decrement active_threads and signal if termination detected
static void finish_work_item(WorkQueue* queue) {
    int prev = atomic_fetch_sub(&queue->active_threads, 1);
    // If we just went to 0 active threads, wake sleepers to check termination
    if (prev == 1) {
        pthread_mutex_lock(&queue->mutex);
        pthread_cond_broadcast(&queue->cond);
        pthread_mutex_unlock(&queue->mutex);
    }
}

static void* worker_thread(void* arg) {
    WorkerArg* wa = (WorkerArg*)arg;
    ThreadPool* pool = wa->pool;
    ThreadState* ts = &pool->thread_states[wa->thread_index];

    // Set QoS to USER_INITIATED — strongly hints kernel toward P-core placement.
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);

    const char* path = NULL;
    const char* subdirs[MAX_SUBDIRS_PER_DIR];

    while (wq_pop(pool->queue, &path)) {
        atomic_store_explicit(&ts->live_path, path, memory_order_relaxed);
        // Skip paths we shouldn't scan (pure string checks, no syscalls)
        if (should_skip_path(path)) {
            finish_work_item(pool->queue);
            continue;
        }

        int found = scan_directory(ts, path, subdirs, MAX_SUBDIRS_PER_DIR);

        // Push first, THEN decrement active count.
        // This ordering prevents a race where another thread sees
        // active_threads==0 before we've pushed our discovered subdirs.
        if (found > 0) {
            wq_push_batch(pool->queue, subdirs, found);
        }

        finish_work_item(pool->queue);
    }

    free(wa);
    return NULL;
}

ThreadPool* threadpool_create(WorkQueue* queue) {
    ThreadPool* pool = malloc(sizeof(ThreadPool));
    pool->num_threads = get_pcore_count();
    pool->thread_ids  = calloc((size_t)pool->num_threads, sizeof(pthread_t));
    pool->queue       = queue;

    // Allocate thread states (128-byte aligned via the struct attribute)
    pool->thread_states = calloc((size_t)pool->num_threads, sizeof(ThreadState));

    for (int i = 0; i < pool->num_threads; i++) {
        ThreadState* ts = &pool->thread_states[i];
        ts->record_arena = arena_create(RECORD_ARENA_SIZE);
        ts->string_arena = arena_create(STRING_ARENA_SIZE);
        ts->record_arena_base  = (ScanRecord*)ts->record_arena->base;
        ts->string_arena_base  = ts->string_arena->base;
        ts->record_count       = 0;
        ts->error_count        = 0;
    }

    fprintf(stderr, "[artemis] P-core count: %d — spawning %d worker threads\n",
            pool->num_threads, pool->num_threads);

    return pool;
}

void threadpool_start(ThreadPool* pool) {
    for (int i = 0; i < pool->num_threads; i++) {
        WorkerArg* wa = malloc(sizeof(WorkerArg));
        wa->pool = pool;
        wa->thread_index = i;
        pthread_create(&pool->thread_ids[i], NULL, worker_thread, wa);
    }
}

void threadpool_join(ThreadPool* pool) {
    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->thread_ids[i], NULL);
    }
}

void threadpool_destroy(ThreadPool* pool) {
    // Note: arenas are NOT destroyed here — they persist for Phase B tree build.
    free(pool->thread_ids);
    // thread_states freed after Phase B
    free(pool);
}
