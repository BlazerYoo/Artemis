#include "arena.h"
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

Arena* arena_create(size_t virtual_size) {
    Arena* a = malloc(sizeof(Arena));
    if (!a) {
        perror("arena_create: malloc");
        return NULL;
    }

    // MAP_PRIVATE | MAP_ANON: macOS overcommits by default.
    // Physical pages are only allocated on first write (page fault).
    // No MAP_NORESERVE needed — that's Linux-only.
    void* base = mmap(NULL, virtual_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) {
        perror("arena_create: mmap");
        free(a);
        return NULL;
    }

    a->base     = (char*)base;
    a->capacity = virtual_size;
    a->offset   = 0;
    return a;
}

void* arena_alloc(Arena* a, size_t size, size_t align) {
    // Align the current offset upward
    size_t aligned = (a->offset + align - 1) & ~(align - 1);
    if (aligned + size > a->capacity) {
        return NULL; // Arena exhausted — shouldn't happen with 10GB virtual
    }
    void* ptr = a->base + aligned;
    a->offset = aligned + size;
    return ptr;
}

const char* arena_alloc_string(Arena* a, const char* src, size_t len) {
    // Allocate len+1 for null terminator, 1-byte aligned
    char* dst = (char*)arena_alloc(a, len + 1, 1);
    if (!dst) return NULL;
    memcpy(dst, src, len);
    dst[len] = '\0';
    return dst;
}

void arena_destroy(Arena* a) {
    if (a) {
        munmap(a->base, a->capacity);
        free(a);
    }
}
