#ifndef ARTEMIS_ARENA_H
#define ARTEMIS_ARENA_H

#include <stddef.h>

typedef struct Arena {
    char*  base;           // start of mmap'd region
    size_t capacity;       // total virtual size
    size_t offset;         // current bump pointer offset
} Arena;

// Create an arena backed by a large mmap'd virtual region.
// Pages are lazily committed by the kernel on first write.
Arena* arena_create(size_t virtual_size);

// Bump-allocate `size` bytes with `align`-byte alignment.
// Returns NULL if arena is exhausted (should never happen with 10GB virtual).
void*  arena_alloc(Arena* a, size_t size, size_t align);

// Copy a string of length `len` into the arena, null-terminate it.
// Returns pointer to the arena-local copy.
const char* arena_alloc_string(Arena* a, const char* src, size_t len);

// Release the entire mmap'd region.
void   arena_destroy(Arena* a);

#endif // ARTEMIS_ARENA_H
