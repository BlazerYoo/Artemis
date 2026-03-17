#ifndef ARTEMIS_TYPES_H
#define ARTEMIS_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
typedef struct Arena Arena;

// ---------------------------------------------------------------------------
// ScanRecord — flat, per-thread, hot-path struct (Phase A)
//
// Each thread bump-allocates these into its arena during the crawl.
// No pointers between threads. 40 bytes, 8-byte aligned.
// ---------------------------------------------------------------------------
typedef struct {
    uint64_t    parent_inode;   // inode of the containing directory
    uint64_t    inode;          // this entry's inode (ATTR_CMN_FILEID)
    uint64_t    physical_size;  // ATTR_FILE_ALLOCSIZE (0 for dirs/symlinks/deduped)
    const char* name;           // pointer into thread's string arena
    uint32_t    type;           // VDIR, VREG, VLNK
    uint32_t    nlink;          // hardlink count (ATTR_CMN_NLINK)
} ScanRecord;

_Static_assert(sizeof(ScanRecord) == 40, "ScanRecord must be 40 bytes");

// ---------------------------------------------------------------------------
// TreeNode — LCRS tree node for Phase B reconstruction
// 56 bytes, 8-byte aligned.
// ---------------------------------------------------------------------------
typedef struct TreeNode {
    uint64_t          rolled_up_size;  // sum of own + all descendants
    uint64_t          own_size;        // physical size of direct children files
    uint64_t          inode;
    struct TreeNode*  first_child;
    struct TreeNode*  next_sibling;
    const char*       name;
    uint8_t           type;
    uint8_t           linked;          // 1 if already linked to a parent
    uint8_t           _pad[6];         // pad to 56 bytes
} TreeNode;

_Static_assert(sizeof(TreeNode) == 56, "TreeNode must be 56 bytes");

// ---------------------------------------------------------------------------
// ThreadState — per-thread state, 128-byte aligned to prevent false sharing
// on M-series L2 cache lines.
// ---------------------------------------------------------------------------
typedef struct {
    ScanRecord* record_arena_base;
    size_t      record_arena_offset;
    char*       string_arena_base;
    size_t      string_arena_offset;
    uint64_t    record_count;
    uint64_t    error_count;
    Arena*      record_arena;
    Arena*      string_arena;
    _Atomic uint64_t      live_scanned_bytes; // For UI progress bar
    _Atomic(const char*)  live_path;          // Pointer into string arena for UI progress
} __attribute__((aligned(128))) ThreadState;

#endif // ARTEMIS_TYPES_H
