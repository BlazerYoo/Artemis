# Artemis — macOS Disk Space Analyzer (Apple Silicon Optimized)

A high-performance disk crawler written in C, heavily optimized for M-series Apple Silicon. Designed to scan an entire macOS APFS filesystem in seconds using strict hardware-sympathetic concurrency and minimal system calls.

## Goal

Crawl every accessible directory on the local machine as fast as possible, categorize disk usage, and produce a clear report of what can be cleaned up. Built for personal use—optimizing strictly for execution speed over cross-platform compatibility.

## Target Performance

- Full disk scan (millions of files): 3-8 seconds on an M1 Pro with APFS SSD.
- The bottleneck must be APFS metadata read latency from the SSD, not CPU overhead, lock contention, or string manipulation.
- Subsequent runs benefit from the OS's Unified Buffer Cache (VFS-level APFS metadata caching), which can make warm scans significantly faster. This is not an Artemis feature — it's an OS behavior that Artemis is designed to exploit.

## Architecture & Core Design

### Language & Dependencies

- Language: C11 (specifically for `<stdatomic.h>`)
- Core Dependencies: `pthread`, `<sys/attr.h>`, `<stdatomic.h>`.
- External Headers (for speed/complexity reduction without compromise):
  - `khash.h` (from klib): Ultra-fast open-addressing hash map. Allows pre-allocating an exact number of slots before scans start, guaranteeing zero hidden memory allocations during hardlink dedup and tree building.
  - `xxHash`: For Phase 3 duplicate detection or inode hashing if needed. Runs at the absolute limits of M-series RAM bandwidth.
- Overhead: Zero ARC, GC, or string bridging. No `malloc`/`free` calls in the hot loop (see Arena Allocation below).

### What NOT to Use (Banned Libraries)

- **Generic Thread Pool Libraries**: While they simplify thread management, they inherently surrender control over QoS and will likely dump raw work onto the slow E-cores. Keep raw `pthread` + Mutex queue so you retain `QOS_CLASS_USER_INITIATED` placement control.
- **Custom Memory Allocators (jemalloc, mimalloc)**: Unnecessary and slower for this specific workload. Phase A uses a "bump allocator" (moving a pointer forward in a massive mmap void). No library on earth can allocate memory faster than that one line of basic math. Keep the custom arena.

### Concurrency Model (P-Core Targeting via QoS)

Artemis explicitly targets Apple Silicon's Performance (P) cores to minimize work-stealing imbalances caused by Efficiency (E) cores.

- P-Core Targeting: Query `hw.perflevel0.physicalcpu` to determine P-core count and spawn that many worker threads. Note: macOS does not expose core affinity APIs (`sched_setaffinity`-style pinning is unavailable). Thread placement is best-effort via QoS, not guaranteed — the kernel may schedule threads on E-cores under thermal pressure or low battery.
- QoS Enforcement: Threads are assigned `QOS_CLASS_USER_INITIATED` via `pthread_set_qos_class_self_np` to strongly hint the scheduler toward P-core placement and prevent I/O throttling. (`QOS_CLASS_USER_INTERACTIVE` is intentionally avoided — it is the highest QoS class reserved for UI frame rendering and would compete with the window server, potentially triggering aggressive thermal throttling for a bulk disk scanner.)
- Work Queue with Batched Pushes: A shared directory queue protected by `pthread_mutex` + `pthread_cond`. Threads pop directories to scan and push discovered subdirectories. To amortize lock acquisition, threads maintain a small local stack and push discovered subdirectories in batches. (A lock-free MPMC queue was considered and rejected — correct implementations are extremely complex (ABA problem, memory reclamation), and since the bottleneck is SSD I/O latency, a mutex adds negligible overhead with far simpler correctness guarantees.)
- Termination Detection (via `<stdatomic.h>`): Threads use `atomic_fetch_add` and `atomic_fetch_sub` to track an `active_threads` counter. A thread atomically increments when it pops work, and decrements when it finishes scanning tightly. The crawl is complete when the queue is empty **AND** `active_threads == 0`. **Crucially, when a thread decrements `active_threads` to 0 and sees the queue is empty, it must call `pthread_cond_broadcast()` to wake up any sleeping threads so they can check the conditions and exit.** On Apple Silicon, these C11 atomics compile down to a single instruction, preventing lock-contention slowdowns while perfectly signaling true termination.
- Tail-End Starvation Prevention: If a thread detects the global work queue is empty (or below a threshold), it immediately flushes its local directory stack back to the global queue, triggering a work-steal. No hoarding allowed when peers are starving — this prevents one thread diving into a massive `node_modules` tree while 7 P-cores wait on the condition variable.

### The Hot Loop: `getattrlistbulk`

Artemis completely bypasses the standard POSIX `opendir` + `readdir` + `stat` pattern.

- Uses `getattrlistbulk()` to fetch metadata for hundreds of entries in a single kernel transition.
- Requested Attributes: `ATTR_CMN_NAME | ATTR_CMN_OBJTYPE | ATTR_CMN_FILEID | ATTR_CMN_NLINK | ATTR_FILE_ALLOCSIZE`. The `FILEID` and `NLINK` fields enable hardlink deduplication (see below).
- Buffer Size: Parameterized, defaulting to 64KB (the sweet spot for M-series unified memory kernel wiring).
- **Attribute Incompleteness & Truncation**: Apple's bulk APIs trade completeness for speed. Requested attributes may be missing, zeroed, or silently truncated if the buffer is too small. We must design assuming unstable attribute availability, detect partial reads, and avoid assuming perfect fidelity.
- File Descriptor Discipline: Each directory is scanned with a strict `open()` → `fstat()` (to get the parent directory's inode) → N × `getattrlistbulk()` → `close()` cycle. The fd is never held longer than the scan of a single directory, keeping per-thread fd usage at exactly 1. This stays well within the default macOS `ulimit -n` of 256 even with all threads active. The initial `fstat()` after `open()` is necessary because `getattrlistbulk` gives the inodes of the children, but not the parent, which is required by Phase B for tree linking.
- Buffer Navigation & `ATTR_FILE_ALLOCSIZE`: The `length` property at the beginning of each entry struct dictates the total byte size of that entry, including variable-length strings and padding. To reach the next entry, simply advance: `cursor += current_entry->length`. However, `ATTR_FILE_ALLOCSIZE` only applies to files. You must check `returned_attrs` or `obj_type` before reading `alloc_size`, as it won't be present in the returned data for directories or symlinks.
- Name String Lifetime: `getattrlistbulk` returns names into the caller-provided buffer, which is **reused on each call**. Entry names must be immediately copied into the thread's string arena during parsing. Storing a pointer directly into the kernel buffer will produce garbage after the next `getattrlistbulk` call.
- Symlink Policy: If `obj_type == VLNK`, log its physical allocation size (typically 0 or 4KB) but **never** push its target to the work queue. `getattrlistbulk` does not follow symlinks by default — it returns metadata of the link itself. Following symlinks would cause double-counting and potential infinite loops.

### Hardlink Deduplication

macOS system directories (`/usr/bin`, etc.) contain many hardlinks. Without deduplication, files with `nlink > 1` will be counted once per link, silently inflating the reported total.

- **Phase A (Hot Loop):** Do not deduplicate during the scan. Just blindly log every file's `nlink` and inode into the flat `ScanRecord` array. Hashing is removed entirely from the hot loop, preventing the scenario where two threads log the same file's full size into separate arenas before an eventual merge.
- **Phase B (Tree Build):** Use a single global `khash` set. As you iterate linearly through the flat records, if a record has `nlink > 1`, check the global `khash`. If it exists, ignore the size. If it doesn't, add the size and insert the inode. This guarantees correct math across all thread arenas and makes Phase A strictly faster.

### APFS Clone Deduplication

> **✅ FINAL VERDICT (Empirically Validated):**
> 
> Testing confirmed that `getattrlistbulk` *does* accurately return `ATTR_CMNEXT_CLONEID` for APFS cloned files without silently zeroing them out. However, adding APFS Clone Deduplication to Artemis was deemed unnecessary for the primary goal. Cloned files share physical blocks, but unlike hardlinks, tracking clone IDs across millions of files requires massive memory overhead (large hash sets) for minimal actionable user benefit. Fast total disk utilization is better calculated via `statfs()` (see "Hidden Space" below).

### Memory & Aggregation Strategy (Two-Phase Design)

The scan is split into two distinct phases to avoid cross-thread data races and cache-line bouncing entirely.

> **Why not per-thread LCRS trees?** A shared work queue means any thread can scan any directory. If Thread A discovers `/foo/bar` and Thread B later scans it, `bar`'s node lives in A's arena but its children live in B's arena. Thread A's post-order traversal of its own arena would never see B's children — sizes won't roll up. And writing B's child pointer back into A's node is both a data race and cache-line bouncing. Flat scan records eliminate this fundamental conflict.

#### Phase A: Flat Scan (Hot Loop)

During the crawl, threads do **not** build trees. Each thread appends flat `ScanRecord` entries into its own arena — a simple bump-allocated array. This eliminates all cross-thread pointer chasing, data races, and cache-line bouncing.

- No Pointers Between Arenas: Scan records contain only inodes and arena-local name pointers. No thread ever writes into another thread's memory.
- No Atomic Counters for Sizes: Threads do not update global directory sizes during the crawl.
- No Path Concatenation for Files: Scan records store only the entry's local name (pointer into string arena) and the parent directory's inode. Full paths are never constructed for file entries.
- Directory Paths for Work Queue: When a subdirectory is discovered, its full path is assembled and stored in the discovering thread's string arena, then pushed to the shared work queue. This is necessary because the receiving thread needs a path to `open()` the directory (the parent fd is already closed). Directory entries are a small fraction of total entries, so the cost is negligible. *(Future optimization to explore: `openat()`-based traversal to reduce path resolution overhead).*

#### Phase B: Post-Scan Tree Construction (Single-Threaded)

After all threads join, a single-threaded pass reconstructs the directory tree from the flat scan records:

1. Iterate all per-thread scan record arrays (just pointer arithmetic — no copies needed since arenas persist until program exit).
2. Build a hash map of `inode → TreeNode`.
3. Link children to parents using `parent_inode` from each `ScanRecord`.
4. Post-order traversal to roll up directory sizes.

This post-scan pass operates entirely in L2/L3 cache on a single core with zero contention. Processing millions of flat records into a tree is a fast in-memory operation — negligible compared to the I/O-bound scan phase.

#### Arena Allocation (Virtual Memory Strategy)

To guarantee truly zero `malloc` calls in the hot loop, thread arenas exploit macOS's 64-bit virtual address space:

- At startup, each thread `mmap`s a massive virtual region (e.g., 10 GB per thread) with `MAP_PRIVATE | MAP_ANON` for both the scan record arena and the string arena.
- On macOS, `MAP_PRIVATE | MAP_ANON` overcommits by default — the XNU kernel lazily allocates physical pages only upon first write (page fault). The arena appears infinite from the thread's perspective, with zero risk of mid-loop allocation stalls. (Note: `MAP_NORESERVE` is Linux-specific and does not exist on Darwin.)
- This eliminates the traditional arena exhaustion problem (e.g., deep `node_modules` trees blowing past a naively-sized arena).

### Error Handling Policy

The hot loop must expect transient filesystem errors and never crash on a single bad file:

- `ENOENT` (file deleted between discovery and scan): Skip and increment thread-local error counter.
- `EACCES` (permissions changed mid-crawl): Skip and increment thread-local error counter.
- All other `getattrlistbulk` errors: Skip the entry, log to thread-local counter, continue.
- After the crawl, report total skipped entries to the user.

## C Data Structures

To avoid memory misalignment faults and ensure 128-byte cache-line safety, the data structures are laid out as follows.

### 1. `getattrlistbulk` Buffer Parsing (No Packed Structs)

The kernel only guarantees 4-byte alignment for the `length` field of each entry. Because `name_info` contains variable-length strings, subsequent 8-byte fields like `alloc_size` will almost certainly land on odd offsets.

**Fix:** Do NOT cast the kernel buffer to a packed struct. Instead, iterate through the buffer using a raw `char*` and `memcpy` each fixed-size field into a properly aligned, stack-allocated local struct. On Apple Silicon, the compiler optimizes small fixed-size `memcpy` calls into a few SIMD instructions, completely eliminating any unaligned load penalty.

**Critical:** The `attrreference_t` struct contains an `attr_dataoffset` field whose offset is *relative to the memory address of the `attrreference_t` itself*. You must resolve the file name pointer directly from the raw kernel buffer *before* (or without) `memcpy`ing the `attrreference_t` to a stack variable. Copying the struct to a new memory location invalidates the offset and will produce garbage pointers.

```c
// Aligned local struct for fixed-size attributes only.
// The file name string is resolved separately from the raw buffer.
typedef struct {
    uint32_t length;
    attribute_set_t returned_attrs;
    uint32_t obj_type;
    uint32_t nlink;
    uint64_t inode;
    uint64_t alloc_size;       // Only valid for VREG entries
    const char* name;          // Resolved from raw buffer, NOT from a copied attrreference_t
} bulk_entry_t;

// Usage:
// 1. Walk raw buffer with char* cursor.
// 2. Locate the attrreference_t IN the raw buffer and resolve name pointer there:
//      const char* name = ((char*)&raw_name_ref) + raw_name_ref.attr_dataoffset;
// 3. memcpy the remaining fixed-size fields (obj_type, nlink, inode, alloc_size)
//    into bulk_entry_t. (Only read alloc_size if valid for VREG).
// 4. Advance to the next entry: cursor += current_entry->length;
```

Requests `ATTR_FILE_ALLOCSIZE` to prevent APFS sparse files from over-reporting logical sizes.

### 2. Scan Record (Per-Thread, Flat, Hot Path)

Each thread bump-allocates these into its arena during the scan. No pointers between threads.

```c
typedef struct {
    uint64_t parent_inode;   // 8 — inode of the containing directory
    uint64_t inode;          // 8 — this entry's inode (ATTR_CMN_FILEID)
    uint64_t physical_size;  // 8 — ATTR_FILE_ALLOCSIZE (0 for dirs/symlinks/deduped hardlinks)
    const char* name;        // 8 — pointer into thread's string arena
    uint32_t type;           // 4 — VDIR, VREG, VLNK
    uint32_t nlink;          // 4 — hardlink count (ATTR_CMN_NLINK)
} ScanRecord;                // 40 bytes total, 8-byte aligned

_Static_assert(sizeof(ScanRecord) == 40, "ScanRecord must be 40 bytes");
```

### 3. Tree Node (Post-Scan Reconstruction Only)

Used only in Phase B to build the directory tree. Not on the hot path.

```c
typedef struct TreeNode {
    uint64_t rolled_up_size;       // 8 — sum of own + all descendants
    uint64_t own_size;             // 8 — physical size of direct children files
    uint64_t inode;                // 8
    struct TreeNode* first_child;  // 8
    struct TreeNode* next_sibling; // 8
    const char* name;              // 8
    uint8_t type;                  // 1
    uint8_t _pad[7];               // 7 — pad to 56 bytes (8-byte aligned)
} TreeNode;
```

### 4. Thread State (False Sharing Prevention)

Aligned to 128 bytes to perfectly match the M1 Pro L2 cache line architecture.

```c
typedef struct {
    ScanRecord* record_arena_base;
    size_t record_arena_offset;
    char* string_arena_base;
    size_t string_arena_offset;
    uint64_t record_count;
    uint64_t error_count;
    // Hardlink dedup is deferred to Phase B (global khash)
} __attribute__((aligned(128))) ThreadState;
```

## Safety & System Friction

- TCC Full Disk Access Check:
  - macOS restricts paths like `~/Desktop`, `~/Downloads`, and `~/Library/Messages` without "Full Disk Access."
  - Artemis probes a known TCC-protected directory (`~/Library/Messages`) with `getattrlistbulk` at startup. If it receives `EPERM`, the program instantly aborts with instructions to grant Full Disk Access, preventing the OS from generating massive background crash/audit logs for millions of denied files.
- APFS Clone Deduplication: See [APFS Clone Deduplication](#apfs-clone-deduplication) section above.
- APFS Volume Selection:
  - macOS has multiple APFS volumes (System, Data, Preboot, Recovery, VM). The read-only sealed System volume and the Preboot/Recovery/VM volumes contain no user-cleanable data. Artemis defaults to scanning only the Data volume (`/System/Volumes/Data`), which is where user files, applications, and caches reside.
- Smart Skipping:
  - Bypasses `/System`, `.Spotlight-V100`, `.fseventsd`, and synthetic firmlinks.
  - At startup, enumerates mount points (`getmntinfo`) and caches them. **Refuses to scan anything that isn't `apfs` or `hfs`.** A pure string-matching `should_skip_path` function is used during the hot loop to avoid blocking `stat()` or `statfs()` calls, which can cause threads to hang indefinitely on network mounts (SMB/NFS) or complex Docker volumes.
  - Skips `/private/var/vm/` (swap files — huge, uncleanable).
  - Skips macOS App Sandboxes and virtual files (`~/Library/Containers`, `~/Library/Group Containers`, `~/Library/Mobile Documents`, `~/Library/CloudStorage`). iCloud and Sandboxes contain hundreds of thousands of nested UUID placeholder files that cause `getattrlistbulk` to crawl. Skipping these enables sub-20 second full-disk scans.

## Output Phases & Calculations

### Size Representation (Base-10 vs Base-2)

macOS Finder (since OS X Snow Leopard) and commercial tools like DaisyDisk exclusively use **Base-10** math for storage (1 GB = 1,000,000,000 bytes). Artemis aligns with this convention to avoid terrifying users with apparent "missing space" discrepancies (which can be up to ~22GB on a 500GB SSD when using Base-2 GiB).

### Hidden Space (Matching DaisyDisk)

Artemis replicates DaisyDisk's "Hidden Space" metric to account for APFS local snapshots (Time Machine), the sealed System volume, and the intentionally-skipped Sandbox/iCloud folders mentioned above.
Instead of attempting to manually track complex APFS shared-block snapshot extents, Artemis relies on simple filesystem truth:
`Hidden Space = (Total APFS Container Blocks Used from statfs) - (Sum of physical bytes of all Scanned Files)`

### Phase 1: Size Report

- Top N largest directories (rolled up post-scan).
- Top N largest individual files.
- Total physical scanned size, file/dir count, skipped entries, and execution time.

### Phase 2: Cleanup Categories

Flags known cleanup targets by walking the generated tree for specific paths:

- `~/Library/Caches/*`
- `~/Library/Developer/Xcode/DerivedData`
- `~/Library/Developer/CoreSimulator`
- Homebrew & npm/yarn caches
- `.Trash` & `/var/log`

### Phase 3: Duplicate / Clone Detection (Future, Optional)

- Uses `xxHash` on size-matched files for rapid duplicate detection. `xxHash` is highly recommended since it is the undisputed king of raw speed, available as a single header, and runs at the limit of the M-series RAM bandwidth.
- If `getattrlistbulk` clone IDs are validated as working: integrated into Phase 1. If not: optional slow pass using per-file `getattrlist()` on size-matched candidates.

## Build Instructions

```bash
# Compile with heavy optimizations, targeting the exact host microarchitecture
# -mcpu=native: targets the exact chip (M1 Pro, M2 Max, M4, etc.) — no ALU paths left on the table
# -flto: Link Time Optimization inlines memcpy buffer parsing across the whole program
# -lpthread is intentionally omitted — on macOS, pthreads are part of libSystem, linked by default
cc -O3 -mcpu=native -flto -o artemis main.c
```
