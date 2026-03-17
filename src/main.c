//
// Artemis — macOS Disk Space Analyzer (Apple Silicon Optimized)
//
// A high-performance disk crawler written in C, heavily optimized for
// M-series Apple Silicon. Scans an entire APFS filesystem using
// getattrlistbulk and P-core targeted multithreading.
//

#include "types.h"
#include "arena.h"
#include "scanner.h"
#include "workqueue.h"
#include "threads.h"
#include "safety.h"
#include "tree.h"
#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <CoreFoundation/CoreFoundation.h>

#define TOP_N_DEFAULT 20

static void print_usage(const char* progname) {
    fprintf(stderr,
        "Usage: %s [OPTIONS] [SCAN_ROOT]\n"
        "\n"
        "Options:\n"
        "  -n NUM    Show top N entries (default: %d)\n"
        "  -v        Verbose output\n"
        "  -h        Show this help\n"
        "\n"
        "SCAN_ROOT defaults to /System/Volumes/Data\n",
        progname, TOP_N_DEFAULT);
}

struct ProgressArgs {
    ThreadPool* pool;
    uint64_t total_volume_used;
    _Atomic int done;
};

// Define the progress thread function inline for the pthread
void* progress_thread(void* arg) {
    struct ProgressArgs* args = (struct ProgressArgs*)arg;
    ThreadPool* p = args->pool;
    printf("\x1b[?25l"); // Hide cursor
    
    struct timespec sleep_time = { .tv_sec = 0, .tv_nsec = 100000000 }; // 100ms
    
    while (!atomic_load_explicit(&args->done, memory_order_acquire)) {
        uint64_t scanned = 0, records = 0;
        const char* current_path = NULL;
        for (int i = 0; i < p->num_threads; i++) {
            scanned += atomic_load_explicit(&p->thread_states[i].live_scanned_bytes, memory_order_relaxed);
            records += p->thread_states[i].record_count;
            if (!current_path) {
                current_path = atomic_load_explicit(&p->thread_states[i].live_path, memory_order_relaxed);
            }
        }
        int pct = 0;
        if (args->total_volume_used > 0) {
            pct = (int)((((double)scanned) / args->total_volume_used) * 100.0);
            if (pct > 100) pct = 100;
        }
        char bar[21];
        int filled = (pct * 20) / 100;
        for (int i = 0; i < 20; i++) bar[i] = (i < filled) ? '=' : ' ';
        bar[20] = '\0';
        
        if (current_path) {
            char path_sh[64];
            size_t plen = strlen(current_path);
            if (plen > 60) snprintf(path_sh, sizeof(path_sh), "...%s", current_path + plen - 57);
            else snprintf(path_sh, sizeof(path_sh), "%s", current_path);
            printf("\r\x1b[KScanning [%s] %3d%% | %llu files | %s", bar, pct, (unsigned long long)records, path_sh);
            fflush(stdout);
        }
        nanosleep(&sleep_time, NULL);
    }
    printf("\r\x1b[K\x1b[?25h"); // Clear line, show cursor
    fflush(stdout);
    return NULL;
}

int main(int argc, char* argv[]) {
    printf("   █████████              █████                              ███         \n");
    printf("  ███░░░░░███            ░░███                              ░░░          \n");
    printf(" ░███    ░███  ████████  ███████    ██████  █████████████   ████   █████ \n");
    printf(" ░███████████ ░░███░░███░░░███░    ███░░███░░███░░███░░███ ░░███  ███░░  \n");
    printf(" ░███░░░░░███  ░███ ░░░   ░███    ░███████  ░███ ░███ ░███  ░███ ░░█████ \n");
    printf(" ░███    ░███  ░███       ░███ ███░███░░░   ░███ ░███ ░███  ░███  ░░░░███\n");
    printf(" █████   █████ █████      ░░█████ ░░██████  █████░███ █████ █████ ██████ \n");
    printf("░░░░░   ░░░░░ ░░░░░        ░░░░░   ░░░░░░  ░░░░░ ░░░ ░░░░░ ░░░░░ ░░░░░░  \n");
    printf("\n");

    int top_n = TOP_N_DEFAULT;
    int verbose = 0;
    const char* user_root = NULL;

    // Argument parsing
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            top_n = atoi(argv[++i]);
            if (top_n < 1) top_n = TOP_N_DEFAULT;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (argv[i][0] != '-') {
            user_root = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // ── Safety checks ──────────────────────────────────────────────
    // Only check TCC when doing a full disk scan (no user-specified root)
    if (!user_root) {
        check_full_disk_access();
    }
    const char* scan_root = get_scan_root(user_root);
    safety_init_mounts(); // Cache non-APFS/HFS mount points for skip checks

    if (verbose) {
        fprintf(stderr, "[artemis] Scan root: %s\n", scan_root);
    }

    // Get root inode
    struct stat root_stat;
    if (stat(scan_root, &root_stat) != 0) {
        perror("stat scan root");
        return 1;
    }
    uint64_t root_inode = (uint64_t)root_stat.st_ino;

    // Get Total Volume Used for Progress Bar Heuristic & macOS UI Alignment
    struct statfs sfs;
    uint64_t total_volume_used = 0;
    if (statfs(scan_root, &sfs) == 0) {
        uint64_t total_capacity = (uint64_t)sfs.f_blocks * (uint64_t)sfs.f_bsize;
        uint64_t available_bytes = (uint64_t)sfs.f_bavail * (uint64_t)sfs.f_bsize; // fallback
        
        // Use CoreFoundation to identically match macOS "About This Mac" Available logic
        CFStringRef pathStr = CFStringCreateWithCString(kCFAllocatorDefault, scan_root, kCFStringEncodingUTF8);
        if (pathStr) {
            CFURLRef url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, pathStr, kCFURLPOSIXPathStyle, true);
            if (url) {
                CFTypeRef value;
                if (CFURLCopyResourcePropertyForKey(url, kCFURLVolumeAvailableCapacityForImportantUsageKey, &value, NULL)) {
                    int64_t avail = 0;
                    if (CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &avail)) {
                        available_bytes = (uint64_t)avail;
                    }
                    CFRelease(value);
                }
                CFRelease(url);
            }
            CFRelease(pathStr);
        }
        
        total_volume_used = total_capacity - available_bytes;
    }

    // ── Phase A: Multi-threaded scan ───────────────────────────────
    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    WorkQueue queue;
    wq_init(&queue, 8192);
    wq_push(&queue, scan_root);

    ThreadPool* pool = threadpool_create(&queue);
    // Start UI Progress Thread
    struct ProgressArgs prog_args = { .pool = pool, .total_volume_used = total_volume_used };
    atomic_init(&prog_args.done, 0);
    pthread_t prog_tid;
    
    threadpool_start(pool);
    pthread_create(&prog_tid, NULL, progress_thread, &prog_args);

    threadpool_join(pool);

    // Stop Progress Thread
    atomic_store_explicit(&prog_args.done, 1, memory_order_release);
    pthread_join(prog_tid, NULL);

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    double elapsed = (double)(t_end.tv_sec - t_start.tv_sec) +
                     (double)(t_end.tv_nsec - t_start.tv_nsec) / 1e9;

    // Collect stats
    uint64_t total_records = 0;
    uint64_t total_errors = 0;
    for (int i = 0; i < pool->num_threads; i++) {
        total_records += pool->thread_states[i].record_count;
        total_errors  += pool->thread_states[i].error_count;
    }

    if (verbose) {
        fprintf(stderr, "[artemis] Phase A complete: %llu records, %llu errors, %.3fs\n",
                (unsigned long long)total_records,
                (unsigned long long)total_errors, elapsed);
    }

    // ── Phase B: Tree construction ─────────────────────────────────
    struct timespec t_tree_start, t_tree_end;
    clock_gettime(CLOCK_MONOTONIC, &t_tree_start);

    TreeNode* root = build_tree(pool->thread_states, pool->num_threads, root_inode);
    rollup_sizes(root);

    clock_gettime(CLOCK_MONOTONIC, &t_tree_end);
    double tree_elapsed = (double)(t_tree_end.tv_sec - t_tree_start.tv_sec) +
                          (double)(t_tree_end.tv_nsec - t_tree_start.tv_nsec) / 1e9;

    if (verbose) {
        fprintf(stderr, "[artemis] Phase B complete: tree built in %.3fs\n", tree_elapsed);
        fprintf(stderr, "[artemis] Files: %llu, Dirs: %llu\n",
                (unsigned long long)tree_total_files(),
                (unsigned long long)tree_total_dirs());
    }

    // ── Output ─────────────────────────────────────────────────────
    report_sizes(root, top_n, elapsed,
                 tree_total_files(), tree_total_dirs(),
                 total_errors, tree_total_physical_size(),
                 total_volume_used);
    report_cleanup(root);

    // ── Cleanup ────────────────────────────────────────────────────
    tree_destroy();
    wq_destroy(&queue);

    // Destroy thread arenas
    for (int i = 0; i < pool->num_threads; i++) {
        arena_destroy(pool->thread_states[i].record_arena);
        arena_destroy(pool->thread_states[i].string_arena);
    }
    free(pool->thread_states);
    threadpool_destroy(pool);

    return 0;
}
