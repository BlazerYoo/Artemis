#include "report.h"
#include "tree.h"

#include <sys/vnode.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Human-readable size formatting
// ---------------------------------------------------------------------------
static void format_size(uint64_t bytes, char* buf, size_t buf_size) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    double size = (double)bytes;
    int unit = 0;
    while (size >= 1000.0 && unit < 4) {
        size /= 1000.0;
        unit++;
    }
    if (unit == 0)
        snprintf(buf, buf_size, "%llu B", (unsigned long long)bytes);
    else
        snprintf(buf, buf_size, "%.1f %s", size, units[unit]);
}

// ---------------------------------------------------------------------------
// Top-N collection via partial sort
// ---------------------------------------------------------------------------
typedef struct {
    TreeNode*  node;
    uint64_t   size;
    char       path[2048];
} SizedEntry;

static SizedEntry* top_dirs = NULL;
static int top_dirs_count = 0;
static int top_dirs_cap = 0;

static SizedEntry* top_files = NULL;
static int top_files_count = 0;
static int top_files_cap = 0;

static void collect_top_n(SizedEntry* entries, int* count, int cap,
                          TreeNode* node, uint64_t size, const char* path) {
    if (*count < cap) {
        entries[*count].node = node;
        entries[*count].size = size;
        strncpy(entries[*count].path, path, sizeof(entries[0].path) - 1);
        entries[*count].path[sizeof(entries[0].path) - 1] = '\0';
        (*count)++;
    } else {
        // Find the minimum entry
        int min_idx = 0;
        for (int i = 1; i < cap; i++) {
            if (entries[i].size < entries[min_idx].size) {
                min_idx = i;
            }
        }
        if (size > entries[min_idx].size) {
            entries[min_idx].node = node;
            entries[min_idx].size = size;
            strncpy(entries[min_idx].path, path, sizeof(entries[0].path) - 1);
            entries[min_idx].path[sizeof(entries[0].path) - 1] = '\0';
        }
    }
}

static int cmp_sized_entry_desc(const void* a, const void* b) {
    const SizedEntry* ea = (const SizedEntry*)a;
    const SizedEntry* eb = (const SizedEntry*)b;
    if (eb->size > ea->size) return 1;
    if (eb->size < ea->size) return -1;
    return 0;
}

// Recursive traversal to collect top dirs and files
static void walk_tree(TreeNode* node, char* path_buf, size_t path_len) {
    if (!node) return;

    // Build current path
    size_t name_len = node->name ? strlen(node->name) : 0;
    size_t new_len = path_len;
    if (path_len > 0 && path_buf[path_len - 1] != '/') {
        path_buf[new_len++] = '/';
    }
    if (name_len > 0 && new_len + name_len < 2048) {
        memcpy(path_buf + new_len, node->name, name_len);
        new_len += name_len;
    }
    path_buf[new_len] = '\0';

    if (node->type == VDIR && node->rolled_up_size > 0) {
        collect_top_n(top_dirs, &top_dirs_count, top_dirs_cap,
                      node, node->rolled_up_size, path_buf);
    } else if (node->type == VREG && node->own_size > 0) {
        collect_top_n(top_files, &top_files_count, top_files_cap,
                      node, node->own_size, path_buf);
    }

    // Recurse into children
    TreeNode* child = node->first_child;
    while (child) {
        char child_path[2048];
        memcpy(child_path, path_buf, new_len + 1);
        walk_tree(child, child_path, new_len);
        child = child->next_sibling;
    }
}

void report_sizes(TreeNode* root, int top_n, double elapsed_secs,
                  uint64_t total_file_count, uint64_t total_dir_count,
                  uint64_t total_errors, uint64_t total_physical,
                  uint64_t total_volume_used) {
    top_dirs_cap = top_n;
    top_files_cap = top_n;
    top_dirs = calloc((size_t)top_n, sizeof(SizedEntry));
    top_files = calloc((size_t)top_n, sizeof(SizedEntry));
    top_dirs_count = 0;
    top_files_count = 0;

    char path_buf[2048] = "";
    walk_tree(root, path_buf, 0);

    // Sort results
    qsort(top_dirs, (size_t)top_dirs_count, sizeof(SizedEntry), cmp_sized_entry_desc);
    qsort(top_files, (size_t)top_files_count, sizeof(SizedEntry), cmp_sized_entry_desc);

    char size_buf[64];
    char hidden_buf[64];
    char vol_used_buf[64];

    // Calculate Hidden Space (APFS Snapshots, System Volume, excluded Containers)
    uint64_t hidden_space = 0;
    if (total_volume_used > total_physical) {
        hidden_space = total_volume_used - total_physical;
    }

    // Header
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("                    ARTEMIS DISK SCAN REPORT\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    // Top directories
    printf("  ┌─ TOP %d LARGEST DIRECTORIES ─────────────────────────────\n", top_n);
    for (int i = 0; i < top_dirs_count; i++) {
        format_size(top_dirs[i].size, size_buf, sizeof(size_buf));
        printf("  │ %2d. %10s  %s\n", i + 1, size_buf, top_dirs[i].path);
    }
    printf("  └──────────────────────────────────────────────────────────\n\n");

    // Top files
    printf("  ┌─ TOP %d LARGEST FILES ───────────────────────────────────\n", top_n);
    for (int i = 0; i < top_files_count; i++) {
        format_size(top_files[i].size, size_buf, sizeof(size_buf));
        printf("  │ %2d. %10s  %s\n", i + 1, size_buf, top_files[i].path);
    }
    printf("  └──────────────────────────────────────────────────────────\n\n");

    // Summary
    format_size(total_physical, size_buf, sizeof(size_buf));
    format_size(hidden_space, hidden_buf, sizeof(hidden_buf));
    format_size(total_volume_used, vol_used_buf, sizeof(vol_used_buf));

    printf("  ┌─ SUMMARY ───────────────────────────────────────────────\n");
    printf("  │ Scanned Files Size:  %s\n", size_buf);
    printf("  │ Hidden Space:        %s (Snapshots, System, Sandboxes)\n", hidden_buf);
    printf("  │ --------------------------------------------------------\n");
    printf("  │ Total Volume Used:   %s\n", vol_used_buf);
    printf("  │ \n");
    printf("  │ Files:               %llu\n", (unsigned long long)total_file_count);
    printf("  │ Directories:         %llu\n", (unsigned long long)total_dir_count);
    printf("  │ Skipped (errors):    %llu\n", (unsigned long long)total_errors);
    printf("  │ Scan time:           %.3f seconds\n", elapsed_secs);
    printf("  └──────────────────────────────────────────────────────────\n\n");

    free(top_dirs);  top_dirs = NULL;
    free(top_files); top_files = NULL;
}

// ---------------------------------------------------------------------------
// Cleanup category reporting
// ---------------------------------------------------------------------------
typedef struct {
    const char* label;
    const char* suffix;  // path suffix to match (from home dir)
} CleanupCategory;

static const CleanupCategory CLEANUP_CATEGORIES[] = {
    { "Xcode DerivedData",         "Library/Developer/Xcode/DerivedData" },
    { "iOS Simulators",            "Library/Developer/CoreSimulator" },
    { "User Caches",               "Library/Caches" },
    { "Homebrew Cache",            "Library/Caches/Homebrew" },
    { "npm Cache",                 ".npm" },
    { "Yarn Cache",                "Library/Caches/Yarn" },
    { "Trash",                     ".Trash" },
    { "System Logs",               "/var/log" },
    { NULL, NULL }
};

// Walk tree to find cleanup paths by matching node paths
static void find_cleanup_node(TreeNode* node, char* path_buf, size_t path_len,
                              const char* suffix, uint64_t* out_size) {
    if (!node) return;

    size_t name_len = node->name ? strlen(node->name) : 0;
    size_t new_len = path_len;
    if (path_len > 0 && path_buf[path_len - 1] != '/') {
        path_buf[new_len++] = '/';
    }
    if (name_len > 0 && new_len + name_len < 2048) {
        memcpy(path_buf + new_len, node->name, name_len);
        new_len += name_len;
    }
    path_buf[new_len] = '\0';

    // Check if this path ends with the suffix
    size_t suffix_len = strlen(suffix);
    if (new_len >= suffix_len) {
        const char* tail = path_buf + new_len - suffix_len;
        if (strcmp(tail, suffix) == 0) {
            *out_size += node->rolled_up_size;
            return; // Don't recurse further — we have the rolled-up size
        }
    }

    TreeNode* child = node->first_child;
    while (child) {
        char child_path[2048];
        memcpy(child_path, path_buf, new_len + 1);
        find_cleanup_node(child, child_path, new_len, suffix, out_size);
        child = child->next_sibling;
    }
}

void report_cleanup(TreeNode* root) {
    printf("  ┌─ CLEANUP OPPORTUNITIES ─────────────────────────────────\n");

    char size_buf[64];
    char path_buf[2048] = "";
    int found_any = 0;

    for (int i = 0; CLEANUP_CATEGORIES[i].label; i++) {
        uint64_t size = 0;
        memset(path_buf, 0, sizeof(path_buf));
        find_cleanup_node(root, path_buf, 0, CLEANUP_CATEGORIES[i].suffix, &size);
        if (size > 0) {
            format_size(size, size_buf, sizeof(size_buf));
            printf("  │ %10s  %s\n", size_buf, CLEANUP_CATEGORIES[i].label);
            found_any = 1;
        }
    }

    if (!found_any) {
        printf("  │ (no significant cleanup targets found)\n");
    }

    printf("  └──────────────────────────────────────────────────────────\n\n");
}
