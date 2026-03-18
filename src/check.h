#ifndef ARTEMIS_CHECK_H
#define ARTEMIS_CHECK_H

#include <sys/param.h>   // MAXPATHLEN
#include <stdbool.h>
#include <stdint.h>

#define CHECK_MAX_PROCS 16
#define CHECK_MAX_REFS  12

// ---------------------------------------------------------------------------
// SafeCheckResult — populated by check_safe_to_delete(), read by report
// ---------------------------------------------------------------------------
typedef struct {
    // ── Basic file info ────────────────────────────────────────────────────
    char     input_path[MAXPATHLEN];
    char     resolved_path[MAXPATHLEN];  // realpath() result (symlinks resolved)
    bool     exists;
    bool     is_dir;
    bool     is_symlink;
    bool     symlink_target_missing;     // broken symlink
    char     symlink_target[MAXPATHLEN];
    int64_t  size_bytes;
    uint32_t nlink;                      // st_nlink from lstat()
    bool     is_in_app_bundle;           // path contains .app/

    // ── Open process handles (libproc) ─────────────────────────────────────
    int  open_proc_count;
    int  open_user_proc_count;               // non-infrastructure processes only
    char open_proc_names[CHECK_MAX_PROCS][256];
    int  open_proc_pids[CHECK_MAX_PROCS];
    bool open_proc_is_infra[CHECK_MAX_PROCS]; // virtualization/indexing/backup daemon

    // ── Spotlight: files whose content references the resolved path ─────────
    int  spotlight_ref_count;
    bool spotlight_overflow;             // more refs exist beyond CHECK_MAX_REFS
    char spotlight_ref_paths[CHECK_MAX_REFS][MAXPATHLEN];
    bool spotlight_not_indexed;          // file not in Spotlight index

    // ── Mach-O type ────────────────────────────────────────────────────────
    bool is_macho;
    bool is_dylib;

    // ── Protected system path ───────────────────────────────────────────────
    bool is_protected;           // path matches a known critical system location
    bool protected_is_critical;  // true = CRIT, false = WARN
    char protected_reason[256];  // human-readable explanation
} SafeCheckResult;

// Run all checks and populate *result.
void check_safe_to_delete(const char *path, SafeCheckResult *result);

// Print formatted safety report to stdout.
void report_safe_to_delete(const SafeCheckResult *result);

#endif // ARTEMIS_CHECK_H
