#include "safety.h"

#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>

void check_full_disk_access(void) {
    // Build path to ~/Library/Messages (TCC-protected)
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home) {
        fprintf(stderr, "[artemis] WARNING: cannot determine home directory, skipping TCC check\n");
        return;
    }

    char probe_path[1024];
    snprintf(probe_path, sizeof(probe_path), "%s/Library/Messages", home);

    int fd = open(probe_path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        if (errno == EPERM || errno == EACCES) {
            fprintf(stderr,
                "\n"
                "╔═════════════════════════════════════════════════════════════╗\n"
                "║  ERROR: Full Disk Access is not granted.                    ║\n"
                "║                                                             ║\n"
                "║  Artemis needs Full Disk Access to scan your entire disk.   ║\n"
                "║                                                             ║\n"
                "║  → System Settings → Privacy & Security → Full Disk Access  ║\n"
                "║  → Add Terminal (or your terminal app)                      ║\n"
                "║                                                             ║\n"
                "║  Then re-run artemis.                                       ║\n"
                "╚═════════════════════════════════════════════════════════════╝\n"
                "\n");
            exit(1);
        }
        // ENOENT: Messages dir doesn't exist — that's fine, no TCC block
        return;
    }
    close(fd);
}

const char* get_scan_root(const char* user_root) {
    const char* root = user_root ? user_root : "/System/Volumes/Data";

    // Verify the path is on APFS or HFS
    struct statfs sfs;
    if (statfs(root, &sfs) != 0) {
        fprintf(stderr, "[artemis] ERROR: cannot statfs '%s': %s\n", root, strerror(errno));
        exit(1);
    }

    if (strcmp(sfs.f_fstypename, "apfs") != 0 &&
        strcmp(sfs.f_fstypename, "hfs") != 0) {
        fprintf(stderr,
            "[artemis] ERROR: scan root '%s' is on filesystem '%s'.\n"
            "          Artemis only supports APFS and HFS. Scanning network mounts\n"
            "          (SMB/NFS) via getattrlistbulk can hang indefinitely.\n",
            root, sfs.f_fstypename);
        exit(1);
    }

    return root;
}

// ---------------------------------------------------------------------------
// Mount point cache — enumerate once at startup, not per-directory
// ---------------------------------------------------------------------------
static char** skip_mounts = NULL;  // paths of non-APFS/HFS mounts
static int skip_mount_count = 0;

void safety_init_mounts(void) {
    struct statfs* mounts = NULL;
    int count = getmntinfo(&mounts, MNT_NOWAIT);
    if (count <= 0) return;

    // Allocate space for non-APFS/HFS mount points
    skip_mounts = malloc(sizeof(char*) * (size_t)count);
    skip_mount_count = 0;

    for (int i = 0; i < count; i++) {
        if (strcmp(mounts[i].f_fstypename, "apfs") != 0 &&
            strcmp(mounts[i].f_fstypename, "hfs") != 0) {
            skip_mounts[skip_mount_count] = strdup(mounts[i].f_mntonname);
            skip_mount_count++;
        }
    }
}

// Basename skip check — entries that should be skipped by name
static const char* SKIP_BASENAMES[] = {
    ".Spotlight-V100",
    ".fseventsd",
    ".DocumentRevisions-V100",
    ".Trashes",
    NULL
};

bool should_skip_path(const char* path) {
    // Check basename first (fast string compare, no syscalls)
    const char* last_slash = strrchr(path, '/');
    const char* basename = last_slash ? last_slash + 1 : path;

    for (int i = 0; SKIP_BASENAMES[i]; i++) {
        if (strcmp(basename, SKIP_BASENAMES[i]) == 0) {
            return true;
        }
    }

    // Check full-path prefix skips
    // /System/Volumes/Data/System firmlinks back to the sealed System volume
    if (strncmp(path, "/System/Volumes/Data/System", 26) == 0) {
        return true;
    }
    // /private/var/vm swap files
    if (strncmp(path, "/private/var/vm", 15) == 0) {
        return true;
    }
    // /System (the sealed System volume)
    if (strncmp(path, "/System", 7) == 0 &&
        strncmp(path, "/System/Volumes/Data", 20) != 0) {
        return true;
    }

    // Check against cached non-APFS/HFS mount points (no syscall!)
    for (int i = 0; i < skip_mount_count; i++) {
        size_t mount_len = strlen(skip_mounts[i]);
        if (strncmp(path, skip_mounts[i], mount_len) == 0 &&
            (path[mount_len] == '/' || path[mount_len] == '\0')) {
            return true;
        }
    }

    // Skip iCloud, CloudStorage, and macOS app sandbox containers.
    // These folders often contain hundreds of thousands of virtual/placeholder files
    // or deeply nested UUID directories that are very slow to scan and rarely
    // useful for manual disk space cleanup.
    if (strstr(path, "/Library/Mobile Documents") != NULL ||
        strstr(path, "/Library/CloudStorage") != NULL ||
        strstr(path, "/Library/Containers") != NULL ||
        strstr(path, "/Library/Group Containers") != NULL) {
        return true;
    }

    return false;
}
