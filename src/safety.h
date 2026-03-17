#ifndef ARTEMIS_SAFETY_H
#define ARTEMIS_SAFETY_H

#include <stdbool.h>

// Check if Full Disk Access is granted by probing ~/Library/Messages.
// If not, prints instructions and exits.
void check_full_disk_access(void);

// Initialize mount point cache (call once at startup).
void safety_init_mounts(void);

// Determine the scan root. Defaults to /System/Volumes/Data.
// Verifies the volume is APFS or HFS.
const char* get_scan_root(const char* user_root);

// Returns true if the given path should be skipped during scanning.
bool should_skip_path(const char* path);

#endif // ARTEMIS_SAFETY_H
