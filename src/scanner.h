#ifndef ARTEMIS_SCANNER_H
#define ARTEMIS_SCANNER_H

#include "types.h"

// Scan a single directory using getattrlistbulk.
// Appends ScanRecords into ts's arena. Returns discovered subdirectory paths
// via out_subdirs (caller provides buffer). Returns number of subdirs found.
//
// out_subdirs: array of const char* pointers (into ts's string arena)
// max_subdirs: capacity of out_subdirs
int scan_directory(ThreadState* ts, const char* path,
                   const char** out_subdirs, int max_subdirs);

#endif // ARTEMIS_SCANNER_H
