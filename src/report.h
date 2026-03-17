#ifndef ARTEMIS_REPORT_H
#define ARTEMIS_REPORT_H

#include "types.h"

// Print Phase 1: top-N largest dirs, top-N largest files, summary.
void report_sizes(TreeNode* root, int top_n, double elapsed_secs,
                  uint64_t total_files, uint64_t total_dirs,
                  uint64_t total_errors, uint64_t total_physical,
                  uint64_t total_volume_used);

// Print Phase 2: cleanup category flagging.
void report_cleanup(TreeNode* root);

#endif // ARTEMIS_REPORT_H
