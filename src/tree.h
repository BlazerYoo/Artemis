#ifndef ARTEMIS_TREE_H
#define ARTEMIS_TREE_H

#include "types.h"

// Build directory tree from flat scan records across all threads.
// Performs hardlink deduplication during tree construction.
// Returns the root TreeNode.
TreeNode* build_tree(ThreadState* threads, int thread_count, uint64_t root_inode);

// Post-order traversal to roll up directory sizes.
void rollup_sizes(TreeNode* root);

// Find a node by inode in the tree's hash map.
TreeNode* tree_find(uint64_t inode);

// Get total counts from the last build_tree call.
uint64_t tree_total_files(void);
uint64_t tree_total_dirs(void);
uint64_t tree_total_physical_size(void);

// Clean up tree structures.
void tree_destroy(void);

#endif // ARTEMIS_TREE_H
