#include "tree.h"
#include "arena.h"
#include "khash.h"

#include <sys/vnode.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Hash maps: inode → TreeNode*, and inode set for hardlink dedup
KHASH_MAP_INIT_INT64(inode_map, TreeNode*)
KHASH_SET_INIT_INT64(inode_set)

static khash_t(inode_map)* node_map = NULL;
static khash_t(inode_set)* hardlink_seen = NULL;
static Arena* tree_arena = NULL;

static uint64_t total_files = 0;
static uint64_t total_dirs = 0;
static uint64_t total_physical = 0;

static TreeNode* get_or_create_node(uint64_t inode, const char* name, uint8_t type,
                                     int update_if_exists) {
    int ret;
    khiter_t k = kh_put(inode_map, node_map, inode, &ret);
    if (ret == 0) {
        // Already exists — update name/type if we now have real data
        TreeNode* existing = kh_val(node_map, k);
        if (update_if_exists && name) {
            existing->name = name;
            existing->type = type;
        }
        return existing;
    }

    // New node — allocate from tree arena
    TreeNode* node = (TreeNode*)arena_alloc(tree_arena, sizeof(TreeNode), _Alignof(TreeNode));
    memset(node, 0, sizeof(TreeNode));
    node->inode = inode;
    node->name  = name;
    node->type  = type;
    kh_val(node_map, k) = node;
    return node;
}

TreeNode* build_tree(ThreadState* threads, int thread_count, uint64_t root_inode) {
    // Count total records for pre-sizing
    uint64_t total_records = 0;
    for (int i = 0; i < thread_count; i++) {
        total_records += threads[i].record_count;
    }

    // Pre-size hash maps
    node_map      = kh_init(inode_map);
    hardlink_seen = kh_init(inode_set);
    kh_resize(inode_map, node_map, (khint_t)(total_records * 2));
    kh_resize(inode_set, hardlink_seen, (khint_t)(total_records / 4));

    // Tree arena for TreeNode allocations (1 GB virtual — more than enough)
    tree_arena = arena_create((size_t)1ULL * 1024 * 1024 * 1024);

    total_files = 0;
    total_dirs = 0;
    total_physical = 0;

    // Create root node
    TreeNode* root = get_or_create_node(root_inode, "/", VDIR, 0);

    // Iterate all per-thread scan record arrays
    for (int t = 0; t < thread_count; t++) {
        ScanRecord* records = threads[t].record_arena_base;
        uint64_t count = threads[t].record_count;

        for (uint64_t r = 0; r < count; r++) {
            ScanRecord* rec = &records[r];

            // Get or create this node
            TreeNode* node = get_or_create_node(rec->inode, rec->name, (uint8_t)rec->type, 1);

            // Hardlink deduplication (Phase B)
            uint64_t size_to_add = 0;
            if (rec->type == VREG) {
                total_files++;
                if (rec->nlink > 1) {
                    // Check if we've already counted this inode
                    int ret;
                    kh_put(inode_set, hardlink_seen, rec->inode, &ret);
                    if (ret != 0) {
                        // First time seeing this inode — count its size
                        size_to_add = rec->physical_size;
                    }
                    // ret == 0 means already seen — skip the size
                } else {
                    size_to_add = rec->physical_size;
                }
            } else if (rec->type == VDIR) {
                total_dirs++;
            }

            node->own_size += size_to_add;
            total_physical += size_to_add;

            // Link child to parent (only once — hardlinks may appear in multiple dirs)
            TreeNode* parent = get_or_create_node(rec->parent_inode, "(unknown)", VDIR, 0);
            if (parent != node && !node->linked) {
                // Prepend to parent's child list (order doesn't matter for summation)
                node->next_sibling = parent->first_child;
                parent->first_child = node;
                node->linked = 1;
            }
        }
    }

    return root;
}

void rollup_sizes(TreeNode* node) {
    if (!node) return;

    node->rolled_up_size = node->own_size;

    TreeNode* child = node->first_child;
    while (child) {
        rollup_sizes(child);
        node->rolled_up_size += child->rolled_up_size;
        child = child->next_sibling;
    }
}

TreeNode* tree_find(uint64_t inode) {
    khiter_t k = kh_get(inode_map, node_map, inode);
    if (k == kh_end(node_map)) return NULL;
    return kh_val(node_map, k);
}

uint64_t tree_total_files(void)         { return total_files; }
uint64_t tree_total_dirs(void)          { return total_dirs; }
uint64_t tree_total_physical_size(void) { return total_physical; }

void tree_destroy(void) {
    if (node_map)      { kh_destroy(inode_map, node_map); node_map = NULL; }
    if (hardlink_seen) { kh_destroy(inode_set, hardlink_seen); hardlink_seen = NULL; }
    if (tree_arena)    { arena_destroy(tree_arena); tree_arena = NULL; }
}
