#include "scanner.h"
#include "arena.h"

#include <sys/attr.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

// 64KB buffer — sweet spot for M-series unified memory kernel wiring.
#define SCAN_BUFFER_SIZE (64 * 1024)

// Attribute list requesting:
//   Common: returned_attrs, name, object type, file ID
//   File:   link count, alloc size (only returned for VREG entries)
static struct attrlist scan_attrlist = {
    .bitmapcount = ATTR_BIT_MAP_COUNT,
    .commonattr  = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_OBJTYPE |
                   ATTR_CMN_FILEID,
    .fileattr    = ATTR_FILE_LINKCOUNT | ATTR_FILE_ALLOCSIZE,
};

int scan_directory(ThreadState* ts, const char* path,
                   const char** out_subdirs, int max_subdirs) {
    int subdir_count = 0;

    int fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        ts->error_count++;
        return 0;
    }

    // Get parent directory inode via fstat
    struct stat dir_stat;
    if (fstat(fd, &dir_stat) < 0) {
        ts->error_count++;
        close(fd);
        return 0;
    }
    uint64_t parent_inode = (uint64_t)dir_stat.st_ino;

    char buf[SCAN_BUFFER_SIZE] __attribute__((aligned(8)));

    for (;;) {
        int count = getattrlistbulk(fd, &scan_attrlist, buf, sizeof(buf), 0);
        if (count < 0) {
            if (errno != EINTR) ts->error_count++;
            if (errno == EINTR) continue;
            break;
        }
        if (count == 0) break; // No more entries

        char* cursor = buf;
        for (int i = 0; i < count; i++) {
            // ── Entry length (first 4 bytes) ──
            uint32_t entry_length;
            memcpy(&entry_length, cursor, sizeof(entry_length));

            // ── returned_attrs (attribute_set_t) ──
            attribute_set_t returned_attrs;
            memcpy(&returned_attrs, cursor + 4, sizeof(returned_attrs));

            // Offset tracker past length + returned_attrs
            size_t off = 4 + sizeof(attribute_set_t);

            // ── Name (attrreference_t) ──
            // CRITICAL: resolve name pointer from the RAW buffer before any copy.
            // The attr_dataoffset is relative to the attrreference_t's own address.
            attrreference_t name_ref;
            memcpy(&name_ref, cursor + off, sizeof(name_ref));
            const char* raw_name = (cursor + off) + (int32_t)name_ref.attr_dataoffset;
            size_t name_len = name_ref.attr_length > 0 ? name_ref.attr_length - 1 : 0;
            off += sizeof(attrreference_t);

            // ── Object type (uint32_t: VDIR/VREG/VLNK) ──
            uint32_t obj_type = 0;
            memcpy(&obj_type, cursor + off, sizeof(obj_type));
            off += sizeof(obj_type);

            // ── File ID / inode (uint64_t) ──
            uint64_t inode = 0;
            memcpy(&inode, cursor + off, sizeof(inode));
            off += sizeof(inode);

            // ── File-only attributes (linkcount + allocsize) ──
            // These are ONLY present for VREG entries. For VDIR/VLNK they are
            // not in the returned data.
            uint32_t nlink = 1;
            uint64_t alloc_size = 0;
            if (obj_type == VREG) {
                if (returned_attrs.fileattr & ATTR_FILE_LINKCOUNT) {
                    memcpy(&nlink, cursor + off, sizeof(nlink));
                    off += sizeof(nlink);
                }
                if (returned_attrs.fileattr & ATTR_FILE_ALLOCSIZE) {
                    memcpy(&alloc_size, cursor + off, sizeof(alloc_size));
                    // off += sizeof(alloc_size);  // not needed, we use entry_length to advance
                }
            }

            // Skip . and ..
            if (name_len == 1 && raw_name[0] == '.') {
                cursor += entry_length;
                continue;
            }
            if (name_len == 2 && raw_name[0] == '.' && raw_name[1] == '.') {
                cursor += entry_length;
                continue;
            }

            // ── Copy name into string arena ──
            // Buffer is reused each getattrlistbulk call — must copy now.
            const char* arena_name = arena_alloc_string(ts->string_arena, raw_name, name_len);
            if (!arena_name) {
                cursor += entry_length;
                continue;
            }

            // ── Append ScanRecord to record arena ──
            ScanRecord* rec = (ScanRecord*)arena_alloc(ts->record_arena,
                                                        sizeof(ScanRecord), _Alignof(ScanRecord));
            if (!rec) {
                cursor += entry_length;
                continue;
            }
            rec->parent_inode  = parent_inode;
            rec->inode         = inode;
            rec->physical_size = alloc_size;  // 0 for dirs and symlinks
            rec->name          = arena_name;
            rec->type          = obj_type;
            rec->nlink         = nlink;
            ts->record_count++;
            
            if (alloc_size > 0) {
                atomic_fetch_add_explicit(&ts->live_scanned_bytes, alloc_size, memory_order_relaxed);
            }

            // ── If directory, build child path for work queue ──
            if (obj_type == VDIR) {
                if (subdir_count < max_subdirs) {
                    size_t path_len = strlen(path);
                    int needs_slash = (path_len > 0 && path[path_len - 1] != '/') ? 1 : 0;
                    
                    size_t child_path_len = path_len + needs_slash + name_len;
                    char* child_path = (char*)arena_alloc(ts->string_arena,
                                                           child_path_len + 1, 1);
                    if (child_path) {
                        memcpy(child_path, path, path_len);
                        if (needs_slash) {
                            child_path[path_len] = '/';
                        }
                        memcpy(child_path + path_len + needs_slash, raw_name, name_len);
                        child_path[child_path_len] = '\0';
                        out_subdirs[subdir_count++] = child_path;
                    }
                }
            }
            // Symlinks: log physical alloc size (already 0 or 4KB), never follow.

            cursor += entry_length;
        }
    }

    close(fd);
    return subdir_count;
}
