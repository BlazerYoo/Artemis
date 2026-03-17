#include <sys/attr.h>
#include <sys/vnode.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
    struct attrlist alist;
    memset(&alist, 0, sizeof(alist));
    alist.bitmapcount = ATTR_BIT_MAP_COUNT;
    alist.volattr = ATTR_VOL_INFO | ATTR_VOL_SPACEFREE | ATTR_VOL_SPACEAVAIL | ATTR_VOL_SPACEUSED;
    
    struct {
        uint32_t length;
        uint64_t free_space;
        uint64_t avail_space;
        uint64_t used_space;
    } __attribute__((aligned(4), packed)) attrbuf;
    
    if (getattrlist("/System/Volumes/Data", &alist, &attrbuf, sizeof(attrbuf), 0) == 0) {
        printf("Free Space:  %.1f GB\n", (double)attrbuf.free_space / 1e9);
        printf("Avail Space: %.1f GB\n", (double)attrbuf.avail_space / 1e9);
        printf("Used Space:  %.1f GB\n", (double)attrbuf.used_space / 1e9);
        printf("Purgeable?:   %.1f GB\n", ((double)attrbuf.avail_space - (double)attrbuf.free_space) / 1e9);
    } else {
        perror("getattrlist");
    }
    return 0;
}
