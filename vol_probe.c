#include <stdio.h>
#include <sys/attr.h>
#include <sys/vnode.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

struct vol_attrs {
    uint32_t length;
    off_t spaceavail;
    off_t spacefree;
    off_t spaceused;
    off_t spacetotal;
};

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    
    struct attrlist al = {0};
    al.bitmapcount = ATTR_BIT_MAP_COUNT;
    // Note: The order in the buffer depends on the order the bits are defined in the bitmask,
    // which corresponds to the header definition order. 
    // ATTR_VOL_SIZE, ATTR_VOL_SPACEFREE, ATTR_VOL_SPACEAVAIL
    al.volattr = ATTR_VOL_SIZE | ATTR_VOL_SPACEFREE | ATTR_VOL_SPACEAVAIL;
    
    // There is no standard ATTR_VOL_SPACEUSED. We just subtract.
    
    struct {
        uint32_t size;
        off_t spacetotal;
        off_t spacefree;
        off_t spaceavail;
    } attrs = {0};

    if (getattrlist(argv[1], &al, &attrs, sizeof(attrs), 0) == 0) {
        printf("Available (purgeable included): %llu\n", (unsigned long long)attrs.spaceavail);
        printf("Free (strictly free):           %llu\n", (unsigned long long)attrs.spacefree);
        printf("Total volume size:              %llu\n", (unsigned long long)attrs.spacetotal);
        printf("Used = Total - Free:            %llu\n", (unsigned long long)(attrs.spacetotal - attrs.spacefree));
    } else {
        perror("getattrlist");
    }
    return 0;
}
