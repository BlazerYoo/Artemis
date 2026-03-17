#include <sys/param.h>
#include <sys/mount.h>
#include <stdio.h>

int main() {
    struct statfs s;
    statfs("/", &s);
    printf("Block Size: %u\n", s.f_bsize);
    printf("Blocks: %llu (%.1f GB)\n", (unsigned long long)s.f_blocks, (double)s.f_blocks * s.f_bsize / 1e9);
    printf("Bfree:  %llu (%.1f GB)\n", (unsigned long long)s.f_bfree, (double)s.f_bfree * s.f_bsize / 1e9);
    printf("Bavail: %llu (%.1f GB)\n", (unsigned long long)s.f_bavail, (double)s.f_bavail * s.f_bsize / 1e9);
    return 0;
}
