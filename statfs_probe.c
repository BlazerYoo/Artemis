#include <stdio.h>
#include <sys/param.h>
#include <sys/mount.h>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    struct statfs s;
    if (statfs(argv[1], &s) == 0) {
        printf("Block size: %u\n", s.f_bsize);
        printf("Total blocks: %llu (%.2f GB)\n", s.f_blocks, (double)(s.f_blocks * s.f_bsize) / 1e9);
        printf("Free blocks:  %llu (%.2f GB)\n", s.f_bfree, (double)(s.f_bfree * s.f_bsize) / 1e9);
        printf("Avail blocks: %llu (%.2f GB)\n", s.f_bavail, (double)(s.f_bavail * s.f_bsize) / 1e9);
        printf("Used blocks:  %llu (%.2f GB)\n", (s.f_blocks - s.f_bfree), (double)((s.f_blocks - s.f_bfree) * s.f_bsize) / 1e9);
    } else {
        perror("statfs");
    }
    return 0;
}
