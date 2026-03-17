#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

int main() {
    CFURLRef url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, CFSTR("/"), kCFURLPOSIXPathStyle, true);
    CFTypeRef value;
    if (CFURLCopyResourcePropertyForKey(url, kCFURLVolumeAvailableCapacityForImportantUsageKey, &value, NULL)) {
        int64_t avail = 0;
        CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &avail);
        printf("Available for Important: %.1f GB\n", (double)avail / 1e9);
        CFRelease(value);
    }
    
    if (CFURLCopyResourcePropertyForKey(url, kCFURLVolumeAvailableCapacityForOpportunisticUsageKey, &value, NULL)) {
        int64_t avail = 0;
        CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &avail);
        printf("Available for Opportunistic: %.1f GB\n", (double)avail / 1e9);
        CFRelease(value);
    }
    
    if (CFURLCopyResourcePropertyForKey(url, kCFURLVolumeAvailableCapacityKey, &value, NULL)) {
        int64_t avail = 0;
        CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &avail);
        printf("Standard Available: %.1f GB\n", (double)avail / 1e9);
        CFRelease(value);
    }
    
    if (CFURLCopyResourcePropertyForKey(url, kCFURLVolumeTotalCapacityKey, &value, NULL)) {
        int64_t avail = 0;
        CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &avail);
        printf("Total Capacity: %.1f GB\n", (double)avail / 1e9);
        CFRelease(value);
    }

    CFRelease(url);
    return 0;
}
