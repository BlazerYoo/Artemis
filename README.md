# Artemis

A high-performance disk space analyzer for macOS, built in C and optimized for Apple Silicon.

Artemis scans your entire filesystem in seconds using Apple's `getattrlistbulk()` bulk metadata API, then reports the largest directories, files, and cleanup opportunities — no GUI, no Electron, no nonsense.

```
$ ./artemis

Scanning /System/Volumes/Data ...
  Threads: 8 (P-cores)
  Scanned 2,847,321 entries in 4.12s

── Top Directories by Size ──────────────────────
  1.  48.2 GB  ~/Library/Developer/Xcode/DerivedData
  2.  31.7 GB  ~/Library/Caches
  3.  22.1 GB  ~/Documents/VMs
  ...

── Cleanup Opportunities ────────────────────────
  Xcode DerivedData     48.2 GB
  Homebrew Cache         6.1 GB
  npm Cache              3.4 GB
  Trash                  1.8 GB
```

## Features

- **Fast** — Full disk scan in 3–8 seconds on Apple Silicon (millions of files)
- **Accurate** — Base-10 sizes matching Finder and "About This Mac"
- **Hardlink-aware** — Deduplicates hardlinked files so nothing is double-counted
- **Cleanup detection** — Identifies reclaimable space (Xcode, Homebrew, npm, Yarn, caches, logs, Trash)
- **Safe** — Never follows symlinks, skips virtual filesystems, checks for Full Disk Access before scanning
- **Minimal** — ~70KB binary, zero runtime dependencies, pure C

## Requirements

- macOS 10.13+
- Clang or GCC with C11 support
- **Full Disk Access** permission (System Settings → Privacy & Security → Full Disk Access → add your terminal)

## Building

```bash
make          # Release build (-O3, LTO, native CPU targeting)
make debug    # Debug build with AddressSanitizer
make clean
```

## Usage

```
artemis [OPTIONS] [PATH]

Options:
  -n NUM    Number of top entries to show (default: 20)
  -v        Verbose output
  -h        Show help
```

PATH defaults to `/System/Volumes/Data` (the APFS Data volume).

```bash
./artemis                        # Scan entire Data volume
./artemis -n 30 -v               # Top 30 entries, verbose
./artemis ~/Documents -n 10      # Scan a specific directory
```

## How It Works

Artemis uses a two-phase architecture designed around the macOS I/O stack:

### Phase A: Parallel Scan

- Detects P-core count and spawns one worker thread per P-core at `QOS_CLASS_USER_INITIATED`
- Each thread pulls directories from a shared work queue and scans them using `getattrlistbulk()`, which returns metadata for hundreds of entries in a single kernel call
- Thread-local arena allocators (virtual memory bump allocation) eliminate all `malloc`/`free` in the hot loop
- Flat `ScanRecord` arrays — no cross-thread writes, no locks on the data path

### Phase B: Tree Construction

- Single-threaded pass over all records to build a directory tree using inode-keyed hash maps
- Hardlinks deduplicated via global inode set
- Post-order traversal rolls up directory sizes

The bottleneck is APFS metadata read latency from SSD — not CPU, memory allocation, or lock contention.

## Project Structure

```
src/
├── main.c        Entry point, argument parsing, progress display
├── scanner.c/h   getattrlistbulk() directory scanning
├── threads.c/h   P-core targeted thread pool
├── workqueue.c/h Thread-safe work queue (mutex + condvar)
├── arena.c/h     Virtual memory bump allocator
├── tree.c/h      Tree reconstruction & hardlink dedup
├── report.c/h    Output formatting & cleanup detection
├── safety.c/h    Full Disk Access checks, mount validation
└── types.h       Core data structures
vendor/
├── khash.h       Hash map (klib)
└── xxhash.h      Fast hashing
```

## Contributing

Contributions are welcome! Some areas where help is appreciated:

- **Intel Mac testing** — The core logic is portable but performance tuning targets Apple Silicon
- **New cleanup categories** — Adding detection for more reclaimable disk space (Docker, CocoaPods, etc.)
- **Output formats** — JSON output, machine-readable modes
- **Tests** — Unit and integration test coverage

Please open an issue before starting significant work so we can discuss the approach.

## License

MIT
