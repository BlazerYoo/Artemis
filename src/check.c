//
// check.c — Safe-to-Delete checker for Artemis
//
// Checks a user-specified file across four layers:
//   1. Open process handles  (libproc — in-process, no subprocess)
//   2. Hardlink count        (lstat st_nlink)
//   3. Spotlight references  (MDQueryCreate — CoreServices, same engine as mdfind
//                             but called directly for zero subprocess overhead)
//   4. Mach-O type detection (raw header parse — detects shared libraries)
//

#include "check.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>

// libproc: in-process file-handle enumeration (what lsof uses internally)
#include <libproc.h>
#include <sys/proc_info.h>

// CoreServices: Spotlight MDQuery (same engine as mdfind, no subprocess)
#include <CoreServices/CoreServices.h>

// Mach-O headers for binary type detection
#include <mach-o/loader.h>
#include <mach-o/fat.h>

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Expand leading ~ to $HOME.
static void expand_tilde(const char *input, char *out, size_t out_size) {
    if (input[0] == '~' && (input[1] == '/' || input[1] == '\0')) {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(out, out_size, "%s%s", home, input + 1);
            return;
        }
    }
    strncpy(out, input, out_size - 1);
    out[out_size - 1] = '\0';
}

// Human-readable size, base-10 (matches report.c style).
static void fmt_size(int64_t bytes, char *buf, size_t buf_size) {
    const char *units[] = { "B", "KB", "MB", "GB", "TB" };
    double size = (double)(bytes < 0 ? 0 : bytes);
    int unit = 0;
    while (size >= 1000.0 && unit < 4) { size /= 1000.0; unit++; }
    if (unit == 0)
        snprintf(buf, buf_size, "%lld B", (long long)bytes);
    else
        snprintf(buf, buf_size, "%.1f %s", size, units[unit]);
}

// ---------------------------------------------------------------------------
// Check 1: lstat — basic file info, hardlinks, symlink status
// ---------------------------------------------------------------------------
static void gather_file_info(const char *expanded, SafeCheckResult *r) {
    struct stat lst;
    if (lstat(expanded, &lst) != 0) {
        r->exists = false;
        return;
    }

    r->exists      = true;
    r->nlink       = (uint32_t)lst.st_nlink;
    r->size_bytes  = (int64_t)lst.st_size;
    r->is_dir      = S_ISDIR(lst.st_mode);
    r->is_symlink  = S_ISLNK(lst.st_mode);

    if (r->is_symlink) {
        ssize_t len = readlink(expanded, r->symlink_target, MAXPATHLEN - 1);
        if (len > 0) r->symlink_target[len] = '\0';
        // Follow the link to check whether its target exists
        struct stat tst;
        r->symlink_target_missing = (stat(expanded, &tst) != 0);
    }

    // Resolve to canonical path for use in process-handle comparison
    if (realpath(expanded, r->resolved_path) == NULL)
        strncpy(r->resolved_path, expanded, MAXPATHLEN - 1);

    // Quick app-bundle heuristic: is this path inside a .app?
    r->is_in_app_bundle = (strstr(r->resolved_path, ".app/") != NULL);
}

// ---------------------------------------------------------------------------
// Infrastructure process classifier
//
// These daemons hold file descriptors as a side-effect of their role
// (VM filesystem serving, Spotlight indexing, iCloud sync, backup, etc.).
// Having one of these open a file does NOT mean a user application is using
// it — it is a false positive for "is this file in use?".
// ---------------------------------------------------------------------------
static const char *INFRA_PREFIXES[] = {
    "com.apple.Virtualization",  // Apple Virtualization.framework (Docker, UTM…)
    "com.apple.virtio",          // virtio drivers inside Virtualization.framework
    "mds",                       // Spotlight metadata server
    "mdworker",                  // Spotlight indexing worker
    "fseventsd",                 // FSEvents daemon
    "backupd",                   // Time Machine
    "bird",                      // iCloud Drive
    "revisiond",                 // Document Revisions daemon
    "kernel_task",               // kernel
    NULL
};

static bool is_infra_process(const char *name) {
    for (int i = 0; INFRA_PREFIXES[i]; i++) {
        if (strncmp(name, INFRA_PREFIXES[i],
                    strlen(INFRA_PREFIXES[i])) == 0)
            return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Check 2: libproc — scan every process's open file descriptors
//
// proc_listpids()  -> list of all PIDs
// proc_pidinfo()   -> PROC_PIDLISTFDS: list of fd structs for one PID
// proc_pidfdinfo() -> PROC_PIDFDVNODEPATHINFO: resolved vnode path for one fd
//
// Permission note: we silently skip PIDs we can't inspect (EPERM).
// ---------------------------------------------------------------------------
static void check_open_handles(SafeCheckResult *r) {
    if (!r->exists) return;

    int pid_buf_size = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (pid_buf_size <= 0) return;

    pid_t *pids = malloc((size_t)pid_buf_size + sizeof(pid_t));
    if (!pids) return;

    int npids = proc_listpids(PROC_ALL_PIDS, 0, pids,
                              pid_buf_size) / (int)sizeof(pid_t);

    for (int i = 0; i < npids && r->open_proc_count < CHECK_MAX_PROCS; i++) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;

        int fdbuf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fdbuf_size <= 0) continue;

        struct proc_fdinfo *fds = malloc((size_t)fdbuf_size +
                                         sizeof(struct proc_fdinfo));
        if (!fds) continue;

        int nfds = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds,
                                fdbuf_size) / (int)sizeof(struct proc_fdinfo);

        for (int j = 0; j < nfds; j++) {
            if (fds[j].proc_fdtype != PROX_FDTYPE_VNODE) continue;

            struct vnode_fdinfowithpath vinfo;
            int ret = proc_pidfdinfo(pid, fds[j].proc_fd,
                                     PROC_PIDFDVNODEPATHINFO,
                                     &vinfo, sizeof(vinfo));
            if (ret < (int)sizeof(struct vnode_fdinfowithpath)) continue;

            if (strcmp(vinfo.pvip.vip_path, r->resolved_path) != 0) continue;

            // Match — record process name and classify
            struct proc_bsdinfo bsdinfo;
            int idx = r->open_proc_count;
            if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0,
                             &bsdinfo, sizeof(bsdinfo)) > 0) {
                strncpy(r->open_proc_names[idx], bsdinfo.pbi_name, 255);
                r->open_proc_names[idx][255] = '\0';
            } else {
                snprintf(r->open_proc_names[idx], 256, "<pid %d>", (int)pid);
            }
            r->open_proc_pids[idx]    = (int)pid;
            r->open_proc_is_infra[idx] = is_infra_process(r->open_proc_names[idx]);
            if (!r->open_proc_is_infra[idx])
                r->open_user_proc_count++;
            r->open_proc_count++;
            break; // one entry per process
        }
        free(fds);
    }
    free(pids);
}

// ---------------------------------------------------------------------------
// Check 3: Spotlight content search via MDQueryCreate
//
// MDQueryCreate is the same engine mdfind uses, called directly here to avoid
// any subprocess overhead. We request kMDItemPath as a value attribute so we
// can retrieve file paths from results without a second lookup.
//
// Query: kMDItemTextContent == "full/resolved/path"c
//   -> finds every file whose indexed text content contains the path string.
//   -> catches shell scripts, Makefiles, plists, JSON/YAML configs, etc.
//
// We also check MDItemCreate for the file itself to detect if it is excluded
// from the Spotlight index (e.g. in a Privacy preference exclusion).
// ---------------------------------------------------------------------------
static void check_spotlight_refs(SafeCheckResult *r) {
    if (!r->exists) return;

    CFStringRef path_cf = CFStringCreateWithCString(
        NULL, r->resolved_path, kCFStringEncodingUTF8);
    if (!path_cf) return;

    // Is this file itself in the Spotlight index?
    MDItemRef self_item = MDItemCreate(NULL, path_cf);
    r->spotlight_not_indexed = (self_item == NULL);
    if (self_item) CFRelease(self_item);

    // Build query string — escape any embedded double-quotes in path
    CFMutableStringRef esc = CFStringCreateMutableCopy(NULL, 0, path_cf);
    CFRelease(path_cf);
    if (!esc) return;

    CFStringFindAndReplace(esc, CFSTR("\""), CFSTR("\\\""),
                           CFRangeMake(0, CFStringGetLength(esc)), 0);

    // kMDItemTextContent == "..." searches file *contents* for the string.
    // The trailing 'c' modifier makes the match case-insensitive.
    CFStringRef query_str = CFStringCreateWithFormat(
        NULL, NULL, CFSTR("kMDItemTextContent == \"%@\"c"), esc);
    CFRelease(esc);
    if (!query_str) return;

    // Request kMDItemPath as a fetchable value attribute
    CFStringRef val_attrs[] = { kMDItemPath };
    CFArrayRef val_list = CFArrayCreate(
        NULL, (const void **)val_attrs, 1, &kCFTypeArrayCallBacks);

    MDQueryRef query = MDQueryCreate(NULL, query_str, val_list, NULL);
    CFRelease(query_str);
    CFRelease(val_list);
    if (!query) return;

    // kMDQuerySynchronous: blocks until index search completes (~50–500 ms).
    // Does not hang — macOS guarantees a bounded search time.
    if (!MDQueryExecute(query, kMDQuerySynchronous)) {
        CFRelease(query);
        return;
    }

    CFIndex count = MDQueryGetResultCount(query);
    for (CFIndex k = 0; k < count; k++) {
        CFTypeRef ref_cf = MDQueryGetAttributeValueOfResultAtIndex(
            query, kMDItemPath, k);
        if (!ref_cf || CFGetTypeID(ref_cf) != CFStringGetTypeID()) continue;

        char ref_buf[MAXPATHLEN];
        if (!CFStringGetCString((CFStringRef)ref_cf, ref_buf,
                                MAXPATHLEN, kCFStringEncodingUTF8))
            continue;

        // Skip the target file itself
        if (strcmp(ref_buf, r->resolved_path) == 0) continue;

        if (r->spotlight_ref_count < CHECK_MAX_REFS) {
            strncpy(r->spotlight_ref_paths[r->spotlight_ref_count],
                    ref_buf, MAXPATHLEN - 1);
            r->spotlight_ref_paths[r->spotlight_ref_count][MAXPATHLEN - 1] = '\0';
            r->spotlight_ref_count++;
        } else {
            r->spotlight_overflow = true;
            break;
        }
    }

    CFRelease(query);
}

// ---------------------------------------------------------------------------
// Check 4: Protected system path
//
// Behavioral checks (open handles, Spotlight) cannot catch files that are
// dangerous to delete simply because of *what they are*, regardless of whether
// any process happens to have them open at this moment.  A keychain file, for
// example, is read by securityd on-demand — it may be closed right now, yet
// deleting it permanently destroys stored credentials and certificates.
//
// Two tiers:
//   CRIT — deleting will likely break macOS, security, or bootability
//   WARN — deleting may break installed software or system services
// ---------------------------------------------------------------------------
typedef struct {
    const char *prefix;
    const char *reason;
    bool        critical;
} ProtectedEntry;

// Home-directory-relative entries are handled separately (see PROTECTED_HOME_REL).
//
// CRITICAL ordering rule: more specific prefixes MUST appear before their
// parents, because the lookup returns on the first match. Two consequences:
//   1. /System/Volumes/Preboot/ must precede /System/
//   2. /Library/Application Support/com.apple.TCC/ must precede
//      /Library/Application Support/
//   3. /Library/Preferences/SystemConfiguration/ must precede
//      /Library/Preferences/
static const ProtectedEntry PROTECTED_ABS[] = {

    // ── APFS special volumes (must precede /System/) ───────────────────────
    { "/System/Volumes/Preboot/",
      "APFS Preboot volume — contains EFI boot files and the sealed system "
      "snapshot manifest; deletion makes the Mac unbootable",
      true },
    { "/System/Volumes/Recovery/",
      "macOS Recovery partition — deletion removes the ability to boot into "
      "Recovery mode, reinstall macOS, or reset passwords",
      true },

    // ── Sealed system volume (macOS Catalina+, SIP-protected) ─────────────
    { "/System/",
      "Sealed macOS system volume — SIP-protected read-only snapshot; "
      "any modification breaks the cryptographic seal and may prevent booting",
      true },

    // ── Essential Unix commands (SIP-protected under /bin, /sbin) ─────────
    { "/bin/",
      "Essential Unix commands (sh, ls, cp, mv, rm…) — SIP-protected; "
      "removal breaks shell execution and basic system operation",
      true },
    { "/sbin/",
      "Essential admin commands (fsck, mount, ifconfig, reboot…) — "
      "SIP-protected; removal breaks filesystem repair and network setup",
      true },

    // ── Core system utilities (SIP-protected under /usr) ──────────────────
    { "/usr/bin/",
      "Core system utilities — SIP-protected",
      true },
    { "/usr/sbin/",
      "Core system admin utilities — SIP-protected",
      true },
    { "/usr/lib/",
      "Core system libraries (libc, libobjc, libSystem…) — SIP-protected; "
      "removal breaks every process that dynamically links against them",
      true },
    { "/usr/libexec/",
      "Core system executables (launchd helpers, xpcproxy, notifyd…) — "
      "SIP-protected",
      true },

    // ── Device files ───────────────────────────────────────────────────────
    { "/dev/",
      "Virtual device files — deletion breaks terminal I/O, disk access, "
      "and all hardware device interfaces",
      true },

    // ── TCC privacy database (specific entry BEFORE /Library/Application Support/)
    // Stores per-app permissions for camera, microphone, contacts, location, etc.
    { "/Library/Application Support/com.apple.TCC/",
      "System TCC privacy database — stores app permissions for camera, "
      "microphone, contacts, and location; deletion resets all privacy grants",
      true },

    // ── Security, credentials, and certificates ────────────────────────────
    { "/Library/Keychains/",
      "System keychain — stores machine WiFi passwords, certificates, and "
      "private keys; deletion causes immediate credential loss",
      true },
    { "/Library/Security/",
      "System security database and root certificate trust store — "
      "deletion breaks TLS/HTTPS verification system-wide",
      true },

    // ── Apple-managed system software ─────────────────────────────────────
    { "/Library/Apple/",
      "Apple-managed system software — written only by macOS updates",
      true },

    // ── Core system configuration ──────────────────────────────────────────
    { "/private/etc/",
      "Core Unix system configuration (hosts, sudoers, pam.d, fstab, ssh…) — "
      "deletion can break login, networking, sudo, or SSH access",
      true },

    // ── System databases ───────────────────────────────────────────────────
    // Covers: dslocal (user/group accounts), dyld shared cache, launchd
    // registry, sandbox profiles, sudo cache, and the system TCC database.
    { "/private/var/db/",
      "System databases — contains user/group accounts (dslocal), dyld "
      "shared library cache, launchd registry, and sandbox profiles",
      true },

    // ── System-wide app support data ──────────────────────────────────────
    // Less specific than the TCC entry above; that entry must come first.
    { "/Library/Application Support/",
      "System-wide application support data — may contain databases, "
      "license stores, or configuration shared across all user accounts",
      false },

    // ── Audio plugins ─────────────────────────────────────────────────────
    // HAL plug-ins affect all system audio I/O; AU/VST affect DAW software.
    { "/Library/Audio/Plug-Ins/",
      "Audio plugin (HAL, Audio Units, VST…) — removal breaks audio "
      "hardware routing or music production software",
      false },

    // ── Automator actions ─────────────────────────────────────────────────
    { "/Library/Automator/",
      "Automator action bundle — removal disables the action in Automator "
      "workflows and Quick Actions",
      false },

    // ── Color management ──────────────────────────────────────────────────
    { "/Library/ColorSync/",
      "Color management profiles and plugins — removal may cause incorrect "
      "color rendering in Photos, Illustrator, Final Cut, and print workflows",
      false },

    // ── CoreAudio / CoreMIDI / QuickTime components ───────────────────────
    { "/Library/Components/",
      "CoreAudio, CoreMIDI, or QuickTime component — removal breaks audio, "
      "MIDI, or media playback for applications that depend on it",
      false },

    // ── Camera and video I/O plugins ──────────────────────────────────────
    // Includes OBS Virtual Camera, Continuity Camera, and other DAL plugins.
    { "/Library/CoreMediaIO/",
      "Camera or video I/O plugin (DAL) — removal disables a virtual camera "
      "source (e.g. OBS Virtual Camera, Continuity Camera)",
      false },

    // ── Directory service plugins ─────────────────────────────────────────
    { "/Library/DirectoryServices/",
      "Directory service plugin — may be required for network authentication "
      "(Active Directory, LDAP) or local account management",
      false },

    // ── Kernel extensions ─────────────────────────────────────────────────
    { "/Library/Extensions/",
      "Third-party kernel extension (kext) — may provide hardware drivers, "
      "VPN functionality, or security software at kernel level",
      false },

    // ── Filesystem plugins ────────────────────────────────────────────────
    { "/Library/Filesystems/",
      "Filesystem plugin (FUSE, NTFS-3G, etc.) — removal disables mounting "
      "of a specific filesystem type",
      false },

    // ── Fonts ─────────────────────────────────────────────────────────────
    { "/Library/Fonts/",
      "System-wide font — removal may cause missing-font issues in documents "
      "and applications that reference it by name",
      false },

    // ── Third-party frameworks ────────────────────────────────────────────
    { "/Library/Frameworks/",
      "Installed framework — one or more installed applications may link "
      "against it at runtime",
      false },

    // ── GPU driver bundles ────────────────────────────────────────────────
    { "/Library/GPUBundles/",
      "GPU driver bundle — removal may break Metal, OpenGL, or OpenCL for a "
      "specific GPU model",
      false },

    // ── Input methods ─────────────────────────────────────────────────────
    { "/Library/Input Methods/",
      "Input method plugin — removal disables a keyboard or IME input method "
      "for all users",
      false },
    { "/Library/InputManagers/",
      "Legacy input manager plugin — may be required by older applications",
      false },

    // ── Browser plugins ───────────────────────────────────────────────────
    { "/Library/Internet Plug-Ins/",
      "Browser plugin (NPAPI/legacy) — removal disables in-browser rendering "
      "for specific content types",
      false },

    // ── Launch daemons and agents ─────────────────────────────────────────
    { "/Library/LaunchAgents/",
      "System launch agent — removal stops a per-login background service",
      false },
    { "/Library/LaunchDaemons/",
      "System launch daemon — removal stops a system-level service at boot",
      false },

    // ── OpenDirectory / authentication plugins ────────────────────────────
    { "/Library/OpenDirectory/",
      "OpenDirectory module — may be required for user authentication or "
      "network directory service integration",
      false },

    // ── Preference panes ──────────────────────────────────────────────────
    { "/Library/PreferencePanes/",
      "System Preferences/Settings panel — removal removes a pane from "
      "System Settings",
      false },

    // ── System preferences (network config must precede general prefs) ─────
    { "/Library/Preferences/SystemConfiguration/",
      "Network configuration (interfaces, DNS, Wi-Fi ordering, proxies) — "
      "deletion resets all network settings for all users",
      false },
    { "/Library/Preferences/",
      "System-wide application preferences — may store system-level or "
      "multi-user configuration for installed software",
      false },

    // ── Printer drivers ───────────────────────────────────────────────────
    { "/Library/Printers/",
      "Printer driver or PPD — removal breaks printing for a specific device",
      false },

    // ── Privileged helper tools ───────────────────────────────────────────
    { "/Library/PrivilegedHelperTools/",
      "Privileged helper tool (SMJobBless) — runs with elevated permissions "
      "on behalf of an installed application",
      false },

    // ── QuickLook generators ──────────────────────────────────────────────
    { "/Library/QuickLook/",
      "QuickLook generator plugin — removal disables Finder thumbnail and "
      "preview for a specific file type",
      false },

    // ── AppleScript additions ─────────────────────────────────────────────
    { "/Library/ScriptingAdditions/",
      "AppleScript scripting addition — removal disables specific AppleScript "
      "commands for all applications system-wide",
      false },

    // ── Homebrew on Apple Silicon ─────────────────────────────────────────
    { "/opt/homebrew/",
      "Homebrew package manager installation — removal uninstalls tools and "
      "libraries that scripts and applications may depend on",
      false },

    // ── Root home directory ───────────────────────────────────────────────
    { "/private/var/root/",
      "Root user home directory — may contain root SSH authorized_keys, "
      "shell configuration, or credentials",
      false },

    // ── Runtime PID files and Unix domain sockets ─────────────────────────
    { "/private/var/run/",
      "Runtime PID files and Unix domain sockets — deleting these while "
      "services are running can prevent process management and IPC",
      false },

    // ── User-installed tools and libraries (Homebrew/MacPorts on Intel) ───
    { "/usr/local/Frameworks/",
      "User-installed frameworks under /usr/local — applications may link "
      "against these at runtime",
      false },
    { "/usr/local/bin/",
      "User-installed binaries (Homebrew/MacPorts) — scripts and applications "
      "may invoke these tools directly",
      false },
    { "/usr/local/lib/",
      "User-installed libraries (Homebrew/MacPorts) — applications may "
      "dynamically link against these at runtime",
      false },
    { "/usr/local/sbin/",
      "User-installed admin tools (Homebrew/MacPorts)",
      false },

    { NULL, NULL, false }
};

// Home-directory-relative protected paths (expanded with $HOME at runtime).
//
// CRITICAL ordering rule: more specific paths MUST appear before their parents.
//   /Library/Application Support/com.apple.TCC/ (CRIT) must precede
//   /Library/Application Support/ (WARN).
static const ProtectedEntry PROTECTED_HOME_REL[] = {

    // ── TCC user privacy database (BEFORE /Library/Application Support/) ──
    { "/Library/Application Support/com.apple.TCC/",
      "User TCC privacy database — stores per-app permissions for camera, "
      "microphone, contacts, and location; deletion resets all privacy grants",
      true },

    // ── User keychain ─────────────────────────────────────────────────────
    { "/Library/Keychains/",
      "Login keychain — contains all saved passwords, app credentials, and "
      "certificates; deletion causes permanent and unrecoverable data loss",
      true },

    // ── Cryptographic keys ────────────────────────────────────────────────
    { "/.ssh/",
      "SSH keys and config — deletion may permanently lock you out of remote "
      "servers if no backup of the private key exists",
      true },
    { "/.gnupg/",
      "GPG keyring and trust database — deletion permanently destroys your "
      "GPG identity and any data encrypted to those keys",
      true },

    // ── Internet account credentials ──────────────────────────────────────
    { "/Library/Accounts/",
      "Internet account data (iCloud, Google, Exchange…) — deletion requires "
      "re-adding all accounts in System Settings",
      false },

    // ── App support data (BEFORE general /Library/Application Support/) ───
    // /Library/Containers/ holds all Mac App Store sandboxed app data:
    // documents, databases, game saves — all isolated per-app.
    { "/Library/Containers/",
      "Mac App Store sandbox containers — each folder is the complete data "
      "store for a sandboxed app; deletion permanently destroys app data",
      false },

    // ── General app support (less specific — after Containers and TCC) ────
    { "/Library/Application Support/",
      "Application support data — may contain app databases, game saves, "
      "license files, or configuration that cannot be recovered",
      false },

    // ── Personal data that may not be in iCloud ───────────────────────────
    { "/Library/Calendars/",
      "Calendar database — may contain locally-stored events not synced "
      "to iCloud or any other calendar service",
      false },
    { "/Library/Contacts/",
      "Contacts database — may contain locally-stored contacts not synced "
      "to iCloud or any other service",
      false },
    { "/Library/Mail/",
      "Mail message store and account data — locally-downloaded email may "
      "not exist on the server and cannot be recovered after deletion",
      false },
    { "/Library/Messages/",
      "iMessage and SMS history database — deletion permanently removes all "
      "message history if not backed up to iCloud",
      false },
    { "/Library/Safari/",
      "Safari data (bookmarks, Reading List, history) — bookmarks are not "
      "always recoverable from iCloud after deletion",
      false },

    // ── HomeKit local database ────────────────────────────────────────────
    { "/Library/HomeKit/",
      "HomeKit local database — may contain automations and scenes not fully "
      "replicated to iCloud; deletion can lose home configuration",
      false },

    // ── User launch agents ────────────────────────────────────────────────
    { "/Library/LaunchAgents/",
      "User launch agent — removal stops a per-user background service at "
      "next login",
      false },

    // ── App preferences ───────────────────────────────────────────────────
    { "/Library/Preferences/",
      "Application preferences (.plist files) — deletion resets apps to "
      "factory defaults; license activation data may be stored here",
      false },

    { NULL, NULL, false }
};

static void check_protected_path(SafeCheckResult *r) {
    if (!r->exists) return;

    const char *p = r->resolved_path;

    // Check absolute protected paths
    for (int i = 0; PROTECTED_ABS[i].prefix; i++) {
        size_t len = strlen(PROTECTED_ABS[i].prefix);
        if (strncmp(p, PROTECTED_ABS[i].prefix, len) == 0) {
            r->is_protected        = true;
            r->protected_is_critical = PROTECTED_ABS[i].critical;
            strncpy(r->protected_reason, PROTECTED_ABS[i].reason,
                    sizeof(r->protected_reason) - 1);
            return;
        }
    }

    // Check home-directory-relative protected paths
    const char *home = getenv("HOME");
    if (!home) return;
    size_t home_len = strlen(home);

    for (int i = 0; PROTECTED_HOME_REL[i].prefix; i++) {
        char full[MAXPATHLEN];
        snprintf(full, sizeof(full), "%s%s", home, PROTECTED_HOME_REL[i].prefix);
        size_t full_len = home_len + strlen(PROTECTED_HOME_REL[i].prefix);
        if (strncmp(p, full, full_len) == 0) {
            r->is_protected        = true;
            r->protected_is_critical = PROTECTED_HOME_REL[i].critical;
            strncpy(r->protected_reason, PROTECTED_HOME_REL[i].reason,
                    sizeof(r->protected_reason) - 1);
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Check 5: Mach-O type detection
//
// Reads the first few bytes of the file to identify Mach-O magic numbers and,
// for single-arch binaries, the filetype field to detect shared libraries.
// Fat (universal) binaries are marked as Mach-O; we inspect the first slice.
// ---------------------------------------------------------------------------
static void check_macho_type(SafeCheckResult *r) {
    if (!r->exists || r->is_dir || r->is_symlink) return;
    if (r->size_bytes < 8) return;

    int fd = open(r->resolved_path, O_RDONLY);
    if (fd < 0) return;

    uint32_t magic = 0;
    if (read(fd, &magic, sizeof(magic)) < (ssize_t)sizeof(magic)) {
        close(fd);
        return;
    }

    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        r->is_macho = true;
        lseek(fd, 0, SEEK_SET);
        struct mach_header_64 mh;
        if (read(fd, &mh, sizeof(mh)) == sizeof(mh)) {
            uint32_t ft = (magic == MH_CIGAM_64)
                          ? __builtin_bswap32(mh.filetype) : mh.filetype;
            r->is_dylib = (ft == MH_DYLIB || ft == MH_DYLIB_STUB);
        }
    } else if (magic == MH_MAGIC || magic == MH_CIGAM) {
        r->is_macho = true;
        lseek(fd, 0, SEEK_SET);
        struct mach_header mh;
        if (read(fd, &mh, sizeof(mh)) == sizeof(mh)) {
            uint32_t ft = (magic == MH_CIGAM)
                          ? __builtin_bswap32(mh.filetype) : mh.filetype;
            r->is_dylib = (ft == MH_DYLIB || ft == MH_DYLIB_STUB);
        }
    } else if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        // Universal binary — inspect first architecture slice
        r->is_macho = true;
        lseek(fd, 0, SEEK_SET);
        struct fat_header fh;
        if (read(fd, &fh, sizeof(fh)) == sizeof(fh)) {
            uint32_t narch = (magic == FAT_CIGAM)
                             ? __builtin_bswap32(fh.nfat_arch) : fh.nfat_arch;
            if (narch > 0) {
                struct fat_arch fa;
                if (read(fd, &fa, sizeof(fa)) == sizeof(fa)) {
                    uint32_t off = (magic == FAT_CIGAM)
                                   ? __builtin_bswap32(fa.offset) : fa.offset;
                    lseek(fd, (off_t)off, SEEK_SET);
                    uint32_t slice_magic = 0;
                    struct mach_header_64 mh;
                    if (read(fd, &mh, sizeof(mh)) == sizeof(mh)) {
                        slice_magic = mh.magic;
                        uint32_t ft = mh.filetype;
                        if (slice_magic == MH_CIGAM_64)
                            ft = __builtin_bswap32(ft);
                        if (slice_magic == MH_MAGIC_64 ||
                            slice_magic == MH_CIGAM_64) {
                            r->is_dylib = (ft == MH_DYLIB ||
                                           ft == MH_DYLIB_STUB);
                        }
                    }
                }
            }
        }
    }

    close(fd);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void check_safe_to_delete(const char *path, SafeCheckResult *r) {
    memset(r, 0, sizeof(*r));

    char expanded[MAXPATHLEN];
    expand_tilde(path, expanded, sizeof(expanded));
    strncpy(r->input_path, path, MAXPATHLEN - 1);

    gather_file_info(expanded, r);
    if (!r->exists) return;

    check_protected_path(r);
    check_open_handles(r);
    check_spotlight_refs(r);
    check_macho_type(r);
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

void report_safe_to_delete(const SafeCheckResult *r) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("                   ARTEMIS SAFETY CHECK\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    if (!r->exists) {
        printf("  ERROR: path not found: %s\n\n", r->input_path);
        return;
    }

    // ── File info header ────────────────────────────────────────────────────
    char size_buf[64];
    fmt_size(r->size_bytes, size_buf, sizeof(size_buf));

    printf("  File:  %s\n", r->input_path);
    if (strcmp(r->input_path, r->resolved_path) != 0)
        printf("  Real:  %s\n", r->resolved_path);
    printf("  Size:  %s\n", size_buf);

    if (r->is_symlink) {
        printf("  Type:  Symbolic link → %s%s\n",
               r->symlink_target,
               r->symlink_target_missing ? "  [TARGET MISSING]" : "");
    } else if (r->is_dylib) {
        printf("  Type:  Mach-O Dynamic Library\n");
    } else if (r->is_macho) {
        printf("  Type:  Mach-O Binary\n");
    } else if (r->is_dir) {
        printf("  Type:  Directory\n");
    } else {
        printf("  Type:  Regular file\n");
    }
    if (r->is_in_app_bundle)
        printf("  Note:  Inside an app bundle (.app)\n");
    printf("\n");

    // ── Checks ──────────────────────────────────────────────────────────────
    int warnings = 0;
    int dangers  = 0;

    printf("  ┌─ SAFETY CHECKS ──────────────────────────────────────────\n");

    // [0] Protected system path
    if (r->is_protected) {
        if (r->protected_is_critical) {
            printf("  │ [CRIT] Protected system location:\n");
            printf("  │          %s\n", r->protected_reason);
            dangers++;
        } else {
            printf("  │ [WARN] Sensitive system location:\n");
            printf("  │          %s\n", r->protected_reason);
            warnings++;
        }
    }

    // [1] Open handles — split user processes (CRIT) from infra daemons (INFO)
    if (r->open_proc_count == 0) {
        printf("  │ [ OK ] Not open by any running process\n");
    } else {
        // User applications — dangerous to delete while open
        if (r->open_user_proc_count > 0) {
            printf("  │ [CRIT] Open by %d user process%s:\n",
                   r->open_user_proc_count,
                   r->open_user_proc_count == 1 ? "" : "es");
            for (int i = 0; i < r->open_proc_count; i++) {
                if (!r->open_proc_is_infra[i])
                    printf("  │          → %s  (pid %d)\n",
                           r->open_proc_names[i], r->open_proc_pids[i]);
            }
            dangers++;
        }
        // System/virtualization/indexing daemons — informational only
        int infra_count = r->open_proc_count - r->open_user_proc_count;
        if (infra_count > 0) {
            printf("  │ [INFO] Held by %d system daemon%s (not a user app):\n",
                   infra_count, infra_count == 1 ? "" : "s");
            for (int i = 0; i < r->open_proc_count; i++) {
                if (r->open_proc_is_infra[i])
                    printf("  │          → %s  (pid %d)\n",
                           r->open_proc_names[i], r->open_proc_pids[i]);
            }
            if (r->open_user_proc_count == 0)
                printf("  │          (virtualization/indexing/backup — safe to ignore)\n");
        }
    }

    // [2] Hardlinks
    if (r->nlink <= 1) {
        printf("  │ [ OK ] Single directory entry (no extra hardlinks)\n");
    } else {
        // nlink includes this entry itself; other links = nlink - 1
        uint32_t other = r->nlink - 1;
        printf("  │ [WARN] %u other hardlink%s share this inode\n",
               other, other == 1 ? "" : "s");
        printf("  │          Data survives until all hardlinks are removed\n");
        warnings++;
    }

    // [3] Broken symlink self-check
    if (r->is_symlink && r->symlink_target_missing) {
        printf("  │ [WARN] Symlink target does not exist (broken link)\n");
        warnings++;
    }

    // [4] App bundle membership
    if (r->is_in_app_bundle) {
        printf("  │ [WARN] File is inside an app bundle — deleting it may\n");
        printf("  │          corrupt or crash the application\n");
        warnings++;
    }

    // [5] Spotlight content references
    if (r->spotlight_ref_count == 0) {
        if (r->spotlight_not_indexed) {
            printf("  │ [ OK ] File is outside Spotlight index\n");
            printf("  │          (manually verify scripts/configs referencing it)\n");
        } else {
            printf("  │ [ OK ] No indexed files reference this path\n");
        }
    } else {
        printf("  │ [WARN] %d file%s reference this path in their content%s:\n",
               r->spotlight_ref_count,
               r->spotlight_ref_count == 1 ? "" : "s",
               r->spotlight_overflow ? " (showing first 12)" : "");
        for (int i = 0; i < r->spotlight_ref_count; i++)
            printf("  │          → %s\n", r->spotlight_ref_paths[i]);
        warnings++;
    }

    // [6] Mach-O shared library
    if (r->is_dylib) {
        const char *basename = strrchr(r->resolved_path, '/');
        basename = basename ? basename + 1 : r->resolved_path;
        printf("  │ [WARN] Mach-O shared library — other binaries may link it\n");
        printf("  │          Verify: otool -L <binary> | grep '%s'\n", basename);
        warnings++;
    }

    printf("  └──────────────────────────────────────────────────────────\n\n");

    // ── Verdict ─────────────────────────────────────────────────────────────
    printf("  ┌─ VERDICT ────────────────────────────────────────────────\n");
    if (dangers > 0) {
        printf("  │ [CRIT] NOT SAFE — %d critical issue%s found\n",
               dangers, dangers == 1 ? "" : "s");
        if (r->open_user_proc_count > 0)
            printf("  │        Close the owning process before deleting\n");
    } else if (warnings > 0) {
        printf("  │ [WARN] REVIEW FIRST — %d warning%s found\n",
               warnings, warnings == 1 ? "" : "s");
    } else {
        printf("  │ [ OK ] SAFE TO DELETE — no issues found\n");
    }
    printf("  └──────────────────────────────────────────────────────────\n\n");
}
