/* passwdprobe -- the in-kernel ramfs is not reachable from ring 3 (PASSWD_PROBE)
 *
 * Runs as uid 1000, the ordinary "user" account, endowed with NOTHING beyond
 * what create_task hands every task: no CAP_USER, no CAP_ENCRYPTED_STORAGE, no
 * capability anyone delegated to it.
 *
 * WHAT THIS EXISTS TO REFUSE. Until 2026-08-22 four paths into the in-kernel
 * ramfs authorised on cspace slot 3 with SC_ANYTYPE:
 *
 *     [SYS_OPEN] = { h_open,         3, CAP_RIGHT_READ,  SC_ANYTYPE }
 *     [15]       = { h_ramfs_create, 3, CAP_RIGHT_WRITE, SC_ANYTYPE }
 *     [16]       = { h_fs_list,      3, CAP_RIGHT_READ,  SC_ANYTYPE }
 *     h_read, fd >= 3: cap_lookup(3, CAP_RIGHT_READ) inline
 *
 * Slot 3 holds the legacy CAP_FRAME that create_task installs in every task --
 * READ|WRITE|EXEC, naming a fixed window, asked for by nobody. It is the same
 * capability that made [C-1] reachable when the dispatch table gated IPC on
 * slot 3, and these four were the last gates still satisfied by it. A gate
 * every task passes is not a gate.
 *
 * WHAT WAS BEHIND IT, AND WHY IT NO LONGER IS. kusers.c used to write the user
 * database into this ramfs as the file "passwd", every record carrying salt[16]
 * and pass_hash[32]. This probe read that file as an ordinary user and got 32
 * bytes -- not the hashes, because ramfs_write took no offset and only the last
 * of four writes survived. The hashes were one bug-fix away from being
 * world-readable.
 *
 * That whole path was deleted on 2026-08-22: it had never worked, and could not
 * have, because the password pepper is re-randomised every boot so a stored hash
 * can never verify in the next boot. So the data behind these gates is gone and
 * the probe now opens an ordinary seeded file instead.
 *
 * The gate stays, and S28 is unchanged, because the property was never about
 * what happened to be stored there: a gate satisfied by a capability every task
 * already holds is not a gate, whatever sits behind it.
 *
 * Falsified by RAMFS_SLOT3_GATE=1, which restores the four slot-3 gates.
 */
#include "syscall.h"
#include "libhorus.h"

#define SYS_RAMFS_CREATE 15
#define SYS_FS_LIST      16

static int checks;
static int failures;

static void check(int ok, const char *what) {
    if (ok) { checks++; return; }
    kput("PASSWDPROBE: FAIL ");
    kput(what);
    kput("\n");
    failures++;
}

void _start(void) {
    kputln("PASSWDPROBE: begin (uid 1000, no capabilities beyond a fresh task's)");

    /* Open a file the store is seeded with.
     *
     * This used to open "passwd", the file kusers.c wrote the user database
     * into -- and that was the sharper demonstration. It is deliberately no
     * longer available: the user-database save/load pair was deleted
     * 2026-08-22 as code that had never run (see kusers.c), so nothing writes
     * "passwd" any more and a check against it would pass TRIVIALLY IN BOTH
     * ARMS -- a required gate silently measuring nothing.
     *
     * So it targets a file the control build's ramfs_init actually seeds. The
     * property under test is unchanged and was never about the file's contents:
     * an unendowed ring-3 task must not reach the in-kernel store at all. */
    int fd = sys_open("hello.txt");
    kput("PASSWDPROBE: sys_open(\"hello.txt\") -> "); kput_int(fd); kputln("");
    check(fd < 0, "opened-a-ramfs-file");

    /* fd numbering is `3 + index`, so sweep the range directly rather than
     * letting a refusal on open hide an open door on read. */
    static unsigned char buf[64];
    int leaked = 0;
    for (int f = 3; f < 11; f++) {
        int n = sys_read(f, buf, sizeof(buf));
        if (n > 0) { leaked = 1; kput("PASSWDPROBE: sys_read(fd="); kput_int(f);
                     kput(") returned "); kput_int(n); kputln(" bytes"); }
    }
    check(!leaked, "read-bytes-out-of-the-in-kernel-ramfs");

    int crc = (int)syscall(SYS_RAMFS_CREATE,
                           (uint64_t)(uintptr_t)"probefile", 0, 0);
    kput("PASSWDPROBE: ramfs_create -> "); kput_int(crc); kputln("");
    check(crc < 0, "created-a-file-in-the-in-kernel-ramfs");

    static char listing[128];
    int lrc = (int)syscall(SYS_FS_LIST, (uint64_t)(uintptr_t)listing,
                           (uint32_t)sizeof(listing), 0);
    kput("PASSWDPROBE: fs_list -> "); kput_int(lrc); kputln("");
    if (lrc > 0) {
        /* Name what is in there. h_fs_list NUL-terminates within the size it is
         * given, and the point of printing it is that the finding should say
         * WHICH files an unprivileged task can enumerate rather than how many. */
        listing[sizeof(listing) - 1] = 0;
        kput("PASSWDPROBE: store contains: "); kput(listing); kputln("");
    }
    check(lrc <= 0, "listed-the-in-kernel-ramfs");

    if (failures) {
        kput("PASSWDPROBE: FAIL ");
        kput_int(failures);
        kputln(" of 4 doors open");
    } else {
        kput("PASSWDPROBE: PASS ");
        kput_int(checks);
        kputln(" checks - the in-kernel ramfs is unreachable from ring 3");
    }
    for (;;) sys_yield();
}
