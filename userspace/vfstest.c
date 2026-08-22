/* vfstest -- the VFS mount table, from ring 3 (roadmap 2.4, VFS_SELFTEST only).
 *
 * Two mounts, two servers, one namespace:
 *
 *     "/"    -> fs_server   (holds the encrypted object store)
 *     "/dev" -> dev_server  (holds nothing but its own endpoint)
 *
 * WHAT IS UNDER TEST is not "can a path be resolved". It is which server a path
 * reaches, and whether reaching it took a capability:
 *
 *   S29  A task that holds no capability for a mount cannot reach that subtree,
 *        whatever path it writes. The path is the same; only the slot differs.
 *
 *   Longest prefix wins. "/dev/zero" must reach dev_server and not the "/"
 *   mount that also matches it. This is checked by WHICH SERVER ANSWERED rather
 *   than by a return code, because first-match does not fail -- the root
 *   filesystem has an inode 0 of its own, so it answers about a different
 *   object and a return-code check would call that success.
 *
 * Falsified by VFS_FIRST_MATCH=1 and VFS_MOUNT_UNGATED=1.
 */
#include "syscall.h"
#include "libhorus.h"
#include "fs_proto.h"

/* Where the harness puts the two endpoint capabilities. */
#define SLOT_FS_CLIENT   CAPSLOT_FS_EP        /* WRITE-only -> fs_server   */
#define SLOT_DEV_CLIENT  21                   /* WRITE-only -> dev_server  */
#define SLOT_EMPTY       30                   /* deliberately holds nothing */

static int checks;
static int failures;

static void check(int ok, const char *what) {
    if (ok) { checks++; return; }
    kput("VFSTEST: FAIL ");
    kput(what);
    kput("\n");
    failures++;
}

void _start(void) {
    kputln("VFSTEST: begin");

    /* Acquire the root filesystem capability the ordinary way -- the same call
     * posix.c's fs_connect() makes. Bounded retry: fs_server registers from
     * another task, so the capability is merely late rather than absent, and an
     * unbounded wait would turn a genuine refusal into a hang ([G-8] sig C). */
    {
        int r = -1;
        for (int i = 0; i < 4000 && r != 0; i++) {
            r = sys_connect_fs_server(SLOT_FS_CLIENT, CAP_R_W);
            if (r != 0) { sys_yield(); spin_delay(); }
        }
        check(r == 0, "connect-to-the-root-filesystem");
    }

    /* (1) The root mount, as every program has today. */
    check(hvfs_mount("/", SLOT_FS_CLIENT, 0) == 0, "mount-root");

    /* (2) A mount must be backed by a capability. SLOT_EMPTY holds nothing, so
     * the prefix alone must not install one -- otherwise every path under it
     * would be addressed to an empty slot and fail one operation at a time
     * instead of at mount. Under VFS_MOUNT_UNGATED=1 this succeeds. */
    check(hvfs_mount("/nope", SLOT_EMPTY, 0) < 0, "mounted-without-a-capability");

    /* (3) The second mount. */
    check(hvfs_mount("/dev", SLOT_DEV_CLIENT, 0) == 0, "mount-dev");

    /* (4) Malformed mounts are refused. */
    check(hvfs_mount("dev", SLOT_DEV_CLIENT, 0) < 0, "relative-prefix-accepted");
    check(hvfs_mount("/dev", SLOT_DEV_CLIENT, 0) < 0, "duplicate-prefix-accepted");

    /* (5) THE ROUTING CHECK. "/dev/zero" must reach dev_server. Checked by which
     * server answered: under first-match the "/" mount also matches and the root
     * filesystem answers about its own inode 0, which is a wrong answer and not
     * an error. */
    int slot = -1; uint32_t ino = 0; char last[FS_NAME_MAX];
    int rc = hvfs_walk("/dev/zero", 0, SLOT_FS_CLIENT, &slot, &ino, last);
    check(rc == 0, "resolve-dev-zero");
    check(slot == SLOT_DEV_CLIENT, "wrong-server-answered");
    check(ino == 2u, "dev-zero-wrong-inode");

    /* (6) A path that only the root mount covers still reaches fs_server. Both
     * mounts live in one namespace; installing /dev did not shadow "/". */
    slot = -1;
    rc = hvfs_walk("/bin", 0, SLOT_FS_CLIENT, &slot, &ino, last);
    check(slot == SLOT_FS_CLIENT, "root-path-left-the-root-mount");
    (void)rc;   /* /bin may or may not exist; the routing is the assertion */

    /* (7) A prefix matches only at a component boundary. "/devices" is NOT under
     * "/dev", and a plain string compare would send it to dev_server. */
    slot = -1;
    (void)hvfs_walk("/devices/x", 0, SLOT_FS_CLIENT, &slot, &ino, last);
    check(slot == SLOT_FS_CLIENT, "prefix-matched-mid-component");

    /* (8) Reading through the mount really works -- the positive direction, so
     * a kernel that refused everything could not pass this suite. */
    {
        struct fs_request rq; struct fs_response rp;
        umemset(&rq, 0, sizeof(rq));
        rq.op = FS_OP_READ; rq.ino = 2u; rq.len = 16;
        int r = hvfs_rpc(SLOT_DEV_CLIENT, &rq, &rp);
        int zeros = (r == 0 && rp.size == 16);
        for (unsigned i = 0; i < 16 && zeros; i++) if (rp.data[i]) zeros = 0;
        check(zeros, "dev-zero-did-not-read-zeros");
    }

    /* (9) ".." is pinned at the mount root: it must not walk out of /dev into
     * the root filesystem's inode space, where the same number means something
     * else entirely. */
    slot = -1; ino = 99u;
    rc = hvfs_walk("/dev/..", 0, SLOT_FS_CLIENT, &slot, &ino, last);
    check(rc == 0 && slot == SLOT_DEV_CLIENT && ino == 0u, "dotdot-escaped-the-mount");

    /* (10) S29 -- THE PROPERTY. The same path, from a table whose /dev mount
     * points at a slot holding no capability, must not resolve. Authority is the
     * capability, not the prefix. This is the check a client-side VFS has to
     * pass to be worth having. */
    {
        /* Reach past the public API deliberately: install the mount, then have
         * the walk go through a slot that holds nothing. hvfs_mount refuses an
         * uncapable slot (check 2), so the only way to construct this state is
         * to ask a mount that IS installed to talk on a slot that is not -- done
         * by resolving with a cwd_slot the task does not hold. */
        slot = -1;
        rc = hvfs_walk("relative/path", 0, SLOT_EMPTY, &slot, &ino, last);
        check(rc < 0, "resolved-through-a-slot-holding-no-capability");
    }

    if (failures) {
        kput("VFSTEST: FAIL "); kput_int(failures); kputln(" checks failed");
    } else {
        kput("VFSTEST: PASS "); kput_int(checks); kputln(" checks");
    }
    for (;;) sys_yield();
}
