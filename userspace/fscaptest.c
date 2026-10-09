/* Capability-addressed filesystem self-test CLIENT (FSCAP_SELFTEST builds only).
 *
 * The client half of `make smoke-fs-cap`: phase 1b step 1 of
 * docs/design/filesystem.md, against the real fs_server. It prints
 * FSCAPTEST: PASS <n> checks, or FSCAPTEST: FAIL <name> naming the first check
 * that did not hold.
 *
 * WHAT IT PROVES:
 *   - a request through a tokened capability reaches the token's object, and a
 *     directory hands back a capability to the child it creates or looks up;
 *   - a capability narrowed to READ cannot write (`readonly-wrote` is the check
 *     the control arm FS_CAP_RIGHTS_UNCHECKED=1 must turn red), and a file's
 *     capability cannot create entries, since a child keeps only the rights that
 *     mean something on its type;
 *   - a name that is "..", or holds "/", is refused: a capability to a directory
 *     reaches that directory and what is below it, and nothing else;
 *   - a capability to an object whose name was removed is refused NOENT, and
 *     never reaches whatever reuses its inode;
 *   - revoking a directory's capability revokes it and everything opened
 *     through it, and leaves the capability it came from working;
 *   - a rename or link that would give an object a name in a second directory
 *     is refused EXDEV, through a capability and through the identity path
 *     alike (step 5, decision 11; `cross-dir-rename` is the check the control
 *     arm FS_XDEV_UNCHECKED=1 must turn red), while a rename within one
 *     directory works and needs both CREATE and DELETE there.
 *
 * Slot map, set up by the kernel harness (selftest.c fscap_selftest):
 *   SLOT_PLAIN  an UNTOKENED capability to fs_server's endpoint with MINT, the
 *               kernel standing in for init, which in a real boot mints the root
 *               directory's capability from one of these. */

#include "syscall.h"
#include "fs_proto.h"
#include "libhorus.h"

#define SLOT_PLAIN  30
#define SLOT_ROOT   31
#define SLOT_DIR    32
#define SLOT_FILE   33
#define SLOT_RO     34
#define SLOT_LOOK   35
#define SLOT_SCRAP  36
#define SLOT_NEW    37
#define SLOT_MVA    38
#define SLOT_MVB    39
#define SLOT_CRONLY 40
#define SLOT_MVLOOK 41

static int checks;

/* Through the kernel log in one write (kput_marker): a gate asserts these lines
 * whole, and SYS_PRINT is not this task's to use. */
static void fail(const char *what)
{
    kput_marker("FSCAPTEST: FAIL ", what);
    sys_exit();
}

static void ok(void) { checks++; }

static void fill(struct fs_request *rq, uint32_t op, const char *name)
{
    char *p = (char *)rq;
    for (unsigned i = 0; i < sizeof(*rq); i++) p[i] = 0;
    rq->magic = FS_PROTO_MAGIC;
    rq->op = op;
    if (name)
        for (unsigned i = 0; name[i] && i < FS_NAME_MAX - 1; i++) rq->name[i] = name[i];
}

static uint8_t rbuf[256];

/* One request through `slot`, with `recv` naming an empty slot for a capability
 * the reply may carry. Returns the reply's rc, or a large negative when the call
 * itself was refused (an empty or revoked slot). */
static int call(unsigned slot, unsigned recv, struct fs_request *rq)
{
    for (int tries = 0; tries < 200000; tries++) {
        int r = sys_ipc_call_cap(slot, recv, rq, sizeof(*rq), rbuf, IPC_NO_CAP);
        if (r >= (int)sizeof(struct fs_response)) return ((struct fs_response *)rbuf)->rc;
        if (r >= 0) return -1000;
        if (r != IPC_AGAIN) return -2000 + r;
        sys_yield();
    }
    return -3000;
}

void _start(void)
{
    struct fs_request rq;

    /* The root directory, as init mints it. */
    if (sys_cap_mint_token(SLOT_ROOT, SLOT_PLAIN,
                           CAP_RIGHT_WRITE | CAP_RIGHT_GRANT | CAP_RIGHT_REVOKE | CAP_RIGHT_MINT | FS_R_ALL,
                           fs_token(0, 0)) != 0)
        fail("mint-root");

    /* Wait for the server: STAT on the root succeeds once it serves. */
    int up = 0;
    for (int i = 0; i < 2000 && !up; i++) {
        fill(&rq, FS_OP_STAT, 0);
        if (call(SLOT_ROOT, IPC_NO_CAP, &rq) == 0) up = 1; else sys_yield();
    }
    if (!up) fail("server-never-answered");
    ok();

    fill(&rq, FS_OP_MKDIR, "capdir");
    if (call(SLOT_ROOT, SLOT_DIR, &rq) != 0) fail("mkdir-through-root");
    ok();

    fill(&rq, FS_OP_CREATE, "f");
    if (call(SLOT_DIR, SLOT_FILE, &rq) != 0) fail("create-through-child-dir");
    ok();

    fill(&rq, FS_OP_WRITE, 0);
    rq.len = 5;
    for (int i = 0; i < 5; i++) rq.data[i] = (uint8_t)"hello"[i];
    if (call(SLOT_FILE, IPC_NO_CAP, &rq) < 0) fail("write-through-file");
    fill(&rq, FS_OP_READ, 0);
    rq.len = 5;
    if (call(SLOT_FILE, IPC_NO_CAP, &rq) != 5 ||
        ((struct fs_response *)rbuf)->data[0] != 'h') fail("read-back-through-file");
    ok();

    /* NARROWED TO READ: it reads, and it must not write. */
    if (sys_cap_mint(SLOT_RO, SLOT_FILE, CAP_RIGHT_WRITE | FS_R_READ) != 0) fail("mint-readonly");
    fill(&rq, FS_OP_READ, 0);
    rq.len = 5;
    if (call(SLOT_RO, IPC_NO_CAP, &rq) != 5) fail("readonly-cannot-read");
    fill(&rq, FS_OP_WRITE, 0);
    rq.len = 1;
    rq.data[0] = 'X';
    if (call(SLOT_RO, IPC_NO_CAP, &rq) != SYS_ERR_PERM) fail("readonly-wrote");
    ok();

    /* A FILE'S CAPABILITY HAS NO DIRECTORY RIGHTS. */
    fill(&rq, FS_OP_CREATE, "g");
    if (call(SLOT_FILE, SLOT_SCRAP, &rq) != SYS_ERR_PERM) fail("file-cap-created-an-entry");
    ok();

    /* NOTHING ABOVE OR BESIDE: "..", ".", and a name holding "/". */
    fill(&rq, FS_OP_LOOKUP, "..");
    if (call(SLOT_DIR, SLOT_SCRAP, &rq) != SYS_ERR_INVAL) fail("lookup-dotdot");
    fill(&rq, FS_OP_LOOKUP, ".");
    if (call(SLOT_DIR, SLOT_SCRAP, &rq) != SYS_ERR_INVAL) fail("lookup-dot");
    fill(&rq, FS_OP_LOOKUP, "a/b");
    if (call(SLOT_DIR, SLOT_SCRAP, &rq) != SYS_ERR_INVAL) fail("lookup-slash");
    ok();

    /* LOOKUP hands back a working capability. */
    fill(&rq, FS_OP_LOOKUP, "f");
    if (call(SLOT_DIR, SLOT_LOOK, &rq) != 0) fail("lookup-f");
    fill(&rq, FS_OP_READ, 0);
    rq.len = 5;
    if (call(SLOT_LOOK, IPC_NO_CAP, &rq) != 5) fail("read-through-looked-up");
    ok();

    /* STALE: the name goes, and every capability to that object stops. */
    fill(&rq, FS_OP_DELETE, "f");
    if (call(SLOT_DIR, IPC_NO_CAP, &rq) != 0) fail("delete-f");
    fill(&rq, FS_OP_READ, 0);
    rq.len = 5;
    if (call(SLOT_FILE, IPC_NO_CAP, &rq) != SYS_ERR_NOENT) fail("stale-capability-read");
    ok();

    /* REVOKE: a directory's capability goes, and with it everything opened
     * through it; the root it came from stays. (The kernel's revoke removes the
     * capability named and every one derived from it.) */
    fill(&rq, FS_OP_CREATE, "h");
    if (call(SLOT_DIR, SLOT_NEW, &rq) != 0) fail("create-h");
    if (sys_cap_revoke(SLOT_DIR) != 0) fail("revoke-dir");
    fill(&rq, FS_OP_STAT, 0);
    if (call(SLOT_NEW, IPC_NO_CAP, &rq) > -1000) fail("child-survived-revoke");
    fill(&rq, FS_OP_STAT, 0);
    if (call(SLOT_DIR, IPC_NO_CAP, &rq) > -1000) fail("revoked-dir-still-answers");
    fill(&rq, FS_OP_STAT, 0);
    if (call(SLOT_ROOT, IPC_NO_CAP, &rq) != 0) fail("root-gone-after-revoke");
    ok();

    /* MOVES (step 5). Two directories, a file in the first. */
    fill(&rq, FS_OP_MKDIR, "mva");
    if (call(SLOT_ROOT, SLOT_MVA, &rq) != 0) fail("mkdir-mva");
    uint32_t a_ino = ((struct fs_response *)rbuf)->ino;
    fill(&rq, FS_OP_MKDIR, "mvb");
    if (call(SLOT_ROOT, SLOT_MVB, &rq) != 0) fail("mkdir-mvb");
    uint32_t b_ino = ((struct fs_response *)rbuf)->ino;
    fill(&rq, FS_OP_CREATE, "m");
    if (call(SLOT_MVA, IPC_NO_CAP, &rq) != 0) fail("create-m");
    uint32_t m_ino = ((struct fs_response *)rbuf)->ino;

    /* Across directories, through the identity path: refused, and the file
     * stays where it was. */
    fill(&rq, FS_OP_RENAME, "m");
    rq.dir_ino = a_ino;
    rq.ino = b_ino;
    rq.data[0] = 'n';
    if (call(SLOT_PLAIN, IPC_NO_CAP, &rq) != SYS_ERR_XDEV) fail("cross-dir-rename");
    fill(&rq, FS_OP_LOOKUP, "m");
    if (call(SLOT_MVA, IPC_NO_CAP, &rq) != 0) fail("cross-dir-rename-moved-it");
    fill(&rq, FS_OP_LINK, "l");
    rq.dir_ino = b_ino;
    rq.ino = m_ino;
    if (call(SLOT_PLAIN, IPC_NO_CAP, &rq) != SYS_ERR_XDEV) fail("cross-dir-link");
    /* A second name beside the first is not a move. */
    fill(&rq, FS_OP_LINK, "l");
    rq.dir_ino = a_ino;
    rq.ino = m_ino;
    if (call(SLOT_PLAIN, IPC_NO_CAP, &rq) != 0) fail("same-dir-link");
    ok();

    /* Through a capability: a request naming a second directory is EXDEV, a
     * rename within the capability's directory works, and it needs DELETE as
     * well as CREATE. */
    fill(&rq, FS_OP_RENAME, "m");
    rq.ino = b_ino;
    rq.data[0] = 'n';
    if (call(SLOT_MVA, IPC_NO_CAP, &rq) != SYS_ERR_XDEV) fail("cap-cross-dir-rename");
    if (sys_cap_mint(SLOT_CRONLY, SLOT_MVA, CAP_RIGHT_WRITE | FS_R_CREATE | FS_R_LOOKUP) != 0)
        fail("mint-create-only");
    fill(&rq, FS_OP_RENAME, "m");
    rq.data[0] = 'n';
    if (call(SLOT_CRONLY, IPC_NO_CAP, &rq) != SYS_ERR_PERM) fail("rename-without-delete");
    fill(&rq, FS_OP_RENAME, "m");
    rq.data[0] = '.';
    rq.data[1] = '.';
    if (call(SLOT_MVA, IPC_NO_CAP, &rq) != SYS_ERR_INVAL) fail("rename-to-dotdot");
    fill(&rq, FS_OP_RENAME, "m");
    rq.data[0] = 'n';
    if (call(SLOT_MVA, IPC_NO_CAP, &rq) != 0) fail("same-dir-rename");
    fill(&rq, FS_OP_LOOKUP, "n");
    if (call(SLOT_MVA, SLOT_MVLOOK, &rq) != 0) fail("renamed-not-found");
    ok();

    char n[12];
    int v = checks, k = 0;
    char d[12];
    do { d[k++] = (char)('0' + v % 10); v /= 10; } while (v);
    int j = 0;
    while (k) n[j++] = d[--k];
    n[j] = 0;
    char line[32];
    const char *t = " checks";
    unsigned m = 0;
    for (unsigned i = 0; n[i]; i++) line[m++] = n[i];
    for (unsigned i = 0; t[i]; i++) line[m++] = t[i];
    line[m] = 0;
    kput_marker("FSCAPTEST: PASS ", line);
    sys_exit();
}
