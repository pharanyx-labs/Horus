/* FS self-test client (FS_SELFTEST builds only).
 *
 * Connects to the userspace fs_server over IPC and exercises the full Phase 2
 * path — mkdir, create, write, read-back+compare, stat, readdir, lookup,
 * delete, and delete-verify — all persisted through the kernel's encrypted
 * object store. Prints "FS_SELFTEST: PASS" on success (the marker `make
 * smoke-fs` asserts) or "FS_SELFTEST: FAIL <stage>" on the first failure.
 */

#include "syscall.h"
#include "fs_proto.h"

/* Console output goes through SYS_WRITE (fd 1); SYS_PRINT is not dispatched. */
static void put(const char *s) { unsigned n = 0; while (s[n]) n++; sys_write(1, s, n); }
static void umemcpy(void *d, const void *s, unsigned n) { uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; }
static void umemset(void *d, int v, unsigned n) { uint8_t *p = d; while (n--) *p++ = (uint8_t)v; }
static unsigned uslen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static int ueq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }
static void ucpy(char *d, const char *s, unsigned n) { unsigned i = 0; for (; i + 1 < n && s[i]; i++) d[i] = s[i]; d[i] = 0; }

static void put_int(int v) {
    char b[12]; int i = 0; unsigned u = (v < 0) ? (put("-"), (unsigned)(-v)) : (unsigned)v;
    if (u == 0) { put("0"); return; }
    char t[12]; int n = 0; while (u) { t[n++] = '0' + (u % 10); u /= 10; }
    while (n) b[i++] = t[--n]; b[i] = 0; put(b);
}
static void fail(const char *stage) { put("FS_SELFTEST: FAIL "); put(stage); put("\n"); sys_exit(); }
static void fail2(const char *stage, int v) { put("FS_SELFTEST: FAIL "); put(stage); put("="); put_int(v); put("\n"); sys_exit(); }

/* Busy-wait in ring 3 between non-blocking IPC polls so the timer preempts us
 * and runs the server (cooperative yield() cannot switch two ring-3 tasks). */
static void spin_delay(void) { for (volatile unsigned i = 0; i < 40000u; i++) { } }

/* One request/reply round-trip (polling the non-blocking IPC); returns rc. */
static int rpc(struct fs_request *rq, struct fs_response *rp) {
    rq->magic = FS_PROTO_MAGIC;
    while (sys_ipc_send(FS_EP_REQ, rq, sizeof(*rq)) < 0) spin_delay();
    for (;;) {
        int r = sys_ipc_recv(FS_EP_REP, rp, sizeof(*rp));
        if (r >= 0) break;
        spin_delay();
    }
    if (rp->magic != FS_PROTO_MAGIC) return -102;
    return rp->rc;
}

void _start(void) {
    struct fs_request rq;
    struct fs_response rp;

    /* Our slot-3 endpoint cap was delegated by the spawner (see fs_selftest), so
     * IPC works immediately. The first rpc() polls until the server is serving.
     * (A best-effort connect also publishes discovery for real clients.) */
    (void)sys_connect_fs_server(4, CAP_R_W);

    /* mkdir /docs */
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_MKDIR; rq.dir_ino = 0; ucpy(rq.name, "docs", FS_NAME_MAX);
    if (rpc(&rq, &rp) != 0) fail("mkdir");
    uint32_t dino = rp.ino;

    /* create /docs/hello.txt */
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_CREATE; rq.dir_ino = dino; ucpy(rq.name, "hello.txt", FS_NAME_MAX);
    if (rpc(&rq, &rp) != 0) fail("create");
    uint32_t fino = rp.ino;

    /* write */
    const char *msg = "Horus phase 2: userspace FS over encrypted blocks.\n";
    unsigned mlen = uslen(msg);
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_WRITE; rq.ino = fino; rq.offset = 0; rq.len = mlen;
    umemcpy(rq.data, msg, mlen);
    if (rpc(&rq, &rp) != (int)mlen) fail("write");

    /* read back and compare */
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_READ; rq.ino = fino; rq.offset = 0; rq.len = mlen;
    { int rr = rpc(&rq, &rp); if (rr != (int)mlen) fail2("read-len", rr); }
    for (unsigned i = 0; i < mlen; i++) if (rp.data[i] != (uint8_t)msg[i]) fail("read-cmp");

    /* stat: size matches */
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_STAT; rq.ino = fino;
    if (rpc(&rq, &rp) != 0) fail("stat");
    if (rp.size != mlen) fail("stat-size");

    /* readdir /docs -> hello.txt */
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_READDIR; rq.dir_ino = dino; rq.offset = 0;
    if (rpc(&rq, &rp) != 0) fail("readdir");
    if (!ueq(rp.name, "hello.txt")) fail("readdir-name");

    /* lookup returns the same inode */
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_LOOKUP; rq.dir_ino = dino; ucpy(rq.name, "hello.txt", FS_NAME_MAX);
    if (rpc(&rq, &rp) != 0) fail("lookup");
    if (rp.ino != fino) fail("lookup-ino");

    /* delete, then lookup must miss */
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_DELETE; rq.dir_ino = dino; ucpy(rq.name, "hello.txt", FS_NAME_MAX);
    if (rpc(&rq, &rp) != 0) fail("delete");
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_LOOKUP; rq.dir_ino = dino; ucpy(rq.name, "hello.txt", FS_NAME_MAX);
    if (rpc(&rq, &rp) != SYS_ERR_NOENT) fail("delete-verify");

    put("FS_SELFTEST: PASS\n");
    sys_exit();
}
