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

#ifdef PERM_SELFTEST
/* Ownership/permission test helpers. Each drives one fs_server request and
 * returns the server's rc (>=0 / bytes on success, negative SYS_ERR_* on denial);
 * read/stat payloads land in `pp`. The server derives the caller's identity from
 * the kernel (SYS_IPC_SENDER), so these calls are enforced against whichever user
 * this task last authenticated as — never anything placed in the request. */
static struct fs_request  pq;
static struct fs_response pp;
static void pfail(const char *s) { put("PERM_SELFTEST: FAIL "); put(s); put("\n"); sys_exit(); }

static int p_make(uint32_t dir, const char *name, int is_dir) {
    umemset(&pq, 0, sizeof(pq)); pq.op = is_dir ? FS_OP_MKDIR : FS_OP_CREATE;
    pq.dir_ino = dir; ucpy(pq.name, name, FS_NAME_MAX);
    if (rpc(&pq, &pp) != 0) return -1;
    return (int)pp.ino;
}
static int p_write(uint32_t ino, const char *s) {
    unsigned n = uslen(s);
    umemset(&pq, 0, sizeof(pq)); pq.op = FS_OP_WRITE; pq.ino = ino; pq.offset = 0; pq.len = n;
    umemcpy(pq.data, s, n);
    return rpc(&pq, &pp);
}
static int p_read(uint32_t ino, unsigned n) {   /* rc = bytes (data in pp.data) or negative */
    umemset(&pq, 0, sizeof(pq)); pq.op = FS_OP_READ; pq.ino = ino; pq.offset = 0; pq.len = n;
    return rpc(&pq, &pp);
}
static int p_chmod(uint32_t ino, uint32_t mode) {
    umemset(&pq, 0, sizeof(pq)); pq.op = FS_OP_CHMOD; pq.ino = ino; pq.mode = mode;
    return rpc(&pq, &pp);
}
static int p_chown(uint32_t ino, uint32_t uid, uint32_t gid) {
    umemset(&pq, 0, sizeof(pq)); pq.op = FS_OP_CHOWN; pq.ino = ino; pq.arg_uid = uid; pq.arg_gid = gid;
    return rpc(&pq, &pp);
}
static int content_is(const char *s, unsigned n) {
    for (unsigned i = 0; i < n; i++) if (pp.data[i] != (uint8_t)s[i]) return 0;
    return 1;
}
#endif

void _start(void) {
    struct fs_request rq;
    struct fs_response rp;

    /* Unlock the encrypted store. With the persistent ATA backend the disk comes
     * up mounted-but-locked (disk_key is only unwrapped by a password), so a login
     * must happen before any block can be read or written — otherwise the very
     * first mkdir fails. Authenticate as the seeded root user (a test-login stand-in
     * for the console login that unlocks a real deployment); storage_unlock is
     * idempotent, so on the ephemeral RAM backend (already unlocked at boot) this is
     * a harmless no-op. */
    (void)sys_auth("root", "rootpass", 0);

    /* Our slot-3 endpoint cap was delegated by the spawner (see fs_selftest), so
     * IPC works immediately. The first rpc() polls until the server is serving.
     * (A best-effort connect also publishes discovery for real clients.) */
    (void)sys_connect_fs_server(4, CAP_R_W);

#ifdef PERSIST_SELFTEST
    /* Reboot-persistence check. Look up a sentinel file in the root directory
     * (ino 0). Absent  -> this is the first boot on a fresh disk: create it and
     * write known content, then print WROTE. Present -> a later boot against the
     * same disk image: read it back and compare, printing PASS/FAIL. The two-boot
     * `make smoke-fs-persist` target asserts WROTE on boot 1 and PASS on boot 2. */
    {
        const char *sentinel = "persist.txt";
        const char *content  = "horus-persist-v1";
        unsigned    clen     = uslen(content);

        umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_LOOKUP; rq.dir_ino = 0;
        ucpy(rq.name, sentinel, FS_NAME_MAX);
        if (rpc(&rq, &rp) == 0) {
            uint32_t fino = rp.ino;                     /* later boot: verify */
            umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_READ; rq.ino = fino;
            rq.offset = 0; rq.len = clen;
            int rr = rpc(&rq, &rp);
            if (rr != (int)clen) { put("PERSIST_SELFTEST: FAIL read-len\n"); sys_exit(); }
            for (unsigned i = 0; i < clen; i++)
                if (rp.data[i] != (uint8_t)content[i]) { put("PERSIST_SELFTEST: FAIL cmp\n"); sys_exit(); }
            put("PERSIST_SELFTEST: PASS\n");
            sys_exit();
        }
        /* first boot: create + write the sentinel, then report WROTE */
        umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_CREATE; rq.dir_ino = 0;
        ucpy(rq.name, sentinel, FS_NAME_MAX);
        if (rpc(&rq, &rp) != 0) { put("PERSIST_SELFTEST: FAIL create\n"); sys_exit(); }
        uint32_t fino = rp.ino;
        umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_WRITE; rq.ino = fino;
        rq.offset = 0; rq.len = clen; umemcpy(rq.data, content, clen);
        if (rpc(&rq, &rp) != (int)clen) { put("PERSIST_SELFTEST: FAIL write\n"); sys_exit(); }
        put("PERSIST_SELFTEST: WROTE\n");
        sys_exit();
    }
#endif

#ifdef PERM_SELFTEST
    /* Zero-trust ownership & permissions. We start as root (authenticated above),
     * build a scenario, then switch this task's identity to a non-root user and
     * confirm the server enforces access against the kernel-attested uid: a client
     * cannot read/modify what its real uid disallows, cannot create where it lacks
     * write, cannot chmod files it doesn't own, cannot chown at all — and root
     * bypasses. Crucially the client never tells the server who it is. */

    /* --- as root: a private file, a world-readable file, a user-owned dir --- */
    int s_ino = p_make(0, "secret", 0);              if (s_ino < 0) pfail("mk-secret");
    if (p_write((uint32_t)s_ino, "topsecret") != 9)  pfail("wr-secret");
    if (p_chmod((uint32_t)s_ino, 0600) != 0)         pfail("chmod-secret");

    int pub_ino = p_make(0, "public", 0);            if (pub_ino < 0) pfail("mk-public");
    if (p_write((uint32_t)pub_ino, "hello") != 5)    pfail("wr-public");   /* default 0644 */

    int d_ino = p_make(0, "udir", 1);                if (d_ino < 0) pfail("mk-udir");
    if (p_chown((uint32_t)d_ino, 1000, 100) != 0)    pfail("chown-udir");  /* give it to user */

    /* --- become uid 1000 (gid 100): the kernel now attests this identity --- */
    if (sys_auth("user", "password", 0) != 0)        pfail("auth-user");

    /* world-readable file: allowed */
    if (p_read((uint32_t)pub_ino, 8) != 5)           pfail("user-read-public-denied");
    if (!content_is("hello", 5))                     pfail("public-content");

    /* root's 0600 file, and writes/creates/chmod it isn't entitled to: DENIED */
    if (p_read((uint32_t)s_ino, 8)   != SYS_ERR_PERM) pfail("secret-read-not-denied");
    if (p_write((uint32_t)s_ino, "x") != SYS_ERR_PERM) pfail("secret-write-not-denied");
    if (p_make(0, "nope", 0)          != -1)          pfail("root-dir-create-not-denied");
    if (pp.rc                         != SYS_ERR_PERM) pfail("root-dir-create-wrong-rc");
    if (p_chmod((uint32_t)s_ino, 0666) != SYS_ERR_PERM) pfail("secret-chmod-not-denied");

    /* in a directory it owns: allowed to create/write/read/chmod */
    int m_ino = p_make((uint32_t)d_ino, "mine", 0);  if (m_ino < 0) pfail("user-create-owned");
    if (p_write((uint32_t)m_ino, "mydata") != 6)     pfail("user-write-owned");
    if (p_read((uint32_t)m_ino, 8) != 6)             pfail("user-read-owned");
    if (!content_is("mydata", 6))                    pfail("owned-content");
    if (p_chmod((uint32_t)m_ino, 0600) != 0)         pfail("user-chmod-owned");
    /* but chown is root-only, even of its own file */
    if (p_chown((uint32_t)m_ino, 0, 0) != SYS_ERR_PERM) pfail("user-chown-not-denied");

    /* --- back to root: superuser bypasses the 0600 owner-only file --- */
    if (sys_auth("root", "rootpass", 0) != 0)        pfail("reauth-root");
    if (p_read((uint32_t)m_ino, 8) != 6)             pfail("root-read-owned");
    if (!content_is("mydata", 6))                    pfail("root-content");
    if (p_chown((uint32_t)m_ino, 0, 0) != 0)         pfail("root-chown");

    put("PERM_SELFTEST: PASS\n");
    sys_exit();
#endif

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
