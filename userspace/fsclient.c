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
#include "libhorus.h"

/* kput/kput_int come from libhorus. This file's own copies are gone -- and the
 * kput_int here had a real bug the shared one does not: `(unsigned)(-v)` negates
 * a signed int, which is undefined for INT_MIN. Reachable, since v is an IPC rc
 * a server chooses. */
static void fail(const char *stage) { kput("FS_SELFTEST: FAIL "); kput(stage); kput("\n"); sys_exit(); }
static void fail2(const char *stage, int v) { kput("FS_SELFTEST: FAIL "); kput(stage); kput("="); kput_int(v); kput("\n"); sys_exit(); }

/* Busy-wait in ring 3 between non-blocking IPC polls so the timer preempts us
 * and runs the server (cooperative yield() cannot switch two ring-3 tasks). */

/* One request/reply round-trip via blocking IPC (sys_ipc_call); returns rc.
 * Using ipc_call (not send + poll-recv on the shared FS_EP_REP) is what makes
 * concurrent clients safe: the server replies with SYS_IPC_REPLY_TO, which
 * routes the reply to THIS caller's blocked call by kernel-recorded identity, so
 * one client can never poll another's reply off a shared endpoint. Retries on -2
 * (request mailbox momentarily full — another client's request is in flight). */
static int rpc(struct fs_request *rq, struct fs_response *rp) {
    rq->magic = FS_PROTO_MAGIC;
    /* Retry ONLY the transient code, and bound even that -- the contract in
     * syscall.h, implemented once in libhorus's ipc_call_retry rather than
     * re-derived per program. The previous form was `while (r < 0)
     * spin_delay();`, which retried SYS_ERR_PERM -- "you hold no capability for
     * this endpoint" -- forever: finding G-8 signature C, a clean authorisation
     * refusal turned into an unkillable silent hang. The reporting stays here
     * because the marker strings are this selftest's, not the library's. */
    int r = ipc_call_retry(CAPSLOT_FS_EP, 0, rq, sizeof(*rq), rp);
    if (r == IPC_ERR_RETRY_EXHAUSTED) {
        kput("FS_SELFTEST: FAIL ipc-retry-exhausted\n");
        return r;
    }
    if (r < 0) {
        kput("FS_SELFTEST: FAIL ipc-refused rc="); kput_int(r); kput("\n");
        return r;                           /* permanent: report, never spin */
    }
    if (rp->magic != FS_PROTO_MAGIC) return -102;
    return rp->rc;
}

/* Acquire the fs endpoint capability, retrying while the server is not yet
 * registered.
 *
 * SYS_CONNECT_FS_SERVER fails with -1 until fs_server has completed
 * SYS_REGISTER_FS_SERVER, and the clients are made runnable at the same moment
 * the server is, so losing that race is ordinary rather than exceptional. The
 * old code called connect ONCE and discarded the result, leaving the client with
 * an empty capability slot and no way to ever notice: every later IPC returned
 * SYS_ERR_PERM into a loop that retried it forever.
 *
 * fs_server already retries its own registration for exactly this reason (it can
 * run before init has granted it the listen capability). This is the same
 * discipline on the other side of the same race. Returns 0 on success. */
static int fs_connect_retry(void) {
    for (unsigned attempt = 0; attempt < 200000u; attempt++) {
        if (sys_connect_fs_server(CAPSLOT_FS_EP, CAP_R_W) == 0) return 0;
        sys_yield();
    }
    return -1;
}

#ifdef PERM_SELFTEST
/* Ownership/permission test helpers. Each drives one fs_server request and
 * returns the server's rc (>=0 / bytes on success, negative SYS_ERR_* on denial);
 * read/stat payloads land in `pp`. The server derives the caller's identity from
 * the kernel (SYS_IPC_SENDER), so these calls are enforced against whichever user
 * this task last authenticated as — never anything placed in the request. */
static struct fs_request  pq;
static struct fs_response pp;
static void pfail(const char *s) { kput("PERM_SELFTEST: FAIL "); kput(s); kput("\n"); sys_exit(); }

static int p_make(uint32_t dir, const char *name, int is_dir) {
    umemset(&pq, 0, sizeof(pq)); pq.op = is_dir ? FS_OP_MKDIR : FS_OP_CREATE;
    pq.dir_ino = dir; ustrncpy(pq.name, name, FS_NAME_MAX);
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
#ifndef CONC_SELFTEST
    (void)sys_auth("root", "rootpass", 0);   /* CONC workers are already uid 0 (kernel-set), RAM store unlocked */
#endif

    /* Acquire the fs endpoint capability before issuing a single request. This is
     * the ONLY way a client reaches the server since IPC became
     * capability-addressed (finding C-1): no ambient endpoint cap exists to fall
     * back on, so a failed connect is not a missed optimisation, it is the
     * difference between working and hanging forever. Must be retried — see
     * fs_connect_retry. */
    if (fs_connect_retry() != 0) {
        kput("FS_SELFTEST: FAIL connect (fs_server never registered)\n");
        sys_exit();
    }

#ifdef CONC_SELFTEST
    /* Multi-client concurrency test. Several client tasks hammer the one
     * fs_server at once; each must receive ITS OWN replies (SYS_IPC_REPLY_TO
     * routes by the request's kernel-recorded sender). Role is the spawn arg:
     * 0 = coordinator, 1..NWORK = workers. A worker repeatedly writes a distinct
     * byte pattern to its own file and reads it back: a mis-routed reply yields
     * another worker's bytes (-> FAIL), and a lost reply hangs the worker so its
     * done-marker never appears (-> the coordinator never PASSes -> smoke
     * times out). The coordinator waits for every worker's done-marker, then
     * prints the single PASS the smoke asserts. */
    {
        const unsigned NWORK = 3;
        const unsigned ITERS = 12;
        uint32_t role = sys_spawn_arg();

        if (role == 0) {
            /* Coordinator: wait until every worker task has exited. Poll task
             * state (not the fs) so the server stays free for the workers — the
             * coordinator, also named "fsclient", is the last one left. A worker
             * that lost a reply would hang here forever -> smoke times out. */
            struct task_info ti;
            for (;;) {
                int alive = 0;
                for (int id = 1; id < 64; id++)
                    if (sys_get_task_info(id, &ti) == 0 && ti.state != 0 && ustreq(ti.name, "fsclient")) alive++;
                if (alive <= 1) break;   /* only the coordinator remains */
                for (int d = 0; d < 40; d++) spin_delay();
            }
            /* Verify each worker's file still holds ITS OWN bytes — a mis-routed
             * create/lookup reply would have made a worker write into another's
             * file, which this catches even though that worker read back its own
             * value. */
            for (unsigned i = 1; i <= NWORK; i++) {
                char fn[8]; fn[0]='w'; fn[1]=(char)('0'+i); fn[2]=0;
                umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_LOOKUP; rq.dir_ino = 0; ustrncpy(rq.name, fn, FS_NAME_MAX);
                if (rpc(&rq, &rp) != 0) { kput("CONC_SELFTEST: FAIL vlookup\n"); sys_exit(); }
                uint32_t vino = rp.ino;
                umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_READ; rq.ino = vino; rq.offset = 0; rq.len = 16;
                if (rpc(&rq, &rp) != 16) { kput("CONC_SELFTEST: FAIL vread\n"); sys_exit(); }
                for (int b = 0; b < 16; b++)
                    if (rp.data[b] != (uint8_t)(0xA0u + i)) { kput("CONC_SELFTEST: FAIL vcontent\n"); sys_exit(); }
            }
            kput("CONC_SELFTEST: PASS\n");
            sys_exit();
        }

        /* Worker `role`: create /w<role>, then loop write+read+verify its own
         * distinct bytes. A mis-routed read reply yields another worker's bytes. */
        char fn[8]; fn[0]='w'; fn[1]=(char)('0'+role); fn[2]=0;
        uint8_t want = (uint8_t)(0xA0u + role);
        umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_CREATE; rq.dir_ino = 0; ustrncpy(rq.name, fn, FS_NAME_MAX);
        (void)rpc(&rq, &rp);                                  /* ok if it already exists */
        umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_LOOKUP; rq.dir_ino = 0; ustrncpy(rq.name, fn, FS_NAME_MAX);
        if (rpc(&rq, &rp) != 0) { kput("CONC_SELFTEST: FAIL lookup\n"); sys_exit(); }
        uint32_t ino = rp.ino;

        for (unsigned k = 0; k < ITERS; k++) {
            umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_WRITE; rq.ino = ino; rq.offset = 0; rq.len = 16;
            for (int b = 0; b < 16; b++) rq.data[b] = want;
            if (rpc(&rq, &rp) != 16) { kput("CONC_SELFTEST: FAIL write\n"); sys_exit(); }

            umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_READ; rq.ino = ino; rq.offset = 0; rq.len = 16;
            if (rpc(&rq, &rp) != 16) { kput("CONC_SELFTEST: FAIL readlen\n"); sys_exit(); }
            for (int b = 0; b < 16; b++)
                if (rp.data[b] != want) { kput("CONC_SELFTEST: FAIL crosstalk\n"); sys_exit(); }
        }
        sys_exit();
    }
#endif

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
        ustrncpy(rq.name, sentinel, FS_NAME_MAX);
        if (rpc(&rq, &rp) == 0) {
            uint32_t fino = rp.ino;                     /* later boot: verify */
            umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_READ; rq.ino = fino;
            rq.offset = 0; rq.len = clen;
            int rr = rpc(&rq, &rp);
            if (rr != (int)clen) { kput("PERSIST_SELFTEST: FAIL read-len\n"); sys_exit(); }
            for (unsigned i = 0; i < clen; i++)
                if (rp.data[i] != (uint8_t)content[i]) { kput("PERSIST_SELFTEST: FAIL cmp\n"); sys_exit(); }
            kput("PERSIST_SELFTEST: PASS\n");
            sys_exit();
        }
        /* first boot: create + write the sentinel, then report WROTE */
        umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_CREATE; rq.dir_ino = 0;
        ustrncpy(rq.name, sentinel, FS_NAME_MAX);
        if (rpc(&rq, &rp) != 0) { kput("PERSIST_SELFTEST: FAIL create\n"); sys_exit(); }
        uint32_t fino = rp.ino;
        umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_WRITE; rq.ino = fino;
        rq.offset = 0; rq.len = clen; umemcpy(rq.data, content, clen);
        if (rpc(&rq, &rp) != (int)clen) { kput("PERSIST_SELFTEST: FAIL write\n"); sys_exit(); }
        kput("PERSIST_SELFTEST: WROTE\n");
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

    kput("PERM_SELFTEST: PASS\n");
    sys_exit();
#endif

    /* mkdir /docs */
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_MKDIR; rq.dir_ino = 0; ustrncpy(rq.name, "docs", FS_NAME_MAX);
    if (rpc(&rq, &rp) != 0) fail("mkdir");
    uint32_t dino = rp.ino;

    /* create /docs/hello.txt */
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_CREATE; rq.dir_ino = dino; ustrncpy(rq.name, "hello.txt", FS_NAME_MAX);
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
    if (!ustreq(rp.name, "hello.txt")) fail("readdir-name");

    /* lookup returns the same inode */
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_LOOKUP; rq.dir_ino = dino; ustrncpy(rq.name, "hello.txt", FS_NAME_MAX);
    if (rpc(&rq, &rp) != 0) fail("lookup");
    if (rp.ino != fino) fail("lookup-ino");

    /* delete, then lookup must miss */
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_DELETE; rq.dir_ino = dino; ustrncpy(rq.name, "hello.txt", FS_NAME_MAX);
    if (rpc(&rq, &rp) != 0) fail("delete");
    umemset(&rq, 0, sizeof(rq)); rq.op = FS_OP_LOOKUP; rq.dir_ino = dino; ustrncpy(rq.name, "hello.txt", FS_NAME_MAX);
    if (rpc(&rq, &rp) != SYS_ERR_NOENT) fail("delete-verify");

    kput("FS_SELFTEST: PASS\n");
    sys_exit();
}
