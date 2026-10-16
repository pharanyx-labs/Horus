/* FS self-test client (FS_SELFTEST builds only).
 *
 * Drives the userspace fs_server through capabilities, as every client does
 * since phase 1b step 6 removed the uid path: mkdir, create, write,
 * read-back+compare, stat, readdir, lookup, delete, and delete-verify, all
 * persisted through the kernel's encrypted object store. Prints
 * "FS_SELFTEST: PASS" on success (the marker `make smoke-fs` asserts) or
 * "FS_SELFTEST: FAIL <stage>" on the first failure.
 *
 * WHERE ITS ROOT COMES FROM. Under init (INIT_FS_SELFTEST) init grants it a
 * root directory capability at CAPSLOT_FS_ROOT, as a spawner grants any
 * program its root. Under a kernel harness the kernel stands in for init: it
 * lends an untokened capability to fs_server's endpoint holding MINT at
 * SLOT_PLAIN, and this task mints the root from it (fs_root), as fscapposix
 * does, since the harness cannot mint a tokened capability into a task.
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

#define SLOT_PLAIN  30   /* the harness's untokened endpoint capability, with MINT */
#define SLOT_ROOT   CAPSLOT_FS_ROOT
/* Capabilities the replies mint, one slot each, in the range the kernel never
 * allocates in (as the hvfs pool uses). Never reused: a test this size does
 * not run out. */
#define SLOT_FIRST  32
#define SLOT_LAST   63
static unsigned g_next_slot = SLOT_FIRST;

static unsigned new_slot(void) {
    if (g_next_slot > SLOT_LAST) fail("out-of-slots");
    return g_next_slot++;
}

static struct fs_response rp;
static union { struct fs_response r; uint8_t raw[256]; } g_in;   /* IPC_MSG_MAX */

/* One request through `slot`, with `recv` naming an empty slot for the
 * capability a LOOKUP, CREATE or MKDIR reply carries (IPC_NO_CAP for none).
 * Returns the reply's rc, its payload in `rp`.
 *
 * sys_ipc_call routes the reply to THIS caller's blocked call by kernel-recorded
 * identity (SYS_IPC_REPLY_TO), so concurrent clients never receive each other's
 * replies. Only IPC_AGAIN is retried, and that is bounded: retrying a permanent
 * refusal (SYS_ERR_PERM, "you hold no capability for this endpoint") forever is
 * finding G-8 signature C, a clean refusal turned into a silent hang. */
static int rpc_cap(unsigned slot, unsigned recv, struct fs_request *rq) {
    rq->magic = FS_PROTO_MAGIC;
    for (unsigned tries = 0; tries < 200000u; tries++) {
        int r = sys_ipc_call_cap(slot, recv, rq, sizeof(*rq), g_in.raw, IPC_NO_CAP);
        if (r >= (int)sizeof(struct fs_response)) {
            rp = g_in.r;
            if (rp.magic != FS_PROTO_MAGIC) return -102;
            return rp.rc;
        }
        if (r >= 0) return -101;
        if (r != IPC_AGAIN) return r;            /* permanent: report, never spin */
        sys_yield();
    }
    kput("FS_SELFTEST: FAIL ipc-retry-exhausted\n");
    return -103;
}

static int rpc(unsigned slot, struct fs_request *rq) { return rpc_cap(slot, IPC_NO_CAP, rq); }

static void req(struct fs_request *rq, uint32_t op, const char *name) {
    umemset(rq, 0, sizeof(*rq));
    rq->op = op;
    if (name) ustrncpy(rq->name, name, FS_NAME_MAX);
}

/* LOOKUP, CREATE or MKDIR `name` in the directory `dir`, the child's capability
 * minted into a fresh slot. Returns the slot, or the negative rc. */
static int child(unsigned dir, uint32_t op, const char *name) {
    struct fs_request rq;
    req(&rq, op, name);
    unsigned s = new_slot();
    int rc = rpc_cap(dir, s, &rq);
    return rc == 0 ? (int)s : rc;
}

/* The root directory: granted at SLOT_ROOT (under init), or minted here from
 * SLOT_PLAIN (under a kernel harness). Then a stat through it must answer
 * before anything else is asked, since the server may still be starting. */
static void fs_root(void) {
    struct fs_request rq;
    req(&rq, FS_OP_STAT, 0);
    if (rpc(SLOT_ROOT, &rq) == 0) return;
    uint32_t kern = CAP_RIGHT_WRITE | CAP_RIGHT_GRANT | CAP_RIGHT_REVOKE | CAP_RIGHT_MINT;
    if (sys_cap_mint_token(SLOT_ROOT, SLOT_PLAIN, kern | FS_R_ALL, fs_token(0, 0)) != 0)
        fail("no-root (neither granted nor mintable)");
    for (unsigned i = 0; i < 2000u; i++) {
        req(&rq, FS_OP_STAT, 0);
        if (rpc(SLOT_ROOT, &rq) == 0) return;
        sys_yield();
    }
    fail("server-never-answered");
}

#ifdef PERM_SELFTEST
/* NO FILESYSTEM REQUEST IS DECIDED BY WHO SENT IT (phase 1b step 6, S14), and a
 * file is never a directory operand ([HORUS-20261008-01]). */
static void pfail(const char *s) { kput_marker("PERM_SELFTEST: FAIL ", s); sys_exit(); }

static int content_is(const char *s, unsigned n) {
    for (unsigned i = 0; i < n; i++) if (rp.data[i] != (uint8_t)s[i]) return 0;
    return 1;
}

static int p_write(unsigned slot, const char *s) {
    struct fs_request rq;
    unsigned n = uslen(s);
    req(&rq, FS_OP_WRITE, 0);
    rq.len = n;
    umemcpy(rq.data, s, n);
    return rpc(slot, &rq);
}

static int p_read(unsigned slot, unsigned n) {   /* rc = bytes (data in rp.data) or negative */
    struct fs_request rq;
    req(&rq, FS_OP_READ, 0);
    rq.len = n;
    return rpc(slot, &rq);
}

/* A request through `slot` that names its objects by inode, as every request
 * did on the uid path: dir_ino, ino and name are the request's own. */
static int p_ino(unsigned slot, uint32_t op, uint32_t dir_ino, uint32_t ino, const char *name) {
    struct fs_request rq;
    req(&rq, op, name);
    rq.dir_ino = dir_ino;
    rq.ino = ino;
    if (op == FS_OP_READ || op == FS_OP_WRITE || op == FS_OP_APPEND) {
        rq.len = 4;
        umemcpy(rq.data, "pwnd", 4);
    }
    if (op == FS_OP_RENAME) ustrncpy((char *)rq.data, "moved", FS_DIRENT_NAME);
    if (op == FS_OP_CHMOD) rq.mode = 0777;
    return rpc(slot, &rq);
}

/* A capability to inode `ino` carrying every right, directory rights included,
 * minted from SLOT_PLAIN: what no client can hold (a reply gives a file only a
 * file's rights, FS_R_FILE_MASK), made here to show that the server's type
 * check stands even if a narrowing ever failed. The generation is found by
 * asking: a stale one is refused NOENT, the live one answers a stat. */
static int forge_cap(uint32_t ino) {
    uint32_t kern = CAP_RIGHT_WRITE | CAP_RIGHT_GRANT | CAP_RIGHT_REVOKE | CAP_RIGHT_MINT;
    unsigned s = new_slot();
    for (uint32_t gen = 0; gen < 64u; gen++) {
        if (sys_cap_mint_token(s, SLOT_PLAIN, kern | FS_R_ALL, fs_token(ino, gen)) != 0) return -1;
        struct fs_request rq;
        req(&rq, FS_OP_STAT, 0);
        if (rpc(s, &rq) == 0) return (int)s;
        (void)sys_cap_revoke(s);
    }
    return -1;
}

static void perm_selftest(void) {
    /* --- victims, made through the root capability ----------------------- */
    int sv = child(SLOT_ROOT, FS_OP_CREATE, "victim");        if (sv < 0) pfail("mk-victim");
    uint32_t v_ino = rp.ino;
    if (p_write((unsigned)sv, "intact") != 6)                 pfail("wr-victim");
    int svd = child(SLOT_ROOT, FS_OP_MKDIR, "vdir");          if (svd < 0) pfail("mk-vdir");
    uint32_t vd_ino = rp.ino;
    if (child((unsigned)svd, FS_OP_CREATE, "kid") < 0)        pfail("mk-vdir-kid");
    uint32_t vk_ino = rp.ino;
    int sud = child(SLOT_ROOT, FS_OP_MKDIR, "udir");          if (sud < 0) pfail("mk-udir");

    /* --- the uid path is gone --------------------------------------------
     *
     * This task is uid 0, as the kernel attests it (sys_auth above), the
     * identity the uid path let through everything. It asks by inode, through
     * the two untokened capabilities a task could ever hold: a WRITE-only copy,
     * the shape SYS_CONNECT_FS_SERVER handed every task that asked, and the
     * MINT-holding one, init's. Every operation must be refused PERM, and the
     * victims must be as they were. FS_UID_PATH_RESTORED=1 serves them again;
     * its arm, smoke-fs-perms-uid-control, requires the first marker below. */
    {
        unsigned plain_w = new_slot();
        if (sys_cap_mint((int)plain_w, SLOT_PLAIN, CAP_RIGHT_WRITE) != 0) pfail("uid-mint-write-only");
        static const struct { uint32_t op; const char *what; } ops[] = {
            { FS_OP_READ,     "uid-path-read"     },
            { FS_OP_STAT,     "uid-path-stat"     },
            { FS_OP_LOOKUP,   "uid-path-lookup"   },
            { FS_OP_READDIR,  "uid-path-readdir"  },
            { FS_OP_WRITE,    "uid-path-write"    },
            { FS_OP_APPEND,   "uid-path-append"   },
            { FS_OP_TRUNCATE, "uid-path-truncate" },
            { FS_OP_CREATE,   "uid-path-create"   },
            { FS_OP_MKDIR,    "uid-path-mkdir"    },
            { FS_OP_LINK,     "uid-path-link"     },
            { FS_OP_RENAME,   "uid-path-rename"   },
            { FS_OP_CHMOD,    "uid-path-chmod"    },
            { FS_OP_CHOWN,    "uid-path-chown"    },
            { FS_OP_DELETE,   "uid-path-delete"   },
        };
        const unsigned slots[2] = { plain_w, SLOT_PLAIN };
        for (unsigned k = 0; k < 2; k++)
            for (unsigned i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
                /* The names are the victim's, so a request served would reach it. */
                const char *nm = (ops[i].op == FS_OP_CREATE || ops[i].op == FS_OP_MKDIR ||
                                  ops[i].op == FS_OP_LINK) ? "planted" : "victim";
                uint32_t dir = 0, ino = v_ino;
                if (ops[i].op == FS_OP_RENAME) ino = 0;           /* new parent: the root */
                if (p_ino(slots[k], ops[i].op, dir, ino, nm) != SYS_ERR_PERM) pfail(ops[i].what);
            }
        if (p_read((unsigned)sv, 8) != 6 || !content_is("intact", 6)) pfail("uid-victim-changed");
        if (child(SLOT_ROOT, FS_OP_LOOKUP, "planted") != SYS_ERR_NOENT) pfail("uid-planted");
    }

    /* --- a FILE is never a directory operand -------------------------------
     *
     * fs_server reads a directory as an array of fs_dirent records in ordinary
     * inode data, and the bytes of a regular file are written by whoever may
     * write it. Until 2026-10-08 the requests that take a directory operand
     * checked permission on it and never its TYPE, so a user could write a
     * forged entry {ino = anything, type = FILE} into a file of their own and
     * pass the file as the "directory": DELETE through it freed the named inode,
     * root's /bin programs or /bin itself (a forged FILE type also skipped the
     * not-empty check), and RENAME did the same.
     *
     * Through capabilities a client is never given directory rights on a file,
     * so the type check stands behind that narrowing; the probe uses a forged
     * capability (forge_cap) to reach it anyway. The claim is that NO directory
     * operation interprets a file as a directory: each is refused with
     * SYS_ERR_INVAL and both victims are untouched. FS_DIR_OPERAND_UNCHECKED=1
     * restores the unchecked server; make smoke-fs-dir-operand-control requires
     * the first stage below. */
    {
        if (child((unsigned)sud, FS_OP_CREATE, "forge") < 0)   pfail("dir-operand-mk-forge");
        uint32_t f_ino = rp.ino;
        int sf = forge_cap(f_ino);                             if (sf < 0) pfail("dir-operand-forge-cap");
        unsigned f = (unsigned)sf;
        struct fs_dirent forged[2];
        umemset(forged, 0, sizeof(forged));
        forged[0].ino = v_ino;  forged[0].type = FS_TYPE_FILE; ustrncpy(forged[0].name, "x", FS_DIRENT_NAME);
        forged[1].ino = vd_ino; forged[1].type = FS_TYPE_FILE; ustrncpy(forged[1].name, "y", FS_DIRENT_NAME);
        struct fs_request rq;
        req(&rq, FS_OP_WRITE, 0);
        rq.len = sizeof(forged);
        umemcpy(rq.data, forged, sizeof(forged));
        if (rpc(f, &rq) != (int)sizeof(forged))                pfail("dir-operand-wr-forge");

        /* The report's attack, first, so the control arm's marker is the headline:
         * free root's file through a forged entry. */
        req(&rq, FS_OP_DELETE, "x");
        if (rpc(f, &rq) != SYS_ERR_INVAL)                      pfail("dir-operand-delete-file");
        /* The same against root's non-empty directory: the forged FILE type is
         * what skipped the not-empty check. */
        req(&rq, FS_OP_DELETE, "y");
        if (rpc(f, &rq) != SYS_ERR_INVAL)                      pfail("dir-operand-delete-nonempty");
        /* RENAME within the forgery: a new name for root's inode, with no link
         * counted for it. (A rename through a capability names one directory.) */
        req(&rq, FS_OP_RENAME, "x");
        ustrncpy((char *)rq.data, "stolen", FS_DIRENT_NAME);
        if (rpc(f, &rq) != SYS_ERR_INVAL)                      pfail("dir-operand-rename");
        req(&rq, FS_OP_LOOKUP, "x");
        if (rpc_cap(f, new_slot(), &rq) != SYS_ERR_INVAL)      pfail("dir-operand-lookup");
        req(&rq, FS_OP_READDIR, 0);
        if (rpc(f, &rq) != SYS_ERR_INVAL)                      pfail("dir-operand-readdir");
        req(&rq, FS_OP_CREATE, "z");
        if (rpc_cap(f, new_slot(), &rq) != SYS_ERR_INVAL)      pfail("dir-operand-create");
        req(&rq, FS_OP_MKDIR, "w");
        if (rpc_cap(f, new_slot(), &rq) != SYS_ERR_INVAL)      pfail("dir-operand-mkdir");

        /* THE PROPERTY, not only the codes: both victims are as root left them.
         * A refusal code over a destroyed victim would be a worse lie than either. */
        if (p_read((unsigned)sv, 8) != 6 || !content_is("intact", 6)) pfail("dir-operand-victim-lost");
        if (child((unsigned)svd, FS_OP_LOOKUP, "kid") < 0 || rp.ino != vk_ino)
            pfail("dir-operand-vdir-lost");
    }

    kput("PERM_SELFTEST: PASS\n");
    sys_exit();
}
#endif

void _start(void) {
    struct fs_request rq;

    /* Unlock the encrypted store. With the persistent ATA backend the disk comes
     * up mounted-but-locked (disk_key is only unwrapped by a password), so a login
     * must happen before any block can be read or written — otherwise the very
     * first mkdir fails. Authenticate as the seeded root user (a test-login stand-in
     * for the console login that unlocks a real deployment); storage_unlock is
     * idempotent, so on the ephemeral RAM backend (already unlocked at boot) this is
     * a harmless no-op. It authorises nothing in the filesystem: the uid path is
     * gone, and the root capability below is what every request goes through. */
#ifndef CONC_SELFTEST
    (void)sys_auth("root", "toor", 0);   /* CONC workers are already uid 0 (kernel-set), RAM store unlocked */
#endif

    fs_root();

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
                int s = child(SLOT_ROOT, FS_OP_LOOKUP, fn);
                if (s < 0) { kput("CONC_SELFTEST: FAIL vlookup\n"); sys_exit(); }
                req(&rq, FS_OP_READ, 0); rq.len = 16;
                if (rpc((unsigned)s, &rq) != 16) { kput("CONC_SELFTEST: FAIL vread\n"); sys_exit(); }
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
        (void)child(SLOT_ROOT, FS_OP_CREATE, fn);              /* ok if it already exists */
        int s = child(SLOT_ROOT, FS_OP_LOOKUP, fn);
        if (s < 0) { kput("CONC_SELFTEST: FAIL lookup\n"); sys_exit(); }

        for (unsigned k = 0; k < ITERS; k++) {
            req(&rq, FS_OP_WRITE, 0); rq.len = 16;
            for (int b = 0; b < 16; b++) rq.data[b] = want;
            if (rpc((unsigned)s, &rq) != 16) { kput("CONC_SELFTEST: FAIL write\n"); sys_exit(); }

            req(&rq, FS_OP_READ, 0); rq.len = 16;
            if (rpc((unsigned)s, &rq) != 16) { kput("CONC_SELFTEST: FAIL readlen\n"); sys_exit(); }
            for (int b = 0; b < 16; b++)
                if (rp.data[b] != want) { kput("CONC_SELFTEST: FAIL crosstalk\n"); sys_exit(); }
        }
        sys_exit();
    }
#endif

#ifdef PERSIST_SELFTEST
    /* Reboot-persistence check. Look up a sentinel file in the root directory.
     * Absent  -> this is the first boot on a fresh disk: create it and write
     * known content, then print WROTE. Present -> a later boot against the same
     * disk image: read it back and compare, printing PASS/FAIL. The two-boot
     * `make smoke-fs-persist` target asserts WROTE on boot 1 and PASS on boot 2. */
    {
        const char *sentinel = "persist.txt";
        const char *content  = "horus-persist-v1";
        unsigned    clen     = uslen(content);

        int s = child(SLOT_ROOT, FS_OP_LOOKUP, sentinel);
        if (s >= 0) {                                   /* later boot: verify */
            req(&rq, FS_OP_READ, 0); rq.len = clen;
            int rr = rpc((unsigned)s, &rq);
            if (rr != (int)clen) { kput("PERSIST_SELFTEST: FAIL read-len\n"); sys_exit(); }
            for (unsigned i = 0; i < clen; i++)
                if (rp.data[i] != (uint8_t)content[i]) { kput("PERSIST_SELFTEST: FAIL cmp\n"); sys_exit(); }
            kput("PERSIST_SELFTEST: PASS\n");
            sys_exit();
        }
        /* first boot: create + write the sentinel, then report WROTE */
        s = child(SLOT_ROOT, FS_OP_CREATE, sentinel);
        if (s < 0) { kput("PERSIST_SELFTEST: FAIL create\n"); sys_exit(); }
        req(&rq, FS_OP_WRITE, 0); rq.len = clen; umemcpy(rq.data, content, clen);
        if (rpc((unsigned)s, &rq) != (int)clen) { kput("PERSIST_SELFTEST: FAIL write\n"); sys_exit(); }
        kput("PERSIST_SELFTEST: WROTE\n");
        sys_exit();
    }
#endif

#ifdef PERM_SELFTEST
    perm_selftest();
#endif

    /* mkdir /docs */
    int sd = child(SLOT_ROOT, FS_OP_MKDIR, "docs");
    if (sd < 0) fail("mkdir");
    unsigned docs = (unsigned)sd;

    /* create /docs/hello.txt */
    int sfile = child(docs, FS_OP_CREATE, "hello.txt");
    if (sfile < 0) fail("create");
    unsigned file = (unsigned)sfile;
    uint32_t fino = rp.ino;

    /* write */
    const char *msg = "Horus phase 2: userspace FS over encrypted blocks.\n";
    unsigned mlen = uslen(msg);
    req(&rq, FS_OP_WRITE, 0); rq.len = mlen;
    umemcpy(rq.data, msg, mlen);
    if (rpc(file, &rq) != (int)mlen) fail("write");

    /* read back and compare */
    req(&rq, FS_OP_READ, 0); rq.len = mlen;
    { int rr = rpc(file, &rq); if (rr != (int)mlen) fail2("read-len", rr); }
    for (unsigned i = 0; i < mlen; i++) if (rp.data[i] != (uint8_t)msg[i]) fail("read-cmp");

    /* stat: size matches */
    req(&rq, FS_OP_STAT, 0);
    if (rpc(file, &rq) != 0) fail("stat");
    if (rp.size != mlen) fail("stat-size");

    /* readdir /docs -> hello.txt */
    req(&rq, FS_OP_READDIR, 0);
    if (rpc(docs, &rq) != 0) fail("readdir");
    if (!ustreq(rp.name, "hello.txt")) fail("readdir-name");

    /* ---- the end of a directory is not the absence of one -------------------
     *
     * Both answered SYS_ERR_NOENT until 2026-09-06, and every caller in the tree
     * resolved that the same way -- as end-of-directory, the fail-OPEN direction
     * for a listing. What a user saw was `ls` printing nothing and no error for a
     * directory it could not read; on a SEALED volume (every ATA machine until a
     * login unlocks it) h_fs_stat answers SYS_ERR_INVAL, fs_server flattened it
     * to NOENT, and the shell stopped there. A locked store reported itself as an
     * empty filesystem.
     *
     * THE CLAIM IS THAT THE TWO CODES DIFFER, so it is asserted by comparing the
     * two OBSERVED values against each other rather than each against a constant.
     * An arm that tested `badrc == FS_RC_ENDDIR` would pass under the defect --
     * there both are NOENT, and neither equals FS_RC_ENDDIR -- which is a check
     * that cannot fail for the reason it was written. The equality goes first
     * because this probe stops at its first failure, and this is the marker that
     * names the defect. "A directory that is not there" is one this task holds a
     * capability to and has deleted: a capability names an object, so a missing
     * directory can no longer be named by a number. */
    req(&rq, FS_OP_READDIR, 0); rq.offset = 1;
    int endrc = rpc(docs, &rq);                /* past the single entry */

    int sgone = child(docs, FS_OP_MKDIR, "gone");
    if (sgone < 0) fail("mkdir-gone");
    req(&rq, FS_OP_DELETE, "gone");
    if (rpc(docs, &rq) != 0) fail("delete-gone");
    req(&rq, FS_OP_READDIR, 0);
    int badrc = rpc((unsigned)sgone, &rq);     /* a directory that is not there */

    if (endrc == badrc) fail2("readdir-end-and-missing-dir-are-the-same", endrc);
    if (endrc != FS_RC_ENDDIR)  fail2("readdir-end-wrong-code", endrc);
    if (badrc != SYS_ERR_NOENT) fail2("readdir-missing-dir-wrong-code", badrc);

    /* lookup returns the same inode */
    if (child(docs, FS_OP_LOOKUP, "hello.txt") < 0) fail("lookup");
    if (rp.ino != fino) fail("lookup-ino");

    /* delete, then lookup must miss */
    req(&rq, FS_OP_DELETE, "hello.txt");
    if (rpc(docs, &rq) != 0) fail("delete");
    if (child(docs, FS_OP_LOOKUP, "hello.txt") != SYS_ERR_NOENT) fail("delete-verify");

    kput("FS_SELFTEST: PASS\n");
    sys_exit();
}
