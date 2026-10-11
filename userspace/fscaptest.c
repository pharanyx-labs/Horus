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
 *     directory works and needs both CREATE and DELETE there;
 *   - a session (step 3(a), §6.4, decision 13) reaches only what its grants
 *     name: an ordinary account's root lists only the paths that lead to its
 *     grants and refuses every other name NOENT (`session-reached-ungranted` is
 *     the check FS_SESSION_GRANTS_ROOT=1 must turn red), cannot create in the
 *     root although its root capability carries the union of its rights
 *     (`session-created-in-root`, for FS_SESSION_RIGHTS_UNCHECKED=1), is given
 *     exactly read, lookup and exec on /bin, and everything in its own home;
 *     a session opens only through the untokened capability holding MINT
 *     (`session-opened-without-mint`, for FS_SESSION_ANY_CALLER=1), and a
 *     capability that outlives its session's end reaches nothing;
 *   - each session's /tmp is its own (S129): the administrator's session does
 *     not see what the user's put there (`session-tmp-shared`, for
 *     FS_SESSION_TMP_SHARED=1), no session sees the store they live in, the
 *     administrator's included (`session-tmp-store-visible`, for
 *     FS_SESSION_TMP_STORE_VISIBLE=1), and a session's /tmp, however deep,
 *     is gone when the session ends (`session-tmp-outlived-its-end`, for
 *     FS_SESSION_TMP_KEPT=1).
 *
 * Slot map, set up by the kernel harness (selftest.c fscap_selftest):
 *   SLOT_PLAIN  an UNTOKENED capability to fs_server's endpoint with MINT, the
 *               kernel standing in for init, which in a real boot mints the root
 *               directory's capability from one of these.
 *   CAPSLOT_DEBUG CAP_DEBUG, so the session checks can read the rights of a
 *               capability the server minted (SYS_CAP_ENUMERATE). */

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
#define SLOT_WA     42
#define SLOT_WALK   43
#define SLOT_WFILE  44
#define SLOT_DIRRO  45
#define SLOT_WRO    46
#define SLOT_NOLOOK 47
#define SLOT_WSCRAP 48
#define SLOT_SROOT  50    /* an ordinary session's root */
#define SLOT_SCWD   51    /* and its working directory */
#define SLOT_SX     52
#define SLOT_SBIN   53
#define SLOT_SHOME  54
#define SLOT_SF     55
#define SLOT_SNOW   56    /* untokened, WRITE only: no MINT */
#define SLOT_SRO    57    /* a read-only copy of the session's root */
#define SLOT_AROOT  58    /* the administrator's session root */
#define SLOT_AX     59
#define SLOT_STMP   60    /* the ordinary session's /tmp */
#define SLOT_ATMP   61    /* the administrator's */
#define SLOT_TX     62
#define SLOT_STORE  63

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

/* An FS_OP_WALK request for `n` names. A name may be anything, including the
 * ones the server must refuse: the packing is the client's, the checking the
 * server's. */
static void fill_walk(struct fs_request *rq, const char *const *names, unsigned n)
{
    fill(rq, FS_OP_WALK, 0);
    if (fs_walk_pack(rq->data, &rq->len, names, n) != 0) rq->len = 0;
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

/* ---- sessions (phase 1b step 3(a); docs/design/filesystem.md §6.4) ---------
 *
 * The harness boots on the RAM store, which is ephemeral, so the policy is the
 * compiled-in default (decision 9): the administrator gets the root; every
 * account gets read, lookup and exec on /bin and /usr, read and lookup on /lib,
 * and its own /home/<name>. The kernel's accounts are root (uid 0) and user
 * (1000, home /home/user, which fs_server made at provisioning). The file
 * language and the persistent-volume rules are tested on the host
 * (make smoke-fs-policy), since this store never consults a file. */
static int session_open(uint32_t uid, struct fs_session_grant *sg)
{
    struct fs_request rq;
    fill(&rq, FS_OP_SESSION, 0);
    rq.arg_uid = uid;
    int rc = call(SLOT_PLAIN, IPC_NO_CAP, &rq);
    if (rc == 0) umemcpy(sg, ((struct fs_response *)rbuf)->data, sizeof(*sg));
    return rc;
}

static int session_end(uint32_t g)
{
    struct fs_request rq;
    fill(&rq, FS_OP_SESSION_END, 0);
    rq.offset = g;
    return call(SLOT_PLAIN, IPC_NO_CAP, &rq);
}

static int walk1(unsigned from, unsigned into, const char *a, const char *b)
{
    struct fs_request rq;
    const char *p[2] = { a, b };
    fill_walk(&rq, p, b ? 2 : 1);
    return call(from, into, &rq);
}

/* The rights of this task's capability in `slot`, as the kernel records them. */
static uint32_t rights_of(unsigned slot)
{
    struct cap_info ci;
    if (sys_cap_enumerate(sys_getpid(), slot, &ci) != 0 || !ci.occupied) return 0;
    return ci.rights;
}

/* The permission bits a stat through `slot` reports, or 0xFFFFFFFF if it
 * failed or did not name the caller as the owner (§7.1: uid and gid say "you"). */
static uint32_t mode_of(unsigned slot)
{
    struct fs_request rq;
    fill(&rq, FS_OP_STAT, 0);
    if (call(slot, IPC_NO_CAP, &rq) != 0) return 0xFFFFFFFFu;
    const struct fs_response *rp = (const struct fs_response *)rbuf;
    if (rp->uid != sys_getuid()) return 0xFFFFFFFFu;
    return rp->mode & 07777u;
}

/* Does a listing of `slot` hold only names in `allowed` (NUL-separated, ending
 * in an empty one), and every name in `needed`? */
static int lists_only(unsigned slot, const char *allowed, const char *needed)
{
    struct fs_request rq;
    char seen[16][FS_NAME_MAX];
    unsigned ns = 0;
    for (uint32_t off = 0; off < 64; off++) {
        fill(&rq, FS_OP_READDIR, 0);
        rq.offset = off;
        int rc = call(slot, IPC_NO_CAP, &rq);
        if (rc == FS_RC_ENDDIR) break;
        if (rc != 0) return 0;
        const char *nm = ((struct fs_response *)rbuf)->name;
        int ok = 0;
        for (const char *a = allowed; *a; a += uslen(a) + 1) if (ustreq(a, nm)) ok = 1;
        if (!ok) return 0;
        if (ns < 16) ustrncpy(seen[ns++], nm, FS_NAME_MAX);
    }
    for (const char *n = needed; *n; n += uslen(n) + 1) {
        int found = 0;
        for (unsigned i = 0; i < ns; i++) if (ustreq(seen[i], n)) found = 1;
        if (!found) return 0;
    }
    return 1;
}

/* Does a listing of `slot` hold `name`? */
static int lists_name(unsigned slot, const char *name)
{
    struct fs_request rq;
    for (uint32_t off = 0; off < 64; off++) {
        fill(&rq, FS_OP_READDIR, 0);
        rq.offset = off;
        if (call(slot, IPC_NO_CAP, &rq) != 0) return 0;
        if (ustreq(((struct fs_response *)rbuf)->name, name)) return 1;
    }
    return 0;
}

static void sessions(void)
{
    struct fs_request rq;
    struct fs_session_grant sg, ag;

    /* A home that is not the user's, made through step 1's root, which carries
     * no grant set: the user's session must not see it. */
    if (walk1(SLOT_ROOT, SLOT_SX, "home", 0) != 0) fail("session-setup-walk-home");
    fill(&rq, FS_OP_MKDIR, "other");
    if (call(SLOT_SX, IPC_NO_CAP, &rq) != 0) fail("session-setup-mkdir-other");
    if (sys_cap_revoke(SLOT_SX) != 0) fail("session-setup-revoke");
    ok();

    /* AN ORDINARY ACCOUNT'S SESSION. */
    if (session_open(1000, &sg) != 0) fail("session-user-open");
    if (sg.g == 0 || sg.g > FS_SESSIONS_MAX || fs_token_g(sg.root_token) != sg.g ||
        !fs_token_tracked(sg.root_token) || sg.cwd_token == 0) fail("session-user-grant");
    if (sg.source != FS_SESSION_SRC_DEFAULT) fail("session-not-default-policy");
    if (sys_cap_mint_token(SLOT_SROOT, SLOT_PLAIN, sg.root_rights, sg.root_token) != 0 ||
        sys_cap_mint_token(SLOT_SCWD, SLOT_PLAIN, sg.cwd_rights, sg.cwd_token) != 0)
        fail("session-user-mint");
    ok();

    /* IT REACHES ONLY WHAT ITS GRANTS NAME, and what they withhold is absent:
     * NOENT, never PERM. */
    if (walk1(SLOT_SROOT, SLOT_SX, "etc", 0) != SYS_ERR_NOENT) fail("session-reached-ungranted");
    fill(&rq, FS_OP_LOOKUP, "etc");
    if (call(SLOT_SROOT, SLOT_SX, &rq) != SYS_ERR_NOENT) fail("session-looked-up-ungranted");
    if (walk1(SLOT_SROOT, SLOT_SX, "home", "other") != SYS_ERR_NOENT) fail("session-reached-other-home");
    if (walk1(SLOT_SROOT, SLOT_SX, "sbin", 0) != SYS_ERR_NOENT) fail("session-reached-sbin");
    ok();

    /* THE ROOT CARRIES THE UNION OF THE SESSION'S RIGHTS, so that a writable
     * home below a read-only root is reachable at all; the server, not the
     * kernel, keeps the root itself to LOOKUP and a filtered listing. This is
     * decision 13's trade, and the check that witnesses the server keeps it. */
    if (!(rights_of(SLOT_SROOT) & FS_R_CREATE)) fail("session-root-not-union");
    fill(&rq, FS_OP_MKDIR, "intruder");
    if (call(SLOT_SROOT, SLOT_SX, &rq) != SYS_ERR_PERM) fail("session-created-in-root");
    fill(&rq, FS_OP_DELETE, "bin");
    if (call(SLOT_SROOT, IPC_NO_CAP, &rq) != SYS_ERR_PERM) fail("session-deleted-in-root");
    ok();

    /* ITS LISTINGS SHOW ONLY THE WAY TO ITS GRANTS. */
    if (!lists_only(SLOT_SROOT, "bin\0lib\0usr\0home\0tmp\0", "bin\0home\0tmp\0")) fail("session-listed-ungranted");
    if (walk1(SLOT_SROOT, SLOT_SHOME, "home", 0) != 0) fail("session-walk-home");
    if (!lists_only(SLOT_SHOME, "user\0", "user\0")) fail("session-listed-other-home");
    ok();

    /* /bin IS EXACTLY READ, LOOKUP AND EXEC. Asserted on the minted rights, not
     * by trying to write: the system-tree rule (S116) refuses a write to /bin
     * whatever the policy says, so a refusal would prove nothing about it. */
    if (walk1(SLOT_SROOT, SLOT_SBIN, "bin", 0) != 0) fail("session-walk-bin");
    if ((rights_of(SLOT_SBIN) & FS_R_ALL) != (FS_R_READ | FS_R_LOOKUP | FS_R_EXEC))
        fail("session-bin-rights");
    ok();

    /* ITS OWN HOME IS ITS OWN, from the working directory init would grant and
     * by a walk from the root alike. */
    fill(&rq, FS_OP_CREATE, "notes");
    if (call(SLOT_SCWD, SLOT_SF, &rq) != 0) fail("session-home-not-writable");
    fill(&rq, FS_OP_WRITE, 0);
    rq.len = 3;
    rq.data[0] = 'm'; rq.data[1] = 'i'; rq.data[2] = 'n';
    if (call(SLOT_SF, IPC_NO_CAP, &rq) != 3) fail("session-home-write");
    if (walk1(SLOT_SROOT, SLOT_SX, "home", "user") != 0) fail("session-walk-own-home");
    if ((rights_of(SLOT_SX) & FS_R_ALL) != FS_R_ALL) fail("session-own-home-rights");
    if (sys_cap_revoke(SLOT_SX) != 0) fail("session-revoke-x");
    ok();

    /* THE TRUTHFUL VIEW (§7.1, S130): owner bits are the capability's rights,
     * other bits the bound on everyone else's. A file in its own home is its
     * alone; /bin is read and run by every account. */
    if (mode_of(SLOT_SF) != 0700u) fail("session-stat-home-not-private");
    if (mode_of(SLOT_SBIN) != 0505u) fail("session-stat-bin-not-shared");
    ok();

    /* ITS OWN /tmp (S129): read, write, lookup, create, delete and setattr, and
     * not exec. A file, and a tree deeper than any fixed bound a sweep might
     * have, so that its end is shown to remove all of it. */
    if (walk1(SLOT_SROOT, SLOT_STMP, "tmp", 0) != 0) fail("session-tmp-missing");
    if ((rights_of(SLOT_STMP) & FS_R_ALL) !=
        (FS_R_READ | FS_R_WRITE | FS_R_LOOKUP | FS_R_CREATE | FS_R_DELETE | FS_R_SETATTR))
        fail("session-tmp-rights");
    fill(&rq, FS_OP_CREATE, "mine");
    if (call(SLOT_STMP, SLOT_TX, &rq) != 0) fail("session-tmp-not-writable");
    if (sys_cap_revoke(SLOT_TX) != 0) fail("session-tmp-revoke");
    {
        const char *dd[12] = { "d", "d", "d", "d", "d", "d", "d", "d", "d", "d", "d", "d" };
        for (unsigned k = 0; k < 12; k++) {
            unsigned at = SLOT_STMP;
            if (k > 0) {
                fill_walk(&rq, dd, k);
                if (call(SLOT_STMP, SLOT_TX, &rq) != 0) fail("session-tmp-deep-walk");
                at = SLOT_TX;
            }
            fill(&rq, FS_OP_MKDIR, "d");
            if (call(at, IPC_NO_CAP, &rq) != 0) fail("session-tmp-deep-mkdir");
            if (k > 0 && sys_cap_revoke(SLOT_TX) != 0) fail("session-tmp-deep-revoke");
        }
    }
    if (walk1(SLOT_SROOT, SLOT_SX, FS_SESSION_TMP_STORE_NAME, 0) != SYS_ERR_NOENT)
        fail("session-tmp-store-visible-to-user");
    if (mode_of(SLOT_STMP) != 0700u) fail("session-stat-tmp-not-private");
    ok();

    /* THE KERNEL STILL BOUNDS IT: a read-only copy of the root walks to the home
     * and gets a read-only directory, never the union. */
    if (sys_cap_mint(SLOT_SRO, SLOT_SROOT, CAP_RIGHT_WRITE | CAP_RIGHT_REVOKE | FS_R_READ | FS_R_LOOKUP) != 0)
        fail("session-mint-readonly");
    if (walk1(SLOT_SRO, SLOT_SX, "home", "user") != 0) fail("session-readonly-walk");
    fill(&rq, FS_OP_CREATE, "x");
    if (call(SLOT_SX, SLOT_AX, &rq) != SYS_ERR_PERM) fail("session-narrowed-copy-widened");
    if (sys_cap_revoke(SLOT_SX) != 0) fail("session-revoke-x2");
    ok();

    /* THE ADMINISTRATOR'S SESSION reaches everything, and a narrower line below
     * ("@all /usr read") does not narrow it there. */
    if (session_open(0, &ag) != 0 || ag.g == 0 || ag.g == sg.g) fail("session-admin-open");
    if (sys_cap_mint_token(SLOT_AROOT, SLOT_PLAIN, ag.root_rights, ag.root_token) != 0)
        fail("session-admin-mint");
    if (walk1(SLOT_AROOT, SLOT_AX, "etc", 0) != 0) fail("session-admin-no-etc");
    if (sys_cap_revoke(SLOT_AX) != 0) fail("session-admin-revoke");
    if (walk1(SLOT_AROOT, SLOT_AX, "usr", 0) != 0 || (rights_of(SLOT_AX) & FS_R_ALL) != FS_R_ALL)
        fail("session-admin-usr-narrowed");
    if (sys_cap_revoke(SLOT_AX) != 0) fail("session-admin-revoke2");
    /* NOT EVEN THE ADMINISTRATOR'S "/ all" reaches the store of /tmps, or
     * through it the user's /tmp; its own /tmp is another directory; and the
     * name cannot be made over. */
    if (walk1(SLOT_AROOT, SLOT_AX, FS_SESSION_TMP_STORE_NAME, 0) != SYS_ERR_NOENT ||
        lists_name(SLOT_AROOT, FS_SESSION_TMP_STORE_NAME)) fail("session-tmp-store-visible");
    if (walk1(SLOT_AROOT, SLOT_ATMP, "tmp", 0) != 0 || !lists_name(SLOT_AROOT, "tmp"))
        fail("session-admin-tmp-missing");
    fill(&rq, FS_OP_LOOKUP, "mine");
    if (call(SLOT_ATMP, SLOT_AX, &rq) != SYS_ERR_NOENT) fail("session-tmp-shared");
    fill(&rq, FS_OP_MKDIR, "tmp");
    if (call(SLOT_AROOT, IPC_NO_CAP, &rq) != SYS_ERR_EXIST) fail("session-tmp-remade");
    fill(&rq, FS_OP_DELETE, "tmp");
    if (call(SLOT_AROOT, IPC_NO_CAP, &rq) != SYS_ERR_PERM) fail("session-tmp-deleted");
    if (sys_cap_revoke(SLOT_ATMP) != 0) fail("session-admin-tmp-revoke");
    ok();

    /* THE BOUND COMES FROM WHERE THE OBJECT IS (decision 17). The user's file,
     * reached by the administrator, is reached by its owner too: other bits are
     * every right, though no grant at the administrator's root names anyone
     * else. The administrator's own grants never count as "other" (decision
     * 16), so a file the user cannot reach shows none. */
    if (walk1(SLOT_AROOT, SLOT_AX, "home", "user") != 0) fail("session-admin-walk-home");
    fill(&rq, FS_OP_LOOKUP, "notes");
    if (call(SLOT_AX, SLOT_TX, &rq) != 0) fail("session-admin-lookup-notes");
    if (mode_of(SLOT_TX) != 0707u) fail("session-stat-admin-bound-low");
    if (sys_cap_revoke(SLOT_TX) != 0 || sys_cap_revoke(SLOT_AX) != 0) fail("session-admin-revoke3");
    if (walk1(SLOT_AROOT, SLOT_AX, "etc", 0) != 0) fail("session-admin-walk-etc");
    if (mode_of(SLOT_AX) != 0700u) fail("session-stat-admin-etc-not-private");
    if (sys_cap_revoke(SLOT_AX) != 0) fail("session-admin-revoke4");
    ok();

    /* A RENAME ONTO OR OFF A NAME THE POLICY NAMES IS EXDEV (§5.5 within one
     * directory): under /home every name is some account's home. */
    if (walk1(SLOT_AROOT, SLOT_AX, "home", 0) != 0) fail("session-admin-walk-home2");
    fill(&rq, FS_OP_RENAME, "other");
    ustrncpy((char *)rq.data, "other2", FS_DIRENT_NAME);
    if (call(SLOT_AX, IPC_NO_CAP, &rq) != SYS_ERR_XDEV) fail("session-renamed-policy-name");
    if (sys_cap_revoke(SLOT_AX) != 0) fail("session-admin-revoke5");
    ok();

    fill(&rq, FS_OP_MKDIR, "admdir");
    if (call(SLOT_AROOT, IPC_NO_CAP, &rq) != 0) fail("session-admin-mkdir");
    fill(&rq, FS_OP_DELETE, "admdir");
    if (call(SLOT_AROOT, IPC_NO_CAP, &rq) != 0) fail("session-admin-rmdir");
    ok();

    /* ONLY THROUGH THE UNTOKENED CAPABILITY HOLDING MINT. A WRITE-only copy of
     * it (what SYS_CONNECT_FS_SERVER hands a client) is refused, and so is any
     * tokened capability, however wide. */
    if (sys_cap_mint(SLOT_SNOW, SLOT_PLAIN, CAP_RIGHT_WRITE) != 0) fail("session-mint-nomint");
    fill(&rq, FS_OP_SESSION, 0);
    rq.arg_uid = 1000;
    if (call(SLOT_SNOW, IPC_NO_CAP, &rq) != SYS_ERR_PERM) fail("session-opened-without-mint");
    fill(&rq, FS_OP_SESSION, 0);
    rq.arg_uid = 0;
    if (call(SLOT_ROOT, IPC_NO_CAP, &rq) != SYS_ERR_PERM) fail("session-opened-through-token");
    fill(&rq, FS_OP_SESSION_END, 0);
    rq.offset = sg.g;
    if (call(SLOT_SNOW, IPC_NO_CAP, &rq) != SYS_ERR_PERM) fail("session-ended-without-mint");
    fill(&rq, FS_OP_SESSION, 0);
    rq.arg_uid = 4242;
    if (call(SLOT_PLAIN, IPC_NO_CAP, &rq) != SYS_ERR_NOENT) fail("session-for-no-account");
    ok();

    /* ENDED, IT REACHES NOTHING: fs_server fails closed even before init's
     * revoke (which in a real logout comes first) has swept the capabilities. */
    if (session_end(sg.g) != 0) fail("session-end");
    /* ITS /tmp WENT WITH IT, all twelve levels: asked through step 1's root,
     * which carries no grant set and so sees the store, as init would. */
    {
        char gn[3] = { (char)('0' + sg.g / 10), (char)('0' + sg.g % 10), 0 };
        if (walk1(SLOT_ROOT, SLOT_STORE, FS_SESSION_TMP_STORE_NAME, 0) != 0)
            fail("session-tmp-store-missing");
        fill(&rq, FS_OP_LOOKUP, gn);
        if (call(SLOT_STORE, SLOT_TX, &rq) != SYS_ERR_NOENT) fail("session-tmp-outlived-its-end");
        if (sys_cap_revoke(SLOT_STORE) != 0) fail("session-tmp-store-revoke");
    }
    fill(&rq, FS_OP_STAT, 0);
    if (call(SLOT_SROOT, IPC_NO_CAP, &rq) != SYS_ERR_NOENT) fail("session-outlived-its-end");
    fill(&rq, FS_OP_READ, 0);
    rq.len = 3;
    if (call(SLOT_SF, IPC_NO_CAP, &rq) != SYS_ERR_NOENT) fail("session-file-outlived-its-end");
    if (session_end(sg.g) != SYS_ERR_NOENT) fail("session-ended-twice");
    if (sys_cap_revoke(SLOT_SROOT) != 0 || sys_cap_revoke(SLOT_SCWD) != 0) fail("session-revoke");
    if (session_end(ag.g) != 0 || sys_cap_revoke(SLOT_AROOT) != 0) fail("session-admin-end");
    ok();

    /* GRANT SETS COME BACK: more sessions than there are sets, one at a time. */
    for (int i = 0; i < 2 * FS_SESSIONS_MAX; i++) {
        struct fs_session_grant t;
        if (session_open(1000, &t) != 0 || t.g == 0 || session_end(t.g) != 0)
            fail("session-grant-set-leaked");
    }
    ok();
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

    /* WALK (step 2, decision 12): capdir/wa/wb/wf, reached in one request. */
    fill(&rq, FS_OP_MKDIR, "wa");
    if (call(SLOT_DIR, SLOT_WA, &rq) != 0) fail("mkdir-wa");
    uint32_t wa_ino = ((struct fs_response *)rbuf)->ino;
    fill(&rq, FS_OP_MKDIR, "wb");
    if (call(SLOT_WA, IPC_NO_CAP, &rq) != 0) fail("mkdir-wb");
    {
        const char *p[] = { "wa", "wb" };
        fill_walk(&rq, p, 2);
        if (call(SLOT_DIR, SLOT_WALK, &rq) != 0 ||
            ((struct fs_response *)rbuf)->type != FS_TYPE_DIR) fail("walk-to-dir");
    }
    fill(&rq, FS_OP_CREATE, "wf");
    if (call(SLOT_WALK, IPC_NO_CAP, &rq) != 0) fail("create-through-walked-dir");
    {
        const char *p[] = { "wa", "wb", "wf" };
        fill_walk(&rq, p, 3);
        if (call(SLOT_DIR, SLOT_WFILE, &rq) != 0 ||
            ((struct fs_response *)rbuf)->type != FS_TYPE_FILE) fail("walk-to-file");
    }
    fill(&rq, FS_OP_WRITE, 0);
    rq.len = 4;
    for (int i = 0; i < 4; i++) rq.data[i] = (uint8_t)"walk"[i];
    if (call(SLOT_WFILE, IPC_NO_CAP, &rq) < 0) fail("write-through-walked");
    ok();

    /* ONE CAPABILITY, DERIVED FROM THE ONE INVOKED: nothing along the path holds
     * it up, so revoking a capability to a directory it passed through (wa's,
     * from the mkdir) leaves it working. This is what a LOOKUP chain cannot do. */
    if (sys_cap_revoke(SLOT_WA) != 0) fail("revoke-wa");
    fill(&rq, FS_OP_READ, 0);
    rq.len = 4;
    if (call(SLOT_WFILE, IPC_NO_CAP, &rq) != 4 ||
        ((struct fs_response *)rbuf)->data[0] != 'w') fail("walked-held-up-by-path");
    ok();

    /* NARROWED: a walk through a read-only directory capability gives a
     * read-only file; and with no LOOKUP there is no walk. */
    if (sys_cap_mint(SLOT_DIRRO, SLOT_DIR, CAP_RIGHT_WRITE | FS_R_READ | FS_R_LOOKUP) != 0)
        fail("mint-dir-readonly");
    {
        const char *p[] = { "wa", "wb", "wf" };
        fill_walk(&rq, p, 3);
        if (call(SLOT_DIRRO, SLOT_WRO, &rq) != 0) fail("walk-readonly");
    }
    fill(&rq, FS_OP_WRITE, 0);
    rq.len = 1;
    rq.data[0] = 'X';
    if (call(SLOT_WRO, IPC_NO_CAP, &rq) != SYS_ERR_PERM) fail("walk-widened");
    if (sys_cap_mint(SLOT_NOLOOK, SLOT_DIR, CAP_RIGHT_WRITE | FS_R_READ) != 0) fail("mint-nolookup");
    {
        const char *p[] = { "wa" };
        fill_walk(&rq, p, 1);
        if (call(SLOT_NOLOOK, SLOT_WSCRAP, &rq) != SYS_ERR_PERM) fail("walk-without-lookup");
    }
    ok();

    /* EVERY NAME IS CHECKED, not only the first. The uid path (until step 6)
     * will make an entry called ".." inside wa, so a server that checked only the
     * first name would find it and hand back a capability to it, which is the
     * defect FS_WALK_NAMES_UNCHECKED=1 puts back. Its result is not asserted:
     * the refusals below must hold whether or not it was made. */
    fill(&rq, FS_OP_MKDIR, "..");
    rq.dir_ino = wa_ino;
    (void)call(SLOT_PLAIN, IPC_NO_CAP, &rq);
    {
        const char *dd[]  = { "wa", ".." };
        const char *dot[] = { "wa", "." };
        const char *sl[]  = { "wa", "wb/wf" };
        const char *emp[] = { "wa", "" };
        fill_walk(&rq, dd, 2);
        if (call(SLOT_DIR, SLOT_WSCRAP, &rq) != SYS_ERR_INVAL) fail("walk-dotdot");
        fill_walk(&rq, dot, 2);
        if (call(SLOT_DIR, SLOT_WSCRAP, &rq) != SYS_ERR_INVAL) fail("walk-dot");
        fill_walk(&rq, sl, 2);
        if (call(SLOT_DIR, SLOT_WSCRAP, &rq) != SYS_ERR_INVAL) fail("walk-slash");
        fill_walk(&rq, emp, 2);
        if (call(SLOT_DIR, SLOT_WSCRAP, &rq) != SYS_ERR_INVAL) fail("walk-empty-name");
    }
    /* A request whose last name runs to the end of data[] unterminated, and one
     * with no names at all. */
    fill(&rq, FS_OP_WALK, 0);
    for (unsigned i = 0; i < FS_WALK_BYTES; i++) rq.data[i] = 'a';
    rq.len = FS_WALK_BYTES;
    if (call(SLOT_DIR, SLOT_WSCRAP, &rq) != SYS_ERR_INVAL) fail("walk-unterminated");
    fill(&rq, FS_OP_WALK, 0);
    if (call(SLOT_DIR, SLOT_WSCRAP, &rq) != SYS_ERR_INVAL) fail("walk-no-names");
    ok();

    /* Each step is a LOOKUP: through a file is refused, a missing name is
     * NOENT, and the uid path has no walk at all. */
    {
        const char *thru[] = { "wa", "wb", "wf", "x" };
        const char *miss[] = { "wa", "nope" };
        fill_walk(&rq, thru, 4);
        if (call(SLOT_DIR, SLOT_WSCRAP, &rq) != SYS_ERR_INVAL) fail("walk-through-file");
        fill_walk(&rq, miss, 2);
        if (call(SLOT_DIR, SLOT_WSCRAP, &rq) != SYS_ERR_NOENT) fail("walk-missing");
        fill_walk(&rq, thru, 1);
        if (call(SLOT_PLAIN, IPC_NO_CAP, &rq) != SYS_ERR_NOSYS) fail("walk-on-uid-path");
    }
    /* More names than one request holds: the client is told, not truncated. */
    {
        const char *l = "abcdefghijklmnopqrstuvw";      /* 23, the longest name */
        const char *p[8] = { l, l, l, l, l, l, l, l };  /* 8 x 24 > FS_WALK_BYTES */
        uint32_t len;
        if (fs_walk_pack(rq.data, &len, p, 8) != SYS_ERR_RANGE) fail("walk-pack-overflow");
    }
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
    if (call(SLOT_WFILE, IPC_NO_CAP, &rq) > -1000) fail("walked-survived-revoke");
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

    sessions();

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
