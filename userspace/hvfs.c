/* hvfs -- the Horus VFS: a mount table and one path walker (roadmap 2.4, [F-2.2]).
 *
 * WHY THIS IS A LIBRARY AND NOT A SERVER.
 *
 * The obvious VFS is a server: clients send it paths, it forwards to whichever
 * backing filesystem owns the subtree. That design has to hold a capability to
 * EVERY backing store, which makes it the most privileged task in ring 3 and a
 * single point whose compromise is a compromise of every mount. It is the
 * monolithic-VFS trust that roadmap 2.4 exists to avoid: "each server holds only
 * the object-store capabilities for its own subtree".
 *
 * So the namespace lives here, in each client, over capabilities that client
 * holds. Crossing a mount point is choosing a different endpoint slot. There is
 * no privileged intermediary because there is no intermediary.
 *
 * WHAT THIS DOES AND DOES NOT ENFORCE -- read this before trusting a path.
 *
 * A mount prefix is a NAME, not a boundary. Authority is the capability in the
 * slot; the prefix is how a program spells it. Two consequences, both deliberate:
 *
 *   - A task that holds no capability for a mount cannot reach that subtree at
 *     all, whatever path it writes. That is the property worth having, and it is
 *     structural: hvfs_rpc sends on the mount's slot, and an empty or wrong-type
 *     slot fails the kernel's IPC capability gate. This is S29.
 *
 *   - A task that DOES hold a server's capability reaches all of that server,
 *     regardless of where it is mounted or whether it is mounted at all. Mounting
 *     `dev_server` at /dev does not confine it to /dev. Confinement is the
 *     server's job (fs_server is a reference monitor over kernel-attested uid);
 *     the mount table only decides which server a path is addressed to.
 *
 * Stating that plainly is the point of this comment. A VFS that looked like it
 * enforced a boundary it does not is worse than one that never claimed to.
 *
 * The table is per-task .bss, so one task's mounts are invisible to every other
 * task and no task can install a mount into another's namespace. Namespace
 * inheritance across spawn is roadmap 2.3 and does not exist yet.
 */
#include "syscall.h"
#include "libhorus.h"
#include "fs_proto.h"

static struct hvfs_mount g_mounts[HVFS_MAX_MOUNTS];

/* ---- helpers ----------------------------------------------------------- */

static unsigned pfx_len(const char *s) {
    unsigned n = 0;
    while (s[n]) n++;
    return n;
}

/* Does `path` lie under `prefix`? A prefix matches only at a component
 * boundary, so "/devices/x" is NOT under "/dev" -- the check that a plain
 * string compare gets wrong, and it would route one server's paths to another. */
static int under_prefix(const char *path, const char *prefix, unsigned plen) {
    if (plen == 1 && prefix[0] == '/') return 1;      /* "/" is under everything */
    for (unsigned i = 0; i < plen; i++)
        if (path[i] != prefix[i]) return 0;
    return path[plen] == '\0' || path[plen] == '/';
}

/* ---- mounting ---------------------------------------------------------- */

int hvfs_mount(const char *prefix, int ep_slot, uint32_t root_ino) {
    if (!prefix || prefix[0] != '/')  return HVFS_ERR_INVAL;
    unsigned plen = pfx_len(prefix);
    if (plen == 0 || plen > HVFS_PREFIX_MAX) return HVFS_ERR_INVAL;
    if (ep_slot < 0)                  return HVFS_ERR_INVAL;

    /* THE GATE. A mount must be backed by a capability this task actually
     * holds, or a prefix string alone would install one -- and every path under
     * it would then be addressed to a slot with nothing in it. Refusing here
     * turns that into an error at mount time instead of a confusing IPC failure
     * per operation later, and it is what makes "the namespace is not authority"
     * true in the useful direction: you cannot name your way into a mount.
     *
     * The probe is a real request, because there is no syscall that reads a
     * capability's contents and there should not be one -- asking the kernel
     * "what is in slot n" would be a capability-introspection primitive. So the
     * weakest legal operation IS the probe: look up the mount root, which any
     * holder of the endpoint may do and which discloses nothing a holder does
     * not already have.
     *
     * Under VFS_MOUNT_UNGATED=1 the probe is skipped and the prefix alone
     * installs the mount. */
#ifndef VFS_MOUNT_UNGATED
    {
        struct fs_request rq;
        struct fs_response rp;
        umemset(&rq, 0, sizeof(rq));
        rq.op      = FS_OP_STAT;
        rq.ino     = root_ino;
        if (hvfs_rpc(ep_slot, &rq, &rp) < 0) return HVFS_ERR_NOCAP;
    }
#endif

    int free_slot = -1;
    for (int i = 0; i < HVFS_MAX_MOUNTS; i++) {
        if (!g_mounts[i].in_use) { if (free_slot < 0) free_slot = i; continue; }
        if (g_mounts[i].plen == plen &&
            under_prefix(g_mounts[i].prefix, prefix, plen) &&
            g_mounts[i].plen == plen)
            return HVFS_ERR_EXIST;               /* already mounted there */
    }
    if (free_slot < 0) return HVFS_ERR_NOMEM;

    g_mounts[free_slot].prefix   = prefix;
    g_mounts[free_slot].plen     = plen;
    g_mounts[free_slot].ep_slot  = ep_slot;
    g_mounts[free_slot].root_ino = root_ino;
    g_mounts[free_slot].in_use   = 1;
    return 0;
}

/* Longest-prefix match.
 *
 * "/" matches every path and "/dev" matches a subset of them, so a table
 * scanned in installation order answers whichever was installed first. That is
 * not a preference: with "/" first, EVERY /dev path is addressed to the root
 * filesystem server -- a request for /dev/zero arrives at a server that has an
 * inode 0 of its own, so it does not fail, it answers about a DIFFERENT OBJECT.
 * Wrong-server-answered is the failure mode, not permission-denied, which is
 * why the witness checks which server replied rather than the return code.
 *
 * Under VFS_FIRST_MATCH=1 the first match wins and that is exactly what happens. */
const struct hvfs_mount *hvfs_resolve(const char *path) {
    const struct hvfs_mount *best = 0;
    for (int i = 0; i < HVFS_MAX_MOUNTS; i++) {
        if (!g_mounts[i].in_use) continue;
        if (!under_prefix(path, g_mounts[i].prefix, g_mounts[i].plen)) continue;
#ifdef VFS_FIRST_MATCH
        return &g_mounts[i];
#else
        if (!best || g_mounts[i].plen > best->plen) best = &g_mounts[i];
#endif
    }
    return best;
}

int hvfs_rpc(int ep_slot, struct fs_request *rq, struct fs_response *rp) {
    rq->magic = FS_PROTO_MAGIC;
    umemset(rp, 0, sizeof(*rp));
    int r = sys_ipc_call(ep_slot, 0, (const void *)rq, (uint32_t)sizeof(*rq),
                         (void *)rp);
    if (r < 0)                       return HVFS_ERR_NOCAP;
    if (rp->magic != FS_PROTO_MAGIC) return HVFS_ERR_INVAL;
    return rp->rc;
}

/* ---- the one walker ---------------------------------------------------- */

/* Shared body. `want_parent` stops before the LAST component and reports the
 * directory holding it, which is what open(O_CREAT), mkdir, unlink and rename
 * need -- they must address the parent whether or not the leaf exists, and
 * hvfs_walk cannot answer that because on success it has already moved past it.
 *
 * One body rather than two walkers, because that is the entire point of this
 * file: posix.c, shell.c and fsclient.c each carried their own copy of this
 * loop, and the copies had drifted (only one of them handled ".."). A second
 * copy here would have re-created the problem inside the fix. */
static int walk_body(const char *path, uint32_t cwd_ino, int cwd_slot,
                     int want_parent,
                     int *out_slot, uint32_t *out_ino, char *out_name);

int hvfs_walk_parent(const char *path, uint32_t cwd_ino, int cwd_slot,
                     int *out_slot, uint32_t *out_ino, char *out_name) {
    return walk_body(path, cwd_ino, cwd_slot, 1, out_slot, out_ino, out_name);
}

int hvfs_walk(const char *path, uint32_t cwd_ino, int cwd_slot,
              int *out_slot, uint32_t *out_ino, char *out_name) {
    return walk_body(path, cwd_ino, cwd_slot, 0, out_slot, out_ino, out_name);
}

static int walk_body(const char *path, uint32_t cwd_ino, int cwd_slot,
                     int want_parent,
                     int *out_slot, uint32_t *out_ino, char *out_name) {
    if (!path || path[0] == '\0' || !out_slot || !out_ino || !out_name) return -1;

    uint32_t dir_ino;
    int      slot;
    uint32_t mount_root;
    const char *p = path;

    if (path[0] == '/') {
        const struct hvfs_mount *m = hvfs_resolve(path);
        if (!m) return -1;                     /* nothing mounted covers it */
        slot       = m->ep_slot;
        dir_ino    = m->root_ino;
        mount_root = m->root_ino;
        /* Skip the mount prefix; what remains is relative to that mount's root.
         * "/" has plen 1 and no component to skip. */
        p = path + (m->plen == 1 ? 1 : m->plen);
        if (*p == '/') p++;
    } else {
        slot       = cwd_slot;
        dir_ino    = cwd_ino;
        mount_root = cwd_ino;   /* conservative: a relative walk cannot rise
                                 * above where it started (see "..") */
    }

    *out_slot   = slot;
    out_name[0] = '\0';

    char comp[FS_NAME_MAX];
    int  depth = 0;

    /* Inodes descended THROUGH, innermost last, so ".." can step back without
     * asking anyone. Bounded by HVFS_MAX_DEPTH, which already bounds the walk;
     * `mount_root` itself is never pushed, which is what pins ".." there. */
    uint32_t desc[HVFS_MAX_DEPTH];
    int      ndesc = 0;
#ifndef HVFS_DOTDOT_SERVER
    /* `mount_root` is read only by the control arm now: an empty descent stack
     * is the same condition, computed locally. Kept assigned above so the two
     * arms differ in one place. */
    (void)mount_root;
#endif

    while (*p) {
        unsigned clen = 0;
        while (p[clen] && p[clen] != '/') clen++;
        if (clen == 0)           { p++; continue; }      /* "//" */
        if (clen >= FS_NAME_MAX) return -1;
        if (++depth > HVFS_MAX_DEPTH) return -1;

        umemcpy(comp, p, clen);
        comp[clen] = '\0';
        p += clen;
        if (*p == '/') p++;

        /* "." is this directory; ".." is the parent, PINNED AT THE MOUNT ROOT.
         * Letting ".." rise past it would hand the caller an inode number that
         * means something entirely different on the other side of the mount --
         * not a permission escape (the slot does not change, so it is still the
         * same server) but a silent aliasing bug, and exactly the kind a real
         * VFS pins its mount points to prevent.
         *
         * ".." POPS THE WALKER'S OWN STACK; it does not ask the server. Until
         * 2026-08-23 it sent a LOOKUP for a ".." entry, and `fs_server` creates
         * no "." or ".." dirents at all -- `dir_add` links exactly the one name
         * mkdir was given -- so that branch could only ever return NOENT. It was
         * dead against the only real filesystem in this tree, and nothing
         * noticed because the one test for ".." used the PINNED case (vfstest
         * check 9, "/dev/.."), which returns before the lookup.
         *
         * Popping is also the better contract for a per-client namespace: the
         * parent of a component this walker descended through is something the
         * walker KNOWS. Asking the server makes the answer something the server
         * asserts, and a compromised or buggy one could answer ".." with any
         * inode it liked -- including one the client had already been refused. */
        if (comp[0] == '.' && comp[1] == '\0') continue;
        if (comp[0] == '.' && comp[1] == '.' && comp[2] == '\0') {
#ifdef HVFS_DOTDOT_SERVER
            /* CONTROL ARM: the pre-2026-08-23 branch, restored. */
            if (dir_ino == mount_root) continue;
            struct fs_request rq; struct fs_response rp;
            umemset(&rq, 0, sizeof(rq));
            rq.op = FS_OP_LOOKUP; rq.dir_ino = dir_ino;
            ustrncpy(rq.name, "..", FS_NAME_MAX);
            if (hvfs_rpc(slot, &rq, &rp) != 0) return -1;
            dir_ino = rp.ino;
#else
            if (ndesc == 0) continue;                    /* pinned at the root */
            dir_ino = desc[--ndesc];
#endif
            continue;
        }

        struct fs_request rq;
        struct fs_response rp;
        umemset(&rq, 0, sizeof(rq));
        rq.op      = FS_OP_LOOKUP;
        rq.dir_ino = dir_ino;
        umemcpy(rq.name, comp, clen + 1u);

        if (*p != '\0') {
            /* An intermediate component must exist. */
            if (hvfs_rpc(slot, &rq, &rp) != 0) return -1;
            if (ndesc < HVFS_MAX_DEPTH) desc[ndesc++] = dir_ino;
            dir_ino = rp.ino;
        } else {
            /* The last one may not, and the caller decides what that means --
             * open(O_CREAT) needs the parent and the name, stat needs an error.
             * Same contract as the three private walkers this replaces. */
            umemcpy(out_name, comp, clen + 1u);
            if (want_parent) { *out_ino = dir_ino; return 0; }   /* parent, leaf unlooked */
            if (hvfs_rpc(slot, &rq, &rp) == 0) { *out_ino = rp.ino; return 0; }
            *out_ino = dir_ino;
            return 1;
        }
    }

    /* Path was the mount point itself ("/", "/dev", or all slashes). */
    *out_ino = dir_ino;
    out_name[0] = '\0';
    return 0;
}
