/* libhorus — the shared runtime for freestanding Horus userspace programs.
 *
 * WHY THIS EXISTS. There are two ways to link a userspace binary here. The
 * newlib path (userspace/crt0.c + posix.c + -lc) gives a real libc and costs
 * ~450 KiB statically per binary; it is what coreutils and tcc use. The
 * freestanding path links the program's own object plus malloc.o and nothing
 * else — and it is what every *server* uses: init, shell, fs_server,
 * console_server. Those are the programs where new userspace work happens, and
 * until now they had no shared runtime at all.
 *
 * The result was 22 hand-copied definitions across 7 files. umemset and umemcpy
 * were written out four times, uslen three, and the same string-equality
 * function existed twice under two names (ueq, ustreq). Each copy was correct,
 * which is precisely what made it a problem: nothing was wrong, so nothing
 * pushed back, and the next server would have made it 26.
 *
 * THE PART THAT IS NOT COSMETIC. ipc_call_retry() below is a security-relevant
 * policy, not a convenience. include/syscall.h:559-567 states the retry contract
 * — retry on ipc_transient() only, and bound even that — because the earlier
 * form, `while (r < 0) spin_delay();`, retried SYS_ERR_PERM forever. That turned
 * a clean capability refusal into an unkillable silent hang, and it is finding
 * G-8 signature C. Two programs had independently re-derived the correct loop,
 * comment and all. A third would have been written from scratch by whoever wrote
 * the next server, under deadline, from memory. Encoding the contract once is
 * the difference between a rule and a habit.
 *
 * WHAT IS DELIBERATELY NOT HERE. This is not a libc and must not grow into one.
 * It holds what more than one freestanding program needed and nothing else. In
 * particular it declares no allocator (malloc.o is already linked into every
 * binary by the pattern rule) and no file I/O (that is the fs_proto.h RPC
 * surface, which is a capability-mediated protocol rather than a library call).
 * Anything that would need authority to implement does not belong in a library:
 * it belongs behind a capability. Adding a function here that takes authority
 * from ambient state, rather than from a slot the caller names, is a defect.
 *
 * NAMING. The existing names are kept exactly — umemset, not hz_memset — so
 * that migrating a program is a pure deletion of its private copy plus one
 * #include, with every call site untouched. That was worth more than a tidier
 * prefix: four of the seven migrated files are security-critical under
 * .github/CODEOWNERS, and a reviewer can confirm at a glance that no call site
 * changed meaning.
 */
#ifndef LIBHORUS_H
#define LIBHORUS_H

#include <stdint.h>
#include "syscall.h"

/* ---- memory ----------------------------------------------------------- */

/* Byte-wise set and copy. `n` is unsigned rather than size_t to match every
 * call site these replaced; the messages they operate on are bounded by
 * IPC_MSG_MAX (256 bytes), so 32 bits is not a limit anything reaches.
 * umemcpy does NOT handle overlap — no caller needed it, and a memmove that
 * nobody exercises is a memmove nobody has tested. */
void umemset(void *d, int v, unsigned n);
void umemcpy(void *d, const void *s, unsigned n);

/* ---- strings ---------------------------------------------------------- */

/* Length of a NUL-terminated string, not counting the NUL. */
unsigned uslen(const char *s);

/* String equality. Returns non-zero when equal — note this is the opposite
 * sense from strcmp(), which is why it is not called that. Both former copies
 * (fsclient's `ueq`, fs_server's `ustreq`) had this sense; the name `ustreq`
 * won because it says so. */
int ustreq(const char *a, const char *b);

/* Bounded copy that ALWAYS terminates. Copies at most n-1 bytes and writes the
 * NUL, so the destination is a valid C string for any n >= 1. This is strlcpy's
 * contract, not strncpy's: strncpy leaves the destination unterminated exactly
 * when the source did not fit, which is the case a caller is least likely to
 * have tested. n == 0 writes nothing. */
void ustrncpy(char *d, const char *s, unsigned n);

/* ---- console output --------------------------------------------------- */

/* Write a NUL-terminated string to fd 1. Goes through SYS_WRITE; SYS_PRINT is
 * not dispatched. Ungated by design — a terminal write is not an authority this
 * system rations (docs/LIMITATIONS.md §1.6) — and since [H-2] it carries nothing
 * else with it: fd 1 no longer also appends to the kernel message ring, whose
 * read side requires CAP_KERNEL_LOG. */
void kput(const char *s);

/* kput followed by a newline, as a single logical line. */
/* Emit `prefix` and `detail` as one write, newline-terminated. Use this for any
 * marker a gate asserts on as a single string -- see the definition. */
void kput_marker(const char *prefix, const char *detail);
void kputln(const char *s);

/* Write a signed decimal. Handles INT_MIN by accumulating into unsigned, which
 * the negation -(unsigned)v does correctly where -v would overflow. */
void kput_int(int v);

/* ---- timing ----------------------------------------------------------- */

/* Busy-wait. There is no sleep to call: SYS_CLOCK_GETTIME and timer
 * notifications are roadmap 2.2 and do not exist yet, so a bounded spin is the
 * only backoff available between IPC retries. The loop counter is volatile so
 * the compiler cannot delete it.
 *
 * spin_delay() is the 40,000-iteration default that five of the six former
 * copies used. spin_delay_n() exists because the sixth did not:
 * recvblockcli.c deliberately spins ten times longer, and collapsing that to
 * the default would have silently changed the timing of a blocking-receive test
 * whose entire subject is timing. A dedup that alters behaviour is not a dedup. */
void spin_delay_n(unsigned iters);
void spin_delay(void);

/* ---- IPC -------------------------------------------------------------- */

/* Returned when the retry bound is reached. Distinct from any kernel rc, and
 * the value both former copies already used. */
#define IPC_ERR_RETRY_EXHAUSTED (-103)

/* How many transient refusals to absorb before giving up. Large because the
 * contended case is another client's request briefly occupying the mailbox, and
 * finite because "retry until it works" is the defect this exists to prevent. */
#define IPC_RETRY_MAX 2000000u

/* One blocking IPC round-trip that obeys the retry contract in syscall.h.
 *
 * Retries ONLY while ipc_transient(rc) — that is, IPC_AGAIN, the request mailbox
 * momentarily full — and at most IPC_RETRY_MAX times. Any other negative return
 * is a PERMANENT refusal and is returned to the caller immediately, unretried:
 * SYS_ERR_PERM means "you hold no capability for this endpoint", and spinning on
 * it hides the one event the capability system exists to make visible.
 *
 * Returns the sys_ipc_call return value (>= 0 on success), the permanent
 * negative rc unchanged, or IPC_ERR_RETRY_EXHAUSTED.
 *
 * The caller still validates the reply's protocol magic. That is deliberately
 * not done here: the magic field's offset and value are protocol-specific
 * (fs_proto.h and console_proto.h differ), and a library that took a byte offset
 * and a constant on trust would be a worse check than the three lines it saved. */
int ipc_call_retry(int ep_slot, uint32_t badge,
                   const void *req, unsigned req_len, void *rep);

/* ---- hvfs: the mount table and path walker (roadmap 2.4) --------------- */

/* Horus has no VFS server, and that is a security decision rather than an
 * omission: one would have to hold a capability to every backing filesystem,
 * making it the most privileged task in ring 3 and a single point whose
 * compromise is a compromise of every mount. The namespace lives in each client
 * instead, over the capabilities that client already holds, so crossing a mount
 * point is choosing a different endpoint slot and there is no intermediary to
 * compromise.
 *
 * READ THIS BEFORE TRUSTING A PATH. A mount prefix is a NAME, not a boundary.
 * A task holding no capability for a mount cannot reach that subtree whatever
 * path it writes (SECURITY.md S29) -- but a task that DOES hold a server's
 * capability reaches all of that server, mounted or not. Confinement is the
 * server's job; the table only decides which server a path is addressed to.
 *
 * The table is per-task, so no task can install a mount into another's
 * namespace. Inheritance across spawn is roadmap 2.3 and does not exist. */

#define HVFS_MAX_MOUNTS   4    /* bounded, fixed .bss, per task            */
#define HVFS_PREFIX_MAX  31    /* longest mount prefix, NUL not counted    */
#define HVFS_MAX_DEPTH   16    /* path components; matches the old walkers */

#define HVFS_ERR_INVAL  (-1)   /* bad prefix, bad path, malformed reply    */
#define HVFS_ERR_NOCAP  (-2)   /* the slot holds no usable capability      */
#define HVFS_ERR_EXIST  (-3)   /* something is already mounted there       */
#define HVFS_ERR_NOMEM  (-4)   /* HVFS_MAX_MOUNTS reached                  */

struct fs_request;
struct fs_response;

struct hvfs_mount {
    const char *prefix;    /* borrowed, not copied: callers pass literals */
    unsigned    plen;
    int         ep_slot;   /* cspace slot holding this mount's CAP_ENDPOINT */
    uint32_t    root_ino;  /* the inode a path under `prefix` starts from   */
    int         in_use;
};

/* Install a mount. Refuses a non-absolute or overlong prefix, a duplicate, a
 * full table, and -- the gate -- a slot holding no usable capability, probed
 * with the weakest legal request rather than by asking the kernel what is in
 * the slot. Returns 0 or a negative HVFS_ERR_*. */
int hvfs_mount(const char *prefix, int ep_slot, uint32_t root_ino);

/* LONGEST-prefix match, so "/dev/zero" reaches the /dev mount and not the "/"
 * one that also matches. First-match would address it to the root filesystem,
 * which has an inode 0 of its own and therefore ANSWERS ABOUT A DIFFERENT
 * OBJECT rather than failing. Returns NULL if nothing covers the path. */
const struct hvfs_mount *hvfs_resolve(const char *path);

/* One request/reply on a mount's endpoint. Fills in the protocol magic and
 * validates the reply's. Returns the server's rc, or a negative HVFS_ERR_*. */
int hvfs_rpc(int ep_slot, struct fs_request *rq, struct fs_response *rp);

/* THE path walker -- the single copy, replacing the three private ones that
 * used to live in posix.c, shell.c and fsclient.c.
 *
 * Resolves `path` (absolute, or relative to cwd_ino on cwd_slot) and reports
 * which mount answered. Contract, unchanged from the walkers it replaces:
 *    0  -> resolved; *out_ino is the object
 *    1  -> everything but the last component resolved; *out_ino is the PARENT
 *          and out_name is the final component (so a caller can create it)
 *   -1  -> bad path, or an intermediate component missing
 * out_name needs FS_NAME_MAX bytes. ".." is pinned at the mount root. */
int hvfs_walk(const char *path, uint32_t cwd_ino, int cwd_slot,
              int *out_slot, uint32_t *out_ino, char *out_name);

/* As hvfs_walk, but stops before the LAST component and reports the directory
 * that holds it, without looking the leaf up. open(O_CREAT), mkdir, unlink and
 * rename all need the parent whether or not the leaf exists. Returns 0 with
 * *out_ino = the parent and out_name = the final component, or -1. A path with
 * no final component ("/" or all slashes) yields an empty out_name, which the
 * caller must reject. */
int hvfs_walk_parent(const char *path, uint32_t cwd_ino, int cwd_slot,
                     int *out_slot, uint32_t *out_ino, char *out_name);

#endif /* LIBHORUS_H */
