#include "syscall.h"
#include "piperevokee_image.h" /* piperevokee_image[]/_len: the stage this spawns */

/*
 * Revocable pipe ends -- LIMITATIONS 1.14, SECURITY.md S3 and S4 for pipe ends,
 * PIPEREVOKE_SELFTEST builds only. `make smoke-pipe-revoke-child` asserts on
 * the one marker this prints: PIPEREVOKE: PASS, or PIPEREVOKE: FAIL <reason>.
 *
 * WHAT IS UNDER TEST. A pipe end a spawner hands to a child's stdin or stdout
 * is DERIVED from the spawner's end, so revoking the spawner's end removes the
 * child's (S3); the revoke reaches nothing else (S4); and the pipe table's count
 * of ends follows the capabilities exactly, so the peer sees EOF or EPIPE the
 * moment the last opposite end is revoked, and a pipe is freed once and only
 * once its last end is gone.
 *
 * Every phase observes from two sides that cannot both be wrong the same way:
 * the capability graph (SYS_CAP_ENUMERATE on the child's stdio slot, with the
 * CAP_DEBUG the kernel side of the self-test grants) and the pipe's behaviour
 * (EOF, EPIPE, the child's own SYS_ERR_PERM).
 *
 *   W  The child writes; this task holds the reader. Revoking this task's
 *      writer end must empty the child's stdout slot, the child's next write
 *      must answer SYS_ERR_PERM, and this task's reads must reach EOF.
 *   R  The child reads; this task holds the writer. Revoking this task's
 *      reader end must empty the child's stdin slot, and this task's next write
 *      must answer SYS_ERR_PIPE at once.
 *   D  A forked child revokes ITS derived copy of the writer end. The original
 *      must survive (S4), the pipe must still say "would block" rather than EOF
 *      while it lives, and EOF must come when this task closes it: the count
 *      was decremented exactly once for the revoked copy.
 *   L  As many pipes can be created at the end as at the start, so no revoke
 *      above left a pipe allocated (a count too high never frees its pipe).
 *
 * THE ARMS. PIPE_CHILD_END_UNDERIVED=1 installs the child's end as a root, the
 * defect 1.14 recorded: phase W fails "child-end-survived-revoke".
 * PIPE_REVOKE_UNCOUNTED=1 removes the ends but leaves their counts: phase W fails
 * "no-eof-after-revoke". smoke-pipe-revoke-child-control and
 * smoke-pipe-revoke-uncounted-control require exactly those markers.
 *
 * Bounded waits are counted in yields, generously: every wait here is for
 * something that is already true or happens within a few scheduling rounds,
 * and the negative waits (no EOF) are what the arms exercise.
 */

/* Must match userspace/piperevokee.c. */
#define PR_SLOT_GONE   27
#define PR_SLOT_OTHER  28

#define CAP_TYPE_PIPE  13          /* CAP_PIPE in src/include/kernel.h */
#define SPIN_LIMIT     200000

static void report(const char *s) {
    int n = 0;
    while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* ONE write per marker: a gated marker assembled from several writes can be
 * split by another writer on the shared console (LIMITATIONS 2.6a). */
static void fail(const char *why) {
    char line[96];
    const char *pfx = "PIPEREVOKE: FAIL ";
    unsigned n = 0;
    while (*pfx && n < sizeof(line) - 2) line[n++] = *pfx++;
    while (*why && n < sizeof(line) - 2) line[n++] = *why++;
    line[n++] = '\n';
    line[n] = 0;
    report(line);
    sys_exit();
}

static int slot_view(int tid, unsigned slot, struct cap_info *ci) {
    return sys_cap_enumerate(tid, slot, ci) == 0;
}

static int wait_for_slot(int tid, unsigned slot) {
    struct cap_info ci;
    for (int i = 0; i < SPIN_LIMIT; i++) {
        if (slot_view(tid, slot, &ci) && ci.occupied) return 1;
        sys_yield();
    }
    return 0;
}

/* Spawn piperevokee with one end wired in and let it run. */
static int spawn_stage(const char *mode, uint32_t in_slot, uint32_t out_slot) {
    char *argv[3] = { (char *)"piperevokee", (char *)mode, 0 };
    int pid = sys_spawn_image_stdio(piperevokee_image, piperevokee_image_len, 2, argv,
                                    in_slot, out_slot);
    if (pid <= 0) return -1;
    if (sys_task_resume(pid) != 0) return -1;
    return pid;
}

static void reap(int pid) {
    (void)sys_kill(pid);
    (void)sys_wait(pid);
}

/* How many pipes can this task create right now? Each is closed again. */
static int pipes_available(void) {
    static int held[64];
    int n = 0;
    while (n < 64) {
        int rw = sys_pipe();
        if (rw < 0) break;
        held[n++] = rw;
    }
    for (int i = 0; i < n; i++) {
        (void)sys_pipe_close((uint32_t)held[i] >> 16);
        (void)sys_pipe_close((uint32_t)held[i] & 0xFFFFu);
    }
    return n;
}

static void phase_writer_revoked(int me) {
    struct cap_info ci;
    int rw = sys_pipe();
    if (rw < 0) fail("pipe-w");
    uint32_t pr = (uint32_t)rw >> 16, pw = (uint32_t)rw & 0xFFFFu;

    /* The precondition: SYS_PIPE's ends carry REVOKE, or nothing below can run. */
    if (!slot_view(me, pw, &ci) || !ci.occupied || !(ci.rights & CAP_RIGHT_REVOKE))
        fail("pipe-end-lacks-revoke");

    int kid = spawn_stage("w", 0, pw);
    if (kid < 0) fail("spawn-writer");

    /* The child holds a writer end and nothing more: no REVOKE, so a spawned
     * stage can use its end but take nothing back. */
    if (!slot_view(kid, STDOUT_PIPE_SLOT, &ci) || !ci.occupied || ci.type != CAP_TYPE_PIPE)
        fail("child-has-no-stdout-end");
    if (ci.rights != CAP_RIGHT_WRITE) fail("child-end-not-write-alone");

    /* The child is alive and writing through its end before anything is revoked. */
    char b;
    int got = 0;
    for (int i = 0; i < SPIN_LIMIT && !got; i++) {
        int r = sys_pipe_read(pr, &b, 1);
        if (r == 1) got = 1;
        else if (r == SYS_ERR_AGAIN) sys_yield();
        else fail("read-before-revoke");
    }
    if (!got) fail("child-never-wrote");

    if (sys_cap_revoke(pw) != 0) fail("revoke-own-writer-refused");
    if (!slot_view(me, pw, &ci) || ci.occupied) fail("own-writer-survived-revoke");

    /* S3: the child's end was derived from the one revoked, so it is gone. */
    if (!slot_view(kid, STDOUT_PIPE_SLOT, &ci)) fail("enumerate-child-w");
    if (ci.occupied) fail("child-end-survived-revoke");

    /* The count came down with it: once the bytes already written are read, the
     * next read is EOF. A count left at one answers "would block" forever. */
    int eof = 0;
    for (int i = 0; i < SPIN_LIMIT && !eof; i++) {
        int r = sys_pipe_read(pr, &b, 1);
        if (r == 0) eof = 1;
        else if (r == SYS_ERR_AGAIN) sys_yield();
        else if (r != 1) fail("read-after-revoke");
    }
    if (!eof) fail("no-eof-after-revoke");

    /* And the child, from its side, no longer has an end to write through. */
    if (!wait_for_slot(kid, PR_SLOT_GONE)) fail("child-never-saw-its-end-gone");
    if (slot_view(kid, PR_SLOT_OTHER, &ci) && ci.occupied) fail("child-saw-epipe-w");

    reap(kid);
    if (sys_pipe_close(pr) != 0) fail("close-reader-w");
}

static void phase_reader_revoked(void) {
    struct cap_info ci;
    int rw = sys_pipe();
    if (rw < 0) fail("pipe-r");
    uint32_t pr = (uint32_t)rw >> 16, pw = (uint32_t)rw & 0xFFFFu;

    int kid = spawn_stage("r", pr, 0);
    if (kid < 0) fail("spawn-reader");
    if (!slot_view(kid, STDIN_PIPE_SLOT, &ci) || !ci.occupied || ci.type != CAP_TYPE_PIPE)
        fail("child-has-no-stdin-end");
    if (ci.rights != CAP_RIGHT_READ) fail("child-end-not-read-alone");

    char b = 'y';
    if (sys_pipe_write(pw, &b, 1) != 1) fail("write-before-revoke");

    if (sys_cap_revoke(pr) != 0) fail("revoke-own-reader-refused");
    if (!slot_view(kid, STDIN_PIPE_SLOT, &ci)) fail("enumerate-child-r");
    if (ci.occupied) fail("child-stdin-survived-revoke");

    /* No reader end exists, and the count says so before the revoke returns. */
    if (sys_pipe_write(pw, &b, 1) != SYS_ERR_PIPE) fail("no-epipe-after-revoke");

    if (!wait_for_slot(kid, PR_SLOT_GONE)) fail("child-never-saw-stdin-gone");
    if (slot_view(kid, PR_SLOT_OTHER, &ci) && ci.occupied) fail("child-saw-eof-r");

    reap(kid);
    if (sys_pipe_close(pw) != 0) fail("close-writer-r");
}

static void phase_derived_revoke_spares_ancestor(int me) {
    struct cap_info ci;
    int rw = sys_pipe();
    if (rw < 0) fail("pipe-d");
    uint32_t pr = (uint32_t)rw >> 16, pw = (uint32_t)rw & 0xFFFFu;

    int child = sys_fork();
    if (child < 0) fail("fork");
    if (child == 0) {
        /* The forked copy of the writer end carries REVOKE, as fork copies
         * rights. Revoking it takes only this copy. Then exit: the teardown
         * closes this task's copy of the reader end in the ordinary way. */
        if (sys_cap_revoke(pw) != 0) report("PIPEREVOKE: FAIL forked-revoke-refused\n");
        sys_exit();
    }
    if (sys_wait(child) != 0) fail("wait-fork");

    /* S4: the ancestor this task holds is untouched... */
    if (!slot_view(me, pw, &ci) || !ci.occupied || ci.type != CAP_TYPE_PIPE)
        fail("ancestor-end-revoked");
    /* ...and still counted: one writer is left, so an empty read would block. */
    char b = 'z';
    int r = sys_pipe_read(pr, &b, 1);
    if (r == 0) fail("eof-while-a-writer-lives");
    if (r != SYS_ERR_AGAIN) fail("read-after-derived-revoke");
    if (sys_pipe_write(pw, &b, 1) != 1) fail("write-after-derived-revoke");
    b = 0;
    if (sys_pipe_read(pr, &b, 1) != 1 || b != 'z') fail("pipe-broken-after-derived-revoke");

    /* Exactly one writer was left: closing it is the EOF. */
    if (sys_pipe_close(pw) != 0) fail("close-writer-d");
    if (sys_pipe_read(pr, &b, 1) != 0) fail("no-eof-after-last-writer");
    if (sys_pipe_close(pr) != 0) fail("close-reader-d");
}

void _start(void) {
    int me = sys_getpid();
    struct cap_info ci;
    if (!slot_view(me, CAPSLOT_TCB, &ci)) fail("no-cap-debug");

    int before = pipes_available();
    if (before <= 2) fail("too-few-pipes");

    phase_writer_revoked(me);
    phase_reader_revoked();
    phase_derived_revoke_spares_ancestor(me);

    int after = pipes_available();
    if (after != before) fail("pipe-leaked");

    report("PIPEREVOKE: PASS\n");
    sys_exit();
}
