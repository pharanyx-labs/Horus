/*
 * Bounded in-kernel byte pipes for shell pipelines (userspace milestone).
 *
 * A pipe is a fixed-size ring buffer with two directions of capability end
 * (CAP_PIPE, direction in the rights bit). Design choices, deliberately:
 *
 *  - **No kernel blocking.** A read on an empty pipe (writers still open) or a
 *    write to a full pipe (reader still open) returns SYS_ERR_AGAIN; userspace
 *    (posix.c) retries after sys_yield(). This keeps pipes entirely clear of the
 *    delicate SMP block/wake machinery (pending_block / saved_ksp frame patching)
 *    — the part of the kernel that has historically been the source of real SMP
 *    bugs. Back-pressure is preserved (a writer cannot outrun a slow reader).
 *  - **Bounded + pooled.** PIPE_BUF_BYTES per pipe, MAX_PIPES total — no unbounded
 *    kernel memory, and a freed pipe is scrubbed so a reused one leaks nothing.
 *  - **Capability-scoped.** Only a task holding a pipe-end cap can touch it; the
 *    direction is enforced by cap_lookup's rights mask (READ vs WRITE).
 *  - **Correct EOF/EPIPE via end refcounts.** reader_ends / writer_ends count the
 *    live end caps across all cspaces; a reader sees EOF (0) when writer_ends hits
 *    0, a writer sees SYS_ERR_PIPE when reader_ends hits 0. Ends are unref'd on
 *    SYS_PIPE_CLOSE and by task_teardown (pipe_close_task_ends), so a stage that
 *    exits — cleanly or on a fault — always releases its ends.
 */

#include "kernel.h"
#include "errno.h"

struct pipe pipes[MAX_PIPES];
static spinlock_t pipe_lock;

/* Per-syscall transfer cap: bounds the on-stack staging buffer and keeps a single
 * read/write short; posix.c loops for larger transfers. */
#define PIPE_IO_CHUNK 1024

int pipe_alloc(void) {
    spin_lock(&pipe_lock);
    for (int i = 0; i < MAX_PIPES; i++) {
        if (!pipes[i].in_use) {
            struct pipe *p = &pipes[i];
            p->in_use = 1;
            p->head = 0; p->count = 0;
            p->reader_ends = 0; p->writer_ends = 0;
            spin_unlock(&pipe_lock);
            return i;
        }
    }
    spin_unlock(&pipe_lock);
    return -1;
}

void pipe_end_ref(int idx, int is_writer) {
    if (idx < 0 || idx >= MAX_PIPES) return;
    spin_lock(&pipe_lock);
    if (pipes[idx].in_use) {
        if (is_writer) pipes[idx].writer_ends++;
        else           pipes[idx].reader_ends++;
    }
    spin_unlock(&pipe_lock);
}

void pipe_end_unref(int idx, int is_writer) {
    if (idx < 0 || idx >= MAX_PIPES) return;
    spin_lock(&pipe_lock);
    struct pipe *p = &pipes[idx];
    if (p->in_use) {
        if (is_writer) { if (p->writer_ends) p->writer_ends--; }
        else           { if (p->reader_ends) p->reader_ends--; }
        if (p->reader_ends == 0 && p->writer_ends == 0) {
            secure_zero(p->buf, sizeof(p->buf));   /* no residue in a reused pipe */
            p->in_use = 0; p->head = 0; p->count = 0;
        }
    }
    spin_unlock(&pipe_lock);
}

/* Ring core operating on KERNEL buffers (no copy_to/from_user, no chunk cap): the
 * user wrappers below stage through a bounded on-stack buffer and copy across the
 * user boundary, while the self-test drives these directly. Return semantics match
 * pipe_read/pipe_write. */
static int pipe_read_bytes(int idx, uint8_t *dst, uint32_t len) {
    if (idx < 0 || idx >= MAX_PIPES) return SYS_ERR_INVAL;
    spin_lock(&pipe_lock);
    struct pipe *p = &pipes[idx];
    if (!p->in_use) { spin_unlock(&pipe_lock); return SYS_ERR_INVAL; }
    if (p->count == 0) {
        uint32_t writers = p->writer_ends;
        spin_unlock(&pipe_lock);
        return writers ? SYS_ERR_AGAIN : 0;    /* would-block vs EOF */
    }
    uint32_t n = p->count < len ? p->count : len;
    for (uint32_t i = 0; i < n; i++)
        dst[i] = p->buf[(p->head + i) % PIPE_BUF_BYTES];
    p->head = (p->head + n) % PIPE_BUF_BYTES;
    p->count -= n;                              /* commit the read under the lock */
    spin_unlock(&pipe_lock);
    return (int)n;
}

static int pipe_write_bytes(int idx, const uint8_t *src, uint32_t len) {
    if (idx < 0 || idx >= MAX_PIPES) return SYS_ERR_INVAL;
    spin_lock(&pipe_lock);
    struct pipe *p = &pipes[idx];
    if (!p->in_use)          { spin_unlock(&pipe_lock); return SYS_ERR_INVAL; }
    if (p->reader_ends == 0) { spin_unlock(&pipe_lock); return SYS_ERR_PIPE;  }
    uint32_t space = PIPE_BUF_BYTES - p->count;
    if (space == 0)          { spin_unlock(&pipe_lock); return SYS_ERR_AGAIN; }
    uint32_t n = len < space ? len : space;
    uint32_t tail = (p->head + p->count) % PIPE_BUF_BYTES;
    for (uint32_t i = 0; i < n; i++)
        p->buf[(tail + i) % PIPE_BUF_BYTES] = src[i];
    p->count += n;
    spin_unlock(&pipe_lock);
    return (int)n;
}

int pipe_read(int idx, uint8_t *dst, uint32_t len) {
    if (len > PIPE_IO_CHUNK) len = PIPE_IO_CHUNK;
    uint8_t stage[PIPE_IO_CHUNK];
    int n = pipe_read_bytes(idx, stage, len);
    if (n <= 0) return n;                        /* EOF (0) / EAGAIN / error */
    if (copy_to_user(dst, stage, (size_t)n) != 0) return SYS_ERR_FAULT;
    return n;
}

int pipe_write(int idx, const uint8_t *src, uint32_t len) {
    if (len > PIPE_IO_CHUNK) len = PIPE_IO_CHUNK;
    uint8_t stage[PIPE_IO_CHUNK];
    if (copy_from_user(stage, src, len) != 0) return SYS_ERR_FAULT;
    return pipe_write_bytes(idx, stage, len);
}

/* Close every pipe end a dying task still holds (called from task_teardown, in
 * kernel context on the dead task's slot). Nulls the cap and unrefs the end so
 * the peer sees EOF/EPIPE and the pipe is freed once both directions reach 0. */
void pipe_close_task_ends(int task_id) {
    if (task_id <= 0 || task_id >= g_max_tasks) return;
    capability_t *cs = tasks[task_id].cspace;
    if (!cs) return;
    uint32_t sz = tasks[task_id].cspace_size ? tasks[task_id].cspace_size : CNODE_SIZE;
    for (uint32_t s = 0; s < sz; s++) {
        if (cs[s].type == CAP_PIPE) {
            int idx       = (int)cs[s].object;
            int is_writer = (cs[s].rights & CAP_RIGHT_WRITE) != 0;
            cs[s].type = CAP_NULL;
            pipe_end_unref(idx, is_writer);
        }
    }
}

/* ---- syscall handlers ----------------------------------------------------- */

/* SYS_PIPE: create a pipe and install a READ end and a WRITE end in the caller's
 * cspace at the first two free slots >= 16. Returns (read_slot<<16)|write_slot. */
void h_pipe(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    capability_t *cs = tasks[cur].cspace;
    uint32_t sz = tasks[cur].cspace_size ? tasks[cur].cspace_size : CNODE_SIZE;
    if (!cs) { r->rax = (uint64_t)(uint32_t)SYS_ERR_PERM; return; }

    int rslot = -1, wslot = -1;
    for (uint32_t s = 16; s < sz; s++) {
        if (cs[s].type == CAP_NULL) {
            if (rslot < 0) rslot = (int)s;
            else { wslot = (int)s; break; }
        }
    }
    if (rslot < 0 || wslot < 0) { r->rax = (uint64_t)(uint32_t)SYS_ERR_NOMEM; return; }

    int idx = pipe_alloc();
    if (idx < 0) { r->rax = (uint64_t)(uint32_t)SYS_ERR_NOMEM; return; }

    cs[rslot].type = CAP_PIPE; cs[rslot].rights = CAP_RIGHT_READ;
    cs[rslot].object = (uint64_t)(uint32_t)idx; cs[rslot].badge = 0;
    cs[rslot].serial = cap_alloc_fresh_serial(); cs[rslot].generation = rust_lineage_current(cs[rslot].serial); /* finding 3.3 */
    cs[wslot].type = CAP_PIPE; cs[wslot].rights = CAP_RIGHT_WRITE;
    cs[wslot].object = (uint64_t)(uint32_t)idx; cs[wslot].badge = 0;
    cs[wslot].serial = cap_alloc_fresh_serial(); cs[wslot].generation = rust_lineage_current(cs[wslot].serial); /* finding 3.3 */
    pipe_end_ref(idx, 0);   /* read end  */
    pipe_end_ref(idx, 1);   /* write end */

    r->rax = ((uint64_t)(uint32_t)rslot << 16) | (uint32_t)wslot;
}

void h_pipe_read(struct interrupt_frame64 *r) {
    uint32_t slot = (uint32_t)r->rbx;
    void    *buf  = (void *)(addr_t)r->rcx;
    uint32_t len  = (uint32_t)r->rdx;
    struct capability *c = cap_lookup(slot, CAP_PIPE, CAP_RIGHT_READ);
    if (!c) { r->rax = (uint64_t)(uint32_t)SYS_ERR_PERM; return; }
    r->rax = (uint64_t)(uint32_t)pipe_read((int)c->object, (uint8_t *)buf, len);
}

void h_pipe_write(struct interrupt_frame64 *r) {
    uint32_t slot = (uint32_t)r->rbx;
    const void *buf = (const void *)(addr_t)r->rcx;
    uint32_t len  = (uint32_t)r->rdx;
    struct capability *c = cap_lookup(slot, CAP_PIPE, CAP_RIGHT_WRITE);
    if (!c) { r->rax = (uint64_t)(uint32_t)SYS_ERR_PERM; return; }
    r->rax = (uint64_t)(uint32_t)pipe_write((int)c->object, (const uint8_t *)buf, len);
}

void h_pipe_close(struct interrupt_frame64 *r) {
    uint32_t slot = (uint32_t)r->rbx;
    int cur = get_current_task();
    capability_t *cs = tasks[cur].cspace;
    uint32_t sz = tasks[cur].cspace_size ? tasks[cur].cspace_size : CNODE_SIZE;
    if (!cs || slot >= sz || cs[slot].type != CAP_PIPE) {
        r->rax = (uint64_t)(uint32_t)SYS_ERR_INVAL; return;
    }
    int idx       = (int)cs[slot].object;
    int is_writer = (cs[slot].rights & CAP_RIGHT_WRITE) != 0;
    cs[slot].type = CAP_NULL;
    pipe_end_unref(idx, is_writer);
    r->rax = 0;
}

/* SYS_STDIO_INFO: report which of the caller's fd0/fd1 the spawner wired to a
 * pipe (STDIO_*_PIPE bits), so posix_init can bind them instead of the console. */
void h_stdio_info(struct interrupt_frame64 *r) {
    r->rax = (uint64_t)tasks[get_current_task()].stdio_flags;
}

#ifdef PIPE_SELFTEST
/* Fast, deterministic, in-kernel exercise of the pipe object — the mechanics that
 * shell pipelines rest on — without loading any coreutil image (which is slow over
 * IPC). Drives the ring core directly: round-trip, EOF, EPIPE, back-pressure, and
 * that a freed pipe is scrubbed. Prints PIPE_SELFTEST: PASS/FAIL. */
static int pst_fail(const char *why) { print("PIPE_SELFTEST: FAIL ("); print(why); println(")"); return 0; }

void pipe_selftest(void) {
    int idx = pipe_alloc();
    if (idx < 0) { pst_fail("alloc"); return; }
    pipe_end_ref(idx, 0);   /* one reader end  */
    pipe_end_ref(idx, 1);   /* one writer end  */

    /* 1. write then read the same bytes back. */
    uint8_t out[5] = { 10, 20, 30, 40, 50 };
    uint8_t in[8]  = { 0 };
    if (pipe_write_bytes(idx, out, 5) != 5) { pst_fail("write"); return; }
    if (pipe_read_bytes(idx, in, 8) != 5)   { pst_fail("read-count"); return; }
    for (int i = 0; i < 5; i++) if (in[i] != out[i]) { pst_fail("read-data"); return; }

    /* 2. empty read while a writer is open -> would-block, not EOF. */
    if (pipe_read_bytes(idx, in, 8) != SYS_ERR_AGAIN) { pst_fail("eagain"); return; }

    /* 3. back-pressure: fill the buffer, then a further write blocks. */
    static uint8_t big[PIPE_BUF_BYTES + 16];
    for (uint32_t i = 0; i < sizeof(big); i++) big[i] = (uint8_t)i;
    if (pipe_write_bytes(idx, big, PIPE_BUF_BYTES) != (int)PIPE_BUF_BYTES) { pst_fail("fill"); return; }
    if (pipe_write_bytes(idx, out, 1) != SYS_ERR_AGAIN) { pst_fail("backpressure"); return; }
    /* drain fully and confirm the count returns to empty-with-writers = AGAIN. */
    if (pipe_read_bytes(idx, big, PIPE_BUF_BYTES) != (int)PIPE_BUF_BYTES) { pst_fail("drain"); return; }
    if (pipe_read_bytes(idx, in, 8) != SYS_ERR_AGAIN) { pst_fail("drained-eagain"); return; }

    /* 4. EOF: once the last writer end is gone, a read returns 0. */
    pipe_end_unref(idx, 1);
    if (pipe_read_bytes(idx, in, 8) != 0) { pst_fail("eof"); return; }
    pipe_end_unref(idx, 0);   /* frees the pipe (both ends gone) */

    /* 5. EPIPE: writing to a pipe whose reader end is gone. */
    int idx2 = pipe_alloc();
    if (idx2 < 0) { pst_fail("alloc2"); return; }
    pipe_end_ref(idx2, 0);
    pipe_end_ref(idx2, 1);
    pipe_end_unref(idx2, 0);   /* drop the reader */
    if (pipe_write_bytes(idx2, out, 1) != SYS_ERR_PIPE) { pst_fail("epipe"); return; }
    pipe_end_unref(idx2, 1);   /* frees it */

    /* 6. a freed pipe is scrubbed (no residue from step 3's fill). */
    if (pipes[idx].in_use != 0) { pst_fail("not-freed"); return; }
    for (uint32_t i = 0; i < PIPE_BUF_BYTES; i++)
        if (pipes[idx].buf[i] != 0) { pst_fail("residue"); return; }

    println("PIPE_SELFTEST: object phase ok");
}

/* PHASE 2: a task that dies WITHOUT closing its end, and the peer that must
 * still see EOF.
 *
 * WHY THE PHASE ABOVE CANNOT REACH IT. Everything there is a direct call on the
 * pipe object: refs taken and dropped by hand, so the EOF it witnesses is the
 * one an orderly close produces. `pipe_close_task_ends` is the BACKSTOP for a
 * stage that dies holding an end -- a fault, a SYS_KILL -- and it works by
 * walking the dead task's cspace for CAP_PIPE. Its ordering inside
 * `task_teardown` is load-bearing: `cap_release_cspace` empties that cspace, so
 * releasing before the walk means the walk finds nothing, no end is unreffed,
 * and the peer waits forever on a writer that no longer exists.
 *
 * THAT ORDERING HAD A DEFECT FLAG AND NO GATE. `CSPACE_RELEASE_BEFORE_PIPES=1`
 * makes the move, and was measured on 2026-08-30 against `smoke-pipe` and
 * `smoke-modules` -- both PASSED under it, because every pipe user in this tree
 * closes its ends explicitly, so by the time a stage dies there is nothing left
 * to find. A control arm that cannot fail cannot gate, so it was kept and not
 * gated, "for the day a workload kills a task mid-pipeline". This is that
 * workload: it is the ONLY thing in the tree that reaches the backstop.
 *
 * IT RUNS AFTER scheduler_init, because before it task 0 has no cspace and the
 * capability the dying task must hold cannot be granted from anywhere. Only this
 * phase prints PASS, so `smoke-pipe` cannot pass on the object phase alone -- the
 * harness ends a boot at its required marker, so an earlier PASS would stop the
 * run before this ever executed. */
void pipe_task_teardown_selftest(void) {
    int idx = pipe_alloc();
    if (idx < 0) { pst_fail("teardown-alloc"); return; }
    pipe_end_ref(idx, 0);   /* the reader end, held by this task: the peer */
    pipe_end_ref(idx, 1);   /* the writer end, held by the task about to die */

    /* The peer's own capability, and the source of the grant. It carries WRITE
     * because rights can only be reduced on delegation, and the end the dying
     * task must hold is the writer's. */
    uint32_t src_slot = KERNEL_RESERVED_CAPS;
    if (!cap_install_object(src_slot, CAP_PIPE, (uint64_t)idx,
                            CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_GRANT, 0)) {
        pst_fail("teardown-cap-install"); return;
    }

    /* The doomed stage: a real task slot, taken from the top so nothing the boot
     * goes on to spawn lands in it. It never runs -- create_task leaves
     * runnable_ctx and saved_ksp at 0, which every selection loop tests. */
    int dying = g_max_tasks - 1;
    create_task(dying, 0, 0, 0, 0, UNTYPED_KERNEL);
    if (tasks[dying].state != 1 || !tasks[dying].cspace) {
        pst_fail("teardown-task-create"); return;
    }
    if (!cap_grant_into(dying, KERNEL_RESERVED_CAPS, src_slot, CAP_RIGHT_WRITE)) {
        pst_fail("teardown-cap-grant"); return;
    }

    /* The premise: while that end is open, an empty read is would-block rather
     * than EOF. Without this the assertion after the death is satisfied by a
     * pipe that had no writer to begin with. */
    uint8_t in[8] = { 0 };
    if (pipe_read_bytes(idx, in, 8) != SYS_ERR_AGAIN) {
        pst_fail("teardown-not-blocking-before-death"); return;
    }

    struct task_exit_cause cause = { .reason = TASK_EXIT_KILLED, .detail = 0,
                                     .err = 0, .rip = 0, .addr = 0 };
    task_teardown(dying, &cause);

    /* The backstop must have run: the writer end is gone, so the peer's read is
     * EOF. Under CSPACE_RELEASE_BEFORE_PIPES it is still SYS_ERR_AGAIN -- the
     * stage died, its end was never released, and the peer waits on nobody. */
    int rc = pipe_read_bytes(idx, in, 8);
    if (rc != 0) {
        if (rc == SYS_ERR_AGAIN) {
            /* ONE literal write, unlike its pst_fail neighbours: this is the
             * marker smoke-pipe-cspace-order-control asserts on, and a gated
             * marker assembled from three calls can be split by another writer
             * on the shared console -- docs/LIMITATIONS.md 2.6a, which
             * tools/check_split_markers.py enforces. */
            println("PIPE_SELFTEST: FAIL peer-never-saw-eof");
            return;
        }
        pst_fail("teardown-read-unexpected"); return;
    }

    pipe_end_unref(idx, 0);   /* the peer lets go; the pipe is freed */
    if (pipes[idx].in_use != 0) { pst_fail("teardown-not-freed"); return; }

    println("PIPE_SELFTEST: PASS");
}
#endif
