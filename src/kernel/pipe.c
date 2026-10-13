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
 *    SYS_PIPE_CLOSE, by task_teardown (pipe_close_task_ends), and by a revocation
 *    that removes them (pipe_release_revoked_ends), so a stage that exits —
 *    cleanly or on a fault — or loses its end to a revoke always releases it.
 *
 * THE INVARIANT THE COUNTS KEEP, AND WHY IT IS ONE-SIDED (LIMITATIONS 1.14, S134). A
 * pipe's count of ends in each direction is NEVER LOWER than the number of
 * pipe-end capabilities naming it, at any moment another CPU could look. Higher
 * is harmless and happens briefly: a close empties its slot under cap_lock and
 * unrefs after dropping it, so for a moment the count includes an end that is
 * gone, and the peer sees "would block" a moment longer than it needs to. Lower
 * is the defect this rule exists for: the count can reach zero while an end
 * still names the pipe, the pipe is freed and scrubbed, and the next pipe_alloc
 * to take the index is reachable through that end (the #553 hazard).
 *
 * So every PRODUCER of an end counts it no later than the moment anything else
 * could remove it: SYS_PIPE counts its two ends before it installs them, and a
 * forked child's copies and a spawned child's stdio end are counted inside the
 * cap_lock section that installs them (pipe_count_forked_ends,
 * cap_install_child_pipe_end), which is the lock every revocation sweep holds. And every
 * revocation subtracts exactly the ends it removed, counted by the Rust sweep
 * as it removes them, before it releases cap_lock (pipe_release_revoked_ends).
 * Taking pipe_lock while cap_lock is held is the nesting cap_lock -> pipe_lock in
 * .github/lock-order.yml, and pipe_lock is a leaf: nothing here takes another
 * lock while holding it.
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

/* Count one more end of pipe `idx`. False, counting nothing, if there is no
 * such pipe: an end of a freed pipe is never counted, so a caller that is about
 * to install one refuses instead (cap_install_child_pipe_end). */
bool pipe_end_ref(int idx, int is_writer) {
    if (idx < 0 || idx >= MAX_PIPES) return false;
    bool counted = false;
    spin_lock(&pipe_lock);
    if (pipes[idx].in_use) {
        if (is_writer) pipes[idx].writer_ends++;
        else           pipes[idx].reader_ends++;
        counted = true;
    }
    spin_unlock(&pipe_lock);
    return counted;
}

/* Free a pipe whose last end has gone. pipe_lock held. */
static void pipe_free_if_unheld(struct pipe *p) {
    if (p->reader_ends == 0 && p->writer_ends == 0) {
        secure_zero(p->buf, sizeof(p->buf));   /* no residue in a reused pipe */
        p->in_use = 0; p->head = 0; p->count = 0;
    }
}

void pipe_end_unref(int idx, int is_writer) {
    if (idx < 0 || idx >= MAX_PIPES) return;
    spin_lock(&pipe_lock);
    struct pipe *p = &pipes[idx];
    if (p->in_use) {
        if (is_writer) { if (p->writer_ends) p->writer_ends--; }
        else           { if (p->reader_ends) p->reader_ends--; }
        pipe_free_if_unheld(p);
    }
    spin_unlock(&pipe_lock);
}

/* RELEASE THE ENDS A REVOCATION REMOVED (LIMITATIONS 1.14).
 *
 * Called by cap_revoke with cap_lock HELD, after the Rust sweep has emptied the
 * revoked slots and counted the pipe ends among them in `tally`: cell 2*i holds
 * the reader ends of pipe i it removed, cell 2*i+1 the writer ends. Each of those
 * ends was counted here when it was made, so each comes off here exactly once;
 * a revoked end is no longer in any slot, so no close or teardown can find it
 * and release it a second time.
 *
 * WHY UNDER cap_lock, AND NOT AFTER IT LIKE A CLOSE. Releasing after the lock
 * would only make a count briefly too high, the harmless side of the invariant
 * at the top of this file. It is done inside so that, once cap_revoke returns,
 * the counts describe exactly the ends that exist: a peer whose last opposite
 * end was revoked sees EOF or EPIPE on its very next call, with nothing in flight.
 *
 * The design recorded in LIMITATIONS 1.14 until 2026-10-13 recounted every
 * pipe's ends from the cspaces under pipe_lock alone instead. That is unsound on
 * SMP: a close empties its slot under cap_lock and unrefs after, so a recount in
 * between counts the end as gone and the unref then takes it off again -- one too
 * few, and a pipe freed while another end names it. Reading the cspaces without
 * cap_lock also sees capabilities half-written.
 *
 * Returns false if the tally asked to release more ends than a pipe had counted,
 * which the invariant says cannot happen; the count stops at zero rather than
 * wrapping, and the caller reports it once it has dropped its locks. */
bool pipe_release_revoked_ends(const uint32_t *tally, uint32_t cells) {
    if (!tally) return true;
    uint32_t n = cells / 2;
    if (n > MAX_PIPES) n = MAX_PIPES;
    bool exact = true;
    spin_lock(&pipe_lock);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t readers = tally[2 * i], writers = tally[2 * i + 1];
        if (readers == 0 && writers == 0) continue;
        struct pipe *p = &pipes[i];
        if (!p->in_use) { exact = false; continue; }
        if (readers > p->reader_ends || writers > p->writer_ends) exact = false;
        p->reader_ends = readers > p->reader_ends ? 0 : p->reader_ends - readers;
        p->writer_ends = writers > p->writer_ends ? 0 : p->writer_ends - writers;
        pipe_free_if_unheld(p);
    }
    spin_unlock(&pipe_lock);
    return exact;
}

/* Ring core operating on KERNEL buffers (no copy_to/from_user, no chunk cap): the
 * syscall handlers below stage through a bounded on-stack buffer and copy across
 * the user boundary, while the self-test drives these directly. Return semantics
 * are SYS_PIPE_READ's and SYS_PIPE_WRITE's. */
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

/* MOVE BYTES THROUGH THE CALLER'S PIPE END, WITH THE END HELD FOR THE WHOLE
 * MOVE (LIMITATIONS 1.14).
 *
 * The end in `slot` is resolved and the ring is read or written under one
 * cap_lock acquisition, with pipe_lock nested inside it. Until 2026-10-13 the
 * handlers resolved the slot with no lock held and used the pipe index after it,
 * which was safe only because nothing but the holder itself could remove its own
 * end, and a task does not close an end while it is inside a read of it. Once a
 * pipe end can be revoked by another task, that gap is reachable: the revoke can
 * take the last ends of the pipe, the pipe is freed, the next pipe_alloc takes
 * the index, and the bytes go to (or come from) a pipe this task holds no end
 * of. Held under the lock every revocation holds, the end either is gone before
 * the move (SYS_ERR_PERM) or exists until it is over.
 *
 * Only kernel memory is touched under the locks: the caller stages the user
 * buffer before a write and copies out after a read, so no page fault (and no
 * page_lock) is ever taken inside cap_lock here. */
static int pipe_io_by_slot(uint32_t slot, int write, uint8_t *stage, uint32_t len) {
    int rc;
    spin_lock(&cap_lock);
    struct capability *c = cap_lookup(slot, CAP_PIPE, write ? CAP_RIGHT_WRITE : CAP_RIGHT_READ);
    if (!c)                          rc = SYS_ERR_PERM;
    else if (c->object >= MAX_PIPES) rc = SYS_ERR_INVAL;
    else if (write)                  rc = pipe_write_bytes((int)c->object, stage, len);
    else                             rc = pipe_read_bytes((int)c->object, stage, len);
    spin_unlock(&cap_lock);
    return rc;
}

/* Does the caller hold a pipe end with `right` in `slot`? Asked before a write
 * touches the caller's buffer, so a refused write fails as refused rather than
 * as a fault; pipe_io_by_slot asks again under the lock, which is the answer that
 * counts. */
static int pipe_end_held(uint32_t slot, uint32_t right) {
    spin_lock(&cap_lock);
    int held = cap_lookup(slot, CAP_PIPE, right) != NULL;
    spin_unlock(&cap_lock);
    return held;
}

/* Close every pipe end a dying task still holds (called from task_teardown, in
 * kernel context on the dead task's slot). Nulls the cap and unrefs the end so
 * the peer sees EOF/EPIPE and the pipe is freed once both directions reach 0. */
void pipe_close_task_ends(int task_id) {
    if (task_id <= 0 || task_id >= g_max_tasks) return;
    uint32_t sz = tasks[task_id].cspace_size ? tasks[task_id].cspace_size : CNODE_SIZE;
    if (!tasks[task_id].cspace) return;

    /* ONE SLOT PER PASS, re-scanning from the start each time, rather than one
     * walk that nulls and unrefs as it goes. The walk has to read the cspace and
     * the null has to be under cap_lock (a teardown races a revocation sweep on
     * another CPU like any other cap-write). Unref'ing inside that walk would
     * hold cap_lock across every end the task holds. cap_lock -> pipe_lock is a
     * declared nesting since 2026-10-13, but a removal does not need it: an unref
     * after the lock leaves the count briefly too HIGH, the harmless side of the
     * invariant at the top of this file, so the locks stay sequential here.
     *
     * The cost is O(slots^2) on a cspace that is all pipe ends: 256 slots, so at
     * most ~32k trivial comparisons, once, on a task that is already dead. The
     * re-scan is also what makes it correct to drop the lock: the slot we just
     * emptied can never be found again, so the loop cannot double-unref an end
     * even if another CPU is closing the same cspace. */
    for (uint32_t pass = 0; pass < sz; pass++) {
        capability_t prev;
        uint32_t found = sz;
        spin_lock(&cap_lock);
        capability_t *cs = tasks[task_id].cspace;
        if (cs) {
            for (uint32_t s = 0; s < sz; s++) {
                if (cs[s].type == CAP_PIPE) { found = s; break; }
            }
        }
        spin_unlock(&cap_lock);
        if (found >= sz) return;                 /* no ends left to release */
        if (!cap_consume_slot_of(task_id, found, &prev)) return;
        if (prev.type != CAP_PIPE) continue;      /* another CPU got there first */
        pipe_end_unref((int)prev.object, (prev.rights & CAP_RIGHT_WRITE) != 0);
    }
}

/* COUNT THE PIPE ENDS A FORKED CHILD WAS GIVEN (LIMITATIONS 1.29), UNDER THE
 * SAME cap_lock THE COPIES WERE MADE UNDER (LIMITATIONS 1.14).
 *
 * A pipe is freed when its reader_ends and writer_ends both reach zero, so
 * every CAP_PIPE that can be closed must have been counted. cap_clone_cspace
 * gives a forked child a derived copy of every capability its parent holds,
 * pipe ends included, and counted none of them: after a fork a pipe had two
 * holders and a count of one, so when the parent closed its end the pipe was
 * scrubbed and freed while the child still held a capability naming its
 * index, and the next pipe_alloc to take that index joined the child to an
 * unrelated pair of tasks. The spawn path's stdio wiring always counted the
 * end it passes on (wire_child_stdio); fork was the copy that did not.
 *
 * Called by cap_clone_cspace with cap_lock HELD, once every copy is made and
 * before the lock is released. Until 2026-10-13 it ran after the clone had
 * dropped the lock, with the refs taken after a second locked read, because
 * cap_lock -> pipe_lock was not an order this kernel had. That was safe while no
 * pipe end could be revoked. Once SYS_PIPE's ends carry REVOKE, a revoke of the
 * parent's end (or an ancestor of it) landing in that window removes the child's
 * copy and subtracts it from a count that never included it: one too few, the
 * defect the invariant at the top of this file forbids. Counted under the lock
 * every sweep holds, the copy and its count are seen together or not at all.
 *
 * Counted from what the child's cspace HOLDS, not from what the clone meant to
 * copy, so a slot the clone could not fill is not counted. The direction is the
 * one pipe_end_unref and the revocation tally use, the capability's own WRITE
 * right, so all three always agree.
 *
 * All or nothing, in one pipe_lock section: every end is checked against a pipe
 * in use before any is counted, and false means nothing was counted, so the
 * caller fails the fork and the child, which never runs, holds no end the table
 * would have to release. The parent's ends were live, so their pipes are in use
 * while the counts keep their invariant; the check is what keeps an end the
 * table never counted from existing if they ever do not. */
bool pipe_count_forked_ends(int child) {
    if (child <= 0 || child >= g_max_tasks) return false;
    capability_t *cs = tasks[child].cspace;
    uint32_t sz = tasks[child].cspace_size ? tasks[child].cspace_size : CNODE_SIZE;
    if (sz > CNODE_SIZE) sz = CNODE_SIZE;
    if (!cs) return false;
    spin_lock(&pipe_lock);
    for (uint32_t s = 0; s < sz; s++) {
        if (cs[s].type != CAP_PIPE || cs[s].serial == 0) continue;
        if (cs[s].object >= MAX_PIPES || !pipes[cs[s].object].in_use) {
            spin_unlock(&pipe_lock);
            return false;
        }
    }
    for (uint32_t s = 0; s < sz; s++) {
        if (cs[s].type != CAP_PIPE || cs[s].serial == 0) continue;
        if (cs[s].rights & CAP_RIGHT_WRITE) pipes[cs[s].object].writer_ends++;
        else                                pipes[cs[s].object].reader_ends++;
    }
    spin_unlock(&pipe_lock);
    return true;
}

/* ---- syscall handlers ----------------------------------------------------- */

/* SYS_PIPE: create a pipe and install a READ end and a WRITE end in the caller's
 * cspace at the first two free slots >= 16. Returns (read_slot<<16)|write_slot.
 *
 * BOTH ENDS CARRY REVOKE (LIMITATIONS 1.14, the maintainer's choice of
 * 2026-10-13). Without it no pipe end could be revoked at all, so the copies of
 * an end a fork or a spawn hands on were outside S3 in a way no test could see.
 * With it the creator can take back every copy of an end it handed on, and only
 * those (S4): its own end goes with them, as a close would take it. A fork
 * keeps the right, since a forked child holds what its parent held; the spawn
 * path hands a child READ or WRITE alone, so a spawned stage cannot revoke.
 * Neither end carries MINT or GRANT, and ring 3 cannot copy one by any path
 * (S133), so REVOKE adds no way to pass an end on. */
void h_pipe(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (!tasks[cur].cspace) { r->rax = (uint64_t)(uint32_t)SYS_ERR_PERM; return; }

    int idx = pipe_alloc();
    if (idx < 0) { r->rax = (uint64_t)(uint32_t)SYS_ERR_NOMEM; return; }

    /* THE TWO ENDS GO IN THROUGH THE LOCKED, ACCOUNTED CAP-WRITE PATH.
     *
     * Until 2026-09-12 this scanned its own cspace for two free slots and then
     * filled twelve fields by hand with no lock and no accounting. Three defects,
     * all of them in cap_install_object_first_free's header: the scan and the
     * store were not atomic against each other, the store was not atomic against
     * rust_cap_revoke_global's sweep (which is documented to rely on cap_lock
     * making every cspace quiescent), and a pipe end cost a task nothing against
     * MAX_CAPS_PER_TASK -- so SYS_PIPE was a way to hold capabilities the stated
     * ceiling did not bound, and SYS_PIPE_CLOSE a way to be credited for them.
     *
     * BOTH ENDS ARE COUNTED BEFORE EITHER IS INSTALLED (LIMITATIONS 1.14, S134).
     * Until 2026-10-13 the refs came after both installs, so for a moment two
     * ends existed that the pipe had not counted. Nothing could revoke them in
     * that moment, but SYS_KILL tears a task down from the killer's CPU, and a
     * teardown that closed them there would have taken the pipe's counts below
     * zero, freed it, and left the late refs to land on whatever pipe took the
     * index next. Counted first, the count is never below the ends that exist.
     * Every failure below has installed nothing it keeps, so it releases both
     * refs, which frees and scrubs the pipe (pipe_end_unref at 0/0). */
    pipe_end_ref(idx, 0);   /* read end  */
    pipe_end_ref(idx, 1);   /* write end */
    uint32_t rslot = 0, wslot = 0;
#ifdef PIPE_CAP_UNACCOUNTED
    /* CONTROL ARM: the pre-2026-09-12 raw store. Same two slots, same fields, no
     * cap_lock and no caps_in_use -- so the ceiling does not bind and SYS_PIPE
     * succeeds on a task that already holds MAX_CAPS_PER_TASK capabilities. */
    {
        capability_t *cs = tasks[cur].cspace;
        uint32_t sz = tasks[cur].cspace_size ? tasks[cur].cspace_size : CNODE_SIZE;
        int rs = -1, ws = -1;
        for (uint32_t s = 16; s < sz; s++) {
            if (cs[s].type == CAP_NULL) {
                if (rs < 0) rs = (int)s;
                else { ws = (int)s; break; }
            }
        }
        if (rs < 0 || ws < 0) {
            pipe_end_unref(idx, 0);
            pipe_end_unref(idx, 1);
            r->rax = (uint64_t)(uint32_t)SYS_ERR_NOMEM;
            return;
        }
        cs[rs].type = CAP_PIPE; cs[rs].rights = CAP_RIGHT_READ | CAP_RIGHT_REVOKE;
        cs[rs].object = (uint64_t)(uint32_t)idx; cs[rs].badge = 0;
        cs[rs].serial = cap_alloc_fresh_serial();
        cs[rs].token = 0;
        cs[ws].type = CAP_PIPE; cs[ws].rights = CAP_RIGHT_WRITE | CAP_RIGHT_REVOKE;
        cs[ws].object = (uint64_t)(uint32_t)idx; cs[ws].badge = 0;
        cs[ws].serial = cap_alloc_fresh_serial();
        cs[ws].token = 0;
        rslot = (uint32_t)rs; wslot = (uint32_t)ws;
    }
#else
    if (!cap_install_object_first_free(CAP_DYNAMIC_FLOOR, CAP_PIPE, (uint64_t)(uint32_t)idx,
                                       CAP_RIGHT_READ | CAP_RIGHT_REVOKE, 0, &rslot)) {
        /* Nothing has been installed, so the two refs above are the pipe's only
         * holders: releasing them frees and scrubs it, which is the rollback. */
        pipe_end_unref(idx, 0);
        pipe_end_unref(idx, 1);
        r->rax = (uint64_t)(uint32_t)SYS_ERR_NOMEM;
        return;
    }
    if (!cap_install_object_first_free(CAP_DYNAMIC_FLOOR, CAP_PIPE, (uint64_t)(uint32_t)idx,
                                       CAP_RIGHT_WRITE | CAP_RIGHT_REVOKE, 0, &wslot)) {
        capability_t prev;
        cap_consume_slot_of(cur, rslot, &prev);   /* give the read end back */
        pipe_end_unref(idx, 0);                   /* and free the pipe */
        pipe_end_unref(idx, 1);
        r->rax = (uint64_t)(uint32_t)SYS_ERR_NOMEM;
        return;
    }
#endif

    r->rax = ((uint64_t)rslot << 16) | wslot;
}

void h_pipe_read(struct interrupt_frame64 *r) {
    uint32_t slot = (uint32_t)r->rbx;
    void    *buf  = (void *)(addr_t)r->rcx;
    uint32_t len  = (uint32_t)r->rdx;
    if (len > PIPE_IO_CHUNK) len = PIPE_IO_CHUNK;
    uint8_t stage[PIPE_IO_CHUNK];
    int n = pipe_io_by_slot(slot, 0, stage, len);
    if (n > 0 && copy_to_user(buf, stage, (size_t)n) != 0) n = SYS_ERR_FAULT;
    r->rax = (uint64_t)(uint32_t)n;              /* EOF (0) / EAGAIN / error / count */
}

void h_pipe_write(struct interrupt_frame64 *r) {
    uint32_t slot = (uint32_t)r->rbx;
    const void *buf = (const void *)(addr_t)r->rcx;
    uint32_t len  = (uint32_t)r->rdx;
    if (!pipe_end_held(slot, CAP_RIGHT_WRITE)) { r->rax = (uint64_t)(uint32_t)SYS_ERR_PERM; return; }
    if (len > PIPE_IO_CHUNK) len = PIPE_IO_CHUNK;
    uint8_t stage[PIPE_IO_CHUNK];
    if (copy_from_user(stage, buf, len) != 0) { r->rax = (uint64_t)(uint32_t)SYS_ERR_FAULT; return; }
    r->rax = (uint64_t)(uint32_t)pipe_io_by_slot(slot, 1, stage, len);
}

void h_pipe_close(struct interrupt_frame64 *r) {
    uint32_t slot = (uint32_t)r->rbx;
    int cur = get_current_task();

    /* The read of the slot, the null, and the accounting are one locked step, and
     * the unref happens after it on what the slot ACTUALLY held. The old code
     * tested the type, then read object and rights, then nulled -- three
     * unsynchronised touches of a slot a revocation sweep may be reading, and two
     * CPUs closing the same slot could both pass the test and both unref, taking
     * writer_ends to 0 while a holder remained. cap_consume_slot_of hands the
     * contents back only to the CPU that emptied the slot. */
    capability_t prev;
    if (!cap_consume_slot_of(cur, slot, &prev) || prev.type != CAP_PIPE) {
        r->rax = (uint64_t)(uint32_t)SYS_ERR_INVAL; return;
    }
    pipe_end_unref((int)prev.object, (prev.rights & CAP_RIGHT_WRITE) != 0);
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
     * runnable_ctx and saved_ksp at 0, which sched_selectable tests. */
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
