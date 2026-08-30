/* syscall_ipc.c -- synchronous IPC (send/recv/reply over endpoints) plus
 * asynchronous notifications, and their syscall handlers. Split out of
 * syscall.c. */
#include "syscall_internal.h"

#define IPC_SPIN_LIMIT 200000

/* Two places below transiently make a BLOCKED peer the current task so
 * copy_to_user resolves through that peer's CR3, and bracket it with
 * sched_impersonate_enter/exit (scheduler.c) — the same primitive the spawn-time
 * image loader uses, because the two subsystems impersonate for the same reason
 * and must declare it the same way. Inside the bracket percpu_current_task[]
 * deliberately misdescribes what this CPU is running; the bracket tells the
 * scheduler's claim auditor what it is really on. Interrupts are already masked
 * by the callers, so this CPU cannot be interrupted mid-window — the declaration
 * exists purely for auditors on OTHER cores. */

/* Serialise endpoint + notification operations across CPUs. A raw test-and-set
 * (endpoint_lock) is used because these run inside the int-0x80 handler with IF
 * already clear. In the single-CPU default build these compile to nothing, so
 * that path is byte-for-byte unchanged. The lock guards the mailbox flags, the
 * badge accumulator, and the wake handoff (state -> RUNNABLE + saved-frame
 * patch); the actual task switch onto the woken task is done later by the
 * running-CPU-guarded scheduler.
 *
 * Concurrent-IPC publish order (with ipc_block_switch):
 *   syscall handler sets pending_block only (not yet wake-visible);
 *   ipc_block_switch writes saved_ksp, barriers, then ipc_publish_pending_block
 *   publishes blocked_waiter / WAIT link under this lock. Wakers always patch a
 *   valid frame. */
#ifdef SMP
extern spinlock_t endpoint_lock;
static inline void ipc_lock(void) {
    while (__sync_lock_test_and_set(&endpoint_lock.locked, 1))
        while (endpoint_lock.locked) __asm__ volatile ("pause");
}
static inline void ipc_unlock(void) { __sync_lock_release(&endpoint_lock.locked); }
#else
static inline void ipc_lock(void) { }
static inline void ipc_unlock(void) { }
#endif

/* ---- Endpoint queue primitives (roadmap 1.3) -------------------------------
 *
 * Both must be called with ipc_lock held: they are the only mutators of the ring,
 * and a torn head/count pair would either lose a message or hand two receivers
 * the same slot. Kept tiny and side-effect-free for that reason — every policy
 * decision (rights, revalidation, blocked waiters) lives in the callers.
 *
 * ep_enqueue copies from a KERNEL buffer: the caller does copy_from_user first,
 * so a fault cannot happen with the lock held. */
static inline int ep_full(const struct endpoint *e)  { return e->count >= EP_QUEUE_SLOTS; }
static inline int ep_empty(const struct endpoint *e) { return e->count == 0; }

static void ep_enqueue(struct endpoint *e, const uint8_t *src, int len, int sender) {
    uint32_t slot = (e->head + e->count) % EP_QUEUE_SLOTS;
    struct ep_msg *m = &e->q[slot];
    if (len < 0) len = 0;
    if (len > IPC_MSG_MAX) len = IPC_MSG_MAX;
    for (int i = 0; i < len; i++) m->data[i] = src[i];
    m->len    = len;
    m->sender = sender;
    __asm__ volatile ("" ::: "memory");
    e->count++;
}

/* Dequeue into a kernel buffer. Returns the length, and writes the sender id
 * through `sender` so the caller can publish it as last_sender AFTER the copy to
 * userspace has succeeded — a failed copy must not advance the reply identity. */
static int ep_dequeue(struct endpoint *e, uint8_t *dst, int max, int *sender) {
    struct ep_msg *m = &e->q[e->head];
    int len = m->len;
    if (len < 0) len = 0;
    if (len > max) len = max;
    for (int i = 0; i < len; i++) dst[i] = m->data[i];
    if (sender) *sender = m->sender;
    /* Scrub the slot before releasing it. An endpoint slot outlives the message
     * in it, and the next sender may be a different, mutually distrusting task;
     * leaving the bytes would make the ring a residue channel between them. */
    for (int i = 0; i < IPC_MSG_MAX; i++) m->data[i] = 0;
    m->len    = 0;
    m->sender = -1;
    e->head = (e->head + 1) % EP_QUEUE_SLOTS;
    e->count--;
    return len;
}

/* ------------------------------------------------------------------------- *
 *  Capability-addressed IPC (audit finding C-1).
 *
 *  Every IPC syscall names its object by a CSPACE SLOT, and the kernel derives
 *  the endpoint/notification index from the capability found there. Userspace
 *  never supplies an object index.
 *
 *  This is the fix for the audit's headline finding. Previously the dispatch
 *  table gated IPC on "hold something in slot 3" (with SC_ANYTYPE, and every task
 *  is created holding a CAP_FRAME there), and the endpoint index came straight
 *  out of a userspace register, bounds-checked only against MAX_ENDPOINTS. The
 *  `object` field of CAP_ENDPOINT — the field that names WHICH endpoint — was
 *  written, delegated, revoked and lineage-tracked, and then never consulted at
 *  the point of use. Any ring-3 task could therefore receive on, send to, and
 *  forge replies on any endpoint in the system, including the filesystem
 *  server's, which defeated the whole ring-3 server isolation story.
 *
 *  The two resolvers below are the choke point. Because they call cap_lookup(),
 *  each one enforces, in one place:
 *    - the slot actually holds a live capability (non-null, serial != 0);
 *    - of the RIGHT TYPE (CAP_ENDPOINT / CAP_NOTIFICATION) — so a CAP_FRAME can
 *      no longer authorise IPC;
 *    - carrying the required RIGHT for the direction (READ to receive, WRITE to
 *      send), so a send-only client capability cannot be used to intercept;
 *    - that passes the serial-keyed lineage generation check, so a revoked or
 *      stale capability fails here exactly as it does everywhere else.
 *  Only then is `object` trusted, and it is re-bounds-checked before use.
 * ------------------------------------------------------------------------- */

/* Resolve an endpoint capability slot to the endpoint index it names.
 * Returns 0 and writes *out_ep on success; negative on any failure. */
/* Carries S13a: a task can operate on an IPC object only through a capability
 * naming it. This resolver IS the gate for every SC_NONE entry in the IPC
 * block of the dispatch table, which is why finding [C-1] was a defect here
 * rather than in any individual handler. */
int ipc_ep_from_slot(uint32_t slot, uint32_t need_rights, uint32_t *out_ep) {
    struct capability *c = cap_lookup(slot, need_rights);
    if (!c || c->type != CAP_ENDPOINT) return -1;
    if (c->object >= EP_INDEX_MAX)     return -1;
    /* The index may name a RETYPED endpoint (roadmap 0.3), so bounds-checking it
     * is no longer sufficient — a retyped object can be destroyed while a stale
     * capability still names its index. Resolve it here so every IPC syscall
     * fails closed on a dead object at the same choke point that enforces the
     * capability, rather than each handler having to remember to check. */
    if (!endpoint_by_index((uint32_t)c->object)) return -1;
    if (out_ep) *out_ep = (uint32_t)c->object;
    return 0;
}

/* Resolve a notification capability slot to the notification index it names.
 * Same discipline as ipc_ep_from_slot; notifications were ambient in exactly the
 * same way (finding C-2), which let any task forge IRQ delivery to a ring-3
 * driver, since SYS_IRQ_REGISTER routes hardware interrupts to these slots. */
int ipc_notif_from_slot(uint32_t slot, uint32_t need_rights, uint32_t *out_slot) {
    struct capability *c = cap_lookup(slot, need_rights);
    if (!c || c->type != CAP_NOTIFICATION)  return -1;
    if (c->object >= NOTIF_INDEX_MAX)       return -1;
    if (!notification_by_index((uint32_t)c->object)) return -1;   /* see ipc_ep_from_slot */
    if (out_slot) *out_slot = (uint32_t)c->object;
    return 0;
}

/* After tasks[cur].saved_ksp is published: turn pending_block into a real
 * wake-visible wait, or complete immediately if the event already arrived
 * (reply in mailbox / target already dead / badge pending). Returns 1 if the
 * task is now blocked (caller should switch away), 0 to resume the same frame. */
int ipc_publish_pending_block(int cur) {
    if (cur <= 0 || cur >= g_max_tasks) return 0;
    uint32_t kind = tasks[cur].pending_block;
    if (kind == 0) return 0;

    /* NB: pending_block is deliberately NOT cleared here.
     *
     * It is this task's public declaration of "I am committed to blocking, I am
     * just not visibly blocked yet", and h_ipc_reply_to reads it to decide
     * between retrying (-2) and dropping a reply as unwanted (0). Clearing it
     * before the state transition below reopens exactly the window it exists to
     * cover: for the instructions between the clear and `state = TASK_BLOCKED_*`
     * the task would advertise neither "blocked" nor "about to block", and a
     * server replying from another CPU in that gap would drop the reply, report
     * success, and leave the client parked forever.
     *
     * So every path below clears it at the point the outcome is decided, and for
     * the endpoint/notification cases that clear happens UNDER ipc_lock together
     * with the state write — the same lock h_ipc_reply_to takes — so the two are
     * one atomic transition from any other CPU's point of view. */

    struct interrupt_frame64 *f =
        (struct interrupt_frame64 *)tasks[cur].saved_ksp;
    if (!f) {
        /* No frame: refuse to publish a waiter (would be a use-after-stale). */
        tasks[cur].pending_block = 0;
        tasks[cur].state        = TASK_RUNNABLE;
        tasks[cur].runnable_ctx = 1;
        /* Withdraw the receive declaration too. A stale ipc_recv_block would make
         * h_ipc_reply_to refuse every future reply to this task -- a permanent
         * wedge from an abandoned wait. */
        tasks[cur].ipc_recv_block = 0;
        return 0;
    }

    if (kind == TASK_BLOCKED_IPC) {
        int reply_ep = tasks[cur].blocked_on;
        struct endpoint *e = (reply_ep < 0) ? 0 : endpoint_by_index((uint32_t)reply_ep);
        if (!e) {
            /* Out of range, or a retyped endpoint destroyed while this task was
             * on its way to blocking on it. Either way there is nothing to wait
             * on: resume rather than park on an object that cannot be signalled. */
            tasks[cur].pending_block = 0;
            tasks[cur].state = TASK_RUNNABLE;
            tasks[cur].runnable_ctx = 1;
            tasks[cur].ipc_recv_block = 0;   /* see the !f case above */
            return 0;
        }
        ipc_lock();
        tasks[cur].pending_block = 0;   /* under the lock: see the note above */
        /* A message raced in before we published the waiter: the reply for a
         * SYS_IPC_CALL, or -- for a blocking SYS_IPC_RECV_BLOCK -- the very
         * request this task is waiting for. Either way it is already queued, so
         * complete inline rather than parking on a non-empty endpoint. */
        if (!ep_empty(e)) {
            int recv_wait = (tasks[cur].ipc_recv_block != 0);
            /* A receiver's buffer is only as big as it said; a reply buffer is
             * IPC_MSG_MAX by contract. */
            int cap_len = recv_wait ? (int)tasks[cur].ipc_recv_max : IPC_MSG_MAX;
            uint8_t kbuf[IPC_MSG_MAX];
            int sender = -1;
            int len = ep_dequeue(e, kbuf, cap_len, &sender);
            if (len > 0 && tasks[cur].ipc_reply_buf != 0) {
                copy_to_user((void *)(addr_t)tasks[cur].ipc_reply_buf, kbuf,
                             (size_t)len);
            }
            e->last_sender = sender;
            f->rax = (uint64_t)(uint32_t)len;
            /* Mint BEFORE the task is marked runnable — the same rule the wake
             * path in sys_ipc_send follows, and for the same reason (see the
             * long note there; getting it wrong there was a measured hang).
             *
             * Strictly this path does not need it: `cur` is the task executing
             * this very syscall, still claimed by this CPU, so nothing can
             * observe the gap. It is done anyway so the rule holds without
             * exception — "a receiver holds its reply right before it is
             * schedulable". An invariant with one documented exception is one a
             * later change quietly widens. */
            if (recv_wait && sender > 0 && sender < g_max_tasks)
                cap_install_reply_for(cur, sender);
            tasks[cur].state        = TASK_RUNNABLE;
            tasks[cur].runnable_ctx = 1;
            tasks[cur].blocked_on   = -1;
            tasks[cur].ipc_recv_block = 0;
            ipc_unlock();
            return 0;   /* resume same task with the message in hand */
        }
        e->blocked_waiter       = cur;
        tasks[cur].state        = TASK_BLOCKED_IPC;
        tasks[cur].runnable_ctx = 0;
        __asm__ volatile ("" ::: "memory");
        ipc_unlock();
        return 1;
    }

    if (kind == TASK_BLOCKED_WAIT) {
        int tid = tasks[cur].blocked_on;
        /* Re-check: target may have exited after the handler looked. */
        if (tid < 0 || tid >= g_max_tasks || tasks[tid].state == TASK_DEAD) {
            tasks[cur].pending_block = 0;
            f->rax = 0;
            tasks[cur].state        = TASK_RUNNABLE;
            tasks[cur].runnable_ctx = 1;
            tasks[cur].blocked_on   = -1;
            return 0;
        }
        tasks[tid].waiter       = cur;
        tasks[cur].pending_block = 0;
        tasks[cur].state        = TASK_BLOCKED_WAIT;
        tasks[cur].runnable_ctx = 0;
        __asm__ volatile ("" ::: "memory");
        return 1;
    }

    if (kind == TASK_BLOCKED_NOTIF) {
        int slot = tasks[cur].blocked_on_notif;
        struct notification *n = (slot < 0) ? 0 : notification_by_index((uint32_t)slot);
        if (!n) {
            tasks[cur].pending_block = 0;
            tasks[cur].state = TASK_RUNNABLE;
            tasks[cur].runnable_ctx = 1;
            tasks[cur].ipc_recv_block = 0;   /* see the !f case above */
            return 0;
        }
        ipc_lock();
        tasks[cur].pending_block = 0;   /* under the lock: see the note above */
        if (n->pending_badge != 0) {
            uint32_t b = n->pending_badge;
            n->pending_badge = 0;
            f->rax = 0;
            f->rbx = (uint64_t)b;
            tasks[cur].state        = TASK_RUNNABLE;
            tasks[cur].runnable_ctx = 1;
            ipc_unlock();
            return 0;
        }
        n->blocked_waiter       = cur;
        tasks[cur].state        = TASK_BLOCKED_NOTIF;
        tasks[cur].runnable_ctx = 0;
        __asm__ volatile ("" ::: "memory");
        ipc_unlock();
        return 1;
    }

    tasks[cur].pending_block = 0;
    tasks[cur].state        = TASK_RUNNABLE;
    tasks[cur].runnable_ctx = 1;
    return 0;
}

/* Undo a published block when the scheduler cannot switch away (no other
 * runnable task). Clears waiter links so we do not leave a dangling publish. */
void ipc_unpublish_block(int cur) {
    if (cur <= 0 || cur >= g_max_tasks) return;
    int st = (int)tasks[cur].state;
    if (st == TASK_BLOCKED_IPC) {
        int ep = tasks[cur].blocked_on;
        ipc_lock();
        struct endpoint *e = (ep < 0) ? 0 : endpoint_by_index((uint32_t)ep);
        if (e && e->blocked_waiter == cur) e->blocked_waiter = -1;
        ipc_unlock();
        tasks[cur].blocked_on = -1;
        /* Un-declare the receive too, or the next wake of this task would be
         * completed as a receive (minting a reply right, rewriting last_sender)
         * on the strength of a wait that was withdrawn. */
        tasks[cur].ipc_recv_block = 0;
    } else if (st == TASK_BLOCKED_WAIT) {
        int tid = tasks[cur].blocked_on;
        if (tid >= 0 && tid < g_max_tasks && tasks[tid].waiter == cur)
            tasks[tid].waiter = -1;
        tasks[cur].blocked_on = -1;
    } else if (st == TASK_BLOCKED_NOTIF) {
        int slot = tasks[cur].blocked_on_notif;
        ipc_lock();
        struct notification *n = (slot < 0) ? 0 : notification_by_index((uint32_t)slot);
        if (n && n->blocked_waiter == cur) n->blocked_waiter = -1;
        ipc_unlock();
    }
    tasks[cur].state        = TASK_RUNNABLE;
    tasks[cur].runnable_ctx = 1;
}

int sys_ipc_send(uint32_t ep, const void *msg, size_t len) {
    struct endpoint *e = endpoint_by_index(ep);
    if (!e) return -1;
    if (len > IPC_MSG_MAX) len = IPC_MSG_MAX;

    /* Snapshot the authorizing write capability (slot 3) so we can confirm it
     * still holds the same identity after the yield loop below. Strictly
     * additive: if the caller has no such cap at entry we don't newly reject
     * (preserves the in-kernel shell caller); we only abort a send whose
     * authorizing cap was revoked/replaced mid-spin (lookup/use TOCTOU). */
    cap_snapshot_t auth = cap_snapshot(cap_lookup(3, CAP_RIGHT_WRITE));

    /* If a task is blocking in SYS_IPC_CALL waiting for a reply on this
     * endpoint, deliver directly: copy from the sender's userspace into a
     * kernel buffer, switch to the waiter's address space, copy into its reply
     * buffer, patch its saved trap frame's rax with the length, then mark it
     * runnable.  ipc_block_switch in interrupt_handler64 already saved the
     * waiter's frame — the next timer tick will iretq it back to ring 3 with
     * the return value in eax. */
    ipc_lock();
    int waiter = e->blocked_waiter;
    /* ep_empty is part of the condition, not an optimisation (roadmap 1.3).
     *
     * Handing this message straight to a blocked receiver while the queue still
     * holds older ones would deliver it out of order. It is a no-op for the reply
     * wait -- ipc_publish_pending_block only parks a caller on an EMPTY endpoint,
     * completing inline otherwise -- so this tightens the guard for the blocking
     * receive without changing the SYS_IPC_CALL path at all. */
    if (waiter > 0 && waiter < g_max_tasks &&
            tasks[waiter].state == TASK_BLOCKED_IPC && ep_empty(e)) {
        if (auth.valid && !cap_revalidate(3, CAP_RIGHT_WRITE, &auth)) { ipc_unlock(); return -1; }

        /* A blocked RECEIVER named its own buffer size; a blocked CALLER's reply
         * buffer is IPC_MSG_MAX by contract. Truncate to whichever applies rather
         * than overrunning a receiver that asked for less. */
        int recv_wait = (tasks[waiter].ipc_recv_block != 0);
        if (recv_wait && len > (size_t)tasks[waiter].ipc_recv_max)
            len = (size_t)tasks[waiter].ipc_recv_max;

        uint8_t kbuf[IPC_MSG_MAX];
        int copy_len = 0;
        if (len > 0) {
            if (copy_from_user(kbuf, msg, len) != 0) { ipc_unlock(); return -1; }
            copy_len = (int)len;
        }

        if (copy_len > 0 && tasks[waiter].ipc_reply_buf != 0) {
            /* Deliver into the waiter's reply buffer. copy_to_user/user_copy
             * translates the destination through tasks[get_current_task()].cr3,
             * so the *current task* must be the waiter for its buffer to resolve
             * -- merely switching cr3 is not enough (user_copy re-derives and
             * restores cr3 itself). This was the bug: the reply was walked
             * through the sender's page tables and written into the sender's
             * address space, so a SYS_IPC_CALL caller (the shell) only ever saw a
             * zeroed reply. Interrupts are masked so a timer tick cannot observe
             * the transient current-task ON THIS CPU -- but an auditor on ANOTHER
             * core can, which is what the impersonation bracket declares to it
             * (sched_impersonate_enter, scheduler.c). */
            uint64_t fl;
            __asm__ volatile ("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
            int sender = get_current_task();
            sched_impersonate_enter();
            set_current_task(waiter);
            copy_to_user((void *)(addr_t)tasks[waiter].ipc_reply_buf, kbuf,
                         (size_t)copy_len);
            set_current_task(sender);
            sched_impersonate_exit();
            __asm__ volatile ("push %0; popfq" :: "r"(fl) : "memory", "cc");
        }

        /* Patch the waiter's saved interrupt frame so that when the timer
         * resumes it, eax holds the reply length (the return value of
         * sys_ipc_call). saved_ksp is always valid when blocked_waiter is set
         * (publish-after-save); refuse if not. */
        struct interrupt_frame64 *wf =
            (struct interrupt_frame64 *)tasks[waiter].saved_ksp;
        if (!wf) { ipc_unlock(); return -1; }
        wf->rax = (uint64_t)(uint32_t)copy_len;

        /* ---- Everything the woken server needs, BEFORE it can run ------------
         *
         * Completing a blocking RECEIVE, not a reply: the server must end up in
         * exactly the state the polling SYS_IPC_RECV would have left it in, or
         * the two receives differ in authority — the interesting half of roadmap
         * 1.3. So the sender becomes the endpoint's attested identity, and the
         * server gets the one-shot right to answer it.
         *
         * THE ORDER HERE IS LOAD-BEARING, and getting it wrong cost a measured
         * regression. The first version minted the reply capability after
         * `state = TASK_RUNNABLE` and after ipc_unlock(), to keep cap_lock out
         * from under endpoint_lock. But a task is schedulable the instant its
         * state flips: another CPU picks it up, it returns to ring 3, services
         * the request and calls SYS_IPC_REPLY_TO — all before the mint lands.
         * cap_lookup then finds no CAP_REPLY and answers SYS_ERR_PERM, which is
         * a PERMANENT code, so the server correctly drops the reply (the IPC
         * retry contract forbids looping on it) and the client waits forever.
         *
         * That is not theoretical: instrumenting console_server's permanent-drop
         * path reproduced it in 4 of 5 failing boots under `-smp 4` with the host
         * loaded, at ~33% of sessions against 0% for the control. It is invisible
         * on one CPU, because there is no second CPU to run the server inside the
         * window — which is exactly why it survived the first round of testing.
         *
         * So the mint happens under ipc_lock, before the wake. cap_lock nesting
         * inside endpoint_lock is a NEW lock order, and it is safe because it is
         * the only one: no path in the tree takes an IPC lock while holding
         * cap_lock (capability.c and untyped.c never reference either). Keep it
         * that way.
         *
         * SYS_IPC_RECV and the publish path still mint after their unlock, and
         * that stays correct for a reason that does not apply here: there the
         * receiver is the CURRENT task, still executing its own syscall and still
         * claimed by this CPU, so no one can observe the gap. This mint targets
         * another task. */
        if (recv_wait) {
            int sender_tid = get_current_task();
            e->last_sender = sender_tid;
            tasks[waiter].ipc_recv_block = 0;
            if (!cap_install_reply_for(waiter, sender_tid)) {
                /* Refuse rather than wake a server into a request it has no
                 * right to answer — that is the failure this ordering exists to
                 * prevent, and doing it deliberately would be no better. The
                 * waiter stays blocked and is woken by the next send; the sender
                 * gets an error it can report. Reachable only if the receiver is
                 * at MAX_CAPS_PER_TASK. */
                ipc_unlock();
                return -1;
            }
        }

        e->blocked_waiter = -1;
        __asm__ volatile ("" ::: "memory");
        tasks[waiter].state        = TASK_RUNNABLE;
        tasks[waiter].runnable_ctx = 1;
        tasks[waiter].blocked_on   = -1;
        ipc_unlock();
        return 0;
    }

    /* Queue it. -2 now means the endpoint's bounded ring is genuinely FULL, not
     * merely occupied: with EP_QUEUE_SLOTS deep, concurrent clients enqueue
     * instead of colliding, so the retry path is reached only under real
     * back-pressure rather than on every second request (roadmap 1.3, [I-5]). */
    if (ep_full(e)) { ipc_unlock(); return -2; }

    if (auth.valid && !cap_revalidate(3, CAP_RIGHT_WRITE, &auth)) { ipc_unlock(); return -1; }

    /* Copy into a kernel buffer BEFORE taking the slot. copy_from_user can fault,
     * and faulting with a half-filled queue slot published would leave a message
     * of indeterminate contents visible to the receiver. */
    uint8_t kbuf2[IPC_MSG_MAX];
    if (len > 0 && copy_from_user(kbuf2, msg, len) != 0) { ipc_unlock(); return -1; }
    ep_enqueue(e, kbuf2, (int)len, get_current_task());
    ipc_unlock();
    return 0;
}

int sys_ipc_recv(uint32_t ep, void *msg, size_t max_len) {
    struct endpoint *e = endpoint_by_index(ep);
    if (!e) return -1;

    /* See sys_ipc_send: snapshot the authorizing read capability and revalidate
     * it after the yield loop so a revoke mid-spin aborts the receive. */
    cap_snapshot_t auth = cap_snapshot(cap_lookup(3, CAP_RIGHT_READ));

    /* Non-blocking (see sys_ipc_send): no message yet -> caller polls from ring
     * 3 and is timer-preempted, rather than spinning on the broken cooperative
     * yield in-kernel. */
    ipc_lock();
    if (ep_empty(e)) { ipc_unlock(); return -2; }

    if (auth.valid && !cap_revalidate(3, CAP_RIGHT_READ, &auth)) { ipc_unlock(); return -1; }

    /* Dequeue into a kernel buffer first, then copy out. Doing it the other way
     * round — copying straight from the slot to userspace — would leave the
     * message dequeued but undelivered if the user copy faulted, silently losing
     * a request that the sender is blocked waiting for a reply to. */
    uint8_t kbuf[IPC_MSG_MAX];
    int sender = -1;
    int len = ep_dequeue(e, kbuf, (int)max_len, &sender);
    if (len > 0 && copy_to_user(msg, kbuf, (size_t)len) != 0) { ipc_unlock(); return -1; }

    /* Only now is this the message being serviced, so only now does its sender
     * become the identity SYS_IPC_SENDER answers about. */
    e->last_sender = sender;
    __asm__ volatile ("" ::: "memory");
    ipc_unlock();

    /* Mint the one-shot right to answer THIS request (roadmap 1.3).
     *
     * Deliberately after ipc_unlock(): cap_install_object takes cap_lock, and
     * taking cap_lock underneath endpoint_lock would create a second lock order
     * between two locks that are otherwise unrelated. Nothing between the unlock
     * and here can invalidate the mint — `sender` is a value, not a pointer, and
     * a sender that dies before the reply is handled by the liveness check in
     * h_ipc_reply_to.
     *
     * Overwriting a previous unconsumed CAP_REPLY is correct: a server that
     * receives twice without replying has abandoned the older request, and the
     * older caller is woken by its own timeout/teardown path rather than left
     * nameable forever. */
    if (sender > 0 && sender < g_max_tasks)
        cap_install_object(CAPSLOT_REPLY, CAP_REPLY, (uint64_t)sender,
                           CAP_RIGHT_WRITE, 0);
    return len;
}

int sys_ipc_reply(uint32_t ep, const void *msg, size_t len) {

    return sys_ipc_send(ep, msg, len);
}
/* Notification objects — one 32-bit badge accumulator per slot, plus a
 * blocked-waiter field mirroring the endpoint design. */
struct notification notifications[MAX_NOTIFICATIONS];

/* sys_notify: OR `badge` into the pending_badge of notification `notif_slot`.
 * If a task is currently blocking in SYS_WAIT_NOTIFY on this slot, wake it:
 * deliver the accumulated badge via its saved trap frame (rbx), patch its
 * return value (rax=0), and mark it runnable.  The badge is delivered through
 * the saved interrupt frame so no cross-address-space pointer copy is needed.
 *
 * Multiple notify() calls before a wait() accumulate badges via OR. */
int sys_notify(uint32_t notif_slot, uint32_t badge) {
    struct notification *n = notification_by_index(notif_slot);
    if (!n) return -1;

    ipc_lock();
    n->pending_badge |= badge;

    int waiter = n->blocked_waiter;
    if (waiter > 0 && waiter < g_max_tasks &&
            tasks[waiter].state == TASK_BLOCKED_NOTIF) {
        uint32_t b = n->pending_badge;
        n->pending_badge    = 0;
        n->blocked_waiter   = -1;

        /* Patch the waiter's saved trap frame: rax=0 (success), rbx=badge.
         * saved_ksp is valid whenever blocked_waiter is published. */
        struct interrupt_frame64 *wf =
            (struct interrupt_frame64 *)tasks[waiter].saved_ksp;
        if (wf) {
            wf->rax = 0;
            wf->rbx = (uint64_t)b;
        }

        __asm__ volatile ("" ::: "memory");
        tasks[waiter].state        = TASK_RUNNABLE;
        tasks[waiter].runnable_ctx = 1;
    }
    ipc_unlock();
    return 0;
}

/* sys_wait_notify: if a badge is already pending, consume it and return 0
 * (badge written via r->rbx → frame->rbx by interrupt_handler64).  Otherwise
 * record a pending block; ipc_block_switch saves the frame then publishes the
 * notif waiter so a concurrent sys_notify cannot race a null saved_ksp. */
int sys_wait_notify(uint32_t notif_slot, uint32_t *out_badge) {
    struct notification *n = notification_by_index(notif_slot);
    if (!n) return -1;

    ipc_lock();
    if (n->pending_badge != 0) {
        *out_badge = n->pending_badge;
        n->pending_badge = 0;
        ipc_unlock();
        return 0;
    }

    /* No badge pending — intent only; not wake-visible until publish. */
    int cur = get_current_task();
    tasks[cur].blocked_on_notif = (int)notif_slot;
    tasks[cur].pending_block    = TASK_BLOCKED_NOTIF;
    /* out_badge and r->rbx will be patched by sys_notify when it wakes us. */
    *out_badge = 0;
    ipc_unlock();
    return 0;
}


/* sys_poll_notify: sys_wait_notify's non-blocking twin. Consume a pending badge
 * if there is one, and otherwise report that there is not -- never block.
 *
 * WHY THIS EXISTS, AND IT IS NOT ONLY A CONVENIENCE.
 *
 * A driver servicing hardware in a loop has, until now, had no way to ask "has
 * my device notified me?" without risking a block: sys_wait_notify parks the
 * caller when nothing is pending, so a single-threaded driver that also wants to
 * poll a device register cannot check both. Every driver in this tree has worked
 * around it by relying on being the only runnable task, which is a property of
 * the test harness rather than of the system.
 *
 * The second reason is about EVIDENCE, and it is what prompted this. Several
 * properties in SECURITY.md are of the form "no event arrives while X", and a
 * blocking wait cannot witness one: it either returns because the event happened
 * (the property is broken) or it blocks forever (the property held, and the test
 * hangs, which the harness reports as a timeout indistinguishable from a crash).
 * S46's mask-until-acknowledged is exactly that shape, and its only witness was a
 * livelock -- a consequence QEMU stopped producing when routing moved to the I/O
 * APIC. A test can now assert the ABSENCE of a notification directly.
 *
 * IPC_AGAIN (-2) rather than 0-with-a-zero-badge, so "nothing pending" is a
 * distinct answer from "a badge of zero arrived", and so it cannot be confused
 * with SYS_ERR_PERM (-1) by a caller testing `< 0`. That is the same discipline
 * SYS_IPC_RECV follows and the same one captest's exact-code checks rely on. */
int sys_poll_notify(uint32_t notif_slot, uint32_t *out_badge) {
    struct notification *n = notification_by_index(notif_slot);
    if (!n) return -1;

    ipc_lock();
    if (n->pending_badge != 0) {
        *out_badge = n->pending_badge;
        n->pending_badge = 0;
        ipc_unlock();
        return 0;
    }
    ipc_unlock();

    /* Deliberately no pending_block, no blocked_waiter, no state change: this
     * call must leave the task exactly as it found it, or a poll in a loop would
     * accumulate the intent-to-block that ipc_publish_pending_block acts on. */
    *out_badge = 0;
    return IPC_AGAIN;
}

/* SYS_POLL_NOTIFY (106): rbx = cspace slot of a CAP_NOTIFICATION with READ.
 * Gated identically to SYS_WAIT_NOTIFY -- a task may only poll a notification it
 * holds, exactly as it may only wait on one (finding C-2). Being non-blocking
 * changes when the answer comes back, never who is entitled to ask. */
void h_poll_notify(struct interrupt_frame64 *r) {
    uint32_t ns;
#ifdef POLL_NOTIFY_UNGATED
    /* Control arm: take the slot as a raw notification index with no capability
     * consulted -- finding C-2's shape in a new syscall, which is exactly the
     * mistake a non-blocking "convenience" variant invites. See
     * make smoke-captest-poll-notify-control. */
    ns = (uint32_t)r->rbx;
#else
    if (ipc_notif_from_slot((uint32_t)r->rbx, CAP_RIGHT_READ, &ns) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; r->rbx = 0; return;
    }
#endif
    uint32_t badge = 0;
    r->rax = (uint64_t)(uint32_t)sys_poll_notify(ns, &badge);
    r->rbx = badge;
}

/* SYS_IPC_SEND (21): rbx = cspace slot of a CAP_ENDPOINT with WRITE. */
void h_ipc_send(struct interrupt_frame64 *r) {
    uint32_t ep;
    if (ipc_ep_from_slot((uint32_t)r->rbx, CAP_RIGHT_WRITE, &ep) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    r->rax = sys_ipc_send(ep, (const void*)(addr_t)r->rcx, r->rdx);
}

/* SYS_IPC_CALL (23): atomic send-then-block-until-reply.
 *   rbx = cspace slot of a CAP_ENDPOINT with WRITE (the service to call)
 *   rcx = IGNORED (was: reply endpoint index — see below)
 *   rdx = userspace ptr to message to send
 *   rsi = send length
 *   rdi = userspace ptr to reply buffer
 *
 * The reply endpoint is NO LONGER caller-supplied: it is always this task's own
 * private reply endpoint (reply_ep_for_task). A caller cannot name someone
 * else's reply endpoint to park on, and — since no task holds a capability to
 * another task's reply endpoint — cannot be woken through one either. That
 * deletes a forgery surface rather than merely gating it, and retires the shared
 * global FS_EP_REP on which concurrent clients used to collide (finding I-5).
 *
 * rcx is accepted and ignored so the 5-argument ABI and the existing userspace
 * wrapper shape are unchanged; the argument is now vestigial.
 *
 * The handler deposits the message and records a pending block only — the reply
 * endpoint's blocked_waiter is *not* published here. interrupt_handler64 calls
 * ipc_block_switch, which saves the trap frame first and only then publishes the
 * waiter (so a cross-CPU reply cannot race a null saved_ksp). */
void h_ipc_call(struct interrupt_frame64 *r) {
    const void *msg   = (const void *)(addr_t)r->rdx;
    size_t   send_len = (size_t)r->rsi;
    uint64_t reply_buf = r->rdi;   /* waiter's reply buffer: a user address, may be high */

    uint32_t send_ep;
    if (ipc_ep_from_slot((uint32_t)r->rbx, CAP_RIGHT_WRITE, &send_ep) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    int cur = get_current_task();
    int rep = reply_ep_for_task(cur);
    if (rep < 0) { r->rax = (uint32_t)-1; return; }
    uint32_t reply_ep = (uint32_t)rep;

    /* Declare the intent to block BEFORE the request becomes visible.
     *
     * Ordering is the whole point here. sys_ipc_send() publishes the request
     * under ipc_lock, and the moment it does, a server on another CPU may
     * receive it, service it, and reply -- all before this handler's next
     * instruction retires. h_ipc_reply_to() decides what to do with that reply
     * by looking at this task: TASK_BLOCKED_IPC means deliver, pending_block ==
     * TASK_BLOCKED_IPC means "committed but not published yet, retry (-2)", and
     * neither means "not waiting on us, drop it (0)".
     *
     * With the send first, there was a window in which the request was visible
     * but pending_block was still 0, so a fast reply landed in the third case:
     * dropped, reported to the server as delivered, and the client then parked
     * on a reply that could never arrive. It reproduced as an intermittent
     * console hang under SMP -- the shell wedged mid-print with the server idle,
     * most often on back-to-back writes (the login-failure path), which is
     * exactly where the server is already in recv and answers fastest.
     *
     * Setting the intent first closes it: the request cannot be seen before the
     * declaration that accompanies it. sys_ipc_send's ipc_lock acquire/release
     * pairs with the reader's, so a CPU that observes the request also observes
     * pending_block. */
    tasks[cur].ipc_reply_buf = reply_buf;
    tasks[cur].blocked_on    = (int)reply_ep;
    tasks[cur].pending_block = TASK_BLOCKED_IPC;
    __asm__ volatile ("" ::: "memory");

    /* Deposit the outgoing message into send_ep. */
    int rc = sys_ipc_send(send_ep, msg, send_len);
    if (rc < 0) {
        /* Nothing was published, so nobody can reply: withdraw the declaration
         * rather than park on an endpoint no request was sent to. Callers retry
         * -2 (mailbox full) from ring 3. */
        tasks[cur].pending_block = 0;
        tasks[cur].blocked_on    = -1;
        tasks[cur].ipc_reply_buf = 0;
        r->rax = (uint32_t)rc;
        return;
    }

    /* r->rax is set by interrupt_handler64 after we return; a wake patches
     * saved_ksp->rax with the reply length. */
    r->rax = 0;
}
/* SYS_IPC_RECV (22): rbx = cspace slot of a CAP_ENDPOINT with READ.
 * READ is the receive right: a client minted WRITE-only (the connect path) can
 * send to a server but can never dequeue that server's traffic. */
void h_ipc_recv(struct interrupt_frame64 *r) {
    uint32_t ep;
    if (ipc_ep_from_slot((uint32_t)r->rbx, CAP_RIGHT_READ, &ep) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    r->rax = sys_ipc_recv(ep, (void*)(addr_t)r->rcx, r->rdx);
}
/* SYS_IPC_RECV_BLOCK (94): rbx = cspace slot of a CAP_ENDPOINT with READ.
 *
 * Roadmap 1.3's last piece. SYS_IPC_RECV returns IPC_AGAIN on an empty queue, so
 * a server with nothing to do polls: it stays RUNNABLE, consumes scheduling
 * turns it cannot use, and on one core actively delays the clients it is waiting
 * for. It also makes priority inheritance inexpressible, because the kernel has
 * no record of who is waiting on what.
 *
 * The wait itself reuses the machinery SYS_IPC_CALL already uses -- record the
 * intent, let interrupt_handler64 save the frame, then publish under ipc_lock --
 * because the hazard is the same one: a waiter published before its frame is
 * saved can be woken by another CPU patching a null saved_ksp. The publish
 * ordering is the load-bearing part and is not duplicated here.
 *
 * The empty test and the block intent are set under ONE ipc_lock hold. Dropping
 * the lock between them would reopen the classic lost-wakeup: a sender could
 * enqueue and find no waiter in the gap, and this task would then park on a queue
 * that already had its message. */
void h_ipc_recv_block(struct interrupt_frame64 *r) {
    uint32_t ep;
    if (ipc_ep_from_slot((uint32_t)r->rbx, CAP_RIGHT_READ, &ep) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    struct endpoint *e = endpoint_by_index(ep);
    if (!e) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    int cur = get_current_task();
    if (cur <= 0 || cur >= g_max_tasks) { r->rax = (uint32_t)-1; return; }

    for (;;) {
        ipc_lock();
        if (!ep_empty(e)) {
            /* Message already waiting: complete inline, exactly as SYS_IPC_RECV
             * does. Nothing blocks, so this is the common case for a busy server
             * and costs it no extra context switch.
             *
             * The retry is not decoration. sys_ipc_recv re-acquires ipc_lock, so
             * a second receiver on this endpoint can drain the queue in between
             * and leave it answering IPC_AGAIN -- which THIS syscall must never
             * return. Its whole contract is that a negative result is permanent,
             * and both ring-3 servers act on that by reporting and exiting, so
             * leaking a -2 here would kill a server on a benign race rather than
             * blocking it. Re-decide instead: either there is still a message, or
             * the endpoint is empty again and blocking is the right answer.
             * Each iteration means some other receiver got a message, so this
             * makes progress for the system even when it retries. */
            ipc_unlock();
            int rc = sys_ipc_recv(ep, (void *)(addr_t)r->rcx, r->rdx);
            if (rc == -2) continue;
            r->rax = (uint32_t)rc;
            return;
        }

        /* Empty: commit to blocking. Only intent is recorded here -- the task is
         * not wake-visible until ipc_publish_pending_block runs with a saved
         * frame. */
        tasks[cur].ipc_reply_buf  = (uint64_t)r->rcx;
        tasks[cur].ipc_recv_max   = (uint32_t)r->rdx;
        tasks[cur].ipc_recv_block = 1;
        tasks[cur].blocked_on     = (int)ep;
        tasks[cur].pending_block  = TASK_BLOCKED_IPC;
        ipc_unlock();

        /* Overwritten by the waker patching saved_ksp->rax with the length. */
        r->rax = 0;
        return;
    }
}

/* SYS_IPC_REPLY (24): rbx = cspace slot of a CAP_ENDPOINT with WRITE. */
void h_ipc_reply(struct interrupt_frame64 *r) {
    uint32_t ep;
    if (ipc_ep_from_slot((uint32_t)r->rbx, CAP_RIGHT_WRITE, &ep) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    r->rax = sys_ipc_reply(ep, (const void*)(addr_t)r->rcx, r->rdx);
}

/* SYS_IPC_SENDER (73): return the authenticated uid of the task that sent the
 * message most recently received on endpoint `ebx`, writing its gid to *ecx.
 * This is the zero-trust identity anchor for a server (e.g. the fs_server): the
 * value is tasks[last_sender].uid — established only by a successful login
 * (SYS_AUTH) and recorded by the kernel when the message was sent — NOT anything
 * the client placed in the message, so a client cannot claim to be another user.
 * Returns (uint32_t)-1 when there is no valid last sender (none yet, or it has
 * since exited). Slot-3 READ is enforced by the dispatch table, so only a task
 * that can legitimately receive on the endpoint may query its sender. */
void h_ipc_sender(struct interrupt_frame64 *r) {
    uint32_t ep;
    /* READ (the receive right): only a task that can legitimately receive on
     * this endpoint may ask who last sent to it. */
    if (ipc_ep_from_slot((uint32_t)r->rbx, CAP_RIGHT_READ, &ep) != 0) {
        r->rax = (uint32_t)-1; return;
    }
    struct endpoint *e = endpoint_by_index(ep);
    if (!e) { r->rax = (uint32_t)-1; return; }
    int t = e->last_sender;
    if (t <= 0 || t >= g_max_tasks || tasks[t].state == 0) { r->rax = (uint32_t)-1; return; }
    if (r->rcx) {
        uint32_t g = tasks[t].gid;
        if (copy_to_user((void *)(addr_t)r->rcx, &g, sizeof(g)) != 0) { r->rax = (uint32_t)-1; return; }
    }
    r->rax = tasks[t].uid;
}

/* SYS_IPC_REPLY_TO (75): reply to the task that sent the request most recently
 * received on `req_ep` (ebx), delivering msg (ecx, len edx) DIRECTLY into that
 * task's blocked SYS_IPC_CALL reply buffer — routed by the kernel-recorded sender
 * (endpoints[req_ep].last_sender), never through a shared reply endpoint. This is
 * what makes a single server safe for concurrent clients: two clients cannot
 * collide on one reply endpoint's single blocked_waiter, and a client cannot
 * intercept another's reply (it can't be another request's last_sender). Slot-3
 * WRITE is enforced by the table (same as reply/send).
 *
 * Return: 0 on delivery, or when the sender is gone (nothing to deliver — dropped).
 * A negative value asks the caller (the server's reply loop) to retry: on SMP the
 * sender may have deposited its request but not yet published its block, so it is
 * momentarily not TASK_BLOCKED_IPC; it will be, so retry. On a single CPU the
 * sender is always already blocked by the time the server runs, so no retry
 * occurs. Mirrors the blocked-waiter delivery in sys_ipc_send. */
/* Carries S13b: a client cannot intercept or forge a server's replies. The
 * reply capability is one-shot and per-task, which is what [C-1] lacked. */
void h_ipc_reply_to(struct interrupt_frame64 *r) {
    const void *msg = (const void *)(addr_t)r->rcx;
    size_t len      = (size_t)r->rdx;

    /* CAP_RIGHT_READ — the RECEIVE right — not WRITE.
     *
     * This is the reply-forgery primitive: it writes the caller's buffer directly
     * into the recorded sender's blocked SYS_IPC_CALL reply buffer and wakes it.
     * Only the task that legitimately RECEIVES requests on this endpoint (i.e.
     * the server) may answer them. Requiring WRITE here would be wrong — WRITE is
     * what every client holds in order to send, so a client could use it to
     * impersonate the server to another client, which is precisely the C-1
     * attack. Clients are minted WRITE-only by the connect path and are refused
     * here. */
    uint32_t req_ep;
    if (ipc_ep_from_slot((uint32_t)r->rbx, CAP_RIGHT_READ, &req_ep) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    if (len > IPC_MSG_MAX) len = IPC_MSG_MAX;

    struct endpoint *req = endpoint_by_index(req_ep);
    if (!req) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    /* ---- The reply target comes from a ONE-SHOT CAPABILITY, not from the
     * endpoint's last_sender field (roadmap 1.3).
     *
     * last_sender is mutable and is overwritten by the next receive, so
     * "reply to the right client" used to be a convention the server had to
     * honour rather than something the kernel enforced — and the bounded queue
     * sharpened that, since a server can now hold several dequeued requests
     * while only the newest was nameable. The capability names ONE blocked
     * caller, cannot be retargeted, and is consumed below, so replying twice or
     * replying to a client this task never received from are both unrepresentable
     * rather than merely refused. */
    struct capability *rc_cap = cap_lookup(CAPSLOT_REPLY, CAP_RIGHT_WRITE);
    if (!rc_cap || rc_cap->type != CAP_REPLY) {
        /* No outstanding request. Distinct from "client gone": this task has no
         * right to answer anybody, which is a caller error worth reporting. */
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    int t = (int)rc_cap->object;
    if (t <= 0 || t >= g_max_tasks || tasks[t].state == TASK_DEAD || tasks[t].state == 0) {
        /* Client gone: nothing to deliver, and the right dies with it — leaving
         * it installed would let a later, unrelated task id reuse land on a
         * capability minted for a task that no longer exists. */
        cap_consume_slot(CAPSLOT_REPLY);
        r->rax = 0; return;
    }

    ipc_lock();
    /* A task blocked in SYS_IPC_RECV_BLOCK is waiting for a REQUEST, not for a
     * reply. Delivering here would write the replier's buffer straight into that
     * task's receive buffer and wake it — a message injected past the endpoint
     * queue, from a task the receiver never accepted a connection from, and
     * attributed to whatever last_sender happened to hold. Fail closed and treat
     * it as "not waiting on us", which also spends the right (see below): a reply
     * capability naming a task that has moved on to receiving is stale by
     * construction, and keeping it would let the answer land on a later,
     * unrelated call. */
    if (tasks[t].state != TASK_BLOCKED_IPC || tasks[t].ipc_recv_block) {
        /* Not blocked yet: racing publish (SMP) -> retry; otherwise not waiting
         * on us (already replied / never called) -> drop. */
        /* "Racing" means the target is committed to blocking FOR A REPLY and has
         * merely not published yet. A task committed to a blocking RECEIVE is not
         * a reply-waiter and never will be, so reporting -2 for it would be a
         * retry that can never succeed — and per the IPC contract a server loops
         * on -2, so that is an unkillable wedge rather than an error. Excluded
         * explicitly. */
        uint32_t racing = (tasks[t].pending_block == (uint32_t)TASK_BLOCKED_IPC) &&
                          !tasks[t].ipc_recv_block;
        ipc_unlock();
        if (racing) {
            /* KEEP the right: the caller is committed to blocking and the server
             * was told to retry, so consuming here would destroy its only means
             * of completing the reply it is being asked to repeat. */
            r->rax = (uint32_t)IPC_AGAIN;
            return;
        }
        /* Dropped, but ANSWERED: the right is spent either way.
         *
         * This path returned 0 without consuming in the first draft, which
         * quietly preserved the exact hazard the capability exists to remove. A
         * retained right outlives the request it was minted for, so if that same
         * client later makes a NEW call and blocks, a reply issued now would be
         * delivered to it — a stale answer landing on an unrelated request. The
         * right names one request, and issuing a reply spends it whether or not
         * anyone was still listening. */
        cap_consume_slot(CAPSLOT_REPLY);
        r->rax = 0;
        return;
    }

    uint8_t kbuf[IPC_MSG_MAX];
    int copy_len = 0;
    if (len > 0) {
        if (copy_from_user(kbuf, msg, len) != 0) { ipc_unlock(); r->rax = (uint32_t)-1; return; }
        copy_len = (int)len;
    }

    if (copy_len > 0 && tasks[t].ipc_reply_buf != 0) {
        /* Deliver into the waiter's reply buffer, which resolves through the
         * waiter's CR3 — so make it the current task across the copy (see the
         * identical dance in sys_ipc_send). Interrupts masked so a tick can't
         * observe the transient current-task on this CPU; the impersonation
         * bracket tells an auditor on another core what we are really running. */
        uint64_t fl;
        __asm__ volatile ("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
        int sender = get_current_task();
        sched_impersonate_enter();
        set_current_task(t);
        copy_to_user((void *)(addr_t)tasks[t].ipc_reply_buf, kbuf, (size_t)copy_len);
        set_current_task(sender);
        sched_impersonate_exit();
        __asm__ volatile ("push %0; popfq" :: "r"(fl) : "memory", "cc");
    }

    struct interrupt_frame64 *wf = (struct interrupt_frame64 *)tasks[t].saved_ksp;
    if (!wf) { ipc_unlock(); r->rax = (uint32_t)-1; return; }
    wf->rax = (uint64_t)(uint32_t)copy_len;

    /* Clear the now-stale waiter publication on the client's own reply endpoint
     * (only if it still points to this task; a concurrent client may have
     * overwritten it — harmless, as delivery routed by identity, not by it). */
    int rep = tasks[t].blocked_on;
    struct endpoint *repe = (rep < 0) ? 0 : endpoint_by_index((uint32_t)rep);
    if (repe && repe->blocked_waiter == t) repe->blocked_waiter = -1;
    tasks[t].blocked_on = -1;
    __asm__ volatile ("" ::: "memory");
    tasks[t].state        = TASK_RUNNABLE;
    tasks[t].runnable_ctx = 1;
    ipc_unlock();

    /* CONSUME the reply right. This is what makes the capability one-shot, and
     * it is why a second reply to the same request cannot be expressed: the slot
     * is empty, so the lookup above fails with SYS_ERR_PERM. Done after
     * ipc_unlock for the lock-ordering reason given at the mint site, and only
     * on the path that actually delivered — a -2 retry must leave the right in
     * place or the server could never complete the reply it was told to retry. */
    cap_consume_slot(CAPSLOT_REPLY);
    r->rax = 0;
}

/* SYS_NOTIFY (25): rbx = cspace slot of a CAP_NOTIFICATION with WRITE. */
void h_notify(struct interrupt_frame64 *r) {
    uint32_t ns;
    if (ipc_notif_from_slot((uint32_t)r->rbx, CAP_RIGHT_WRITE, &ns) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    r->rax = sys_notify(ns, r->rcx);
}
/* SYS_WAIT_NOTIFY (26): slot-3 READ enforced by the table.
 * The badge is returned in r->rbx so interrupt_handler64 writes it into
 * frame->rbx; the userspace wrapper reads it from the ebx output constraint.
 * For the blocking path r->rbx is patched in sys_notify via saved_ksp->rbx. */
void h_wait_notify(struct interrupt_frame64 *r) {
    uint32_t ns;
    if (ipc_notif_from_slot((uint32_t)r->rbx, CAP_RIGHT_READ, &ns) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; r->rbx = 0; return;
    }
    uint32_t badge = 0;
    r->rax = sys_wait_notify(ns, &badge);
    r->rbx = badge;
}

/* user management (33/34/35): admin/self check lives in do_useradd/userdel/passwd. */

