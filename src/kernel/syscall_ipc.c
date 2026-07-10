/* syscall_ipc.c -- synchronous IPC (send/recv/reply over endpoints) plus
 * asynchronous notifications, and their syscall handlers. Split out of
 * syscall.c. */
#include "syscall_internal.h"

#define IPC_SPIN_LIMIT 200000

/* Serialise endpoint + notification operations across CPUs. A raw test-and-set
 * (endpoint_lock) is used because these run inside the int-0x80 handler with IF
 * already clear. In the single-CPU default build these compile to nothing, so
 * that path is byte-for-byte unchanged. The lock guards the mailbox flags, the
 * badge accumulator, and the wake handoff (state -> RUNNABLE + saved-frame
 * patch); the actual task switch onto the woken task is done later by the
 * running-CPU-guarded scheduler. */
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

int sys_ipc_send(uint32_t ep, const void *msg, size_t len) {
    if (ep >= MAX_ENDPOINTS) return -1;
    if (len > IPC_MSG_MAX) len = IPC_MSG_MAX;
    struct endpoint *e = &endpoints[ep];

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
    if (waiter > 0 && waiter < MAX_TASKS &&
            tasks[waiter].state == TASK_BLOCKED_IPC) {
        if (auth.valid && !cap_revalidate(3, CAP_RIGHT_WRITE, &auth)) { ipc_unlock(); return -1; }

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
             * the transient current-task. */
            uint64_t fl;
            __asm__ volatile ("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
            int sender = get_current_task();
            set_current_task(waiter);
            copy_to_user((void *)(addr_t)tasks[waiter].ipc_reply_buf, kbuf,
                         (size_t)copy_len);
            set_current_task(sender);
            __asm__ volatile ("push %0; popfq" :: "r"(fl) : "memory", "cc");
        }

        /* Patch the waiter's saved interrupt frame so that when the timer
         * resumes it, eax holds the reply length (the return value of
         * sys_ipc_call). */
        struct interrupt_frame64 *wf =
            (struct interrupt_frame64 *)tasks[waiter].saved_ksp;
        wf->rax = (uint64_t)(uint32_t)copy_len;

        e->blocked_waiter = -1;
        __asm__ volatile ("" ::: "memory");
        tasks[waiter].state       = TASK_RUNNABLE;
        tasks[waiter].runnable_ctx = 1;
        ipc_unlock();
        return 0;
    }

    /* Non-blocking: if the single mailbox slot is still full, tell the caller to
     * retry. The old form spun in-kernel calling yield(), but the cooperative
     * scheduler cannot correctly switch two ring-3 tasks (only timer preemption
     * can); a caller that polls from ring 3 gets preempted and makes progress. */
    if (e->has_message) { ipc_unlock(); return -2; }

    if (auth.valid && !cap_revalidate(3, CAP_RIGHT_WRITE, &auth)) { ipc_unlock(); return -1; }

    if (len > 0 && copy_from_user(e->msg, msg, len) != 0) { ipc_unlock(); return -1; }
    e->msg_len = (int)len;
    e->sender_task = get_current_task();
    __asm__ volatile ("" ::: "memory");
    e->has_message = 1;
    ipc_unlock();
    return 0;
}

int sys_ipc_recv(uint32_t ep, void *msg, size_t max_len) {
    if (ep >= MAX_ENDPOINTS) return -1;
    struct endpoint *e = &endpoints[ep];

    /* See sys_ipc_send: snapshot the authorizing read capability and revalidate
     * it after the yield loop so a revoke mid-spin aborts the receive. */
    cap_snapshot_t auth = cap_snapshot(cap_lookup(3, CAP_RIGHT_READ));

    /* Non-blocking (see sys_ipc_send): no message yet -> caller polls from ring
     * 3 and is timer-preempted, rather than spinning on the broken cooperative
     * yield in-kernel. */
    ipc_lock();
    if (!e->has_message) { ipc_unlock(); return -2; }

    if (auth.valid && !cap_revalidate(3, CAP_RIGHT_READ, &auth)) { ipc_unlock(); return -1; }

    int len = e->msg_len;
    if (len > (int)max_len) len = (int)max_len;
    if (len < 0) len = 0;
    if (len > 0 && copy_to_user(msg, e->msg, (size_t)len) != 0) { ipc_unlock(); return -1; }

    e->last_sender = e->sender_task;
    __asm__ volatile ("" ::: "memory");
    e->has_message = 0;
    ipc_unlock();
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
    if (notif_slot >= MAX_NOTIFICATIONS) return -1;
    struct notification *n = &notifications[notif_slot];

    ipc_lock();
    n->pending_badge |= badge;

    int waiter = n->blocked_waiter;
    if (waiter > 0 && waiter < MAX_TASKS &&
            tasks[waiter].state == TASK_BLOCKED_NOTIF) {
        uint32_t b = n->pending_badge;
        n->pending_badge    = 0;
        n->blocked_waiter   = -1;

        /* Patch the waiter's saved trap frame: rax=0 (success), rbx=badge.
         * interrupt_handler64 wrote frame->rbx from r.ebx before calling
         * ipc_block_switch; patching here overwrites that with the real badge
         * so that when the timer iretq's the waiter back to ring 3 the value
         * is already in ebx for the userspace wrapper to read. */
        struct interrupt_frame64 *wf =
            (struct interrupt_frame64 *)tasks[waiter].saved_ksp;
        wf->rax = 0;
        wf->rbx = (uint64_t)b;

        __asm__ volatile ("" ::: "memory");
        tasks[waiter].state       = TASK_RUNNABLE;
        tasks[waiter].runnable_ctx = 1;
    }
    ipc_unlock();
    return 0;
}

/* sys_wait_notify: if a badge is already pending, consume it and return 0
 * (badge written via r->ebx → frame->rbx by interrupt_handler64).  Otherwise
 * block the task in TASK_BLOCKED_NOTIF state; sys_notify will wake it and
 * patch its saved frame when a badge arrives. */
int sys_wait_notify(uint32_t notif_slot, uint32_t *out_badge) {
    if (notif_slot >= MAX_NOTIFICATIONS) return -1;
    struct notification *n = &notifications[notif_slot];

    ipc_lock();
    if (n->pending_badge != 0) {
        *out_badge = n->pending_badge;
        n->pending_badge = 0;
        ipc_unlock();
        return 0;
    }

    /* No badge pending — block. */
    int cur = get_current_task();
    n->blocked_waiter         = cur;
    tasks[cur].state          = TASK_BLOCKED_NOTIF;
    tasks[cur].runnable_ctx   = 0;
    /* out_badge and r->ebx will be patched by sys_notify when it wakes us. */
    *out_badge = 0;
    ipc_unlock();
    return 0;
}


void h_ipc_send(struct regs *r) {
    r->eax = sys_ipc_send(r->ebx, (const void*)(addr_t)r->ecx, r->edx);
}

/* SYS_IPC_CALL (23): atomic send-then-block-until-reply.
 *   ebx = send endpoint index
 *   ecx = reply endpoint index
 *   edx = userspace ptr to message to send
 *   esi = send length
 *   edi = userspace ptr to reply buffer
 * The handler deposits the message, marks the task BLOCKED_IPC, and returns.
 * interrupt_handler64 detects the blocked state and calls ipc_block_switch()
 * to yield to the next runnable task.  When sys_ipc_send delivers a message to
 * the reply endpoint, it patches this task's saved frame and marks it runnable. */
void h_ipc_call(struct regs *r) {
    uint32_t send_ep  = r->ebx;
    uint32_t reply_ep = r->ecx;
    const void *msg   = (const void *)(addr_t)r->edx;
    size_t   send_len = (size_t)r->esi;
    uint32_t reply_buf = r->edi;

    if (send_ep >= MAX_ENDPOINTS || reply_ep >= MAX_ENDPOINTS) {
        r->eax = (uint32_t)-1; return;
    }

    /* Deposit the outgoing message into send_ep. */
    int rc = sys_ipc_send(send_ep, msg, send_len);
    if (rc < 0) { r->eax = (uint32_t)rc; return; }

    int cur = get_current_task();

    /* Arm the reply endpoint with the waiter info before blocking. */
    endpoints[reply_ep].blocked_waiter = cur;
    tasks[cur].ipc_reply_buf  = reply_buf;
    tasks[cur].state          = TASK_BLOCKED_IPC;
    tasks[cur].runnable_ctx   = 0;
    /* r->eax is set by interrupt_handler64 after we return from here:
     * it will be overwritten by ipc_block_switch/wf->rax when unblocked. */
    r->eax = 0;
}
/* SYS_IPC_RECV (22): slot-3 READ enforced by the table. */
void h_ipc_recv(struct regs *r) {
    r->eax = sys_ipc_recv(r->ebx, (void*)(addr_t)r->ecx, r->edx);
}
/* SYS_IPC_REPLY (24): slot-3 WRITE enforced by the table. */
void h_ipc_reply(struct regs *r) {
    r->eax = sys_ipc_reply(r->ebx, (const void*)(addr_t)r->ecx, r->edx);
}
/* SYS_NOTIFY (25): slot-3 WRITE enforced by the table. */
void h_notify(struct regs *r) {
    r->eax = sys_notify(r->ebx, r->ecx);
}
/* SYS_WAIT_NOTIFY (26): slot-3 READ enforced by the table.
 * The badge is returned in r->ebx so interrupt_handler64 writes it into
 * frame->rbx; the userspace wrapper reads it from the ebx output constraint.
 * For the blocking path r->ebx is patched in sys_notify via saved_ksp->rbx. */
void h_wait_notify(struct regs *r) {
    uint32_t badge = 0;
    r->eax = sys_wait_notify(r->ebx, &badge);
    r->ebx = badge;
}

/* user management (33/34/35): admin/self check lives in do_useradd/userdel/passwd. */

