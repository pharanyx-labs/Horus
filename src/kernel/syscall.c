#include "syscall_internal.h"

void syscall_handler64(void)
{
    uint64_t num;
    __asm__ volatile ("" : "=a"(num)); 
    switch ((uint32_t)num) {
        case 0:
            yield();
            __asm__ volatile ("" : : "a"(0));
            break;
        default:
            
            __asm__ volatile ("" : : "a"(-38) );
            break;
    }
}

/* ------------------------------------------------------------------------- *
 *  Per-syscall handlers.
 *
 *  Each handler is the extracted body of one dispatch case, so the switch in
 *  syscall_handler() is a thin table of one-liners and every syscall can be
 *  audited in isolation. This is a behaviour-preserving move: switch-level
 *  `break` became `return` (inner loop break/continue are unchanged), and the
 *  shared in_kernel bookkeeping still brackets the dispatch in syscall_handler.
 * ------------------------------------------------------------------------- */

/* SYS_GET_LINE (3): read a line from the console into the caller's buffer.
 *
 * CAP_CONSOLE, type-tested, and NO slot-3 fallback (2026-08-24). It used to read
 *
 *     c = cap_lookup(8, CAP_RIGHT_READ);
 *     if (!c) c = cap_lookup(3, CAP_RIGHT_READ);
 *
 * with neither lookup type-tested, and the dispatch entry declares SC_NONE --
 * so the handler was the only gate, and slot 3 is the legacy CAP_FRAME
 * `create_task` installs in EVERY task. A sixth door of [H-3]'s shape, on
 * console INPUT: what the user is typing.
 *
 * Measured before the change rather than argued: `captest`, holding that decoy
 * and no CAP_CONSOLE, passed the check and BLOCKED inside the console read --
 * it did not merely qualify, it was reading.
 *
 * What made it survive is that it is unreachable while a ring-3 console server
 * owns the UART, and one always does in a live boot. That is a circumstance --
 * the server being alive -- not a gate, and it is the same "safe by ordering"
 * shape as the CSPRNG in #200. The `console_hw_owned()` check below stays; it
 * answers a different question (do not race the owner), and a question about
 * racing is not an answer about authority.
 *
 * `cap_lookup` does not test type -- by design, it is the rights-and-liveness
 * check -- so every caller must, and the five call sites in this tree that did
 * not were found by looking for exactly that. */
static void h_get_line(struct interrupt_frame64 *r) {
    struct capability *c = cap_lookup(CAPSLOT_CONSOLE, CAP_RIGHT_READ);
    if (!c || c->type != CAP_CONSOLE) {
#ifdef GETLINE_SLOT3_FALLBACK
        /* CONTROL ARM: the pre-2026-08-24 fallback, untyped, on the slot every
         * task is born holding. captest reaches the console read under it. */
        c = cap_lookup(3, CAP_RIGHT_READ);
        if (!c)
#endif
        { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    }

    /* Fail closed while a ring-3 console server owns the serial UART: a kernel-side
     * read here would race the owner's read and steal bytes from a typed line. The
     * caller must route input through the console server (see userspace sh_get_line);
     * this in-kernel path is only for before handoff / after the owner has died. */
    if (console_hw_owned()) { r->rax = (uint32_t)-1; return; }

    void *user_dest = (void *)(addr_t)r->rbx;
    uint32_t max_len = 127;
    char line[128];
    uint32_t len = 0;
    char ch;

    while (len < max_len) {
        ch = console_getc();

        if (ch == '\r' || ch == '\n') {
            print("\n");
            break;
        }

#ifdef DEBUG_SHELL
        if (ch == 0x1B) {
            /* Spin for serial — do not cooperative-yield mid-syscall. */
            while ((inb(0x3FD) & 1) == 0) { __asm__ volatile ("pause"); }
            char seq1 = inb(0x3F8);
            while ((inb(0x3FD) & 1) == 0) { __asm__ volatile ("pause"); }
            char seq2 = inb(0x3F8);

            if (seq1 == '[') {
                if (seq2 == 'A') {
                    if (history_count > 0) {
                        if (history_pos < 0) history_pos = history_count - 1;
                        else if (history_pos > 0) history_pos--;

                        for (uint32_t i = 0; i < len; i++) {
                            print("\b \b");
                        }
                        len = 0;
                        while (len < max_len - 1 && cmd_history[history_pos][len]) {
                            line[len] = cmd_history[history_pos][len];
                            char echo[2] = {line[len], 0};
                            print(echo);
                            len++;
                        }
                        line[len] = 0;
                    }
                } else if (seq2 == 'B') {
                    if (history_pos >= 0) {
                        history_pos++;
                        if (history_pos >= history_count) {
                            history_pos = -1;
                            for (uint32_t i = 0; i < len; i++) print("\b \b");
                            len = 0;
                            line[0] = 0;
                        } else {
                            for (uint32_t i = 0; i < len; i++) print("\b \b");
                            len = 0;
                            while (len < max_len - 1 && cmd_history[history_pos][len]) {
                                line[len] = cmd_history[history_pos][len];
                                char echo[2] = {line[len], 0};
                                print(echo);
                                len++;
                            }
                            line[len] = 0;
                        }
                    }
                }
            }
            continue;
        }
#endif
        if ((unsigned char)ch < 32 && ch != '\b' && ch != 0x7F) {
            continue;
        }

        if (ch == '\b' || ch == 0x7F) {
            if (len > 0) {
                len--;
                print("\b \b");
            }
            continue;
        }

        char echo[2] = {ch, 0};
        print(echo);
        line[len++] = ch;
    }

    line[len] = 0;

#ifdef DEBUG_SHELL
    if (len > 0) {
        if (history_count == HISTORY_SIZE) {
            for (int i = 0; i < HISTORY_SIZE - 1; i++) {
                for (int j = 0; j < CMD_MAX; j++) {
                    cmd_history[i][j] = cmd_history[i+1][j];
                }
            }
            history_count--;
        }
        for (uint32_t j = 0; j < CMD_MAX && j <= len; j++) {
            cmd_history[history_count][j] = line[j];
        }
        history_count++;
    }
    history_pos = -1;
#endif

    if (copy_to_user(user_dest, line, len + 1) != 0) {
        r->rax = -1;
    } else {
        r->rax = len;
    }
}

/* SYS_GET_SYSINFO (6): copy a zero-padded version string to the caller. */
#ifdef LEGACY_SYSCALLS_PRESENT
static void h_sysinfo(struct interrupt_frame64 *r) {
    const char *info = "Horus v0.4 | per-task paging + cspaces | Rust validators";
    /* Copy a zero-padded fixed-size buffer rather than 64 bytes straight
     * off the string literal: the literal is shorter than 64 bytes, so
     * the old copy leaked ~7 bytes of adjacent .rodata to userspace. */
    char infobuf[64];
    size_t ii = 0;
    for (; ii < sizeof(infobuf) - 1 && info[ii]; ii++) infobuf[ii] = info[ii];
    for (; ii < sizeof(infobuf); ii++) infobuf[ii] = 0;
    if (copy_to_user((void*)(addr_t)r->rbx, infobuf, sizeof(infobuf)) == 0) {
        r->rax = 0;
    } else {
        r->rax = -1;
    }
}
#endif /* LEGACY_SYSCALLS_PRESENT */

/* SYS_SBRK (10): increment the program break by `increment` bytes.
 * Returns the OLD break (pointer to start of newly allocated region) on
 * success, or (uint32_t)-1 on failure.  heap_end grows on demand up to
 * USER_HEAP_MAX_SIZE; the demand pager allocates physical pages lazily. */
static void h_sbrk(struct interrupt_frame64 *r) {
    int tid = get_current_task();
    /* 64-bit end to end (finding [I-2], roadmap 1.5). Every value here --
     * heap_start, heap_current, heap_end -- is uint64_t in the TCB; this handler
     * used to narrow the arithmetic to 32 bits in five places, so a break above
     * 4 GiB was computed, range-checked, and then stored truncated. The range
     * check ran on the truncated value, which is what made it a correctness bug
     * rather than a mere clamp: the check could PASS on a wrapped address.
     * Latent only while every heap sits below 4 GiB; USER_HEAP_HIGH_BASE=1
     * rebuilds the reachable case as a control arm. */
    int64_t increment = (int64_t)r->rbx;
    if (increment == 0) { r->rax = tasks[tid].heap_current; return; }

    uint64_t cur         = tasks[tid].heap_current;
    uint64_t heap_max    = tasks[tid].heap_start + USER_HEAP_MAX_SIZE;

    /* Overflow BEFORE the range test, per roadmap 1.5 -- a wrapped sum that lands
     * back inside [heap_start, heap_max] would otherwise be accepted as valid. */
    uint64_t new_current;
    if (increment > 0) {
        if ((uint64_t)increment > UINT64_MAX - cur) { r->rax = (uint64_t)-1; return; }
        new_current = cur + (uint64_t)increment;
    } else {
        /* Negate via -(x+1)+1 so INT64_MIN has no undefined step. sbrk must still
         * shrink, so this is a real path, not a guard. */
        uint64_t dec = (uint64_t)(-(increment + 1)) + 1u;
        if (dec > cur) { r->rax = (uint64_t)-1; return; }
        new_current = cur - dec;
    }

    /* There used to be a clamp here against kernel_lowmem_critical_floor(): the
     * kernel was linked low, so a heap growing up the low window could shadow
     * kernel data (tasks[], page tables, cspaces) on the task's own CR3. The
     * kernel now lives at KERNEL_VMA — no kernel state occupies a user address —
     * so the guard has nothing left to guard and is gone. */
    if (new_current < tasks[tid].heap_start || new_current > heap_max) {
        /* (uint64_t)-1, not (uint32_t)-1. SBRK returns an ADDRESS, and its
         * failure sentinel is the all-ones pointer: newlib's _sbrk compares the
         * result against (void *)(intptr_t)-1, which is 64-bit now. A
         * (uint32_t)-1 would zero-extend into rax as 0x00000000FFFFFFFF, miss
         * that compare, and hand malloc 4 GiB-minus-one as a valid heap address.
         * Every other syscall returns a 32-bit status code and is unaffected. */
        r->rax = (uint64_t)-1;
        return;
    }
    /* Extend the authorised ceiling on demand; physical pages arrive lazily. */
    if (new_current > tasks[tid].heap_end) {
        uint64_t new_end = (new_current + 0xFFFULL) & ~0xFFFULL;
        if (new_end < new_current) new_end = heap_max;   /* page-align wrapped */
        if (new_end > heap_max)    new_end = heap_max;
        tasks[tid].heap_end = new_end;
    }
    uint64_t old = tasks[tid].heap_current;
    tasks[tid].heap_current = new_current;
    r->rax = old;
}

/* SYS_BRK (62): set the program break to an absolute address.
 * Returns the new break on success.  On failure (addr out of range) returns
 * the unchanged current break — callers check return == addr to detect error,
 * matching the Linux brk(2) convention.  addr=0 queries without changing. */
static void h_brk(struct interrupt_frame64 *r) {
    int tid = get_current_task();
    uint64_t addr     = r->rbx;
    uint64_t heap_max = tasks[tid].heap_start + USER_HEAP_MAX_SIZE;

    /* No kernel-floor clamp: the kernel lives at KERNEL_VMA, not in the user
     * window. See h_sbrk. */
    if (addr == 0) { r->rax = tasks[tid].heap_current; return; }

    if (addr < tasks[tid].heap_start || addr > heap_max) {
        r->rax = tasks[tid].heap_current;   /* failure: return unchanged break */
        return;
    }
    /* 64-bit, like h_sbrk ([I-2]). This one was the sharper of the two: `addr` is
     * validated against heap_start/heap_max as a full 64-bit value just above,
     * and was then truncated on the way into storage -- so the check passed on
     * the real address while the break was set from a wrapped one. */
    uint64_t aligned = (addr + 0xFFFULL) & ~0xFFFULL;
    if (aligned < addr)     aligned = heap_max;   /* page-align wrapped */
    if (aligned > heap_max) aligned = heap_max;
    tasks[tid].heap_current = aligned;
    tasks[tid].heap_end     = aligned;
    r->rax = aligned;
}

/* SYS_WRITE (11): write to fd 1 (console). Length clamped to the scratch buf.
 *
 * SC_NONE in the dispatch table, and that stays right: writing to the TERMINAL
 * is not an authority this system rations -- every ring-3 task has a stdout, and
 * `SYSCALLS.md` marks fd 1 ambient deliberately. What IS an authority, and was
 * being handed out with it, is appending to the KERNEL MESSAGE RING.
 *
 * Finding [H-2]. `print()` calls `klog_append()` for every byte before it tests
 * console ownership, so until this gate existed an unprivileged task could
 *   (a) forge lines that appear in `dmesg` indistinguishable from kernel
 *       diagnostics, and
 *   (b) push 16 KiB through fd 1 to evict every genuine line from `klog_buf`,
 * which is an anti-forensics primitive aimed at the log a maintainer reads after
 * an incident. The asymmetry is the tell: SYS_DMESG -- the READ side of this same
 * ring -- was converted to require CAP_KERNEL_LOG by [I-1], and the write side
 * was never considered.
 *
 * So the append is gated on the capability and the console write is not. Note
 * what this deliberately does NOT do: it does not gate on uid, on task id, or on
 * "is this the shell" (no ambient authority -- see [I-1]/[H-1]). It asks the
 * capability graph, and it fails closed when the answer is no.
 *
 * Today that closes the finding completely rather than narrowing it, and the
 * reason is worth stating because it is a property of the root cnode rather than
 * of this function: `root_cnode[15]` mints CAP_KERNEL_LOG with CAP_RIGHT_READ and
 * nothing else (`capability.c`), and delegation may only ever reduce rights, so
 * NO task in the system can hold the WRITE right this asks for. The authority is
 * expressible -- mint it with WRITE the day a userspace logger has a reason to
 * exist -- without being granted. Deleting the append outright would have been
 * fewer lines and would have made that future case unexpressible.
 *
 * The type test alongside the rights test is not redundant. `cap_lookup()` falls
 * back to the root cnode for a task with no cspace, where slot 16 is
 * CAP_BOOT_MODULE, not CAP_KERNEL_LOG; the rights mask already refuses it (that
 * cap is READ too), and this makes the refusal independent of that coincidence.
 *
 * Witness: `make smoke-klog-forge`. Falsified by `KLOG_WRITE_UNGATED=1`
 * (`make smoke-klog-forge-control`), which restores the unconditional append. */
static void h_write(struct interrupt_frame64 *r) {
    int fd = r->rbx;
    void *buf = (void*)(addr_t)r->rcx;
    size_t len = r->rdx;

    if (fd != 1) { r->rax = -1; return; }

    char kbuf[256];
    size_t to_copy = len > 255 ? 255 : len;
    if (copy_from_user(kbuf, buf, to_copy) != 0) {
        r->rax = -1;
        return;
    }
    kbuf[to_copy] = 0;

#ifdef KLOG_WRITE_UNGATED
    /* Control arm for [H-2] -- the pre-fix behaviour, where a ring-3 write went
     * into the kernel log with no authority at all. Never set in a ship build;
     * `smoke-klog-forge-control` sets it and REQUIRES the FAIL marker. */
    int may_klog = 1;
#else
    struct capability *logc = cap_lookup(CAPSLOT_KERNEL_LOG, CAP_RIGHT_WRITE);
    int may_klog = (logc && logc->type == CAP_KERNEL_LOG);
#endif

    print_from_user(kbuf, may_klog);
    r->rax = to_copy;
}

/* SYS_READ (12): read from fd 0 (console line) or fd>=3 (ramfs, needs slot-3 read). */
static void h_read(struct interrupt_frame64 *r) {
    int fd = r->rbx;
    void *buf = (void*)(addr_t)r->rcx;
    size_t len = r->rdx;

    if (fd == 0) {
        /* Fail closed while a ring-3 console server owns the serial UART (see
         * h_get_line): the kernel must not be a second reader. */
        if (console_hw_owned()) { r->rax = (uint32_t)-1; return; }
        char line[128];
        uint32_t got = 0;
        while (got < len && got < 127) {
            char ch = console_getc();
            if (ch == '\r' || ch == '\n') { print("\n"); break; }
            if (ch == '\b' || ch == 0x7F) { if (got > 0) { got--; print("\b \b"); } continue; }
            char echo[2] = {ch, 0}; print(echo);
            line[got++] = ch;
        }
        line[got] = 0;
        if (copy_to_user(buf, line, got + 1) != 0) r->rax = (uint32_t)SYS_ERR_FAULT;
        else r->rax = got;
    } else if (fd >= 3) {
        /* Retired 2026-08-22 with the ramfs dispatch entries above, and for the
         * same reason: `cap_lookup(3, CAP_RIGHT_READ)` is satisfied by the
         * legacy CAP_FRAME every task is born holding, so this branch handed
         * the in-kernel ramfs to any caller. It is the one that mattered most
         * of the four, because it is the one that MOVES BYTES -- the others
         * name and create; this one reads out.
         *
         * Left as a live branch under the control arm rather than deleted
         * outright, because the fd >= 3 range is where a real file descriptor
         * table will land when one exists, and a reviewer arriving then should
         * find the reason this door was shut rather than an empty else. */
#ifdef RAMFS_SLOT3_GATE
        struct capability *c = cap_lookup(3, CAP_RIGHT_READ);
        if (!c) { r->rax = -1; return; }
        char kbuf[256];
        size_t to_read = len > 255 ? 255 : len;
        int n = ramfs_read(fd, kbuf, to_read);
        if (n > 0) {
            if (copy_to_user(buf, kbuf, n) == 0) r->rax = n;
            else r->rax = -1;
        } else {
            r->rax = n;
        }
#else
        r->rax = (uint32_t)SYS_ERR_NOSYS;
#endif
    } else {
        r->rax = -1;
    }
}

/* SYS_EXEC (14): create a task at an already-loaded image.
 * Capability (slot 3, WRITE|EXEC) is enforced centrally by the dispatch table. */
#ifdef LEGACY_SYSCALLS_PRESENT
static void h_exec(struct interrupt_frame64 *r) {
    uint32_t load_base = r->rbx;
    uint32_t entry_offset = r->rcx;
    (void)(r->rdx);

    /* Guard against uint32 overflow: a crafted (load_base, entry_offset) pair
     * whose sum wraps around could yield an entry point at an arbitrary address.
     * The resulting task would fault immediately (paging enforces ring separation),
     * but the overflow is confusing and could mask future bugs. */
    if ((uint64_t)load_base + entry_offset >= USER_MAX_VADDR) {
        r->rax = -1;
        return;
    }

    int new_id = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        if (tasks[i].state == 0) {
            new_id = i;
            break;
        }
    }
    if (new_id < 0) {
        r->rax = -1;
        return;
    }

    /* Premap stays at the fixed base and the default size (this path loads a
     * small non-relocated image); the user-supplied load_base only drives the
     * entry/eip, as before. */
    create_task(new_id, load_base + entry_offset, DEMO_TASK_STACK_TOP, USER_AREA_BASE, 0);

    tasks[new_id].heap_start = USER_HEAP_BASE + new_id * 0x10000;
    tasks[new_id].heap_current = tasks[new_id].heap_start;
    tasks[new_id].heap_end = tasks[new_id].heap_start + 0x10000;

    tasks[new_id].name[0] = 's'; tasks[new_id].name[1] = 'p';
    tasks[new_id].name[2] = 'a'; tasks[new_id].name[3] = 'w';
    tasks[new_id].name[4] = 'n'; tasks[new_id].name[5] = '0' + new_id;
    tasks[new_id].name[6] = 0;

    r->rax = new_id;
}
#endif /* LEGACY_SYSCALLS_PRESENT */

/* SYS_FS_LIST (16): list ramfs entries, honouring the caller's buffer size.
 * Capability (slot 3, READ) is enforced centrally by the dispatch table. */

static void h_exit(struct interrupt_frame64 *r) {
    struct task_exit_cause cause = { TASK_EXIT_NORMAL, 0, 0, 0, 0 };
    task_teardown(get_current_task(), &cause);
    r->rax = 0;
}

/* Return non-zero if the current task may terminate `target`: either it holds a
 * CAP_TCB capability to the target with WRITE rights (every task has one to
 * itself at slot 0; a spawner is granted one per child in do_spawn), or it holds
 * CAP_USER admin authority (slot 6). */
static int task_kill_authorized(int target) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) return 0;

    struct capability *admin = cap_lookup(6, CAP_RIGHT_ALL);
    if (admin && admin->type == CAP_USER) return 1;

    capability_t *cs = tasks[cur].cspace;
    if (!cs) return 0;
    for (uint32_t s = 0; s < tasks[cur].cspace_size; s++) {
        if (cs[s].type == CAP_TCB && cs[s].object == (uint64_t)target &&
            (cs[s].rights & CAP_RIGHT_WRITE)) {
            return 1;
        }
    }
    return 0;
}

/* SYS_KILL (63): terminate task ebx. Authorised by a CAP_TCB capability to the
 * target (or CAP_USER admin) — enforced in the handler because the target is
 * dynamic, so the central slot-based gate cannot express it. Killing yourself
 * behaves like SYS_EXIT (interrupt_handler64 redirects on the state==0 return). */
static void h_kill(struct interrupt_frame64 *r) {
    int target = (int)r->rbx;
    if (target <= 0 || target >= MAX_TASKS || tasks[target].state == 0) {
        r->rax = (uint32_t)SYS_ERR_INVAL;
        return;
    }
    if (!task_kill_authorized(target)) {
        r->rax = (uint32_t)SYS_ERR_PERM;
        return;
    }
    /* detail = who did it: a supervisor that sees "killed" needs the killer to
     * tell a deliberate shutdown from a stray SYS_KILL. */
    struct task_exit_cause cause = { TASK_EXIT_KILLED, (uint32_t)get_current_task(), 0, 0, 0 };
    task_teardown(target, &cause);
    r->rax = 0;
}

/* A deliverable signal for a task blocked in SYS_WAIT must interrupt the wait so
 * the handler runs promptly, rather than only when the awaited task eventually
 * exits (which may be never). Rewrite the blocked task's saved SYS_WAIT trap
 * frame to return SYS_ERR_INTR, drop the back-link from whatever it was waiting
 * on (so that task's teardown won't also try to wake it), and make it runnable.
 * It resumes from the wait with EINTR, and the queued signal is then delivered on
 * its return to ring 3 (deliver_pending_signal). */
static void signal_interrupt_wait(int t) {
    struct interrupt_frame64 *f = (struct interrupt_frame64 *)tasks[t].saved_ksp;
    if (!f) return;
    f->rax = (uint64_t)(uint32_t)SYS_ERR_INTR;
    for (int w = 1; w < MAX_TASKS; w++) {
        if (tasks[w].waiter == t) { tasks[w].waiter = -1; break; }
    }
    tasks[t].state        = TASK_RUNNABLE;
    tasks[t].runnable_ctx = 1;
}

/* SYS_SIGNAL (66): send signal `ecx` to task `ebx`. Same authority as SYS_KILL —
 * a CAP_TCB to the target (or CAP_USER admin), enforced here since the target is
 * dynamic. If the target registered a handler it is delivered asynchronously:
 * the signal is queued in pending_sigs and the lowest-numbered *unmasked* one is
 * consumed when the task is next resumed to ring 3, redirecting it into its
 * handler (see preempt_on_tick / try_deliver_fault_signal). A masked signal stays
 * pending until SYS_SIGMASK unblocks it. With no handler — or for the uncatchable
 * SIG_KILL — the default action applies and the target is terminated. Signalling
 * yourself is permitted (self-TCB). */
static void h_signal(struct interrupt_frame64 *r) {
    int target      = (int)r->rbx;
    uint32_t signum = r->rcx;
    if (target <= 0 || target >= MAX_TASKS || tasks[target].state == 0) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }
    if (signum == 0 || signum > SIG_MAX) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    if (!task_kill_authorized(target))   { r->rax = (uint32_t)SYS_ERR_PERM;  return; }

    if (signum == SIG_KILL || tasks[target].sig_handler == 0) {
        struct task_exit_cause cause = { TASK_EXIT_SIGNAL, signum, 0, 0, 0 };
        task_teardown(target, &cause);         /* default action: terminate */
    } else {
        tasks[target].pending_sigs |= (1u << signum);   /* async: delivered on next resume */
        /* If it's parked in SYS_WAIT and this signal isn't masked, interrupt the
         * wait so the handler runs promptly instead of waiting on the target. */
        if (tasks[target].state == TASK_BLOCKED_WAIT &&
            !(tasks[target].sig_mask & (1u << signum))) {
            signal_interrupt_wait(target);
        }
    }
    r->rax = 0;
}

/* SYS_TASK_RESUME(tid): make a spawned-but-suspended child schedulable.
 *
 * Authorised exactly like SYS_KILL / SYS_SIGNAL: the caller must hold a CAP_TCB
 * for the target (do_spawn grants the spawner one per child) or CAP_USER admin.
 * A task therefore only ever resumes a child it supervises.
 *
 * Idempotent, and safe on an already-running task: it only re-asserts
 * runnable_ctx, which a live task already has. Refuses a task with no fabricated
 * context (saved_ksp == 0), since making that schedulable would hand the
 * scheduler a null frame. */
void h_task_resume(struct interrupt_frame64 *r) {
    int target = (int)r->rbx;
    if (target <= 0 || target >= MAX_TASKS || tasks[target].state == 0) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }
    if (!task_kill_authorized(target)) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    if (!tasks[target].saved_ksp)      { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    tasks[target].runnable_ctx = 1;
    r->rax = SYS_OK;
}

/* SYS_WAIT (17): block until task `tid` exits.
 *
 * Records a pending block only; ipc_block_switch saves the trap frame first and
 * only then sets tasks[tid].waiter + TASK_BLOCKED_WAIT so a concurrent teardown
 * cannot wake a task whose saved_ksp is not yet the SYS_WAIT frame. */
static void h_wait(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    int tid = r->rbx;
    if (tid < 0 || tid >= MAX_TASKS || tid == cur) { r->rax = (uint32_t)-1; return; }
    if (tasks[tid].state == TASK_DEAD) {
        /* Already gone: satisfied without blocking — so task_teardown never got
         * to hand us the cause. Take it from the corpse instead. Safe precisely
         * because the slot still reads TASK_DEAD: a reused slot is not dead, so
         * this can never report a live task's record. */
        tasks[cur].wait_exit_info = tasks[tid].exit_info;
        r->rax = 0;
        return;
    }

    /* Intent only — not wake-visible until ipc_publish_pending_block. */
    tasks[cur].blocked_on    = tid;
    tasks[cur].pending_block = TASK_BLOCKED_WAIT;
    r->rax = 0;   /* the value the caller sees once task_teardown wakes it */
}

/* SYS_GET_TASK_INFO (18): report task_info for `tid` (self, or any with admin/audit). */
static void h_task_info(struct interrupt_frame64 *r) {
    int tid = r->rbx;
    struct task_info *out = (struct task_info*)(addr_t)r->rcx;

    if (tid < 0 || tid >= MAX_TASKS) {
        r->rax = -1;
        return;
    }

    /* CAP_DEBUG, and ONLY CAP_DEBUG (roadmap 3.6, second half, 2026-08-24).
     *
     * This accepted CAP_USER or CAP_AUDIT as well until now, which meant that
     * "may I see the process list" was answered by "do you administer users" or
     * "do you hold the audit log's keys". Those gates were real -- finding I-1
     * replaced an ambient uid-0 test with them -- but they named authority far
     * beyond what the caller needed, and an ambient-authority sweep does not
     * find that: it looks for gates that are missing or vacuous, and these were
     * neither.
     *
     * Every holder that legitimately observes now holds the capability for
     * observing. The shell got CAP_DEBUG when it landed; `proctest` and
     * `fsclient` were endowed with a real CAP_AUDIT *for this syscall* and are
     * endowed with CAP_DEBUG instead (src/kernel/selftest.c). Nothing else read
     * another task's info.
     *
     * A task may still read its OWN info with no capability at all -- that is
     * the `tid != get_current_task()` test below, unchanged. */
    struct capability *c = cap_lookup(CAPSLOT_DEBUG, CAP_RIGHT_READ);
    int is_privileged = (c && c->type == CAP_DEBUG);
#ifdef TASKINFO_WIDE_AUTHORITY
    /* CONTROL ARM: the pre-2026-08-24 acceptance set. CAP_USER or CAP_AUDIT also
     * answer "may I see the process list", which is the bundling this narrowing
     * removed. captest holds neither, so it cannot show the widening on its own
     * -- the arm is aimed at the SHELL, which holds CAP_USER for useradd and
     * would regain introspection through it. */
    if (!is_privileged) {
        c = cap_lookup(6, CAP_RIGHT_ALL);
        if (c && c->type == CAP_USER) is_privileged = 1;
    }
    if (!is_privileged) {
        c = cap_lookup(CAPSLOT_AUDIT, CAP_RIGHT_READ);
        if (c && c->type == CAP_AUDIT) is_privileged = 1;
    }
#endif
    /* No root promotion (finding I-1). Cross-task introspection requires a
     * CAP_USER or CAP_AUDIT capability, checked above — being uid 0 is not
     * authority. The shell's `ps` works because init delegates it a CAP_AUDIT,
     * which is revocable; uid 0 was not. */

    if (!is_privileged && tid != get_current_task()) {
        r->rax = -3;
        return;
    }

    struct task_info info;
    for (size_t z = 0; z < sizeof(info); z++) ((uint8_t*)&info)[z] = 0;
    info.id = tid;
    info.state = tasks[tid].state;
    info.uid = tasks[tid].uid;
    info.gid = tasks[tid].gid;
    /* Do NOT leak the page-table physical base to ring-3: it reveals
     * the physical memory layout and aids exploitation. Field is kept
     * for ABI stability but always reported as 0; no consumer uses it. */
    info.cr3 = 0;
    info.heap_used = tasks[tid].heap_current - tasks[tid].heap_start;
    for (int k = 0; k < 31 && tasks[tid].name[k]; k++)
        info.name[k] = tasks[tid].name[k];
    info.name[31] = 0;
    /* Do not disclose ANOTHER task's instruction pointer (finding I-4): it is a
     * live code address and defeats that task's ASLR. `cr3` is suppressed just
     * above for the same reason. A task may still see its own. */
    info.eip = (tid == get_current_task()) ? tasks[tid].eip : 0;
    info.blocked_on = tasks[tid].blocked_on;
    info.blocked_on_notif = tasks[tid].blocked_on_notif;
    info.in_kernel = tasks[tid].in_kernel;
    info.caps_in_use = tasks[tid].caps_in_use;

    if (copy_to_user(out, &info, sizeof(info)) == 0) r->rax = 0;
    else r->rax = (uint32_t)SYS_ERR_FAULT;
}

/* SYS_CLOCK_GETTIME (98): monotonic time since boot (roadmap 2.2).
 *
 * Derived from the PIT tick counter, NOT from the TSC, and that is the whole
 * design. CR4.TSD denies ring 3 RDTSC to remove the cycle-accurate timer that
 * cache and covert-channel attacks lean on; a nanosecond-resolution syscall
 * would hand it straight back. So the resolution is one PIT tick -- 10 ms at
 * PIT_TICK_HZ -- and `nsec` comes out a multiple of 10,000,000.
 *
 * No capability. A coarse count of time since boot is not authority over any
 * object, and every task can already approximate it by counting yields; gating
 * it would buy nothing and push callers toward a worse clock of their own. Self
 * -scoped and read-only, the same class as SYS_GETPID and SYS_TASK_EXIT_INFO.
 *
 * Any clock id other than HORUS_CLOCK_MONOTONIC is refused rather than
 * approximated. There is no wall clock in this system -- nothing reads an RTC,
 * nothing attests one -- and answering CLOCK_REALTIME with uptime would be a
 * number shaped like a date with nothing behind it.
 *
 * Monotonic BY CONSTRUCTION rather than by care: the source is a counter the
 * timer interrupt only ever increments, widened to 64 bits on 2026-08-24
 * because at 100 Hz a u32 wraps after ~497 days, and a clock that goes
 * backwards makes every timeout built on it fire early or never. */
static void h_clock_gettime(struct interrupt_frame64 *r) {
    uint32_t clock_id = (uint32_t)r->rbx;
    struct horus_timespec *out = (struct horus_timespec *)(addr_t)r->rcx;

    if (clock_id != HORUS_CLOCK_MONOTONIC) {
        r->rax = (uint32_t)SYS_ERR_INVAL;
        return;
    }

    struct horus_timespec ts;
#ifdef CLOCK_TSC_RESOLUTION
    /* CONTROL ARM: the obvious "better" clock -- read the TSC and report real
     * nanoseconds. It is more accurate, more useful, and it gives ring 3 back
     * exactly the cycle-accurate timer CR4.TSD spends a control register bit to
     * deny. captest's resolution check must go red under it; if it does not,
     * that check is decoration. */
    {
        uint64_t us = kmsg_uptime_us();
        ts.sec  = us / 1000000u;
        ts.nsec = (uint32_t)((us % 1000000u) * 1000u);
    }
#else
    uint64_t ticks = get_system_ticks64();
    ts.sec      = ticks / PIT_TICK_HZ;
    ts.nsec     = (uint32_t)((ticks % PIT_TICK_HZ) * (1000000000u / PIT_TICK_HZ));
#endif
    ts.reserved = 0;

    r->rax = (copy_to_user(out, &ts, sizeof(ts)) == 0)
           ? 0u : (uint32_t)SYS_ERR_FAULT;
}

/* SYS_CAP_ENUMERATE (97): read one slot of one task's cspace (roadmap 3.6).
 *
 * The capability graph is the security argument of this system, and until now
 * nothing could see it: a reviewer could read the code that mints and delegates,
 * but not ask a running machine what any task actually holds. This makes the
 * graph observable from ring 3, under an explicit and revocable authority.
 *
 * Authority is CAP_DEBUG at CAPSLOT_DEBUG with READ, enforced centrally by the
 * dispatch table -- so the handler never repeats the check, and cannot forget
 * to. Observation only: nothing here writes, and the root CAP_DEBUG is minted
 * READ-only so no delegate can hold anything more.
 *
 * A dead or never-created task reports every slot empty rather than an error.
 * The distinction between "task 9 holds nothing" and "there is no task 9" is
 * one a caller can already make with SYS_GET_TASK_INFO, and answering it here
 * too would make this syscall a task-existence oracle for a caller that holds
 * CAP_DEBUG but was refused task info -- a combination that should not arise,
 * but the cheaper answer is not to depend on that. */
static void h_cap_enumerate(struct interrupt_frame64 *r) {
    int      tid  = (int)r->rbx;
    uint32_t slot = (uint32_t)r->rcx;
    struct cap_info *out = (struct cap_info *)(addr_t)r->rdx;

    if (tid < 0 || tid >= MAX_TASKS || slot >= CNODE_SIZE) {
        r->rax = (uint32_t)SYS_ERR_INVAL;
        return;
    }

    struct cap_info info;
    for (size_t z = 0; z < sizeof(info); z++) ((uint8_t *)&info)[z] = 0;
    info.slot = slot;

    /* Under cap_lock: a concurrent mint, grant or revoke on another CPU must not
     * be read half-written. The copy_to_user happens after the unlock -- it can
     * fault, and faulting with a kernel lock held is how a spinlock becomes a
     * deadlock. */
    spin_lock(&cap_lock);
    if (tasks[tid].state != 0 && tasks[tid].cspace) {
        struct capability *cap = &tasks[tid].cspace[slot];
        if (cap->type != CAP_NULL) {
            info.occupied   = 1;
            info.type       = cap->type;
            info.rights     = cap->rights;
            info.serial     = cap->serial;
            info.badge      = cap->badge;
            info.generation = cap->generation;
            /* `object` is deliberately not reported -- see struct cap_info. */
        }
    }
    spin_unlock(&cap_lock);

    r->rax = (copy_to_user(out, &info, sizeof(info)) == 0)
           ? 0u : (uint32_t)SYS_ERR_FAULT;
}

/* SYS_RUN (19): drop the current task to ring 3 at an already-loaded image.
 * Capability (slot 3, WRITE|EXEC) is enforced centrally by the dispatch table. */
static void h_run(struct interrupt_frame64 *r) {
    uint32_t load_base = r->rbx;
    uint32_t entry = r->rcx;

    tasks[get_current_task()].heap_current = tasks[get_current_task()].heap_start;

    if (get_current_task() == 0) {
        r->rax = -1;
        return;
    }
    /* Guard uint32 overflow same as h_exec. */
    if ((uint64_t)load_base + entry >= USER_MAX_VADDR) {
        r->rax = -1;
        return;
    }
    drop_to_ring3(load_base + entry, tasks[get_current_task()].esp);
    r->rax = 0;
}

/* SYS_RECEIVE_PROGRAM: stage a program image and return its header.
 * Capability (slot 3, WRITE|EXEC) is enforced centrally by the dispatch table.
 *
 * DELIBERATELY NOT BRACKETED BY spawn_stage_acquire() (roadmap 1.7), and this is
 * the one arm → consume window in the kernel that is not. The arm here is a
 * blocking read of up to MAX_PROGRAM_SIZE bytes off the second serial port, and
 * the consume is a later SYS_SPAWN — a different syscall, seconds later, driven
 * by whoever is at the other end of the wire. Holding the staging lock across
 * that would mask interrupts on this CPU for the whole transfer and stall every
 * other spawner behind a human, which is a worse property than the one it would
 * buy.
 *
 * What makes that safe is the ownership stamp ([G-11], loader.c): if another
 * task arms an image between this receive and the spawn that consumes it, the
 * spawn is REFUSED rather than loading the wrong program. The failure mode
 * degrades to "your upload was overwritten, try again", which is the fail-closed
 * direction. Do not "fix" this by adding the bracket without first making the
 * transfer non-blocking. */
static void h_receive_program(struct interrupt_frame64 *r) {
    void *user_hdr = (void *)(addr_t)r->rbx;
    struct program_header k_hdr;

    int rc = do_receive_program(&k_hdr);
    if (rc != 0) {
        r->rax = rc;
        return;
    }

    if (user_hdr) {
        if (copy_to_user(user_hdr, &k_hdr, sizeof(k_hdr)) != 0) {
            r->rax = -3;
            return;
        }
    }

    r->rax = 0;
}

/* SYS_AUTH: authenticate the calling task as a user (sets uid/gid on success). */

/* SYS_YIELD: request a full-context switch; interrupt_handler64 runs
 * sched_yield_switch on the live trap frame after this returns. */
static void h_yield(struct interrupt_frame64 *r) {
    yield();
    r->rax = 0;
}

/* cap mint/transfer/move/revoke (4/8/9/51): authority enforced inside the
 * cap_* primitives (caller_has_authority + per-right checks). */
static void h_cap_mint(struct interrupt_frame64 *r) {
    bool ok = cap_mint(r->rbx, r->rcx, r->rdx);
    r->rax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_MINT, r->rbx, ok ? 0 : -1, ok ? "cap mint" : "cap mint denied");
}
static void h_cap_transfer(struct interrupt_frame64 *r) {
    bool ok = cap_transfer(r->rbx, r->rcx);
    r->rax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_TRANSFER, r->rbx, ok ? 0 : -1, ok ? "cap transfer" : "cap transfer denied");
}
static void h_cap_move(struct interrupt_frame64 *r) {
    bool ok = cap_move(r->rbx, r->rcx);
    r->rax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_TRANSFER, r->rbx, ok ? 0 : -1, ok ? "cap move" : "cap move denied");
}
static void h_cap_revoke(struct interrupt_frame64 *r) {
    /* The authoritative rights check (CAP_RIGHT_REVOKE on the target, kernel
     * exempt) and the no-ambient-authority guard live in cap_revoke(). */
    bool ok = cap_revoke(r->rbx);
    r->rax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_REVOKE, r->rbx, ok ? 0 : -1, ok ? "cap revoke" : "cap revoke denied");
}

/* SYS_CAP_GRANT (65): delegate a capability into a supervised child's cspace.
 * Copy the caller's capability at `src_slot` into tasks[target]'s cspace at
 * `dest_slot` with a fresh serial (so the grantee's cap_lookup accepts it),
 * preserving type/rights/object/badge/generation so the delegated copy tracks the
 * same lineage — a later revoke of the object invalidates it too. Authorised by a
 * CAP_TCB (WRITE) to the target (the spawner's per-child cap) or CAP_USER admin,
 * exactly like SYS_KILL: a task may only push capabilities down into children it
 * supervises (no ambient authority upward). The target must be a live task other
 * than the caller. The caller can only delegate a capability it actually holds. */
static void h_cap_grant(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    int target = (int)r->rbx;
    uint32_t src_slot  = r->rcx;
    uint32_t dest_slot = r->rdx;

    if (target <= 0 || target >= MAX_TASKS || target == cur || tasks[target].state == 0) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }
    if (src_slot >= CNODE_SIZE || dest_slot >= CNODE_SIZE) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }
    if (!tasks[cur].cspace || !tasks[target].cspace) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }
    /* Same authority as SYS_KILL: a CAP_TCB to the target, or admin. */
    if (!task_kill_authorized(target)) {
        audit_log(AUDIT_CAP_TRANSFER, (uint32_t)target, -1, "cap grant denied");
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    /* The source must be a live capability the caller actually holds (checked
     * again authoritatively under cap_lock inside cap_grant_into; this gives the
     * caller a specific NOENT for a missing source). */
    struct capability *src = cap_lookup(src_slot, 0);
    if (!src || src->type == CAP_NULL) {
        r->rax = (uint32_t)SYS_ERR_NOENT; return;
    }

    /* Delegate through the locked, accounted, lineage-correct cap-write path.
     * This replaced a raw `tasks[target].cspace[dest_slot] = *src` store that
     * (a) raced a concurrent global revoke under SMP, (b) never counted the
     * granted cap against the target's MAX_CAPS_PER_TASK ceiling, and (c) left a
     * malformed lineage (badge copied from the grandparent). Rights are passed as
     * CAP_RIGHT_ALL to preserve the 3-argument SYS_CAP_GRANT ABI; cap_grant_into
     * masks them to the source's own rights, so this can still only ever reduce
     * authority, never widen it. */
    if (!cap_grant_into(target, dest_slot, src_slot, CAP_RIGHT_ALL)) {
        audit_log(AUDIT_CAP_TRANSFER, (uint32_t)target, -1, "cap grant failed");
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }

    audit_log(AUDIT_CAP_TRANSFER, (uint32_t)target, 0, "cap grant");
    r->rax = 0;
}

#ifdef LEGACY_SYSCALLS_PRESENT
/* clear screen (5): slot-3 WRITE enforced by the table. */
static void h_clear(struct interrupt_frame64 *r) {
    clear_screen();
    r->rax = 0;
}
#endif /* LEGACY_SYSCALLS_PRESENT */

#if defined(DEBUG_SHELL) || defined(LEGACY_SYSCALLS_PRESENT)
/* debug command exec (7): only meaningful under DEBUG_SHELL. */
static void h_debug_exec(struct interrupt_frame64 *r) {
    char cmd[128];
    if (copy_from_user(cmd, (void*)(addr_t)r->rbx, 127) != 0) {
        r->rax = -1;
        return;
    }
    cmd[127] = 0;
#ifdef DEBUG_SHELL
    r->rax = process_user_command(cmd);
#else
    r->rax = -1;
#endif
}
#endif /* DEBUG_SHELL || LEGACY_SYSCALLS_PRESENT */

/* ramfs open (13): slot-3 READ enforced by the table. */

static void h_getuid(struct interrupt_frame64 *r) {
    r->rax = tasks[get_current_task()].uid;
}

/* SYS_GETPID (20): this task's own id. Self-authorizing — a task learning its
 * own identity grants it nothing it did not already have, so no capability gate.
 *
 * This number was defined in both syscall headers and wrapped as sys_getpid()
 * (libc's getpid() calls it) but never had a handler or a dispatch-table entry,
 * so every call fell through to the fail-closed deny path and came back
 * negative. Nothing shipped checked the result, which is why it went unnoticed
 * until captest asserted on it. */
static void h_getpid(struct interrupt_frame64 *r) {
    r->rax = (uint32_t)get_current_task();
}

/* SYS_CONSOLE_OWNED: report whether a ring-3 console server owns the console
 * hardware. Read-only status a client uses to decide whether to route its stdout
 * through the server (see userspace posix_write); self-authorizing. */
static void h_console_owned(struct interrupt_frame64 *r) {
    r->rax = (uint32_t)(console_hw_owned() ? 1 : 0);
}

/* SYS_SIGACTION: register (handler != 0) or clear (handler == 0) THIS task's own
 * fault-signal handler. Self-authority only -- a task sets a handler for itself,
 * never for another (async cross-task signals would need a capability on the
 * target's TCB, which this does not provide). The handler entry is validated
 * against the user code window in safe Rust so a fault can only ever redirect
 * ring-3 control flow to plausible user code. */
static void h_sigaction(struct interrupt_frame64 *r) {
    /* uint64_t: sig_handler is a full user code address. This was uint32_t,
     * which silently truncated one — harmless only while every image lived
     * below 4 GiB. */
    uint64_t handler = r->rbx;
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    if (handler != 0 && !rust_signal_handler_addr_ok(handler,
                                                     tasks[cur].image_base,
                                                     tasks[cur].image_end)) {
        r->rax = (uint32_t)SYS_ERR_INVAL;   /* handler is not inside this task's image */
        return;
    }
    tasks[cur].sig_handler = handler;
    tasks[cur].in_signal   = 0;
    r->rax = SYS_OK;
}

/* SYS_SIGRETURN is serviced directly in interrupt_handler64 (it must rewrite the
 * live trap frame). This table stub only runs if sigreturn is called outside a
 * handler -- in which case there is nothing to resume, so it fails. */
static void h_sigreturn_stub(struct interrupt_frame64 *r) {
    r->rax = (uint32_t)SYS_ERR_INVAL;   /* sigreturn called outside a handler */
}

/* SYS_SIGMASK: block/unblock THIS task's own signals. `ebx` = how (SIG_SETMASK /
 * SIG_BLOCK / SIG_UNBLOCK), `ecx` = mask. A blocked signal that arrives stays in
 * pending_sigs and is delivered once unblocked (see deliver_pending_signal).
 * SIG_KILL can never be blocked. Returns the previous blocked mask. Self-only. */
static void h_sigmask(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    uint32_t how  = r->rbx;
    uint32_t mask = r->rcx;
    uint32_t old  = tasks[cur].sig_mask;
    uint32_t nm;
    if      (how == SIG_BLOCK)   nm = old | mask;
    else if (how == SIG_UNBLOCK) nm = old & ~mask;
    else                         nm = mask;             /* SIG_SETMASK (default) */
    nm &= ~(1u << SIG_KILL);                            /* SIG_KILL is never blockable */
    tasks[cur].sig_mask = nm;
    r->rax = old;
}

/* SYS_SIGALTSTACK (72): register (ss_size != 0) or disable (ss_size == 0) THIS
 * task's own alternate signal stack. When set, a signal delivered while the task
 * is not already running on it enters the handler on [ss_sp, ss_sp+ss_size)
 * instead of the interrupted user stack (see try_deliver_fault_signal in idt.c).
 * Self-only authority — a task sets its own altstack, never another's. The range
 * must lie wholly inside the user address space and be at least SIG_ALTSTACK_MIN
 * bytes, and cannot be changed while a handler is already running on it
 * (SS_ONSTACK) — all three fail closed. Returns SYS_OK or a negative SYS_ERR_*. */
static void h_sigaltstack(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t sp   = r->rbx;   /* the altstack pointer; a user address, now possibly high */
    uint32_t size = r->rcx;

    /* Re-pointing the altstack while executing on it would corrupt the running
     * handler's own frame — POSIX returns EPERM here; fail closed. */
    if (tasks[cur].sig_on_stack) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    if (size == 0) {                                  /* disable */
        tasks[cur].sig_altstack_sp   = 0;
        tasks[cur].sig_altstack_size = 0;
        r->rax = SYS_OK;
        return;
    }
    if (size < SIG_ALTSTACK_MIN)                 { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    if (sp < USER_AREA_BASE)                     { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    if ((uint64_t)sp + (uint64_t)size > USER_MAX_VADDR) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    tasks[cur].sig_altstack_sp   = sp;
    tasks[cur].sig_altstack_size = size;
    r->rax = SYS_OK;
}

/* SYS_BOOT_MODULE_INFO (77): return the recorded boot-module count, and fill the
 * caller's struct boot_module_info for a valid index. Gated centrally on
 * CAP_BLOCK_DEV (the store-owner authority); the uid==0 check here mirrors the
 * rest of the object-store API, so only the trusted FS server reaches it. Boot
 * modules are bootloader-supplied images at the same trust tier as the block
 * store, so read-only exposure to that owner is not an escalation. */
static void h_boot_module_info(struct interrupt_frame64 *r) {
    uint32_t index = (uint32_t)r->rbx;
    void    *uout  = (void *)(addr_t)r->rcx;
    uint32_t count = boot_module_count();

    if (uout && index < count) {
        const struct boot_module *m = boot_module_get(index);
        struct boot_module_info info;
        /* An unverified module (no match in the kernel's embedded SHA-256
         * manifest — audit A4) is reported as an empty slot: zero size, empty
         * name. The index stays valid so module numbering is stable, but the
         * provisioning loop skips it exactly as it skips a malformed one, and
         * SYS_BOOT_MODULE_READ refuses its payload outright. */
        if (m->verified) {
            info.size = (uint32_t)(m->end - m->start);
            for (int i = 0; i < BOOT_MODULE_INFO_NAME_MAX; i++) info.name[i] = m->name[i];
        } else {
            info.size = 0;
            for (int i = 0; i < BOOT_MODULE_INFO_NAME_MAX; i++) info.name[i] = 0;
        }
        info.name[BOOT_MODULE_INFO_NAME_MAX - 1] = 0;
        if (copy_to_user(uout, &info, sizeof(info)) != 0) { r->rax = (uint32_t)SYS_ERR_FAULT; return; }
    }
    r->rax = count;
}

/* SYS_BOOT_MODULE_READ (78): copy a byte range out of a boot module's payload
 * into a user buffer. The payload lives in physical RAM outside the kernel image
 * (where GRUB dropped it), reached through the PHYS_KVA window. Same gate as
 * SYS_BOOT_MODULE_INFO. offset/len are bounded to the module extent, so a crafted
 * request cannot read past it.
 *
 * This is the only handler whose length is not already bounded by a kernel
 * staging buffer -- it copies straight out of the PHYS_KVA window -- so it is the
 * one place a caller could ask for more than copy_to_user will move in a single
 * call. It therefore clamps to USER_MEM_MAX_COPY itself and returns the count it
 * actually copied: a SHORT READ, which is what the ABI already promises ("bytes
 * copied from a boot module's payload") and what fs_server's provisioning loop
 * already handles by advancing on the returned value. Before [C-4] was fixed the
 * clamp lived inside copy_to_user and this returned the UNCLAMPED len, so a
 * request above 64 KiB reported bytes it had not written. */
static void h_boot_module_read(struct interrupt_frame64 *r) {
    uint32_t index  = (uint32_t)r->rbx;
    uint32_t offset = (uint32_t)r->rcx;
    void    *ubuf   = (void *)(addr_t)r->rdx;
    uint32_t len    = (uint32_t)r->rsi;

    const struct boot_module *m = boot_module_get(index);
    if (!m) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    /* Refuse a payload that did not match the kernel's embedded SHA-256 manifest
     * (audit A4). Verification ran once at boot, before userspace existed, so this
     * is a flag test — and it is the choke point: a module that fails it can never
     * be read, hence never provisioned into /bin as a root-owned executable. */
    if (!m->verified) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    uint32_t size = (uint32_t)(m->end - m->start);
    if (offset >= size) { r->rax = 0; return; }          /* at/after end: 0 bytes */
    uint32_t avail = size - offset;
    if (len > avail) len = avail;
    if (len > USER_MEM_MAX_COPY) len = USER_MEM_MAX_COPY;   /* short read, honestly reported */
    if (len == 0) { r->rax = 0; return; }

    const void *src = PHYS_KVA(m->start + offset);
    if (copy_to_user(ubuf, src, len) != 0) { r->rax = (uint32_t)SYS_ERR_FAULT; return; }
    r->rax = len;
}

/* SYS_DMESG: copy a chunk of the kernel message ring (boot + kernel log) to a
 * user buffer. ROOT ONLY -- the kernel log discloses addresses and boot detail,
 * so like Linux (dmesg_restrict) it is gated to uid 0, enforced here against the
 * caller's kernel-attested identity (never anything the caller supplies). The
 * caller reads the log in small chunks (rcx = byte offset from the oldest
 * retained byte, rdx = max bytes), so it never needs a multi-KiB user buffer and
 * the kernel needs only a small per-call stack buffer -- no shared state to race.
 * Args: rbx = user buffer, rcx = offset, rdx = max. Returns bytes copied
 * (0 at end), or SYS_ERR_PERM / SYS_ERR_FAULT. */
static void h_dmesg(struct interrupt_frame64 *r) {
    void *ubuf     = (void *)(addr_t)r->rbx;
    uint32_t offset = (uint32_t)r->rcx;
    uint32_t max    = (uint32_t)r->rdx;
    char chunk[1024];
    if (max > sizeof(chunk)) max = (uint32_t)sizeof(chunk);
    uint32_t n = klog_copy(chunk, offset, max);
    if (n && copy_to_user(ubuf, chunk, n) != 0) { r->rax = (uint32_t)SYS_ERR_FAULT; return; }
    r->rax = n;
}

/* SYS_RETYPE (90): carve kernel objects out of untyped memory (roadmap 0.3).
 * Args: rbx = cspace slot of a CAP_UNTYPED, rcx = KOBJ_* class, rdx = count,
 * rsi = first destination slot, rdi = pages per object (KOBJ_FRAME only; 0 = 1).
 * Returns the number of objects created, or a negative SYS_ERR_*.
 *
 * SC_NONE in the dispatch table, for the same reason the IPC syscalls are: the
 * authorizing capability is the one the CALLER NAMES, so a fixed table slot
 * would authorise the wrong thing (finding C-1). untyped_retype resolves rbx
 * through cap_lookup and refuses anything that is not a CAP_UNTYPED with WRITE. */
static void h_retype(struct interrupt_frame64 *r) {
    /* rdi is the frame LENGTH in pages, and it is the fifth argument rather than
     * a new syscall so that one authority gate covers both shapes. Every retype
     * written before frames had a length passes 0 here, which normalises to the
     * ordinary single-page object -- and a non-zero length on a class that has
     * none is refused inside, not ignored. */
    r->rax = (uint64_t)(uint32_t)untyped_retype((uint32_t)r->rbx, (uint32_t)r->rcx,
                                                (uint32_t)r->rdx, (uint32_t)r->rdi,
                                                (uint32_t)r->rsi);
}

/* SYS_UNTYPED_INFO (91): rbx = cspace slot of a CAP_UNTYPED (READ),
 * rcx = user struct untyped_info *. Lets a task see how much of its own kernel
 * memory budget it has spent — a budget it cannot observe is one it cannot
 * manage. Same slot-is-the-gate discipline as SYS_RETYPE. */
static void h_untyped_info(struct interrupt_frame64 *r) {
    struct untyped_info info;
    int rc = untyped_info((uint32_t)r->rbx, &info);
    if (rc != 0) { r->rax = (uint64_t)(uint32_t)rc; return; }
    if (copy_to_user((void *)(addr_t)r->rcx, &info, sizeof(info)) != 0) {
        r->rax = (uint32_t)SYS_ERR_FAULT; return;
    }
    r->rax = 0;
}

#ifdef IRQ_POLICY_AUDIT
/* SYS_IRQ_POLICY_INFO (92): rbx = user struct irq_policy_info *. Roadmap 1.1
 * step 2b -- the in-band replacement for printing the audit at the UART from the
 * timer ISR, which split the login prompt and hung the harness measuring it.
 *
 * Gated exactly like SYS_DMESG (CAP_KERNEL_LOG, READ) rather than by a fresh
 * authority: these are kernel-internal statistics of the same class, and the
 * return addresses in the site table are kernel text. Absent from the dispatch
 * table outside IRQ_POLICY_AUDIT builds, so the ship kernel answers NOSYS. */
static void h_irq_policy_info(struct interrupt_frame64 *r) {
    struct irq_policy_info info;
    irq_policy_snapshot(&info);
    if (copy_to_user((void *)(addr_t)r->rbx, &info, sizeof(info)) != 0) {
        r->rax = (uint32_t)SYS_ERR_FAULT; return;
    }
    r->rax = 0;
}
#endif

/* SYS_TASK_EXIT_INFO (93): report why the last task this caller waited on died.
 *
 * Self-scoped: it returns the record task_teardown copied onto THIS task when
 * its SYS_WAIT was satisfied, so it discloses nothing the caller did not already
 * have the authority to observe by waiting. That is why it needs no capability
 * of its own — there is no cross-task read here to gate. Asking before any wait
 * has completed yields reason == TASK_EXIT_NONE rather than a stale answer. */
static void h_task_exit_info(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    if (copy_to_user((void *)(addr_t)r->rbx, &tasks[cur].wait_exit_info,
                     sizeof(struct task_exit_info)) != 0) {
        r->rax = (uint32_t)SYS_ERR_FAULT; return;
    }
    r->rax = 0;
}

typedef struct {
    void   (*fn)(struct interrupt_frame64 *r);
    uint16_t slot;     /* authorizing cspace slot, or SC_NONE */
    uint32_t rights;   /* rights required at `slot` */
    int      ctype;    /* required capability type, or SC_ANYTYPE */
} syscall_desc_t;

#define SYSCALL_TABLE_SIZE 106

/* ------------------------------------------------------------------------- *
 *  Capability-checked dispatch table.
 *
 *  Every syscall has exactly one entry. syscall_handler() validates the
 *  number, enforces the declared capability in ONE place, then calls the
 *  handler -- so a syscall physically cannot be reached without its check, and
 *  an unknown / reserved number (or a gap such as 1, 2, 20) fails closed.
 *
 *  slot == SC_NONE means there is no single fixed authorizing capability: the
 *  handler (or the helper it calls) performs its own authorization, noted per
 *  entry. A few entries declare the fixed part here and keep an extra,
 *  argument-dependent check in the handler (block uid==0, register-fs ep slot).
 * ------------------------------------------------------------------------- */
static const syscall_desc_t syscall_table[SYSCALL_TABLE_SIZE] = {
    [SYS_YIELD]                    = { h_yield,                   SC_NONE, 0, SC_ANYTYPE },
    [SYS_EXIT]                     = { h_exit,                    SC_NONE, 0, SC_ANYTYPE }, /* self-terminate */
    [SYS_KILL]                     = { h_kill,                    SC_NONE, 0, SC_ANYTYPE }, /* CAP_TCB/admin in handler */
    [SYS_GET_LINE]                 = { h_get_line,                SC_NONE, 0, SC_ANYTYPE }, /* CAP_CONSOLE READ, type-tested in the handler */
    [SYS_CAP_MINT]                 = { h_cap_mint,                SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_mint */
    /* SYS_CLEAR (5) cleared the kernel VGA text buffer, which console_server
     * has owned since it took the framebuffer. No userspace wrapper exists
     * for it anywhere in this tree; a live session's `clear` goes through the
     * server. Removed 2026-08-23. */
#ifdef LEGACY_SYSCALLS_PRESENT
    [SYS_CLEAR]                    = { h_clear,                   3, CAP_RIGHT_WRITE, SC_ANYTYPE },
#endif
    /* SYS_SYSINFO (6) returned a version string, with no wrapper anywhere in
     * the tree -- reachable only by issuing the raw number. Removed
     * 2026-08-23; a version readout that nothing reads is surface, not a
     * feature. */
#ifdef LEGACY_SYSCALLS_PRESENT
    [SYS_SYSINFO]                  = { h_sysinfo,                 SC_NONE, 0, SC_ANYTYPE }, /* ambient version string */
#endif
    /* SYS_DEBUG_EXEC (7) hands a 127-byte ring-3 string to the in-kernel
     * debug shell with SC_NONE -- no capability at all. That is the "extra
     * syscall surface" a DEBUG_SHELL=1 build is documented to carry, so the
     * entry now exists only in such a build; the ship kernel fails closed at
     * SYS_ERR_NOSYS. Before 2026-08-23 the ENTRY was unconditional and only
     * the handler's body was guarded, so the ship kernel dispatched it, did a
     * user copy, and returned -1 -- a syscall doing work for nobody. */
#if defined(DEBUG_SHELL) || defined(LEGACY_SYSCALLS_PRESENT)
    [SYS_DEBUG_EXEC]               = { h_debug_exec,              SC_NONE, 0, SC_ANYTYPE }, /* DEBUG_SHELL only */
#endif
    [SYS_CAP_TRANSFER]             = { h_cap_transfer,            SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_transfer */
    [SYS_CAP_MOVE]                 = { h_cap_move,                SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_move */
    [SYS_SBRK]                     = { h_sbrk,                    SC_NONE, 0, SC_ANYTYPE }, /* own heap, bounds-checked */
    [SYS_WRITE]                    = { h_write,                   SC_NONE, 0, SC_ANYTYPE }, /* ambient console (fd 1) */
    [SYS_READ]                     = { h_read,                    SC_NONE, 0, SC_ANYTYPE }, /* fd 0 ambient; fd>=3 slot-3 READ in handler */
    /* ---- The in-kernel ramfs surface, retired 2026-08-22 ------------------
     *
     * SYS_OPEN, 15 (ramfs create) and 16 (ramfs list) used to read
     * `{ handler, 3, CAP_RIGHT_READ|WRITE, SC_ANYTYPE }`. Slot 3 holds the
     * legacy CAP_FRAME that create_task installs in EVERY task, with
     * READ|WRITE|EXEC, and SC_ANYTYPE accepts any type -- so all three were
     * satisfied by a capability nobody asked for and everybody has. That is
     * [C-1]'s shape, and these were the last three gates still wearing it.
     *
     * They are removed rather than re-gated, following syscalls 38-45: the
     * ramfs is an in-kernel toy superseded by fs_server, no ring-3 program in
     * this tree calls any of them, and an ABI kept alive for nobody is surface
     * with no owner. The ramfs itself stays -- kusers.c uses it internally for
     * the user database -- so what closes is the door, not the room.
     *
     * Absent entries fail closed at SYS_ERR_NOSYS by table dispatch. Under
     * RAMFS_SLOT3_GATE=1 they come back exactly as they were, which is what
     * makes `make smoke-passwd-probe` a measurement. */
#ifdef RAMFS_SLOT3_GATE
    [SYS_OPEN]                     = { h_open,                    3, CAP_RIGHT_READ, SC_ANYTYPE },
#endif
    /* SYS_EXEC_LEGACY (14) was a FOURTH door of exactly the shape described
     * above, and it sat directly beneath this comment for the whole of [H-3].
     * `{ h_exec, 3, CAP_RIGHT_WRITE|CAP_RIGHT_EXEC, SC_ANYTYPE }` -- slot 3, the
     * legacy CAP_FRAME every task is born holding, any type. It creates a TASK.
     *
     * Measured on 2026-08-23 before removing it: `passwdprobe`, running as uid
     * 1000 and holding no delegated capability, called syscall 14 and got back
     * task id 2. Not an argument about reachability -- a task, on the wire.
     *
     * And the task it makes has no identity of its own: create_task assigns
     * `state`, never `uid` or `gid`, so a new task carries whatever the slot
     * held -- 0 on a never-used slot (.bss), the previous occupant's uid on a
     * reused one. Every legitimate spawn path sets the child's identity from
     * its parent; this one predates all of them. Since S18, uid 0 confers no
     * KERNEL authority -- but fs_server enforces file permissions against the
     * kernel-attested uid (S13/S14), so a uid-0 task holds root's access to the
     * filesystem, and a reused slot is identity confusion in the other
     * direction.
     *
     * The [H-3] sweep did not miss it through carelessness: this entry was
     * written `[14]`, a bare number, so it matched none of the `[SYS_NAME]`
     * patterns the coverage manifest and every audit grep are built on. It was
     * named in #201 and removed here. */
#ifdef LEGACY_SYSCALLS_PRESENT
    [SYS_EXEC_LEGACY]              = { h_exec,                    3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
#endif
#ifdef RAMFS_SLOT3_GATE
    [SYS_RAMFS_CREATE]             = { h_ramfs_create,            3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [SYS_RAMFS_LIST]               = { h_fs_list,                 3, CAP_RIGHT_READ, SC_ANYTYPE },
#endif
    [SYS_WAIT]                     = { h_wait,                    SC_NONE, 0, SC_ANYTYPE },
    [SYS_GET_TASK_INFO]            = { h_task_info,               SC_NONE, 0, SC_ANYTYPE }, /* self, or admin/audit in handler */
    [SYS_EXEC]                     = { h_run,                     3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    /* IPC is capability-ADDRESSED (audit finding C-1): the first argument is a
     * cspace slot, and the handler resolves it through cap_lookup to the endpoint
     * or notification it names — checking type, right, and lineage in one place
     * (ipc_ep_from_slot / ipc_notif_from_slot in syscall_ipc.c).
     *
     * These entries MUST stay SC_NONE. A fixed slot-3 gate here would be worse
     * than redundant: slot 3 holds a CAP_FRAME in every task, so the old entry
     * authorised IPC for everyone and the per-object capability was never
     * consulted. The per-slot lookup in the handler IS the gate. */
    [SYS_IPC_SEND]                 = { h_ipc_send,                SC_NONE, 0, SC_ANYTYPE },
    [SYS_IPC_RECV]                 = { h_ipc_recv,                SC_NONE, 0, SC_ANYTYPE },
    [SYS_IPC_RECV_BLOCK]           = { h_ipc_recv_block,          SC_NONE, 0, SC_ANYTYPE },
    [SYS_IPC_CALL]                 = { h_ipc_call,                SC_NONE, 0, SC_ANYTYPE },
    [SYS_IPC_REPLY]                = { h_ipc_reply,               SC_NONE, 0, SC_ANYTYPE },
    [SYS_NOTIFY]                   = { h_notify,                  SC_NONE, 0, SC_ANYTYPE },
    [SYS_WAIT_NOTIFY]              = { h_wait_notify,             SC_NONE, 0, SC_ANYTYPE },
    [SYS_RECEIVE_PROGRAM]          = { h_receive_program,         3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_SPAWN]                    = { h_spawn,                   3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_EXEC_NAMED]               = { h_exec_named,              3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_CAP_GRANT]                = { h_cap_grant,               SC_NONE, 0, SC_ANYTYPE }, /* CAP_TCB-to-target/admin in handler */
    [SYS_SIGNAL]                   = { h_signal,                  SC_NONE, 0, SC_ANYTYPE }, /* CAP_TCB-to-target/admin in handler */
    [SYS_SIGMASK]                  = { h_sigmask,                 SC_NONE, 0, SC_ANYTYPE }, /* self: block/unblock own signals */
    [SYS_SPAWN_ARG]                = { h_spawn_arg,               SC_NONE, 0, SC_ANYTYPE }, /* self: read own spawn argument */
    [SYS_GET_ARGV]                 = { h_get_argv,                SC_NONE, 0, SC_ANYTYPE }, /* self: read own argument vector */
    /* execve-from-fd: spawn/exec a caller-supplied program image. Same slot-3
     * WRITE|EXEC gate as SYS_SPAWN / SYS_EXEC_NAMED; the image is validated by the
     * loader (arm_image_from_user -> try_elf_load) exactly like a named binary. */
    [SYS_SPAWN_IMAGE]              = { h_spawn_image,             3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    /* Same gate as SYS_SPAWN, and deliberately not SC_NONE: fork is a second way
     * to create a task, so it answers to the capability that gates the first.
     * See h_fork in kspawn.c. */
    [SYS_FORK]                     = { h_fork,                    3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_EXEC_IMAGE]               = { h_exec_image,              3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_SIGALTSTACK]              = { h_sigaltstack,             SC_NONE, 0, SC_ANYTYPE }, /* self: register own altstack */
    /* Zero-trust identity: a receiver reads the kernel-attested uid of an
     * endpoint's last sender. Slot-3 READ (same as SYS_IPC_RECV) so only a
     * legitimate receiver on the endpoint can query it. */
    [SYS_IPC_SENDER]               = { h_ipc_sender,              SC_NONE, 0, SC_ANYTYPE },
    /* Object-store owner/mode persistence — same gate as the rest of the store
     * (CAP_BLOCK_DEV slot 7 + uid 0 in the handler): filesystem server only. */
    /* NB: `rights` and `ctype` are DISTINCT fields. These entries used to pass
     * CAP_BLOCK_DEV (the type constant, 11) in the RIGHTS position with
     * ctype = SC_ANYTYPE — so the gate actually demanded rights 0b1011
     * (READ|WRITE|GRANT) on a capability of ANY type. Type confusion in an
     * authorisation check, the same class as finding C-1. They now require the
     * object-store capability BY TYPE. */
    [SYS_FS_SET_META]              = { h_fs_set_meta,             CAPSLOT_AUDIT, CAP_RIGHT_READ | CAP_RIGHT_WRITE, CAP_ENCRYPTED_STORAGE },
    /* Reply routed to the request's kernel-recorded sender (multi-client safe).
     * Slot-3 WRITE, same as the other send/reply paths. */
    [SYS_IPC_REPLY_TO]             = { h_ipc_reply_to,            SC_NONE, 0, SC_ANYTYPE },
    [SYS_GETUID]                   = { h_getuid,                  SC_NONE, 0, SC_ANYTYPE },
    [SYS_GETPID]                   = { h_getpid,                  SC_NONE, 0, SC_ANYTYPE }, /* own id: self-authorizing */
    [SYS_CONSOLE_OWNED]            = { h_console_owned,           SC_NONE, 0, SC_ANYTYPE }, /* console status: read-only, self-authorizing */
    [SYS_AUTH]                     = { h_auth,                    SC_NONE, 0, SC_ANYTYPE }, /* self-authorizing */
    [SYS_SUDO]                     = { h_sudo,                    SC_NONE, 0, SC_ANYTYPE }, /* re-auth in handler */
    [SYS_GET_PASS]                 = { h_get_pass,                SC_NONE, 0, SC_ANYTYPE },
    [SYS_USERADD]                  = { h_useradd,                 SC_NONE, 0, SC_ANYTYPE }, /* admin check in do_useradd */
    [SYS_USERDEL]                  = { h_userdel,                 SC_NONE, 0, SC_ANYTYPE }, /* admin check in do_userdel */
    [SYS_PASSWD]                   = { h_passwd,                  SC_NONE, 0, SC_ANYTYPE }, /* admin/self in do_passwd */
    [SYS_ROTATE_KEYS]              = { h_rotate_keys,             8, CAP_RIGHT_READ, CAP_CONSOLE },
    [SYS_READ_AUDIT]               = { h_read_audit,              7, CAP_RIGHT_READ, CAP_AUDIT },
    /* Syscalls 38-45 were the legacy in-memory capfs (a parallel, unencrypted
     * capability-FS separate from the encrypted fs_server). Removed: the entries
     * are absent, so the dispatcher fails them closed (SYS_ERR_NOSYS). The
     * numbers are left reserved (not reused) so no future syscall silently
     * inherits an old ring-3 caller. */
    [SYS_REGISTER_STORAGE_BACKEND] = { h_register_storage_backend, SC_NONE, 0, SC_ANYTYPE },
    [SYS_BLOCK_READ]               = { h_block_read,              CAPSLOT_AUDIT, CAP_RIGHT_READ | CAP_RIGHT_WRITE, CAP_ENCRYPTED_STORAGE }, /* + uid 0 in handler */
    [SYS_BLOCK_WRITE]              = { h_block_write,             CAPSLOT_AUDIT, CAP_RIGHT_READ | CAP_RIGHT_WRITE, CAP_ENCRYPTED_STORAGE }, /* + uid 0 in handler */
    [SYS_REGISTER_FS_SERVER]       = { h_register_fs_server,      6, CAP_RIGHT_ALL, CAP_USER }, /* + ep lookup in handler */
    [SYS_CONNECT_FS_SERVER]        = { h_connect_fs_server,       SC_NONE, 0, SC_ANYTYPE },
    [SYS_CAP_REVOKE]               = { h_cap_revoke,              SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_revoke */
    [SYS_AUDIT_DIGEST]             = { h_audit_digest,            7, CAP_RIGHT_READ, CAP_AUDIT },
#ifdef PREEMPT_SELFTEST
    /* Test-only trace hook; absent (fails closed) in the ship kernel. */
    [SYS_PREEMPT_TRACE]            = { h_preempt_trace,           SC_NONE, 0, SC_ANYTYPE },
#endif
    [SYS_SIGACTION]                = { h_sigaction,               SC_NONE, 0, SC_ANYTYPE }, /* self: register own handler */
    [SYS_SIGRETURN]                = { h_sigreturn_stub,          SC_NONE, 0, SC_ANYTYPE }, /* real work in interrupt_handler64 */
    /* Encrypted object-store API — same gate as the raw block syscalls
     * (CAP_BLOCK_DEV slot 7 here + uid 0 in the handler). */
    [SYS_FS_INODE_ALLOC]           = { h_fs_inode_alloc,          CAPSLOT_AUDIT, CAP_RIGHT_READ | CAP_RIGHT_WRITE, CAP_ENCRYPTED_STORAGE },
    [SYS_FS_INODE_FREE]            = { h_fs_inode_free,           CAPSLOT_AUDIT, CAP_RIGHT_READ | CAP_RIGHT_WRITE, CAP_ENCRYPTED_STORAGE },
    [SYS_FS_INODE_LINK]            = { h_fs_inode_link,           CAPSLOT_AUDIT, CAP_RIGHT_READ | CAP_RIGHT_WRITE, CAP_ENCRYPTED_STORAGE },
    [SYS_FBLOCK_READ]              = { h_fblock_read,             CAPSLOT_AUDIT, CAP_RIGHT_READ | CAP_RIGHT_WRITE, CAP_ENCRYPTED_STORAGE },
    [SYS_FBLOCK_WRITE]             = { h_fblock_write,            CAPSLOT_AUDIT, CAP_RIGHT_READ | CAP_RIGHT_WRITE, CAP_ENCRYPTED_STORAGE },
    [SYS_FS_STAT]                  = { h_fs_stat,                 CAPSLOT_AUDIT, CAP_RIGHT_READ | CAP_RIGHT_WRITE, CAP_ENCRYPTED_STORAGE },
    [SYS_FS_SET_SIZE]              = { h_fs_set_size,            CAPSLOT_AUDIT, CAP_RIGHT_READ | CAP_RIGHT_WRITE, CAP_ENCRYPTED_STORAGE },
    [SYS_BRK]                     = { h_brk,                    SC_NONE, 0, SC_ANYTYPE }, /* own heap, demand-paged */
    /* Boot-module read surface — same gate as the object store (CAP_BLOCK_DEV
     * slot 7 here + uid 0 in the handler), so only the FS server reaches it. */
    [SYS_BOOT_MODULE_INFO]        = { h_boot_module_info,  CAPSLOT_BOOT_MODULE, CAP_RIGHT_READ, CAP_BOOT_MODULE },
    [SYS_BOOT_MODULE_READ]        = { h_boot_module_read,  CAPSLOT_BOOT_MODULE, CAP_RIGHT_READ, CAP_BOOT_MODULE },
    /* Device delegation (syscall_hw.c): map one of a device's frames, grant its
     * ports, route its IRQ. SC_NONE — and that is the gate, not the absence of
     * one. Each of these took a FIXED slot-10 CAP_IO_DEVICE entry here until
     * 2026-08-28, which made holding the type the whole authority and let one
     * capability reach a compiled-in console allowlist regardless of what it
     * named. The first argument is now a cspace slot resolved by iodev_from_slot,
     * exactly as the IPC syscalls resolve theirs (finding C-1), and the resource
     * asked for is checked against what THAT device declares. Leaving a fixed
     * entry here would re-admit the old behaviour underneath the new check, which
     * is why removing it is part of the fix rather than a tidy-up. */
    [SYS_MAP_PHYS]                = { h_map_phys,                SC_NONE, 0, SC_ANYTYPE },
    [SYS_IOPORT_GRANT]            = { h_ioport_grant,            SC_NONE, 0, SC_ANYTYPE },
    [SYS_IRQ_REGISTER]            = { h_irq_register,            SC_NONE, 0, SC_ANYTYPE },
    [SYS_DEVICE_INFO]             = { h_device_info,             SC_NONE, 0, SC_ANYTYPE },
    [SYS_DEVICE_ENABLE]           = { h_device_enable,           SC_NONE, 0, SC_ANYTYPE },
    [SYS_DMA_ADDR]                = { h_dma_addr,                SC_NONE, 0, SC_ANYTYPE },
    [SYS_IRQ_ACK]                 = { h_irq_ack,                 SC_NONE, 0, SC_ANYTYPE },
    /* Pipes: authorization is the pipe-end capability passed as the slot argument,
     * validated in the handler (cap_lookup with the direction's right), so no fixed
     * table slot. SYS_PIPE/STDIO_INFO are self-scoped (own cspace / own tcb). */
    [SYS_PIPE]                    = { h_pipe,                    SC_NONE, 0, SC_ANYTYPE },
    [SYS_PIPE_READ]               = { h_pipe_read,               SC_NONE, 0, SC_ANYTYPE },
    [SYS_PIPE_WRITE]              = { h_pipe_write,              SC_NONE, 0, SC_ANYTYPE },
    [SYS_PIPE_CLOSE]              = { h_pipe_close,              SC_NONE, 0, SC_ANYTYPE },
    [SYS_STDIO_INFO]              = { h_stdio_info,              SC_NONE, 0, SC_ANYTYPE },
    [SYS_DMESG]                   = { h_dmesg,  CAPSLOT_KERNEL_LOG, CAP_RIGHT_READ, CAP_KERNEL_LOG },
    /* CAP_TCB-to-target / admin checked in the handler, as for SYS_KILL. */
    [SYS_TASK_RESUME]             = { h_task_resume,             SC_NONE, 0, SC_ANYTYPE },
    /* Untyped memory (roadmap 0.3). MUST stay SC_NONE: the authorizing
     * capability is the one named by the caller's first argument, and a fixed
     * table slot here would repeat exactly the C-1 mistake — gating on a
     * capability every task happens to hold while never consulting the one that
     * actually names the resource. untyped_retype / untyped_info do the lookup. */
    [SYS_RETYPE]                  = { h_retype,                  SC_NONE, 0, SC_ANYTYPE },
    [SYS_UNTYPED_INFO]            = { h_untyped_info,            SC_NONE, 0, SC_ANYTYPE },
#ifdef IRQ_POLICY_AUDIT
    /* Roadmap 1.1 audit readout; absent (fails closed) in the ship kernel. */
    [SYS_IRQ_POLICY_INFO]         = { h_irq_policy_info, CAPSLOT_KERNEL_LOG, CAP_RIGHT_READ, CAP_KERNEL_LOG },
#endif
    /* Self-scoped (finding G-8): hands back the death record of the task THIS
     * caller waited on, which waiting already entitled it to observe. No
     * cross-task disclosure, so no capability to gate on. */
    [SYS_TASK_EXIT_INFO]          = { h_task_exit_info,          SC_NONE, 0, SC_ANYTYPE },
    /* Frame capabilities (roadmap 2.1). MUST stay SC_NONE, for a reason that is
     * live rather than theoretical here: every task is born holding a CAP_FRAME
     * in slot 3, so an entry naming CAPSLOT_FRAME/CAP_FRAME would type-check,
     * read like a real gate, and pass for every task in the system. The
     * authorising capability is the one the caller names in its first argument;
     * syscall_vm.c does the lookup, the type test and the index bound. Same rule
     * and same reason as SYS_RETYPE above.
     *
     * (The narrowing half of delegation is SYS_CAP_MINT, which already existed
     * as the unnamed entry [4] above; roadmap 2.1 gave it a name rather than a
     * second implementation.) */
    [SYS_MAP_FRAME]               = { h_map_frame,               SC_NONE, 0, SC_ANYTYPE },
    [SYS_UNMAP_FRAME]             = { h_unmap_frame,             SC_NONE, 0, SC_ANYTYPE },
    [SYS_MAP_REGION]              = { h_map_region,              SC_NONE, 0, SC_ANYTYPE }, /* CAP_FRAME per slot, type-tested in the handler */
    [SYS_FRAME_PAGES]             = { h_frame_pages,             SC_NONE, 0, SC_ANYTYPE }, /* CAP_FRAME the caller names, type-tested in the handler */
    /* Observation, gated centrally: CAP_DEBUG at CAPSLOT_DEBUG with READ. The
     * table is the gate, so h_cap_enumerate contains no authority check at all
     * -- which is the point of the central gate, and why a handler that repeats
     * it is a smell rather than defence in depth. */
#ifdef CAP_ENUMERATE_UNGATED
    /* CONTROL ARM: the same syscall with no declared capability, so the central
     * gate lets every caller through to the handler. captest must go red. */
    [SYS_CAP_ENUMERATE]           = { h_cap_enumerate,           SC_NONE, 0, SC_ANYTYPE },
#else
    [SYS_CAP_ENUMERATE]           = { h_cap_enumerate,           CAPSLOT_DEBUG, CAP_RIGHT_READ, CAP_DEBUG },
#endif
    /* OUTSIDE the CAP_ENUMERATE_UNGATED arm, and it was not on the first try:
     * appended to the #else branch, this entry existed only in ordinary builds,
     * so the control-arm kernel had no clock at all and captest failed on
     * `clock-monotonic-refused` instead of the door it was aiming at. The arm
     * caught it, which is what arms are for -- but note what did NOT: the
     * coverage deriver models the SHIP build, where the entry is present and
     * correct, so a syscall accidentally scoped to a defect arm's #else is
     * invisible to it.
     *
     * No capability: a coarse count of time since boot is not authority over an
     * object, and its resolution is chosen so it does not restore what CR4.TSD
     * takes away. See h_clock_gettime. */
    [SYS_CLOCK_GETTIME]           = { h_clock_gettime,           SC_NONE, 0, SC_ANYTYPE },
};

/* Compile-time guard: the table must have a slot for every syscall number, so
 * no defined syscall can index past it and fall through the
 * `num < SYSCALL_TABLE_SIZE` bound into the deny path by accident.
 * SYS_UNMAP_FRAME is currently the highest syscall number. Adding a higher one
 * (or shrinking the table) breaks the build here and forces you to grow
 * SYSCALL_TABLE_SIZE -- which lands you right next to the entries you must
 * fill in. (C cannot check the function pointer itself in a static assert; a
 * still-missing entry stays NULL and fails closed at runtime, and adding an
 * entry past the array bound is already a hard compiler error.) */
_Static_assert(SYSCALL_TABLE_SIZE == SYS_IRQ_ACK + 1,
               "syscall_table size must equal (highest syscall number + 1): "
               "grow SYSCALL_TABLE_SIZE and add the new entry when adding a syscall");

/* ---- syscall success-path coverage (SYSCALL_COVERAGE builds only) ----------
 *
 * Records the first time each syscall's HANDLER BODY is entered, and says so on
 * the wire. Not "was the syscall called" and not "did it succeed" -- entered.
 *
 * That is the precise signal, because it is precisely what was missing when
 * issue #176 hid behind a 100-check conformance suite. `captest` is a REFUSAL
 * suite by construction: the two checks naming SYS_DMESG and SYS_AUDIT_DIGEST
 * both assert SYS_ERR_PERM, and the central gate above returns before `d->fn`
 * is ever reached. So both syscalls were named by the suite, both were
 * "tested", and neither handler had ever run. A defect in the handler's
 * argument handling was therefore invisible to every gate in the tree.
 *
 * Deliberately NOT recorded as "returned success". A return-value test needs a
 * per-syscall rule about what success looks like -- SYS_BRK returns an address
 * that is negative as an int32, SYS_READ returns a count, SYS_IPC_RECV_BLOCK
 * blocks -- and a heuristic in a gate is a gate that lies eventually. "The body
 * ran" is decidable, uniform, and is the property whose absence caused the miss.
 *
 * Emitted through kfault_str() rather than print(), for the reason the kernel
 * fault banner uses it (idt.c): print() is klog-only once console_server owns
 * the console, so anything reported through it during a live session is
 * inaudible on the wire -- and a live session is exactly when the interesting
 * syscalls run. Same idiom as KSTACK0_PARK_TRACE. */
#ifdef SYSCALL_COVERAGE
static uint8_t syscov_seen[SYSCALL_TABLE_SIZE];
static void syscov_note(uint32_t num) {
    if (num >= SYSCALL_TABLE_SIZE) return;
    if (syscov_seen[num]) return;
    syscov_seen[num] = 1;
    kfault_begin(0);
    kfault_str("\nSYSCOV ");
    kfault_dec((int)num);
    kfault_str("\n");
    kfault_end(0);
}
#else
static inline void syscov_note(uint32_t num) { (void)num; }
#endif

void syscall_handler(struct interrupt_frame64 *r) {
    if (get_current_task() < MAX_TASKS) {
        tasks[get_current_task()].in_kernel = 1;
    }

    uint32_t num = r->rax;
    const syscall_desc_t *d = (num < SYSCALL_TABLE_SIZE) ? &syscall_table[num] : (const syscall_desc_t *)0;

    if (!d || !d->fn) {
        /* Unknown, reserved, or unimplemented syscall number: fail closed. */
        r->rax = (uint32_t)SYS_ERR_NOSYS;
    } else if (d->slot != SC_NONE) {
        /* Central capability gate: a syscall cannot run without its declared
         * capability. Handlers no longer repeat this check. */
        struct capability *c = cap_lookup(d->slot, d->rights);
        if (!c || (d->ctype != SC_ANYTYPE && (int)c->type != d->ctype)) {
            r->rax = (uint32_t)SYS_ERR_PERM;
        } else {
            syscov_note(num);
            d->fn(r);
        }
    } else {
        syscov_note(num);
        d->fn(r);
    }

    if (get_current_task() < MAX_TASKS) {
        tasks[get_current_task()].in_kernel = 0;
    }
}


