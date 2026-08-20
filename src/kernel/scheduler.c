#include "kernel.h"

tcb_t tasks[MAX_TASKS];
int current_task = 0;
int percpu_current_task[MAX_CPUS];

/* The last ring-3 task each CPU ran, for flush-on-switch (0 = none yet).
 *
 * Deliberately OUTSIDE the SMP guard. Flush-on-switch is a side-channel
 * mitigation on the task-switch path, not an SMP mechanism: a uniprocessor
 * kernel switches between mutually distrusting ring-3 tasks on one logical CPU
 * and needs the barrier just as much. set_current_task() reads this
 * unconditionally, which is correct -- it was the DECLARATION that was guarded,
 * so SMP=0 failed to compile.
 *
 * Note the shape of the wrong fix: guarding the *use* in set_current_task with
 * `#ifdef SMP` would also build, and would silently switch the mitigation off on
 * uniprocessor. The array is one int per CPU; there is nothing to save. */
int percpu_last_user_task[MAX_CPUS];

#ifdef SMP
/* Per-CPU "parked in the idle loop" flag. Set only when a CPU is dropped back to
 * ap_idle_loop with no task to run (enter_cpu_idle); cleared the moment a real
 * task is made current on it (set_current_task with v > 0). It is what lets the
 * BSP be rescheduled out of a genuine idle — a task that blocked it there is woken
 * cross-core and must be picked back up — WITHOUT reintroducing preemption of the
 * BSP's real ring-0 kernel work (e.g. the SMP self-test's result-spin loop, which
 * also runs with current-task 0 but must run to completion). */
int percpu_idle[MAX_CPUS];

/* ---- Declared impersonation: when percpu_current_task[] is deliberately lying --
 *
 * copy_to_user/user_copy translate through tasks[get_current_task()].cr3, so
 * writing into ANOTHER task's address space requires briefly making that task the
 * current one. Two subsystems do this:
 *
 *   - IPC reply delivery (sys_ipc_send, h_ipc_reply_to) impersonates the blocked
 *     peer across a <=256-byte copy, with interrupts masked. Microseconds.
 *   - SPAWN (do_spawn -> load_staged_image_into) impersonates the CHILD across the
 *     whole ELF load, so the loader's copies land in the child's address space.
 *     That is a ~450 KiB copy plus page-table construction and relocation
 *     processing: under TCG it spans many timer ticks.
 *
 * For those windows percpu_current_task[] does NOT describe the task the CPU is
 * running, so the raw claim invariant cannot hold and an auditor on another core
 * would read a violation that is not one.
 *
 * The answer is NOT to blind the auditor. `percpu_real_task[]` records the task
 * the CPU is genuinely running for the duration, and the checker audits against
 * THAT — so coverage is continuous even across the longest operation in the
 * system, which is precisely where a real leak would otherwise hide. An
 * exemption that switches the checker off for the duration of every spawn is a
 * hole in the shape of the thing being checked.
 *
 * `percpu_impersonating[]` is a nesting DEPTH, not a flag: nothing nests these
 * today, but a depth cannot be silently un-set by an inner bracket if something
 * ever does. A CPU cannot migrate mid-window — the ring-0 preemption guard in
 * preempt_on_tick declines to switch a CPU away from a live kernel context — so
 * enter and exit always run on the same CPU.
 *
 * History: the IPC windows were declared (as a `percpu_in_user_copy` flag) when
 * SCHED_INVARIANTS false-positived on them. The spawn window was NOT, and it
 * produced the "stale scheduler claim: task 1 claimed by cpu N but that cpu was
 * running 4" report that stood open as a suspected scheduler defect — task 1 is
 * `init`, task 4 is the shell it was in the middle of spawning, and the claim on
 * init was correct and live the whole time. See TESTS.md. */
volatile int percpu_impersonating[MAX_CPUS];
volatile int percpu_real_task[MAX_CPUS];
#endif

#ifdef SMP
/* Which CPU is currently running each task (-1 == not running anywhere). The SMP
 * scheduler's mutual-exclusion guard: preempt_on_tick only ever claims a task
 * whose entry is -1, so a task's single kernel stack + saved trap frame are
 * never touched by two CPUs at once. Managed under the scheduler lock.
 *
 * ---- THE CLAIM INVARIANT ----------------------------------------------------
 *
 *     task_running_cpu[t] == c   <=>   percpu_current_task[c] == t     (t > 0)
 *
 * A claim is a two-way binding, and BOTH directions carry weight:
 *
 *   ->  If a task is claimed by CPU c, that CPU must actually be running it.
 *       Every selection loop in this file (preempt_on_tick, sched_yield_switch,
 *       ipc_block_switch) skips any candidate whose entry is not -1. So a claim
 *       held by a CPU that is NOT running the task makes that task unschedulable
 *       *by every CPU in the system, including the one holding the claim*. The
 *       task stays RUNNABLE with a valid resumable context and simply never runs
 *       again: not a crash, not a halt, a silent livelock in which the remaining
 *       tasks spin-yield against each other forever.
 *
 *   <-  If a CPU is running a task, that task must be claimed by it. Otherwise a
 *       second CPU may select the same task and two cores execute one task's
 *       single kernel stack and trap frame concurrently — memory corruption
 *       across a privilege boundary, which is far worse than the hang.
 *
 * The dangerous asymmetry to watch for is a path that CLAIMS unconditionally but
 * RELEASES conditionally. Releasing on a narrower condition than claiming leaks a
 * claim on every path the condition excludes.
 *
 * Note that a leaked claim is not merely a lost task: it is usually the visible
 * symptom of a CPU having abandoned a live kernel context (see the ring-0
 * preemption guard in preempt_on_tick). Restoring the invariant by clearing the
 * stale entry WITHOUT fixing the abandonment makes the task schedulable again —
 * and it then resumes from a stale trap frame, discarding whatever kernel work
 * was in flight, possibly including a lock it still holds. Fix the abandonment
 * first; treat a stale claim as a symptom to be diagnosed, never as a value to be
 * quietly corrected. */
int task_running_cpu[MAX_TASKS];

/* ---- THE CLAIM ENDS LATER THAN THE SWITCH DOES -----------------------------
 *
 * The invariant above buys exactly one thing: "a task's single kernel stack +
 * saved trap frame are never touched by two CPUs at once". Releasing the
 * outgoing task inside the switch path does not deliver that, and finding G-8
 * is the receipt.
 *
 * Every switch path here is called FROM interrupt_handler64, which is running on
 * the outgoing task's kernel stack — the C frames sit immediately below the trap
 * frame the CPU pushed on entry. Releasing `cur` and dropping the scheduler lock
 * publishes that task as claimable while this CPU still has to:
 *
 *   - pop six callee-saved registers off that stack in preempt_on_tick's epilogue
 *   - `ret` through a return address on that stack
 *   - run interrupt_handler64's floor guard, out->cs read and fpu_restore
 *   - read its stack-protector canary from that stack
 *   - pop four more callee-saved registers and `ret` again
 *   - and only THEN reach isr_common_stub64's `movq %rax,%rsp`
 *
 * Another CPU that claims the task in that window resumes it to ring 3 from its
 * saved frame, and its very next trap re-enters the ISR on the SAME stack, at the
 * SAME depth, running the SAME functions — so it rewrites precisely the words
 * this CPU has not finished reading. The overlap being exact is what made the
 * corruption so hard to see: the return addresses and the stack canary land back
 * at their own slots with their own values, so the frame validates and the
 * `ret`s go where they should. Only the DATA differs, and the first datum that
 * matters is the resume %rsp on its way to `movq %rax,%rsp`. That is G-8's
 * signature exactly: a resume value that is a plausible word from the wrong
 * context (a `.text` return address in one capture, `4` in another), a canary
 * that passed, and a claim invariant that reads perfectly consistent at the
 * moment of the fault — because it IS consistent. The task really is running on
 * exactly one CPU. The other one is merely still leaving.
 *
 * So the claim is held until the CPU has physically left the stack, and released
 * from sched_release_deferred() below, which isr_common_stub64 calls immediately
 * after `movq %rax,%rsp` — the first instruction at which this CPU is provably
 * reading a different stack. The delay is a few tens of instructions; a CPU that
 * wanted this task simply takes it on the next tick.
 *
 * `g_kstack_inflight` is the standing witness rather than a comment: bit t is set
 * while some CPU is in that window on task t's stack, and interrupt_handler64
 * tests it on entry. If any CPU ever enters an ISR for a task whose bit is set,
 * two CPUs are on one kernel stack and the kernel says so and halts instead of
 * corrupting itself quietly. One load and a bit test on the common path.
 *
 * KSTACK_RELEASE_EARLY=1 restores the pre-fix release site — the defect, on
 * demand — and is what `make smoke-kstack-race-control` builds. */
volatile uint64_t g_kstack_inflight = 0;

/* Task this CPU still has to unwind off, or -1. Written only by the owning CPU.
 * The functions that manage it live below sched_raw_lock(). */
static int percpu_deferred_release[MAX_CPUS] = { [0 ... MAX_CPUS - 1] = -1 };

/* Bitmask of CPUs that have run at least one user task (bit c == CPU c). The SMP
 * self-test reads it to confirm work actually landed on more than one core. */
volatile unsigned smp_cpus_ran_tasks = 0;
#endif

#ifndef SMP
/* Uniprocessor: no second CPU to hand a stack to, so the window does not exist.
 * Defined anyway because isr_common_stub64 calls it unconditionally — a SMP=0
 * build that silently dropped the call would diverge from the SMP one in the ISR
 * epilogue, which is the last place in this kernel worth having two versions of. */
void sched_release_deferred(void) { }
#endif

/* Task 0's kernel stack is per_task_kstacks[0] (paging.c), bound by
 * create_user_pagedir(0) above a guard page like every other task's — so the
 * boot/idle/reaper task (the page-fault handler resumes on
 * tasks[0].kernel_stack_top when it kills a task and finds no successor, idt.c)
 * is guarded too. Task 0 previously kept a separate, 16-byte-aligned,
 * *unguarded* task0_kernel_stack here; per_task_kstacks[0] was allocated and
 * never used, so moving task 0 onto it guards the stack and reclaims the
 * duplicate. */

spinlock_t scheduler_lock;
spinlock_t page_lock;
spinlock_t cap_lock;
spinlock_t endpoint_lock;
spinlock_t storage_lock;

addr_t current_kernel_stack_top = 0;  

void scheduler_lock_acquire(void);
void scheduler_lock_release(void);

struct endpoint endpoints[MAX_ENDPOINTS];

uint32_t system_ticks = 0;

void scheduler_init(void) {
    for (int i = 0; i < MAX_TASKS; i++) {
        tasks[i].state = 0;
        tasks[i].esp = 0;
        tasks[i].eip = 0;
        tasks[i].cap_tcb = 0;
        tasks[i].cr3 = 0;
        tasks[i].priority = 1;
        tasks[i].cspace = 0;
        tasks[i].cspace_size = 0;
        tasks[i].heap_start = 0;
        tasks[i].heap_current = 0;
        tasks[i].heap_end = 0;
        tasks[i].name[0] = 0;
        tasks[i].waiter = -1;
        tasks[i].blocked_on = -1;
        tasks[i].ipc_role = 0;
        tasks[i].in_kernel = 0;
        tasks[i].blocked_on_notif = -1;
        tasks[i].pending_block = 0;
        tasks[i].auth_fail_count = 0;
        tasks[i].auth_lockout_until = 0;
    }

    create_task(0, 0, 0, 0, 0);   /* task 0: no image, default premap */

    tasks[0].uid = 0;
    tasks[0].gid = 0;

    users_init();

    /* Endpoints and notifications start with NO waiter. -1 is the documented
     * "nobody" sentinel for all three of these fields; 0 is a real task id (the
     * boot/idle task), so leaving them at their .bss zero states "task 0 is
     * blocked here", which is false for every endpoint in the system.
     *
     * Benign today only because every consumer happens to test `waiter > 0`
     * rather than `waiter >= 0` — i.e. the code is correct by coincidence at each
     * use site rather than by construction at the source. One future reader
     * writing the more natural `>= 0` gets a wake sent to task 0. Initialise to
     * the sentinel the field is documented to use. (Retyped endpoints from
     * untyped memory already do this in kobj_alloc; this is the static tables
     * catching up.) */
    for (int i = 0; i < MAX_ENDPOINTS; i++) {
        endpoints[i].head           = 0;
        endpoints[i].count          = 0;
        endpoints[i].last_sender    = -1;
        endpoints[i].blocked_waiter = -1;
        for (int s = 0; s < EP_QUEUE_SLOTS; s++) {
            endpoints[i].q[s].len    = 0;
            endpoints[i].q[s].sender = -1;
        }
    }
    for (int i = 0; i < MAX_NOTIFICATIONS; i++) {
        notifications[i].pending_badge  = 0;
        notifications[i].blocked_waiter = -1;
    }

    
    for (int c = 0; c < MAX_CPUS; c++) percpu_current_task[c] = 0;
    for (int c = 0; c < MAX_CPUS; c++) percpu_last_user_task[c] = 0;
#ifdef SMP
    /* No CPU is impersonating anyone yet. -1 is "not impersonating", so it must
     * not be left as 0 (a valid task id, and the idle task's at that). */
    for (int c = 0; c < MAX_CPUS; c++) { percpu_impersonating[c] = 0;
                                         percpu_real_task[c]     = -1; }
#endif
    percpu_current_task[0] = 0;
    current_task = 0;
    scheduler_lock = (spinlock_t){0};
    page_lock = (spinlock_t){0};
    cap_lock = (spinlock_t){0};
    endpoint_lock = (spinlock_t){0};
    storage_lock = (spinlock_t){0};

    current_kernel_stack_top = KERNEL_TSS_STACK;
}

void create_task(int id, addr_t entry, addr_t stack_top, addr_t image_base,
                 uint32_t premap_pages) {
    if (id >= MAX_TASKS) return;

    /* Record the (possibly ASLR-randomized) image base before create_user_pagedir
     * runs, so it premaps the image window at the right virtual address. Default
     * to the fixed low base for task 0 / callers that don't relocate. */
    tasks[id].image_base = image_base ? image_base : (uint64_t)USER_AREA_BASE;
    tasks[id].image_end  = tasks[id].image_base;   /* refined by the loader once the image size is known */

    /* How many image-window pages create_user_pagedir premaps. The spawn path
     * passes staged_image_span_pages() so the whole image is present for the
     * loader's copy_to_user; task 0 and the flat demo paths pass 0, which
     * create_user_pagedir reads as the USER_ASPACE_PREMAP_PAGES default. Set here
     * (not left to slot-reuse staleness) so every rebuild of a slot is explicit. */
    tasks[id].image_premap_pages = premap_pages;

    tasks[id].state = 1;
    tasks[id].esp = (addr_t)(stack_top ? (stack_top - 256) : 0);
    tasks[id].eip = entry;
    tasks[id].cap_tcb = id;

    /* Every task's kernel stack — task 0 included — is per_task_kstacks[id],
     * bound by create_user_pagedir (called below) above a guard page. Nothing
     * reads tasks[id].kernel_stack_top between here and that call, so there is no
     * bootstrap value to pin first; task_kstack_top() PANICs on a 0 stack, which
     * only fires once a task is actually scheduled, long after this completes. */
    fpu_task_init(id);           /* start from a clean x87/SSE register file */
    tasks[id].saved_ksp = 0;
    tasks[id].runnable_ctx = 0;
    tasks[id].pending_block = 0;
    tasks[id].sig_handler = 0;   /* no signal handler until the task registers one */
    tasks[id].in_signal = 0;
    tasks[id].pending_sigs = 0;   /* no async signals queued */
    tasks[id].sig_mask     = 0;   /* nothing blocked */
    tasks[id].sig_altstack_sp   = 0;   /* no alternate signal stack until registered */
    tasks[id].sig_altstack_size = 0;
    tasks[id].sig_on_stack      = 0;
    tasks[id].spawn_arg    = 0;   /* no spawn argument */
    tasks[id].argc         = 0;   /* no argument vector */
    tasks[id].argv_ptr     = 0;

create_user_pagedir(id);

    /* The task's cspace is a KOBJ_CNODE carved from the kernel's untyped region
     * (roadmap 0.3, finding I-7). It used to be `static struct capability
     * cspace_pool[MAX_TASKS][256]` — 512 KiB of `.bss` charged against the
     * `__bss_end <= USER_PHYS_BASE` linker ASSERT, present in the image whether
     * or not a single task ever ran, and a hard ceiling of MAX_TASKS cspaces that
     * could only be raised by spending more of the 16 MiB image budget.
     *
     * Allocated once per task id and kept for the life of the boot, which is
     * exactly the lifetime cspace_pool[id] had. Freeing it at teardown would be a
     * genuine reclaim, but `tasks[id].cspace == NULL` is the sentinel cap_lookup
     * reads as "fall back to the kernel root cnode" — so a freed-and-nulled
     * cspace on a slot anything still consults would be an authority ESCALATION,
     * not a crash. Reclaiming cspaces needs that fallback removed first; it is
     * not blocking the memory model this change is about. */
    if (!tasks[id].cspace) {
        void *cn = kobj_alloc(UNTYPED_KERNEL, KOBJ_CNODE, 0);
        if (!cn) {
            /* The kernel reserve is sized for MAX_TASKS cspaces by construction
             * (untyped_init), so this is unreachable rather than a resource
             * limit. Refuse to run a task with no cspace: cap_lookup would fall
             * back to the root cnode and hand it every primordial capability. */
            for (;;) { __asm__ volatile("cli; hlt"); }
        }
        tasks[id].cspace = (struct capability *)cn;
    }
    tasks[id].cspace_size = CNODE_SIZE;

    /* Zero the entire cspace before installing initial capabilities.
     * kobj_alloc hands back zeroed memory, but task slots are reused: a dead
     * task's CAP_USER/CAP_CONSOLE/etc. would otherwise survive into the next task
     * spawned at the same index, granting it unearned authority. */
    for (int s = 0; s < CNODE_SIZE; s++) {
        tasks[id].cspace[s].type       = CAP_NULL;
        tasks[id].cspace[s].rights     = 0;
        tasks[id].cspace[s].object     = 0;
        tasks[id].cspace[s].badge      = 0;
        tasks[id].cspace[s].serial     = 0;
        tasks[id].cspace[s].generation = 0;
    }

    tasks[id].cspace[0].type   = CAP_TCB;
    tasks[id].cspace[0].rights = CAP_RIGHT_ALL;
    tasks[id].cspace[0].object = id;
    tasks[id].cspace[0].badge  = 0;
    tasks[id].cspace[0].serial = (0xB0000000U | ((uint32_t)id << 16) | 0U);
    /* Serial-keyed generation stamp (finding 3.3). These structured serials are
     * reused when a task slot is reused, so stamping the current cell value keeps
     * a reincarnated slot's capability valid even if the prior incarnation's
     * serial was revoked (bumped), rather than born stale. */
    tasks[id].cspace[0].generation = rust_lineage_current(tasks[id].cspace[0].serial);

    tasks[id].cspace[3].type   = CAP_FRAME;
    tasks[id].cspace[3].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC;
    tasks[id].cspace[3].object = USER_AREA_BASE;
    tasks[id].cspace[3].badge  = 0;
    tasks[id].cspace[3].serial = (0xB0000000U | ((uint32_t)id << 16) | 3U);
    tasks[id].cspace[3].generation = rust_lineage_current(tasks[id].cspace[3].serial);

    /* Slot 4: this task's PRIVATE reply endpoint, and the ONLY endpoint
     * capability a task is born with (audit finding C-1).
     *
     * Slots 4 and 5 used to hold ambient CAP_ENDPOINTs for objects 0 and 1, given
     * unconditionally to every task with READ|WRITE. Combined with the IPC
     * syscalls taking a raw object index rather than a slot, that meant authority
     * over an endpoint was universal: any task could receive on, send to, and
     * forge replies on any endpoint, including a server's. Both ambient grants are
     * gone. A task now reaches a service only via a capability something
     * DELEGATED to it (SYS_CAP_GRANT from its supervisor, or the connect path).
     *
     * The reply endpoint is per-task (reply_ep_for_task) and is what SYS_IPC_CALL
     * parks on. It is deliberately never handed to anyone else, so nothing can
     * intercept this task's replies or wake it spuriously. READ|WRITE: the task
     * receives its own replies (READ) and the kernel's delivery path is expressed
     * as a send (WRITE). */
    {
        int rep = reply_ep_for_task(id);
        if (rep >= 0) {
            tasks[id].cspace[4].type   = CAP_ENDPOINT;
            tasks[id].cspace[4].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
            tasks[id].cspace[4].object = (uint64_t)rep;
            tasks[id].cspace[4].badge  = 0;
            tasks[id].cspace[4].serial = (0xB0000000U | ((uint32_t)id << 16) | 4U);
            tasks[id].cspace[4].generation = rust_lineage_current(tasks[id].cspace[4].serial);
        }
    }

    
    if (id == 0) {
        tasks[id].cspace[8].type   = CAP_CONSOLE;
        tasks[id].cspace[8].rights = CAP_RIGHT_ALL;
        tasks[id].cspace[8].object = 0;
        tasks[id].cspace[8].badge  = 0;
        tasks[id].cspace[8].serial = 0xC0DE0008U;
        tasks[id].cspace[8].generation = 0;

        tasks[id].cspace[9].type   = CAP_ENCRYPTED_STORAGE;
        tasks[id].cspace[9].rights = CAP_RIGHT_ALL;
        tasks[id].cspace[9].object = 0;
        tasks[id].cspace[9].badge  = 0;
        tasks[id].cspace[9].serial = 0xC0DE0009U;
        tasks[id].cspace[9].generation = 0;
    }
}

void create_user_task(int id, addr_t entry, addr_t stack_top) {
    create_task(id, entry, stack_top, USER_AREA_BASE, 0);   /* flat: default premap */
}


/* ---- Direct-to-UART diagnostic output -------------------------------------
 *
 * Shared by the claim checker (SCHED_INVARIANTS) and the hang watchdog
 * (HANG_WATCHDOG). Deliberately NOT gated on SMP: the watchdog exists to
 * diagnose hangs, and one of the open ones (finding G-8 signature C) happens on
 * a UNIPROCESSOR boot, where every SMP diagnostic is inapplicable by
 * construction. */
/* ---- Panic output, straight to the UART -----------------------------------
 *
 * UNCONDITIONAL, and that is a change: these were compiled only under
 * SCHED_INVARIANTS / HANG_WATCHDOG / IRQ_POLICY_AUDIT. A kernel-mode trap
 * happens in the SHIP kernel and has to be able to speak, so the primitives it
 * reports through cannot be debug-build-only. A few dozen bytes of .text.
 *
 * NOT print(). Once a ring-3 console server owns the console, kernel print() is
 * suppressed, and while it is coming up both writers touch COM1 concurrently
 * from different CPUs. A panic emitted through print() therefore arrived
 * interleaved and truncated -- literally "PA[NIC: console_server] ready" -- so
 * the one message that has to survive was the one that did not. That reads as a
 * hang rather than a detected violation, which is precisely the confusion this
 * whole facility exists to remove.
 *
 * Everything below writes bytes to COM1 itself, with interrupts already off and
 * every other CPU about to be halted. It bypasses the console ownership rules
 * deliberately: there is no owner left to be polite to. */
static void panic_ch(char ch) {
    while ((inb(0x3FD) & 0x20) == 0) { }
    outb(0x3F8, (uint8_t)ch);
}

/* First CPU to detect a violation gets the UART; the rest halt silently.
 *
 * Not defensive tidiness — without it two cores that trip on the same tick
 * interleave byte-by-byte and the report comes out as
 * "PANICPANIC: : unbalanced impersostale scheduler claim...", i.e. neither
 * message is readable and the run looks like a garbled hang. That is the same
 * failure this facility was built to eliminate (see the note above on why it
 * writes to COM1 directly rather than through print()), reappearing one level up.
 * Observed during the falsification runs for the impersonation bracket. */
static volatile int panic_claimed = 0;
static void panic_begin(void) {
    if (__sync_lock_test_and_set(&panic_claimed, 1))
        for (;;) __asm__ volatile ("cli; hlt");   /* someone else is reporting */
}
static void panic_str(const char *s) { while (*s) panic_ch(*s++); }
static void panic_dec(int v) {
    char buf[12];
    int i = 0, neg = (v < 0);
    unsigned u = neg ? (unsigned)(-v) : (unsigned)v;
    if (!u) buf[i++] = '0';
    while (u) { buf[i++] = (char)('0' + (u % 10)); u /= 10; }
    if (neg) panic_ch('-');
    while (i) panic_ch(buf[--i]);
}
static void panic_hex64(uint64_t v) {
    panic_ch('0'); panic_ch('x');
    int sh = 60;
    while (sh > 0 && ((v >> sh) & 0xF) == 0) sh -= 4;   /* no leading zeroes */
    for (; sh >= 0; sh -= 4) {
        int n = (int)((v >> sh) & 0xF);
        panic_ch((char)(n < 10 ? '0' + n : 'a' + n - 10));
    }
}

/* ---- Kernel-fault reporting, for the trap paths in idt.c -------------------
 *
 * A trap taken at CPL 0 is a KERNEL defect, and every report of one went
 * through println(), which is klog-only once console_server owns the console.
 * So the reports were inaudible during a live session -- which is exactly when
 * these happen. G-8's supervisor fault tore down the ring-3 shell on every
 * occurrence and the only thing that ever reached the wire was init noticing
 * its child had gone; the address, the faulting rip and the error code, all of
 * which the kernel had in hand and printed, went to a buffer nobody reads.
 *
 * This is a second writer to a UART a ring-3 server owns (finding #126).
 * Deliberately, and only from these call sites: by the time one runs, the
 * kernel has trapped in its own code, there is no owner left worth being
 * polite to, and a report that loses a race with a shell prompt is not a
 * report. The panic paths already took this exception. A SURVIVABLE kernel
 * fault is not less worth hearing than a fatal one -- it is the one that hides.
 *
 * kfault_begin(0) is for a trap the kernel survives (it kills the current task
 * and carries on): it must be sayable again, so the claim is released, and the
 * wait for it is BOUNDED. panic_begin()'s permanent claim is right for a halt
 * and wrong here -- a diagnostic that can wedge a CPU is a worse defect than
 * the interleaved line it avoids. Past the budget we print anyway.
 *
 * kfault_begin(1) is for one it does not survive, and keeps the UART. */
static volatile int kfault_claim = 0;
void kfault_begin(int fatal) {
    if (fatal) panic_begin();       /* first CPU here reports, the rest halt */
    /* The fatal path takes the byte-stream claim too (and never releases it),
     * so a survivable report on another CPU waits its bounded turn rather than
     * interleaving into the last message the kernel will ever print. */
    for (int i = 0; i < 1000000; i++) {
        if (!__sync_lock_test_and_set(&kfault_claim, 1)) return;
        __asm__ volatile ("pause");
    }
}
void kfault_end(int fatal) {
    if (fatal) for (;;) __asm__ volatile ("cli; hlt");
    __sync_lock_release(&kfault_claim);
}

#ifdef RESUME_RSP_INJECT_PRECLAIM
/* Test-only. Reproduces the state a fatal exception on ANOTHER CPU leaves the
 * reporting facility in: panic_claimed taken and never released. Every later
 * report bracketed with fatal=1 then halts its CPU without emitting a byte,
 * which is precisely how the resume-%rsp floor guard came to be inaudible on
 * exactly the boots it existed to explain. Taking the claim here without the
 * halt lets one boot assert the fix. */
void kfault_claim_permanently_for_test(void) {
    __sync_lock_test_and_set(&panic_claimed, 1);
}
#endif

void kfault_str(const char *s) { panic_str(s); }
void kfault_hex(uint64_t v)    { panic_hex64(v); }
void kfault_dec(int v)         { panic_dec(v); }

/* A task name, bounded. tasks[].name is a fixed array and a torn-down or
 * never-started slot need not hold a terminator; a reporter must not be the
 * thing that runs off the end of .bss. */
void kfault_task(int t) {
    kfault_dec(t);
    if (t < 0 || t >= MAX_TASKS) return;
    panic_str(" '");
    for (unsigned i = 0; i < sizeof(tasks[t].name) && tasks[t].name[i]; i++)
        panic_ch(tasks[t].name[i]);
    panic_str("'");
}

/* #PF error bits, spelled out. "err=0x11" has cost this project a
 * symbolisation cycle more than once: it is present + instruction fetch at
 * CPL 0 -- the kernel executed a page marked NX -- which is an entirely
 * different diagnosis from the absent-page read that "err=0x0" is. */
void kfault_pf_err(uint64_t err) {
    panic_str((err & 0x1)  ? "present"  : "not-present");
    panic_str((err & 0x2)  ? ",write"   : ",read");
    panic_str((err & 0x4)  ? ",user"    : ",supervisor");
    if (err & 0x8)  panic_str(",reserved-bit");
    if (err & 0x10) panic_str(",exec");
}

/* The register line. rip and cs say whose code trapped; rsp and rbp say which
 * dereference did it. A supervisor fault on a small constant address is a
 * near-null base plus a struct offset, and the base is in one of those two far
 * more often than not -- printing them is what turns a capture into a site
 * instead of another reproduce-and-symbolise cycle. */
/* Who else thinks they are running this task, and what each CPU thinks it is
 * running. Printed only from a fault report, so it costs nothing on any healthy
 * path -- and it is the one observation that separates the leading hypothesis
 * from its alternatives.
 *
 * That hypothesis: two CPUs executing on ONE kernel stack. It accounts for both
 * open kernel-fault signatures at once. A #PF handler reading a frame whose rip
 * and err_code belong to a different trap (G-8's single datapoint) is what a
 * concurrent push by another CPU into the same frame looks like; and a trap
 * frame that iretq's into a kernel stack address (the fault holding roadmap
 * 1.1) is what one looks like once the corruption reaches the rip slot. The
 * invariant is task_running_cpu[t] == c <=> percpu_current_task[c] == t, and a
 * fault is exactly the moment to ask whether it still holds. */
void kfault_claims(int task) {
#ifdef SMP
    panic_str("\n  claim: task ");     panic_dec(task);
    panic_str(" running_cpu=");        panic_dec((task >= 0 && task < MAX_TASKS)
                                                 ? task_running_cpu[task] : -1);
    panic_str("  percpu_current=[");
    for (int c = 0; c < MAX_CPUS; c++) {
        if (c) panic_ch(',');
        panic_dec(percpu_current_task[c]);
    }
    panic_str("]  imp=[");
    for (int c = 0; c < MAX_CPUS; c++) {
        if (c) panic_ch(',');
        panic_dec(percpu_impersonating[c]);
    }
    panic_str("]");
#else
    (void)task;
#endif
}

void kfault_frame(const struct interrupt_frame64 *f) {
    if (!f) return;
    /* The frame's OWN account of what trapped, printed next to the values the
     * handler derived. They should agree; the one recorded G-8 datapoint says
     * they need not. Its rip symbolises -- in the CI binary that produced it --
     * to a `jne`, an instruction with no memory operand, which cannot raise a
     * #PF on a data address; and an IRQ frame carries err_code=0, exactly what
     * that report showed. So `vec` and `errc` here are the question "is this
     * frame even the frame of the fault being reported?", asked at the moment
     * it can still be answered. */
    panic_str("\n  vec=");  panic_dec((int)f->int_no);
    panic_str(" errc=");    panic_hex64(f->err_code);
    panic_str("\n  rip="); panic_hex64(f->rip);
    panic_str(" cs=");     panic_hex64(f->cs);
    panic_str(" rflags="); panic_hex64(f->rflags);
    panic_str("\n  rsp="); panic_hex64(f->rsp);
    panic_str(" rbp=");    panic_hex64(f->rbp);
    panic_str(" cpu=");    panic_dec(this_cpu());
}

#ifdef HANG_WATCHDOG
/* ---- Hang watchdog: turn a silent stall into a state dump -------------------
 *
 * Some self-tests print NOTHING between their last setup line and their single
 * PASS marker. `smoke-fs-conc` is the worst case: the four client tasks are
 * silent on the happy path, so a boot that wedges anywhere in the workload
 * produces a serial log identical to a boot that is merely slow, ending at
 * "[fs_server] filesystem provisioned" with 120 seconds of nothing after it.
 * That is finding G-8 signature C, and it is undiagnosable from the log alone --
 * there is no log.
 *
 * So once the deadline passes, dump what the scheduler can see: every live task,
 * whether it is runnable, whether it has a resumable context, and what it is
 * blocked on. That is enough to separate the cases that matter:
 *
 *   every task RUNNABLE, none blocked   -> nobody is stuck; the run was just slow
 *   a task BLOCKED_IPC with no peer     -> a lost wake / dropped reply
 *   a task RUNNABLE but not selectable  -> a scheduling bug (claim, ctx, ksp)
 *
 * Fires ONCE and lets the boot continue, deliberately. Halting would destroy the
 * distinction above by preventing a merely-slow run from going on to pass -- and
 * "it would have passed given another second" is exactly the hypothesis under
 * test. The harness still fails the boot on its own timeout; this only makes the
 * serial log say why.
 *
 * Compiled out by default; the ship kernel pays nothing. */
#ifndef HANG_WATCHDOG_TICKS
#define HANG_WATCHDOG_TICKS 4000       /* ~40s at 100Hz */
#endif
/* Dump more than once, spaced HANG_WATCHDOG_TICKS apart.
 *
 * One snapshot cannot tell a LIVELOCK (tasks running hard, state churning, no
 * forward progress) from a FROZEN state (nothing changing at all), and those have
 * different causes and different fixes. Successive dumps do: compare them. */
#ifndef HANG_WATCHDOG_DUMPS
#define HANG_WATCHDOG_DUMPS 3
#endif
static int watchdog_dumps = 0;

static void watchdog_dump(int seq) {
    panic_str("\n==== HANG WATCHDOG dump ");
    panic_dec(seq);
    panic_str("/");
    panic_dec((int)HANG_WATCHDOG_DUMPS);
    panic_str(" at tick ");
    panic_dec((int)system_ticks);
    panic_str(" ====\n");
#ifdef SMP
    for (int c = 0; c < MAX_CPUS; c++) {
        panic_str("cpu "); panic_dec(c);
        panic_str(": current="); panic_dec(percpu_current_task[c]);
        panic_str(" idle=");     panic_dec(percpu_idle[c]);
        panic_str(" imp=");      panic_dec(percpu_impersonating[c]);
        panic_str("\n");
    }
#else
    panic_str("uniprocessor; current="); panic_dec(current_task); panic_str("\n");
#endif
    for (int t = 0; t < MAX_TASKS; t++) {
        if (tasks[t].state == 0) continue;
        panic_str("task "); panic_dec(t);
        panic_str(" '");
        for (int k = 0; k < 16 && tasks[t].name[k]; k++) panic_ch(tasks[t].name[k]);
        panic_str("' state=");   panic_dec((int)tasks[t].state);
        panic_str(" rctx=");     panic_dec(tasks[t].runnable_ctx ? 1 : 0);
        panic_str(" ksp=");      panic_dec(tasks[t].saved_ksp ? 1 : 0);
        panic_str(" pblock=");   panic_dec((int)tasks[t].pending_block);
        panic_str(" blkon=");    panic_dec(tasks[t].blocked_on);
        panic_str(" waiter=");   panic_dec(tasks[t].waiter);
#ifdef SMP
        panic_str(" cpu=");      panic_dec(task_running_cpu[t]);
#endif
        /* Where the task is parked. For everything except the CPU's current task
         * this is the ring-3 rip its trap frame will resume at -- i.e. which spin
         * loop it is in. That is the difference between "all five tasks are
         * hammering the same endpoint" and "one of them is somewhere unexpected". */
        if (tasks[t].saved_ksp) {
            struct interrupt_frame64 *f =
                (struct interrupt_frame64 *)tasks[t].saved_ksp;
            panic_str(" rip=0x");
            for (int sh = 60; sh >= 0; sh -= 4) {
                int nyb = (int)((f->rip >> sh) & 0xF);
                panic_ch((char)(nyb < 10 ? '0' + nyb : 'a' + nyb - 10));
            }
        }
        panic_str("\n");
    }
    /* The endpoints themselves. The task table can look entirely healthy -- every
     * task RUNNABLE, nothing blocked -- while the thing they are all spinning on
     * is wedged, and that is exactly the state finding G-8 signature C reaches.
     * Only endpoints carrying state are printed; the rest are noise. */
    for (uint32_t i = 0; i < MAX_ENDPOINTS; i++) {
        struct endpoint *e = endpoint_by_index(i);
        if (!e) continue;
        /* Skip endpoints that have never carried traffic. NB the idle value here
         * is -1, not 0: an earlier version tested `last_sender == 0` and so
         * skipped nothing, printing all 128 and flushing the later dumps out of
         * the capture window. */
        if (e->count == 0 && e->blocked_waiter < 0 && e->last_sender <= 0) continue;
        panic_str("ep "); panic_dec((int)i);
        panic_str(": queued=");   panic_dec((int)e->count);
        panic_str("/");           panic_dec(EP_QUEUE_SLOTS);
        panic_str(" head=");      panic_dec((int)e->head);
        panic_str(" last=");      panic_dec(e->last_sender);
        panic_str(" blkwaiter="); panic_dec(e->blocked_waiter);
        /* Who is waiting in the ring, in service order. A full queue whose head
         * never advances is a stalled server; a queue that is always empty while
         * clients spin is the opposite problem. */
        for (uint32_t k = 0; k < e->count; k++) {
            struct ep_msg *m = &e->q[(e->head + k) % EP_QUEUE_SLOTS];
            panic_str(k ? "," : " senders=");
            panic_dec(m->sender);
        }
        panic_str("\n");
    }
    panic_str("==== END HANG WATCHDOG ====\n");
}
#endif /* HANG_WATCHDOG */

#ifdef IRQ_POLICY_AUDIT
void irq_policy_report_uart(const char *when);   /* defined below, next to spin_lock */
void irq_policy_totals_uart(const char *when);   /* likewise -- one line, no table */
/* Ticks between `periodic` reports; 0 = off, which is the DEFAULT and is exactly
 * the behaviour #124 shipped. Periodic reporting is opt-in because it is not free:
 * these lines go out of the timer ISR on the polled UART, into the same serial the
 * ring-3 console_server owns once the shell is up. Left on continuously it
 * perturbs the session it is measuring. Turn it on for a measurement run
 * (-DIRQ_POLICY_REPORT_EVERY=N), not for a gate. */
#ifndef IRQ_POLICY_REPORT_EVERY
#define IRQ_POLICY_REPORT_EVERY 0u
#endif

/* IRQ_POLICY_QUIET=1 suppresses every timer-driven report, leaving the counting
 * itself intact.
 *
 * These reports go out through panic_str -- straight at the UART, deliberately
 * bypassing the runtime suppression of print(). That suppression is not an
 * inconvenience to route around: it exists because ring-3 console_server owns the
 * serial line, and a second writer interleaves. The tick-41 report lands squarely
 * on the login prompt and splits it:
 *
 *     root@horus\n[irq-policy] handshake-early @tick=41: accidental_sti=96 ...
 *
 * so `root@horus#` never appears contiguously and any harness waiting for it
 * waits forever. The guest is fine; the observer is broken. Measured interleaved
 * against the ship kernel, adjacent boots: ship 0/10 failures, audit 10/10.
 * This is the `PA[NIC: console_server] ready` bug one level up.
 *
 * So: quiet for anything that drives the shell, loud for the boot-window gate
 * (smoke-irq-policy exits on its marker at tick 40 and never reaches a prompt). */
/* Default ON since roadmap 1.1 step 2b. The timer-driven reports were the only
 * way to read these counters when they were written, so they were on by default
 * and every session-scale measurement was taken through a corrupting instrument.
 * SYS_IRQ_POLICY_INFO replaced them with an in-band readout, so the async path
 * is now the exception: `make smoke-irq-policy` passes IRQ_POLICY_QUIET=0
 * because it is a boot-window gate that exits on its marker at tick 40 and never
 * reaches a prompt. Anything that drives a shell wants the default. */
#ifndef IRQ_POLICY_QUIET
#define IRQ_POLICY_QUIET 1
#endif

/* The `handshake-late` report at tick 200. 1 = as #124 shipped. This one lands
 * AFTER console_server has taken the serial line, which is the hypothesis under
 * test: set to 0 to keep only the tick-40 report (which fires while the kernel
 * still owns the console) and see whether the session failures go away. */
#ifndef IRQ_POLICY_REPORT_LATE
#define IRQ_POLICY_REPORT_LATE 1
#endif
#endif

void timer_handler(void) {
    system_ticks++;
#ifdef IRQ_POLICY_AUDIT
    /* Report at two points either side of the init -> fs_server -> console_server
     * -> shell handshake, which is the window roadmap 1.1 says depends on the
     * accidental sti. Straight to the UART: once console_server owns the console
     * the kernel's print() is suppressed, and a report nobody sees is no report.
     *
     * ...and then periodically for the rest of the boot, because the two fixed
     * points are NOT a session measurement and were mistaken for one. The
     * `handshake-early` snapshot at tick 40 covers boot only; roadmap 1.1 and
     * TESTS.md both attributed its numbers to "a scripted shell session", which
     * overstates how much of the system they had seen. The counts keep climbing
     * long after tick 200 -- the two IPC capability sites scale with message
     * traffic -- so a run has to say WHEN it was sampled for its numbers to mean
     * anything. `periodic` lines let the last one before shutdown stand as the
     * session total. */
    if (!IRQ_POLICY_QUIET) {
        static int rep = 0;
        static uint32_t next_periodic = 0;
        if ((rep == 0 && system_ticks > 40u) ||
            (IRQ_POLICY_REPORT_LATE && rep == 1 && system_ticks > 200u)) {
            rep++;
            irq_policy_report_uart(rep == 1 ? "handshake-early" : "handshake-late");
            if (rep == 1) { irq_milestone_report(); irq_policy_selftest(); }
            if (rep == 2) next_periodic = system_ticks + IRQ_POLICY_REPORT_EVERY;
        } else if (IRQ_POLICY_REPORT_EVERY && rep >= 2 && system_ticks >= next_periodic) {
            next_periodic = system_ticks + IRQ_POLICY_REPORT_EVERY;
            /* Totals only -- the per-site table is ~8 extra UART lines per report
             * and is what makes continuous reporting disturb the session. */
            irq_policy_totals_uart("periodic");
        }
    }
#endif
#ifdef HANG_WATCHDOG
    if (watchdog_dumps < HANG_WATCHDOG_DUMPS &&
        system_ticks > (uint32_t)HANG_WATCHDOG_TICKS * (uint32_t)(watchdog_dumps + 1)) {
        watchdog_dumps++;              /* bump FIRST: the dump is slow (polled UART) */
        watchdog_dump(watchdog_dumps);
    }
#endif
}

uint32_t get_system_ticks(void) {
    return system_ticks;
}

/* ----------------------------------------------------------------------------
 * Preemptive scheduling
 *
 * The timer ISR (idt.c, vector 32) calls preempt_on_tick() with the current
 * task's full trap frame. We switch tasks *only* when the tick interrupted
 * ring-3 code: at that instant the task holds no kernel spinlock (spin_lock
 * disables interrupts, so the timer can't fire inside a critical section) and
 * its entire state is captured by the trap frame the CPU + isr_common_stub64
 * pushed onto its per-task kernel stack. A tick that lands in ring 0 (mid
 * syscall / interrupt handler) is never a switch point -- we just tick and
 * return -- which keeps the kernel effectively non-preemptible and avoids all
 * reentrancy hazards. Switching is a pure kernel-%rsp swap: save the current
 * frame pointer, load the next task's, and let the ISR epilogue pop+iretq into
 * it. No spinlock is taken here (interrupts are already disabled in the gate).
 * ------------------------------------------------------------------------- */

static volatile int preempt_enabled = 0;

/* Arm the timer switch. Called once the boot path is past its delicate
 * single-threaded init and a user task is (about to be) running. Until then a
 * tick only advances system_ticks. */
void sched_enable_preemption(void) {
    preempt_enabled = 1;
}

/* Every task that can reach the scheduler has a stack: create_task binds task
 * 0's, and create_user_pagedir binds every other task's before it is runnable.
 * There used to be a fallback here that returned kernel_stacks[id] when
 * kernel_stack_top was 0 — unreachable for that reason, and dangerous if it
 * ever had fired, because it would have handed back a *different* stack from
 * the one the TSS RSP0 and the task's saved trap frame agree on. A scheduler
 * running a task on the wrong kernel stack is not something to paper over with
 * a plausible-looking address. */
static inline uint64_t task_kstack_top(int id) {
    if (!tasks[id].kernel_stack_top) {
        println("PANIC: task has no kernel stack");
        for (;;) __asm__ volatile ("cli; hlt");
    }
    return tasks[id].kernel_stack_top;
}

/* Fabricate an initial, resumable interrupt trap frame at the top of task
 * `id`'s kernel stack, so the timer switch can iretq into a freshly spawned
 * user task exactly as if it had just been preempted at its entry point. cs/ss
 * are the 64-bit user segments, IF is set so the task is itself preemptible,
 * and all GP registers start zeroed. */
void sched_prepare_user_context(int id, uint64_t entry, uint64_t user_rsp) {
    if (id < 0 || id >= MAX_TASKS) return;
    uint64_t top = task_kstack_top(id) & ~0xFULL;
    struct interrupt_frame64 *f =
        (struct interrupt_frame64 *)(top - sizeof(struct interrupt_frame64));

    f->r15 = f->r14 = f->r13 = f->r12 = f->r11 = f->r10 = f->r9 = f->r8 = 0;
    f->rbp = f->rdi = f->rsi = f->rdx = f->rcx = f->rbx = f->rax = 0;
    f->int_no   = 0;
    f->err_code = 0;
    f->rip      = entry;
    /* 64-bit user code (GDT 0x20 | RPL 3). Selector 0x20 already described a
     * 64-bit user code segment (L=1, D=0, DPL=3) long before anything used it,
     * so the ABI flip needs no GDT change -- only this selector. */
    f->cs       = 0x23;
    f->rflags   = 0x202;         /* IF set, reserved bit 1 */
    /* Enter the task's entry point under the SAME stack alignment a `call` would
     * have produced. The System V AMD64 ABI guarantees rsp+8 is 16-byte aligned
     * at a function's first instruction -- i.e. rsp % 16 == 8, because call just
     * pushed an 8-byte return address. Every _start here is an ordinary C
     * function, so GCC compiles it against that guarantee and freely emits
     * 16-byte SSE accesses (movaps) on stack slots it computed from entry rsp.
     *
     * iretq pushes no return address, so handing over a 16-byte-aligned rsp puts
     * every one of those slots 8 bytes out and the first movaps raises #GP. That
     * is not hypothetical: it is what this got wrong. Simple flat test binaries
     * never touch SSE and ran fine, while newlib faulted inside the first puts()
     * -- and because a ring-3 exception tears the task down silently, it looked
     * like a hang rather than a crash.
     *
     * Bias by 8 so the entry point sees what it was compiled to expect. */
    f->rsp      = (user_rsp & ~0xFULL) - 8;
    /* User data (GDT 0x30 | RPL 3). Unchanged: in long mode SS base/limit are
     * ignored, so the same descriptor serves both modes. */
    f->ss       = 0x33;

    tasks[id].saved_ksp     = (uint64_t)f;
    tasks[id].runnable_ctx  = 1;
}

#ifdef SMP
int this_cpu(void);   /* defined below */

/* Gate for cross-CPU task scheduling. APs come online and take timer ticks
 * immediately, but they only start *pulling runnable tasks* once the BSP has
 * populated the runnable pool and set this — which closes the window where an
 * AP could grab a task the BSP launched (via sched_enter_user) but not yet
 * claimed.
 *
 * Set by smp_bringup() once every AP is parked and the runnable pool is
 * consistent — i.e. it is 1 for the whole of a normal SMP boot, well before any
 * ring-3 task exists. (The SMP self-test sets it on its own path for the same
 * reason.) A previous version of this comment claimed "normal SMP boot leaves it
 * 0", which is the opposite of what smp.c does; that sent at least one
 * investigation of the console-smp hang down a blind alley before gdb showed the
 * flag set. Actual preemption still waits on `preempt_enabled`. */
volatile int smp_sched_enabled = 0;

/* Raw test-and-set on the scheduler lock for use *inside* an interrupt handler,
 * where IF is already clear (the gate is an interrupt gate): unlike spin_lock()
 * it must not touch IF, or the ISR epilogue's iretq would race a re-entry. */
static void sched_raw_lock(void) {
    while (__sync_lock_test_and_set(&scheduler_lock.locked, 1))
        while (scheduler_lock.locked) __asm__ volatile ("pause");
}
static void sched_raw_unlock(void) { __sync_lock_release(&scheduler_lock.locked); }

/* Record that this CPU is still executing ISR C frames on task `t`'s kernel
 * stack, so a second CPU entering an ISR for `t` is detected rather than silently
 * writing over them. Caller holds sched_raw_lock. */
static void sched_mark_kstack_inflight(int cpu, int t)
{
    if (cpu < 0 || cpu >= MAX_CPUS || t <= 0 || t >= MAX_TASKS) return;
    percpu_deferred_release[cpu] = t;
    __sync_fetch_and_or(&g_kstack_inflight, 1ULL << t);
}

/* Hand task `t` over from `cpu`. Caller holds sched_raw_lock. See the long note
 * at percpu_deferred_release[] for why this does not simply clear the claim. */
static void sched_release_outgoing(int cpu, int t)
{
    sched_mark_kstack_inflight(cpu, t);
#ifdef KSTACK_RELEASE_EARLY
    /* The defect: published as claimable while this CPU is still on its stack. */
    if (t > 0 && t < MAX_TASKS) task_running_cpu[t] = -1;
#endif
}

/* Called by isr_common_stub64 directly after `movq %rax,%rsp`, i.e. on the first
 * instruction at which this CPU is provably no longer reading the outgoing task's
 * stack.
 *
 * Interrupts are off here (every gate is an interrupt gate), so this cannot be
 * re-entered, and the frame it pushes goes below the INCOMING task's trap frame —
 * the same unused region the ISR's own C frames occupied on entry.
 *
 * The bit is cleared before the claim is dropped, never after: the other order
 * leaves a moment in which the task is claimable with its bit still set, so the
 * next CPU to pick it up would report a collision that had already ended.
 *
 * Both arms run this. Under KSTACK_RELEASE_EARLY the claim is already gone (or
 * already someone else's), which is what the `== cpu` test is for — so the two
 * arms differ only in WHEN the claim is dropped, and not in what the detector
 * sees. */
void sched_release_deferred(void)
{
    int cpu = this_cpu();
    if (cpu < 0 || cpu >= MAX_CPUS) return;
    int t = percpu_deferred_release[cpu];
    if (t < 0) return;                      /* the common case: no switch happened */
    percpu_deferred_release[cpu] = -1;
    __sync_fetch_and_and(&g_kstack_inflight, ~(1ULL << t));
    sched_raw_lock();
    if (t > 0 && t < MAX_TASKS && task_running_cpu[t] == cpu)
        task_running_cpu[t] = -1;
    sched_raw_unlock();
}

#ifdef KSTACK_RACE_WIDEN
/* Test-only. Holds this CPU inside the switch path AFTER the outgoing task has
 * been handed over and the scheduler lock dropped, but BEFORE the ISR epilogue
 * has left that task's kernel stack — i.e. it stretches the exact window this
 * file's deferred release closes, and nothing else.
 *
 * It exists because the window is otherwise a few tens of instructions wide and
 * only opens when a second CPU happens to tick into it, which is why G-8 read as
 * ~2-3% per boot and cost 150-boot arms to observe once. Widened, the same window
 * is entered on essentially every switch, so the two arms answer in one boot each
 * instead of in a week of soaks:
 *
 *   KSTACK_RACE_WIDEN=1                        -> the fix holds the claim across
 *                                                 the window; nothing can take the
 *                                                 stack; the session completes
 *   KSTACK_RACE_WIDEN=1 KSTACK_RELEASE_EARLY=1 -> the pre-fix release publishes it
 *                                                 mid-window; another CPU takes it
 *                                                 and the detector fires
 *
 * The delay is deliberately a dumb spin with interrupts already off rather than
 * anything clock-based: it must not itself take a lock, touch a task, or become a
 * scheduling event, or the arm would be measuring the instrument. Absent from
 * every shipping configuration; set by `make smoke-kstack-race*` and nothing
 * else. */
static void kstack_race_widen(int cpu)
{
    /* ---- Only SOME CPUs linger, and that is the whole trick -----------------
     *
     * The obvious widener -- spin on every switch -- is self-defeating, and it took
     * a measurement to see why. A collision needs CPU A to linger in the window on
     * task T's stack WHILE another CPU takes T, resumes it to ring 3 and lets it
     * trap. But the taker reaches this same point in this same function on its own
     * switch, so if it spins too it is always at least one full spin behind -- and
     * the collision it was supposed to cause is exactly what its own spin prevents.
     * Measured rather than reasoned after the fact: widening every switch
     * reproduced on only 2 boots in 7, and thinning it to one switch in 8 on 0 in 3.
     *
     * So the CPUs are split. A CPU in KSTACK_RACE_WIDEN_CPUMASK lingers; the rest
     * take and resume at full speed. The default 0x5 makes cpu 0 and cpu 2 the
     * lingerers and cpu 1 and cpu 3 the takers under the `-smp 4` the gate boots --
     * the arrangement the race actually needs, and about twice as fast as spinning
     * everywhere as a side effect.
     *
     * This tilts the ODDS of observing the window and nothing else. It does not
     * create a window, shorten a claim, or touch a task: the same build with the
     * deferred release in place lingers in exactly the same places and the takers
     * find nothing to take, which is what smoke-kstack-race asserts.
     *
     * The spin has to stay FULL WIDTH -- the taker needs time for a ~10 ms timer
     * tick, a selection and a resume into ring 3 -- which is why the count is not
     * simply lowered instead. A dumb spin with interrupts already off,
     * deliberately: it must not take a lock, touch a task, or become a scheduling
     * event, or the arm would be measuring the instrument. */
    if (cpu < 0 || !(((unsigned)KSTACK_RACE_WIDEN_CPUMASK >> cpu) & 1u)) return;
    for (volatile unsigned i = 0; i < (unsigned)KSTACK_RACE_WIDEN_SPINS; i++)
        __asm__ volatile ("pause");
}
#define KSTACK_WIDEN(cpu) kstack_race_widen(cpu)
#else
#define KSTACK_WIDEN(cpu) ((void)0)
#endif

/* ---- Where a CPU parks when the last task it was running dies ------------
 *
 * The fault/exit fallbacks in idt.c resume a CPU at resume_shell_after_fault()
 * when task_exit_switch() finds nothing else runnable. All three chose
 * tasks[0].kernel_stack_top for that, which is ONE stack shared by every CPU
 * that takes the path -- so two CPUs parking there are two CPUs executing ring-0
 * code, and taking timer ticks, on the same stack at the same addresses. That is
 * S20 again, in the one place the g_kstack_inflight bitmask cannot see it: that
 * detector is keyed on task ids and skips task 0, which is legitimately the
 * current task on several CPUs at once as the idle sentinel.
 *
 * This is the exact check instead. It is on the parking path only -- a cold path
 * reached when a task dies with nothing to run -- so it costs the hot path
 * nothing, and it names both CPUs and the stack rather than leaving a corrupted
 * resume %rsp to be symbolised later. */
static volatile uint64_t percpu_park_rsp[MAX_CPUS];

/* Clear this CPU's parked-stack record; it is taking a real task. Called from
 * set_current_task() for a non-idle task. */
static void sched_park_clear(int cpu)
{
    if (cpu >= 0 && cpu < MAX_CPUS) percpu_park_rsp[cpu] = 0;
}

/* Record that this CPU is about to park at ring 0 on `rsp`, and fail closed if
 * another CPU is already parked on the same stack. */
void sched_note_park(uint64_t rsp)
{
    int cpu = this_cpu();
    if (cpu < 0 || cpu >= MAX_CPUS || !rsp) return;

    for (int c = 0; c < MAX_CPUS; c++) {
        if (c == cpu) continue;
        if (percpu_park_rsp[c] != rsp) continue;

        /* Two CPUs about to idle on one kernel stack. Neither has corrupted
         * anything yet -- both are heading for `sti; hlt` -- but the first timer
         * tick on each pushes a trap frame at the same address, and from there it
         * is the same failure as G-8 with none of its rarity. Report under the
         * BOUNDED claim (see the note at kfault_begin) and halt. */
        kfault_begin(0);
        kfault_str("\nPANIC: two CPUs parking on one kernel stack rsp=");
        kfault_hex(rsp);
        kfault_str(" this-cpu=");    kfault_dec(cpu);
        kfault_str(" already-cpu="); kfault_dec(c);
        kfault_str(" task=");        kfault_task(get_current_task());
        kfault_claims(get_current_task());
        kfault_str("\nKERNEL FATAL SHARED PARK STACK - halting\n");
        kfault_end(0);
        for (;;) __asm__ volatile ("cli; hlt");
    }
    percpu_park_rsp[cpu] = rsp;
}

/* Which CPU is still unwinding off task `t`, or -1. Failure path only. */
int sched_kstack_holder(int t)
{
    for (int c = 0; c < MAX_CPUS; c++)
        if (percpu_deferred_release[c] == t) return c;
    return -1;
}
#endif

/* Async signal delivery. When a ring-3 task is about to resume, redirect it into
 * its registered handler if SYS_SIGNAL queued one. The lowest-numbered *unmasked*
 * pending signal is delivered; masked signals stay queued until SYS_SIGMASK
 * unblocks them. Reuses the fault-signal path: try_deliver_fault_signal rewrites
 * the trap frame to enter the handler (signal number in ebx) and saves the
 * pre-signal frame for SYS_SIGRETURN. Left pending if the task is already inside a
 * handler (delivered after it returns; the in_signal guard lives in that helper). */
extern int try_deliver_fault_signal(struct interrupt_frame64 *frame, int cur,
                                    uint32_t signum, uint64_t fault_addr);
static void deliver_pending_signal(uint64_t frame_ptr, int tid) {
    if (tid <= 0 || tid >= MAX_TASKS) return;
    uint32_t deliverable = tasks[tid].pending_sigs & ~tasks[tid].sig_mask;
    if (deliverable == 0) return;
    struct interrupt_frame64 *f = (struct interrupt_frame64 *)frame_ptr;
    if ((f->cs & 3) != 3) return;   /* only into a ring-3 frame */
    uint32_t sig = (uint32_t)__builtin_ctz(deliverable);   /* lowest pending signal (1..31) */
    if (try_deliver_fault_signal(f, tid, sig, 0)) {
        tasks[tid].pending_sigs &= ~(1u << sig);
    }
}


#if defined(SMP) && defined(SCHED_INVARIANTS)
/* ---- Machine-checked claim invariant (SCHED_INVARIANTS=1 builds only) -------
 *
 * Asserts, in both directions:
 *
 *     task_running_cpu[t] == c   <=>   percpu_current_task[c] == t     (t > 0)
 *
 * This exists because the failure mode of a violated claim invariant is a silent
 * livelock forty seconds and several thousand timer ticks after the mistake, with
 * every task still marked RUNNABLE and nothing in the log. Diagnosing one
 * instance of that took a gdb stub, a custom kernel with counters, and eighteen
 * QEMU boots. This turns the same defect into an immediate panic naming the task,
 * the CPU, and the code path -- an intermittent hang becomes an attributable
 * failure.
 *
 * The caller must hold sched_raw_lock, so the snapshot is quiescent: every path
 * that mutates a claim does so under that lock, and each leaves the invariant
 * true at its exit even though it is transiently false in the middle (between
 * releasing the outgoing task and claiming the incoming one).
 *
 * Compiled out entirely by default -- the ship kernel pays nothing -- and turned
 * on for the SMP jobs in CI, which is where the races actually occur. */
/* Two-strike state: the (task, cpu) pair flagged by the previous audit, or -1. */
static int sched_susp_task = -1;
static int sched_susp_cpu  = -1;


/* Report and halt. Split out so both directions read identically. */
static void sched_claim_panic(const char *what, const char *where,
                              int t, int c, int seen) {
    panic_begin();
    panic_str("\nPANIC: "); panic_str(what);
    panic_str(" at "); panic_str(where);
    panic_str(": task "); panic_dec(t);
    panic_str(" claimed by cpu "); panic_dec(c);
    panic_str(" but that cpu was running "); panic_dec(seen);
    panic_str(" (persisted across two audits; observed by cpu ");
    panic_dec(this_cpu());
    panic_str(")\n");
    for (;;) __asm__ volatile ("cli; hlt");
}

/* An enter() with no matching exit() would reroute every later audit of this CPU
 * through a percpu_real_task[] that stopped being true long ago -- i.e. it would
 * turn the mechanism that keeps the checker honest into the thing blinding it.
 * So the bracket is itself checked: see the ring-3 assertion in preempt_on_tick. */
static void sched_bracket_panic(const char *where, int cpu, int depth, int real) {
    panic_begin();
    panic_str("\nPANIC: unbalanced impersonation bracket at "); panic_str(where);
    panic_str(": cpu "); panic_dec(cpu);
    panic_str(" reached ring 3 at depth "); panic_dec(depth);
    panic_str(" (still claiming to run task "); panic_dec(real);
    panic_str("; an enter() lost its exit())\n");
    for (;;) __asm__ volatile ("cli; hlt");
}

/* What CPU `c` is REALLY running, which is what the invariant is stated over.
 *
 * Normally percpu_current_task[c]. Inside a declared impersonation window it is
 * percpu_real_task[c] instead — see the note at the top of this file. Returning
 * the real task rather than skipping the CPU is what keeps the audit continuous
 * across a spawn, which is both the longest window and the one a genuine leak
 * would be easiest to hide in.
 *
 * Returns -1 for "cannot tell, do not judge": the two variables are written on
 * the other CPU without a lock, so an auditor can land between the depth
 * increment and the snapshot. That is a mid-flight read of a correct kernel, not
 * a violation, and callers skip it. The two-strike rule covers the rest: the
 * window is a handful of instructions and cannot repeat 10 ms later. */
static int sched_running_on(int c) {
    int d = percpu_impersonating[c];
    __sync_synchronize();
    if (d == 0) return percpu_current_task[c];
    int r = percpu_real_task[c];
    return (r < 0) ? -1 : r;
}

static void sched_assert_claims(const char *where) {
    /* ---- Why this takes TWO strikes -------------------------------------
     *
     * A momentarily inconsistent pair is not a bug. Not every writer of
     * task_running_cpu[] holds the scheduler lock -- task_teardown releases a
     * claim from syscall and fault context without it -- so an auditor on
     * another core can catch a genuine, harmless mid-flight update. Panicking on
     * that would make the checker cry wolf on correct code, which is worse than
     * having no checker: it trains you to disbelieve it.
     *
     * The failure this exists to catch is a claim that is stuck FOREVER. So the
     * first sighting of an inconsistent pair only arms a suspicion; it must still
     * be true at the next audit -- a different tick, ~10ms later at 100Hz, an
     * eternity next to the microseconds any real switch takes -- before it counts.
     *
     * An earlier version panicked on first sight and reported failures on a
     * kernel that was in fact correct. */
    /* -> A claim must be held by a CPU that is really running that task. A stale
     *    claim makes the task unschedulable by EVERY CPU, including the holder. */
    /* ---- Dead tasks are exempt ------------------------------------------
     *
     * task_teardown() releases the claim, but the CPU that was running the task
     * keeps naming it in percpu_current_task[] until task_exit_switch() runs --
     * and in between it does real work, including a full capability-graph sweep
     * (kobj_gc). That window is long enough to span several audits, so it would
     * otherwise be reported as persistent.
     *
     * Exempting dead tasks costs nothing, because the property being protected is
     * "a RUNNABLE task must remain selectable". Selection requires state == 1, so
     * a dead task can never be the subject of the livelock this guards against.
     */
    /* ---- The deferred release is a claim with no runner, and it is correct ----
     *
     * Since [G-8], a switch path holds the outgoing task's claim until the CPU has
     * left that task's kernel stack (see percpu_deferred_release[]). Inside that
     * window -- tens of instructions, but `enter_cpu_idle` audits from inside it --
     * task_running_cpu[t] names a CPU that is deliberately no longer running t.
     * That is the property being enforced, not a leak.
     *
     * Encoded here rather than left to the two-strike timing argument. The window
     * is far too short to survive to a second audit, so it would almost certainly
     * never panic -- but "almost certainly never" is how a checker earns a
     * reputation for crying wolf, and this file already records what that cost:
     * a correct kernel accused of a capability leak, blocking a roadmap item for a
     * fortnight. A documented exception belongs in the checker. */
    for (int t = 1; t < MAX_TASKS; t++) {
        if (tasks[t].state == 0) continue;
        int c = task_running_cpu[t];
        if (c < 0) continue;
        if (percpu_deferred_release[c] == t) continue;   /* still unwinding off it */
        if (c >= MAX_CPUS) {
            print("PANIC: scheduler claim names a bogus cpu at "); print(where);
            print(": task "); print_decimal((uint64_t)t);
            print(" claimed by cpu "); print_decimal((uint64_t)c); println("");
            for (;;) __asm__ volatile ("cli; hlt");
        }
        /* Snapshot the value actually compared and report THAT. Re-reading it for
         * the message lets a concurrent update make the panic text
         * self-contradictory ("task 1 claimed by cpu 0 which is running 1") --
         * which an earlier version printed, and which sends you hunting for the
         * wrong bug. */
        int seen = sched_running_on(c);
        if (seen < 0) continue;                 /* mid-flight; see sched_running_on */
        if (seen != t) {
            if (sched_susp_task == t && sched_susp_cpu == c)
                sched_claim_panic("stale scheduler claim", where, t, c, seen);
            sched_susp_task = t;      /* first sighting: arm, do not accuse */
            sched_susp_cpu  = c;
            return;
        }
    }
    /* <- A task a CPU is running must be claimed by it, or a second CPU can
     *    select it and two cores execute one kernel stack concurrently. */
    for (int c = 0; c < MAX_CPUS; c++) {
        int t = sched_running_on(c);            /* the real task; see above */
        if (t <= 0 || t >= MAX_TASKS) continue;
        if (tasks[t].state == 0) continue;      /* teardown window; see above */
        int seen = task_running_cpu[t];         /* snapshot; see above */
        if (seen != c) {
            if (sched_susp_task == t && sched_susp_cpu == c)
                sched_claim_panic("unclaimed running task", where, t, c, seen);
            sched_susp_task = t;
            sched_susp_cpu  = c;
            return;
        }
    }
    /* Fully consistent: drop any armed suspicion. */
    sched_susp_task = -1;
    sched_susp_cpu  = -1;
}
#else
#define sched_assert_claims(where) ((void)0)
#endif

/* Called from the timer ISR. Returns the kernel %rsp the ISR epilogue should
 * resume on: the same frame when we don't switch, or the next task's saved
 * frame when we do. */
/* ---- the resume %rsp is validated where it is PRODUCED -- finding [G-9] -----
 *
 * interrupt_handler64 already refuses a bogus resume value and reports it
 * (idt.c, resume_rsp_is_bogus). That is a CONSUMER-side check: it knows the
 * value and the CPU, and nothing about where the value came from. The open
 * residue of [G-9] is a `-7` handed back by the dispatcher, and the reason it is
 * still open is exactly that nobody knows which switch function produced it.
 *
 * All four switch functions end in the same three lines -- take
 * tasks[next].saved_ksp, drop the scheduler lock, return it -- and every one of
 * their selection loops requires saved_ksp to be merely NON-ZERO. `-7` is
 * non-zero. So each of them checks the value before handing it back:
 *
 *   - the report NAMES the producer, so the next reproduction is a fact rather
 *     than a mystery. Same move that made the last [G-9] progress: bounding the
 *     consumer-side guard at both ends turned an obscure fault inside the ISR
 *     epilogue into a line naming the value, the task and the CPU;
 *   - the caller gets 0 instead of garbage. Every caller already treats 0 as
 *     "nothing runnable" and parks this CPU on its own ring-0 stack, which is
 *     survivable. iretq onto `-7` is not.
 *
 * Reported through kfault_str() for the reason the fault banner uses it: print()
 * is klog-only once console_server owns the console, and a live session is the
 * only place this has ever been seen.
 *
 * This does NOT claim to fix [G-9]. It converts an unexplained crash into a named
 * refusal and narrows the search to whichever producer the report names -- or, if
 * the workload still fails while this stays silent, rules all four out and points
 * at the remaining producers (exec_reenter_switch, the page-fault path). Either
 * answer is progress; today there is neither. */
static int ksp_is_bogus(uint64_t ksp)
{
    extern uint8_t __bss_start[], __bss_end[];
    if (ksp >= (uint64_t)(uintptr_t)__bss_start &&
        ksp <  (uint64_t)(uintptr_t)__bss_end)
        return 0;
    extern uint8_t ist1_stack_guard[], ist3_stack_top[];
    if (ksp >= (uint64_t)(uintptr_t)ist1_stack_guard &&
        ksp <  (uint64_t)(uintptr_t)ist3_stack_top)
        return 0;
    return 1;
}

/* Report and refuse. Returns 0 so the caller takes its "nothing runnable" path.
 * `who` is the producing function; `t` the task whose saved_ksp it is. */
static uint64_t ksp_refuse(const char *who, int t, uint64_t ksp)
{
    kfault_begin(0);
    kfault_str("\nSCHED BOGUS KSP from "); kfault_str(who);
    kfault_str(" task=");  kfault_dec(t);
    kfault_str(" ksp=");   kfault_hex(ksp);
    kfault_str(" cpu=");   kfault_dec(this_cpu());
    kfault_str(" -- refusing, parking this CPU instead\n");
    kfault_end(0);
    return 0;
}

uint64_t preempt_on_tick(uint64_t frame_rsp, uint64_t interrupted_cs) {
    if (!preempt_enabled) return frame_rsp;
#ifndef SMP
    if ((interrupted_cs & 3) != 3) return frame_rsp;   /* only preempt ring 3 */

    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) return frame_rsp;

    /* Deliver any signal queued for the running task before it resumes. */
    deliver_pending_signal(frame_rsp, cur);

    /* Round-robin: the next runnable user task (id != 0) with a resumable
     * context. */
    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (cur + i) % MAX_TASKS;
        if (cand == 0 || cand == cur) continue;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 && tasks[cand].runnable_ctx
            && tasks[cand].saved_ksp) {
            next = cand;
            break;
        }
    }
    if (next < 0) return frame_rsp;   /* nobody else runnable -> keep running */

    /* Save the outgoing task's frame, install the incoming task's address
     * space + kernel stack, and hand its saved frame back to the ISR epilogue.
     * Kernel stacks and the task array live in the shared kernel mapping that
     * is present in every address space, so this stays valid across switch_cr3
     * even though we are still executing on the outgoing task's kernel stack. */
    tasks[cur].saved_ksp    = frame_rsp;
    tasks[cur].runnable_ctx = 1;

    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    current_kernel_stack_top = kstop;
    set_current_task(next);
    return tasks[next].saved_ksp;
#else
    /* SMP: any CPU may run any task, so selection + claim is serialised under the
     * scheduler lock and a task is only ever taken when task_running_cpu[] shows
     * it running nowhere. The shared runnable pool + this per-CPU pull is the
     * load-balancing mechanism: an idle AP grabs whatever work is available. The
     * BSP (cpu 0) is never pulled out of its ring-0 idle/kernel context by the
     * timer -- only its ring-3 tasks are preempted -- which preserves the exact
     * single-CPU boot flow; the APs do the multi-core work. */
    int cpu = this_cpu();
    if (!smp_sched_enabled) return frame_rsp;
    int ring3 = ((interrupted_cs & 3) == 3);
#ifdef SCHED_INVARIANTS
    /* Balance check for the impersonation bracket, and the reason the bracket can
     * be trusted as an audit input rather than merely believed. A CPU executing
     * ring-3 code is definitionally not inside one -- every window is opened and
     * closed within a single ring-0 syscall -- so a non-zero depth here is an
     * enter() that lost its exit(). Free, exact, and checked on every ring-3 tick.
     * Deliberately placed BEFORE the ring-0 guard's early return, which is the
     * only path out of this function that skips the audit. */
    if (ring3 && cpu >= 0 && cpu < MAX_CPUS && percpu_impersonating[cpu] != 0)
        sched_bracket_panic("preempt_on_tick", cpu, percpu_impersonating[cpu],
                            percpu_real_task[cpu]);
#endif
    /* ---- Never switch a CPU away from a live ring-0 context -----------------
     *
     * This path can save exactly one thing: a ring-3 trap frame. It has no way to
     * preserve an in-flight KERNEL context — the C call stack a syscall is
     * executing on, and any lock it holds. So a CPU may only be switched away
     * when it is either in ring 3 (frame saveable, below) or parked in an idle
     * loop (nothing to save).
     *
     * This guard used to apply to `cpu == 0` only, on the stated reasoning that
     * "syscalls run with interrupts cleared, so a ring-0 tick never lands
     * mid-syscall". That reasoning does not hold: spin_unlock() ends with an
     * UNCONDITIONAL `sti` once the nesting depth reaches zero (finding C-3.1), so
     * the first lock a syscall takes and releases re-enables interrupts for the
     * rest of that syscall. A timer tick then lands in ring 0 with a live task,
     * and on an AP the old guard let it through.
     *
     * What followed was the smoke-console-smp hang. The tick would select another
     * task and switch to it, but the save-and-release block below is gated on
     * `ring3`, so the abandoned task was never released: task_running_cpu[cur]
     * stayed pointing at this CPU forever. Every selection loop skips a claimed
     * candidate, so that task — still RUNNABLE, still holding a valid frame —
     * became unschedulable by every CPU in the system, including this one. The
     * observed end state was a livelock: timer ticking, tasks spin-yielding, one
     * task stranded, and in the worst capture a single CPU holding claims on
     * three different tasks it was not running.
     *
     * Note the leaked claim was the SYMPTOM. Underneath it, a syscall had been
     * abandoned mid-flight with its kernel stack discarded — and because
     * `tasks[cur].saved_ksp` still held the stale ring-3 frame from its last
     * save, "fixing" the leak by clearing the claim would have resumed the task
     * from that stale frame, silently dropping the syscall's work and any lock it
     * still held. The leak was masking a memory-safety bug rather than causing
     * one. That is why this is fixed here, at the abandonment, and not by
     * scrubbing the claim afterwards.
     *
     * Applying the guard to every CPU is also what the BSP already relied on, so
     * this removes a special case rather than adding one. `percpu_idle` is set by
     * enter_cpu_idle() and by an AP parking at bringup (smp.c), and cleared by
     * set_current_task() the moment a CPU takes a real task. */
    if (!ring3 && !percpu_idle[cpu]) return frame_rsp;

    sched_raw_lock();

    /* Periodic system-wide audit of the claim invariant. One call site covers
     * every path that can violate it, because a leak left behind anywhere is
     * observed by the next tick on any CPU — within ~10ms at 100Hz — rather than
     * forty seconds later as an unexplained hang. Placed before the defensive
     * claim below so that claim cannot paper over a violation it did not cause.
     * Compiled out unless SCHED_INVARIANTS=1. */
    sched_assert_claims("preempt_on_tick");

    int cur = percpu_current_task[cpu];

    /* Defensively claim the task we are currently running, so another CPU cannot
     * grab a task that was launched onto this CPU outside the timer path. */
    if (cur > 0 && cur < MAX_TASKS && task_running_cpu[cur] < 0)
        task_running_cpu[cur] = cpu;

    /* Deliver any signal queued for the task running here before it resumes —
     * the SMP twin of the non-SMP branch above. Without this, a signal sent
     * (e.g. by SYS_KILL from another CPU) to a task blocked-then-woken or spinning
     * in ring 3 would never enter its handler under SMP. The frame is rewritten in
     * place, so both the save-and-switch and the no-switch return below carry the
     * redirected frame. Safe under the raw lock: the delivery helper takes no lock
     * and touches only tasks[cur] plus this CPU's own frame. */
    if (ring3 && cur > 0 && cur < MAX_TASKS)
        deliver_pending_signal(frame_rsp, cur);

    int next = -1;
    for (int i = 1; i <= MAX_TASKS; i++) {
        int cand = (cur + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 &&
            tasks[cand].runnable_ctx && tasks[cand].saved_ksp && task_running_cpu[cand] < 0) {
            next = cand;
            break;
        }
    }
    if (next < 0) { sched_raw_unlock(); return frame_rsp; }   /* keep running cur */

    /* Save + release the outgoing task if it was a real user task in ring 3. A
     * ring-0 (idle) context is stateless and simply abandoned. */
    if (cur > 0 && cur < MAX_TASKS && ring3) {
        tasks[cur].saved_ksp    = frame_rsp;
        tasks[cur].runnable_ctx = 1;
        sched_release_outgoing(cpu, cur);
    }

    task_running_cpu[next] = cpu;
    smp_cpus_ran_tasks |= (1u << cpu);
    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    if (cpu == 0) current_kernel_stack_top = kstop;
    set_current_task(next);
    uint64_t ksp = tasks[next].saved_ksp;
    sched_raw_unlock();
    KSTACK_WIDEN(cpu);
    /* The selection loop only required saved_ksp to be NON-ZERO, which
     * rejects a cleared slot and nothing else. `-7` is non-zero. */
    if (ksp_is_bogus(ksp)) return ksp_refuse("preempt_on_tick", next, ksp);
    return ksp;
#endif
}

#ifdef SMP
extern uint8_t *ap_idle_stack_top(int cpu);   /* smp.c */
extern void ap_idle_loop(void);               /* smp.c */

/* Return this CPU to its idle loop, leaving no task current on it. Used when a
 * task blocks (IPC/wait/notif) but no other task is runnable here: under SMP the
 * awaited wake arrives from another core, so this CPU must idle and let a timer
 * tick reschedule the woken task — it must NOT fabricate a reply by resuming the
 * blocked caller with an unfilled buffer (which split typed console lines and made
 * logins fail intermittently under SMP). Fabricates the same ring-0 trap frame the
 * ISR epilogue expects, on this CPU's idle stack, resuming at ap_idle_loop with
 * interrupts enabled. Caller holds sched_raw_lock and must publish the blocked task
 * as schedulable (task_running_cpu = -1) before calling. */
/* NB: this deliberately does NOT sweep task_running_cpu[] for claims held by the
 * parking CPU, though an earlier draft did. Clearing a stale claim makes its task
 * schedulable again — and a claim is stale precisely when its task was abandoned,
 * so the task then resumes from a stale trap frame, discarding kernel work that
 * may include a held lock. Measured, not theorised: adding that sweep took the
 * pinned stress harness from 24/24 to 13/20. See the note at task_running_cpu[];
 * a stale claim is a symptom to diagnose, never a value to correct. */
static uint64_t enter_cpu_idle(int cpu) {
    uint8_t *top = ap_idle_stack_top(cpu);
    struct interrupt_frame64 *f =
        (struct interrupt_frame64 *)(void *)(top - sizeof(struct interrupt_frame64));
    f->r15 = f->r14 = f->r13 = f->r12 = f->r11 = f->r10 = f->r9 = f->r8 = 0;
    f->rbp = f->rdi = f->rsi = f->rdx = f->rcx = f->rbx = f->rax = 0;
    f->int_no = 0;
    f->err_code = 0;
    f->rip    = (uint64_t)(uintptr_t)ap_idle_loop;
    f->cs     = 0x08;
    f->rflags = 0x202;                 /* IF=1: idle with interrupts on */
    f->rsp    = (uint64_t)(uintptr_t)top;
    f->ss     = 0x10;
    percpu_current_task[cpu] = 0;       /* this CPU now idle (no task) */
    percpu_idle[cpu] = 1;               /* ...and parked in ap_idle_loop */
    if (cpu == 0) current_task = 0;
    sched_assert_claims("enter_cpu_idle");
    return (uint64_t)(uintptr_t)f;
}
#endif

/* Block/switch with the concurrent-IPC publish order:
 *
 *   1. Write saved_ksp (the live trap frame) first.
 *   2. Full barrier so other CPUs observe the frame before the waiter.
 *   3. Publish the block (endpoint blocked_waiter / wait link / notif waiter
 *      + TASK_BLOCKED_* state) via ipc_publish_pending_block.
 *   4. Only then switch away.
 *
 * The previous order set BLOCKED + waiter in the syscall handler and saved the
 * frame only here — a reply on another CPU could patch a stale/null saved_ksp.
 * Syscall handlers now only set pending_block (+ object fields); this path
 * owns both the save and the publish. */
uint64_t ipc_block_switch(int blocked_task, uint64_t frame_rsp) {
    if (blocked_task <= 0 || blocked_task >= MAX_TASKS) return frame_rsp;

    /* (1) Frame first — wakers must never see a published waiter without this. */
    tasks[blocked_task].saved_ksp = frame_rsp;
    __sync_synchronize();

    /* (2) Publish waiter / BLOCKED state (or complete if already satisfied). */
    int must_switch = 1;
    if (tasks[blocked_task].pending_block != 0) {
        must_switch = ipc_publish_pending_block(blocked_task);
    } else {
        /* Legacy path: already in BLOCKED_* (should not happen for new code). */
        tasks[blocked_task].runnable_ctx = 0;
    }
    if (!must_switch) {
        /* Wait already satisfied with a valid frame; resume the same task. */
        return frame_rsp;
    }

#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
    sched_release_outgoing(cpu, blocked_task);   /* blocking: release it, once off its stack */

    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (blocked_task + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == TASK_RUNNABLE && tasks[cand].cr3 != 0 &&
                tasks[cand].runnable_ctx && tasks[cand].saved_ksp && task_running_cpu[cand] < 0) {
            next = cand;
            break;
        }
    }
    if (next < 0) {
        /* No task to switch to on this CPU. blocked_task stays genuinely blocked
         * and becomes schedulable by any CPU as soon as this CPU is off its kernel
         * stack -- sched_release_outgoing above deferred the release to the ISR
         * epilogue rather than doing it here, which is [G-8]; return
         * this CPU to idle so a timer tick reschedules the woken task once its
         * cross-core reply lands. Resuming the caller here instead — the old
         * single-CPU fallback — fabricated a zero-length reply into its unfilled
         * buffer, which under SMP split console input and broke logins. */
        uint64_t idle = enter_cpu_idle(cpu);
        sched_raw_unlock();
        KSTACK_WIDEN(cpu);
        return idle;
    }

    task_running_cpu[next] = cpu;
    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    if (cpu == 0) current_kernel_stack_top = kstop;
    set_current_task(next);
    uint64_t ksp = tasks[next].saved_ksp;
    sched_raw_unlock();
    KSTACK_WIDEN(cpu);
    /* The selection loop only required saved_ksp to be NON-ZERO, which
     * rejects a cleared slot and nothing else. `-7` is non-zero. */
    if (ksp_is_bogus(ksp)) return ksp_refuse("ipc_block_switch", next, ksp);
    return ksp;
#else
    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (blocked_task + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == TASK_RUNNABLE && tasks[cand].cr3 != 0 &&
                tasks[cand].runnable_ctx && tasks[cand].saved_ksp) {
            next = cand;
            break;
        }
    }
    if (next < 0) {
        ipc_unpublish_block(blocked_task);
        return frame_rsp;
    }

    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    current_kernel_stack_top = kstop;
    set_current_task(next);

    return tasks[next].saved_ksp;
#endif
}


void print_boot_timestamp(void) {
    uint32_t ms = system_ticks;
    uint32_t sec = ms / 1000;
    uint32_t frac = ms % 1000;

    print("[ ");
    if (sec < 10) print("   ");
    else if (sec < 100) print("  ");
    else if (sec < 1000) print(" ");
    print_decimal(sec);
    print(".");
    if (frac < 10) print("00");
    else if (frac < 100) print("0");
    print_decimal(frac);
    print(" ] ");
}

/* ---- x87/SSE context ---------------------------------------------------
 *
 * The kernel itself is built -mno-sse -mno-mmx -mno-80387 and so never touches
 * these registers; they belong entirely to ring 3, and the only job here is to
 * stop one task's register file leaking into (or being clobbered by) another's.
 * FXSAVE/FXRSTOR are inline asm precisely because the compiler is not allowed to
 * emit SSE -- the flags bind codegen, not the assembler.
 *
 * CR4.OSFXSR is already set by the boot path (multiboot.S), which is what makes
 * both these instructions and ring-3 SSE legal in the first place. */
static uint8_t g_fpu_template[512] __attribute__((aligned(16)));

/* The register file a brand-new task starts with: x87 reset, MXCSR at its
 * architectural default (0x1F80 = all SIMD exceptions masked). A zeroed FXSAVE
 * image would be wrong -- MXCSR=0 unmasks every SIMD exception, so the first
 * ring-3 divide would trap. */
void fpu_init_template(void) {
    uint32_t mxcsr = 0x1F80;
    __asm__ volatile ("fninit");
    __asm__ volatile ("ldmxcsr %0" :: "m"(mxcsr));
    __asm__ volatile ("fxsave (%0)" :: "r"(g_fpu_template) : "memory");
}

void fpu_task_init(int id) {
    if (id < 0 || id >= MAX_TASKS) return;
    for (int i = 0; i < 512; i++) tasks[id].fpu_state[i] = g_fpu_template[i];
}

void fpu_save(int id) {
    if (id <= 0 || id >= MAX_TASKS) return;
    __asm__ volatile ("fxsave (%0)" :: "r"(tasks[id].fpu_state) : "memory");
}

void fpu_restore(int id) {
    if (id <= 0 || id >= MAX_TASKS) return;
    __asm__ volatile ("fxrstor (%0)" :: "r"(tasks[id].fpu_state) : "memory");
}

/* Request a voluntary yield from a syscall handler. interrupt_handler64 sees
 * g_want_yield matching the caller and performs sched_yield_switch on the live
 * trap frame — the same full-context path as preemption and blocking IPC.
 * Never switches from mid-kernel cooperative code (that path is gone). */
volatile int g_want_yield = -1;

void yield(void) {
    g_want_yield = get_current_task();
}

/* Idle the current CPU. The only way between tasks is the full-context path
 * (timer preemption, ipc_block_switch, sched_yield_switch, sched_enter_user). */
void __attribute__((noreturn)) kernel_idle(void) {
#ifdef SMP
    /* Declare this CPU parked before looping. It is reached when a task exits or
     * faults and nothing else is runnable (task_exit_switch returned 0, so the
     * fault path resumed here on task 0's stack), which leaves
     * percpu_current_task[] still naming the DEAD task and percpu_idle clear —
     * i.e. the CPU describing itself as busy with a task that no longer exists.
     *
     * That matters because preempt_on_tick only lets a ring-0 tick switch an
     * IDLE CPU away. Without this, a CPU that reaped the last runnable task would
     * sit in this loop declining every tick, and would never pick up work again
     * even once another CPU made a task runnable. This loop holds no state — it
     * is `sti; hlt` — so it is exactly the context a tick may abandon.
     *
     * NB the DEBUG_SHELL build's resume_shell_after_fault runs the interactive
     * in-kernel shell instead of calling this, and so stays correctly marked
     * busy: real kernel work must not be abandoned. */
    int cpu = this_cpu();
    if (cpu >= 0 && cpu < MAX_CPUS) {
        percpu_current_task[cpu] = 0;
        percpu_idle[cpu]         = 1;
    }
    if (cpu == 0) current_task = 0;
#endif
    for (;;) __asm__ volatile ("sti; hlt");
}

/* Enter a task that already has a fabricated/saved full trap frame
 * (sched_prepare_user_context / do_spawn). Installs CR3, TSS RSP0, and current
 * task, then runs the same pop+iretq epilogue as isr_common_stub64 so first
 * entry matches every later resume. Does not return. */
void __attribute__((noreturn)) sched_enter_user(int tid) {
    if (tid <= 0 || tid >= MAX_TASKS ||
        !tasks[tid].runnable_ctx || !tasks[tid].saved_ksp || !tasks[tid].cr3) {
        kernel_idle();
    }

#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
    task_running_cpu[tid] = cpu;
#endif
    switch_cr3(tasks[tid].cr3);
    uint64_t kstop = task_kstack_top(tid);
    set_tss_kernel_stack(kstop);
#ifdef SMP
    if (cpu == 0) current_kernel_stack_top = kstop;
#else
    current_kernel_stack_top = kstop;
#endif
    set_current_task(tid);
    /* First entry does not come through interrupt_handler64, so load this task's
     * register file here -- otherwise it would start on whatever the previous
     * task left in xmm. */
    fpu_restore(tid);
    uint64_t ksp = tasks[tid].saved_ksp;
#ifdef SMP
    sched_raw_unlock();
#endif

    /* Mirror isr_common_stub64's epilogue: load the saved frame as %rsp first
     * (before clobbering any GPRs with segment selectors), set user data
     * segments, pop GPRs, skip int_no/err_code, iretq into ring 3. */
    __asm__ volatile (
        "mov %0, %%rsp\n\t"
        "mov $0x33, %%ax\n\t"
        "mov %%ax, %%ds\n\t"
        "mov %%ax, %%es\n\t"
        "mov %%ax, %%fs\n\t"
        "mov %%ax, %%gs\n\t"
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "popq %%r13\n\t"
        "popq %%r12\n\t"
        "popq %%r11\n\t"
        "popq %%r10\n\t"
        "popq %%r9\n\t"
        "popq %%r8\n\t"
        "popq %%rbp\n\t"
        "popq %%rdi\n\t"
        "popq %%rsi\n\t"
        "popq %%rdx\n\t"
        "popq %%rcx\n\t"
        "popq %%rbx\n\t"
        "popq %%rax\n\t"
        "addq $16, %%rsp\n\t"
        "iretq\n\t"
        :: "r"(ksp) : "memory", "cc", "rax"
    );
    __builtin_unreachable();
}

/* Voluntary yield with a live trap frame (SYS_YIELD). Save the caller's frame
 * and switch to another runnable user task if one exists; otherwise resume the
 * same frame. Returns the kernel %rsp for the ISR epilogue. */
uint64_t sched_yield_switch(int cur, uint64_t frame_rsp) {
    if (cur <= 0 || cur >= MAX_TASKS) return frame_rsp;

#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
#endif
    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (cur + i) % MAX_TASKS;
        if (cand == 0 || cand == cur) continue;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 &&
            tasks[cand].runnable_ctx && tasks[cand].saved_ksp
#ifdef SMP
            && task_running_cpu[cand] < 0
#endif
           ) {
            next = cand;
            break;
        }
    }
    if (next < 0) {
#ifdef SMP
        sched_raw_unlock();
#endif
        return frame_rsp;
    }

    tasks[cur].saved_ksp    = frame_rsp;
    tasks[cur].runnable_ctx = 1;
#ifdef SMP
    sched_release_outgoing(cpu, cur);
    task_running_cpu[next]  = cpu;
#endif
    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
#ifdef SMP
    if (cpu == 0) current_kernel_stack_top = kstop;
#else
    current_kernel_stack_top = kstop;
#endif
    set_current_task(next);
    uint64_t ksp = tasks[next].saved_ksp;
#ifdef SMP
    sched_raw_unlock();
    KSTACK_WIDEN(cpu);
#endif
    /* The selection loop only required saved_ksp to be NON-ZERO, which
     * rejects a cleared slot and nothing else. `-7` is non-zero. */
    if (ksp_is_bogus(ksp)) return ksp_refuse("sched_yield_switch", next, ksp);
    return ksp;
}

/* Terminate task `id`: wake a SYS_WAIT waiter blocked on it, drop its signal
 * handler, mark it dead, and (SMP) release its running-CPU guard so no core will
 * reselect it. The caller (SYS_EXIT / SYS_KILL) is responsible for switching the
 * CPU away from the task if it happens to be the one currently running. */
void task_teardown(int id, const struct task_exit_cause *cause) {
    if (id <= 0 || id >= MAX_TASKS) return;

    /* Record the cause BEFORE anything else can fail or switch away: this is the
     * only account of why the task died, and the paths that reach here (a ring-3
     * #PF among them) have nowhere else to report from — kernel print() stops
     * reaching the wire once console_server owns the console. */
    struct task_exit_info *rec = &tasks[id].exit_info;
    rec->tid    = id;
    rec->reason = cause ? (int32_t)cause->reason : TASK_EXIT_NONE;
    rec->detail = cause ? cause->detail : 0;
    rec->err    = cause ? cause->err    : 0;
    rec->rip    = cause ? cause->rip    : 0;
    rec->addr   = cause ? cause->addr   : 0;
    /* Copy the name now: the slot is reusable the moment state hits 0, and the
     * supervisor's whole question is *which* task this was. */
    int n = 0;
    for (; n < 31 && tasks[id].name[n]; n++) rec->name[n] = tasks[id].name[n];
    rec->name[n] = 0;

    /* Drop any IRQ->notification routing this task registered, so a hardware IRQ
     * cannot keep notifying a dead task's slot. */
    irq_notify_clear_task(id);

    /* Revoke native port I/O: task slots are reused without being zeroed (do_spawn
     * only re-inits selected fields), and io_allowed is otherwise never cleared, so
     * a fresh task could inherit a dead driver's port grant. Clearing it here also
     * releases the console back to the kernel if this was the console owner, so the
     * shell's in-kernel console fallback works again after a console_server crash. */
    tasks[id].io_allowed = 0;
    console_clear_owner(id);

    /* Release any pipe ends this task still holds so the peer sees EOF/EPIPE and
     * the pipe is freed — a pipeline stage that exits (cleanly or on a fault)
     * must not wedge the stage on the other side. */
    pipe_close_task_ends(id);

    int w = tasks[id].waiter;
    if (w >= 0 && w < MAX_TASKS) {
        /* Unblock a SYS_WAIT waiter: make it runnable and resumable so the
         * scheduler resumes it via the trap frame ipc_block_switch saved when it
         * blocked (it returns from SYS_WAIT with eax already 0). */
        if (tasks[w].state == TASK_BLOCKED_WAIT) {
            /* Hand the cause to the supervisor along with the wake. The waiter
             * resumes straight through iretq with no kernel code running on its
             * behalf, so there is no later point at which it could be delivered
             * — and by the time the waiter runs, this slot may already belong to
             * its replacement. */
            tasks[w].wait_exit_info = tasks[id].exit_info;
            tasks[w].state        = TASK_RUNNABLE;
            tasks[w].runnable_ctx = 1;
        }
        tasks[id].waiter = -1;
    }

    tasks[id].sig_handler = 0;
    tasks[id].in_signal   = 0;
    tasks[id].sig_altstack_sp   = 0;   /* clear so a reused slot never inherits a stale altstack */
    tasks[id].sig_altstack_size = 0;
    tasks[id].sig_on_stack      = 0;
    tasks[id].state       = 0;   /* dead: the scheduler will not select it */
    tasks[id].runnable_ctx = 0;  /* and it has no resumable context any more */
    tasks[id].saved_ksp    = 0;
#ifdef SMP
    task_running_cpu[id]  = -1;  /* release the SMP mutual-exclusion guard */
#endif

    /* A dead task's capabilities stop counting: its cspace is no longer swept by
     * revocation and nothing in it can be used again. So this is the other point
     * at which a retyped kernel object can lose its last name, and the sweep has
     * to run here too — otherwise an object created by a task that then exited
     * would live until some unrelated task happened to revoke something.
     *
     * Ordering matters: state is already 0 above, so the sweep correctly treats
     * this task's cspace as unreachable.
     *
     * Safe to call with interrupts masked — task_teardown is reached from the
     * page-fault handler (idt.c), and it is the first thing on that path to take
     * a lock at all. That is a property of spin_unlock itself since roadmap 1.1:
     * it restores the caller's RFLAGS.IF instead of asserting `sti` (C-3.1), so
     * a fault handler cannot have interrupts enabled underneath it by taking a
     * lock. Until 2026-08-18 it was instead a property of a pushfq/popfq bracket
     * inside untyped.c, which is why that bracket is gone -- see the locking note
     * at the top of that file. */
    kobj_gc();
}

/* Switch away from a task that has just terminated (SYS_EXIT / SYS_KILL-self),
 * called from interrupt_handler64 with the dead task's trap frame. The dead
 * frame is abandoned (not saved); we resume the next runnable task via its saved
 * trap frame — the same iretq mechanism the timer and blocking IPC use — and
 * return its kernel %rsp for the ISR epilogue. Returns 0 if nothing else is
 * runnable, so the caller can fall back to the kernel idle/reaper. */
uint64_t task_exit_switch(int dead) {
#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
#endif
    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (dead + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 && tasks[cand].runnable_ctx
            && tasks[cand].saved_ksp
#ifdef SMP
            && task_running_cpu[cand] < 0
#endif
           ) { next = cand; break; }
    }
    if (next < 0) {
#ifdef SMP
        /* Deliberately does NOT mark this CPU idle here, though an earlier draft
         * did. The caller still has kernel work to finish (it returns through the
         * fault/exit path before reaching kernel_idle), and percpu_idle is exactly
         * the flag that permits a ring-0 tick to switch a CPU away — so setting it
         * this early re-opens the abandonment window the ring-0 preemption guard
         * closes. Measured: it cost 7 failures in 20 on the pinned stress harness.
         * kernel_idle() sets it at the point the CPU genuinely has nothing left to
         * do, which is the correct place. */
        sched_raw_unlock();
#endif
        return 0;   /* nothing else to run — caller idles */
    }
#ifdef SMP
    task_running_cpu[next] = cpu;
    /* `dead` has no claim left to defer -- task_teardown dropped it and no
     * selection loop looks at a task in state 0 -- but this CPU is still unwinding
     * off its kernel stack, and the SLOT is now free for init to respawn into.
     * per_task_kstacks[] is indexed by slot, so a reused slot is the same stack:
     * marking it keeps the detector honest on the respawn path (signature A's
     * "init: shell exited, relaunching") without changing any behaviour, since
     * sched_release_deferred's `== cpu` test finds nothing to release. */
    sched_mark_kstack_inflight(cpu, dead);
#endif
    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
#ifdef SMP
    if (cpu == 0) current_kernel_stack_top = kstop;
#else
    current_kernel_stack_top = kstop;
#endif
    set_current_task(next);
    uint64_t ksp = tasks[next].saved_ksp;
#ifdef SMP
    sched_raw_unlock();
    KSTACK_WIDEN(cpu);
#endif
    /* The selection loop only required saved_ksp to be NON-ZERO, which
     * rejects a cleared slot and nothing else. `-7` is non-zero. */
#ifdef KSP_GUARD_INJECT
    /* Control arm: forge exactly the value [G-9] was seen to hand back, on the
     * producer the PROC_SELFTEST workload drives. Never a shipping config. */
    ksp = (uint64_t)-7;
#endif
    if (ksp_is_bogus(ksp)) return ksp_refuse("task_exit_switch", next, ksp);
    return ksp;
}

/* Enter task `t` via the fresh ring-3 context sched_prepare_user_context just
 * fabricated for it — used by SYS_EXEC_NAMED, which replaced the task's image in
 * place. Mirrors task_exit_switch's tail (install the address space + kernel
 * stack, hand the saved frame to the ISR epilogue) but re-enters the *same* task
 * rather than switching away. Returns the kernel %rsp for the ISR epilogue. */
uint64_t exec_reenter_switch(int t) {
    if (t <= 0 || t >= MAX_TASKS) return 0;
#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
#ifdef SCHED_INVARIANTS
    /* ---- The exec hand-off belongs to THIS cpu -- finding [G-9] -------------
     *
     * This function re-enters the SAME task the caller was already running: it
     * claims `t`, installs its CR3 and hands the ISR epilogue the frame that the
     * exec tail fabricated at the top of t's kernel stack. It has no outgoing
     * task to release, because there is not supposed to be one.
     *
     * That held only as long as the hand-off could not be taken by the wrong
     * core. It was a single global `g_exec_reenter_task` consumed on the exit of
     * every syscall on every CPU, so an exec armed on one core was routinely
     * consumed by another -- which then claimed the exec'ing task (leaking
     * whatever it had been running, since there is no release here) and resumed
     * that task's freshly built trap frame while the core that ran the exec was
     * still executing on it. One race, all three [G-9] signatures.
     *
     * The storage is per-CPU now (kspawn.c), so this is a property rather than a
     * hope -- and one comparison is cheap enough to keep asserting it. */
    if (percpu_current_task[cpu] != t) {
        panic_begin();
        panic_str("\nPANIC: exec re-entry taken by the wrong cpu: cpu ");
        panic_dec(cpu);
        panic_str(" is running task ");   panic_dec(percpu_current_task[cpu]);
        panic_str(" but re-entered task "); panic_dec(t);
        panic_str(" (the per-CPU exec hand-off has been shared again; see [G-9])\n");
        for (;;) __asm__ volatile ("cli; hlt");
    }
#endif
    task_running_cpu[t] = cpu;
#endif
    switch_cr3(tasks[t].cr3);
    uint64_t kstop = task_kstack_top(t);
    set_tss_kernel_stack(kstop);
#ifdef SMP
    if (cpu == 0) current_kernel_stack_top = kstop;
#else
    current_kernel_stack_top = kstop;
#endif
    set_current_task(t);
    uint64_t ksp = tasks[t].saved_ksp;
#ifdef SMP
    sched_raw_unlock();
#endif
    return ksp;
}

/* ---- Which CPU am I? -------------------------------------------------------
 *
 * get_current_task() calls this, and get_current_task() is the kernel's "who is
 * the subject" accessor: ~110 call sites across capability.c, syscall*.c,
 * paging.c, kaudit.c, storage.c and the fault handlers, several per syscall. So
 * whatever this function costs, the syscall path pays a multiple of it.
 *
 * It used to cost an uncached LAPIC MMIO read (finding [I-6]): hundreds of
 * cycles on a UC mapping, and by a wide margin the dominant avoidable cost in
 * the syscall path.
 *
 * Two observations remove it.
 *
 * 1. In a single-CPU build (SMP=0, e.g. MINIMAL_SECURE) there is exactly one CPU
 *    and its id is 0 by construction: scheduler_init seeds
 *    percpu_current_task[0], and set_current_task mirrors into current_task only
 *    for c == 0. There, the MMIO read was answering a question that had a
 *    compile-time answer. (The shipped default is SMP=1, so the STR path below
 *    is the one that actually runs.)
 *
 * 2. Under SMP the CPU already carries its own identity in a register. Every CPU
 *    ltr's a DIFFERENT TSS -- it has to, because RSP0 and the IST stacks are
 *    loaded from the running CPU's TSS on a ring-3 -> ring-0 transition (see
 *    gdt.c). Those selectors are laid out linearly: 0x38 for the BSP
 *    (multiboot.S: setup_tss64) and 0x48/0x58/0x68 for APs 1..3 (gdt.c:
 *    ap_tss_selector = 0x48 + (cpu-1)*16). So `str` -- a register read, no
 *    memory reference, no serialisation -- plus a subtract and a shift IS the
 *    CPU id. TR is written once per CPU at bringup and never again, so the
 *    answer cannot go stale mid-syscall.
 *
 * Why not the `%gs`-based per-CPU block the roadmap sketches (F-1.1)? Because
 * getting the per-CPU base to survive a ring transition requires `swapgs` in
 * every ISR entry and exit -- the ring-3 return paths in this file and in
 * drop_to_ring3() load 0x33 into %gs, and loading a selector into %gs ZEROES the
 * GS base in long mode, so a base installed without swapgs does not survive the
 * first return to ring 3. Adding swapgs means a CS-conditional swap on every
 * entry (exceptions can arrive from ring 0), matching swaps on every exit
 * including the epilogue that iretq's into a DIFFERENT task's frame, and the
 * NMI/IST re-entrancy hazard that has produced a long line of CVEs in kernels
 * with more reviewers than this one. STR gets essentially the same win for none
 * of that risk, and does not preclude doing %gs later.
 *
 * UMIP (CR4.11, set in cpu_enable_protections) blocks STR at CPL 3 only; this
 * runs at CPL 0.
 *
 * Selector of CPU c's TSS: 0x38 + c*0x10. Keep in sync with setup_tss64
 * (src/boot/multiboot.S) and ap_tss_selector() (src/kernel/gdt.c); the
 * PERCPU_SELFTEST cross-checks the mapping against the LAPIC on every CPU that
 * comes online, so a divergence here is caught rather than assumed away. */
#define TSS_SEL_CPU0   0x38u
#define TSS_SEL_STRIDE 0x10u

/* The original LAPIC-MMIO derivation. Still the bootstrap answer -- an AP has
 * TR == 0 until setup_ap_tss() ltr's its TSS, and ap_entry64() must know which
 * CPU it is in order to pick that TSS -- and still the independent oracle the
 * self-test falsifies the fast path against. */
int this_cpu_lapic(void) {
    volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
    uint32_t id_reg = lapic[0x20 / 4];
    uint32_t cpu = (id_reg >> 24) & 0xFF;
    if (cpu >= MAX_CPUS) cpu = 0;
    return (int)cpu;
}

int this_cpu(void) {
#ifndef SMP
    /* One CPU, and the rest of this file already indexes it as 0. */
    return 0;
#else
    uint16_t tr;
    __asm__ volatile ("str %0" : "=r"(tr));

    /* TR carries no RPL/TI of its own, but mask rather than trust that. */
    unsigned sel = (unsigned)tr & 0xFFF8u;
    if (sel >= TSS_SEL_CPU0) {
        unsigned d = sel - TSS_SEL_CPU0;
        if ((d % TSS_SEL_STRIDE) == 0) {
            unsigned c = d / TSS_SEL_STRIDE;
            if (c < MAX_CPUS) return (int)c;
        }
    }

    /* No TSS loaded yet (early AP bringup) or an unrecognised selector: fall
     * back rather than guess. Wrong here is a CPU running another CPU's task. */
    return this_cpu_lapic();
#endif
}

#ifdef SMP
/* Bit c set once CPU c has, running on itself, confirmed that its STR-derived id
 * matches the LAPIC's. Read by PERCPU_SELFTEST, which needs a witness that the
 * agreement was established on every core rather than inferred on one. */
volatile unsigned percpu_id_verified = 0;

/* Cross-check the TSS-selector derivation against the LAPIC, on this CPU, once,
 * at the point its TSS is loaded.
 *
 * This is the falsifiable half of the STR fast path: the mapping 0x38 + c*0x10
 * is a claim about two files this one does not include (multiboot.S's
 * setup_tss64 and gdt.c's ap_tss_selector), and a claim about a layout a future
 * GDT edit could silently break. If either moves, every get_current_task() on
 * that CPU starts naming another CPU's task -- one core reading and writing
 * another's current-task slot, which is the claim invariant violated from a
 * direction no scheduler assertion watches.
 *
 * So this fails closed rather than degrading: a mismatch means the derivation is
 * unsound on this hardware, and continuing means silently misattributing every
 * subsequent syscall. Not gated behind a self-test flag -- it runs once per CPU
 * at bringup, costs one MMIO read, and the failure it catches is not one to ship
 * unchecked. */
void percpu_id_verify_self(void) {
    uint16_t tr;
    __asm__ volatile ("str %0" : "=r"(tr));

    int from_tss   = this_cpu();
    int from_lapic = this_cpu_lapic();

    if (from_tss != from_lapic || from_tss < 0 || from_tss >= MAX_CPUS) {
        print("PANIC: per-CPU id mismatch: TR=");
        print_hex((uint32_t)tr);
        print(" str-derived=");
        print_decimal(from_tss);
        print(" lapic=");
        print_decimal(from_lapic);
        print(" -- TSS selector layout disagrees with gdt.c/multiboot.S\n");
        for (;;) __asm__ volatile ("cli; hlt");
    }

    __sync_fetch_and_or(&percpu_id_verified, 1u << (unsigned)from_tss);
}
#endif /* SMP */

int get_current_task(void) {
    int c = this_cpu();
    if (c < 0 || c >= MAX_CPUS) c = 0;
    return percpu_current_task[c];
}

/* The flush-on-switch policy predicate (exposed for FLUSH_SELFTEST): a flush is
 * due when the CPU is about to resume a ring-3 task (`next` >= 1) different from
 * the `prev` user task it last ran. Switches to the kernel idle task (next <= 0)
 * and same-task resumes do not flush. Pure — no side effects. */
int sched_domain_switch_would_flush(int prev_user_task, int next_task) {
    return next_task > 0 && next_task < MAX_TASKS && prev_user_task != next_task;
}

void set_current_task(int v) {
    int c = this_cpu();
    if (c < 0 || c >= MAX_CPUS) c = 0;

    /* Flush-on-switch: evict the microarchitectural state (indirect-branch
     * predictor, L1D cache, store/fill/load buffers) an incoming ring-3 task
     * could use to snoop the outgoing one on this logical CPU, whenever the CPU is
     * about to resume a DIFFERENT ring-3 task. This is the single switch
     * chokepoint — set_current_task(v) is called exactly when the CPU is about to
     * resume v — so hooking here covers every switch path (timer preemption, IPC
     * block, yield, first entry) with none able to bypass it. Same-task resumes
     * and switches to the kernel idle task (v <= 0) skip it; the barriers are
     * gated on detected CPU support, so it is a no-op where unavailable. It does
     * NOT cover a sibling SMT thread running concurrently on the same core — see
     * docs/LIMITATIONS.md (disable SMT / core-schedule for that). */
    if (sched_domain_switch_would_flush(percpu_last_user_task[c], v)) {
        percpu_last_user_task[c] = v;
        cpu_flush_microarch_state();
    }

    /* Taking a real task means this CPU is no longer parked in the ring-0 idle
     * loop, so its parked-stack record stops being true. Leaving it set would
     * make the next CPU to park there report a collision that had already ended
     * -- the same stale-bit mistake sched_release_deferred() avoids by clearing
     * before it releases. */
#ifdef SMP
    if (v > 0) sched_park_clear(c);
#endif

    percpu_current_task[c] = v;
#ifdef SMP
    if (v > 0) percpu_idle[c] = 0;   /* running a real task: no longer idle-parked */
#endif

    if (c == 0) current_task = v;

    /* Single switch chokepoint: point this CPU's TSS I/O bitmap at the active
     * bitmap only for a task holding a port-I/O grant; every other task gets
     * iomap_base past the limit, so a ring-3 in/out #GPs. */
    tss_set_io_allowed(v > 0 && v < MAX_TASKS && tasks[v].io_allowed);
}

/* Open/close a declared impersonation window: see the long note on
 * percpu_real_task[] at the top of this file.
 *
 * Call enter() BEFORE the set_current_task() that installs the impersonated
 * identity — it snapshots the task the CPU is really running — and exit() AFTER
 * the set_current_task() that restores it. Both must run on the same CPU, which
 * the ring-0 preemption guard guarantees.
 *
 * No-ops without SMP, where there is no other core to observe the window. */
void sched_impersonate_enter(void) {
#ifdef SMP
    int c = this_cpu();
    if (c < 0 || c >= MAX_CPUS) return;
    if (percpu_impersonating[c] == 0)
        percpu_real_task[c] = percpu_current_task[c];
    percpu_impersonating[c]++;
    __sync_synchronize();
#endif
}

void sched_impersonate_exit(void) {
#ifdef SMP
    __sync_synchronize();
    int c = this_cpu();
    if (c < 0 || c >= MAX_CPUS) return;
    if (percpu_impersonating[c] > 0 && --percpu_impersonating[c] == 0)
        percpu_real_task[c] = -1;
#endif
}

void scheduler_lock_acquire(void) { spin_lock(&scheduler_lock); }
void scheduler_lock_release(void) { spin_unlock(&scheduler_lock); }



#ifdef IRQ_LEGACY_GLOBAL_LOCK
/* The defect itself: one nesting depth for the whole machine, non-atomic
 * (**[C-3]**). Only the legacy control-arm build still has it. */
static volatile int irq_lock_depth = 0;
#endif

#ifdef IRQ_POLICY_AUDIT
/* ---- Measuring the accidental `sti` (roadmap 1.1 step 1) -------------------
 *
 * spin_unlock re-enables interrupts unconditionally when the nesting depth
 * reaches zero -- even when the caller had masked them itself and merely happened
 * to take a lock inside its own `cli` region. Boot and early init take many such
 * locks, so interrupts come on earlier and more often than any stated policy asks
 * for, and the init -> fs_server -> console_server -> shell handshake has come to
 * depend on the timer preemption that results. That is finding C-3.1, and it is
 * why the obvious per-CPU IF-preserving lock was written, passed every local
 * gate, and still broke the ring-3 startup handshake in CI.
 *
 * The roadmap's step 1 is "find every window relying on the accidental sti". This
 * measures it instead of reasoning about it: record IF as the OUTERMOST lock is
 * taken, and count the releases that would flip interrupts from off to on against
 * the caller's own intent. Those, and only those, are the load-bearing ones -- a
 * release that restores IF=1 to a caller who already had IF=1 changes nothing.
 *
 * Observation only: the `sti` still fires exactly as before, so this build boots
 * identically to the ship kernel. NB irq_lock_depth is a non-atomic global (that
 * is part of the defect), so under SMP these counts are indicative, not exact --
 * which is itself worth knowing before anyone quotes them as a spec. */
#ifdef IRQ_LEGACY_GLOBAL_LOCK
static volatile int      irq_outer_if = 1;   /* IF when the outermost lock was taken */
#endif
/* Releases where the caller's own IF was CLEAR. The legacy lock turns each of
 * these into an `sti` the caller never asked for (accidental); the per-CPU lock
 * suppresses each one (suppressed). Same predicate, same workload, so the two
 * counts are directly comparable across the two builds -- which is exactly the
 * evidence that the fix removes those enablements and only those. */
volatile unsigned        irq_accidental_sti = 0;
volatile unsigned        irq_suppressed_sti = 0;
volatile unsigned        irq_benign_sti     = 0;
#define IRQ_SITE_SLOTS 12
/* The readout struct mirrors this width; drift would silently truncate the
 * table the whole finding is stated over. */
_Static_assert(IRQ_SITE_SLOTS == IRQ_POLICY_SITE_SLOTS,
               "IRQ_SITE_SLOTS and IRQ_POLICY_SITE_SLOTS must agree");
volatile uint64_t        irq_accidental_site[IRQ_SITE_SLOTS];
volatile unsigned        irq_accidental_hits[IRQ_SITE_SLOTS];
volatile unsigned        irq_site_count = 0;

static void irq_record_site(uint64_t ra) {
    for (unsigned i = 0; i < irq_site_count && i < IRQ_SITE_SLOTS; i++) {
        if (irq_accidental_site[i] == ra) { irq_accidental_hits[i]++; return; }
    }
    if (irq_site_count < IRQ_SITE_SLOTS) {
        irq_accidental_site[irq_site_count] = ra;
        irq_accidental_hits[irq_site_count] = 1;
        irq_site_count++;
    }
}
#endif /* IRQ_POLICY_AUDIT */

#ifdef IRQ_POLICY_AUDIT
/* ---- Boot-milestone IF state (roadmap 1.1 step 2) --------------------------
 *
 * The kernel's boot-time interrupt enablement is currently an EMERGENT property
 * of a locking defect rather than a stated design: spin_unlock's unconditional
 * `sti` turns interrupts on as a side effect of the first lock any syscall takes
 * (see the audit above). Roadmap 1.1 step 2 asks for a self-test asserting IF at
 * the boot milestones "so the dependency cannot silently return".
 *
 * This records IF at named points. The expected values are NOT invented -- they
 * are what the kernel actually does today, measured and then written down, so the
 * test's job is to notice when that changes. Encoding a policy nobody has
 * implemented would make it fail on a correct kernel, which is the failure mode
 * TESTS.md keeps warning about. */
#define IRQ_MILESTONES 8
struct irq_milestone { const char *name; int if_state; int seen; };
static struct irq_milestone irq_ms[IRQ_MILESTONES];
static unsigned irq_ms_n = 0;

void irq_milestone(const char *name) {
    if (irq_ms_n >= IRQ_MILESTONES) return;
    uint64_t fl;
    __asm__ volatile ("pushfq; pop %0" : "=r"(fl) :: "memory");
    for (unsigned i = 0; i < irq_ms_n; i++)
        if (irq_ms[i].name == name) return;     /* first sighting only */
    irq_ms[irq_ms_n].name     = name;
    irq_ms[irq_ms_n].if_state = (fl & 0x200ULL) ? 1 : 0;
    irq_ms[irq_ms_n].seen     = 1;
    irq_ms_n++;
}

/* ---- The gate (roadmap 1.1 step 2) -----------------------------------------
 *
 * These expectations are MEASURED, not designed: they are what the kernel does
 * today, written down so that a change to interrupt policy cannot arrive
 * silently. Interrupts are off at every boot milestone and at syscall entry (the
 * int 0x80 gate clears IF), which is why the accidental `sti` in spin_unlock is
 * load-bearing at all -- every syscall starts masked, so the first lock it
 * releases turns interrupts on for the remainder.
 *
 * When step 3 lands the IF-preserving lock, some of these will change. That is
 * the point: the diff will have to state which, rather than the handshake quietly
 * acquiring or losing preemption windows the way it did on 2026-07-27. */
/* The one expectation that DIFFERS between the two locks, and the reason this
 * gate is worth having at all. A critical section must hand back the interrupt
 * state it was given; the legacy lock asserts IF=1 instead. Stated per build so
 * the control arm is also gated rather than merely tolerated. */
#ifdef IRQ_LEGACY_GLOBAL_LOCK
#define IRQ_EXPECT_RELEASE_IF 1
#else
#define IRQ_EXPECT_RELEASE_IF 0
#endif

static const struct { const char *name; int expect; } irq_expect[] = {
    { "post-idt",              0 },
    { "post-paging",           0 },
    { "post-protections",      0 },
    { "kernel-ready",          0 },
    { "first-syscall-entry",   0 },
    /* Roadmap 1.1 step 3: interrupts are RESTORED by a lock release, never
     * imposed. This is the assertion that the accidental `sti` (**[C-3.1]**) is
     * gone and cannot silently return. */
    { "outermost-lock-release", IRQ_EXPECT_RELEASE_IF },
};
#define IRQ_EXPECT_N ((int)(sizeof(irq_expect)/sizeof(irq_expect[0])))

static int irq_streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

/* PASS/FAIL last, and straight to the UART: smoke_test.sh kills QEMU the instant
 * it sees the marker, so anything printed after it is dead code. */
void irq_policy_selftest(void) {
    int checked = 0;
    for (int e = 0; e < IRQ_EXPECT_N; e++) {
        int found = 0;
        for (unsigned i = 0; i < irq_ms_n; i++) {
            if (!irq_streq(irq_ms[i].name, irq_expect[e].name)) continue;
            found = 1;
            if (irq_ms[i].if_state != irq_expect[e].expect) {
                panic_str("IRQ_POLICY: FAIL "); panic_str(irq_expect[e].name);
                panic_str(" IF="); panic_dec(irq_ms[i].if_state);
                panic_str(" expected "); panic_dec(irq_expect[e].expect);
                panic_str("\n");
                return;
            }
            checked++;
            break;
        }
        if (!found) {
            /* A milestone that never fired is a silent hole, not a pass: the
             * boot path may have been reordered so the point no longer exists. */
            panic_str("IRQ_POLICY: FAIL milestone-never-reached ");
            panic_str(irq_expect[e].name); panic_str("\n");
            return;
        }
    }
    panic_str("IRQ_POLICY: PASS ");
    panic_dec(checked);
    panic_str(" milestones\n");
}

/* Straight to the UART: this is reported from the timer, after console_server may
 * already own the console, where the kernel's print() is suppressed. */
void irq_milestone_report(void) {
    panic_str("[irq-policy] boot milestones (IF at each):\n");
    for (unsigned i = 0; i < irq_ms_n; i++) {
        panic_str("[irq-policy]   "); panic_str(irq_ms[i].name);
        panic_str(" IF="); panic_dec(irq_ms[i].if_state);
        panic_str("\n");
    }
}
#endif

#ifdef IRQ_POLICY_AUDIT
/* UART variant, safe to call from the timer ISR after console handover. */
/* The in-band readout (roadmap 1.1 step 2b), behind SYS_IRQ_POLICY_INFO.
 *
 * Everything else in this file reports by writing at the UART from the timer,
 * which is what broke the session it was measuring. This one just fills a struct
 * and lets the caller decide when and how to print -- through console_server,
 * the single writer, like any other program. That is the whole fix: the kernel
 * stops being a second writer. */
void irq_policy_snapshot(struct irq_policy_info *out) {
    out->accidental = irq_accidental_sti;
    out->suppressed = irq_suppressed_sti;
    out->benign     = irq_benign_sti;
    out->ticks      = system_ticks;
    unsigned n = irq_site_count;
    if (n > IRQ_POLICY_SITE_SLOTS) n = IRQ_POLICY_SITE_SLOTS;
    out->sites = n;
    for (unsigned i = 0; i < IRQ_POLICY_SITE_SLOTS; i++) {
        out->site[i].ra   = (i < n) ? irq_accidental_site[i] : 0;
        out->site[i].hits = (i < n) ? irq_accidental_hits[i] : 0;
        out->site[i]._pad = 0;
    }
}

/* The one-line form: totals and the sample point, no per-site table. */
void irq_policy_totals_uart(const char *when) {
    panic_str("\n[irq-policy] "); panic_str(when);
    /* The sample point, not just the numbers: these counts are cumulative and
     * still climbing, so a figure quoted without its tick is not a measurement. */
    panic_str(" @tick="); panic_dec((int)system_ticks);
    panic_str(": accidental_sti="); panic_dec((int)irq_accidental_sti);
    panic_str(" benign_sti=");      panic_dec((int)irq_benign_sti);
    panic_str(" sites=");           panic_dec((int)irq_site_count);
    panic_str("\n");
}

void irq_policy_report_uart(const char *when) {
    irq_policy_totals_uart(when);
    for (unsigned i = 0; i < irq_site_count && i < IRQ_SITE_SLOTS; i++) {
        panic_str("[irq-policy]   ra=0x");
        for (int sh = 60; sh >= 0; sh -= 4) {
            int nyb = (int)((irq_accidental_site[i] >> sh) & 0xF);
            panic_ch((char)(nyb < 10 ? '0'+nyb : 'a'+nyb-10));
        }
        panic_str(" hits="); panic_dec((int)irq_accidental_hits[i]);
        panic_str("\n");
    }
}

/* Report what the audit saw. Called at boot milestones so the numbers can be
 * attributed to a phase rather than to "the boot" as a whole -- roadmap 1.1 has
 * to know WHICH windows depend on the accidental sti, not merely that some do. */
void irq_policy_report(const char *when) {
    print("[irq-policy] "); print(when);
    print(": accidental_sti="); print_decimal((uint64_t)irq_accidental_sti);
    print(" benign_sti=");      print_decimal((uint64_t)irq_benign_sti);
    print(" sites=");           print_decimal((uint64_t)irq_site_count);
    print("\n");
    for (unsigned i = 0; i < irq_site_count && i < IRQ_SITE_SLOTS; i++) {
        print("[irq-policy]   site ra=");
        print_hex64(irq_accidental_site[i]);
        print(" hits="); print_decimal((uint64_t)irq_accidental_hits[i]);
        print("\n");
    }
}
#endif

#ifndef IRQ_LEGACY_GLOBAL_LOCK
/* ---- The IF-preserving, per-CPU lock (roadmap 1.1 step 3, [C-3]/[C-3.1]) ----
 *
 * Two defects, one fix.
 *
 * The nesting depth was a SINGLE GLOBAL shared by every CPU, incremented and
 * decremented non-atomically (**[C-3]**). Under SMP one CPU's release could
 * drive the count to zero while another still held a lock, so that other CPU's
 * critical section ran with interrupts on.
 *
 * And the release ended in an UNCONDITIONAL `sti` once the count reached zero
 * (**[C-3.1]**), so a critical section IMPOSED IF=1 on a caller that had
 * deliberately masked interrupts. Because `int 0x80` clears IF on entry, every
 * syscall starts masked, and the first lock it took and released turned
 * interrupts on for the remainder — which is how boot-time interrupt
 * enablement came to be a consequence of a locking bug rather than a policy.
 *
 * Both go away together: make the state per-CPU, and RESTORE the caller's own
 * RFLAGS.IF instead of asserting one. The outermost acquire records what the
 * caller had; the outermost release puts exactly that back.
 *
 * Reading this_cpu() here is cheap and safe. It is an `str` plus arithmetic
 * (see the long note on this_cpu() above), not an MMIO read, and a CPU cannot
 * change identity underneath either half: the acquire reads it after `cli`, the
 * release reads it while the section still holds IF=0, and ring 0 is not
 * preemptible (preempt_on_tick's ring-0 guard). A CPU therefore executes the
 * whole acquire..release on itself.
 *
 * WHY THIS DID NOT WORK IN JULY, AND WHAT CHANGED. The equivalent patch was
 * written on 2026-07-27, passed every local gate, and broke the ring-3 startup
 * handshake in CI. It was reverted, and the roadmap recorded the reason: the
 * accidental `sti` was load-bearing, because the handshake depended on the
 * preemption it produced. Three subsystems were then changed to route around
 * C-3.1 rather than fix it — most importantly preempt_on_tick's ring-0 guard,
 * which was widened from `cpu == 0` to every CPU precisely because a syscall
 * could be interrupted mid-flight (see the long note there, which names C-3.1
 * explicitly). With that guard in place a ring-0 tick is never a switch point,
 * so the `sti` no longer creates the preemption anything depended on. This
 * change is safe *because* those workarounds exist; it is also what lets them
 * be reasoned about again, since interrupt policy is now stated rather than
 * emergent. It was re-measured rather than re-argued — see docs/ROADMAP.md. */
static volatile int irq_depth_pc[MAX_CPUS];
static volatile int irq_saved_if_pc[MAX_CPUS];

void spin_lock(spinlock_t *lock) {
    uint64_t fl;
    __asm__ volatile ("pushfq; pop %0" : "=r"(fl) :: "memory");
    __asm__ volatile ("cli" ::: "memory");
    int c = this_cpu();
    if (c < 0 || c >= MAX_CPUS) c = 0;
    if (irq_depth_pc[c]++ == 0)
        irq_saved_if_pc[c] = (fl & 0x200ULL) ? 1 : 0;
    while (__sync_lock_test_and_set(&lock->locked, 1)) {
        while (lock->locked) { __asm__ volatile ("pause" ::: "memory"); }
    }
}

void spin_unlock(spinlock_t *lock) {
    int c = this_cpu();
    if (c < 0 || c >= MAX_CPUS) c = 0;
    __sync_lock_release(&lock->locked);
    if (irq_depth_pc[c] > 0 && --irq_depth_pc[c] == 0) {
#ifdef IRQ_POLICY_AUDIT
        /* Count the SAME predicate the legacy lock counts, so the two builds are
         * directly comparable on one workload: was IF clear when the outermost
         * lock was taken? Under the legacy lock those releases fire an `sti` the
         * caller never asked for and are counted as `accidental`. Here they are
         * SUPPRESSED, and counted as such.
         *
         * That correspondence is the measurement this change is justified by:
         * same workload, legacy accidental == per-CPU suppressed means the fix
         * removes exactly those enablements and nothing else. A `suppressed`
         * count of 0 would mean the instrument, not the defect, had gone away. */
        if (!irq_saved_if_pc[c]) {
            irq_suppressed_sti++;
            irq_record_site((uint64_t)(uintptr_t)__builtin_return_address(0));
        } else {
            irq_benign_sti++;
        }
#endif
        /* Restore, never impose. This is the whole change. */
        if (irq_saved_if_pc[c]) __asm__ volatile ("sti" ::: "memory");
#ifdef IRQ_POLICY_AUDIT
        /* Records IF as it stands after the FIRST outermost release of the boot,
         * which is the single observation that distinguishes the two locks: the
         * legacy one has just asserted IF=1 regardless, this one has restored
         * whatever the caller had (0, at that point in boot). Gated by
         * irq_policy_selftest, so an unconditional `sti` cannot come back
         * silently. */
        irq_milestone("outermost-lock-release");
#endif
    }
}
#else /* IRQ_LEGACY_GLOBAL_LOCK: the pre-1.1 lock, kept buildable as the control
       * arm. Rebuilding the defect exactly is how the fix was MEASURED rather
       * than asserted, the same role EP_QUEUE_SLOTS=1 plays for roadmap 1.3.
       * Never ship this. */
void spin_lock(spinlock_t *lock) {
#ifdef IRQ_POLICY_AUDIT
    uint64_t fl;
    __asm__ volatile ("pushfq; pop %0" : "=r"(fl) :: "memory");
#endif
    __asm__ volatile ("cli" ::: "memory");
#ifdef IRQ_POLICY_AUDIT
    if (irq_lock_depth == 0) irq_outer_if = (fl & 0x200ULL) ? 1 : 0;
#endif
    irq_lock_depth++;
    while (__sync_lock_test_and_set(&lock->locked, 1)) {
        while (lock->locked) { __asm__ volatile ("pause" ::: "memory"); }
    }
}
void spin_unlock(spinlock_t *lock) {
    __sync_lock_release(&lock->locked);

    if (irq_lock_depth > 0 && --irq_lock_depth == 0) {
#ifdef IRQ_POLICY_AUDIT
        /* The whole question of 1.1, in one branch: was IF already set when the
         * outermost lock was taken? If not, this `sti` is enabling interrupts the
         * caller deliberately masked -- an accident the boot path now relies on. */
        if (!irq_outer_if) {
            irq_accidental_sti++;
            irq_record_site((uint64_t)(uintptr_t)__builtin_return_address(0));
        } else {
            irq_benign_sti++;
        }
#endif
        __asm__ volatile ("sti" ::: "memory");
#ifdef IRQ_POLICY_AUDIT
        irq_milestone("outermost-lock-release");   /* see the per-CPU branch */
#endif
    }
}
#endif /* IRQ_LEGACY_GLOBAL_LOCK */

/* How many nested spinlocks THIS CPU currently holds (roadmap 1.1 step 1).
 *
 * The point of stating interrupt policy is that a window which must run with
 * interrupts ENABLED can now say so and check it, instead of inheriting IF=1 as
 * a side effect of whatever lock the caller happened to release. The one such
 * window in the tree is the TLB-shootdown wait (smp_maybe_shootdown), whose
 * comment has always required interrupts on; this is what lets it enforce that
 * rather than document it. Enabling interrupts while holding a lock is the
 * hazard the requirement trades against, so the count has to be askable. */
int irq_locks_held_here(void) {
#ifdef IRQ_LEGACY_GLOBAL_LOCK
    return irq_lock_depth;
#else
    int c = this_cpu();
    if (c < 0 || c >= MAX_CPUS) c = 0;
    return irq_depth_pc[c];
#endif
}


