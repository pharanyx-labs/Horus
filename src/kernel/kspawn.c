/* kspawn.c -- process creation: spawn-argument staging + argv marshalling,
 * do_spawn() (build address space, load staged image, endow caps), exec-in-
 * place (SYS_EXEC_NAMED), and the spawn/argv syscall handlers. Split out of
 * syscall.c. */
#include "syscall_internal.h"

#define SPAWN_MAX_ARGS   16
#define SPAWN_ARGS_BYTES 512
static uint32_t g_args_argc = 0;
static uint32_t g_args_total = 0;              /* bytes used in g_args_strbuf */
static char     g_args_strbuf[SPAWN_ARGS_BYTES];
static uint16_t g_args_len[SPAWN_MAX_ARGS];    /* length incl NUL of each arg */

/* ---- ONE OWNER FOR THE SPAWN STAGING -- roadmap 1.7 -----------------------
 *
 * Everything SYS_SPAWN / SYS_EXEC_* needs in flight is process-wide: the ELF
 * staging buffer and armed header (loader.c), and the argv staging below. The
 * path was written for a kernel that spawned from one core, and under SMP two
 * CPUs interleaved through it freely -- CPU A arms its image, CPU B arms
 * another, and A loads B's.
 *
 * Two of the four singletons were removed rather than guarded on 2026-08-17:
 * the exec re-entry hand-off is per-CPU ([G-9]) and the page-table reclaim is
 * CR3-guarded ([G-10]). Per-CPU is the wrong answer for the rest. A staging
 * buffer per CPU is LOADER_STAGING_BYTES of real memory per core for state that
 * is logically per-SPAWN, not per-CPU, and the argv/stdio state has the same
 * shape. So this window is serialised instead.
 *
 * The lock is taken BEFORE the image is armed and released once the staged
 * state has been consumed -- not around each singleton separately, because the
 * hazard is the interleaving of a multi-step sequence, and a lock per field
 * would leave every interleaving of the sequence available. Interrupt latency
 * is not a new cost here: `int 0x80` is an interrupt gate, so the whole spawn
 * already ran with IF=0 on that CPU, and spin_lock/spin_unlock have preserved
 * the caller's IF since roadmap 1.1.
 *
 * Lock ORDER: this is the outermost lock in the kernel. It is taken by syscall
 * entry points holding nothing, and cap_lock / the untyped lock / sched_raw_lock
 * are taken underneath it. Never take it while holding one of those.
 *
 * The exec path releases from inside exec_into_armed_image(), because that
 * function does not return to its caller in the usual sense -- it hands the ISR
 * epilogue a fresh ring-3 context. Releasing at the end of the staged-state
 * consumption keeps the acquire/release pair on one CPU, which is what
 * spin_lock's per-CPU IRQ bookkeeping requires.
 *
 * SPAWN_STAGE_UNSERIALISED=1 makes the acquire/release no-ops -- the
 * pre-2026-08-18 kernel exactly. It gates NOTHING, and that is a measured
 * decision rather than an omission: across 16 boots at -smp 4 with the window
 * held open on purpose (SPAWN_STAGE_WIDEN), it was entered 214 times and never
 * once by two CPUs at a time, in either arm. Every spawner in this tree is init
 * or one of init's children, so the busiest one cannot run while init is
 * mid-spawn. A control arm that cannot fail cannot gate anything, so no smoke
 * target claims a rate here; the flag is kept for the day a workload has two
 * live spawners. Whatever theft such a workload produces is REPORTED rather than
 * executed, because the ownership stamp (loader.c, [G-11]) refuses a foreign
 * image -- so the arm measures the serialisation without also being an exploit.
 * See TESTS.md, finding G-10. */
/* Unused, deliberately, in the SPAWN_STAGE_UNSERIALISED control arm: the arm is
 * "the same kernel with the lock taken out", so the declaration stays and only
 * the acquire/release vanish. */
static __attribute__((unused)) spinlock_t spawn_stage_lock;

/* Which CPU is inside the arm -> consume window, or -1. Instrument only, and
 * compiled out unless SPAWN_STAGE_TRACE=1: the mutual exclusion is the lock's
 * job. It exists to answer the question a green run cannot -- was the window
 * ever entered twice at all? -- because a serialised build that never saw
 * contention proves nothing about serialisation, and in this tree it never does
 * (see the note above). Read BEFORE the acquire, which is the only point at
 * which "somebody else is in there" is observable. Same role KSTACK0_PARK_TRACE
 * plays for the park path. Not a defect flag; not shipped. */
#ifdef SPAWN_STAGE_TRACE
static volatile int spawn_window_cpu = -1;
#endif

void spawn_stage_acquire(void) {
#ifdef SPAWN_STAGE_TRACE
    int occupant = spawn_window_cpu;
    /* Every entry, not only the contended ones: a run with no contention means
     * one of two very different things -- the window is genuinely never entered
     * twice, or it is barely entered at all -- and only the entry count tells
     * them apart. This is the same reason KSTACK0_PARK_TRACE counts parks. */
    print("SPAWN STAGE: window cpu ");
    print_decimal(this_cpu());
    print(" task ");
    print_decimal(get_current_task());
    print("\n");
    if (occupant >= 0 && occupant != this_cpu()) {
        print("SPAWN STAGE: contended - cpu ");
        print_decimal(this_cpu());
        print(" arrived while cpu ");
        print_decimal(occupant);
        print(" was inside the staging window\n");
    }
#endif
#ifndef SPAWN_STAGE_UNSERIALISED
    spin_lock(&spawn_stage_lock);
#endif
#ifdef SPAWN_STAGE_TRACE
    spawn_window_cpu = this_cpu();
#endif
}

void spawn_stage_release(void) {
#ifdef SPAWN_STAGE_TRACE
    spawn_window_cpu = -1;
#endif
#ifndef SPAWN_STAGE_UNSERIALISED
    spin_unlock(&spawn_stage_lock);
#endif
}

/* Not a defect: holds the arm -> consume window open so that an interleaving
 * happens if one is possible at all. Set in BOTH arms; that is what makes the
 * pair a measurement rather than two unrelated runs (same role KSTACK_RACE_WIDEN
 * plays for [G-8]). Under the lock the widened window is held, so it costs the
 * other CPU a spin; unserialised, it is the race.
 *
 * It did not produce one. 12M spins per window (verified in the emitted code,
 * because a widener the optimiser deleted would be worse than none) across 16
 * boots produced 214 window entries and 0 overlaps. That is the answer, not a
 * failure of the instrument: see the note on SPAWN_STAGE_UNSERIALISED above. */
#ifdef SPAWN_STAGE_WIDEN
#ifndef SPAWN_STAGE_WIDEN_SPINS
#define SPAWN_STAGE_WIDEN_SPINS 12000000u
#endif
/* Bounded to the first SPAWN_STAGE_WIDEN_WINDOWS spawns: the workload's
 * concurrent spawns are all in the first seconds of boot (init launching
 * fs_server / console_server / the shell while a self-test driver launches its
 * children), and widening every later spawn only makes the boot slower without
 * making the window more likely to be entered twice. */
#ifndef SPAWN_STAGE_WIDEN_WINDOWS
#define SPAWN_STAGE_WIDEN_WINDOWS 24
#endif
static volatile uint32_t spawn_widen_left = SPAWN_STAGE_WIDEN_WINDOWS;
static void spawn_stage_widen(void) {
    if (spawn_widen_left == 0) return;
    spawn_widen_left--;
    for (volatile uint32_t i = 0; i < SPAWN_STAGE_WIDEN_SPINS; i++)
        __asm__ volatile ("pause" ::: "memory");
}
#else
static void spawn_stage_widen(void) { }
#endif

/* Report a refused consume: the staged image belongs to another task. Serialised
 * this cannot happen, and 0 is the assertion; unserialised it counts how often a
 * CPU stole the staging. Printed rather than panicking because the refusal has
 * ALREADY made it safe -- the spawn fails closed -- and a boot that keeps
 * running reports every theft in it instead of only the first. It is also the
 * line the [G-11] self-test looks for, where the foreign owner is forged rather
 * than raced. */
static void spawn_stage_report_theft(int owner) {
    print("SPAWN STAGE: theft - image armed by task ");
    print_decimal(owner);
    print(", consumed by task ");
    print_decimal(get_current_task());
    print(" on cpu ");
    print_decimal(this_cpu());
    print(" (see roadmap 1.7)\n");
}

/* Copy a NUL-terminated string from user vaddr `usrc` into `dst` (cap bytes incl
 * NUL). Returns length excluding NUL, or -1 on fault / no NUL within cap. */
static int copy_user_cstr(char *dst, uint64_t usrc, uint32_t cap) {
    for (uint32_t i = 0; i < cap; i++) {
        char c;
        if (copy_from_user(&c, (const void *)(addr_t)(usrc + i), 1) != 0) return -1;
        dst[i] = c;
        if (c == 0) return (int)i;
    }
    return -1;   /* over-long / no terminator within cap */
}

/* Stage the spawner's argv (argc strings at user array `uargv`) for the next
 * spawn. Clears the staging on any error so a partial vector is never applied.
 * `uargv` points at the caller's `char *argv[]`, whose entries are 8 bytes now
 * that userspace is 64-bit -- reading them as 4 would pair each low half with
 * the next pointer's high half and stage garbage. */
static void stage_spawn_args(uint64_t uargv, uint32_t uargc) {
    g_args_argc = 0; g_args_total = 0;
    if (uargc == 0 || uargv == 0 || uargc > SPAWN_MAX_ARGS) return;
    uint64_t ptrs[SPAWN_MAX_ARGS];
    if (copy_from_user(ptrs, (const void *)(addr_t)uargv, uargc * sizeof(uint64_t)) != 0) return;
    uint32_t total = 0;
    for (uint32_t i = 0; i < uargc; i++) {
        if (total >= SPAWN_ARGS_BYTES) return;
        int len = copy_user_cstr(g_args_strbuf + total, ptrs[i], SPAWN_ARGS_BYTES - total);
        if (len < 0) return;                 /* fault or over-long: abort, no args */
        g_args_len[i] = (uint16_t)(len + 1);
        total += (uint32_t)len + 1;
    }
    g_args_argc  = uargc;
    g_args_total = total;
}

#ifdef COREUTILS_SELFTEST
/* Stage an argv the KERNEL already holds, for a gated self-test that spawns a
 * ported program with arguments. stage_spawn_args above reads the vector out of
 * a ring-3 caller's address space (copy_user_cstr); a kernel-side driver has the
 * strings in its own, so it needs this variant rather than a fake user pointer.
 * Same staging, same consumption by build_child_argv. Gated: the ship kernel has
 * no in-kernel argv source and should not carry one. */
void stage_spawn_args_kernel(const char *const *argv, uint32_t argc) {
    g_args_argc = 0; g_args_total = 0;
    if (argc == 0 || !argv || argc > SPAWN_MAX_ARGS) return;
    uint32_t total = 0;
    for (uint32_t i = 0; i < argc; i++) {
        const char *s = argv[i];
        if (!s) return;
        uint32_t len = 0;
        while (s[len] && total + len + 1 < SPAWN_ARGS_BYTES) len++;
        if (s[len]) return;                   /* over-long: abort, no args */
        for (uint32_t j = 0; j <= len; j++) g_args_strbuf[total + j] = s[j];
        g_args_len[i] = (uint16_t)(len + 1);
        total += len + 1;
    }
    g_args_argc  = argc;
    g_args_total = total;
}
#endif /* COREUTILS_SELFTEST */

/* Marshal the staged argv onto child `tid`'s initial stack and record argc + the
 * argv[] base on its TCB. Must run with `tid` current (so copy_to_user targets
 * its address space) and before sched_prepare_user_context reads esp. Consumes
 * the staging. No-op when nothing is staged. */
static void build_child_argv(int tid) {
    if (g_args_argc == 0) return;
    uint32_t argc = g_args_argc;
    uint64_t sp   = (tasks[tid].esp ? tasks[tid].esp : 0x007ff000ULL) & ~0xFULL;
    uint64_t str_vaddr[SPAWN_MAX_ARGS];
    uint32_t off = 0;
    for (uint32_t i = 0; i < argc; i++) {
        uint32_t len = g_args_len[i];
        sp -= len;
        copy_to_user((void *)(addr_t)sp, g_args_strbuf + off, len);
        str_vaddr[i] = sp;
        off += len;
    }
    /* The child reads this as `char *argv[]`, so entries are 8 bytes wide and
     * 8-byte aligned now that userspace is 64-bit. */
    sp &= ~7ULL;
    sp -= (uint64_t)(argc + 1) * sizeof(uint64_t);   /* argv[], NULL-terminated */
    uint64_t argv_base = sp;
    for (uint32_t i = 0; i < argc; i++)
        copy_to_user((void *)(addr_t)(argv_base + i * sizeof(uint64_t)),
                     &str_vaddr[i], sizeof(uint64_t));
    uint64_t nullp = 0;
    copy_to_user((void *)(addr_t)(argv_base + (uint64_t)argc * sizeof(uint64_t)),
                 &nullp, sizeof(uint64_t));
    tasks[tid].argc     = argc;
    tasks[tid].argv_ptr = argv_base;
    tasks[tid].esp      = (argv_base - 16) & ~0xFULL;
    g_args_argc = 0; g_args_total = 0;
}

/* Wire the child's stdin/stdout to pipe ends the spawner holds. Runs inside
 * do_spawn_inner, before sched_prepare_user_context publishes a resumable frame
 * — so the child cannot be picked by any CPU until its stdio slots and
 * stdio_flags are set. Copies the spawner's pipe-end cap into the child's
 * reserved slot with a fresh serial and bumps that end's refcount, so the child
 * holds a first-class end that task_teardown will release. A malformed/absent
 * slot is silently left as the console default (fail-safe).
 *
 * `caller` and `spec` are PARAMETERS, and that is the fix, not a tidy-up
 * (roadmap 1.7, the authority half). They were two file-scope globals:
 * g_spawn_caller was written at do_spawn() entry and read here, hundreds of KiB
 * of ELF copying later, so a second CPU entering do_spawn in that window
 * redirected this read to ITS cspace. The child then inherited a pipe capability
 * from a task that never spawned it — capability inheritance across a parentage
 * that does not exist, which no rights mask can catch because the rights were
 * never widened; the wrong cspace was consulted. Passing them down the call
 * chain makes the wrong parent unexpressible rather than unlikely, and
 * do_spawn_stdio has already checked that `caller` is the task that armed the
 * image it is loading. */
static void wire_child_stdio(int child, int caller, uint32_t spec) {
    tasks[child].stdio_flags = 0;
    if (spec == 0) return;

    if (caller <= 0 || caller >= MAX_TASKS) return;
    capability_t *pcs = tasks[caller].cspace;     /* spawner */
    capability_t *ccs = tasks[child].cspace;      /* child   */
    if (!pcs || !ccs) return;
    uint32_t psz = tasks[caller].cspace_size ? tasks[caller].cspace_size : CNODE_SIZE;

    uint32_t in_slot  = spec & 0xFFFFu;           /* read end -> child stdin  */
    uint32_t out_slot = (spec >> 16) & 0xFFFFu;   /* write end -> child stdout */

    if (in_slot && in_slot < psz &&
        pcs[in_slot].type == CAP_PIPE && (pcs[in_slot].rights & CAP_RIGHT_READ)) {
        ccs[STDIN_PIPE_SLOT] = pcs[in_slot];
        ccs[STDIN_PIPE_SLOT].serial     = cap_alloc_fresh_serial();
        ccs[STDIN_PIPE_SLOT].badge      = 0;
        ccs[STDIN_PIPE_SLOT].generation = rust_lineage_current(ccs[STDIN_PIPE_SLOT].serial); /* finding 3.3 */
        pipe_end_ref((int)pcs[in_slot].object, 0);   /* +1 read end */
        tasks[child].stdio_flags |= STDIO_STDIN_PIPE;
    }
    if (out_slot && out_slot < psz &&
        pcs[out_slot].type == CAP_PIPE && (pcs[out_slot].rights & CAP_RIGHT_WRITE)) {
        ccs[STDOUT_PIPE_SLOT] = pcs[out_slot];
        ccs[STDOUT_PIPE_SLOT].serial     = cap_alloc_fresh_serial();
        ccs[STDOUT_PIPE_SLOT].badge      = 0;
        ccs[STDOUT_PIPE_SLOT].generation = rust_lineage_current(ccs[STDOUT_PIPE_SLOT].serial); /* finding 3.3 */
        pipe_end_ref((int)pcs[out_slot].object, 1);  /* +1 write end */
        tasks[child].stdio_flags |= STDIO_STDOUT_PIPE;
    }
}

static int do_spawn_inner(int caller, uint32_t stdio_spec) {
    if (!program_armed) {
        return -1;
    }

    int new_id = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        if (tasks[i].state == 0) {
            new_id = i;
            break;
        }
    }
    if (new_id < 0) {
        return -2;
    }

    uint64_t load_base = USER_AREA_BASE;
    uint64_t stack_top = 0;
    choose_image_placement(new_id, &load_base, &stack_top);

    /* Premap the image window to the staged image's whole loaded span, so the
     * loader's copy_to_user can write every PT_LOAD segment (it needs the pages
     * present). Computed from the still-armed staged image, before the address
     * space is built. */
    create_task(new_id, load_base + armed_hdr.entry, stack_top, load_base,
                staged_image_span_pages());

    load_staged_image_into(new_id, load_base);

    /* load_staged_image_into left `new_id` current, so copy_to_user targets its
     * address space: marshal any staged argv onto its stack before its initial
     * context is fabricated (this lowers new_id's esp below the argv block). */
    build_child_argv(new_id);

    uint32_t cap6_serial = 0;
    struct capability *creator_admin = cap_lookup(6, CAP_RIGHT_ALL);
    if (creator_admin && creator_admin->type == CAP_USER) {
        cap6_serial = cap_alloc_fresh_serial();
    }
    spin_lock(&cap_lock);
    if (creator_admin && creator_admin->type == CAP_USER) {
        tasks[new_id].cspace[6].type   = CAP_USER;
        tasks[new_id].cspace[6].rights = CAP_RIGHT_ALL;
        tasks[new_id].cspace[6].object = 0;
        tasks[new_id].cspace[6].badge  = creator_admin->serial ? creator_admin->serial : 0xC0DE0006U;
        tasks[new_id].cspace[6].serial = cap6_serial;
        /* Stamp the child admin cap from its OWN fresh serial, not the creator's
         * generation (finding 3.3): the cap is keyed by cap6_serial, so its
         * generation must track that serial's cell for revoke to invalidate it. */
        tasks[new_id].cspace[6].generation = rust_lineage_current(cap6_serial);
    }
    spin_unlock(&cap_lock);

    /* Wire pipe stdio (if this spawn requested it) BEFORE publishing a resumable
     * frame below — until sched_prepare_user_context sets runnable_ctx, no CPU can
     * schedule the child, so it cannot reach posix_init before its stdio is set. */
    wire_child_stdio(new_id, caller, stdio_spec);

    /* Fabricate an initial resumable trap frame so sched_enter_user and the
     * preemptive scheduler can iretq into this task (entry/esp/cr3 are final). */
    sched_prepare_user_context(new_id, tasks[new_id].eip,
                               tasks[new_id].esp ? tasks[new_id].esp : 0x007ff000ULL);

    /* SPAWN SUSPENDED. sched_prepare_user_context just set runnable_ctx = 1,
     * which is what makes a task schedulable; clear it so the child cannot run
     * until its supervisor explicitly resumes it (SYS_TASK_RESUME).
     *
     * This closes a whole BUG CLASS, not one bug. A supervisor's only way to
     * endow a child is `spawn -> sys_cap_grant... -> child runs`, but spawn used
     * to publish the child as runnable immediately, so under SMP it genuinely
     * started executing on another core BEFORE the grants landed. The child then
     * ran with a partially-populated cspace and failed in whatever way its
     * missing capability implied. Three separate instances of this were found and
     * individually papered over with retry loops before the pattern was
     * recognised: fs_server's registration, posix's fs_connect, and finally the
     * shell's console capability — which had no retry, so the shell simply never
     * printed its banner and CI timed out.
     *
     * Retrying in each client is whack-a-mole: it needs every current AND future
     * client to anticipate a race it cannot see. Suspending the child instead
     * makes the safe ordering the ONLY expressible one.
     *
     * The failure mode also improves, which is the real point. Forgetting to
     * resume is a DETERMINISTIC hang — the child never runs, every time, locally
     * as well as in CI. Racing an endowment was intermittent, and intermittent
     * failures get re-run rather than fixed. */
    tasks[new_id].runnable_ctx = 0;

    return new_id;
}

/* Give `spawner` a CAP_TCB capability to child `pid`, so it can wait on, signal,
 * or terminate the child (SYS_WAIT / SYS_KILL). Installed in the first free
 * cspace slot at or above 16, clear of the reserved low slots, with a fresh
 * serial so cap_lookup accepts it. No-op for the kernel/idle spawner. */
static void grant_child_tcb_cap(int spawner, int pid) {
    if (spawner <= 0 || spawner >= MAX_TASKS || pid <= 0 || pid >= MAX_TASKS) return;
    capability_t *cs = tasks[spawner].cspace;
    if (!cs) return;
    for (uint32_t s = 16; s < tasks[spawner].cspace_size; s++) {
        if (cs[s].type == CAP_NULL) {
            cs[s].type       = CAP_TCB;
            cs[s].rights     = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
            cs[s].object     = (uint64_t)pid;
            cs[s].badge      = 0;
            cs[s].serial     = cap_alloc_fresh_serial();
            cs[s].generation = rust_lineage_current(cs[s].serial); /* finding 3.3 */
            break;
        }
    }
}

/* do_spawn must run in the kernel address space: create_user_pagedir and the
 * image loader reach freshly-allocated physical pages through PHYS_KVA, which
 * lives in the kernel half and is therefore absent from a ring-3 caller's CR3
 * until the child's pml4[256..511] is populated; and do_spawn_inner installs the
 * child as the current task. This wrapper switches to the kernel page tables for
 * the duration and restores the caller's address space + current task on return,
 * so SYS_SPAWN works from ring 3 and the caller continues. The caller is also
 * granted a CAP_TCB to the new child. */
int do_spawn(void) { return do_spawn_stdio(0); }

int do_spawn_stdio(uint32_t stdio_spec) {
    extern uint64_t pml4[];
    uint64_t caller_cr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(caller_cr3));
    int caller_task = get_current_task();

    /* The image this is about to load must be the one THIS task armed
     * ([G-11]). Checked here, before a single frame is allocated, because it is
     * the one point that sees both the staged image and its consumer:
     *
     *  - it refuses SYS_SUDO's confused deputy, where the arm and the elevated
     *    spawn are separate syscalls and need not have come from the same task;
     *  - it is the standing witness that spawn_stage_acquire() actually brackets
     *    every arm -> consume window, since a stolen staging arrives here as a
     *    foreign owner rather than as the wrong image running;
     *  - and it is what lets `caller_task` be handed to wire_child_stdio as the
     *    child's parent: the task that armed the image and the task whose cspace
     *    the child's stdio is inherited from are now provably the same one.
     *
     * Fail closed, and loudly enough to count: -3 rather than a spawn of
     * somebody else's program. */
    if (program_armed && !staged_image_owned_by_current()) {
        spawn_stage_report_theft(staged_owner_task);
        return -3;
    }
    spawn_stage_widen();

    uint64_t kcr3 = virt_to_phys(pml4);   /* CR3 takes a physical address */

    if (caller_cr3 != kcr3) __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");
    /* Declare the impersonation. do_spawn_inner -> load_staged_image_into installs
     * the CHILD as this CPU's current task so the loader's copy_to_user lands in
     * the child's address space, and it stays that way until the restore below.
     * That is the whole ELF load — a ~450 KiB copy plus page-table construction
     * and relocation processing — during which percpu_current_task[] names a task
     * this CPU is not running while the CALLER remains correctly claimed by it.
     *
     * Undeclared, that reads to an auditor on another core as a stale claim, and
     * it did: "task 1 claimed by cpu N but that cpu was running 4" is init midway
     * through spawning the shell, and it stood open as a suspected scheduling
     * defect. The window is real, deliberate, and long; the bracket makes it
     * legible rather than invisible. Balanced within this function on purpose —
     * an enter() in loader.c paired with an exit() here would be exactly the kind
     * of split bracket that rots. */
    sched_impersonate_enter();
    int pid = do_spawn_inner(caller_task, stdio_spec);
    set_current_task(caller_task);
    sched_impersonate_exit();
    if (caller_cr3 != kcr3) __asm__ volatile ("mov %0, %%cr3" :: "r"(caller_cr3) : "memory");

    if (pid > 0) grant_child_tcb_cap(caller_task, pid);

    /* Propagate the console service capability to the child, SEND-ONLY.
     *
     * Since finding C-1 a task can only reach the console server through a
     * capability naming its endpoint, and a task is born with none. The shell
     * must therefore pass one to every utility it spawns, or `ls`, `cat`, `tcc`
     * and friends have no stdout. This is delegation by inheritance — the same
     * shape as POSIX fd inheritance.
     *
     * Rights are masked to WRITE whatever the parent holds, so a child can only
     * ever SEND to the console. Even console_server (which holds READ|WRITE to
     * receive requests) hands a child a send-only copy, so the receive right
     * cannot escape the one task meant to have it. The copy is a derived
     * capability, so revoking the parent's sweeps every child's with it.
     *
     * This MUST be here, after set_current_task(caller_task), and not inside
     * do_spawn_inner: load_staged_image_into leaves the CHILD current so its
     * copy_to_user targets the right address space, and cap_grant_into resolves
     * its source slot in the CURRENT task's cspace. Run any earlier and it reads
     * the child's own (empty) cspace and silently propagates nothing — which is
     * exactly what happened on the first attempt, and cost a `printf` with no
     * output in smoke-modules. */
    if (pid > 0) {
        struct capability *con = cap_lookup(CAPSLOT_CONSOLE_EP, CAP_RIGHT_WRITE);
        if (con && con->type == CAP_ENDPOINT) {
            cap_grant_into(pid, CAPSLOT_CONSOLE_EP, CAPSLOT_CONSOLE_EP,
                           CAP_RIGHT_WRITE);
        }
    }
    /* A child runs as its spawner's identity. This is what lets init's uid-0
     * fs_server pass the object-store's uid==0 gate, and it closes a latent
     * privilege bug: previously a child kept its (BSS-zero) task-slot uid, so a
     * task spawned by a non-root user could come up as uid 0. Authority still
     * flows through capabilities; uid only mirrors the spawner. */
    if (pid > 0) {
        tasks[pid].uid = tasks[caller_task].uid;
        tasks[pid].gid = tasks[caller_task].gid;
    }
    return pid;
}

/* ---- SYS_FORK (101) -- roadmap 2.3 ---------------------------------------
 *
 * Duplicate the caller into a new task whose address space is a copy-on-write
 * clone of the caller's. Returns the child's tid to the parent and 0 to the
 * child, from the same instruction, POSIX-fashion.
 *
 * GATED EXACTLY AS SYS_SPAWN IS -- slot 3, WRITE|EXEC -- and that choice is the
 * point rather than a copied line. The tempting reading is that fork needs no
 * capability at all: it names no object, and a task copying ITSELF reaches
 * nothing it could not already reach. Both halves of that are true and it is
 * still the wrong conclusion, because it would make SYS_FORK a SECOND way to
 * bring a task into existence, ungated, standing beside the one that is gated.
 * Revoking a task's slot-3 capability would then stop it spawning and not stop
 * it forking, and the property "this task can create no more tasks" -- which is
 * what that revocation means -- would quietly stop being true. A new path to an
 * existing capability's effect inherits that capability's gate; anything else is
 * a widening dressed as an omission.
 *
 * What the gate does NOT have to do is bound the child's authority, because the
 * child is born with the same endowment create_task gives every task (its own
 * CAP_TCB, its own reply endpoint, the legacy image frame) plus the send-only
 * console copy SYS_SPAWN already propagates, and NOTHING ELSE the parent holds.
 *
 * WHAT THE CHILD DOES *NOT* INHERIT, deliberately:
 *
 *  - The parent's CSPACE. This is the one people expect and it is the next
 *    commit, not this one. Duplicating a cspace copies every delegated
 *    capability the parent holds, and each copy has to be a DERIVED capability
 *    with its own serial stamped from the parent's lineage cell, or revoking the
 *    parent's would not sweep the child's -- a revocation hole, reachable from
 *    ring 3, dressed up as a convenience. That is an authority change and it
 *    gets its own commit, its own invariant and its own arm. Until then a forked
 *    child that needs a service must be handed it with SYS_CAP_GRANT, exactly as
 *    a spawned one is. docs/LIMITATIONS.md records this.
 *  - `io_allowed`. A ring-3 port-I/O grant is per-task by construction (the TSS
 *    I/O bitmap is flipped on context switch); inheriting it would hand a second
 *    task the console hardware nothing gave it.
 *  - The file master key. It mirrors uid, which IS inherited, so leaving it
 *    behind means a forked child cannot decrypt its user's files until it
 *    authenticates. Fail closed: a key is the one thing worth copying only on
 *    purpose.
 *  - Any in-flight kernel state: blocked-on endpoints, a pending reply buffer, a
 *    one-shot CAP_REPLY, pending signals. A fork mid-IPC would otherwise produce
 *    two tasks waiting on one reply. create_task zeroes all of it.
 *
 * WHAT IT DOES INHERIT: the memory (copy-on-write), uid/gid, the heap bounds,
 * the image window, the registered signal handler and mask, the FPU register
 * file, and the argv the parent was given -- everything that describes the
 * running program rather than an authority or a kernel-side rendezvous.
 *
 * THE CHILD IS BORN RUNNABLE, unlike a spawned one, and the difference is
 * principled. SYS_SPAWN suspends its child because a supervisor's only way to
 * endow one is `spawn -> grant -> resume`, and publishing it earlier let it run
 * with a half-populated cspace (see do_spawn_inner). Fork performs the child's
 * entire endowment inside this syscall, before the frame is published, so there
 * is no window for a supervisor to lose. Suspending anyway would mean every
 * forking program had to resume its own child, which is not fork.
 *
 * The staging lock is taken for the SLOT ALLOCATOR, not for the loader staging
 * this path never touches: do_spawn_inner scans tasks[] for `state == 0` under
 * this same lock, and a fork racing a spawn for the last free slot would
 * otherwise have both take it. Same lock, same reason it is the outermost one.
 */
void h_fork(struct interrupt_frame64 *r) {
    extern uint64_t pml4[];
    int parent = get_current_task();
    if (parent <= 0 || parent >= MAX_TASKS) { r->rax = (uint64_t)(uint32_t)SYS_ERR_INVAL; return; }

    uint64_t parent_cr3 = tasks[parent].cr3;
    if (parent_cr3 == 0) { r->rax = (uint64_t)(uint32_t)SYS_ERR_INVAL; return; }

    uint64_t caller_cr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(caller_cr3));
    uint64_t kcr3 = virt_to_phys(pml4);

    spawn_stage_acquire();

    int child = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        if (tasks[i].state == 0) { child = i; break; }
    }
    if (child < 0) {
        spawn_stage_release();
        r->rax = (uint64_t)(uint32_t)SYS_ERR_NOMEM;
        return;
    }

    /* Same reason do_spawn does it: create_task -> create_user_pagedir and the
     * clone below reach freshly-allocated physical pages through PHYS_KVA, in the
     * kernel half. Restoring the caller's CR3 at the end also performs the TLB
     * flush the clone's downgraded parent PTEs require -- see clone_user_aspace. */
    if (caller_cr3 != kcr3) __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");

    /* create_task builds the slot's bookkeeping and its birth cspace, and calls
     * create_user_pagedir -- which builds an address space the clone immediately
     * discards. That waste is bought deliberately: the alternative is a second
     * copy of create_task's fifteen fields and its cspace construction, which is
     * precisely the kind of duplicate that drifts out of step with the original
     * and grants a forked task authority a spawned one does not have. Keeping the
     * child's birth endowment LITERALLY the same code is the property worth
     * paying a page-table build for. clone_user_aspace reclaims the tree on the
     * slot exactly as create_user_pagedir would. */
    create_task(child, tasks[parent].eip, 0, tasks[parent].image_base,
                tasks[parent].image_premap_pages);

    int rc = clone_user_aspace((uint32_t)child, parent_cr3);
    if (rc != 0) {
        /* The slot is released rather than left half-alive: state 0 is what makes
         * it allocatable again, and a task with cr3 == 0 must never be reachable
         * by the scheduler. runnable_ctx is already 0 (create_task) and no frame
         * has been published, so nothing can have claimed it. */
        tasks[child].state = 0;
        tasks[child].cr3 = 0;
        if (caller_cr3 != kcr3) __asm__ volatile ("mov %0, %%cr3" :: "r"(caller_cr3) : "memory");
        spawn_stage_release();
        /* -3 from the clone is the policy refusal (a kernel object's page, or a
         * huge page); -2 is out of memory. Reported apart so a caller can tell
         * "this fork is never going to work" from "try again later". */
        r->rax = (uint64_t)(uint32_t)(rc == -2 ? SYS_ERR_NOMEM : SYS_ERR_INVAL);
        return;
    }

    /* Everything that describes the running program rather than an authority. */
    tasks[child].uid                = tasks[parent].uid;
    tasks[child].gid                = tasks[parent].gid;
    tasks[child].heap_start         = tasks[parent].heap_start;
    tasks[child].heap_current       = tasks[parent].heap_current;
    tasks[child].heap_end           = tasks[parent].heap_end;
    tasks[child].image_base         = tasks[parent].image_base;
    tasks[child].image_end          = tasks[parent].image_end;
    tasks[child].image_premap_pages = tasks[parent].image_premap_pages;
    tasks[child].priority           = tasks[parent].priority;
    tasks[child].sig_handler        = tasks[parent].sig_handler;
    tasks[child].sig_mask           = tasks[parent].sig_mask;
    tasks[child].sig_altstack_sp    = tasks[parent].sig_altstack_sp;
    tasks[child].sig_altstack_size  = tasks[parent].sig_altstack_size;
    tasks[child].spawn_arg          = tasks[parent].spawn_arg;
    tasks[child].argc               = tasks[parent].argc;
    tasks[child].argv_ptr           = tasks[parent].argv_ptr;
    for (int i = 0; i < 32; i++) tasks[child].name[i] = tasks[parent].name[i];
    for (int i = 0; i < 512; i++) tasks[child].fpu_state[i] = tasks[parent].fpu_state[i];

    /* ---- ENDOW BEFORE PUBLISHING, and the order is the whole of it ---------
     *
     * `runnable_ctx = 1` below is what makes the child schedulable, and under SMP
     * another CPU may claim it on the very next tick. Everything the child is
     * owed must therefore already be in its cspace by then. Written the other way
     * round -- publish, then grant -- this reintroduces do_spawn_inner's bug
     * class exactly: a child that starts running on another core with a
     * partially-populated cspace and fails in whatever way its missing capability
     * implies. That cost three separately-diagnosed intermittent failures before
     * the pattern was recognised (fs_server's registration, posix's fs_connect,
     * and the shell's console capability, which simply never printed its banner).
     *
     * This is also the reason a forked child needs no SYS_TASK_RESUME while a
     * spawned one does. Spawn cannot close the window: its child's endowment
     * comes from a SUPERVISOR, in syscalls that necessarily run after the spawn
     * returns, so the only safe ordering is to suspend and let the supervisor say
     * when. Fork's endowment is entirely in-kernel and finishes here, so there is
     * no window to leave open -- and a fork that demanded its parent resume it
     * would not be a fork.
     *
     * Neither grant can fail in a way the child would notice: a parent with no
     * console capability simply has a child with none, which is the same
     * inheritance SYS_SPAWN performs.
     *
     * The child gets a DERIVED copy of every capability the parent holds, in the
     * same slots (cap_clone_cspace). It replaced a single hand-written grant of
     * the console endpoint -- the same one SYS_SPAWN propagates -- which was the
     * whole of a forked child's inheritance until now.
     *
     * The rights are the parent's, not narrowed, and the reasoning for that is at
     * cap_clone_cspace. What matters here is that this cannot widen anything:
     * every copy is a derived CHILD of a capability the parent already holds, so
     * the child's authority is a subtree of the parent's, and fork adds no new
     * ROOT to the capability graph.
     *
     * A failure is fatal to the fork rather than partial. A task running with an
     * arbitrary prefix of its parent's authority is a configuration nothing asked
     * for and nothing can reason about -- and worse, the prefix would depend on
     * slot order, so the same program would fork differently depending on which
     * slot its capabilities happened to land in. Same argument S35 makes about a
     * partly-installed mapping, for the same reason: the caller is told the call
     * failed, so it must hold what it held before. */
    if (cap_clone_cspace(parent, child) < 0) {
        tasks[child].state = 0;
        tasks[child].cr3 = 0;
        if (caller_cr3 != kcr3) __asm__ volatile ("mov %0, %%cr3" :: "r"(caller_cr3) : "memory");
        spawn_stage_release();
        r->rax = (uint64_t)(uint32_t)SYS_ERR_NOMEM;
        return;
    }
    /* A parent may wait on, signal, or kill what it forked -- the same CAP_TCB
     * SYS_SPAWN hands back, in the same first free slot at or above 16. This one
     * lands in the PARENT's cspace, so it is not part of the race above; it is
     * kept here so the two halves of "who may reach whom" read together. */
    grant_child_tcb_cap(parent, child);

    /* The child resumes from the same instruction as the parent, on its own copy
     * of the same user stack, with rax = 0. `r` IS the parent's live trap frame
     * at the top of the parent's kernel stack; the child's copy goes to the top
     * of its own, which is where the ISR epilogue expects to find it (the same
     * placement sched_prepare_user_context computes for a fresh task).
     *
     * LAST, deliberately: `runnable_ctx = 1` is the publish, and everything the
     * child is owed is already in place above. See the note there. */
    {
        uint64_t top = (tasks[child].kernel_stack_top) & ~0xFULL;
        struct interrupt_frame64 *cf =
            (struct interrupt_frame64 *)(top - sizeof(struct interrupt_frame64));
        *cf = *r;
        cf->rax = 0;                       /* fork() == 0 in the child */
        tasks[child].saved_ksp    = (uint64_t)cf;
        tasks[child].runnable_ctx = 1;
    }

    if (caller_cr3 != kcr3) __asm__ volatile ("mov %0, %%cr3" :: "r"(caller_cr3) : "memory");
    spawn_stage_release();

    r->rax = (uint64_t)child;
}

/* Set by the exec tail to ask interrupt_handler64 to re-enter this task via the
 * fresh context sched_prepare_user_context fabricated for it, instead of iretq'ing
 * back into the (now-replaced) old image. -1 when no exec re-entry is pending.
 *
 * ---- PER-CPU, AND THAT IS THE WHOLE POINT ([G-9]) --------------------------
 *
 * This used to be a single `int`. The consume site (idt.c) runs on the exit of
 * EVERY syscall on EVERY CPU and had no test that the pending exec belonged to
 * the CPU reading it, so an exec armed on one core was routinely taken by
 * another. The thief claimed the exec'ing task, installed its CR3, and resumed
 * its freshly fabricated frame -- while the core that actually ran the exec was
 * still executing on that same trap frame, which is the top of that task's
 * kernel stack.
 *
 * That single race produced all three of the signatures filed under [G-9]:
 *
 *   - the leaked claim ("task N claimed by cpu C but that cpu was running M"):
 *     the thief abandons whatever it was running without releasing it, because
 *     exec_reenter_switch has no outgoing task to release -- it is written for
 *     the case where the incoming task IS the outgoing one;
 *   - the opposite direction ("a task running with no claim"), once the real
 *     exec'ing CPU carries on running a task the thief has re-claimed;
 *   - two CPUs on one kernel stack, reported by the stack canary in h_write,
 *     because both cores are then reading and writing one trap frame.
 *
 * Per-CPU storage removes the sharing rather than guarding it: there is no
 * window left in which the wrong core can observe the hand-off at all. The
 * identity assertion in exec_reenter_switch (scheduler.c, SCHED_INVARIANTS
 * builds) is the standing witness that it stays that way.
 *
 * EXEC_REENTER_GLOBAL=1 restores the single shared slot -- the defect, on
 * demand -- and is what `make smoke-exec-reenter-control` builds. */
#ifdef EXEC_REENTER_GLOBAL
static int g_exec_reenter[1] = { -1 };
#define EXEC_REENTER_IDX  0
#else
static int g_exec_reenter[MAX_CPUS] = { [0 ... MAX_CPUS - 1] = -1 };
#define EXEC_REENTER_IDX  this_cpu()
#endif

/* Arm the re-entry for the CPU performing the exec. */
void exec_reenter_arm(int t) {
    int i = EXEC_REENTER_IDX;
    if (i < 0 || i >= (int)(sizeof g_exec_reenter / sizeof g_exec_reenter[0])) i = 0;
    g_exec_reenter[i] = t;
}

/* Take this CPU's pending re-entry, or -1. Clears it, so a given exec is
 * consumed exactly once by exactly the core that armed it. */
int exec_reenter_take(void) {
    int i = EXEC_REENTER_IDX;
    if (i < 0 || i >= (int)(sizeof g_exec_reenter / sizeof g_exec_reenter[0])) i = 0;
    int t = g_exec_reenter[i];
    if (t > 0) g_exec_reenter[i] = -1;
    return t;
}

/* SYS_EXEC_NAMED (64): replace the calling task's image with a named embedded
 * binary, keeping the same task id and cspace (capabilities survive the exec,
 * POSIX-style). Like do_spawn the rebuild+load must run in the kernel address
 * space (create_user_pagedir and the loader reach fresh physical pages through
 * the kernel identity map); unlike do_spawn we do NOT restore the caller — on
 * success we switch to the freshly-built image's CR3 and drop to ring 3 at its
 * entry, so this never returns. The old page directory/frames leak, consistent
 * with the kernel's non-freeing task teardown (task_teardown only marks slots
 * dead). Capability (slot 3, WRITE|EXEC) is enforced centrally by the table. */
/* Shared tail of SYS_EXEC_NAMED / SYS_EXEC_IMAGE: replace the current task's
 * image in place with the currently-armed staged image, keeping its task id and
 * cspace (capabilities survive the exec, POSIX-style). Preconditions: a program
 * is armed (arm_named_binary / arm_image_from_user succeeded) and any new argv is
 * already staged from the caller's still-live address space. Like do_spawn the
 * rebuild+load runs in the kernel address space; unlike do_spawn we do NOT
 * restore the caller — on success we hand interrupt_handler64 a fresh ring-3
 * context (exec_reenter_arm) for the new image, so this never returns. The old
 * page directory/frames leak, consistent with the kernel's non-freeing teardown.
 * Takes no trap frame: it never returns to the caller, so it has no return value
 * to write, and the frame it would write to is the one it just overwrote with
 * the new image's fresh ring-3 context. */
static void exec_into_armed_image(void) {
    int cur = get_current_task();

    /* Past this point the caller's image is torn down and replaced; there is no
     * clean return path. Switch to the kernel address space for the rebuild. */
    extern uint64_t pml4[];
    uint64_t kcr3 = virt_to_phys(pml4);   /* CR3 takes a physical address */
    __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");

    uint64_t load_base = USER_AREA_BASE;
    uint64_t stack_top = 0;
    choose_image_placement(cur, &load_base, &stack_top);

    /* ---- THE CSPACE IS NOT TOUCHED, AND THAT IS THE PROPERTY (S42) --------
     *
     * Rebuild only the address space (fresh PML4 into tasks[cur].cr3). The task
     * keeps every capability it held, with the same serial and the same badge, so
     * it keeps its POSITION in the derivation graph and not merely its authority.
     * Two things follow, and the second is why this is a security property rather
     * than POSIX nostalgia:
     *
     *  - a revocation aimed at whatever these were derived from still reaches
     *    them, so a task cannot launder delegated authority into a root of its
     *    own by execing;
     *  - and combined with SYS_FORK, which endows the child with DERIVED copies
     *    (S41), `fork(); exec();` -- the only sequence a shell ever performs --
     *    produces a task whose authority is still a subtree of its parent's.
     *
     * Written as the ABSENCE of a step, which is the hardest kind of property to
     * witness: nothing here can be pointed at. `EXEC_RESET_CSPACE=1` and
     * `EXEC_ROOT_CSPACE=1` add the two steps that would break each half of it
     * (see cap_exec_mutate_cspace in capability.c), and `make smoke-forkexec`
     * measures the difference.
     *
     * Reset signal dispositions like a real exec. create_user_pagedir reads
     * image_base for the premap, so set it first. */
#if defined(EXEC_RESET_CSPACE) || defined(EXEC_ROOT_CSPACE)
    { extern void cap_exec_mutate_cspace(int t); cap_exec_mutate_cspace(cur); }
#endif
    tasks[cur].image_base  = load_base;
    tasks[cur].image_end   = load_base;
    /* Size the image-window premap to the new image's loaded span (still armed),
     * so create_user_pagedir maps enough for the loader's copy_to_user below. */
    tasks[cur].image_premap_pages = staged_image_span_pages();
    tasks[cur].esp         = stack_top ? (stack_top - 256) : 0;
    tasks[cur].sig_handler  = 0;
    tasks[cur].in_signal    = 0;
    tasks[cur].pending_sigs = 0;
    tasks[cur].sig_mask     = 0;
    tasks[cur].sig_altstack_sp   = 0;   /* a fresh image has no alternate signal stack */
    tasks[cur].sig_altstack_size = 0;
    tasks[cur].sig_on_stack      = 0;
    tasks[cur].spawn_arg    = 0;
    tasks[cur].argc         = 0;
    tasks[cur].argv_ptr     = 0;
    create_user_pagedir(cur);

    load_staged_image_into(cur, load_base);   /* sets eip/heap/name, disarms */

    /* Marshal any staged argv onto the freshly-built stack (load_staged_image_into
     * left `cur` current, so copy_to_user targets its new address space); this
     * lowers tasks[cur].esp below the argv block before the frame is fabricated. */
    build_child_argv(cur);

    /* Enter the new image the same way spawn / the timer / the exit-switch enter
     * a task: fabricate a fresh ring-3 trap frame (IF set, zeroed GP regs, ring-3
     * selectors) and hand it to the ISR epilogue via saved_ksp. A hand-rolled
     * lretq from inside the syscall ISR runs with interrupts off and the wrong
     * initial context; this reuses the proven resume path instead. interrupt_
     * handler64 takes THIS CPU's armed re-entry and switches CR3 + kernel stack + resumes
     * the fabricated frame. Runs with the kernel CR3 still active; the switch to
     * tasks[cur].cr3 happens in exec_reenter_switch before the iretq. */
    uint64_t new_eip = tasks[cur].eip;
    uint64_t new_esp = tasks[cur].esp ? (uint64_t)tasks[cur].esp : 0x007ff000ULL;
    sched_prepare_user_context(cur, new_eip, new_esp);
    exec_reenter_arm(cur);
    /* No return value is written. `r` IS the fabricated frame -- sched_prepare_
     * user_context built the new ring-3 context over this same memory (top of
     * the task's kernel stack), so a store to r->rax would land on the new
     * image's initial rax rather than on a caller that no longer exists. This
     * used to write 0 into a throwaway 32-bit copy of the frame; with the
     * handler operating on the real frame it would be writing the new context. */
}

/* SYS_EXEC_NAMED (64): replace the caller's image with a named embedded binary.
 * Resolve+arm the name and stage argv while the caller's address space is still
 * live (a bad name fails cleanly, image intact), then hand off to the shared
 * exec tail. Capability (slot 3, WRITE|EXEC) is enforced centrally by the table. */
void h_exec_named(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    if (!r->rbx) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    char name[32];
    uint32_t len = r->rcx ? r->rcx : 31u;
    if (len > 31) len = 31;
    if (copy_from_user(name, (void *)(addr_t)r->rbx, len) != 0) {
        r->rax = (uint32_t)SYS_ERR_FAULT;
        return;
    }
    name[len] = 0;

    /* From here to the release below, this CPU owns the staging (roadmap 1.7):
     * the armed image, the argv, and the header they are described by. The
     * bracket starts BEFORE the arm, because arming is half of what is being
     * serialised -- an arm that lands inside another CPU's window is exactly the
     * interleaving this closes. */
    spawn_stage_acquire();
    if (arm_named_binary(name) != 0) {
        spawn_stage_release();
        r->rax = (uint32_t)SYS_ERR_NOENT;
        return;
    }

    /* Stage the new argv (esi = user char* array, edi = argc) NOW, while the
     * caller's old address space is still active so copy_from_user can read the
     * strings; it is marshalled onto the fresh stack after the rebuild. */
    stage_spawn_args(r->rsi, r->rdi);

    exec_into_armed_image();   /* consumes the staging; no clean return on success */
    /* Reached with the new image's ring-3 context already fabricated and armed:
     * exec_into_armed_image returns to us, and the ISR epilogue -- not this
     * function -- performs the switch. The staged state is consumed by now, so
     * the window is over and the release is on the CPU that acquired. */
    spawn_stage_release();
}

/* SYS_EXEC_IMAGE (71): replace the caller's image with a program image the caller
 * supplies in its own memory (execve-from-fd — the caller read it from a file via
 * the fs_server). Validate+arm the image and stage argv while the caller's
 * address space is still live (a bad image fails cleanly, image intact), then
 * hand off to the shared exec tail. ebx=image, ecx=len, esi=argv, edi=argc.
 * Capability (slot 3, WRITE|EXEC) is enforced centrally by the table. */
void h_exec_image(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    spawn_stage_acquire();
    int rc = arm_image_from_user(r->rbx, r->rcx, 0);
    if (rc != 0) {                                   /* image intact on failure */
        spawn_stage_release();
        r->rax = (uint32_t)SYS_ERR_INVAL;
        return;
    }

    /* Stage argv while the caller's old address space is still active. */
    stage_spawn_args(r->rsi, r->rdi);

    exec_into_armed_image();   /* consumes the staging; no clean return on success */
    spawn_stage_release();
}

/* SYS_SPAWN_IMAGE (70): spawn a child from a program image the caller supplies in
 * its own memory (execve-from-fd, spawn form). Mirrors h_spawn but arms the
 * loader from the caller's buffer instead of a named embedded binary.
 * ebx=image, ecx=len, edx=one-word spawn arg, esi=argv, edi=argc. Returns the
 * child pid, or a negative SYS_ERR_*. Slot-3 WRITE|EXEC enforced by the table. */
void h_spawn_image(struct interrupt_frame64 *r) {
    spawn_stage_acquire();
    int rc = arm_image_from_user(r->rbx, r->rcx, 0);
    if (rc != 0) {
        spawn_stage_release();
        r->rax = (uint32_t)SYS_ERR_INVAL;
        return;
    }

    /* Stage the caller's argv before the child exists; do_spawn_inner marshals it
     * onto the child's stack. Read here while the caller is still current. */
    stage_spawn_args(r->rsi, r->rdi);
    /* Pipe-stdio redirection (r8, the 6th syscall arg): passed down to
     * wire_child_stdio, which wires the child's fd0/fd1 to THIS caller's pipe
     * ends. 0 = console default. It travels as an argument rather than in a
     * global for the reason wire_child_stdio's header note gives. */
    int pid = do_spawn_stdio((uint32_t)r->r8);   /* consumes the armed image */
    g_args_argc = 0;            /* drop staging if the spawn failed before consuming it */
    spawn_stage_release();
    if (pid > 0 && pid < MAX_TASKS) tasks[pid].spawn_arg = r->rdx;
    r->rax = (uint32_t)pid;
}


void h_spawn(struct interrupt_frame64 *r) {
    char name[32];
    if (r->rbx) {
        uint32_t len = r->rcx ? r->rcx : 31u;
        if (len > 31) len = 31;
        /* Read the name BEFORE taking the staging lock: copy_from_user can fault
         * on a bad pointer, and there is nothing to serialise until an image is
         * about to be armed. Keeping the fault outside the critical section also
         * keeps the section short enough to reason about. */
        if (copy_from_user(name, (void *)(addr_t)r->rbx, len) != 0) {
            r->rax = (uint32_t)SYS_ERR_FAULT;
            return;
        }
        name[len] = 0;
    }
    spawn_stage_acquire();
    if (r->rbx) {
        int rc = arm_named_binary(name);
        if (rc != 0) {
            spawn_stage_release();
            r->rax = (uint32_t)SYS_ERR_NOENT;
            return;
        }
    }
    /* Stage the caller's argv (esi = user char* array, edi = argc) before the
     * child exists; do_spawn_inner marshals it onto the child's stack. Read here
     * while the caller is still current so copy_from_user hits its memory. */
    stage_spawn_args(r->rsi, r->rdi);
    int pid = do_spawn();
    g_args_argc = 0;   /* drop staging if the spawn failed before consuming it */
    spawn_stage_release();
    /* Hand the child its one-word spawn argument (edx), retrievable via
     * SYS_SPAWN_ARG. Zero for callers that don't pass one. */
    if (pid > 0 && pid < MAX_TASKS) tasks[pid].spawn_arg = r->rdx;
    /* Don't switch to the child here: do_spawn returns with the caller restored
     * as the current task, and the child (runnable) is picked up by the timer.
     * The old cooperative schedule() mis-handles a ring-3 caller mid-syscall. */
    r->rax = (uint32_t)pid;
}

/* SYS_SPAWN_ARG (68): return the one-word argument this task was spawned with. */
void h_spawn_arg(struct interrupt_frame64 *r) {
    r->rax = tasks[get_current_task()].spawn_arg;
}

/* SYS_GET_ARGV (69): return this task's argc and write the argv[] base (a user
 * vaddr into its own stack) to *ebx. argc 0 / argv 0 when spawned without args. */
void h_get_argv(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    /* 8 bytes, and a uint64_t to hold it: the caller's out-parameter is a
     * `char **`, which is 8 bytes wide in 64-bit userspace. Narrowing this to
     * uint32_t and copying 4 wrote only the low half of the pointer and left the
     * caller's high half untouched — correct only while the argv block happened
     * to sit below 4 GiB (it is built on the low stack), and silently wrong for
     * any argv placed higher. */
    uint64_t argv_ptr = tasks[cur].argv_ptr;
    if (r->rbx) copy_to_user((void *)(addr_t)r->rbx, &argv_ptr, sizeof(argv_ptr));
    r->rax = tasks[cur].argc;
}

/* SYS_GETUID (29). */

