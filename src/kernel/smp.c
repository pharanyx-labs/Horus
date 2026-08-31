/* smp.c -- SMP application-processor bringup, LAPIC, and TLB shootdown.
 *
 * Split out of scheduler.c: the BSP-side AP boot sequence (trampoline staging +
 * INIT-SIPI-SIPI), per-CPU LAPIC timer, and the cross-CPU TLB-shootdown
 * protocol. smp_bringup() is the always-compiled entry (called from main.c); the
 * multi-core machinery below it is gated on SMP=1. The scheduling hot paths that
 * consume this (preempt_on_tick, ipc_block_switch, ...) live in scheduler.c.
 */
#include "kernel.h"

/* Defined in scheduler.c (the scheduling core). */
int this_cpu(void);
int this_cpu_lapic(void);
#ifdef SMP
void percpu_id_verify_self(void);
extern volatile unsigned percpu_id_verified;
extern int *task_running_cpu;
extern volatile int smp_sched_enabled;   /* scheduler.c: master switch for the SMP branch */
/* scheduler.c: "this CPU is parked in an idle loop and holds no task context".
 * preempt_on_tick consults it to decide whether a ring-0 tick may switch this CPU
 * away: an idle context has nothing worth preserving, any other ring-0 context
 * does. An AP that parks without setting this would take ring-0 ticks that the
 * scheduler declines to act on, and would therefore never pull work at all. */
extern int percpu_idle[MAX_CPUS];
#endif

/* ===== SMP: application-processor bringup ================================== *
 * The BSP copies the real-mode trampoline (src/boot/ap_trampoline.S) to
 * AP_TRAMP_PHYS, publishes three qword cells the trampoline consumes, then wakes
 * every AP at once with a broadcast INIT-SIPI-SIPI ("all excluding self", so no
 * APIC-id enumeration / MADT parse is needed).  Each AP walks itself up to long
 * mode, picks a private idle stack by LAPIC id, and enters ap_entry64().  All of
 * this is gated on SMP=1; the default build is single-CPU and never wakes an AP.
 *
 * smp_cpus_online counts CPUs that finished bringup (BSP starts it at 1) and is
 * the source of truth for smp_get_online_count() and the TLB-shootdown path. */
static volatile int smp_cpus_online = 1;

/* SMT sibling threads that were brought up but PARKED (never scheduled) to avoid
 * side-channel co-residency — see ap_entry64. They still service TLB-shootdown
 * IPIs, so they count toward the shootdown ack total even though they run no
 * tasks: `present = online + parked` is the set of CPUs the all-excluding-self
 * broadcast reaches. */
static volatile int smp_siblings_parked = 0;

/* Is `apic_id` a secondary (sibling) SMT thread? True when the low SMT bits of the
 * APIC id are non-zero (platform.smt_shift from CPUID leaf 0x0B). The primary
 * thread of every core has those bits zero, so exactly one thread per core (and
 * always the BSP, apic 0) is schedulable. */
static int apic_is_smt_sibling(uint32_t apic_id) {
    int shift = platform.smt_shift;
    if (shift <= 0) return 0;
    return (apic_id & ((1u << (unsigned)shift) - 1u)) != 0;
}

/* Set once the local APIC is up on the BSP (so this_cpu() is safe to call).
 * Gates the per-CPU TSS routing in set_tss_kernel_stack(); stays 0 in the
 * single-CPU default build. Read by gdt.c. */
volatile int smp_active = 0;

/* Low-memory cells shared with the trampoline. MUST match ap_trampoline.S.
 * (AP_TRAMP_PHYS itself lives in kernel.h — paging.c needs it too, to keep that
 * one page of the identity map alive for the trampoline to execute from.) */
#define AP_STACK_BASE_CELL   0x8FD8UL
#define AP_CR3_CELL          0x8FE0UL
#define AP_ENTRY_CELL        0x8FE8UL
/* Per-CPU ring-0 idle/park slot: one guard page plus KERNEL_STACK_SIZE of usable
 * stack, so the space a parked CPU gets is exactly what it got on task 0's stack
 * before the [G-8] park fix moved it here.
 *
 * It was 0x4000 (16 KiB, no guard). Placing the guard inside the slot on
 * 2026-08-17 left 12 KiB usable and produced `PANIC: stack smashing detected` at a
 * 40% rate on a task-killing SMP workload; measured, the same build with the guard
 * unarmed (16 KiB usable) produced zero smashes in 20 boots. Taking 4 KiB from a
 * stack while simultaneously routing a new path onto it was the mistake, and the
 * honest correction is to stop economising: the park path had KERNEL_STACK_SIZE
 * before, so it has KERNEL_STACK_SIZE now.
 *
 * DUPLICATED IN src/boot/ap_trampoline.S, which computes each AP's initial stack
 * top as base + (apic_id + 1) * AP_IDLE_STACK_SIZE and cannot include this header.
 * The _Static_assert below pins the two; if it fires, update the assembly. */
#define AP_IDLE_STACK_SIZE   (0x1000UL + KERNEL_STACK_SIZE)

static inline void lapic_write(uint32_t reg, uint32_t val) {
    volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
    lapic[reg / 4] = val;
}
static inline uint32_t lapic_read(uint32_t reg) {
    volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
    return lapic[reg / 4];
}

/* Enable the local APIC: clear the task-priority register (accept every vector)
 * and set the spurious-interrupt vector register (enable bit 8 + vector 0xFF).
 * Run once by the BSP and once by every AP. */
static void lapic_enable(void) {
    lapic_write(0x80, 0);                                    /* TPR = 0 */
    lapic_write(0xF0, (lapic_read(0xF0) & 0xFFFFFF00) | 0x100 | 0xFF);
}

static void lapic_enable_bsp(void) { lapic_enable(); }

/* Signal end-of-interrupt to the local APIC (write 0 to the EOI register).
 * Called from the vector-0x40 LAPIC-timer path in idt.c. */
void lapic_eoi(void) { lapic_write(0xB0, 0); }

#ifdef SMP
/* Bounded pause-spin. Only the AP-bringup and TLB-shootdown paths use it, both
 * SMP-only, so it lives inside the guard (an SMP=0 build would flag it unused). */
static void smp_busy_delay(int iters) {
    for (volatile int d = 0; d < iters; d++) __asm__ volatile ("pause");
}

/* Per-CPU idle stacks. APs index by LAPIC id (see ap_trampoline.S), so MAX_CPUS
 * slots cover ids 0..MAX_CPUS-1; slot 0 (the BSP's) is unused on this path.
 * An AP whose id has no slot parks in the trampoline rather than running off
 * the end of this array. */
/* Per-CPU ring-0 idle stacks. Slot `c` is [guard page][stack], and the trampoline
 * and ap_idle_stack_top() both compute the TOP as base + (c+1)*AP_IDLE_STACK_SIZE,
 * so the guard lives in the slot's FIRST page rather than being prepended to it --
 * the arithmetic on both sides stays a single stride from the array base. Usable
 * stack is KERNEL_STACK_SIZE; the guard is the 4 KiB below it.
 *
 * These stacks had NO guard until 2026-08-17, which made SECURITY.md's S9 ("an
 * unmapped guard page below every kernel stack") false: every CPU parked here by
 * enter_cpu_idle() was running ring-0 code, and taking interrupts, on an
 * unguarded stack whose neighbour is another CPU's idle stack. The array is
 * page-aligned so every guard is a whole page kern_arm_guard_page() can clear,
 * exactly as ap_ist[] in gdt.c and per_task_kstacks[] in paging.c already are. */
static uint8_t ap_idle_stacks[MAX_CPUS][AP_IDLE_STACK_SIZE]
    __attribute__((aligned(4096)));
uint32_t ap_idle_guards_armed = 0;

/* Guard page of CPU `cpu`'s idle stack: the low page of its slot. */
static uint8_t *ap_idle_guard(int cpu) {
    if (cpu < 0 || cpu >= MAX_CPUS) cpu = 0;
    return &ap_idle_stacks[0][0] + (uintptr_t)cpu * AP_IDLE_STACK_SIZE;
}

/* Unmap the guard page below every per-CPU idle stack. Called once at boot from
 * paging_init(), before smp_bringup(), so the cleared entries are inherited into
 * each AP's CR3 with no shootdown -- the same one-pass arming kstack_guards_init()
 * and ap_ist_guards_init() do. Slot 0 is armed too: it is the BSP's, and the BSP
 * parks here like every other CPU. */
void ap_idle_guards_init(void) {
    extern int kern_arm_guard_page(uint64_t vaddr);
    for (int c = 0; c < MAX_CPUS; c++)
        if (kern_arm_guard_page((uint64_t)(uintptr_t)ap_idle_guard(c)) == 0)
            ap_idle_guards_armed++;
}

#ifdef WX_SELFTEST
/* Gated: enumerate the idle-stack guards so smoke-wx can assert each is absent
 * while the stack page just above it stays present. */
uint32_t ap_idle_guard_count(void) { return (uint32_t)MAX_CPUS; }
uint64_t ap_idle_guard_vaddr(int i) { return (uint64_t)(uintptr_t)ap_idle_guard(i); }
#endif

/* ap_trampoline.S bounds the LAPIC id against its own AP_MAX_CPUS: it is
 * assembled with -x assembler-with-cpp and cannot include a header full of C
 * declarations, so the value is duplicated there. Pin the two together — if
 * this fires, update AP_MAX_CPUS in src/boot/ap_trampoline.S to match. */
_Static_assert(MAX_CPUS == 4,
               "MAX_CPUS changed: update AP_MAX_CPUS in src/boot/ap_trampoline.S to match");
/* The trampoline strides the idle-stack array by this value in assembly, where it
 * is a literal. Nothing detected a mismatch before: the size was duplicated with
 * no assertion at all, so changing it on one side alone would hand every AP a
 * stack overlapping its neighbour's -- silently, and at bringup, before anything
 * can report. Pinned now, in the same shape as the MAX_CPUS assert above. */
_Static_assert(AP_IDLE_STACK_SIZE == 0x11000UL,
               "AP_IDLE_STACK_SIZE changed: update the literal in "
               "src/boot/ap_trampoline.S to match");

extern uint8_t ap_trampoline_start[], ap_trampoline_end[];
extern void ap_load_kernel_segments(void);   /* lowlevel64.S */
void ap_load_idt(void);                       /* idt.c */
void setup_ap_tss(int cpu, uintptr_t rsp0);   /* gdt.c */

/* Count of LAPIC-timer ticks taken across all APs — the SMP self-test reads it
 * to confirm the APs are actually being interrupted (and thus preemptible). */
volatile unsigned long ap_timer_ticks = 0;

/* LAPIC timer registers + the calibrated initial count for a ~100 Hz tick. */
#define LAPIC_TIMER_LVT    0x320
#define LAPIC_TIMER_INIT   0x380
#define LAPIC_TIMER_CUR    0x390
#define LAPIC_TIMER_DIV    0x3E0
#define LAPIC_TIMER_VECTOR 0x40
static uint32_t lapic_timer_count = 0;

/* Measure the LAPIC timer frequency against PIT channel 2 (a one-shot mode-0
 * countdown gated on port 0x61) and record the count for a ~10 ms period. Run
 * once on the BSP before the APs start their periodic timers. */
static void lapic_timer_calibrate(void) {
    lapic_write(LAPIC_TIMER_DIV, 0x3);                       /* divide by 16 */
    lapic_write(LAPIC_TIMER_LVT, (1u << 16) | LAPIC_TIMER_VECTOR);  /* masked */

    uint8_t p61 = inb(0x61);
    outb(0x61, (uint8_t)((p61 & 0xFD) | 0x01));   /* gate2 on, speaker off */
    outb(0x43, 0xB0);                              /* ch2, lo/hi, mode 0 */
    uint16_t cnt = 11932;                          /* ~10 ms @ 1.193182 MHz */
    outb(0x42, (uint8_t)(cnt & 0xFF));
    outb(0x42, (uint8_t)(cnt >> 8));

    lapic_write(LAPIC_TIMER_INIT, 0xFFFFFFFFu);    /* start LAPIC countdown */
    while (!(inb(0x61) & 0x20)) { }                /* wait for PIT OUT2 high */
    uint32_t remaining = lapic_read(LAPIC_TIMER_CUR);
    lapic_write(LAPIC_TIMER_INIT, 0);              /* stop */

    lapic_timer_count = 0xFFFFFFFFu - remaining;   /* ticks in ~10 ms => 100 Hz */
    if (lapic_timer_count < 1000) lapic_timer_count = 1000000;  /* sane fallback */
}

/* Start this CPU's LAPIC timer in periodic mode at the calibrated rate. */
static void lapic_timer_start_periodic(void) {
    lapic_write(LAPIC_TIMER_DIV, 0x3);                              /* divide by 16 */
    lapic_write(LAPIC_TIMER_LVT, (1u << 17) | LAPIC_TIMER_VECTOR);  /* periodic */
    lapic_write(LAPIC_TIMER_INIT, lapic_timer_count ? lapic_timer_count : 1000000);
}

/* The AP idle context: sit with interrupts enabled so the LAPIC timer keeps
 * firing. Each tick runs preempt_on_tick(), which pulls a runnable task onto
 * this CPU when one is available. Reached both as the AP's initial context and
 * whenever it has no task to run. */
void ap_idle_loop(void) {
    for (;;) __asm__ volatile ("sti; hlt");
}

/* Top (highest address) of CPU `cpu`'s idle stack — the one ap_entry64 handed it.
 * Reused by the scheduler when a running CPU must drop back to idle mid-operation
 * (a task blocked with no peer to switch to): the CPU returns to ap_idle_loop on
 * this stack and lets a timer tick reschedule the woken task. Slot 0 is the BSP's;
 * it is otherwise unused on the AP path, so the BSP idles here too. */
uint8_t *ap_idle_stack_top(int cpu) {
    if (cpu < 0 || cpu >= MAX_CPUS) cpu = 0;
    return &ap_idle_stacks[0][0] + (uintptr_t)(cpu + 1) * AP_IDLE_STACK_SIZE;
}

/* The ring-0 stack CPU `cpu` parks on when the last task it was running dies.
 * Per-CPU, and that is the whole point: all three fault/exit fallbacks in idt.c
 * used tasks[0].kernel_stack_top, one stack shared by every CPU taking the path.
 * Measured on a task-killing workload at -smp 4, the path is entered 5-8 times a
 * boot and two CPUs were parked on that one stack 2-3 times a boot. This is the
 * same stack enter_cpu_idle() already parks on, so the fault path now joins the
 * kernel's one park mechanism instead of hand-rolling a worse second one. */
uint64_t ap_park_stack_top(int cpu) {
    return (uint64_t)(uintptr_t)ap_idle_stack_top(cpu);
}

/* 64-bit C entry for every AP, reached from the trampoline on the AP's private
 * idle stack.  Adopt the shared kernel GDT/IDT, install a per-CPU TSS (own RSP0
 * + IST fault stacks), enable the local APIC + its periodic timer, check in, and
 * drop into the idle loop where timer ticks drive the scheduler. */
void ap_entry64(void) {
    ap_load_kernel_segments();    /* shared kernel GDT: CS=0x08, data=0x10 */
    ap_load_idt();                /* shared kernel IDT */

    /* CR4 protection bits are per-CPU: the BSP set SMEP/SMAP/UMIP/TSD in its own
     * CR4 (cpu_enable_protections, from kernel_main), but an AP comes out of the
     * trampoline with none of them. Without this an AP would run ring-3 tasks
     * with SMEP/SMAP off and ring-3 RDTSC allowed — a silent hole that only opens
     * under SMP. platform.has_* was filled by the BSP's feature detection before
     * any AP started, so this sets the same bits the BSP has. */
    cpu_enable_protections();

    /* TR is still 0 here -- this AP has no TSS yet -- so this_cpu() answers from
     * the LAPIC, which is exactly the bootstrap case its fallback exists for. */
    int cpu = this_cpu();
    uintptr_t idle_top = (uintptr_t)ap_idle_stack_top(cpu);
    setup_ap_tss(cpu, idle_top);  /* per-CPU TSS + IST, ltr'd */

    /* TR now holds this AP's selector, so this_cpu() switches to the STR path.
     * Confirm on this core that it agrees with the LAPIC before anything relies
     * on it -- from here on every get_current_task() here trusts the derivation. */
    percpu_id_verify_self();

    lapic_enable();

    /* SMT sibling policy: to prevent side-channel co-residency (a sibling thread
     * shares the core's L1/L2 with the primary, which the time-slice flush-on-
     * switch cannot cover), a secondary thread is PARKED here — it never starts
     * its scheduler timer and never enters the scheduler, so no ring-3 task ever
     * runs on it and its core-partner (the primary thread) does all the work.
     * It stays TLB-coherent and serviceable: the LAPIC is enabled and interrupts
     * are ON, so TLB-shootdown IPIs are handled (and acked) here; only the LOCAL
     * timer that would drive scheduling is left off. This is "disable SMT" done in
     * software, without needing to suppress the AP in firmware. */
    if (apic_is_smt_sibling((uint32_t)cpu)) {
        /* Parked and holding no task, like any other idle CPU. This one never
         * starts its timer so preempt_on_tick never runs here, but the flag is
         * the honest description of the state and keeps the claim invariant
         * (scheduler.c) uniform across every parked CPU. */
        percpu_idle[cpu] = 1;
        __sync_fetch_and_add(&smp_siblings_parked, 1);
        for (;;) __asm__ volatile ("sti; hlt");
    }

    /* Mark this CPU idle BEFORE starting its timer. preempt_on_tick only lets a
     * ring-0 tick switch a CPU away when the CPU is idle-parked; an AP that
     * reached its idle loop without this flag would decline every tick and sit
     * there forever with runnable work available. Setting it before the timer
     * starts closes the window where the first tick could arrive and find the
     * CPU describing itself as busy. set_current_task() clears it the moment
     * this CPU picks up a real task. */
    percpu_idle[cpu] = 1;

    lapic_timer_start_periodic();

    __sync_fetch_and_add(&smp_cpus_online, 1);

    ap_idle_loop();               /* timer ticks now schedule tasks onto this CPU */
}

/* Broadcast INIT then two SIPIs to "all excluding self" (ICR destination
 * shorthand 0b11).  Wakes every AP without an APIC-id list. */
static void lapic_broadcast_init_sipi(uint8_t vector) {
    lapic_write(0x300, 0x000C4500);                /* INIT assert, all-excl-self */
    smp_busy_delay(500000);                        /* ~10 ms settle */
    lapic_write(0x300, 0x000C4600 | vector);       /* SIPI #1 */
    smp_busy_delay(50000);
    lapic_write(0x300, 0x000C4600 | vector);       /* SIPI #2 (spec: send twice) */
    smp_busy_delay(50000);
}

/* Bring up the APs and wait for exactly `expected_cpus` (BSP + APs) to check in.
 * `expected_cpus` comes from the ACPI MADT (see smp_bringup), so the wait ends as
 * soon as the real cores are online instead of stalling for a fixed MAX_CPUS that
 * may never appear. Only called when expected_cpus > 1. */
static void smp_start_aps(int expected_cpus) {
    /* Calibrate the LAPIC timer once (on the BSP, using the PIT) so every AP can
     * start its periodic timer at a known ~100 Hz rate. */
    lapic_timer_calibrate();

    /* Stage the trampoline at its real-mode SIPI load address. AP_TRAMP_PHYS is
     * a PHYSICAL address — an AP starts in real mode and can only be pointed at
     * low memory — so write it through the higher-half alias rather than treating
     * the number as a virtual address. (The low identity map still resolves it,
     * but the kernel no longer lives there and should not address through it.) */
    uint8_t *dst = (uint8_t *)PHYS_KVA(AP_TRAMP_PHYS);
    uint32_t n = (uint32_t)(ap_trampoline_end - ap_trampoline_start);
    for (uint32_t i = 0; i < n; i++) dst[i] = ap_trampoline_start[i];

    /* Publish the cells the trampoline reads (CR3, entry, idle-stack base).
     * CR3 is already physical. The entry and stack are kernel VAs, and stay
     * virtual: the trampoline consumes them with 64-bit loads *after* it has
     * enabled paging on this very CR3, so the higher half is live by then. */
    uint64_t cr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(cr3));
    *(volatile uint64_t *)PHYS_KVA(AP_CR3_CELL)        = cr3;
    *(volatile uint64_t *)PHYS_KVA(AP_ENTRY_CELL)      = (uint64_t)(uintptr_t)&ap_entry64;
    *(volatile uint64_t *)PHYS_KVA(AP_STACK_BASE_CELL) = (uint64_t)(uintptr_t)&ap_idle_stacks[0][0];
    __asm__ volatile ("mfence" ::: "memory");

    lapic_broadcast_init_sipi((uint8_t)(AP_TRAMP_PHYS >> 12));   /* vector 0x08 */

    /* Wait (bounded) for the APs to check in. The loop exits the instant every
     * expected CPU is online, so an accurate MADT count means no wasted spinning;
     * the 200-iteration cap is only a backstop for a core that never appears. */
    for (int spins = 0;
         spins < 200 && (smp_cpus_online + smp_siblings_parked) < expected_cpus;
         spins++)
        smp_busy_delay(20000);

    kmsg_begin();
    print("smp: ");
    print_decimal((uint64_t)smp_cpus_online);
    print(" cores online");
    if (smp_siblings_parked > 0) {
        print(", ");
        print_decimal((uint64_t)smp_siblings_parked);
        print(" SMT siblings parked (co-residency avoided)");
    }
    print("\n");
}
#endif /* SMP */

void smp_bringup(void) {
    lapic_enable_bsp();
#ifdef SMP
    /* LAPIC is mapped (paging_init) and now enabled, so this_cpu() is safe and
     * per-CPU TSS routing can turn on before any AP or context switch runs. */
    smp_active = 1;

    /* The BSP's TSS (selector 0x38) was ltr'd by setup_tss64 in the boot asm, so
     * its STR path is already live; this is the first point the LAPIC oracle is
     * safe to read, which is what the check needs to compare against. */
    percpu_id_verify_self();

    /* No task is running on any CPU yet. Done unconditionally (before the count
     * branch) because the BSP's own preempt_on_tick consults task_running_cpu[]
     * even when there are no APs — leaving it zero would read as "task N running
     * on CPU 0" and break single-CPU scheduling. */
    for (int i = 0; i < g_max_tasks; i++) task_running_cpu[i] = -1;

    /* Ask ACPI how many CPUs actually exist. On success we wake and wait for
     * exactly that many; a uniprocessor skips AP bringup entirely (no trampoline
     * staging, no INIT-SIPI, no wait). If the MADT can't be parsed, fall back to
     * the old conservative broadcast that assumes up to MAX_CPUS. */
    uint8_t apic_ids[MAX_CPUS];
    int ncpu = acpi_detect_cpus(apic_ids, MAX_CPUS);
    if (ncpu < 1) {
        kmsg("smp: ACPI MADT unreadable, assuming up to MAX_CPUS");
        ncpu = MAX_CPUS;
    } else if (ncpu > MAX_CPUS) {
        /* More CPUs than we have idle-stack slots for: cap here; any AP whose
         * LAPIC id lands outside the array parks in the trampoline (see
         * ap_trampoline.S), so this only forgoes their compute, never faults. */
        kmsg("smp: MADT reports more CPUs than MAX_CPUS, capping");
        ncpu = MAX_CPUS;
    }

    if (ncpu > 1) {
        smp_start_aps(ncpu);
    } else {
        kmsg("smp: uniprocessor, 1 CPU, no APs to start");
    }

    /* Turn on the SMP scheduler now that every AP is parked in its idle loop and
     * the runnable pool is consistent. Until this is set, preempt_on_tick's SMP
     * branch is a no-op, so the online APs would sit idle and the BSP would never
     * preempt a ring-3 task — the whole system would run cooperatively on one CPU.
     * Actual preemption still waits for preempt_enabled (set as the shell starts),
     * so setting it here only arms the mechanism; it does not switch anything yet. */
    smp_sched_enabled = 1;

#ifdef PERCPU_SELFTEST
    /* Gated: every AP has now run percpu_id_verify_self() on itself during
     * bringup, so the witness bitmask is complete and can be checked for gaps.
     * Prints and boot continues; make smoke-percpu asserts on the marker. */
    percpu_selftest();
#endif
#endif

#ifdef IRQ_POLICY_AUDIT
    irq_milestone("kernel-ready");
    irq_policy_report("kernel-ready");
#endif
    kmsg("kernel ready, starting init (PID 1)");
#ifdef PREEMPT_SELFTEST
    /* Gated: spawn two non-yielding ring-3 tracers and prove the timer
     * time-slices them (prints PREEMPT_SELFTEST: PASS). Does not return -- it
     * launches into ring 3 and the tasks run forever. */
    preempt_selftest();
#elif defined(SIGNAL_SELFTEST)
    /* Gated: spawn a task that faults on purpose and prove its registered
     * handler runs instead of the task being killed (SIGNAL_SELFTEST: PASS). */
    signal_selftest();
#elif defined(TSD_SELFTEST)
    /* Gated: spawn a task that executes RDTSC and prove it #GPs under CR4.TSD,
     * landing in its fault handler instead of returning a timestamp
     * (TSD_SELFTEST: PASS). */
    tsd_selftest();
#elif defined(FS_SELFTEST)
    /* Gated: spawn the userspace fs_server plus a client that drives it over
     * IPC (mkdir/create/write/read/readdir/lookup/delete) against the kernel's
     * encrypted object store, proving the Phase 2 stack end-to-end
     * (prints FS_SELFTEST: PASS). */
    fs_selftest();
#elif defined(WAL_CRASHTEST)
    /* Gated: two-boot journal crash-recovery test. Boot 1 commits a write then
     * halts before applying it; boot 2 replays the committed transaction at mount
     * and confirms the data survived (prints WAL_CRASHTEST: PASS). */
    { extern void wal_crashtest(void); wal_crashtest(); }
#elif defined(NEWLIB_SELFTEST)
    /* Gated: spawn hello_newlib (newlib + posix + malloc on Horus) and confirm
     * printf/sprintf/malloc/string ops all work end-to-end (prints
     * NEWLIB_SELFTEST: PASS to serial). */
    newlib_selftest();
#elif defined(BIGFILE_SELFTEST)
    /* Gated: write blocks across the direct / single-indirect / double-indirect
     * mapping regions of one inode and read them back, proving large-file
     * (double-indirect) support on the encrypted object store (prints
     * BIGFILE_SELFTEST: PASS to serial). */
    bigfile_selftest();
#elif defined(SMP_SELFTEST)
    /* Gated: spawn a pool of forever-looping workers and prove the application
     * processors pull and run them concurrently (prints SMP_SELFTEST: PASS). */
    smp_selftest();
#elif defined(PROC_SELFTEST)
    /* Gated: drive SYS_EXIT + SYS_KILL from ring 3 and confirm both children
     * reach the dead state (prints PROC_SELFTEST: PASS). */
    proc_selftest();
#elif defined(NOTIFY_SELFTEST)
    /* Gated: a waiter blocks in SYS_WAIT_NOTIFY and a sender fires a badge with
     * SYS_NOTIFY; prove the badge round-trips to userspace (NOTIFY_SELFTEST: PASS). */
    notify_selftest();
#elif defined(KLOG_FORGE_SELFTEST)
    /* Gated: a ring-3 task endowed with CAP_KERNEL_LOG (READ) floods SYS_WRITE
     * fd 1 with more bytes than the kernel message ring holds, and proves the
     * ring took none of them and lost nothing it already had (KLOGTEST: PASS).
     * The witness for [H-2]; falsified by KLOG_WRITE_UNGATED=1. */
    klog_forge_selftest();
#elif defined(MAPPHYS_SELFTEST)
    /* Gated: a ring-3 task endowed with CAP_IO_DEVICE maps the allowlisted VGA
     * framebuffer into its own address space and round-trips a cell through it,
     * proving the SYS_MAP_PHYS device-delegation path (MAPPHYS_SELFTEST: PASS).
     * First driver-privilege-separation job; see docs/design/console-server.md. */
    mapphys_selftest();
#elif defined(SHLIBC_SELFTEST)
    /* Gated: the REAL shared libc -- newlib plus its port glue in one object --
     * loaded once into frames, mapped by a ring-3 task that calls into it
     * (LIBCTEST: PASS). Roadmap 2.5's remaining claim; the property tests for the
     * mechanism itself live under SHLIB_SELFTEST below. */
    shlibc_selftest();
#elif defined(SHLIB_SELFTEST)
    /* Gated: one shared library, loaded once into frames, mapped read+exec by two
     * tasks that each execute it and neither of which can write it
     * (SHLIBTEST: PASS). Roadmap 2.5's mechanism; falsified by
     * SHLIB_TEXT_WRITABLE. */
    shlib_selftest();
#elif defined(NET_SELFTEST)
    /* Gated: a ring-3 virtio-net driver whose whole authority is one device
     * capability and one untyped region completes an ARP exchange on the wire
     * (NETTEST: PASS). Roadmap 2.6; falsified by NET_NO_BUSMASTER and
     * NET_DMA_ADDR_VIRTUAL. */
    net_selftest();
#elif defined(DEVCAP_SELFTEST)
    /* Gated: a ring-3 task holding TWO device capabilities proves each reaches
     * only its own device's frames, ports and IRQ (DEVCAPTEST: PASS). The witness
     * that CAP_IO_DEVICE names a device rather than conferring the console;
     * falsified by IO_DEVICE_OBJECT_UNCHECKED / _PORTS_GLOBAL / _IRQ_UNCHECKED. */
    devcap_selftest();
#elif defined(IOPORT_SELFTEST)
    /* Gated: a ring-3 task endowed with CAP_IO_DEVICE is granted native port I/O
     * (SYS_IOPORT_GRANT / TSS I/O bitmap); an allowlisted port succeeds and a
     * non-allowlisted port #GPs (IOPORT_SELFTEST: PASS). Second
     * driver-privilege-separation job; see docs/design/console-server.md. */
    ioport_selftest();
#elif defined(IRQ_SELFTEST)
    /* Gated: a ring-3 task endowed with CAP_IO_DEVICE routes the timer IRQ to a
     * notification (SYS_IRQ_REGISTER) and a real hardware interrupt wakes it with
     * the registered badge (IRQ_SELFTEST: PASS). Third driver-privilege-separation
     * job; see docs/design/console-server.md. */
    irq_selftest();
#elif defined(TUI_SELFTEST)
    /* Gated: console_server plus a client that drives libhorus's TUI against its
     * own buffers. Asserts what a screen cannot show -- that a one-cell change
     * costs a handful of bytes rather than a repaint, that an out-of-range write
     * is discarded, and that a truncated escape sequence yields a key instead of
     * a wait. TUITEST: PASS. Falsified by TUI_NO_DAMAGE_DIFF=1 and
     * TUI_CLAMP_OFF=1. */
    { extern void tui_selftest(void); tui_selftest(); }
#elif defined(CONSOLE_SELFTEST)
    /* Gated: stand up the ring-3 console_server (owns the console hardware via the
     * J2/J3 mechanisms) and a client that drives it over IPC; the server emits the
     * client's line to serial natively (CONSOLE_SELFTEST: PASS). First J5 cutover
     * milestone; see docs/design/console-server.md. */
    console_selftest();
#elif defined(LIBHORUS_SELFTEST)
    /* Gated: a ring-3 task drives libhorus's own conformance suite -- the bounds
     * and termination guarantees its callers depend on, and the one that is a
     * security property rather than a convenience: ipc_call_retry must return a
     * PERMANENT refusal rather than spin on it (finding G-8 signature C). Prints
     * LIBHORUS_SELFTEST: PASS from ring 3. Falsified by LIBHORUS_RETRY_ANY=1 and
     * LIBHORUS_STRNCPY_UNTERMINATED=1. */
    { extern void libhorus_selftest(void); libhorus_selftest(); }
#elif defined(VFS_SELFTEST)
    /* Gated: a second filesystem server (holding nothing but its own endpoint)
     * and a client that mounts it at /dev alongside fs_server at / -- roadmap
     * 2.4. Asserts which server each path reaches, and that reaching a mount
     * took a capability rather than a prefix. VFSTEST: PASS <n> checks. */
    { extern void vfs_selftest(void); vfs_selftest(); }
#elif defined(PASSWD_PROBE)
    { extern void passwd_probe_selftest(void); passwd_probe_selftest(); }
#elif defined(FRAME_SELFTEST)
    /* Gated: two ring-3 tasks around one page of physical memory (roadmap 2.1).
     * One retypes a KOBJ_FRAME out of its CAP_UNTYPED, maps it, and asserts every
     * refusal the map path owes -- most importantly that the legacy CAP_FRAME
     * every task is born holding in slot 3 maps nothing. It then mints a
     * READ-only copy and delegates it, and the second task proves it can see the
     * first's bytes and cannot obtain a writable mapping. Prints
     * FRAMETEST: PASS <n> checks from ring 3. Falsified by
     * FRAME_INDEX_UNCHECKED=1 and FRAME_RIGHTS_UNCHECKED=1. */
    { extern void frame_selftest(void); frame_selftest(); }
#elif defined(RECVBLOCK_SELFTEST)
    /* Gated: a ring-3 server waits on an empty endpoint with SYS_IPC_RECV_BLOCK
     * while a client dawdles before each request; the server proves it made
     * exactly ONE receive syscall per message (so it slept rather than polled)
     * and that the wake left it holding the one-shot reply right
     * (RECVBLOCK_SELFTEST: PASS). Roadmap 1.3's last item. */
    { extern void recvblock_selftest(void); recvblock_selftest(); }
#elif defined(CONSOLE_ISOLATION_TEST)
    /* Gated: the ring-3 console_server takes the hardware then deliberately faults;
     * the kernel contains it as a ring-3 fault and stays alive (CONSOLE_ISOLATION:
     * PASS). The Phase 6 close-out blast-radius proof; see docs/design/console-server.md. */
    console_isolation_selftest();
#elif defined(FPU_SELFTEST)
    /* Gated: two ring-3 tasks share one CPU; one loads a sentinel into every xmm
     * register and requires it intact across switches, the other requires never
     * to see it (prints FPUTEST: PASS twice). SECURITY.md S16. */
    { extern void fpu_selftest(void); fpu_selftest(); }
#elif defined(FORK_SELFTEST)
    /* Gated: fork this task and prove from ring 3 that the child's memory is a
     * COPY rather than a share, and that a mapped CAP_FRAME refuses the fork
     * (prints FORKTEST: PASS). Roadmap 2.3. */
    { extern void fork_selftest(void); fork_selftest(); }
#elif defined(FORKEXEC_SELFTEST)
    /* Gated: fork this task, let the child replace its image with SYS_EXEC_NAMED,
     * and prove from ring 3 that the exec replaced the image and not the
     * authority -- the inherited capability keeps its identity and its place in
     * the derivation graph, so the parent's revoke still reaches it (prints
     * FORKEXECTEST: PASS). SECURITY.md S42, roadmap 2.3. */
    { extern void forkexec_selftest(void); forkexec_selftest(); }
#elif defined(COW_SELFTEST)
    /* Gated: read two fresh heap pages (shared zero page) then write one, and
     * prove the write broke COW into a private page without disturbing the
     * sibling (prints COW_SELFTEST: PASS). */
    { extern void cow_selftest(void); cow_selftest(); }
#elif defined(CAPTEST_SELFTEST)
    /* Gated: drive the syscall surface and the capability model from ring 3,
     * asserting mostly on the refusals (prints CAPTEST: PASS <n> checks). */
    { extern void captest_selftest(void); captest_selftest(); }
#else
#ifdef ELF_SELFTEST
    /* Gated: verify try_elf_load's W^X enforcement on a real ELF before the
     * (never-returning) drop to userspace. This is the actual pre-userspace
     * point — smp_bringup() spawns init and sched_enter_user's into ring 3,
     * so it never returns to kernel_main. */
    elf_loader_selftest();
#endif
#ifdef ELF64_SELFTEST
    /* Gated: verify the loader's x86-64 RELA relocation path on a real 64-bit
     * static-PIE. Loads and inspects only — never executed, so this is
     * independent of the ring-3 ABI still being 32-bit. */
    { extern void elf64_loader_selftest(void); elf64_loader_selftest(); }
#endif
#ifdef ASLR_SELFTEST
    /* Gated: spawn several PIE images and prove the loader randomises the image
     * base, and that every base keeps the premap inside one page table. */
    { extern void aslr_selftest(void); aslr_selftest(); }
#endif
    spawn_initial_userspace_init();
#endif
}

void tlb_shootdown(uint64_t vaddr) {
    __asm__ volatile ("invlpg (%0)" :: "r"(vaddr) : "memory");
}

#ifdef SMP
/* TLB-shootdown acknowledgement protocol.
 *
 * The initiator serialises on shootdown_lock (a raw test-and-set that does NOT
 * disable interrupts), sets smp_shootdown_pending to the number of other CPUs,
 * broadcasts vector 0xFB, and spins until every receiver has flushed and
 * decremented the counter. Because the lock does not mask interrupts and the
 * single caller (below) is invoked with interrupts enabled and no scheduler lock
 * held, an initiator waiting for acks -- or waiting for the lock -- still
 * services other CPUs' shootdown IPIs, so two initiators cannot wedge each
 * other. A bounded spin is a final backstop against a wedged CPU. */
static volatile int shootdown_lock = 0;
volatile int smp_shootdown_pending = 0;

/* Receiver side (idt.c, vector 0xFB), after flushing its TLB. */
void smp_ack_shootdown(void) {
    __sync_fetch_and_sub(&smp_shootdown_pending, 1);
}
#endif

/* Flush `vaddr` locally and, on a multi-CPU system, ask every other CPU to flush
 * too and wait for them to acknowledge before returning -- so once this returns
 * no CPU can still hold a stale translation for `vaddr`. On a single-CPU system
 * it is just a local invlpg.
 *
 * MUST be called with interrupts enabled and no scheduler/​page lock held (see
 * the protocol note above); it is therefore NOT used on the switch_cr3 fast path
 * (a local CR3 reload already flushes the local TLB). */
void smp_maybe_shootdown(uint64_t vaddr) {
    tlb_shootdown(vaddr);
#ifdef SMP
    /* The all-excluding-self broadcast reaches every brought-up CPU, including
     * parked SMT siblings (which service and ack the IPI to stay TLB-coherent), so
     * the ack total is `present = online + parked`, not just the schedulable
     * `online`. Undercounting would let the initiator return before a parked
     * sibling flushed; overcounting (waiting for a CPU that never received) would
     * spin to the backstop. */
    int present = smp_cpus_online + smp_siblings_parked;
    if (present > 1) {
        /* ---- The one window that must run with interrupts ON (roadmap 1.1) ---
         *
         * Both spins below wait on OTHER CPUs, and those CPUs may simultaneously
         * be waiting on this one: the receiver side of this protocol is an IPI
         * (vector 0xFB), so a CPU spinning here with IF clear cannot flush and
         * acknowledge, and two initiators wedge each other until the backstop
         * expires. The requirement has always been in the comment above. What it
         * has never had is a source: it was satisfied by accident, because
         * spin_unlock's unconditional `sti` had already enabled interrupts for
         * whatever syscall got here (finding [C-3.1]).
         *
         * With the IF-preserving lock that accident is gone, so the window says
         * what it needs and takes it deliberately -- which is what roadmap 1.1
         * step 1 asks for: find the windows relying on the accidental `sti` and
         * issue it on purpose. IF is restored afterwards rather than left set,
         * because this must not become a second source of ambient enablement.
         *
         * Holding a spinlock across this is the hazard the enable trades against
         * -- an IRQ handler that took the same lock would deadlock -- and the
         * protocol note above already forbids it. Now it is CHECKED. A caller
         * that gets this wrong gets a named panic here rather than an
         * intermittent lockup somewhere else. */
        if (irq_locks_held_here() != 0) {
            println("PANIC: tlb shootdown with a spinlock held");
            for (;;) __asm__ volatile ("cli; hlt");
        }
        uint64_t fl;
        __asm__ volatile ("pushfq; pop %0" : "=r"(fl) :: "memory");
        __asm__ volatile ("sti" ::: "memory");       /* deliberate; see above */

        while (__sync_lock_test_and_set(&shootdown_lock, 1))
            __asm__ volatile ("pause");              /* IF stays set: still service IPIs */
        smp_shootdown_pending = present - 1;
        __asm__ volatile ("mfence" ::: "memory");
        lapic_write(0x300, 0x000C0000 | 0xFB);       /* all-excluding-self, vec 0xFB */
        for (int i = 0; i < 100000000 && smp_shootdown_pending > 0; i++)
            __asm__ volatile ("pause");
        __sync_lock_release(&shootdown_lock);

        if (!(fl & 0x200)) __asm__ volatile ("cli" ::: "memory");   /* restore */
    }
#endif
}

int smp_get_online_count(void) {
    return smp_cpus_online;
}
