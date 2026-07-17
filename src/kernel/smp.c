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
#ifdef SMP
extern int task_running_cpu[MAX_TASKS];
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
#define AP_IDLE_STACK_SIZE   0x4000UL

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

static void smp_busy_delay(int iters) {
    for (volatile int d = 0; d < iters; d++) __asm__ volatile ("pause");
}

#ifdef SMP
/* Per-CPU idle stacks. APs index by LAPIC id (see ap_trampoline.S), so MAX_CPUS
 * slots cover ids 0..MAX_CPUS-1; slot 0 (the BSP's) is unused on this path.
 * An AP whose id has no slot parks in the trampoline rather than running off
 * the end of this array. */
static uint8_t ap_idle_stacks[MAX_CPUS][AP_IDLE_STACK_SIZE] __attribute__((aligned(16)));

/* ap_trampoline.S bounds the LAPIC id against its own AP_MAX_CPUS: it is
 * assembled with -x assembler-with-cpp and cannot include a header full of C
 * declarations, so the value is duplicated there. Pin the two together — if
 * this fires, update AP_MAX_CPUS in src/boot/ap_trampoline.S to match. */
_Static_assert(MAX_CPUS == 4,
               "MAX_CPUS changed: update AP_MAX_CPUS in src/boot/ap_trampoline.S to match");

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

    int cpu = this_cpu();
    uintptr_t idle_top = (uintptr_t)&ap_idle_stacks[0][0]
                       + (uintptr_t)(cpu + 1) * AP_IDLE_STACK_SIZE;
    setup_ap_tss(cpu, idle_top);  /* per-CPU TSS + IST, ltr'd */

    lapic_enable();
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

static void smp_start_aps(void) {
    /* No task is running on any CPU yet. */
    for (int i = 0; i < MAX_TASKS; i++) task_running_cpu[i] = -1;

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

    /* Wait (bounded) for the APs to check in. */
    for (int spins = 0; spins < 200 && smp_cpus_online < MAX_CPUS; spins++)
        smp_busy_delay(20000);

    print("[smp] CPUs online: ");
    print_hex((uint64_t)smp_cpus_online);
    print("\n");
}
#endif /* SMP */

void smp_bringup(void) {
    lapic_enable_bsp();
#ifdef SMP
    /* LAPIC is mapped (paging_init) and now enabled, so this_cpu() is safe and
     * per-CPU TSS routing can turn on before any AP or context switch runs. */
    smp_active = 1;
    smp_start_aps();
#endif

    println("[ok] kernel ready, starting init...");
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
#elif defined(COW_SELFTEST)
    /* Gated: read two fresh heap pages (shared zero page) then write one, and
     * prove the write broke COW into a private page without disturbing the
     * sibling (prints COW_SELFTEST: PASS). */
    { extern void cow_selftest(void); cow_selftest(); }
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
    if (smp_get_online_count() > 1) {
        while (__sync_lock_test_and_set(&shootdown_lock, 1))
            __asm__ volatile ("pause");              /* IF stays set: still service IPIs */
        smp_shootdown_pending = smp_get_online_count() - 1;
        __asm__ volatile ("mfence" ::: "memory");
        lapic_write(0x300, 0x000C0000 | 0xFB);       /* all-excluding-self, vec 0xFB */
        for (int i = 0; i < 100000000 && smp_shootdown_pending > 0; i++)
            __asm__ volatile ("pause");
        __sync_lock_release(&shootdown_lock);
    }
#endif
}

int smp_get_online_count(void) {
    return smp_cpus_online;
}
