#include "kernel.h"

/*
 * On x86-64 the GDT and the 64-bit TSS descriptor are installed by the boot
 * assembly (src/boot/multiboot.S: gdt64_start, selectors 0x08/0x10 kernel
 * code/data, 0x20/0x28 user code, 0x30 user data, 0x38 TSS). The only runtime
 * GDT/TSS work left for C is keeping the active TSS's RSP0 -- the ring-0 stack
 * loaded automatically on every ring-3 -> ring-0 transition -- pointed at the
 * current task's kernel stack.
 *
 * Under SMP each CPU needs its own TSS: RSP0 (and the IST fault stacks) are
 * loaded from *the running CPU's* TSS on a ring-3->ring-0 transition, so two
 * cores entering the kernel at once must not share one kernel stack. The BSP
 * keeps the boot tss64 (selector 0x38); each AP gets its own TSS + IST stacks
 * and a descriptor at selector 0x48/0x58/0x68 (reserved in multiboot.S), and
 * ltr's it in setup_ap_tss(). set_tss_kernel_stack() then routes RSP0 updates to
 * whichever CPU is running. The default (non-SMP) build compiles to exactly the
 * original single-TSS behaviour.
 */

extern uint8_t tss64[];

#define TSS64_SIZE   104
#define TSS_RSP0_OFF 4
#define TSS_IST1_OFF 36
#define TSS_IST2_OFF 44
#define TSS_IST3_OFF 52

/* I/O permission bitmap, appended to the TSS so a task holding a port-I/O grant
 * (the console-driver server) can run in/out natively at ring 3 while every other
 * task's in/out #GPs. iomap_base (@102) points at the bitmap only while a granted
 * task runs; otherwise it is set past the segment limit (disabled), so all ring-3
 * I/O faults. The bitmap is one bit per port (0=allow, 1=deny) plus a mandatory
 * terminating 0xFF byte. Layout mirrors the boot tss64 in multiboot.S. */
#define TSS_IOMAP_OFF        102
#define TSS_IO_BITMAP_OFF    104
#define TSS_IO_BITMAP_BYTES  8192
#define TSS_FULL_SIZE        (TSS_IO_BITMAP_OFF + TSS_IO_BITMAP_BYTES + 1)  /* + terminator */
#define TSS_IOMAP_DISABLED   0xFFFFu   /* iomap_base >= limit => no bitmap => deny all */

/* Fill a TSS's I/O bitmap: deny every port, then clear (allow) exactly the
 * console's ports. Kept deliberately narrow -- a granted driver can touch the
 * serial UARTs, the PS/2 keyboard, and the VGA register file, nothing else (not
 * the PIC, not the ATA/CMOS/PCI ports). */
static void tss_io_bitmap_fill(uint8_t *tss) {
    uint8_t *bm = tss + TSS_IO_BITMAP_OFF;
    for (int i = 0; i < TSS_IO_BITMAP_BYTES; i++) bm[i] = 0xFF;   /* deny all */
    bm[TSS_IO_BITMAP_BYTES] = 0xFF;                               /* terminating byte */
    static const struct { uint16_t base, count; } allow[] = {
        { 0x60,  1 }, { 0x64, 1 },     /* PS/2 keyboard data / status-command */
        { 0x2F8, 8 }, { 0x3F8, 8 },    /* serial COM2 / COM1 register files */
        { 0x3B0, 0x30 },               /* VGA CRTC/sequencer/graphics/attribute (0x3B0-0x3DF) */
    };
    for (unsigned r = 0; r < sizeof(allow) / sizeof(allow[0]); r++)
        for (uint16_t p = 0; p < allow[r].count; p++) {
            uint16_t port = (uint16_t)(allow[r].base + p);
            bm[port >> 3] &= (uint8_t)~(1u << (port & 7));        /* 0 = allow */
        }
}

#ifdef SMP
extern uint8_t gdt64_start[];
extern int this_cpu(void);
extern volatile int smp_active;   /* scheduler.c: 1 once the LAPIC is up */

/* Per-CPU TSS + IST fault stacks for the APs (indices 1..MAX_CPUS-1; the BSP
 * uses the boot tss64). IST stacks must be per-CPU because #PF/#DF/#GP gates
 * switch to them via the TSS, and AP-run user tasks demand-page (a #PF).
 *
 * Each IST stack is laid out above a page-aligned guard page, exactly as the
 * BSP's boot IST stacks are in multiboot.S: a fault handler that runs its IST
 * stack off the bottom (IST1 takes #DF/#GP/#PF, so it is on the path of every
 * demand page fault an AP-run task takes) then faults on the guard instead of
 * silently corrupting the IST stack below it or adjacent .bss. Each block is two
 * 4 KiB pages — [guard][stack] — and the whole array is page-aligned so every
 * guard is a whole page kern_arm_guard_page() can clear. ap_ist_guards_init()
 * unmaps the guards at boot; the IST pointer installed in the TSS is the top of
 * the stack page. */
#define AP_IST_COUNT       3            /* IST1/IST2/IST3 */
#define AP_IST_BLOCK_PAGES 2            /* one guard page + one stack page */
static uint8_t ap_tss[MAX_CPUS][TSS_FULL_SIZE] __attribute__((aligned(16)));
static uint8_t ap_ist[MAX_CPUS][AP_IST_COUNT][AP_IST_BLOCK_PAGES * 4096]
    __attribute__((aligned(4096)));

/* Top of CPU `cpu`'s IST stack `k` (0..2): the block's high page, which the
 * stack grows down from onto the guard page just below it. */
static inline uintptr_t ap_ist_top(int cpu, int k) {
    return (uintptr_t)&ap_ist[cpu][k][AP_IST_BLOCK_PAGES * 4096];
}

/* Guard page (block low page) below CPU `cpu`'s IST stack `k`. */
static inline uintptr_t ap_ist_guard(int cpu, int k) {
    return (uintptr_t)&ap_ist[cpu][k][0];
}

/* Selector of CPU c's TSS descriptor (two GDT slots each, starting at 0x48). */
static inline uint16_t ap_tss_selector(int cpu) {
    return (uint16_t)(0x48 + (cpu - 1) * 16);
}

/* Encode a 16-byte available-64-bit-TSS descriptor into a GDT slot. */
static void encode_tss_desc(uint8_t *slot, uint64_t base, uint32_t limit) {
    slot[0] = (uint8_t)(limit & 0xFF);
    slot[1] = (uint8_t)((limit >> 8) & 0xFF);
    slot[2] = (uint8_t)(base & 0xFF);
    slot[3] = (uint8_t)((base >> 8) & 0xFF);
    slot[4] = (uint8_t)((base >> 16) & 0xFF);
    slot[5] = 0x89;                                  /* present, type=9 (avail TSS) */
    slot[6] = (uint8_t)((limit >> 16) & 0x0F);       /* limit[19:16], flags=0 */
    slot[7] = (uint8_t)((base >> 24) & 0xFF);
    *(uint32_t *)(slot + 8)  = (uint32_t)(base >> 32);
    *(uint32_t *)(slot + 12) = 0;
}

/* Build CPU `cpu`'s TSS (RSP0 + per-CPU IST stacks), install its GDT descriptor,
 * and load it (ltr). Called once from ap_entry64 during AP bringup. */
void setup_ap_tss(int cpu, uintptr_t rsp0) {
    if (cpu <= 0 || cpu >= MAX_CPUS) return;
    uint8_t *tss = ap_tss[cpu];
    for (int i = 0; i < TSS64_SIZE; i++) tss[i] = 0;
    *(uint64_t *)(tss + TSS_RSP0_OFF) = (uint64_t)rsp0;
    *(uint64_t *)(tss + TSS_IST1_OFF) = (uint64_t)ap_ist_top(cpu, 0);
    *(uint64_t *)(tss + TSS_IST2_OFF) = (uint64_t)ap_ist_top(cpu, 1);
    *(uint64_t *)(tss + TSS_IST3_OFF) = (uint64_t)ap_ist_top(cpu, 2);
    /* Disabled by default; the console allowlist is prefilled so the per-switch
     * iomap_base flip (tss_set_io_allowed) can activate it on this CPU too. */
    *(uint16_t *)(tss + TSS_IOMAP_OFF) = TSS_IOMAP_DISABLED;
    tss_io_bitmap_fill(tss);

    uint16_t sel = ap_tss_selector(cpu);
    encode_tss_desc(gdt64_start + sel, (uint64_t)(uintptr_t)tss, TSS_FULL_SIZE - 1);
    __asm__ volatile ("ltr %0" :: "r"(sel) : "memory");
}

/* Count of AP IST guard pages actually unmapped; read by the gated self-test,
 * which would pass just as happily on an empty loop. */
uint32_t ap_ist_guards_armed = 0;

/* Unmap the guard page below every AP IST stack. Called once at boot from
 * paging_init(), before smp_bringup(), so the cleared entries are inherited into
 * each AP's CR3 with no shootdown — the same one-pass arming kstack_guards_init()
 * and kern_fixed_stack_guards_init() do. All MAX_CPUS-1 AP slots are armed even
 * though not every core comes up; an unused slot's guard is simply absent .bss,
 * which is harmless. */
void ap_ist_guards_init(void) {
    extern int kern_arm_guard_page(uint64_t vaddr);
    for (int c = 1; c < MAX_CPUS; c++)
        for (int k = 0; k < AP_IST_COUNT; k++)
            if (kern_arm_guard_page((uint64_t)ap_ist_guard(c, k)) == 0)
                ap_ist_guards_armed++;
}

#ifdef WX_SELFTEST
/* Gated: enumerate the AP IST guards so smoke-wx (built WX_SELFTEST=1 SMP=1) can
 * assert each is absent while the stack page just above it stays present. The
 * APs are CPUs 1..MAX_CPUS-1, three IST stacks each, flattened row-major. */
uint32_t ap_ist_guard_count(void) { return (uint32_t)((MAX_CPUS - 1) * AP_IST_COUNT); }
uint64_t ap_ist_guard_vaddr(int i) {
    int c = i / AP_IST_COUNT + 1;
    int k = i % AP_IST_COUNT;
    if (i < 0 || c < 1 || c >= MAX_CPUS) return 0;
    return (uint64_t)ap_ist_guard(c, k);
}
#endif
#endif /* SMP */

void set_tss_kernel_stack(uintptr_t rsp0) {
#ifdef SMP
    if (smp_active) {
        int c = this_cpu();
        if (c > 0 && c < MAX_CPUS) {
            *(uint64_t *)(ap_tss[c] + TSS_RSP0_OFF) = (uint64_t)rsp0;
            return;
        }
    }
#endif
    *(uint64_t *)(tss64 + TSS_RSP0_OFF) = (uint64_t)rsp0;   /* tss64 + 4 == RSP0 */
}

/* Prefill the BSP TSS's I/O bitmap with the console allowlist (deny all, allow the
 * console ports). Called once at boot, before any ring-3 task runs. The bitmap
 * stays inactive (iomap_base disabled) until a task with a port-I/O grant is
 * switched in. The AP TSSes are filled the same way in setup_ap_tss. */
void tss_io_bitmap_init(void) {
    tss_io_bitmap_fill(tss64);
    *(uint16_t *)(tss64 + TSS_IOMAP_OFF) = TSS_IOMAP_DISABLED;
}

/* Point the *running CPU's* TSS iomap_base at the bitmap (in/out consult it) when
 * `allowed`, or past the segment limit (all ring-3 in/out #GP) otherwise. Called
 * from the context-switch chokepoint (set_current_task) with the incoming task's
 * grant, and directly by SYS_IOPORT_GRANT so the grant takes effect immediately
 * for the calling task without waiting for a reschedule. Routed per-CPU exactly
 * like set_tss_kernel_stack. */
void tss_set_io_allowed(int allowed) {
    uint16_t base = allowed ? (uint16_t)TSS_IO_BITMAP_OFF : (uint16_t)TSS_IOMAP_DISABLED;
#ifdef SMP
    if (smp_active) {
        int c = this_cpu();
        if (c > 0 && c < MAX_CPUS) {
            *(uint16_t *)(ap_tss[c] + TSS_IOMAP_OFF) = base;
            return;
        }
    }
#endif
    *(uint16_t *)(tss64 + TSS_IOMAP_OFF) = base;
}
