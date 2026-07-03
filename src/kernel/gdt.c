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

#ifdef SMP
extern uint8_t gdt64_start[];
extern int this_cpu(void);
extern volatile int smp_active;   /* scheduler.c: 1 once the LAPIC is up */

/* Per-CPU TSS + IST fault stacks for the APs (indices 1..MAX_CPUS-1; the BSP
 * uses the boot tss64). IST stacks must be per-CPU because #PF/#DF/#GP gates
 * switch to them via the TSS, and AP-run user tasks demand-page (a #PF). */
static uint8_t ap_tss[MAX_CPUS][TSS64_SIZE] __attribute__((aligned(16)));
static uint8_t ap_ist[MAX_CPUS][3][4096]    __attribute__((aligned(16)));

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
    *(uint64_t *)(tss + TSS_IST1_OFF) = (uint64_t)(uintptr_t)&ap_ist[cpu][0][4096];
    *(uint64_t *)(tss + TSS_IST2_OFF) = (uint64_t)(uintptr_t)&ap_ist[cpu][1][4096];
    *(uint64_t *)(tss + TSS_IST3_OFF) = (uint64_t)(uintptr_t)&ap_ist[cpu][2][4096];

    uint16_t sel = ap_tss_selector(cpu);
    encode_tss_desc(gdt64_start + sel, (uint64_t)(uintptr_t)tss, TSS64_SIZE - 1);
    __asm__ volatile ("ltr %0" :: "r"(sel) : "memory");
}
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
