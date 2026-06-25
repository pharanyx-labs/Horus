#include "kernel.h"

struct gdt_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_middle;
    uint8_t  access;
    uint8_t  granularity;
    uint8_t  base_high;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uintptr_t base;
} __attribute__((packed));

struct tss_entry {
    uint32_t prev_tss; uint32_t esp0; uint32_t ss0;
    uint32_t esp1, ss1, esp2, ss2;
    uint32_t cr3, eip, eflags, eax, ecx, edx, ebx, esp, ebp, esi, edi;
    uint32_t es, cs, ss, ds, fs, gs, ldt;
    uint16_t trap, iomap_base;
} __attribute__((packed));

static struct gdt_entry gdt[6];
static struct gdt_ptr gdt_ptr;
static struct tss_entry tss __attribute__((aligned(16)));

extern void gdt_flush(uintptr_t);
extern void tss_flush(void);

static void gdt_set_gate(int32_t num, uintptr_t base, uint32_t limit, uint8_t access, uint8_t gran) {
    gdt[num].base_low = base & 0xFFFF;
    gdt[num].base_middle = (base >> 16) & 0xFF;
    gdt[num].base_high = (base >> 24) & 0xFF;
    gdt[num].limit_low = limit & 0xFFFF;
    gdt[num].granularity = ((limit >> 16) & 0x0F) | (gran & 0xF0);
    gdt[num].access = access;
}

void gdt_init(void) {
    gdt_ptr.limit = (sizeof(struct gdt_entry) * 6) - 1;
    gdt_ptr.base = (uintptr_t)&gdt[0];

    gdt_set_gate(0, 0, 0, 0, 0);
    gdt_set_gate(1, 0, 0xFFFFFFFF, 0x9A, 0xCF);
    gdt_set_gate(2, 0, 0xFFFFFFFF, 0x92, 0xCF);
    gdt_set_gate(3, 0, 0xFFFFFFFF, 0xFA, 0xCF);
    gdt_set_gate(4, 0, 0xFFFFFFFF, 0xF2, 0xCF);
    gdt_set_gate(5, (uintptr_t)&tss, sizeof(tss) - 1, 0x89, 0x00);

    gdt_flush((uintptr_t)&gdt_ptr);

    tss.ss0 = 0x10;
    tss.esp0 = KERNEL_TSS_STACK;
    tss.iomap_base = 0xFFFF;
    tss.cs = 0x08;
    tss.ss = tss.ds = tss.es = tss.fs = tss.gs = 0x10;

    tss_flush();
}

void set_tss_kernel_stack(uintptr_t esp0) {
    tss.esp0 = esp0;
#if defined(__x86_64__)
    extern uint8_t tss64[];
    *(uint64_t *)(tss64 + 4) = (uint64_t)esp0;
#endif
}
