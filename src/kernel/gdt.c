#include "kernel.h"

/*
 * On x86-64 the GDT and the 64-bit TSS descriptor are installed by the boot
 * assembly (src/boot/multiboot.S: gdt64_start, selectors 0x08/0x10 kernel
 * code/data, 0x20/0x28 user code, 0x30 user data, 0x38 TSS). The only runtime
 * GDT/TSS work left for C is keeping the active TSS's RSP0 -- the ring-0 stack
 * loaded automatically on every ring-3 -> ring-0 transition -- pointed at the
 * current task's kernel stack.
 */
void set_tss_kernel_stack(uintptr_t rsp0) {
    extern uint8_t tss64[];
    *(uint64_t *)(tss64 + 4) = (uint64_t)rsp0;   /* tss64 + 4 == RSP0 field */
}
