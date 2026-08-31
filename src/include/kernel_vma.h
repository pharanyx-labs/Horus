/* kernel_vma.h — the kernel's virtual/physical link offset.
 *
 * Included by C (via kernel.h) AND by the boot assembly, which is built with
 * -x assembler-with-cpp. It therefore must contain nothing but this #define:
 * no types, no declarations, nothing the assembler cannot swallow.
 *
 * linker64.ld carries the same value and is the authority on placement — a
 * linker script cannot include this header, so the two are checked against each
 * other instead: linker64.ld exports __kernel_vma_from_linker, and
 * kernel_main asserts it matches KERNEL_VMA before doing anything else.
 *
 * Why this value specifically: see the comment in linker64.ld. Short version —
 * -mcmodel=kernel permits 32-bit sign-extended symbol references, valid only in
 * [-2 GiB, +2 GiB), and this is the base of the top half of that range. */
#ifndef HORUS_KERNEL_VMA_H
#define HORUS_KERNEL_VMA_H

#define KERNEL_VMA 0xFFFFFFFF80000000

/* The BSP's kernel stack, in bytes. Defined HERE, in the one header both the C
 * side and the boot assembly include, so there is a single value rather than two
 * that can drift -- the mistake AP_IDLE_STACK_SIZE has a _Static_assert to catch
 * because it IS duplicated.
 *
 * Raised 16 KiB -> 64 KiB on 2026-08-31 with the 4 KiB filesystem block size,
 * and the boot fault it fixes is worth recording: kernel_main runs storage_init
 * on this stack, and storage_unlock's frame alone grew to 12,464 bytes when
 * every `uint8_t buf[BLOCK_SIZE]` local grew eightfold. The overflow ran into
 * bsp_stack_guard and faulted at 0xffffffff801bbb58 -- the guard page working
 * exactly as intended, on the first boot after the change.
 *
 * Note this is SEPARATE from KERNEL_STACK_SIZE, which sizes per-task stacks;
 * raising that one did not touch this one, which is why the boot still broke. */
#define BSP_STACK_SIZE 65536

#endif /* HORUS_KERNEL_VMA_H */
