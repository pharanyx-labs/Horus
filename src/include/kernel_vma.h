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

#endif /* HORUS_KERNEL_VMA_H */
