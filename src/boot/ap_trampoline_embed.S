/* src/boot/ap_trampoline_embed.S: embeds the AP trampoline blob in .rodata and
 * refuses to assemble if the blob would not fit below its cells.
 *
 * #included by multiboot.S (SMP builds only). It is its own file for one reason:
 * `make smoke-ap-trampoline` assembles THIS file, on its own, against a blob it
 * built in a scratch directory, so the gate exercises the same .error the kernel
 * build does rather than a copy of it. AP_TRAMPOLINE_BIN names the blob; the
 * kernel build leaves it at its default.
 *
 * Why the bound is checked here as well as in src/boot/ap_trampoline.ld: the
 * linker script bounds what IT produces, and this bounds what is actually
 * embedded, however it was produced. On 2026-09-19 a host binutils default made
 * the old link command emit a 134,479,912-byte blob (see ap_trampoline.ld). The
 * only thing that stopped it was the unrelated .bss ASSERT in linker64.ld, and
 * that only because the overrun happened to be large; the same defect at a few
 * KiB would have linked, and smp_start_aps would have copied it over the cells
 * at 0x8FD8 and past them.
 *
 * 0xFD8 is AP_STACK_BASE_CELL (0x8FD8) minus AP_TRAMP_PHYS (0x8000): see
 * src/kernel/smp.c, src/boot/ap_trampoline.S and src/include/kernel.h. It is
 * duplicated because this file cannot include a header of C declarations. */

#ifndef AP_TRAMPOLINE_BIN
#define AP_TRAMPOLINE_BIN "src/boot/ap_trampoline.bin"
#endif

.section .rodata
/* Real-mode AP startup trampoline (src/boot/ap_trampoline.S), linked flat at
 * 0x8000 and copied there by smp_start_aps before the broadcast SIPI. */
.align 16
.global ap_trampoline_start
ap_trampoline_start:
.incbin AP_TRAMPOLINE_BIN
.global ap_trampoline_end
ap_trampoline_end:

.if (ap_trampoline_end - ap_trampoline_start) > 0xFD8
.error "AP trampoline blob does not fit below its cells at 0x8FD8 (see src/boot/ap_trampoline_embed.S)"
.endif
