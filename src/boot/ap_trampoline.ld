/* src/boot/ap_trampoline.ld: the flat image of the AP startup trampoline.
 *
 * WHY A SCRIPT, AND NOT `-Ttext=0x8000 --oformat binary`. That command line
 * placed .text and left every other allocated input section to the DEFAULT
 * i386 script. A binary image spans every allocated output section, so any
 * section the default script put elsewhere is included, and so is the gap
 * between them. On 2026-09-19 a build on Void Linux (binutils 2.44, whose gas
 * is configured to emit the "x86 ISA used" property note by default) got a
 * `.note.gnu.property` in ap_trampoline.o. The default script placed it at
 * 0x080480d4, the i386 executable base, and the "270-byte" trampoline came out
 * as 134,479,912 bytes: 128 MiB of zeros between 0x8000 and the note.
 * multiboot.S embeds the blob in .rodata, so the kernel image ran past
 * USER_PHYS_BASE and the link failed. Ubuntu's binutils does not emit the note,
 * which is why CI stayed green. The output depended on a host default, and
 * nothing said so.
 *
 * This script leaves nothing to a default. Everything the trampoline could
 * legitimately contain goes into one output section at the SIPI load address,
 * and everything that is metadata is discarded. An input section of a kind not
 * named here would be an orphan again, so the ASSERT below bounds the result
 * either way, and multiboot.S bounds the bytes it actually embeds.
 *
 * Witness: `make smoke-ap-trampoline`, falsified by
 * `make smoke-ap-trampoline-control` (AP_TRAMPOLINE_FLAT_LINK=1). See TESTS.md. */

OUTPUT_FORMAT(binary)

SECTIONS
{
    /* The SIPI vector is 0x08, so an AP starts at CS:IP = 0x0800:0, which is
     * physical 0x8000 (AP_TRAMP_PHYS in src/include/kernel.h). */
    . = 0x8000;

    .text : {
        *(.text) *(.text.*)
        *(.rodata) *(.rodata.*)
        *(.data) *(.data.*)
    }

    /DISCARD/ : {
        *(.note) *(.note.*)
        *(.comment)
        *(.eh_frame) *(.eh_frame.*)
    }

    /* The BSP publishes three qword cells in the same page, from
     * AP_STACK_BASE_CELL (0x8FD8) up: see src/kernel/smp.c and
     * src/boot/ap_trampoline.S. A blob that reached them would be overwritten by
     * the cells, or would overwrite them, depending on the order of the writes.
     * 0x8FD8 is duplicated here because a linker script cannot include a header,
     * the same reason linker64.ld duplicates KERNEL_VMA. */
    ASSERT(. <= 0x8FD8, "AP trampoline overlaps the cells at AP_STACK_BASE_CELL (0x8FD8)")
}
