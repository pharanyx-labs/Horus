/*
 * Static-PIE (ET_DYN) linker script for relocatable Horus userspace binaries.
 *
 * Produces three page-aligned PT_LOAD segments with distinct permission flags
 * so the kernel loader (try_elf_load) can apply per-segment W^X:
 *
 *   .text   FLAGS(5) = R + X
 *   .rodata FLAGS(4) = R
 *   .data   FLAGS(6) = R + W   (NX enforced by the kernel)
 *
 * The image is linked at base 0; the kernel loads it at a randomized base
 * (ASLR) and applies R_386_RELATIVE relocations. Freestanding userspace only
 * traps via `int 0x80`, so GCC's GOTOFF addressing usually leaves zero dynamic
 * relocations, but any that appear are handled by the loader. Kept as a real
 * ELF (never objcopy-flattened). (FLAGS bits: 1=X, 2=W, 4=R = ELF PF_X/W/R.)
 */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD    FLAGS(5);   /* R + X */
    rodata PT_LOAD    FLAGS(4);   /* R     */
    data   PT_LOAD    FLAGS(6);   /* R + W */
    dyn    PT_DYNAMIC FLAGS(4);
}

SECTIONS
{
    . = 0;
    .text : { *(.text) *(.text.*) } :text

    . = ALIGN(0x1000);
    .rodata  : { *(.rodata) *(.rodata.*) } :rodata
    .dynamic : { *(.dynamic) }             :rodata :dyn
    .rel.dyn : { *(.rel.dyn) *(.rel.*) }   :rodata
    .dynsym  : { *(.dynsym) }              :rodata
    .dynstr  : { *(.dynstr) }              :rodata
    .hash    : { *(.hash) *(.gnu.hash) }   :rodata

    . = ALIGN(0x1000);
    .data : { *(.data) *(.data.*) }        :data
    .got  : { *(.got) *(.got.plt) }        :data
    .bss  : { *(.bss) *(.bss.*) *(COMMON) } :data

    /DISCARD/ : {
        *(.eh_frame) *(.eh_frame.*)
        *(.note) *(.note.*)
        *(.comment) *(.gnu.version*) *(.interp)
    }
}
