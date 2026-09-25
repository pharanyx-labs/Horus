/*
 * pie_shared.ld -- pie.ld for a program linked against the shared libc
 * (docs/design/shared-libc.md §8, §9).
 *
 * Everything pie.ld says holds here, and two things are added, both for the
 * ring-3 linker in crt0_dyn:
 *
 *   __horus_image_start   the first byte of the image, at link address 0. A
 *                         PC-relative reference to it is the load base, which is
 *                         what turns every link-time address in the dynamic
 *                         section into a runtime one.
 *
 *   __horus_relro_start / __horus_relro_end
 *                         the GOT, and the read-only-after-relocation data, ON
 *                         PAGES OF THEIR OWN. crt0 fills the GOT with the
 *                         library's addresses and then seals exactly this range
 *                         (SYS_MEM_SEAL), so a later write cannot redirect a call.
 *
 * WHY THE GOT MOVED. pie.ld puts .got between .data and .bss in one segment, so
 * its pages hold the program's writable variables too, and sealing them would
 * seal those. Here it is page-aligned on both sides, and the seal takes nothing
 * the program still needs to write.
 */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD    FLAGS(5);   /* R + X */
    rodata PT_LOAD    FLAGS(4);   /* R     */
    data   PT_LOAD    FLAGS(6);   /* R + W, the RELRO pages first */
    dyn    PT_DYNAMIC FLAGS(4);
}

SECTIONS
{
    . = 0;
    __horus_image_start = .;
    .text : { *(.text) *(.text.*) } :text

    . = ALIGN(0x1000);
    .rodata  : { *(.rodata) *(.rodata.*) } :rodata
    .dynamic : { *(.dynamic) }             :rodata :dyn
    .rel.dyn  : { *(.rel.dyn) *(.rel.*) }    :rodata
    .rela.dyn : { *(.rela.dyn) *(.rela.*) }  :rodata
    .dynsym  : { *(.dynsym) }              :rodata
    .dynstr  : { *(.dynstr) }              :rodata
    .hash    : { *(.hash) *(.gnu.hash) }   :rodata

    . = ALIGN(0x1000);
    __horus_relro_start = .;
    .data.rel.ro : { *(.data.rel.ro) *(.data.rel.ro.*) } :data
    .got  : { *(.got) *(.got.plt) }        :data
    . = ALIGN(0x1000);
    __horus_relro_end = .;

    .data : { *(.data) *(.data.*) }        :data
    .bss  : { *(.bss) *(.bss.*) *(COMMON) } :data

    /DISCARD/ : {
        *(.eh_frame) *(.eh_frame.*)
        *(.note) *(.note.*)
        *(.comment) *(.gnu.version*) *(.interp)
    }
}
