/* shlib.ld -- two loadable segments, because they have two different owners.
 *
 * A shared library has text every task executes and data every task must have
 * its OWN of. Those are not two kinds of convenience, they are two different
 * security properties:
 *
 *   text   shared, read+exec, writable by nobody  (S49)
 *   data   private per task, read+write, never exec  (S50)
 *
 * A page is the granularity of both mapping and protection, so anything that
 * has to differ between tasks must START ON ITS OWN PAGE. That is what the
 * `. = ALIGN(4096)` before .data is for, and it is load-bearing rather than
 * tidiness: without it the linker packs .data onto the same page as .dynamic
 * and the export table, and then the page can be shared or private but the
 * three things on it need different answers. Measured before this file existed
 * -- the default script produces exactly that collision.
 *
 * THE EXPORT TABLE IS IN THE SHARED SEGMENT, deliberately. It holds function
 * pointers into shared text, and it is what the loader hands every caller; a
 * table each task could rewrite would be a table the loader found for nobody.
 * It is const, so it belongs with rodata, and it is placed explicitly because
 * -e shlib_exports puts its address in e_entry and the loader reads it there.
 *
 * WHAT WAS TRIED AND DID NOT WORK. Moving the table with a
 * `section(".rodata.shlib_exports")` attribute instead of a script: the
 * assembler warns "setting incorrect section attributes", RELRO collapses, and
 * .rodata, .dynamic and .data all land in ONE RW segment -- the opposite of
 * what was wanted. A script is the only thing that controls segment assignment
 * precisely enough, which is why this file exists rather than a one-line flag.
 */
PHDRS {
  rx   PT_LOAD    FLAGS(5);   /* R+X -- shared between every task            */
  rw   PT_LOAD    FLAGS(6);   /* R+W -- instantiated privately per task      */
  dyn  PT_DYNAMIC FLAGS(4);
}

SECTIONS {
  . = SIZEOF_HEADERS;

  /* Relocation and symbol metadata. Read once, by the loader, before any task
   * exists; shared and read-only thereafter. */
  .gnu.hash : { *(.gnu.hash) }             :rx
  .dynsym   : { *(.dynsym) }               :rx
  .dynstr   : { *(.dynstr) }               :rx
  .rela.dyn : { *(.rela.dyn) }             :rx

  . = ALIGN(4096);
  .text     : { *(.text .text.*) }         :rx
  .rodata   : { *(.rodata .rodata.*) }     :rx
  .shlib_exports : { *(.shlib_exports) }   :rx
  .dynamic  : { *(.dynamic) }              :rx :dyn

  /* ---- everything below here is PER TASK ---------------------------------
   * shlib_init copies this segment's initial image into a fresh frame for each
   * task that maps the library, so a task sees the library's initialisers and
   * never another task's writes. */
  . = ALIGN(4096);
  .data     : { *(.data .data.*) }         :rw
  .bss      : { *(.bss .bss.* COMMON) }    :rw

  /* No unwind tables: nothing in this system unwinds through library frames,
   * and .eh_frame would otherwise straddle the boundary above. */
  /DISCARD/ : { *(.eh_frame) *(.eh_frame_hdr) *(.comment) *(.note.*) }
}
