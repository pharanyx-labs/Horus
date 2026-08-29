/* shlib_start.c -- what a shared-libc program does before it has a libc.
 *
 * A program linked against the stub archive has no libc code of its own: every
 * libc function it calls is a tail jump through the export table
 * (tools/gen_libc_stubs.sh). This file is what makes that table exist, and it
 * runs before anything that could use it.
 *
 * IT CANNOT CALL LIBC, and that constraint shapes the whole file. memset, the
 * stdio it would like for an error message, even memcpy -- all of them are
 * stubs that jump through a table this code has not filled in yet, so calling
 * one before the end of shlib_bind() jumps through a null pointer. Everything
 * here is therefore hand-rolled and uses only raw syscalls.
 *
 * WHAT IT DOES, in the order it has to happen:
 *
 *   1. Ask where the library is (SYS_SHLIB_INFO). The base is drawn per boot
 *      (S51), so it cannot be assumed -- and the call is answered only because
 *      this task holds a capability over the library's own text.
 *   2. Map every page, asking each for the rights ITS capability carries: text
 *      READ|EXEC and never WRITE (S49), the writable range READ|WRITE and never
 *      EXEC (S50). A uniform request fails on whichever kind it guessed wrong.
 *   3. Publish the export table's address. Every stub reads it, so nothing may
 *      call a stub before this line.
 *   4. Initialise _impure_ptr from the table.
 *
 * WHY STEP 4 IS THE INTERESTING ONE. _impure_ptr is newlib's per-process
 * reentrancy structure -- errno, the stdio buffers, the atexit list, the rand
 * state. It is DATA, and a data reference cannot be redirected by a tail jump:
 * the compiler emits the address directly. That is what needs a GOT, and a GOT
 * is what a real dynamic linker provides.
 *
 * It works here anyway, and only because of what it is: a POINTER to per-task
 * state rather than the state itself. The program gets its own copy of the
 * pointer, initialised from the library's, and it points at the one struct
 * _reent in the library's own private data page -- the copy S50 gives this task.
 * So the program and the library agree about errno without sharing a variable.
 *
 * optarg and optind get no such treatment and cannot: they ARE the state. A
 * program-local copy would diverge from the library's getopt that writes it, so
 * no stub is emitted, and a program that needs them fails to LINK rather than
 * running with an optind that silently stops advancing.
 */
#include "syscall.h"

/* Filled in by shlib_bind(); read by every stub in libc_stubs.S. Deliberately
 * not static: the thunks reference it by name. */
const void *const *__horus_shlib_table;

/* newlib's reentrancy pointer, as the program's own copy. The library has its
 * own; both end up pointing at the same struct in the library's per-task data. */
struct _reent;
struct _reent *_impure_ptr;

/* Must match LIBC_SLOT_FIRST in src/include/kernel.h -- the first capability
 * over the shared library's pages. */
#define SLOT_LIBC_FIRST 40

/* Index of _impure_ptr in the export table. Generated with the table itself, so
 * this file holds no remembered number. */
#include "libc_exports.h"

/* Returns 0 on success. On failure the caller has no libc and cannot report
 * much: it writes a fixed string with a raw syscall and exits, because a
 * program that continues here dies later at an address that explains nothing. */
int shlib_bind(void) {
    struct shlib_info si;

    if (sys_shlib_info(SLOT_LIBC_FIRST, &si) != 0) return -1;
    if (si.pages == 0 || si.entry == 0) return -1;

    for (unsigned i = 0; i < si.pages; i++) {
        int is_data = (si.data_first != SHLIB_INFO_NO_DATA) &&
                      (i >= si.data_first) && (i < si.data_first + si.data_pages);
        unsigned rights = is_data ? (CAP_RIGHT_READ | CAP_RIGHT_WRITE)
                                  : (CAP_RIGHT_READ | CAP_RIGHT_EXEC);
        if (sys_map_frame(SLOT_LIBC_FIRST + i,
                          si.base + (unsigned long long)i * 4096, rights) != 0)
            return -1;
    }

    /* Publish LAST of the mapping steps: a stub that read this pointer while the
     * library was half-mapped would jump into an address that is not there yet.
     * Nothing in this function calls a stub, which is what makes the ordering
     * enforceable rather than merely intended. */
    __horus_shlib_table = (const void *const *)(unsigned long)si.entry;

    /* The library's own _impure_ptr lives in its per-task data; the table entry
     * is the ADDRESS of that pointer, so one dereference gives the value the
     * library itself uses. */
    struct _reent **lib_impure =
        (struct _reent **)__horus_shlib_table[SHLIB_IDX__impure_ptr];
    if (lib_impure == 0 || *lib_impure == 0) return -1;
    _impure_ptr = *lib_impure;

    return 0;
}
