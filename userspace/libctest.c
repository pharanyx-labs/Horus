#include "syscall.h"
#include "libc_exports.h"

/*
 * libctest -- newlib, executing from the shared library, in ring 3.
 *
 * WHAT THIS IS THE WITNESS FOR. Roadmap 2.5 has had its mechanism since S49:
 * text shared and unwritable, data private per task (S50), base randomised per
 * boot (S51). What it has NOT had is a program that actually calls a libc
 * function out of that library rather than out of its own static copy. Every
 * property above was demonstrated on `shlibdemo.so`, a three-page object written
 * for the purpose. This one runs the real thing -- ~135 KiB of newlib, its port
 * glue and libhorus, linked into one object the kernel loads at boot.
 *
 * The distinction matters because a demo object cannot fail the way a libc can.
 * newlib is not a bag of pure functions: it has writable state (`_impure_ptr`,
 * which is errno, the stdio buffers, the atexit list and the rand state), it
 * calls back into the port's syscall glue, and it allocates. Each of those
 * crosses the shared/private boundary S50 draws, and none of them was exercised
 * by an object whose entire data segment was one `int`.
 *
 * WHY IT DOES NOT LINK AGAINST THE LIBRARY. It calls THROUGH the export table by
 * index, and links nothing. That is deliberate and it is the honest shape of
 * what exists: there is no dynamic linker here, so a program cannot yet resolve
 * `strlen` by name and have it bind to the library. Generating stubs that do
 * this per symbol is the next step and it is a build-system job; what has to be
 * true first is that the calls WORK, which is what this file establishes.
 *
 * The indices come from libc_exports.h, generated in the same pass as the table
 * itself, so this file holds no remembered numbers -- see
 * tools/gen_libc_exports.sh on why order is the ABI.
 */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }

/* Must match LIBC_SLOT_FIRST in src/include/kernel.h. */
#define SLOT_LIBC_FIRST 40

/* The table the kernel put at the library's e_entry. Read-only and shared: it
 * holds pointers into shared text, so a per-task copy would be a table each
 * task could rewrite. */
typedef const void *const *export_table;

void _start(void) {
    wr("LIBCTEST: begin\n");

    /* (1) Where is the library this boot? The base is drawn at boot (S51), so it
     * is asked for rather than assumed -- and answered only because slot
     * SLOT_LIBC_FIRST holds a capability over the library's own text. */
    struct shlib_info si;
    if (sys_shlib_info(SLOT_LIBC_FIRST, &si) != 0) {
        wr("LIBCTEST: FAIL shlib-info\n"); sys_exit();
    }
    if (si.pages == 0 || si.entry == 0) {
        wr("LIBCTEST: FAIL empty-library\n"); sys_exit();
    }

    /* (2) Map it. Text READ|EXEC, the one writable page READ|WRITE and never
     * EXEC -- each page asked for the rights ITS capability carries, because the
     * two sets are disjoint and a uniform request fails on whichever it guessed
     * wrong. */
    unsigned mapped = 0;
    for (unsigned i = 0; i < si.pages; i++) {
        /* The writable RANGE, not a single page: newlib's writable segment is
         * two pages. Asking uniformly, or assuming one, fails on whichever page
         * it guessed wrong -- which is exactly how the first version of this
         * test found that the ABI reported one index. */
        int is_data = (si.data_first != SHLIB_INFO_NO_DATA) &&
                      (i >= si.data_first) && (i < si.data_first + si.data_pages);
        unsigned rights = is_data ? (CAP_RIGHT_READ | CAP_RIGHT_WRITE)
                                  : (CAP_RIGHT_READ | CAP_RIGHT_EXEC);
        if (sys_map_frame(SLOT_LIBC_FIRST + i,
                          si.base + (unsigned long long)i * 4096, rights) != 0) break;
        mapped = i + 1;
    }
    if (mapped != si.pages) {
        wr("LIBCTEST: FAIL partial-map\n"); sys_exit();
    }

    export_table ex = (export_table)(unsigned long)si.entry;

    /* (3) Pure text first, because it isolates the failure. If `strlen` does not
     * work, nothing about data or allocation is worth reporting -- the library is
     * not mapped where it was relocated for, and every later check would fail for
     * that one reason. */
    {
        unsigned long (*p_strlen)(const char *) =
            (unsigned long (*)(const char *))ex[SHLIB_IDX_strlen];
        int (*p_strcmp)(const char *, const char *) =
            (int (*)(const char *, const char *))ex[SHLIB_IDX_strcmp];

        if (p_strlen == 0 || p_strcmp == 0) {
            wr("LIBCTEST: FAIL null-export\n"); sys_exit();
        }
        if (p_strlen("horus") != 5) {
            wr("LIBCTEST: FAIL strlen\n"); sys_exit();
        }
        if (p_strcmp("horus", "horus") != 0 || p_strcmp("a", "b") >= 0) {
            wr("LIBCTEST: FAIL strcmp\n"); sys_exit();
        }
        wr("LIBCTEST: shared text executes\n");
    }

    /* (4) The library's WRITABLE state, which is the half a demo object could
     * not exercise. `_impure_ptr` is newlib's per-process reentrancy structure:
     * errno, the stdio buffers, the atexit list, the rand state. It lives in the
     * library's data segment, and its value is an address patched by a RELATIVE
     * relocation into the TEMPLATE page -- so every task's private copy inherits
     * a pointer to the library's data page, which each task maps its own frame
     * of. It must therefore point INTO the library's mapping and not be null. */
    {
        void **p_impure = (void **)ex[SHLIB_IDX__impure_ptr];
        if (p_impure == 0) {
            wr("LIBCTEST: FAIL no-impure-export\n"); sys_exit();
        }
        unsigned long long v = (unsigned long long)(unsigned long)*p_impure;
        if (v == 0) {
            wr("LIBCTEST: FAIL impure-null\n"); sys_exit();
        }
        if (v < si.base || v >= si.base + (unsigned long long)si.pages * 4096) {
            wr("LIBCTEST: FAIL impure-outside-library\n"); sys_exit();
        }
        wr("LIBCTEST: reentrancy state resolves inside the library\n");
    }

    /* (5) A call that goes THROUGH the library's writable state. `strlen` above
     * is pure text; this is not -- newlib's sprintf reaches the reentrancy
     * structure, so it exercises the shared/private boundary rather than only
     * the shared half. If the data page were mapped read-only, or were shared
     * between tasks, this is where it shows.
     *
     * sprintf and not snprintf: the export set is DERIVED from what the shipped
     * programs actually reference (tools/gen_libc_exports.sh), and they use
     * sprintf. Reaching for a symbol that is not in the table would have been a
     * test written against an interface nobody asked for. */
    {
        int (*p_sprintf)(char *, const char *, ...) =
            (int (*)(char *, const char *, ...))ex[SHLIB_IDX_sprintf];
        if (p_sprintf == 0) {
            wr("LIBCTEST: FAIL no-sprintf-export\n"); sys_exit();
        }
        char buf[32];
        for (unsigned i = 0; i < sizeof(buf); i++) buf[i] = 0;
        int n = p_sprintf(buf, "%s-%d", "horus", 42);
        if (n != 8) { wr("LIBCTEST: FAIL sprintf-len\n"); sys_exit(); }
        const char *want = "horus-42";
        for (int i = 0; i < 9; i++)
            if (buf[i] != want[i]) { wr("LIBCTEST: FAIL sprintf-text\n"); sys_exit(); }
        wr("LIBCTEST: formatted output through the library's own state\n");
    }

    wr("LIBCTEST: PASS\n");
    sys_exit();
}
