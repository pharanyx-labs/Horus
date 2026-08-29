#include "syscall.h"

/*
 * SHLIB_SELFTEST driver -- the witness that shared library text is executable by
 * many and writable by none (S49).
 *
 * The kernel loads userspace/shlibdemo.so ONCE into frames at boot and endows
 * two tasks with READ|EXEC capabilities over those same frames. This task maps
 * them, calls into the library, and then tries every way it has to write them.
 * shlibpeer does the same independently and reports the pair's verdict.
 *
 * WHY THIS MATTERS MORE THAN THE SIZE SAVING. Sharing a library is a memory
 * optimisation; sharing it WRITABLY is a code-injection primitive between every
 * task that maps it -- one task patches a function and another runs the patch.
 * That is strictly worse than the static per-program copies it replaces, which
 * at least isolated the damage. So the interesting assertion here is not that
 * the call works, it is that the write does not.
 */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }

#define SLOT_SHLIB_FIRST 40          /* caps over the library's pages */
#define SHLIB_VA         0x0000000300000000ULL

/* SHLIB_EXPORTS_OFF, SHLIB_PAGES and SHLIB_DATA_PAGE are DERIVED from
 * shlibdemo.so at build time by tools/shlib_offsets.sh. They were hardcoded
 * until 2026-08-29 -- the export table was `SHLIB_VA + 0x4000` here and in
 * shlibpeer.c -- and the linker script that split the object into a shared and a
 * per-task segment moved it. A test that reads the wrong address does not fail
 * honestly; it reads whatever is there and reports on it. */
#include "shlib_offsets.h"

/* The library's export table, at its base +e_entry. Index, not name: resolving
 * by name is what a dynamic linker does and this mechanism does not have one
 * yet -- said plainly rather than implied. */
struct shlib_exports {
    int (*add)(int, int);
    int (*magic)(void);
    int (*checksum)(const char *);
    int (*state_get)(void);
    void (*state_set)(int);
    int (*state_initial)(void);
    const void *end;
};

/* The value this task writes into its own copy of the library's data. Arbitrary,
 * and deliberately not the initialiser: the peer distinguishes "I saw my own
 * initialised copy" from "I saw the value the other task wrote". */
#define OUR_STATE 0x0BADF00D

#define MAGIC_EXPECTED 0x5A5A1234

void _start(void) {
    wr("SHLIBTEST: begin\n");

    /* (1) Map every page of the library from the capabilities we were given.
     * READ|EXEC is all we ask for, and all we could get: the capabilities were
     * minted without WRITE, and rights only ever narrow on delegation (S27). */
    unsigned pages = 0;
    for (unsigned i = 0; i < SHLIB_PAGES; i++) {
        /* Each page is asked for the rights ITS capability carries, and the two
         * sets are disjoint on purpose: text is READ|EXEC and never writable
         * (S49), data is READ|WRITE and never executable (W^X -- this task can
         * write the page, so it must not be able to jump into what it wrote).
         *
         * Asking uniformly would fail on whichever page it guessed wrong, and a
         * loop that breaks on first failure would then report "no pages" rather
         * than the property under test. */
        unsigned rights = (i == SHLIB_DATA_PAGE)
                        ? (CAP_RIGHT_READ | CAP_RIGHT_WRITE)
                        : (CAP_RIGHT_READ | CAP_RIGHT_EXEC);
        int rc = sys_map_frame(SLOT_SHLIB_FIRST + i, SHLIB_VA + (unsigned long long)i * 4096,
                               rights);
        if (rc != 0) break;
        pages = i + 1;
    }
    if (pages == 0) { wr("SHLIBTEST: FAIL no-pages-mapped\n"); sys_exit(); }
    if (pages != SHLIB_PAGES) { wr("SHLIBTEST: FAIL partial-map\n"); sys_exit(); }

    /* (2) Call into it. The entry table's address is what the kernel put in the
     * library's e_entry; the loader mapped the whole object at SHLIB_VA. */
    struct shlib_exports *ex =
        (struct shlib_exports *)(unsigned long)(SHLIB_VA + SHLIB_EXPORTS_OFF);
    if (ex->magic == 0 || ex->add == 0) { wr("SHLIBTEST: FAIL no-export-table\n"); sys_exit(); }

    if (ex->magic() != MAGIC_EXPECTED) { wr("SHLIBTEST: FAIL wrong-magic\n"); sys_exit(); }
    if (ex->add(20, 22) != 42)         { wr("SHLIBTEST: FAIL wrong-add\n"); sys_exit(); }
    if (ex->checksum("horus") != ex->checksum("horus")) {
        wr("SHLIBTEST: FAIL unstable-checksum\n"); sys_exit();
    }

    /* (2b) THE OTHER HALF, S50: this task's copy of the library's writable data.
     *
     * Two separate claims, checked separately because two separate arms break
     * them separately:
     *
     *   initialised -- the copy carries the library's initialisers, not zeroes.
     *                  SHLIB_DATA_UNINITIALISED=1 breaks this and nothing else.
     *   private     -- no other task sees what this one writes. Only the PEER
     *                  can witness that, which is why the sentinel is written
     *                  here and judged there.
     *
     * The expected value comes from the library's own TEXT (state_initial),
     * never from a literal here: a constant written down in this file would be a
     * second copy of a fact shlibdemo.c owns, and the two would drift. */
    if (ex->state_get == 0 || ex->state_set == 0 || ex->state_initial == 0) {
        wr("SHLIBTEST: FAIL no-state-exports\n"); sys_exit();
    }
    if (ex->state_get() != ex->state_initial()) {
        wr("SHLIBTEST: FAIL data-not-initialised\n"); sys_exit();
    }

    /* Write our sentinel through the library's own accessor -- a real store to
     * the library's .data, made by library code, which is what a libc doing
     * `errno = EINVAL` would be. If this faults, the data page was mapped
     * read-only and the property is broken in the other direction. */
    ex->state_set(OUR_STATE);
    if (ex->state_get() != OUR_STATE) {
        wr("SHLIBTEST: FAIL own-write-not-visible\n"); sys_exit();
    }
    wr("SHLIBTEST: data initialised from the image, and written\n");

    /* (3) THE ASSERTION. Try to obtain a writable mapping of the same frames,
     * every way the ABI offers.
     *
     * Asking for WRITE outright is the obvious one and S27's rights floor
     * refuses it. Asking for WRITE|EXEC is refused twice over -- by the floor and
     * by W^X. And mapping READ|EXEC at a second address then writing THROUGH it
     * is the one worth having: it checks the PTE really lacks the write bit,
     * rather than only that the syscall said no. */
#ifndef SHLIB_TEXT_WRITABLE
    if (sys_map_frame(SLOT_SHLIB_FIRST, SHLIB_VA + 0x100000,
                      CAP_RIGHT_READ | CAP_RIGHT_WRITE) == 0) {
        wr("SHLIBTEST: FAIL got-writable-mapping\n"); sys_exit();
    }
    if (sys_map_frame(SLOT_SHLIB_FIRST, SHLIB_VA + 0x100000,
                      CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC) == 0) {
        wr("SHLIBTEST: FAIL got-wx-mapping\n"); sys_exit();
    }

    wr("SHLIBTEST: mapped and called; no writable mapping obtainable\n");
#endif

    /* Under the arm the checks above are skipped deliberately -- they CANNOT
     * pass there, and stopping at the first of them would make the arm's marker
     * "a writable mapping was obtainable" rather than the thing that matters,
     * which is what the OTHER task then executes. The probe stops at its first
     * failure, so which failure it reaches is a choice about what the arm
     * demonstrates. */

#ifdef SHLIB_TEXT_WRITABLE
    /* The control arm's payload, and it is the attack this property exists to
     * prevent rather than a symbolic stand-in for one.
     *
     * Map the SAME frames a second time, writable (no EXEC, so W^X is not what
     * refuses it -- only the missing WRITE right would be), and overwrite
     * shlib_magic with `mov eax, 0xDEADBEEF; ret`. We execute through the
     * read+exec alias; the peer executes through its own. Neither of us wrote
     * anything the other could see, on a correct kernel.
     *
     * Note which task is harmed: not this one. The peer calls a function this
     * task rewrote, in its own address space, having asked for nothing but
     * read+exec. That asymmetry is why a shared library mapped writable is worse
     * than the per-program static copies it replaces. */
    {
        unsigned long long rw = SHLIB_VA + 0x200000;
        for (unsigned i = 0; i < pages; i++) {
            if (sys_map_frame(SLOT_SHLIB_FIRST + i, rw + (unsigned long long)i * 4096,
                              CAP_RIGHT_READ | CAP_RIGHT_WRITE) != 0) {
                wr("SHLIBTEST: FAIL arm-no-rw-mapping\n"); sys_exit();
            }
        }
        unsigned long long off = (unsigned long long)(unsigned long)ex->magic - SHLIB_VA;
        volatile unsigned char *p = (volatile unsigned char *)(unsigned long)(rw + off);
        p[0] = 0xB8;                       /* mov eax, imm32 */
        p[1] = 0xEF; p[2] = 0xBE; p[3] = 0xAD; p[4] = 0xDE;
        p[5] = 0xC3;                       /* ret */
        wr("SHLIBTEST: patched shared text through a writable alias\n");
    }
#endif

    /* (4) Hand over to the peer, which maps the SAME frames independently and
     * checks it sees the same code -- and, under the control arm, whether this
     * task's patch is visible to it. The peer is spawned suspended so this task
     * finishes its own checks first; frametest holds its peer back the same way
     * and for the same reason. */
    int peer = (int)sys_spawn_arg();
    if (peer <= 0) { wr("SHLIBTEST: FAIL peer-tid\n"); sys_exit(); }
    if (sys_task_resume(peer) != 0) {
        wr("SHLIBTEST: FAIL resume-peer\n"); sys_exit();
    }
    for (;;) sys_yield();
}
