#include "syscall.h"

/*
 * The second half of SHLIB_SELFTEST. It maps the SAME library frames as
 * shlibtest, independently, and checks that what it executes is what the kernel
 * loaded -- not what another task put there.
 *
 * A single task proving it cannot write its own library page proves less than it
 * looks: the interesting failure is cross-task, where one holder of a shared
 * mapping patches code a DIFFERENT holder runs. So the pair is the witness, and
 * this side is the one that would notice.
 */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }

#define SLOT_SHLIB_FIRST 40
#define SHLIB_VA         0x0000000300000000ULL
#define MAGIC_EXPECTED   0x5A5A1234

/* Derived from shlibdemo.so at build time; see the note in shlibtest.c. */
#include "shlib_offsets.h"

struct shlib_exports {
    int (*add)(int, int);
    int (*magic)(void);
    int (*checksum)(const char *);
    int (*state_get)(void);
    void (*state_set)(int);
    int (*state_initial)(void);
    const void *end;
};

/* Must match OUR_STATE in shlibtest.c: the value the OTHER task wrote into its
 * own copy of the library's data. Seeing it here means the two tasks share one
 * writable page, which is the disclosure S50 refuses. */
#define PEER_SENTINEL 0x0BADF00D

void _start(void) {
    unsigned pages = 0;
    for (unsigned i = 0; i < SHLIB_PAGES; i++) {
        /* Rights per page, as in shlibtest: text READ|EXEC, data READ|WRITE.
         * This task asks for a writable mapping of ITS OWN data page, which it
         * is entitled to -- the question S50 answers is whose page that is. */
        unsigned rights = (i == SHLIB_DATA_PAGE)
                        ? (CAP_RIGHT_READ | CAP_RIGHT_WRITE)
                        : (CAP_RIGHT_READ | CAP_RIGHT_EXEC);
        int rc = sys_map_frame(SLOT_SHLIB_FIRST + i, SHLIB_VA + (unsigned long long)i * 4096,
                               rights);
        if (rc != 0) break;
        pages = i + 1;
    }
    if (pages == 0) { wr("SHLIBTEST: FAIL peer-no-pages\n"); for (;;) sys_yield(); }
    if (pages != SHLIB_PAGES) { wr("SHLIBTEST: FAIL peer-partial-map\n"); for (;;) sys_yield(); }

    struct shlib_exports *ex =
        (struct shlib_exports *)(unsigned long)(SHLIB_VA + SHLIB_EXPORTS_OFF);
    if (ex->magic == 0) { wr("SHLIBTEST: FAIL peer-no-export-table\n"); for (;;) sys_yield(); }

    /* The magic value is the thing a patch would change, and this task never
     * wrote it. Under MAGIC_EXPECTED it proves the peer executes the kernel's
     * copy; under the control arm, where shlibtest gets a writable mapping and
     * patches the function, this is where the patch surfaces. */
    int m = ex->magic();
    if (m != MAGIC_EXPECTED) {
        wr("SHLIBTEST: FAIL peer-saw-patched-code\n");
        for (;;) sys_yield();
    }
    if (ex->add(1, 2) != 3) { wr("SHLIBTEST: FAIL peer-wrong-add\n"); for (;;) sys_yield(); }

    /* THE S50 ASSERTION, and this task is the only one that can make it.
     *
     * shlibtest ran first and wrote PEER_SENTINEL into its copy of the library's
     * writable data. This task reads the same symbol, at the same virtual
     * address, through its own mapping. It must see the library's INITIALISER --
     * meaning it got a copy of its own, made from the library's image.
     *
     * Two distinguishable failures, so the marker names which one happened:
     *
     *   the other task's value  -> the data page is SHARED. One task reads and
     *                              writes another's libc state; for real newlib
     *                              that is another task's errno, stdio buffers
     *                              and malloc arena.
     *   anything else           -> the copy was never initialised from the
     *                              library's image (zeroes, typically).
     *
     * The expected value is read from the library's TEXT, which is shared and
     * immutable, so this comparison holds no copy of a constant that could
     * drift from shlibdemo.c's. */
    if (ex->state_get == 0 || ex->state_initial == 0) {
        wr("SHLIBTEST: FAIL peer-no-state-exports\n"); for (;;) sys_yield();
    }
    {
        int seen = ex->state_get();
        if (seen == PEER_SENTINEL) {
            wr("SHLIBTEST: FAIL peer-saw-our-data\n"); for (;;) sys_yield();
        }
        if (seen != ex->state_initial()) {
            wr("SHLIBTEST: FAIL data-not-initialised\n"); for (;;) sys_yield();
        }
    }

    /* And the write must land in THIS task's copy only. shlibtest has already
     * finished reading, so nothing downstream depends on the value; what is
     * being checked is that a store by library code works at all on a page that
     * had to be writable to be useful. */
    ex->state_set(0x51500001);
    if (ex->state_get() != 0x51500001) {
        wr("SHLIBTEST: FAIL peer-own-write-not-visible\n"); for (;;) sys_yield();
    }

    wr("SHLIBTEST: PASS\n");
    for (;;) sys_yield();
}
