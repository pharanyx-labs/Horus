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

struct shlib_exports {
    int (*add)(int, int);
    int (*magic)(void);
    int (*checksum)(const char *);
    const void *end;
};

void _start(void) {
    unsigned pages = 0;
    for (unsigned i = 0; i < 32; i++) {
        int rc = sys_map_frame(SLOT_SHLIB_FIRST + i, SHLIB_VA + (unsigned long long)i * 4096,
                               CAP_RIGHT_READ | CAP_RIGHT_EXEC);
        if (rc != 0) break;
        pages = i + 1;
    }
    if (pages == 0) { wr("SHLIBTEST: FAIL peer-no-pages\n"); for (;;) sys_yield(); }

    struct shlib_exports *ex = (struct shlib_exports *)(unsigned long)(SHLIB_VA + 0x4000);
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

    wr("SHLIBTEST: PASS\n");
    for (;;) sys_yield();
}
