#include "syscall.h"

/*
 * Copy-on-write self-test driver (COW_SELFTEST builds only).
 *
 * Proves the shared-zero-page / copy-on-write path end to end, entirely from
 * ring 3 — the observable property needs no kernel introspection:
 *
 *   1. A fresh, never-touched heap region reads back as zeros. Under the hood
 *      each read faults in the one shared zero page read-only + COW, but that is
 *      invisible here; what we assert is that the bytes are zero.
 *   2. Writing one page must NOT disturb a sibling page. If the shared zero page
 *      were mapped writable and shared, a write to page A would change page B
 *      too. It must instead trigger a private copy for A alone.
 *   3. The written value must stick, and re-reading the sibling must still be
 *      zero.
 *
 * What this does NOT distinguish: these assertions hold equally if the pager
 * ignored the shared zero page and simply handed every fault its own private
 * zeroed frame — isolation and zero-reads are properties of both designs. This
 * gates the user-visible contract (which is the part a regression would break in
 * a way userspace can see); that the sharing itself engages was confirmed by
 * tracing the pager (two zero-page->private breaks, one per written page, exactly
 * as expected here). Asserting it in CI needs kernel introspection this test
 * deliberately does without — see get_cow_fault_count().
 *
 * Prints "COW_SELFTEST: PASS" on success; `make smoke-cow` asserts on it, and on
 * "COW_SELFTEST: FAIL" for the failure path.
 */

static void report(const char *s) {
    int n = 0;
    while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

void _start(void) {
    /* A fresh region straight from the break: sbrk returns the old break, so
     * [base, base+len) has never been touched — every page still demand-faults. */
    volatile unsigned char *base = (volatile unsigned char *)sys_sbrk(0x4000);
    if (base == (void *)-1 || base == 0) {
        report("COW_SELFTEST: FAIL sbrk\n"); sys_exit();
    }

    volatile unsigned char *a = base + 0x1000;   /* page A */
    volatile unsigned char *b = base + 0x2000;   /* page B */

    /* 1. Fresh pages read as zero (each aliases the shared zero page on read). */
    if (a[0] != 0 || a[7] != 0 || b[0] != 0 || b[7] != 0) {
        report("COW_SELFTEST: FAIL nonzero\n"); sys_exit();
    }

    /* 2. Write page A. This is a write to a read-only COW alias of the zero page,
     *    so it must break COW and give A a private frame. */
    a[0] = 0xAB;
    a[7] = 0xCD;

    /* 3. A holds the writes; B is untouched (still the shared zero page). If A and
     *    B had wrongly shared one writable frame, b[0] would now be 0xAB. */
    if (a[0] != 0xAB || a[7] != 0xCD) {
        report("COW_SELFTEST: FAIL write-lost\n"); sys_exit();
    }
    if (b[0] != 0 || b[7] != 0) {
        report("COW_SELFTEST: FAIL isolation\n"); sys_exit();
    }

    /* 4. Writing B now must likewise stay private to B and not disturb A. */
    b[0] = 0x11;
    if (b[0] != 0x11 || a[0] != 0xAB) {
        report("COW_SELFTEST: FAIL isolation2\n"); sys_exit();
    }

    report("COW_SELFTEST: PASS\n");
    sys_exit();
}
