/* libhorus conformance self-test (LIBHORUS_SELFTEST builds only).
 *
 * WHY THIS EXISTS AT ALL. Sharing a runtime concentrates risk: before libhorus,
 * a bug in one program's private umemcpy broke one program. Now a bug in
 * libhorus breaks init, shell, fs_server and console_server at once. That
 * concentration is the trade the library makes, and it is only a good trade if
 * the shared copy is held to a standard the seven private copies never were.
 *
 * So this asserts the properties the call sites actually depend on, from ring 3,
 * on the real binary the ISO ships -- not the happy path. Two of them are the
 * reason the file exists:
 *
 *   1. ustrncpy ALWAYS terminates. Its callers write a name into a fixed buffer
 *      and then treat it as a C string. strncpy's contract leaves the buffer
 *      unterminated exactly when the source did not fit, which is the case
 *      nobody tests and an attacker picks. Falsified by
 *      LIBHORUS_STRNCPY_UNTERMINATED=1.
 *
 *   2. ipc_call_retry NEVER retries a permanent refusal. This is finding G-8
 *      signature C: SYS_ERR_PERM means "you hold no capability for this
 *      endpoint", and the old `while (r < 0) spin_delay();` spun on it forever,
 *      turning the one event the capability system exists to make visible into
 *      an indistinguishable hang. Until now that property was asserted by
 *      comments in two programs and tested by nothing. Falsified by
 *      LIBHORUS_RETRY_ANY=1, which restores the old loop: this test then never
 *      returns and the PASS marker never appears.
 *
 * Prints its own marker from ring 3, so LIBHORUS_SELFTEST: PASS on serial is
 * end-to-end proof rather than a claim about a build.
 */
#include "syscall.h"
#include "libhorus.h"

static int failures;

static void check(int ok, const char *what) {
    if (ok) return;
    kput("LIBHORUS_SELFTEST: FAIL ");
    kput(what);
    kput("\n");
    failures++;
}

/* A canary byte either side of the region under test. Every bounded write here
 * must leave both untouched; an off-by-one that writes one past the end is the
 * mistake these helpers are most likely to grow, and a length check alone would
 * not see it. */
#define GUARD 0x5A

static void test_memory(void) {
    uint8_t buf[16];

    umemset(buf, GUARD, sizeof(buf));
    umemset(buf + 4, 0x11, 8);
    check(buf[3] == GUARD && buf[12] == GUARD, "memset-overran");
    check(buf[4] == 0x11 && buf[11] == 0x11, "memset-underfilled");

    /* n == 0 must write nothing at all. */
    umemset(buf, GUARD, sizeof(buf));
    umemset(buf + 8, 0x22, 0);
    check(buf[8] == GUARD, "memset-zero-wrote");

    uint8_t src[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    umemset(buf, GUARD, sizeof(buf));
    umemcpy(buf + 2, src, sizeof(src));
    check(buf[1] == GUARD && buf[10] == GUARD, "memcpy-overran");
    check(buf[2] == 1 && buf[9] == 8, "memcpy-wrong-bytes");

    umemset(buf, GUARD, sizeof(buf));
    umemcpy(buf + 2, src, 0);
    check(buf[2] == GUARD, "memcpy-zero-wrote");
}

static void test_strings(void) {
    check(uslen("") == 0, "uslen-empty");
    check(uslen("abcd") == 4, "uslen-four");

    check(ustreq("", ""), "ustreq-empty");
    check(ustreq("horus", "horus"), "ustreq-same");
    check(!ustreq("horus", "horuz"), "ustreq-lastchar");
    check(!ustreq("horus", "horu"), "ustreq-prefix");
    check(!ustreq("horu", "horus"), "ustreq-prefix-rev");

    /* The termination guarantee, at each boundary that matters. */
    char d[8];

    umemset(d, GUARD, sizeof(d));
    ustrncpy(d, "abc", sizeof(d));                  /* fits */
    check(ustreq(d, "abc"), "strncpy-fit");
    check(d[4] == GUARD, "strncpy-fit-overran");

    umemset(d, GUARD, sizeof(d));
    ustrncpy(d, "abcdefghij", sizeof(d));           /* truncates */
    check(d[7] == 0, "strncpy-truncate-unterminated");
    check(ustreq(d, "abcdefg"), "strncpy-truncate-content");

    umemset(d, GUARD, sizeof(d));
    ustrncpy(d, "abcdefg", 8);                      /* exact fit + NUL */
    check(d[7] == 0, "strncpy-exact-unterminated");

    umemset(d, GUARD, sizeof(d));
    ustrncpy(d, "abc", 1);                          /* room for the NUL only */
    check(d[0] == 0, "strncpy-one-unterminated");
    check(d[1] == GUARD, "strncpy-one-overran");

    umemset(d, GUARD, sizeof(d));
    ustrncpy(d, "abc", 0);                          /* must write nothing */
    check(d[0] == GUARD, "strncpy-zero-wrote");
}

/* The property that matters most, and the one nothing tested before.
 *
 * CAPSLOT_NOTIFY is empty in this task: the selftest installs no capability
 * there. sys_ipc_call against an empty slot is SYS_ERR_PERM -- a PERMANENT
 * refusal -- so ipc_call_retry must return it promptly and unchanged.
 *
 * "Promptly" is the whole assertion, and it is why this test is structured as a
 * return rather than a comparison: under LIBHORUS_RETRY_ANY=1 the call does not
 * come back at all, so there is nothing to compare. The gate is the marker that
 * follows never being printed. A test for a hang cannot be an equality check. */
static void test_ipc_refusal_is_not_retried(void) {
    uint8_t req[16];
    uint8_t rep[16];

    umemset(req, 0, sizeof(req));
    umemset(rep, 0, sizeof(rep));

    kput("LIBHORUS_SELFTEST: calling an empty slot (must refuse, not spin)\n");
    int r = ipc_call_retry(CAPSLOT_NOTIFY, 0, req, sizeof(req), rep);

    /* Reaching here at all is the result. The specific code is checked too:
     * a permanent refusal must be handed back unchanged, not remapped to the
     * retry-exhausted sentinel, or a caller cannot tell "denied" from "busy". */
    check(r < 0, "refusal-returned-success");
    check(r != IPC_ERR_RETRY_EXHAUSTED, "refusal-reported-as-exhausted");
}

void _start(void) {
    kput("LIBHORUS_SELFTEST: begin\n");

    test_memory();
    test_strings();
    test_ipc_refusal_is_not_retried();

    /* Exercised for its INT_MIN path: negating INT_MIN as a signed int is
     * undefined, and a diagnostic that invokes UB while reporting a fault is
     * worse than no diagnostic. Printed rather than compared because kput_int
     * writes to fd 1 and libhorus has no format-to-buffer entry point -- adding
     * one purely so a test could read it back would be shaping the interface
     * around the test. The value is on the wire for a reader. */
    kput("LIBHORUS_SELFTEST: int_min=");
    kput_int(-2147483647 - 1);
    kput(" zero=");
    kput_int(0);
    kput(" neg=");
    kput_int(-42);
    kput("\n");

    if (failures == 0) kput("LIBHORUS_SELFTEST: PASS\n");
    else               kput("LIBHORUS_SELFTEST: FAIL\n");

    sys_exit();
    for (;;) { }
}
