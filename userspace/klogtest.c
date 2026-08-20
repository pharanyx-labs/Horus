#include "syscall.h"

/*
 * KLOG_FORGE_SELFTEST driver — the witness for finding [H-2].
 *
 * The kernel (klog_forge_selftest) spawns this program with a CAP_KERNEL_LOG
 * capability in slot CAPSLOT_KERNEL_LOG and, immediately before entering ring 3,
 * prints KERNEL_MARKER into the kernel message ring.
 *
 * Note which right that capability carries: READ, and only READ, because
 * root_cnode[15] mints it that way and delegation can only narrow. So this probe
 * can READ the kernel log and — if the gate in h_write() is doing its job —
 * cannot write to it. Holding the capability for one direction and being refused
 * the other is the whole property under test, and it is why the probe is endowed
 * at all rather than run bare: a bare task would prove that a task with NO
 * capability cannot write, which is a weaker claim and not the one [H-2] makes.
 *
 * The sequence:
 *   1. scan the ring and confirm KERNEL_MARKER is there (setup check — if this
 *      fails the test proves nothing, so it reports FAIL setup, not PASS);
 *   2. push FLOOD_BYTES of INJECT through SYS_WRITE fd 1, which is more than the
 *      16 KiB ring holds, so under the pre-fix behaviour it both lands in the log
 *      and evicts everything already there;
 *   3. scan the ring again and require BOTH: KERNEL_MARKER survived (no
 *      eviction) and INJECT is absent (no forgery).
 *
 * Both halves matter and they fail differently. A fix that merely rate-limited
 * ring-3 appends would keep the marker and still leak INJECT; one that dropped
 * the bytes but left the ring advancing would lose the marker. Asserting only
 * one of the two would pass such a half-fix.
 */

#define KERNEL_MARKER  "KLOGTEST-KMARK-7F3A"
#define INJECT         "KLOGFORGE-INJECT"
#define CHUNK_BYTES    240      /* SYS_WRITE clamps at 255 */
#define FLOOD_CHUNKS   120      /* 120 * 240 = 28800 bytes > the 16384-byte ring */

/* The ring is read in CHUNK-byte bites with the last CARRY bytes of the previous
 * bite kept in front of the next one, so a needle lying across a chunk boundary
 * is still matched. The carry is not optional: a marker split across two reads
 * and therefore not found would be reported as "evicted", i.e. this test would
 * fail in the direction that looks exactly like a real finding while actually
 * being a bug in the test.
 *
 * `win` is STATIC on purpose, and that is a second property under test.
 *
 * It was a local until issue #176 was understood, because every SYS_DMESG into a
 * static returned SYS_ERR_FAULT while the identical call into a stack buffer
 * succeeded. The cause was not in the kernel: sys_dmesg() passed its buffer as
 * `(uint32_t)(unsigned long)buf`, so the kernel was handed the low 32 bits of an
 * address this program never named, and faithfully walked that instead.
 *
 * Which storage class the buffer has is therefore the whole difference between
 * exercising the bug and missing it: USER_IMAGE_ASLR_BASE is 16 GiB, so a static
 * is above 4 GiB by construction and always truncated, while this task's stack
 * sits near 8 MiB and is never affected. A stack buffer here would make this
 * gate silently stop testing the ABI. Hence the explicit floor check in
 * _start(): if the buffer is NOT above 4 GiB the probe FAILS rather than passing
 * a test it is no longer running. */
#define CHUNK          1024
#define CARRY          32       /* must exceed the longest needle; checked below */

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* Append a signed decimal to a report string. The probe has no libc. */
static void report_code(const char *prefix, int v) {
    char b[48];
    int i = 0;
    while (*prefix) b[i++] = *prefix++;
    if (v < 0) { b[i++] = '-'; v = -v; }
    char d[12]; int dl = 0;
    if (v == 0) d[dl++] = '0';
    while (v) { d[dl++] = (char)('0' + (v % 10)); v /= 10; }
    while (dl) b[i++] = d[--dl];
    b[i++] = '\n'; b[i] = 0;
    report(b);
}

static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }

static int match_at(const char *hay, const char *needle) {
    while (*needle) { if (*hay != *needle) return 0; hay++; needle++; }
    return 1;
}

/* Substring search over an explicit length: the ring is not NUL-terminated and
 * may legitimately contain NULs, so this cannot use a string function. */
static int contains(const char *hay, int hlen, const char *needle) {
    int nlen = slen(needle);
    if (nlen == 0 || hlen < nlen) return 0;
    for (int i = 0; i + nlen <= hlen; i++) {
        if (match_at(hay + i, needle)) return 1;
    }
    return 0;
}

/* 1 if `needle` appears anywhere in the kernel message ring. On a SYS_DMESG
 * error, writes the negative code to *err and returns 0 — the caller must check
 * *err before believing a 0, or a denied read would be reported as "absent". */
static char win[CARRY + CHUNK];

static int klog_contains(const char *needle, int *err) {
    int carry = 0;
    unsigned off = 0;
    *err = 0;
    if (slen(needle) > CARRY) { *err = -1; return 0; }   /* CARRY too small */
    for (;;) {
        int n = sys_dmesg(win + carry, off, CHUNK);
        if (n < 0)  { *err = n; return 0; }
        if (n == 0) break;
        off += (unsigned)n;
        int have = carry + n;
        if (contains(win, have, needle)) return 1;
        int keep = have < CARRY ? have : CARRY;
        for (int i = 0; i < keep; i++) win[i] = win[have - keep + i];
        carry = keep;
    }
    return 0;
}

void _start(void) {
    int err = 0;

    /* (0) Setup: the destination must be above 4 GiB, or the ABI half of this
     *     gate (issue #176) is not being exercised at all. See the note on
     *     `win`. A failure here means the loader stopped honouring
     *     USER_IMAGE_ASLR_BASE, not that the kernel log is unsafe -- so it is
     *     reported as a distinct marker. */
    if ((unsigned long)(void *)win < (1UL << 32)) {
        report("KLOGTEST: FAIL setup buffer-not-high\n");
        sys_exit();
    }

    /* (1) Setup: the kernel's marker must be in the ring before we touch it. */
    if (!klog_contains(KERNEL_MARKER, &err) || err) {
        if (err) report_code("KLOGTEST: FAIL setup dmesg rc=", err);
        else     report("KLOGTEST: FAIL setup marker-absent\n");
        sys_exit();
    }

    /* (2) Flood fd 1 with more bytes than the ring can hold. */
    static char chunk[CHUNK_BYTES + 1];
    {
        int i = 0;
        while (i < CHUNK_BYTES - 1) {
            const char *p = INJECT " ";
            while (*p && i < CHUNK_BYTES - 1) chunk[i++] = *p++;
        }
        chunk[i++] = '\n';
        chunk[i] = 0;
    }
    for (int c = 0; c < FLOOD_CHUNKS; c++) {
        sys_write(1, chunk, CHUNK_BYTES);
    }

    /* (3) The ring must be untouched by any of that: nothing forged in, and
     *     nothing evicted out.
     *
     * BOTH are evaluated before either is reported, rather than returning at the
     * first failure. That is what lets the control arm exercise both branches on
     * every boot -- KLOG_WRITE_UNGATED=1 prints "FAIL forged+evicted" -- instead
     * of only the first one in source order. An assertion no arm has ever been
     * seen to trip is an assertion nobody has tested. */
    int forged = klog_contains(INJECT, &err);
    if (err) { report_code("KLOGTEST: FAIL post dmesg rc=", err); sys_exit(); }
    int survived = klog_contains(KERNEL_MARKER, &err);
    if (err) { report_code("KLOGTEST: FAIL post dmesg rc=", err); sys_exit(); }

    if (forged && !survived) { report("KLOGTEST: FAIL forged+evicted\n"); sys_exit(); }
    if (forged)              { report("KLOGTEST: FAIL forged\n");         sys_exit(); }
    if (!survived)           { report("KLOGTEST: FAIL evicted\n");        sys_exit(); }

    report("KLOGTEST: PASS\n");
    sys_exit();
}
