/* auditprobe -- the probe task that holds exactly one CAP_AUDIT
 *
 * WHY THIS TASK EXISTS AT ALL.
 *
 * `.github/syscall-coverage.yml` records which syscall HANDLER BODIES a tracked
 * workload enters, and it exists because issue #176 -- a pointer truncation in
 * sys_dmesg() and sys_audit_digest(), 100% reproducible for every static buffer
 * in the system -- was invisible to a 100-check conformance suite. captest names
 * both syscalls; both of its checks assert SYS_ERR_PERM; the dispatch table
 * refuses before the handler runs. Neither handler had ever executed.
 *
 * SYS_DMESG has been `covered` since that manifest existed. SYS_AUDIT_DIGEST and
 * its neighbour SYS_READ_AUDIT had not: their dispatch rows are
 * `{ h_*, 7, CAP_RIGHT_READ, CAP_AUDIT }`, a real capability, so the central gate
 * returns first and "captest asserts the refusal" is worth nothing -- the refusal
 * is the TABLE's, not the handler's. So the syscall that motivated the whole file
 * still sat behind a body nothing entered.
 *
 * Covering it needs a task that HOLDS the capability, and captest deliberately
 * holds as little as possible: endowing captest with CAP_AUDIT to raise a number
 * would widen the authority of the one task in this tree whose job is to have
 * none. The manifest's own entry says what to do instead -- "a probe task holding
 * one CAP_AUDIT is worth writing" -- and this is it.
 *
 * WHAT IT HOLDS. Slot 7 (CAPSLOT_AUDIT), a CAP_AUDIT with READ, installed from
 * the root cnode by captest_selftest(). Nothing else beyond what create_task
 * hands every task. It runs as uid 1000, an ordinary user, so a success here is
 * the capability's doing and not root's -- and the two refusal checks below say
 * the same thing from the other side.
 *
 * WHY THE BUFFERS ARE STATIC, AND WHY THAT IS THE POINT.
 *
 * USER_IMAGE_ASLR_BASE is 16 GiB with 4 TiB of randomisation, so every static in
 * a PIE image is above 4 GiB BY CONSTRUCTION, while a stack buffer sits around
 * 8 MiB. That is exactly why #176 survived: every caller in the tree happened to
 * pass a stack buffer, which the truncation leaves alone. So this probe calls
 * each syscall TWICE, once into a stack buffer and once into a static, and
 * requires both to be delivered. Under SYSCALL_PTR_TRUNC32=1 the stack half
 * still passes and the static half does not, which is issue #176's signature
 * rather than merely "something broke".
 *
 * The static check requires the BYTES, not the return code. The truncation is
 * not fail-closed: the kernel walks the truncated address in the caller's own
 * address space, so if nothing is mapped there it refuses (SYS_ERR_FAULT, what
 * #176 observed) and if something IS -- the stack at ~8 MiB and the heap at
 * ~16 MiB are both reachable by truncation -- it writes kernel bytes into a page
 * the caller never nominated and reports success. Only "did the buffer I named
 * change" catches both, and a check that read the return code alone would pass
 * on the boot where the defect did the most damage.
 *
 * Falsified by SYSCALL_PTR_TRUNC32=1: `make smoke-auditprobe-control` requires
 * AUDITPROBE: FAIL digest-into-a-static-buffer, and `make smoke-auditprobe` must
 * go red under the same flag.
 *
 * AND FALSIFIED FROM THE OTHER SIDE, by the flag that says the coverage above was
 * earned. SYSCOV_PROBES_ABSENT=1 compiles out the four calls that enter the two
 * handlers -- exactly as it already compiles out captest's section 13 -- so
 * `make smoke-syscall-coverage` must go red naming SYS_AUDIT_DIGEST and
 * SYS_READ_AUDIT among the syscalls declared covered whose bodies never ran.
 * Without it, a promotion this probe earned would be indistinguishable from one
 * that was free all along, some other tracked workload having entered the bodies
 * anyway. The refusal checks stay live under the flag: they are not coverage
 * probes, they are what says the capability names one object.
 */
#include "syscall.h"
#include "libhorus.h"

static int checks;
static int failures;

static void check(int ok, const char *what) {
    if (ok) { checks++; return; }
    kput_marker("AUDITPROBE: FAIL ", what);
    failures++;
}

#ifndef SYSCOV_PROBES_ABSENT
#define DIGEST_LEN 40           /* 8-byte LE event count + 32-byte chain head MAC */
#define FILL       0xA5         /* sentinel: a delivered digest must overwrite it */
#define WINDOW     16           /* records read back when looking for our own */

/* Above 4 GiB by construction -- see the header comment. */
static unsigned char g_digest[DIGEST_LEN];

/* The overrun witness, and it is ONE STRUCT rather than two statics on purpose:
 * two objects in .bss are laid out adjacently in practice and by nothing in the
 * standard, so a guard that depends on it is a check that might be measuring the
 * linker. A struct's members are in declaration order with the guard after the
 * array, which is what this needs.
 *
 * NARROW[2] rather than WINDOW[16] is also deliberate. Under AUDIT_ABI_LEGACY the
 * kernel writes 256 bytes per record at a 256-byte stride; with 16 slots the
 * array is 2560 bytes and the log would need ELEVEN records before the write ran
 * past it. The probe makes two events, so at two slots (320 bytes) the second
 * record starts at 256 and ends at 512 -- 192 bytes into the guard. A guard the
 * defect cannot reach is a check that cannot fail. */
static struct {
    struct audit_record ev[2];
    unsigned char       guard[512];
} g_narrow;

static struct audit_record g_events[WINDOW];

/* Did the kernel write into the buffer we actually named? A digest delivered
 * somewhere else leaves every byte at FILL. */
static int overwritten(const unsigned char *b, unsigned n) {
    for (unsigned i = 0; i < n; i++)
        if (b[i] != FILL) return 1;
    return 0;
}

/* The first 8 bytes of a digest are the total event count, little-endian. The
 * count only ever rises, which is what makes it usable as an ordering witness
 * with captest running concurrently in the same image: another task's events
 * widen the delta and can never close it. */
static unsigned long long digest_count(const unsigned char *b) {
    unsigned long long v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | b[i];
    return v;
}

/* The remaining 32 bytes are the running chain head, extended over every event.
 * Two digests taken across an event must differ here as well as in the count --
 * a count that moved on its own would be a counter, not a chain. */
static int same_mac(const unsigned char *a, const unsigned char *b) {
    for (int i = 8; i < DIGEST_LEN; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}
#endif /* SYSCOV_PROBES_ABSENT */

void _start(void) {
    kputln("AUDITPROBE: begin (uid 1000, one CAP_AUDIT at slot 7 and nothing else)");

#ifndef SYSCOV_PROBES_ABSENT
    /* ---- 1. the handler runs at all: a stack buffer, unaffected by #176 ---- */
    unsigned char d1[DIGEST_LEN];
    umemset(d1, FILL, sizeof(d1));
    int srv = sys_audit_digest(d1);
    kput("AUDITPROBE: audit_digest(stack) -> "); kput_int(srv); kputln("");
    check(srv >= 0 && overwritten(d1, sizeof(d1)), "digest-into-a-stack-buffer");

    /* The verify status of the retained window. 0 is "intact"; a positive value
     * is the first tampered index plus one, and -1 is a chain that was never
     * initialised. Nothing has tampered with anything on this boot, so anything
     * but 0 is a real answer worth failing on rather than a flake to tolerate. */
    check(srv == 0, "audit-chain-does-not-verify");
#endif

    /* ---- 2. two audited actions of our own, adding no authority ------------ */
    /*
     * Reading a log back is only a round trip if something went into it, and
     * this probe is spawned into an image where nothing has yet: measured on
     * 2026-09-01, the digest reported ZERO events here, so the first draft's
     * "the count is non-zero" and "read_audit returns records" both failed
     * against a perfectly healthy kernel. They were assumptions about the
     * workload dressed as assertions about the kernel.
     *
     * So the probe makes its own entries, and it makes TWO because the overrun
     * witness below needs the kernel to write two records before a 256-byte
     * stride can carry a write past a two-slot array.
     *
     * WHY A DENIED GRANT AND NOT A DENIED MINT. The first version used
     * sys_cap_mint / sys_cap_transfer against an empty slot: h_cap_mint audits
     * both outcomes, so a refusal made an entry and left the cspace untouched,
     * which is exactly the shape wanted. It also broke an unrelated control arm,
     * and the way it broke it is the interesting part. `cap_mint` and
     * `cap_transfer` are the ONLY two callers of `kcap_lookup`, which is S52's
     * halting assert on a NULL lookup -- so under CAP_LOOKUP_ASSERT_HANG=1 this
     * probe wedged inside the syscall holding cap_lock with IF=0, and
     * `smoke-captest-mint-hang-control` failed because captest never reached the
     * section-12 marker its EXPECT_STALL requires FIRST. That arm was right and
     * this probe was wrong: an empty-slot capability operation is that arm's
     * trigger, and a second task issuing one changes which task reaches it.
     *
     * A denied GRANT audits from `h_cap_grant`'s authority check, which runs
     * before any lookup and calls `cap_lookup` rather than `kcap_lookup`, so it
     * is inert under that flag. It is also the better check on its own terms:
     * this task holds one CAP_AUDIT and no CAP_TCB for anybody, so it must not
     * be able to push that capability into another task.
     *
     * The target is DISCOVERED rather than assumed. h_cap_grant answers
     * SYS_ERR_INVAL for a dead or out-of-range target WITHOUT auditing, and
     * SYS_ERR_PERM only after the authority check it audits -- so a PERM is
     * proof an entry was made, and counting PERMs is how the probe knows it
     * caused two events rather than hoping a particular task id was live.
     *
     * The ordering is deliberate: this runs BEFORE the reads below, so the
     * entries are near the oldest end of the ring, which is the end read_audit
     * returns.
     */
    int audited = 0;
    for (int pass = 0; pass < 2 && audited < 2; pass++) {
        for (int t = 1; t < 8 && audited < 2; t++) {
            int g = sys_cap_grant(t, CAPSLOT_AUDIT, 25);
            if (g == SYS_ERR_PERM) audited++;
        }
    }
    kput("AUDITPROBE: denied cap_grants audited -> "); kput_int(audited); kputln("");
    check(audited >= 2, "could-not-cause-two-audited-events");

#ifndef SYSCOV_PROBES_ABSENT
    /* ---- 3. #176's runtime witness on SYS_AUDIT_DIGEST --------------------- */
    umemset(g_digest, FILL, sizeof(g_digest));
    int grv = sys_audit_digest(g_digest);
    kput("AUDITPROBE: audit_digest(static) -> "); kput_int(grv); kputln("");
    check(grv >= 0 && overwritten(g_digest, sizeof(g_digest)),
          "digest-into-a-static-buffer");

    /* And the bytes are the RIGHT bytes. "The buffer changed" would be satisfied
     * by any garbage; the count must have advanced across the event we just
     * caused, and the chain head must have moved with it. */
    check(digest_count(g_digest) > digest_count(d1), "digest-count-did-not-advance");
    check(!same_mac(d1, g_digest), "digest-chain-head-did-not-move");

    /* ---- 4. the second handler, the same two ways -------------------------- */
    struct audit_record sev[2];
    umemset(sev, FILL, sizeof(sev));
    int sn = sys_read_audit(sev, 2);
    kput("AUDITPROBE: read_audit(stack, 2) -> "); kput_int(sn); kputln("");
    check(sn > 0, "read-audit-into-a-stack-buffer");

    umemset(g_events, FILL, sizeof(g_events));
    int gn = sys_read_audit(g_events, WINDOW);
    kput("AUDITPROBE: read_audit(static, 16) -> "); kput_int(gn); kputln("");
    check(gn > 0 && overwritten((const unsigned char *)g_events, sizeof(g_events)),
          "read-audit-into-a-static-buffer");

    /* ---- 4a. the kernel wrote INSIDE the array it was given ----------------
     *
     * The memory-safety half, and the one no return code can report. The stride
     * the kernel writes at is part of the syscall's ABI just as much as the field
     * offsets are, and a caller cannot observe it from the values it reads --
     * every check above would pass on a kernel that delivered the right bytes in
     * the right places and then kept going for another 184 bytes per record.
     *
     * So: fill the array AND the bytes after it, ask for exactly as many records
     * as the array holds, and require the bytes after it to be untouched. */
    umemset(&g_narrow, FILL, sizeof(g_narrow));
    int nn = sys_read_audit(g_narrow.ev, 2);
    kput("AUDITPROBE: read_audit(narrow, 2) -> "); kput_int(nn); kputln("");
    check(nn == 2, "read-audit-did-not-fill-a-two-record-request");
    check(!overwritten(g_narrow.guard, sizeof(g_narrow.guard)),
          "read-audit-wrote-past-the-array");

    /* Find our own entry. This task is the only uid 1000 in the image -- every
     * other task in a CAPTEST_SELFTEST boot is uid 0 -- so subject_uid is an
     * anchor that needs no syscall to learn a task id and cannot be confused
     * with captest's own capability operations. */
    int mine = 0;
    for (int i = 0; i < gn && i < WINDOW; i++)
        if (g_events[i].subject_uid == 1000 && g_events[i].type == AUDIT_CAP_TRANSFER)
            mine = 1;
    check(mine, "read-audit-did-not-return-our-own-event");
#endif /* SYSCOV_PROBES_ABSENT */

    /* ---- 5. one capability names one thing --------------------------------- */
    /* CAP_AUDIT is the audit log's authority and nothing else's. The kernel
     * message ring is a different object behind a different capability
     * (CAP_KERNEL_LOG at CAPSLOT_KERNEL_LOG), and SYS_DMESG is the OTHER wrapper
     * issue #176 was about -- so this task holds the capability for one of the
     * pair and must still be refused the other. That is the [C-1] shape: a gate
     * a nearby capability satisfies is not a gate. */
    static unsigned char klog[64];
    int drc = sys_dmesg(klog, 0, sizeof(klog));
    kput("AUDITPROBE: dmesg -> "); kput_int(drc); kputln("");
    check(drc == SYS_ERR_PERM, "cap-audit-authorised-dmesg");

    /* Same again against a slot this task does not own: SYS_ROTATE_KEYS is gated
     * on CAP_CONSOLE at slot 8. Holding slot 7 must not answer for slot 8. */
    int rrc = sys_rotate_keys();
    kput("AUDITPROBE: rotate_keys -> "); kput_int(rrc); kputln("");
    check(rrc < 0, "cap-audit-authorised-key-rotation");

    if (failures) {
        kput("AUDITPROBE: FAIL ");
        kput_int(failures);
        kputln(" checks failed");
    } else {
        kput("AUDITPROBE: PASS ");
        kput_int(checks);
        kputln(" checks - the audit handlers ran, and CAP_AUDIT authorised only them");
    }
    for (;;) sys_yield();
}
