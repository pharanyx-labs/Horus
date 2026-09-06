/* blockprobe -- the probe task that holds exactly one CAP_ENCRYPTED_STORAGE
 *
 * WHY THIS TASK EXISTS AT ALL.
 *
 * `.github/syscall-coverage.yml` records which syscall HANDLER BODIES a tracked
 * workload enters. SYS_BLOCK_READ and SYS_BLOCK_WRITE were on its `uncovered`
 * list from the day the manifest was written: their dispatch rows are
 * { h_block_*, CAPSLOT_AUDIT, READ|WRITE, CAP_ENCRYPTED_STORAGE }, a real
 * capability, and the only task in this tree that holds one is fs_server, which
 * reaches the medium through its own higher-level calls and has no reason to
 * bypass its own layer. So the two syscalls that read and write the raw medium
 * beneath the filesystem had never executed, on any build, in any test.
 *
 * `docs/LIMITATIONS.md` 1.8 is the record of what that costs. Twice now, writing
 * the probe that enters an uncovered handler has found a defect on the first
 * boot: S52 (a helper that spun forever on a NULL lookup while holding cap_lock
 * with interrupts masked, reachable in one syscall by any ring-3 task) and S71
 * (`struct audit_event` declared twice under one name, 256 bytes against 72, the
 * copy running 184 bytes past the caller's array per record). This is the third
 * time, and it found the error vocabulary below.
 *
 * WHAT IT HOLDS. Slot 7 (CAPSLOT_AUDIT), root_cnode[9]'s CAP_ENCRYPTED_STORAGE,
 * installed by captest_selftest(). Nothing else beyond what create_task hands
 * every task. It runs as uid 1000, an ordinary user, so a success here is the
 * capability's doing and not root's.
 *
 * THE SLOT IS SHARED AND THE TYPE IS NOT, which is why this probe is the mirror
 * of auditprobe rather than a copy of it. CAPSLOT_AUDIT carries CAP_AUDIT for the
 * audit syscalls and CAP_ENCRYPTED_STORAGE for these; the two probes hold
 * different types in the SAME slot, and each must be refused the other's
 * syscalls. That is S60 -- the type test living in cap_lookup, in one place --
 * asserted from both sides rather than argued. Check 7 below is that assertion.
 *
 * WHY NOTHING IS EVER WRITTEN TO THE MEDIUM, AND WHY THAT IS A BOUNDARY RATHER
 * THAN AN OVERSIGHT.
 *
 * h_block_write's body is entered here by calls that the storage layer then
 * REFUSES, so the handler runs, copy_from_user runs, and no byte reaches the
 * disk. A successful raw block write would have to land inside the live volume:
 * `storage_format_sealed` lays the data region out over the tail of the device
 * and gives the rest to the filesystem, so there is no block on this image that
 * is provably not the filesystem's. A probe that scribbles on the volume it
 * shares a boot with is a flaky gate, and a flaky gate is worse than a missing
 * one. So h_block_write's SUCCESS path is not entered by this probe and is not
 * claimed to be; entering it needs a scratch device, which is roadmap 2.9's
 * "selecting among several targets" once a second device can be addressed.
 *
 * WHY THE BUFFERS ARE STATIC AS WELL AS AUTOMATIC.
 *
 * USER_IMAGE_ASLR_BASE is 16 GiB with 4 TiB of randomisation, so every static in
 * a PIE image is above 4 GiB BY CONSTRUCTION, while a stack buffer sits around
 * 8 MiB. That is the whole reason issue #176 survived: every caller in the tree
 * happened to pass a stack buffer, which a 32-bit truncation leaves alone. Both
 * of these syscalls take a user buffer pointer and neither had ever been called,
 * so each is exercised TWICE here, once into a static and once into an
 * automatic, and both must be delivered.
 *
 * On the write side that check is free of any risk, and the reason is worth
 * stating because it is what makes check 5 meaningful. h_block_write copies from
 * the user BEFORE it asks the storage layer for the block, so a write to a block
 * the device refuses still runs copy_from_user over the caller's pointer. A
 * kernel that truncated it would answer SYS_ERR_FAULT; one that did not answers
 * the storage layer's refusal. The check requires the refusal, so it witnesses
 * the pointer surviving without a byte being written.
 *
 * THE BLOCK NUMBER IS 64-BIT AND IS SPLIT ACROSS TWO REGISTERS. sys_block_read
 * packs it as (block >> 32) in rbx and (uint32_t)block in rcx, and the handler
 * reassembles it. Check 4 asks for block 2^40, which no device in this tree has:
 * it must be REFUSED, and a kernel that dropped the high half would truncate it
 * to 0, read the superblock, and succeed. So that check is also a truncation
 * witness on the argument -- the [I-2] shape, on a path nothing had run.
 *
 * Falsified by BLOCK_ERRNO_LEGACY=1, which restores the bare -1/-3 returns these
 * two handlers shipped with: `make smoke-blockprobe-control` requires
 * BLOCKPROBE: FAIL bad-block-is-indistinguishable-from-refusal, and
 * `make smoke-blockprobe` must go red under the same flag.
 *
 * AND FALSIFIED FROM THE OTHER SIDE by SYSCOV_PROBES_ABSENT=1, which compiles out
 * the calls that enter the two bodies exactly as it already compiles out
 * captest's section 13 and auditprobe's four calls. `make smoke-syscall-coverage`
 * must then go red naming SYS_BLOCK_READ and SYS_BLOCK_WRITE among the syscalls
 * declared covered whose bodies never ran -- without which a promotion this probe
 * earned would be indistinguishable from one that was free all along.
 */
#include "syscall.h"
#include "errno.h"
#include "block_size.h"
#include "libhorus.h"

static int checks;
static int failures;

static void check(int ok, const char *what) {
    if (ok) { checks++; return; }
    kput_marker("BLOCKPROBE: FAIL ", what);
    failures++;
}

#define BLK  HORUS_BLOCK_SIZE
#define FILL 0x5A                  /* sentinel: a delivered block must overwrite it */

/* Past the end of any device this tree can attach: the vdisk is 4096 blocks and
 * BLOCKS_PER_DISK is a 16 GiB ceiling at 4194304. 2^40 is clear of both, and its
 * high half is non-zero, which is the point -- see the header comment. */
#define BLOCK_PAST_THE_END (1ULL << 40)

#ifndef SYSCOV_PROBES_ABSENT
/* Above 4 GiB by construction -- see the header comment. */
static unsigned char g_static_rd[BLK];
static unsigned char g_static_wr[BLK];
static unsigned char g_static_again[BLK];   /* block 0, re-read after the refusals */

/* Did the kernel write into the buffer we actually named? A block delivered
 * somewhere else leaves every byte at FILL. */
static int overwritten(const unsigned char *b, unsigned n) {
    for (unsigned i = 0; i < n; i++)
        if (b[i] != FILL) return 1;
    return 0;
}

static int same_bytes(const unsigned char *a, const unsigned char *b, unsigned n) {
    for (unsigned i = 0; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}
#endif /* SYSCOV_PROBES_ABSENT */

void _start(void) {
    kputln("BLOCKPROBE: begin (uid 1000, one CAP_ENCRYPTED_STORAGE at slot 7 and nothing else)");

#ifndef SYSCOV_PROBES_ABSENT
    /* ---- 1. the read handler runs at all: an automatic buffer -------------- */
    /* Block 0 is the superblock. It is always present on a mounted volume, and
     * reading it is the one medium access this probe can make that is certainly
     * safe -- it changes nothing and the block certainly exists. */
    unsigned char stack_rd[BLK];
    umemset(stack_rd, FILL, BLK);
    int r1 = sys_block_read(0, stack_rd, BLK);
    kput("BLOCKPROBE: block_read(0, stack) -> "); kput_int(r1); kputln("");
    check(r1 == (int)BLK && overwritten(stack_rd, BLK), "block-read-into-a-stack-buffer");

    /* ---- 2. the same read into a static, which is above 4 GiB -------------- */
    umemset(g_static_rd, FILL, BLK);
    int r2 = sys_block_read(0, g_static_rd, BLK);
    kput("BLOCKPROBE: block_read(0, static) -> "); kput_int(r2); kputln("");
    check(r2 == (int)BLK && overwritten(g_static_rd, BLK), "block-read-into-a-static-buffer");

    /* ---- 3. and both deliveries are the same block ------------------------- */
    /* Two reads of block 0 into two buffers must agree byte for byte. A kernel
     * that delivered SOMETHING to each -- the wrong block, or a stale scratch
     * buffer -- passes checks 1 and 2 and fails this one. */
    check(same_bytes(stack_rd, g_static_rd, BLK), "two-reads-of-block-0-disagree");

    /* ---- 4. a block past the end of the device is refused ------------------ */
    /* And refused DISTINGUISHABLY. Before this probe both handlers returned the
     * storage layer's bare -1, which is the value of SYS_ERR_PERM -- so a caller
     * could not tell "you hold no capability for this" from "that block does not
     * exist", and a refusal test could not tell whether the handler had run at
     * all. Requiring SYS_ERR_IO is what makes checks 4-6 witness the BODY rather
     * than the dispatch table's gate in front of it. */
    /* Into a scratch buffer of its own: stack_rd still holds block 0 and check 6b
     * compares against it, so a refused read must not be given the buffer the
     * comparison depends on. */
    unsigned char scratch[BLK];
    umemset(scratch, FILL, BLK);
    int r3 = sys_block_read(BLOCK_PAST_THE_END, scratch, BLK);
    kput("BLOCKPROBE: block_read(2^40, stack) -> "); kput_int(r3); kputln("");
    check(r3 == SYS_ERR_IO, "bad-block-is-indistinguishable-from-refusal");
    check(!overwritten(scratch, BLK), "refused-read-still-wrote-the-buffer");

    /* ---- 5. a write past the end, from a static source --------------------- */
    /* Nothing reaches the medium: the storage layer refuses the block. What this
     * witnesses is that copy_from_user, which runs FIRST, was handed the pointer
     * this task named -- a truncated one would fault instead. See the header. */
    umemset(g_static_wr, 0xC3, BLK);
    int w1 = sys_block_write(BLOCK_PAST_THE_END, g_static_wr, BLK);
    kput("BLOCKPROBE: block_write(2^40, static) -> "); kput_int(w1); kputln("");
    check(w1 == SYS_ERR_IO, "block-write-from-a-static-buffer");

    /* ---- 6. and the same from an automatic source -------------------------- */
    unsigned char stack_wr[BLK];
    umemset(stack_wr, 0xC3, BLK);
    int w2 = sys_block_write(BLOCK_PAST_THE_END, stack_wr, BLK);
    kput("BLOCKPROBE: block_write(2^40, stack) -> "); kput_int(w2); kputln("");
    check(w2 == SYS_ERR_IO, "block-write-from-a-stack-buffer");

    /* ---- 6b. and the storage layer still works afterwards ------------------ */
    /* A refused operation must leave the layer usable: these paths take
     * storage's locks, and one that returned an error without releasing what it
     * held would strand every later caller. Reading block 0 again is what says
     * it did not.
     *
     * IT DELIBERATELY DOES NOT COMPARE THE BYTES against what check 1 read, and
     * the reason is worth recording because the comparison is the obvious thing
     * to write. The refused writes named block 2^40, which no device has, so
     * block 0 was never their target and "block 0 is unchanged" witnesses
     * nothing about them. What it WOULD do is race the filesystem: this probe
     * shares its boot with a live, mounted volume, and fs_server may legitimately
     * rewrite the superblock between two reads. That is a check that fails for a
     * reason unrelated to its claim, which is the definition of a flaky gate. */
    umemset(g_static_again, FILL, BLK);
    int r4 = sys_block_read(0, g_static_again, BLK);
    kput("BLOCKPROBE: block_read(0, static) again -> "); kput_int(r4); kputln("");
    check(r4 == (int)BLK && overwritten(g_static_again, BLK),
          "storage-layer-unusable-after-refused-writes");
#endif /* SYSCOV_PROBES_ABSENT */

    /* ---- 7. one slot, two types, and the type is the gate ------------------ */
    /* This task holds CAP_ENCRYPTED_STORAGE at CAPSLOT_AUDIT. The audit syscalls
     * are gated on CAP_AUDIT at THE SAME SLOT. Holding the slot must not answer
     * for the type -- that is S60, and auditprobe asserts the same rule from the
     * other side with the types exchanged. A kernel that checked only the slot
     * would pass both probes' positive checks and fail both of these. */
    static unsigned char digest[40];
    int arc = sys_audit_digest(digest);
    kput("BLOCKPROBE: audit_digest -> "); kput_int(arc); kputln("");
    check(arc == SYS_ERR_PERM, "cap-encrypted-storage-authorised-the-audit-log");

    /* ---- 8. and holding slot 7 does not answer for slot 8 ------------------ */
    /* SYS_ROTATE_KEYS is gated on CAP_CONSOLE at slot 8, so the table refuses
     * this task before h_rotate_keys runs. Worth stating what is behind that
     * refusal as well: do_rotate_keys asks has_encrypted_storage_cap(), which
     * looks in CAPSLOT_STORAGE (slot 9) -- so even past the table, this task's
     * CAP_ENCRYPTED_STORAGE would not answer, because it is the right type in
     * the wrong slot. Slot identity is part of the name of a capability and not
     * merely where it happens to sit. */
    int rrc = sys_rotate_keys();
    kput("BLOCKPROBE: rotate_keys -> "); kput_int(rrc); kputln("");
    check(rrc < 0, "cap-encrypted-storage-authorised-key-rotation");

    if (failures) {
        kput("BLOCKPROBE: FAIL ");
        kput_int(failures);
        kputln(" checks failed");
    } else {
        kput("BLOCKPROBE: PASS ");
        kput_int(checks);
        kputln(" checks - the raw block handlers ran, and said which refusal was which");
    }
    for (;;) sys_yield();
}
