/* formatprobe -- the probe task that holds exactly one CAP_STORAGE_FORMAT
 *
 * WHY THIS TASK EXISTS AT ALL.
 *
 * `.github/syscall-coverage.yml` records which syscall HANDLER BODIES a tracked
 * workload enters. SYS_STORAGE_DEVICE and SYS_STORAGE_FORMAT were the last two
 * on its `uncovered` list that carry a real capability in their dispatch rows:
 * { CAPSLOT_STORAGE_FORMAT, READ or WRITE, CAP_STORAGE_FORMAT }. captest holds
 * none, so the central gate refuses it before either body runs, and its section
 * 15 checks say nothing about the bodies. init holds one and calls
 * SYS_STORAGE_INFO at every boot, but SYS_STORAGE_DEVICE only when the machine
 * has a persistent disk, and SYS_STORAGE_FORMAT never: the installer does. So
 * both bodies ran only in separate boots with disk images attached, and
 * `docs/LIMITATIONS.md` 1.8 is the record of what an unentered body costs: four
 * times, the first probe into one found a defect on its first boot.
 *
 * WHAT IT HOLDS. Slot 23 (CAPSLOT_STORAGE_FORMAT), a copy of root_cnode[22]'s
 * CAP_STORAGE_FORMAT, READ|WRITE, installed by captest_selftest(). Nothing else
 * beyond what create_task hands every task. uid 1000, an ordinary user, so what
 * it is allowed is the capability's doing and not root's. Like auditprobe and
 * blockprobe it is embedded only in a CAPTEST_SELFTEST image: a task whose whole
 * purpose is to hold the authority to erase a disk has no business in the ship
 * image.
 *
 * NOTHING IS FORMATTED, AND THAT IS BY CONSTRUCTION RATHER THAN BY LUCK.
 *
 * h_storage_format's body refuses before it destroys anything: the length check
 * comes before the copy, the copy before storage_authorize_format, and that
 * before storage_unlock, which is the only step that writes. So the body can be
 * entered, and every refusal in it exercised, without a byte reaching a medium.
 * Every format call below is refused, and each one is chosen to differ in
 * exactly ONE argument from a call the handler would AUTHORISE. The base call is
 * device 0 (on a machine with no persistent disk, the one thing an index can
 * mean), a well-formed password, and zero size, flags and swap. This probe never
 * makes it. On this diskless boot it would pass every check and reach
 * storage_unlock, which would then refuse it with its own code, -8, because an
 * ephemeral store gives the format no device to write; with a disk attached it
 * would erase that disk.
 *
 * The one-argument rule is what makes a refusal here a measurement. A call that
 * was wrong in two ways would still be refused by a kernel that dropped either
 * check, so it would witness neither. With one, the refusal can only be that
 * argument's: SYS_ERR_INVAL from the check, not -8 from beyond it. The arm below
 * shows the rule holding for the check it falsifies: under it, that call gets
 * all the way to storage_unlock's -8.
 *
 * THE BOOT IS DISKLESS. The CAPTEST_SELFTEST image attaches no disk, so
 * `device_count` is 0 and every SYS_STORAGE_DEVICE index is past the end. The
 * survey's success path is make smoke-storage-survey's, where init calls it with
 * one and then two disks attached; the format's is the installer gates'. This
 * probe's job is the bodies' refusals, which no tracked workload had entered.
 *
 * THE INDICES ARE DERIVED FROM THE SURVEY, NOT WRITTEN AS NUMBERS. "Past the
 * end" is `device_count` for the survey, and for the format it is 1 on a diskless
 * machine (where 0 is valid) and `device_count` otherwise. A literal would name a
 * real disk the day this image is booted with one attached.
 *
 * Falsified by STORAGE_FORMAT_PASSWORD_TRUNCATED=1, which shortens an over-long
 * password instead of refusing it: make smoke-formatprobe-control requires
 * FORMATPROBE: FAIL format-accepted-a-password-a-login-cannot-type, and
 * make smoke-formatprobe must go red under the same flag.
 *
 * AND FALSIFIED FROM THE OTHER SIDE by SYSCOV_PROBES_ABSENT=1, which compiles out
 * every call that enters the two bodies, as it does for captest's section 13 and
 * the other probes. make smoke-syscall-coverage must then go red naming
 * SYS_STORAGE_DEVICE and SYS_STORAGE_FORMAT among the syscalls declared covered
 * whose bodies never ran.
 */
#include "syscall.h"
#include "errno.h"
#include "libhorus.h"

static int checks;
static int failures;

static void check(int ok, const char *what) {
    if (ok) { checks++; return; }
    kput_marker("FORMATPROBE: FAIL ", what);
    failures++;
}

#define FILL 0x5A                  /* sentinel: a refused survey must not touch it */

#ifndef SYSCOV_PROBES_ABSENT
/* Statics, so above 4 GiB by construction (USER_IMAGE_ASLR_BASE is 16 GiB), the
 * range issue #176's truncation broke. A refusal that comes AFTER the copy, like
 * the bad index below, then also says the kernel read the pointer this task
 * named: a truncated one would answer SYS_ERR_FAULT instead. */
static const char g_pw[] = "formatprobe-must-not-format";       /* 27, under the bound */
/* One character past STORAGE_FORMAT_PASSWORD_MAX, so 32. A login copies 31
 * bytes of what was typed (h_auth), so a volume sealed to this could never be
 * opened by typing it. */
static const char g_pw_long[] = "formatprobe-thirty-two-character";
static struct storage_info g_survey;

/* An address in the kernel half. It is not this task's memory under any mapping,
 * so copy_from_user must refuse it. */
#define KERNEL_HALF ((const char *)0xFFFF800000000000ULL)

static int untouched(const void *p, unsigned n) {
    const unsigned char *b = (const unsigned char *)p;
    for (unsigned i = 0; i < n; i++)
        if (b[i] != FILL) return 0;
    return 1;
}

/* The one-argument rule, in one place: the base call with one thing changed. */
static int format_with(unsigned device, const char *pw, unsigned plen,
                       uint64_t volume_blocks, uint32_t flags, uint64_t swap_blocks) {
    return sys_storage_format(device, pw, plen, volume_blocks, flags, swap_blocks);
}
#endif /* SYSCOV_PROBES_ABSENT */

void _start(void) {
    kputln("FORMATPROBE: begin (uid 1000, one CAP_STORAGE_FORMAT at slot 23 and nothing else)");

    /* ---- 0. the capability authorises at all ------------------------------- */
    /* SYS_STORAGE_INFO answers to the same capability with READ, and init covers
     * it already. It is here as the positive control: every check below expects
     * SYS_ERR_INVAL or SYS_ERR_FAULT, which only a handler BODY returns, and a
     * capability that did not authorise would turn each of them into the
     * table's SYS_ERR_PERM. It also supplies the device count. */
    struct storage_info si;
    umemset(&si, FILL, sizeof(si));
    int irc = sys_storage_info(&si);
    kput("FORMATPROBE: storage_info -> "); kput_int(irc);
    kput(" devices "); kput_int((int)si.device_count); kputln("");
    check(irc == 0, "cap-storage-format-did-not-authorise-the-survey");

#ifndef SYSCOV_PROBES_ABSENT
    unsigned count = si.device_count;

    /* ---- 1. a survey past the end is refused, and writes nothing ----------- */
    /* S82: the survey answers only about the device it was asked about. An
     * index past the end answered about some other disk would be read as the
     * disk about to be erased. Into a static, so a delivered survey would land
     * in memory above 4 GiB as well as fail the check. */
    umemset(&g_survey, FILL, sizeof(g_survey));
    int d1 = sys_storage_device(count, &g_survey);
    kput("FORMATPROBE: storage_device(count) -> "); kput_int(d1); kputln("");
    check(d1 == SYS_ERR_INVAL, "survey-of-an-index-past-the-end-not-refused");
    check(untouched(&g_survey, sizeof(g_survey)), "refused-survey-still-wrote-the-buffer");

    /* ---- 2. and index 0xFFFFFFFF, which the handler reads as an int -------- */
    /* h_storage_device passes (int)(uint32_t)rbx, so this arrives as -1. It must
     * be refused as a negative index, not wrap into the enumeration. */
    umemset(&g_survey, FILL, sizeof(g_survey));
    int d2 = sys_storage_device(0xFFFFFFFFu, &g_survey);
    kput("FORMATPROBE: storage_device(-1) -> "); kput_int(d2); kputln("");
    check(d2 == SYS_ERR_INVAL, "survey-of-index-minus-one-not-refused");
    check(untouched(&g_survey, sizeof(g_survey)), "refused-negative-survey-still-wrote-the-buffer");

    /* ---- 3. the format: an empty password ---------------------------------- */
    /* Refused before anything is copied: a volume sealed to nothing. */
    unsigned plen = (unsigned)(sizeof(g_pw) - 1);
    int f1 = format_with(0, g_pw, 0, 0, 0, 0);
    kput("FORMATPROBE: format(empty password) -> "); kput_int(f1); kputln("");
    check(f1 == SYS_ERR_INVAL, "format-accepted-an-empty-password");

    /* ---- 4. a password a login cannot type back ---------------------------- */
    /* The round-trip bound (S142; include/syscall.h, sys_storage_format). A kernel
     * that shortened this instead of refusing it would, on a machine with a
     * disk, seal the volume to the first 31 characters. That is what
     * STORAGE_FORMAT_PASSWORD_TRUNCATED=1 does; on this diskless boot the call
     * is then authorised and reaches storage_unlock, which answers -8 for want
     * of a device rather than the length check's SYS_ERR_INVAL. This check's
     * name is the arm's marker. */
    unsigned plen_long = (unsigned)(sizeof(g_pw_long) - 1);
    int f2 = format_with(0, g_pw_long, plen_long, 0, 0, 0);
    kput("FORMATPROBE: format(32-character password) -> "); kput_int(f2); kputln("");
    check(plen_long == STORAGE_FORMAT_PASSWORD_MAX + 1 && f2 == SYS_ERR_INVAL,
          "format-accepted-a-password-a-login-cannot-type");

    /* ---- 5. a password the caller does not own ----------------------------- */
    /* Kernel memory, not this task's: the copy must fail, and the answer must
     * be SYS_ERR_FAULT, which says the copy ran. */
    int f3 = format_with(0, KERNEL_HALF, plen, 0, 0, 0);
    kput("FORMATPROBE: format(kernel-half password) -> "); kput_int(f3); kputln("");
    check(f3 == SYS_ERR_FAULT, "format-read-a-password-from-kernel-memory");

    /* ---- 6. a device that is not there ------------------------------------- */
    /* S83: the call that erases a disk names the disk it erases, and an index
     * that names none is refused rather than rounded to one that exists. The
     * password is the static one and is copied first, so SYS_ERR_INVAL rather
     * than SYS_ERR_FAULT also says the pointer arrived whole. */
    unsigned absent = count == 0 ? 1u : count;
    int f4 = format_with(absent, g_pw, plen, 0, 0, 0);
    kput("FORMATPROBE: format(device past the end) -> "); kput_int(f4); kputln("");
    check(f4 == SYS_ERR_INVAL, "format-of-a-device-that-is-not-there-not-refused");

    /* ---- 7. device 0xFFFFFFFF, read as -1 ---------------------------------- */
    int f5 = format_with(0xFFFFFFFFu, g_pw, plen, 0, 0, 0);
    kput("FORMATPROBE: format(device -1) -> "); kput_int(f5); kputln("");
    check(f5 == SYS_ERR_INVAL, "format-of-device-minus-one-not-refused");

    /* ---- 8. a flag this kernel does not know ------------------------------- */
    /* Refused, not ignored: a caller asking for something the kernel cannot do
     * must not get a volume that silently lacks it. */
    int f6 = format_with(0, g_pw, plen, 0, 0x80000000u, 0);
    kput("FORMATPROBE: format(unknown flag) -> "); kput_int(f6); kputln("");
    check(f6 == SYS_ERR_INVAL, "format-accepted-a-flag-it-does-not-know");

    /* ---- 9. swap without the layout that has a place for it ---------------- */
    int f7 = format_with(0, g_pw, plen, 0, 0, 64);
    kput("FORMATPROBE: format(swap, no partition table) -> "); kput_int(f7); kputln("");
    check(f7 == SYS_ERR_INVAL, "format-accepted-swap-without-a-partition-table");

    /* ---- 10. a volume too small to lay out --------------------------------- */
    /* One block. On a machine with no disk any size is refused, because the
     * ephemeral store is sized by the kernel; with one, a size under
     * STORAGE_MIN_BLOCKS is. Refused either way, so this stays a one-argument
     * change whichever machine boots it. */
    int f8 = format_with(0, g_pw, plen, 1, 0, 0);
    kput("FORMATPROBE: format(one-block volume) -> "); kput_int(f8); kputln("");
    check(f8 == SYS_ERR_INVAL, "format-accepted-a-one-block-volume");
#endif /* SYSCOV_PROBES_ABSENT */

    if (failures) {
        kput("FORMATPROBE: FAIL ");
        kput_int(failures);
        kputln(" checks failed");
    } else {
        kput("FORMATPROBE: PASS ");
        kput_int(checks);
        kputln(" checks - the survey and format handlers ran, and refused without writing");
    }
    for (;;) sys_yield();
}
