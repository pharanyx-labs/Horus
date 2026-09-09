/* execprobe -- the task that enters SYS_EXEC_IMAGE, which nothing ever had
 *
 * WHY THIS TASK EXISTS AT ALL.
 *
 * `.github/syscall-coverage.yml` records which syscall HANDLER BODIES a tracked
 * workload enters. SYS_EXEC_IMAGE (71) sat on its `uncovered` list carrying the
 * strongest reason any entry there has ever carried: "MEASURED 2026-08-20: NOT
 * entered by any of the five selftest builds tried. No build in this tree is
 * known to reach it." Not a tracked workload, not a selftest image, not a defect
 * arm, not the shell -- and it had a userspace wrapper (`sys_exec_image`) with no
 * caller anywhere, which is the exact shape this file apologised for on syscall
 * 19 three days before this was written.
 *
 * `docs/LIMITATIONS.md` 1.8 is the record of what that costs. Three times now,
 * writing the probe that enters an uncovered handler has found a defect on the
 * first boot: S52, S71, and the raw-block error vocabulary. This is the fourth
 * such probe.
 *
 * AND THERE WAS A CLAIM STANDING ON IT. `SECURITY.md` **S42** -- "an exec
 * replaces the image, not the authority" -- names `SYS_EXEC_NAMED` **and**
 * `SYS_EXEC_IMAGE` in its mechanism column, and its witness `make smoke-forkexec`
 * drives only the first. So half of a security property was asserted about a
 * syscall no test had run. That is the [C-1] shape at the level of a claim rather
 * than a gate, and it is what roadmap 4.12 exists to prevent.
 *
 * WHAT IT HOLDS. Slot 19 (CAPSLOT_DEBUG), root_cnode[18]'s CAP_DEBUG, installed
 * by captest_selftest(). Nothing else beyond what create_task hands every task,
 * and it runs as uid 1000, so nothing here answers to root.
 *
 * THE CAPABILITY IS ALSO THE INSTRUMENT, which is why it is CAP_DEBUG and not
 * something else. `SYS_CAP_ENUMERATE` needs it, so the post-exec call both
 * demonstrates that the capability still AUTHORISES and reads back the identity
 * it authorised with. One capability answers both halves of S42; a second one
 * would have widened this task's authority to say the same thing.
 *
 * HOW THE TWO HALVES MEET. A task that execs cannot watch itself do it: the code
 * that asks the question is gone before there is an answer. So the pre-exec
 * sample -- task id, and the capability's type, rights, serial and badge -- is
 * carried across in the ARGV of the exec itself, and `userspace/execimgee.c`
 * compares what it finds against what it was handed. Two things follow from
 * that arrangement and both are deliberate. The successor cannot forge its own
 * serial, because it reads it from the kernel and not from the vector. And argv
 * delivery stops being a check of its own and becomes load-bearing for every
 * check after it -- an exec that lost the vector fails loudly at the first line
 * rather than quietly weakening the ones behind it.
 *
 * WHY THE REFUSALS COME FIRST, AND WHY THE SUCCESSFUL EXEC IS ALSO A CHECK OF
 * THEM. Each rejected image ENTERS h_exec_image, is refused by
 * arm_image_from_user, and returns -- so each one takes `spawn_stage_acquire()`
 * and must give it back. A failure path that returned without releasing would
 * wedge every later spawn and exec in the system, and nothing would report it:
 * the machine would simply stop making tasks. The exec at the end of this file
 * is what says the staging still works, in the same way blockprobe's second read
 * of block 0 says the storage layer survived its refusals.
 *
 * Falsified by the two arms S42 already owns, which live in the exec tail both
 * forms share and therefore reach this one unchanged: EXEC_RESET_CSPACE=1
 * (`make smoke-execprobe-reset-control`) and EXEC_ROOT_CSPACE=1
 * (`make smoke-execprobe-root-control`). That is the point of writing the checks
 * in S42's own vocabulary -- the arms that falsify the named form now falsify the
 * image form too, and the claim's two syscalls have one witness each.
 *
 * AND FALSIFIED FROM THE OTHER SIDE by SYSCOV_PROBES_ABSENT=1, which compiles out
 * every call into the handler exactly as it already compiles out captest's
 * section 13, auditprobe's four calls and blockprobe's. `make smoke-syscall-
 * coverage` must then go red naming SYS_EXEC_IMAGE among the syscalls declared
 * covered whose bodies never ran -- without which a promotion this probe earned
 * would be indistinguishable from one that was free all along.
 */
#include "syscall.h"
#include "errno.h"
#include "libhorus.h"

#ifndef SYSCOV_PROBES_ABSENT
#include "execimgee_image.h"   /* execimgee_image[] / execimgee_image_len */
#endif

static int checks;
static int failures;

static void check(int ok, const char *what) {
    if (ok) { checks++; return; }
    kput_marker("EXECPROBE: FAIL ", what);
    failures++;
}

/* Render an unsigned decimal into `buf` (>= 12 bytes) and return it. The
 * pre-exec sample crosses into the successor as argv strings, so it needs a
 * formatter; there is no printf here and this is the whole of one. */
static char *utoa(unsigned v, char *buf) {
    char tmp[12];
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v) { tmp[n++] = (char)('0' + (v % 10u)); v /= 10u; }
    int i = 0;
    while (n) buf[i++] = tmp[--n];
    buf[i] = 0;
    return buf;
}

#ifndef SYSCOV_PROBES_ABSENT
/* Four bytes that are neither HORU nor \x7fELF, so arm_image_from_user reaches
 * its final `else` and fails closed on an unrecognised container. Static rather
 * than automatic on purpose: every static in a PIE image is above 4 GiB by
 * construction (USER_IMAGE_ASLR_BASE is 16 GiB), so this call also hands the
 * kernel a pointer a 32-bit truncation would destroy -- the issue #176 shape, on
 * a syscall that had never been called with any pointer at all. */
static const unsigned char g_not_a_container[64] = { 0xCC, 0xCC, 0xCC, 0xCC };

/* A pointer no PIE image maps: the image window starts at 16 GiB and the stack
 * sits around 8 MiB, so page 1 is unmapped in every task in this system.
 * copy_from_user must refuse it rather than fault the kernel. */
#define UNMAPPED_USER_PAGE ((const void *)0x1000UL)
#endif /* SYSCOV_PROBES_ABSENT */

void _start(void) {
    kputln("EXECPROBE: begin (uid 1000, one CAP_DEBUG at slot 19 and nothing else)");

    int pid = sys_getpid();

    /* ---- 0. the pre-exec sample ------------------------------------------
     *
     * Fatal rather than a failed check if it cannot be read: everything after
     * the exec is compared against these five numbers, so a run that could not
     * take them has nothing to say and should say so once, not eight times. */
    struct cap_info pre;
    if (sys_cap_enumerate(pid, CAPSLOT_DEBUG, &pre) != 0 || !pre.occupied) {
        kput_marker("EXECPROBE: FAIL ", "no-cap-debug-before-the-exec");
        for (;;) sys_yield();
    }
    kput("EXECPROBE: before the exec: pid "); kput_int(pid);
    kput(", serial "); kput_int((int)pre.serial);
    kput(", badge "); kput_int((int)pre.badge); kputln("");

#ifndef SYSCOV_PROBES_ABSENT
    /* ---- 1. a null image pointer is refused -------------------------------
     *
     * The first of five calls that ENTER h_exec_image and come back. Each is a
     * separate rule in arm_image_from_user and each returns through the same
     * failure path, so they are written out rather than folded: a handler that
     * fails closed on one container and open on another passes any one of them. */
    int r_null = sys_exec_image(0, 64, 0, 0);
    kput("EXECPROBE: exec_image(NULL) -> "); kput_int(r_null); kputln("");
    check(r_null == SYS_ERR_INVAL, "exec-image-accepted-a-null-pointer");

    /* ---- 2. a length below the four bytes of a magic number ---------------- */
    int r_short = sys_exec_image(g_not_a_container, 3, 0, 0);
    kput("EXECPROBE: exec_image(len 3) -> "); kput_int(r_short); kputln("");
    check(r_short == SYS_ERR_INVAL, "exec-image-accepted-a-three-byte-image");

    /* ---- 3. a length past MAX_PROGRAM_SIZE --------------------------------
     *
     * Refused on the bound, before a byte is copied. A kernel that clamped
     * instead would go on to read 4 GiB out of this task's address space. */
    int r_huge = sys_exec_image(g_not_a_container, 0xFFFFFFFFu, 0, 0);
    kput("EXECPROBE: exec_image(len 4G-1) -> "); kput_int(r_huge); kputln("");
    check(r_huge == SYS_ERR_INVAL, "exec-image-accepted-an-over-long-length");

    /* ---- 4. a pointer this task does not map ------------------------------ */
    int r_unmapped = sys_exec_image(UNMAPPED_USER_PAGE, 64, 0, 0);
    kput("EXECPROBE: exec_image(unmapped) -> "); kput_int(r_unmapped); kputln("");
    check(r_unmapped == SYS_ERR_INVAL, "exec-image-accepted-an-unmapped-pointer");

    /* ---- 5. bytes that are no container this loader knows ------------------ */
    int r_junk = sys_exec_image(g_not_a_container, sizeof(g_not_a_container), 0, 0);
    kput("EXECPROBE: exec_image(junk) -> "); kput_int(r_junk); kputln("");
    check(r_junk == SYS_ERR_INVAL, "exec-image-accepted-an-unrecognised-container");

    /* ---- 6. a container claiming more than its buffer holds is refused -----
     *
     * execimgee's real image handed over at HALF its length: the header still
     * declares the whole payload, so `len` and the header disagree, and
     * arm_image_from_user must refuse rather than read past the buffer. This is
     * the exec-side witness for the same length check proctest tests on the
     * spawn side; its sibling is the OVERREACH check (S84), where the container
     * is honest and the ELF inside it lies, refused one layer down by the
     * staged_bytes() bound. A truncated image trips both, so proctest carries
     * the two control arms and this asserts the refusal reaches the exec path. */
    int r_trunc = sys_exec_image(execimgee_image, execimgee_image_len / 2, 0, 0);
    kput("EXECPROBE: exec_image(half an image) -> "); kput_int(r_trunc); kputln("");
    check(r_trunc == SYS_ERR_INVAL, "exec-image-accepted-a-truncated-image");

    /* ---- 7. and every one of those left this task exactly as it was --------
     *
     * "The image is intact on failure" is what h_exec_image's early return
     * claims, and it is a claim about the caller rather than about a return
     * code. Reaching this line at all is most of it; the id and the capability
     * are the rest. */
    check(sys_getpid() == pid, "a-refused-exec-changed-our-task-id");
    struct cap_info still;
    check(sys_cap_enumerate(pid, CAPSLOT_DEBUG, &still) == 0 && still.occupied &&
          still.serial == pre.serial, "a-refused-exec-disturbed-our-cspace");

    /* ---- 8. the real one ---------------------------------------------------
     *
     * Carries the pre-exec sample as argv. Anything reached after this line is a
     * failure by construction: SYS_EXEC_IMAGE does not return on success. */
    char b_pid[12], b_ser[12], b_bdg[12], b_typ[12], b_rgt[12], b_chk[12], b_fai[12];
    char *av[8];
    av[0] = "execimgee";
    av[1] = utoa((unsigned)pid,        b_pid);
    av[2] = utoa(pre.serial,           b_ser);
    av[3] = utoa(pre.badge,            b_bdg);
    av[4] = utoa(pre.type,             b_typ);
    av[5] = utoa(pre.rights,           b_rgt);
    av[6] = utoa((unsigned)(checks + 1), b_chk);   /* +1: the exec itself */
    av[7] = utoa((unsigned)failures,   b_fai);

    kputln("EXECPROBE: handing this task to the image it supplied");
    int r_exec = sys_exec_image(execimgee_image, execimgee_image_len, 8, av);

    kput("EXECPROBE: exec_image(valid) returned "); kput_int(r_exec); kputln("");
    kput_marker("EXECPROBE: FAIL ", "a-valid-image-was-refused");
    kput("EXECPROBE: FAIL "); kput_int(failures + 1); kputln(" checks failed");
#else
    kputln("EXECPROBE: skipped (SYSCOV_PROBES_ABSENT)");
#endif /* SYSCOV_PROBES_ABSENT */

    for (;;) sys_yield();
}
