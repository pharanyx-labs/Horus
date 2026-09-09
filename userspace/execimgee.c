/* execimgee -- the image execprobe replaces itself with, and the only half of
 * the witness that can see across the exec
 *
 * A task that execs cannot watch itself do it. The code that would ask the
 * question is gone by the time there is an answer, and the task that comes back
 * has no memory of what it was: a fresh image, fresh statics, a fresh stack.
 * Everything this file checks it therefore checks against a baseline it was
 * HANDED, in the argv of the exec itself -- see the header of
 * userspace/execprobe.c for why that arrangement was chosen over a second task
 * watching from outside.
 *
 * WHAT IT CANNOT DO IS FORGE ITS OWN ANSWER. The five numbers in argv are the
 * claim; every value compared against them is read back from the kernel here,
 * after the exec, through SYS_CAP_ENUMERATE and SYS_GET_TASK_INFO. A kernel that
 * dropped, re-minted or re-parented the capability answers differently from the
 * vector and this file says which.
 *
 * THE CHECKS ARE S42's, IN S42's VOCABULARY, and that is deliberate rather than
 * imitative. `SECURITY.md` S42 names SYS_EXEC_NAMED and SYS_EXEC_IMAGE together
 * and was witnessed only for the first, by make smoke-forkexec; writing this
 * side in the same terms means the two control arms that falsify that gate --
 * EXEC_RESET_CSPACE=1 and EXEC_ROOT_CSPACE=1, which live in the exec tail both
 * forms share -- falsify this one unchanged. Markers are named after
 * forkexectest's for the same reason.
 *
 * ONE CHECK IS NOT S42's. The uid: an exec that changed it would be a privilege
 * change performed by a syscall whose whole defence is that it is self-only, and
 * "self-only" stops meaning anything if the self that comes back is a different
 * principal. It is cheap to state and nothing else states it.
 *
 * NO CHECK SHORT-CIRCUITS past the argv gate, for forktest.c's reason: each
 * states a separate rule, an arm aims at each, and an early exit on the first
 * would make the later ones unreachable from any arm -- which is the definition
 * of a check that cannot fail.
 */
#include "syscall.h"
#include "errno.h"
#include "libhorus.h"

static int checks;
static int failures;

static void check(int ok, const char *what) {
    if (ok) { checks++; return; }
    kput_marker("EXECPROBE: FAIL ", what);
    failures++;
}

/* Parse a non-negative decimal, or -1 on anything else. A mangled vector must
 * become a failed comparison rather than a plausible number: returning 0 for
 * garbage would make "the serial survived" true whenever the serial is 0. */
static long parse_uint(const char *s) {
    if (!s || !*s) return -1;
    long v = 0;
    for (unsigned i = 0; s[i]; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
        if (v > 4294967295L) return -1;
    }
    return v;
}

void _start(void) {
    char **argv = 0;
    int argc = sys_get_argv(&argv);

    kput("EXECPROBE: the supplied image is running, argc "); kput_int(argc); kputln("");

    /* ---- 1. the vector crossed the exec -----------------------------------
     *
     * Fatal, and the only fatal check here: every comparison below reads its
     * baseline out of this vector, so a run without it cannot distinguish "the
     * kernel is right" from "we have nothing to compare against". Reported as a
     * failure and stopped, rather than continued into seven checks that would
     * all fail for one reason. */
    if (argc != 8 || !argv || !ustreq(argv[0], "execimgee") || argv[8] != 0) {
        kput_marker("EXECPROBE: FAIL ", "exec-image-did-not-deliver-our-argv");
        kputln("EXECPROBE: FAIL 1 checks failed");
        for (;;) sys_yield();
    }
    checks++;

    long want_pid    = parse_uint(argv[1]);
    long want_serial = parse_uint(argv[2]);
    long want_badge  = parse_uint(argv[3]);
    long want_type   = parse_uint(argv[4]);
    long want_rights = parse_uint(argv[5]);
    long pre_checks  = parse_uint(argv[6]);
    long pre_fails   = parse_uint(argv[7]);
    check(want_pid >= 0 && want_serial >= 0 && want_badge >= 0 && want_type >= 0 &&
          want_rights >= 0 && pre_checks >= 0 && pre_fails >= 0,
          "exec-image-mangled-the-argv-strings");

    /* ---- 2. it is the same task ------------------------------------------- */
    int pid = sys_getpid();
    kput("EXECPROBE: after the exec: pid "); kput_int(pid); kputln("");
    check(pid == (int)want_pid, "exec-image-changed-the-task-id");

    /* ---- 3. the capability is still there ---------------------------------
     *
     * And the call that asks is itself gated on it, so a dropped capability is
     * refused by the central gate and reported here rather than answered with an
     * empty slot. EXEC_RESET_CSPACE=1 -- "give the new image a clean slate" --
     * fails here and nowhere else. */
    struct cap_info post;
    int erc = sys_cap_enumerate(pid, CAPSLOT_DEBUG, &post);
    kput("EXECPROBE: cap_enumerate(self, 19) -> "); kput_int(erc); kputln("");
    if (erc != 0 || !post.occupied) {
        kput_marker("EXECPROBE: FAIL ", "exec-dropped-our-capability");
        failures++;
    } else {
        checks++;

        /* ---- 4. it is the same authority ---------------------------------- */
        check(post.type == (unsigned)want_type && post.rights == (unsigned)want_rights,
              "exec-altered-our-capability");

        /* ---- 5. it is the SAME capability, not a fresh one that resembles it
         *
         * A re-mint leaves every capability derived from this one badging a
         * serial that no longer exists, so a revocation aimed at this would stop
         * reaching them. Identical authority, no lineage: invisible to every
         * functional check, which is why it gets one of its own. */
        kput("EXECPROBE: serial "); kput_int((int)post.serial);
        kput(", badge "); kput_int((int)post.badge); kputln("");
        check(post.serial == (unsigned)want_serial, "exec-recreated-our-capability");

        /* ---- 6. and it still names its parent ------------------------------ */
        check(post.badge == (unsigned)want_badge, "exec-orphaned-our-capability");
    }

    /* ---- 7. the kernel loaded the bytes we supplied ------------------------
     *
     * The name comes out of the .bin container header of the image execprobe
     * handed the kernel, so it is the one thing here that could not be true of
     * some other image the loader might have entered. */
    struct task_info ti;
    int trc = sys_get_task_info(pid, &ti);
    check(trc == 0 && ustreq(ti.name, "execimgee"), "exec-image-entered-some-other-image");

    /* ---- 8. and we are still the principal we were -------------------------
     *
     * See the header: self-only is not a defence if the self that comes back is
     * a different principal. execprobe is spawned as uid 1000. */
    check(trc == 0 && ti.uid == 1000, "exec-image-changed-our-uid");

    checks   += (int)pre_checks;
    failures += (int)pre_fails;

    if (failures) {
        kput("EXECPROBE: FAIL "); kput_int(failures); kputln(" checks failed");
    } else {
        kput("EXECPROBE: PASS "); kput_int(checks);
        kputln(" checks - the image syscall ran, refused what it should, and kept the authority it found");
    }
    for (;;) sys_yield();
}
