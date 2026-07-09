#include "syscall.h"

/*
 * Process-control self-test driver (PROC_SELFTEST builds only).
 *
 * The kernel (proc_selftest) spawns three tasks — this driver, a "hello" child
 * that finishes with sys_exit, and a "looper" child that loops forever — and
 * grants this driver CAP_AUDIT (to read task state) plus a CAP_TCB capability to
 * the looper child (to terminate it). The driver then:
 *   1. waits until no live task named "hello" remains  -> SYS_EXIT worked;
 *   2. finds the live "looper", SYS_KILLs it via the TCB cap, and confirms it
 *      reaches the dead state                          -> SYS_KILL worked.
 * Prints "PROC_SELFTEST: PASS" on success; `make smoke-proc` asserts on it.
 *
 * The driver deliberately does not spawn anything itself: spawning from ring 3
 * is a separate piece of work (a task's CR3 does not map the physical pages
 * do_spawn touches) tracked for the init/exec stage.
 */

static void report(const char *s) {
    int n = 0;
    while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

static int name_eq(const char *a, const char *b) {
    int i = 0;
    for (; a[i] && b[i]; i++) if (a[i] != b[i]) return 0;
    return a[i] == b[i];
}

/* First live task whose name matches, or -1. */
static int find_alive(const char *name) {
    struct task_info ti;
    for (int id = 1; id < 64; id++) {
        if (sys_get_task_info(id, &ti) == 0 && ti.state != 0 && name_eq(ti.name, name))
            return id;
    }
    return -1;
}

/* Ring-3 spin (preemptible) so the timer can run/reap the children. */
static void settle(void) { for (volatile int d = 0; d < 20000; d++) { } }

void _start(void) {
    /* --- SYS_EXIT: the "hello" child terminates itself --- */
    int gone = 0;
    for (int i = 0; i < 4000; i++) {
        if (find_alive("hello") < 0) { gone = 1; break; }
        settle();
    }
    if (!gone) { report("PROC_SELFTEST: FAIL exit\n"); sys_exit(); }

    /* --- SYS_KILL: terminate the forever-looping "looper" via its TCB cap --- */
    int loop = find_alive("looper");
    if (loop < 0)            { report("PROC_SELFTEST: FAIL find-looper\n"); sys_exit(); }
    if (sys_kill(loop) != 0) { report("PROC_SELFTEST: FAIL kill-rc\n");     sys_exit(); }

    int dead = 0;
    struct task_info ti;
    for (int i = 0; i < 4000; i++) {
        if (sys_get_task_info(loop, &ti) == 0 && ti.state == 0) { dead = 1; break; }
        settle();
    }
    if (!dead) { report("PROC_SELFTEST: FAIL kill\n"); sys_exit(); }

    /* --- ring-3 spawn: the driver spawns a child itself, which then exits --- */
    int child = sys_spawn_named("hello");
    if (child <= 0) { report("PROC_SELFTEST: FAIL r3-spawn\n"); sys_exit(); }
    int reaped = 0;
    struct task_info ci;
    for (int i = 0; i < 6000; i++) {
        if (sys_get_task_info(child, &ci) == 0 && ci.state == 0) { reaped = 1; break; }
        settle();
    }
    if (!reaped) { report("PROC_SELFTEST: FAIL r3-spawn-exit\n"); sys_exit(); }

    report("PROC_SELFTEST: PASS exit+kill+spawn\n");

    /* --- SYS_EXEC_NAMED: spawn a child ("exectest") that replaces its own image
     * with "hello" in place (same pid, same cspace). We (the driver) stay alive
     * so the child's exit switches cleanly back to us. If exec worked, control
     * passed to hello, which runs and exits, so the child pid reaches the dead
     * state; if exec had *returned*, the child would print "FAIL exec-returned"
     * (caught by the smoke fail-marker), and a broken exec would fault (caught by
     * the kernel fault detector). Observing the child cleanly gone, with neither,
     * confirms exec transferred control into the replaced image. --- */
    int ec = sys_spawn_named("exectest");
    if (ec <= 0) { report("PROC_SELFTEST: FAIL exec-spawn\n"); sys_exit(); }
    int ec_gone = 0;
    struct task_info ei;
    for (int i = 0; i < 8000; i++) {
        if (sys_get_task_info(ec, &ei) == 0 && ei.state == 0) { ec_gone = 1; break; }
        settle();
    }
    if (!ec_gone) { report("PROC_SELFTEST: FAIL exec-child-stuck\n"); sys_exit(); }

    /* --- SYS_CAP_GRANT: delegate our CAP_AUDIT (slot 7) into a child's cspace.
     * We hold a CAP_TCB to the child (granted on spawn), so the grant is
     * authorised. The child ("grantee") polls SYS_READ_AUDIT until the delegated
     * cap lands (proving the grant works) and checks that its own unauthorised
     * grants are all denied (fail-closed), then prints "grant OK" and exits. --- */
    int gp = sys_spawn_named("grantee");
    if (gp <= 0) { report("PROC_SELFTEST: FAIL grant-spawn\n"); sys_exit(); }
    if (sys_cap_grant(gp, 7, 7) != 0) { report("PROC_SELFTEST: FAIL grant-rc\n"); sys_exit(); }
    int gg = 0;
    struct task_info gi;
    for (int i = 0; i < 12000; i++) {
        if (sys_get_task_info(gp, &gi) == 0 && gi.state == 0) { gg = 1; break; }
        settle();
    }
    if (!gg) { report("PROC_SELFTEST: FAIL grant-child-stuck\n"); sys_exit(); }

    report("PROC_SELFTEST: PASS exit+kill+spawn+exec+grant\n");

    /* --- SYS_WAIT: block until a child exits, on the preemptive block/switch
     * path (TASK_BLOCKED_WAIT) rather than the old cooperative yield() spin.
     * Spawn "hello" (which exits on its own) and immediately block on it — the
     * child has not been scheduled yet, so this reliably suspends us until the
     * child's teardown wakes us. sys_wait must return 0 only once the child is
     * actually dead (an early/spurious wake while it is still alive is a bug). */
    int wc = sys_spawn_named("hello");
    if (wc <= 0) { report("PROC_SELFTEST: FAIL wait-spawn\n"); sys_exit(); }
    if (sys_wait(wc) != 0) { report("PROC_SELFTEST: FAIL wait-rc\n"); sys_exit(); }
    struct task_info wi;
    if (sys_get_task_info(wc, &wi) == 0 && wi.state != 0) {
        report("PROC_SELFTEST: FAIL wait-early\n"); sys_exit();   /* woke while still alive */
    }
    report("PROC_SELFTEST: wait OK\n");

    /* --- SYS_WAIT wakes on a FAULT death too: spawn "faulter" (takes an
     * unhandled #UD) and block on it. The kernel's fault handler tears the task
     * down and must wake us just like a clean exit does — this is the path a
     * blocking init relies on to relaunch a shell that *faulted*, not only one
     * that exited. sys_wait must return 0 with the child confirmed dead. --- */
    int fc = sys_spawn_named("faulter");
    if (fc <= 0) { report("PROC_SELFTEST: FAIL fault-spawn\n"); sys_exit(); }
    if (sys_wait(fc) != 0) { report("PROC_SELFTEST: FAIL fault-wait-rc\n"); sys_exit(); }
    struct task_info fi;
    if (sys_get_task_info(fc, &fi) == 0 && fi.state != 0) {
        report("PROC_SELFTEST: FAIL fault-wait-early\n"); sys_exit();
    }
    report("PROC_SELFTEST: fault-wait OK\n");

    /* --- SYS_SIGNAL: async task-to-task signal to a registered handler. Spawn
     * "sigtarget" (it registers a handler and spins); we hold its CAP_TCB from
     * the spawn, so we may signal it. Give it time to register, then send
     * SIG_USR1; the kernel redirects it into its handler, which prints the final
     * "+signal" pass marker (only reachable via handler delivery — an unhandled
     * signal would terminate it silently) and exits. Confirm it reaches dead. --- */
    int sp = sys_spawn_named("sigtarget");
    if (sp <= 0) { report("PROC_SELFTEST: FAIL sig-spawn\n"); sys_exit(); }
    for (int i = 0; i < 3000; i++) settle();   /* let it register its handler */
    if (sys_send_signal(sp, SIG_USR1) != 0) { report("PROC_SELFTEST: FAIL sig-send\n"); sys_exit(); }
    int sg = 0;
    struct task_info si;
    for (int i = 0; i < 12000; i++) {
        if (sys_get_task_info(sp, &si) == 0 && si.state == 0) { sg = 1; break; }
        settle();
    }
    if (!sg) { report("PROC_SELFTEST: FAIL sig-stuck\n"); sys_exit(); }
    /* sigtarget's handler printed the final "+signal" PASS marker on delivery. */
    sys_exit();
}
