#include "syscall.h"

/*
 * The spawned stage whose stdio end its spawner revokes -- LIMITATIONS 1.14,
 * PIPEREVOKE_SELFTEST builds only. The driver is piperevoketest.c, and the
 * reasoning for the whole test lives there.
 *
 * It is spawned with one pipe end wired in, and argv[1] says which: "w" for a
 * writer end in STDOUT_PIPE_SLOT, "r" for a reader end in STDIN_PIPE_SLOT. It
 * uses that end until the kernel says it no longer has one (SYS_ERR_PERM: the
 * slot is empty, because the revoke of the spawner's end removed it), records
 * that, and then waits to be killed. It never closes the end itself and never
 * exits on its own, so the only way its end can go is the revoke under test --
 * an end released by a close or an exit would make the driver's EOF mean
 * nothing.
 *
 * ---- IT REPORTS THROUGH THE CAPABILITY GRAPH, NOT THE CONSOLE --------------
 *
 * As forkexecee does, and for its reason: the driver decides, this task only
 * states a fact, and it states it where the driver can read it with
 * SYS_CAP_ENUMERATE. A capability minted from slot 0 (the CAP_TCB on self that
 * every task is born with, carrying CAP_RIGHT_ALL) into PR_SLOT_GONE means "my
 * end answered SYS_ERR_PERM"; one in PR_SLOT_OTHER means it answered something
 * a live or a removed end should never answer (EOF on a reader, EPIPE on a
 * writer, while the driver still holds the opposite end).
 */

/* Must match userspace/piperevoketest.c. */
#define PR_SLOT_GONE   27   /* the stdio end answered SYS_ERR_PERM: it is gone */
#define PR_SLOT_OTHER  28   /* it answered something no test step allows        */

static void park(void) {
    for (;;) sys_yield();
}

void _start(void) {
    char **argv = 0;
    int argc = sys_get_argv(&argv);
    int writer = (argc >= 2 && argv[1] && argv[1][0] == 'w');
    char byte = 'x';

    for (;;) {
        int r = writer ? sys_pipe_write(STDOUT_PIPE_SLOT, &byte, 1)
                       : sys_pipe_read(STDIN_PIPE_SLOT, &byte, 1);
        if (r == SYS_ERR_PERM) {
            (void)sys_cap_mint(PR_SLOT_GONE, CAPSLOT_TCB, CAP_RIGHT_READ);
            park();
        }
        /* A writer's EPIPE or a reader's EOF: the driver holds the opposite end
         * for the whole test, so neither is possible while this end exists. */
        if (r == SYS_ERR_PIPE || (!writer && r == 0)) {
            (void)sys_cap_mint(PR_SLOT_OTHER, CAPSLOT_TCB, CAP_RIGHT_READ);
            park();
        }
        sys_yield();
    }
}
