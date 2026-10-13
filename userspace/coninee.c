#include "syscall.h"
#include "console_proto.h"
#include "libhorus.h"

/*
 * The program the console's input is lent to -- S93, LIMITATIONS 2.9b,
 * CONSOLE_SELFTEST builds only. The driver is consoletest.c, which plays the
 * shell: it lends this task the keyboard, waits until this task has seen it,
 * takes it back, and then requires that this task has lost it.
 *
 * It asks console_server, through its own CAPSLOT_CONSOLE_IN, the one question
 * the three input operations ask (CON_OP_INPUT_HELD), which reads nothing, so
 * the test needs nobody at the keyboard. It never exits on its own, so the only
 * way its capability can go is the revoke under test.
 *
 * ---- IT REPORTS THROUGH THE CAPABILITY GRAPH, NOT THE CONSOLE --------------
 *
 * As piperevokee does: a capability minted from slot 0 (the CAP_TCB on self
 * every task is born with, carrying CAP_RIGHT_ALL) into a marker slot states a
 * fact the driver reads with SYS_CAP_ENUMERATE.
 *   CI_SLOT_HELD   the lent capability carried input
 *   CI_SLOT_GONE   after that, it stopped carrying input (the revoke landed)
 *   CI_SLOT_NEVER  the capability it was lent never carried input
 */

/* Must match userspace/consoletest.c. */
#define CI_SLOT_HELD   27
#define CI_SLOT_GONE   28
#define CI_SLOT_NEVER  29

static void mark(unsigned slot) {
    (void)sys_cap_mint((int)slot, CAPSLOT_TCB, CAP_RIGHT_READ);
}

static void park(void) {
    for (;;) sys_yield();
}

void _start(void) {
    if (console_input_held(CAPSLOT_CONSOLE_IN) != 0) {
        mark(CI_SLOT_NEVER);
        park();
    }
    mark(CI_SLOT_HELD);
    for (;;) {
        /* Once the slot is empty the call itself is refused (no capability to
         * send through), and that is "gone" as much as the server's own
         * SYS_ERR_PERM would be. */
        if (console_input_held(CAPSLOT_CONSOLE_IN) != 0) {
            mark(CI_SLOT_GONE);
            park();
        }
        sys_yield();
    }
}
