#include "syscall.h"

/*
 * make smoke-retype-race (RETYPE_RACE_SELFTEST only). The revoker of the pair.
 *
 * Every SYS_CAP_REVOKE runs the object collector. This retypes one endpoint of
 * its own, then mints a copy and revokes it as fast as it can, for as long as it
 * lives: `retyperace` kills it when its rounds are done, and that teardown runs
 * the collector once more. Minting and revoking a copy spends no untyped
 * memory, so the loop can run for ever. It needs nothing but an untyped region:
 * any task can do this.
 */
#define SLOT_UNTYPED CAPSLOT_UNTYPED
#define SLOT_MINE    40
#define SLOT_COPY    41

void _start(void) {
    if (sys_retype(SLOT_UNTYPED, KOBJ_ENDPOINT, 1, SLOT_MINE) != 1) {
        sys_write(1, "RETYPETEST: FAIL revoker-retype\n", 32);
        sys_exit();
    }
    /* Every mint and revoke must work: a revoker whose calls fail sweeps
     * nothing, and the gate would then pass having tested nothing. The kernel
     * also reports any retype window no sweep crossed (RETYPE_WINDOW_WIDEN). */
    for (;;) {
        if (sys_cap_mint(SLOT_COPY, SLOT_MINE, CAP_RIGHT_READ | CAP_RIGHT_REVOKE) != 0 ||
            sys_cap_revoke(SLOT_COPY) != 0) {
            sys_write(1, "RETYPETEST: FAIL revoker-mint-or-revoke\n", 40);
            sys_exit();
        }
    }
}
