/* Lending the console's input to a program for as long as it runs (S93;
 * LIMITATIONS 2.9b, closed 2026-10-13). See include/console_proto.h for the
 * rule console_server applies and include/libhorus.h for the contract.
 *
 * A separate member of libhorus.a, as hvfs.o and tui.o are, so a program that
 * never starts another links none of it. */
#include "libhorus.h"
#include "console_proto.h"

/* The rights a lent copy carries: send, and the three a borrower needs to lend
 * onward exactly as its lender did -- pass on (GRANT), narrow (MINT) and take
 * back (REVOKE). Never READ: the kernel strips the receive right from every
 * tokened capability (TOKEN_STRIPPED_RIGHTS), and asking for it here would only
 * be a request the kernel refuses to honour. */
#define CON_LEND_RIGHTS (CAP_RIGHT_WRITE | CAP_RIGHT_GRANT | CAP_RIGHT_MINT | CAP_RIGHT_REVOKE)

int console_lend(int child, unsigned from_slot, unsigned lend_slot, struct con_lend *l) {
    if (!l) return -1;
    l->slot = (int)lend_slot;
    l->lent = 0;
    l->krc = 0;
    /* A copy of OUR input capability in a slot of ours, and the child's copy is
     * granted FROM it, so the child's descends from it: revoking this one copy
     * later sweeps the child's and anything the child passed on, and leaves
     * ours alone. Granting ours directly would leave nothing to revoke but our
     * own. The slot is emptied first, because a mint overwrites what it lands
     * on, and what is there could be a copy still lent to somebody else. */
    (void)sys_cap_revoke(lend_slot);
    int r = sys_cap_mint((int)lend_slot, (int)from_slot, CON_LEND_RIGHTS);
    if (r != 0) { l->krc = r; return -1; }   /* we hold no input to lend */
    l->lent = 1;
    r = sys_cap_grant(child, lend_slot, CAPSLOT_CONSOLE_IN);
    if (r != 0) {
        l->krc = r;
        console_unlend(l);
        return -2;
    }
    return 0;
}

void console_unlend(struct con_lend *l) {
    if (!l || !l->lent) return;
#ifdef CONSOLE_LEND_UNREVOKED
    /* CONTROL ARM -- never ship. The lender forgets to take the input back, so
     * a program that has ended, and anything it passed the capability to, can
     * go on reading what is typed at the next prompt. consoletest's lent-copy
     * check must report a FAIL marker under it. */
    l->lent = 0;
    return;
#endif
    (void)sys_cap_revoke((uint32_t)l->slot);
    l->lent = 0;
}

int console_input_held(unsigned slot) {
    struct con_request  rq;
    struct con_response rp;
    umemset(&rq, 0, sizeof(rq));
    umemset(&rp, 0, sizeof(rp));
    rq.magic = CON_PROTO_MAGIC;
    rq.op    = CON_OP_INPUT_HELD;
    int r = ipc_call_retry((int)slot, 0, &rq, sizeof(rq), &rp);
    if (r < 0) return r;
    if (rp.magic != CON_PROTO_MAGIC) return -1;
    return rp.rc;
}
