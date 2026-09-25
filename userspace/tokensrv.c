/* Capability-token self-test SERVER (TOKEN_SELFTEST builds only).
 *
 * The server half of `make smoke-captoken` (docs/design/filesystem.md §5.1). It
 * holds the receive end of one endpoint and NOTHING that lets it mint: no MINT
 * right, no untyped, no capability to its clients. Everything it hands out, it
 * hands out through SYS_IPC_REPLY_CAP, which can only narrow the capability the
 * request came through. That is the property under test, so the server is
 * deliberately naive: it mints whatever it is asked to mint, with whatever rights
 * it is asked for, and the CLIENT checks that the kernel did not let it.
 *
 * Every reply echoes what SYS_IPC_INVOKER said about the request, so the client
 * can assert on the kernel's attestation rather than on anything the server
 * could make up.
 */

#include "syscall.h"
#include "libhorus.h"
#include "tokentest.h"

static void fail(const char *what) {
    kput_marker("TOKENTEST: FAIL server-", what);
    sys_exit();
}

void _start(void) {
    struct tok_req rq;
    struct tok_rep rp;

    for (;;) {
        int rc = sys_ipc_recv_block(CAPSLOT_CONSOLE_EP, &rq, sizeof(rq));
        if (rc < 0) fail("recv-block-refused");

        struct ipc_invoker inv;
        if (sys_ipc_invoker(CAPSLOT_CONSOLE_EP, &inv) != 0) fail("invoker-refused");

        rp.status       = TOK_OK;
        rp.token        = inv.token;
        rp.rights       = inv.rights;
        rp.carried      = inv.carried;
        rp.carry_token  = inv.carry_token;
        rp.carry_rights = inv.carry_rights;

        if (rc == (int)sizeof(rq) && rq.op == TOK_OP_MINT) {
            /* Ask for exactly what the client asked for. The kernel decides what
             * it actually gets. */
            int mr = sys_ipc_reply_cap(CAPSLOT_CONSOLE_EP, &rp, sizeof(rp),
                                       rq.want_rights, rq.want_token);
            if (mr == 0) continue;
            /* Refused: nothing was delivered and the reply right was kept, so the
             * call can still be answered, and must be, or the client hangs. That
             * this second reply succeeds is itself a check on the kernel's
             * "refusal keeps the right" rule. */
            rp.status = TOK_MINT_REFUSED;
        }
        int rr;
        unsigned tries = 0;
        while ((rr = sys_ipc_reply_to(CAPSLOT_CONSOLE_EP, &rp, sizeof(rp))) == IPC_AGAIN) {
            if (++tries > 200000u) fail("reply-timeout");
        }
        if (rr < 0) fail("reply-to-refused");
    }
}
