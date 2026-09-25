/* Capability-token self-test CLIENT (TOKEN_SELFTEST builds only).
 *
 * The client half of `make smoke-captoken`, and the half that decides the result:
 * it prints TOKENTEST: PASS <n> checks, or TOKENTEST: FAIL <name> naming the first
 * check that did not hold. docs/design/filesystem.md §5.1 is the design.
 *
 * WHAT IT PROVES, against a server that asks for everything (tokensrv.c):
 *   - a server sees the token and rights of the capability a request came
 *     through, as the kernel records them, and nothing the client can choose;
 *   - a reply-minted capability is bounded by the capability the request came
 *     through, whatever rights the server asks for (`reply-mint-escalated` is the
 *     check the control arm TOKEN_REPLY_MINT_UNMASKED=1 must turn red);
 *   - it never carries the receive right, so a client cannot become a receiver;
 *   - narrowing a tokened capability keeps its token;
 *   - a token is minted only from an untokened capability holding MINT;
 *   - a carried capability is reported, and one to a different endpoint is
 *     refused before anything is sent;
 *   - a reply-mint into an occupied slot, or into a call that named no slot, is
 *     refused, delivers nothing, and leaves the server able to answer anyway;
 *   - revoking a capability revokes everything reply-minted through it.
 *
 * Slot map, set up by tokencli's kernel harness (selftest.c token_selftest):
 *   SLOT_PLAIN  an UNTOKENED capability to the server's endpoint, with WRITE,
 *               MINT, REVOKE, GRANT and the four service bits: the kernel standing
 *               in for init, which in a real boot holds one of these because it
 *               made the endpoint;
 *   SLOT_OTHER  a capability to a DIFFERENT endpoint, for the carry refusal.
 */

#include "syscall.h"
#include "libhorus.h"
#include "tokentest.h"

#define SLOT_PLAIN   40
#define SLOT_ROOT    41
#define SLOT_CHILD   42
#define SLOT_GREEDY  43
#define SLOT_SELF    44
#define SLOT_NARROW  45
#define SLOT_BAD     46
#define SLOT_OTHER   47

/* A reply buffer must be the kernel's IPC_MSG_MAX (src/include/kernel.h), which
 * userspace headers do not export; sys_ipc_call's callers size it the same way. */
#define TOK_RBUF 256

#define PLAIN_RIGHTS (CAP_RIGHT_WRITE | CAP_RIGHT_MINT | CAP_RIGHT_REVOKE | CAP_RIGHT_GRANT | TOK_R_SERVICE)

static int checks;

static void fail(const char *what) {
    kput_marker("TOKENTEST: FAIL ", what);
    sys_exit();
}

static void check(int ok, const char *what) {
    if (!ok) fail(what);
    checks++;
}

/* One call. IPC_AGAIN (a full queue) is the only retryable answer; anything else
 * negative is returned so the caller can assert on it. */
static int call(unsigned slot, unsigned recv, unsigned carry, uint32_t op,
                uint32_t want_rights, uint64_t want_token, struct tok_rep *out) {
    struct tok_req rq = { op, want_rights, want_token };
    static unsigned char rbuf[TOK_RBUF];
    int rc;
    unsigned tries = 0;
    while ((rc = sys_ipc_call_cap(slot, recv, &rq, sizeof(rq), rbuf, carry)) == IPC_AGAIN) {
        if (++tries > 200000u) fail("call-timeout");
        spin_delay();
    }
    if (rc >= 0 && out) umemcpy(out, rbuf, sizeof(*out));
    return rc;
}

void _start(void) {
    struct tok_rep rp;

    kput("TOKENTEST: begin\n");

    /* ---- 1. An untokened capability: the server sees token 0 and its rights. */
    check(call(SLOT_PLAIN, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) >= 0, "plain-call-refused");
    check(rp.token == 0, "plain-call-reported-a-token");
    check(rp.rights == PLAIN_RIGHTS, "plain-call-reported-wrong-rights");
    check(rp.carried == 0, "plain-call-reported-a-carry");

    /* ---- 2. The first reply-mint: the server asks for EVERY right. */
    check(call(SLOT_PLAIN, SLOT_ROOT, IPC_NO_CAP, TOK_OP_MINT, 0xFFFFFFFFu, 0x100, &rp) >= 0, "root-mint-call-refused");
    check(rp.status == TOK_OK, "root-mint-refused");
    check(call(SLOT_ROOT, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) >= 0, "root-call-refused");
    check(rp.token == 0x100, "root-carries-wrong-token");
    check(rp.rights == PLAIN_RIGHTS, "reply-mint-escalated");            /* the control arm's target */
    check((rp.rights & CAP_RIGHT_READ) == 0, "reply-minted-receive-right");

    /* ---- 3. A narrower child, and the server trying to widen it again. */
    check(call(SLOT_ROOT, SLOT_CHILD, IPC_NO_CAP, TOK_OP_MINT, CAP_RIGHT_WRITE | TOK_R_A, 0x200, &rp) >= 0, "child-mint-call-refused");
    check(rp.status == TOK_OK && rp.token == 0x100, "child-mint-saw-wrong-invoker");
    check(call(SLOT_CHILD, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) >= 0, "child-call-refused");
    check(rp.token == 0x200 && rp.rights == (CAP_RIGHT_WRITE | TOK_R_A), "child-wrong-token-or-rights");
    check(call(SLOT_CHILD, SLOT_GREEDY, IPC_NO_CAP, TOK_OP_MINT, 0xFFFFFFFFu, 0x300, &rp) >= 0, "greedy-mint-call-refused");
    check(call(SLOT_GREEDY, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) >= 0, "greedy-call-refused");
    check(rp.token == 0x300, "greedy-wrong-token");
    check(rp.rights == (CAP_RIGHT_WRITE | TOK_R_A), "reply-mint-widened-a-child");

    /* ---- 4. A tokened capability cannot receive. */
    unsigned char junk[16];
    check(sys_ipc_recv(SLOT_ROOT, junk, sizeof(junk)) == SYS_ERR_PERM, "tokened-capability-received");

    /* ---- 5. Narrowing keeps the token. */
    check(sys_cap_mint(SLOT_NARROW, SLOT_ROOT, CAP_RIGHT_WRITE | TOK_R_B) == 0, "narrowing-refused");
    check(call(SLOT_NARROW, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) >= 0, "narrow-call-refused");
    check(rp.token == 0x100, "narrowing-lost-the-token");
    check(rp.rights == (CAP_RIGHT_WRITE | TOK_R_B), "narrowing-wrong-rights");

    /* ---- 6. Minting a token: only from an untokened capability with MINT. */
    check(sys_cap_mint_token(SLOT_BAD, SLOT_ROOT, 0xFFFFFFFFu, 0x999) != 0, "token-minted-from-a-tokened-capability");
    check(sys_cap_mint_token(SLOT_BAD, SLOT_PLAIN, 0xFFFFFFFFu, 0) != 0, "zero-token-minted");
    check(sys_cap_mint_token(SLOT_SELF, SLOT_PLAIN, CAP_RIGHT_WRITE | TOK_R_C | CAP_RIGHT_READ, 0x500) == 0, "mint-token-refused");
    check(call(SLOT_SELF, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) >= 0, "self-call-refused");
    check(rp.token == 0x500, "minted-token-wrong");
    check(rp.rights == (CAP_RIGHT_WRITE | TOK_R_C), "mint-token-wrong-rights");

    /* ---- 7. Carrying a second capability. */
    check(call(SLOT_CHILD, IPC_NO_CAP, SLOT_ROOT, TOK_OP_ECHO, 0, 0, &rp) >= 0, "carry-call-refused");
    check(rp.token == 0x200, "carry-changed-the-invoker");
    check(rp.carried == 1 && rp.carry_token == 0x100 && rp.carry_rights == PLAIN_RIGHTS, "carry-misreported");
    check(call(SLOT_CHILD, IPC_NO_CAP, SLOT_OTHER, TOK_OP_ECHO, 0, 0, &rp) == SYS_ERR_PERM, "carried-another-endpoint");

    /* ---- 8. Refused mints deliver nothing, and the server can still answer. */
    check(call(SLOT_ROOT, SLOT_CHILD, IPC_NO_CAP, TOK_OP_MINT, 0xFFFFFFFFu, 0x666, &rp) >= 0, "occupied-mint-call-refused");
    check(rp.status == TOK_MINT_REFUSED, "mint-into-an-occupied-slot");
    check(call(SLOT_CHILD, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) >= 0 && rp.token == 0x200,
          "occupied-slot-was-overwritten");
    check(call(SLOT_ROOT, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_MINT, 0xFFFFFFFFu, 0x777, &rp) >= 0, "unnamed-mint-call-refused");
    check(rp.status == TOK_MINT_REFUSED, "mint-into-a-call-that-named-no-slot");
    check(call(SLOT_ROOT, 3, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) == SYS_ERR_INVAL, "reserved-receive-slot-accepted");

    /* ---- 9. Revocation reaches everything minted through a capability. */
    check(sys_cap_revoke(SLOT_ROOT) == 0, "revoke-refused");
    check(call(SLOT_CHILD, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) < 0, "child-survived-its-parent");
    check(call(SLOT_GREEDY, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) < 0, "grandchild-survived");
    check(call(SLOT_NARROW, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) < 0, "narrowed-copy-survived");
    check(call(SLOT_SELF, IPC_NO_CAP, IPC_NO_CAP, TOK_OP_ECHO, 0, 0, &rp) >= 0, "unrelated-token-was-revoked");

    kput("TOKENTEST: PASS ");
    kput_int(checks);
    kput(" checks\n");
    sys_exit();
}
