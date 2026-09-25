/* The wire format between tokensrv and tokencli (TOKEN_SELFTEST builds only).
 * See tokencli.c for what the test proves. */
#ifndef HORUS_TOKENTEST_H
#define HORUS_TOKENTEST_H

#include <stdint.h>

#define TOK_OP_ECHO 1u   /* reply with what SYS_IPC_INVOKER reported */
#define TOK_OP_MINT 2u   /* as ECHO, and reply-mint want_rights/want_token */

#define TOK_OK            0u
#define TOK_MINT_REFUSED  1u

/* Service-defined rights: the bits a server gives meaning to. The kernel treats
 * them as opaque and only ever intersects them. */
#define TOK_R_A (1u << 8)
#define TOK_R_B (1u << 9)
#define TOK_R_C (1u << 10)
#define TOK_R_D (1u << 11)
#define TOK_R_SERVICE (TOK_R_A | TOK_R_B | TOK_R_C | TOK_R_D)

struct tok_req {
    uint32_t op;
    uint32_t want_rights;
    uint64_t want_token;
};

struct tok_rep {
    uint32_t status;
    uint32_t rights;        /* SYS_IPC_INVOKER's attestation, echoed */
    uint64_t token;
    uint32_t carried;
    uint32_t carry_rights;
    uint64_t carry_token;
};

#endif
