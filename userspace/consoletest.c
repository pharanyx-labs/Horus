/* Console self-test client (CONSOLE_SELFTEST builds only).
 *
 * Connects to the userspace console server over IPC and asks it to write a line
 * to the console. The server emits that line to the serial port with its own
 * hands (native out), so the success marker appearing on serial is proof of the
 * whole ring-3 console output path: client -> IPC -> console_server -> hardware,
 * with no kernel console code involved.
 *
 * Then it is the witness for who may use the console (`make smoke-console-pass`):
 * S93, input is a capability lent for as long as a program runs, and S135, the
 * kernel's own console paths need the console's capabilities (LIMITATIONS 1.6
 * and 2.9b, closed 2026-10-13). One marker, CONSOLE_PASS: PASS or
 * CONSOLE_PASS: FAIL <reason>.
 *
 * WHAT THIS TASK HOLDS, from the kernel half of the self-test
 * (console_selftest in src/kernel/selftest.c), and why each:
 *
 *   CT_SLOT_MINTER  init's console input minter: the console endpoint,
 *                   untokened, with WRITE, MINT, GRANT and REVOKE and no
 *                   receive right, so this task can do what init does and mint
 *                   the input capability. It is also how this task talks to the
 *                   server, since it starts with nothing in CAPSLOT_CONSOLE_EP.
 *   CAPSLOT_UNTYPED to spawn the borrower and retype an endpoint
 *   CAPSLOT_DEBUG   to read the borrower's slots (SYS_CAP_ENUMERATE)
 *
 * and, deliberately, NOTHING in CAPSLOT_CONSOLE_EP or CAPSLOT_CONSOLE, so the
 * first step can show the kernel refusing a task that holds neither.
 *
 * Each step's failure has its own reason, and each control arm reaches a
 * different first failure:
 *   KCONSOLE_WRITE_UNGATED=1  kernel-write-without-capability
 *   KCONSOLE_READ_UNGATED=1   kernel-read-without-capability
 *   CONSOLE_INPUT_UNGATED=1   untokened-holds-input
 *   CONSOLE_LEND_UNREVOKED=1  lent-input-survived
 */

#include "syscall.h"
#include "console_proto.h"
#include "libhorus.h"
#include "coninee_image.h"   /* coninee_image[]/_len: the borrower this spawns */

#define CT_SLOT_MINTER  30   /* init's console input minter, untokened (root[23]) */
#define CT_SLOT_OTHER   29   /* the console endpoint under a token that is not input */
#define CT_SLOT_LEND    26   /* the copy the borrower's is granted from */
#define CT_SLOT_NOTCON  31   /* an endpoint that is not the console */

/* Must match userspace/coninee.c. */
#define CI_SLOT_HELD    27
#define CI_SLOT_GONE    28
#define CI_SLOT_NEVER   29

#define SPIN_LIMIT      200000

/* One request/reply round-trip through `slot`. The retry contract (transient
 * only, and bounded) lives in libhorus's ipc_call_retry: the old `while (r < 0)`
 * retried SYS_ERR_PERM forever and turned a capability refusal into an
 * unkillable hang (G-8 signature C). */
static int rpc_through(unsigned slot, struct con_request *rq, struct con_response *rp) {
    rq->magic = CON_PROTO_MAGIC;
    int r = ipc_call_retry((int)slot, 0, rq, sizeof(*rq), rp);
    if (r < 0) return r;
    if (rp->magic != CON_PROTO_MAGIC) return -102;
    return rp->rc;
}

/* Emit a line through the console SERVER, which writes to serial natively.
 * kput cannot be seen here: the kernel's print() is klog-only once a ring-3
 * server owns the console, and this task holds no console capability for the
 * kernel path anyway. ONE request per marker, so another writer cannot split
 * it (LIMITATIONS 2.6a). */
static void say(const char *m) {
    struct con_request  q;
    struct con_response r;
    umemset(&q, 0, sizeof(q));
    q.op  = CON_OP_WRITE;
    unsigned k = uslen(m); if (k > CON_IO_MAX) k = CON_IO_MAX;
    umemcpy(q.data, m, k);
    q.len = k;
    (void)rpc_through(CT_SLOT_MINTER, &q, &r);
}

static void fail(const char *why) {
    char line[96];
    const char *pfx = "CONSOLE_PASS: FAIL ";
    unsigned n = 0;
    while (*pfx && n < sizeof(line) - 2) line[n++] = *pfx++;
    while (*why && n < sizeof(line) - 2) line[n++] = *why++;
    line[n++] = '\n';
    line[n] = 0;
    say(line);
    sys_exit();
}

/* Ask the server for one of the three reads through `slot`. A refusal returns
 * at once; a read that is SERVED blocks for a keystroke nobody will type, so a
 * step that expects a refusal and does not get one hangs here rather than
 * failing -- which is why every such step is preceded by CON_OP_INPUT_HELD, the
 * same predicate without the read, and the arm reaches that first. */
static int ask(unsigned slot, uint32_t op) {
    struct con_request  q;
    struct con_response r;
    umemset(&q, 0, sizeof(q));
    q.op  = op;
    q.len = 8;
    return rpc_through(slot, &q, &r);
}

static int slot_occupied(int tid, unsigned slot, struct cap_info *ci) {
    return sys_cap_enumerate(tid, slot, ci) == 0 && ci->occupied;
}

static int wait_for_slot(int tid, unsigned slot) {
    struct cap_info ci;
    for (int i = 0; i < SPIN_LIMIT; i++) {
        if (slot_occupied(tid, slot, &ci)) return 1;
        sys_yield();
    }
    return 0;
}

/* ---- 1. The kernel's console write needs the console's capability (S135) ---- */
static void step_kernel_write(void) {
    /* Neither the console endpoint in CAPSLOT_CONSOLE_EP nor CAP_CONSOLE in
     * CAPSLOT_CONSOLE: refused, whatever the bytes. Until 2026-10-13 this
     * returned the length written. */
    if (sys_write(1, "x", 1) != SYS_ERR_PERM) fail("kernel-write-without-capability");

    /* An endpoint in the console's slot that is not the console's: refused,
     * because the kernel compares the object and not only the type. */
    if (sys_retype(CAPSLOT_UNTYPED, KOBJ_ENDPOINT, 1, CT_SLOT_NOTCON) != 1) fail("retype-endpoint");
    if (sys_cap_mint(CAPSLOT_CONSOLE_EP, CT_SLOT_NOTCON, CAP_RIGHT_WRITE | CAP_RIGHT_REVOKE) != 0)
        fail("mint-other-endpoint");
    if (sys_write(1, "x", 1) != SYS_ERR_PERM) fail("kernel-write-through-another-endpoint");
    if (sys_cap_revoke(CAPSLOT_CONSOLE_EP) != 0) fail("revoke-other-endpoint");

    /* And the positive half: the console endpoint, send-only, as every program
     * holds it, is accepted. Nothing reaches the wire -- the server owns it --
     * but the kernel's answer is the length, not a refusal. */
    if (sys_cap_mint(CAPSLOT_CONSOLE_EP, CT_SLOT_MINTER, CAP_RIGHT_WRITE) != 0) fail("mint-stdout");
    if (sys_write(1, "x", 1) != 1) fail("kernel-write-refused-to-a-holder");
}

/* ---- 2. The kernel's console reads need CAP_CONSOLE with READ (S135) ---------- */
static void step_kernel_read(void) {
    char b[8];
    /* A console server owns the UART here, so the kernel would refuse these
     * anyway (SYS_ERR_BUSY, "do not race the owner"); the capability is asked
     * FIRST, so the answer is SYS_ERR_PERM, and under KCONSOLE_READ_UNGATED it
     * is the ownership refusal instead. Measured: the ownership refusal was -1
     * until this test was written, which IS SYS_ERR_PERM, and the arm passed the
     * base gate; the two refusals had to be made distinguishable first. */
    if (sys_read(0, b, sizeof(b)) != SYS_ERR_PERM) fail("kernel-read-without-capability");
    if (sys_get_pass(b, sizeof(b)) != SYS_ERR_PERM) fail("kernel-getpass-without-capability");
}

/* ---- 3. console_server reads only for the input capability (S93) -------------- */
static void step_server_input(void) {
    /* The stdout every program holds: untokened, send-only. Asked first without
     * a read, then each read, every one refused without reading. */
    if (console_input_held(CAPSLOT_CONSOLE_EP) != SYS_ERR_PERM) fail("untokened-holds-input");
    if (ask(CAPSLOT_CONSOLE_EP, CON_OP_GETPASS)  != SYS_ERR_PERM) fail("getpass-served-untokened");
    if (ask(CAPSLOT_CONSOLE_EP, CON_OP_GETLINE)  != SYS_ERR_PERM) fail("getline-served-untokened");
    if (ask(CAPSLOT_CONSOLE_EP, CON_OP_READ_RAW) != SYS_ERR_PERM) fail("readraw-served-untokened");

    /* A holder of stdout cannot make itself an input capability: it carries no
     * MINT, and the kernel refuses a tokened mint without it. */
    if (sys_cap_mint_token(CAPSLOT_CONSOLE_IN, CAPSLOT_CONSOLE_EP, CAP_RIGHT_WRITE,
                           CON_TOKEN_INPUT) == 0)
        fail("stdout-minted-input");

    /* A token that is not the input token is not input. */
    if (sys_cap_mint_token(CT_SLOT_OTHER, CT_SLOT_MINTER, CAP_RIGHT_WRITE, CON_TOKEN_INPUT + 1) != 0)
        fail("mint-other-token");
    if (console_input_held(CT_SLOT_OTHER) != SYS_ERR_PERM) fail("other-token-holds-input");
    if (ask(CT_SLOT_OTHER, CON_OP_GETPASS) != SYS_ERR_PERM) fail("getpass-served-other-token");

    /* What init does: mint the input capability from the untokened minter. The
     * positive half: it carries input. */
    if (sys_cap_mint_token(CAPSLOT_CONSOLE_IN, CT_SLOT_MINTER,
                           CAP_RIGHT_WRITE | CAP_RIGHT_GRANT | CAP_RIGHT_MINT | CAP_RIGHT_REVOKE,
                           CON_TOKEN_INPUT) != 0)
        fail("mint-input");
    if (console_input_held(CAPSLOT_CONSOLE_IN) != 0) fail("input-not-recognised");
}

/* ---- 4. Lent for as long as the program runs, then taken back (S93) ----------- */
static void step_lend(void) {
    char *argv[2] = { (char *)"coninee", 0 };
    int kid = sys_spawn_image(coninee_image, coninee_image_len, 1, argv);
    if (kid <= 0) fail("spawn-borrower");

    /* Spawned with the stdout every child inherits and no input: what a program
     * the shell starts without waiting for it (`spawn`) holds. */
    struct cap_info ci;
    if (slot_occupied(kid, CAPSLOT_CONSOLE_IN, &ci)) fail("borrower-born-with-input");

    struct con_lend l;
    if (console_lend(kid, CAPSLOT_CONSOLE_IN, CT_SLOT_LEND, &l) != 0) fail("lend");
    if (!slot_occupied(kid, CAPSLOT_CONSOLE_IN, &ci)) fail("lent-input-not-installed");
    if (ci.rights != (CAP_RIGHT_WRITE | CAP_RIGHT_GRANT | CAP_RIGHT_MINT | CAP_RIGHT_REVOKE))
        fail("lent-input-wrong-rights");
    if (sys_task_resume(kid) != 0) fail("resume-borrower");

    /* The borrower reads its lent capability as input before anything is taken
     * back. */
    if (!wait_for_slot(kid, CI_SLOT_HELD)) {
        fail(slot_occupied(kid, CI_SLOT_NEVER, &ci) ? "lent-input-not-input" : "borrower-silent");
    }

    console_unlend(&l);

    /* From two sides that cannot both be wrong the same way: the borrower's slot
     * is empty in the capability graph, and the borrower itself sees its input
     * gone. */
    if (slot_occupied(kid, CAPSLOT_CONSOLE_IN, &ci)) fail("lent-input-survived");
    if (!wait_for_slot(kid, CI_SLOT_GONE)) fail("lent-input-still-reads");

    /* And it took back only the lent copy: the lender still holds input (S4). */
    if (console_input_held(CAPSLOT_CONSOLE_IN) != 0) fail("lender-lost-input");

    (void)sys_kill(kid);
    (void)sys_wait(kid);
}

void _start(void) {
    /* The payload IS the success marker of smoke-console: the server writes it to
     * serial natively, so its appearance proves the ring-3 console served this
     * write end-to-end. */
    static const char *msg = "CONSOLE_SELFTEST: PASS\n";

    struct con_request  rq;
    struct con_response rp;
    umemset(&rq, 0, sizeof(rq));
    rq.op  = CON_OP_WRITE;
    unsigned n = uslen(msg); if (n > CON_IO_MAX) n = CON_IO_MAX;
    umemcpy(rq.data, msg, n);
    rq.len = n;
    if (rpc_through(CT_SLOT_MINTER, &rq, &rp) != (int)n) sys_exit();   /* no channel to say it on */

    step_kernel_write();
    step_kernel_read();
    step_server_input();
    step_lend();

    say("CONSOLE_PASS: PASS console input is a capability, lent and taken back; the kernel's console paths ask for theirs\n");
    sys_exit();
}
