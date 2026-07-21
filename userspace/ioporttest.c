#include "syscall.h"

/*
 * IOPORT_SELFTEST driver. The kernel (ioport_selftest) spawns this program with a
 * CAP_IO_DEVICE capability in slot 10 (the SYS_IOPORT_GRANT gate).
 *
 * It proves the TSS I/O-permission bitmap end-to-end from ring 3:
 *   0. register a fault handler (a denied in/out #GPs, delivered as a fault signal);
 *   1. request the port grant, then read an ALLOWLISTED port -- must NOT fault;
 *   2. read a NON-allowlisted port -- must #GP into the handler.
 * Reaching the handler at stage 2 is success. A fault at stage 1 (allowed port
 * faulted) or falling through stage 2 (denied port allowed) is a failure. This is
 * also the falsification hook: neuter the grant and the stage-1 read faults.
 */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }

static volatile int stage = 0;

/* Entered at ring 3 on a #GP from a denied in/out. The faulting instruction is
 * not restarted here, so we report and park (the TSD/signal self-test pattern).
 * The stage tells us whether this fault was the expected one. */
static void handler(void) {
    if (stage == 1)      wr("IOPORT_SELFTEST: FAIL allowed-port-faulted\n");
    else if (stage == 2) wr("IOPORT_SELFTEST: PASS\n");
    else                 wr("IOPORT_SELFTEST: FAIL unexpected-fault\n");
    for (;;) { sys_yield(); }
}

static inline unsigned char inb(unsigned short port) {
    unsigned char v;
    __asm__ volatile ("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

#define ALLOWED_PORT 0x3FD   /* serial COM1 line-status register: on the allowlist */
#define DENIED_PORT  0x70    /* CMOS address register: NOT on the allowlist */

void _start(void) {
    if (sys_signal((uintptr_t)&handler) != 0) {
        wr("IOPORT_SELFTEST: FAIL register\n"); for (;;) sys_yield();
    }
    wr("IOPORT_SELFTEST: begin\n");

    if (sys_ioport_grant() != 0) {
        wr("IOPORT_SELFTEST: FAIL grant\n"); for (;;) sys_yield();
    }

    /* (1) An allowlisted port must NOT fault now that the grant is active. */
    stage = 1;
    (void)inb(ALLOWED_PORT);

    /* (2) A non-allowlisted port must still #GP into the handler (-> PASS). */
    stage = 2;
    (void)inb(DENIED_PORT);

    /* Reached only if the denied read did NOT fault: the bitmap is too permissive. */
    wr("IOPORT_SELFTEST: FAIL denied-port-allowed\n");
    for (;;) sys_yield();
}
