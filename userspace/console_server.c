/* Userspace console server (Phase 6, driver privilege separation).
 *
 * The console (VGA text / serial) driver, moved out of ring 0 into a ring-3
 * server that owns the hardware directly. At startup it takes ownership of the
 * console hardware using the three device-delegation mechanisms:
 *   - SYS_IOPORT_GRANT  (J3): native in/out on the serial UART + VGA registers;
 *   - SYS_MAP_PHYS      (J2): the VGA text framebuffer mapped into its own AS.
 * (Keyboard input via SYS_IRQ_REGISTER (J4) is a later job.) It then serves
 * console-write requests over IPC: a client sends CON_OP_WRITE and the server
 * emits the bytes to the serial port and the framebuffer with its own hands — no
 * kernel console code on the path. A bug in this parsing/output logic can no
 * longer reach kernel memory, which is the whole point.
 *
 * This is the gated CONSOLE_SELFTEST milestone (server + client driven over IPC),
 * exactly as the filesystem server was first proven via FS_SELFTEST before
 * becoming the default. See docs/proposals/console-server.md and include/console_proto.h.
 */

#include "syscall.h"
#include "console_proto.h"

/* ---- native port I/O (usable only after SYS_IOPORT_GRANT) ------------------ */
static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile ("outb %0, %1" :: "a"(val), "Nd"(port));
}
static inline uint8_t inb(uint16_t port) {
    uint8_t v; __asm__ volatile ("inb %1, %0" : "=a"(v) : "Nd"(port)); return v;
}

/* ---- serial (COM1) --------------------------------------------------------- */
#define COM1      0x3F8
#define COM1_LSR  (COM1 + 5)
#define LSR_THRE  0x20            /* transmitter holding register empty */
static void ser_putc(char c) {
    while (!(inb(COM1_LSR) & LSR_THRE)) { }   /* wait for the UART to drain */
    outb(COM1, (uint8_t)c);
}

/* ---- VGA text framebuffer -------------------------------------------------- */
#define VGA_PADDR  0xB8000UL
#define VGA_VADDR  0xB8000UL      /* identity-map the framebuffer into the user half */
#define VGA_CELLS  (80 * 50)
#define VGA_ATTR   0x07           /* light-grey on black */
static volatile uint16_t *const vga = (volatile uint16_t *)VGA_VADDR;
static unsigned vga_pos = 0;

static void vga_putc(char c) {
    if (c == '\n') {
        vga_pos = (vga_pos / 80 + 1) * 80;
    } else if (c == '\r') {
        vga_pos = (vga_pos / 80) * 80;
    } else {
        vga[vga_pos++] = (uint16_t)((VGA_ATTR << 8) | (uint8_t)c);
    }
    if (vga_pos >= VGA_CELLS) vga_pos = 0;    /* wrap (no scroll in this first slice) */
}

/* Emit one console byte to both outputs, expanding \n to \r\n on serial. */
static void con_putc(char c) {
    if (c == '\n') ser_putc('\r');
    ser_putc(c);
    vga_putc(c);
}
static void con_write(const uint8_t *data, unsigned len) {
    for (unsigned i = 0; i < len; i++) con_putc((char)data[i]);
}
static void ser_puts(const char *s) { while (*s) con_putc(*s++); }

/* ---- input ----------------------------------------------------------------- */
/* Read one console character. Serial RX is polled (the COM1 line-status data-ready
 * bit, then the data register) exactly as the in-kernel console_getc does — this
 * is what the headless system and the tests drive. When nothing is ready we yield
 * the CPU rather than busy-spin, so the (preemptible, ring-3) wait does not starve
 * the rest of the system the way the old unpreemptible ring-0 console read did.
 *
 * Keyboard (PS/2) input stays with the kernel for now; moving it here needs the
 * IRQ->notification bridge wired so the kernel stops draining the controller
 * (a follow-up). See docs/proposals/console-server.md. */
static char con_getc(void) {
    for (;;) {
        if (inb(COM1_LSR) & 0x01)          /* serial receive-data-ready */
            return (char)inb(COM1);
        sys_yield();
    }
}

/* Read one line from the console: echo as typed, handle backspace, stop at Enter.
 * `mask` masks the echo with '*' for password entry. Mirrors the kernel's
 * h_get_line / h_get_pass so behaviour (and the session tests) are unchanged.
 * Returns the line length; `out` is NUL-terminated. */
static int con_getline(uint8_t *out, unsigned max, int mask) {
    if (max > CON_LINE_MAX - 1) max = CON_LINE_MAX - 1;
    unsigned len = 0;
    for (;;) {
        char ch = con_getc();
        if (ch == '\r' || ch == '\n') { con_putc('\n'); break; }
        if (ch == '\b' || ch == 0x7F) {            /* backspace */
            if (len > 0) { len--; ser_puts("\b \b"); }
            continue;
        }
        if ((unsigned char)ch < 32) continue;      /* ignore other control chars */
        if (len >= max) continue;                  /* line full: drop extra input */
        con_putc(mask ? '*' : ch);
        out[len++] = (uint8_t)ch;
    }
    out[len] = 0;
    return (int)len;
}

/* ---- helpers --------------------------------------------------------------- */
static void kput(const char *s) { unsigned n = 0; while (s[n]) n++; sys_write(1, s, n); }
static void umemset(void *d, int v, unsigned n) { uint8_t *p = d; while (n--) *p++ = (uint8_t)v; }

void _start(void) {
    /* Take native port I/O first — everything below (serial, VGA registers) needs
     * it. If it is refused we have no console of our own; report via the kernel
     * console (the only path left) and park. */
    if (sys_ioport_grant() != 0) { kput("CONSOLE_SELFTEST: FAIL grant\n"); for (;;) sys_yield(); }

    /* Map the VGA text framebuffer (two 4 KiB frames: an 80x50 buffer is 8000
     * bytes) into our own address space. */
    if (sys_map_phys(VGA_PADDR,          VGA_VADDR,          4096, MAP_PHYS_WRITE) != 0 ||
        sys_map_phys(VGA_PADDR + 0x1000, VGA_VADDR + 0x1000, 4096, MAP_PHYS_WRITE) != 0) {
        kput("CONSOLE_SELFTEST: FAIL map\n"); for (;;) sys_yield();
    }
    /* Prove the mapping is the real framebuffer: write + read back the last cell
     * (it is in the second mapped frame). */
    vga[VGA_CELLS - 1] = (uint16_t)((VGA_ATTR << 8) | '.');
    if (vga[VGA_CELLS - 1] != (uint16_t)((VGA_ATTR << 8) | '.')) {
        kput("CONSOLE_SELFTEST: FAIL vga\n"); for (;;) sys_yield();
    }

    /* From here on the console output is ours, produced entirely in ring 3. */
    ser_puts("[console_server] ready (ring-3; owns serial + VGA framebuffer)\n");

    struct con_request  rq;
    struct con_response rp;
    for (;;) {
        int r = sys_ipc_recv(CON_EP_REQ, (char *)&rq, sizeof(rq));
        if (r < 0) { sys_yield(); continue; }          /* no request yet: yield the CPU
                                                        * (don't busy-spin — a second
                                                        * busy-spin server alongside
                                                        * fs_server starves the shell
                                                        * under emulation) */

        umemset(&rp, 0, sizeof(rp));
        rp.magic = CON_PROTO_MAGIC;
        int was_pass = 0;
        if (rq.magic != CON_PROTO_MAGIC) {
            rp.rc = -1;
        } else if (rq.op == CON_OP_WRITE) {
            unsigned n = rq.len; if (n > CON_IO_MAX) n = CON_IO_MAX;
            con_write(rq.data, n);                    /* <-- ring-3 drives the hardware */
            rp.rc = (int)n;
        } else if (rq.op == CON_OP_GETLINE) {
            rp.rc = con_getline(rp.data, rq.len ? rq.len : (CON_LINE_MAX - 1), 0);
        } else if (rq.op == CON_OP_GETPASS) {
            rp.rc = con_getline(rp.data, rq.len ? rq.len : (CON_LINE_MAX - 1), 1);
            was_pass = 1;
        } else {
            rp.rc = -1;
        }
        /* Reply to THIS request's sender by kernel-recorded identity; retry on a
         * transient "client still blocking" race, before the next recv. */
        while (sys_ipc_reply_to(CON_EP_REQ, (const char *)&rp, sizeof(rp)) < 0) sys_yield();
        /* Do not let a just-read password linger in the reply buffer between
         * requests (it was already delivered to the caller). */
        if (was_pass) umemset(rp.data, 0, sizeof(rp.data));
    }
}
