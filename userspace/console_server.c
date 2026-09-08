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
 * becoming the default. See docs/design/console-server.md and include/console_proto.h.
 */

#include "syscall.h"
#include "console_proto.h"
#include "libhorus.h"
#include "console_font.h"   /* the same glyphs the kernel blits */

/* How many times to retry the startup SYS_IOPORT_GRANT while init finishes
 * endowing us with CAP_IO_DEVICE (see _start). Each attempt yields, so this is a
 * bounded wait for a capability that is on its way, not a spin: generous enough
 * to cover init's remaining startup on a loaded multi-core boot, finite so a
 * genuinely unauthorised server still fails closed rather than hanging. */
#define CON_GRANT_RETRIES 1000

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

/* light-grey on black: the attribute BOTH displays render, hoisted above the
 * two blocks that use it so neither has a private idea of the default. */
#define VGA_ATTR   0x07

/* ---- The linear framebuffer ------------------------------------------------
 *
 * The same 80x50 cell grid the VGA text path drives, rendered as pixels. On a
 * machine with no legacy text window -- a UEFI boot with no CSM, which is what
 * the target hardware does -- this is the only display there is, and without it
 * ring 3 is blind: the kernel draws its boot log and the shell reaches nobody.
 *
 * THE ADDRESS AND THE SHAPE COME FROM DIFFERENT PLACES, deliberately. Where the
 * framebuffer is comes from SYS_DEVICE_INFO's mmio[] ranges; what shape it is
 * comes from SYS_FB_INFO. One fact, one source: two syscalls reporting the same
 * address is the arrangement that lets a display be mapped at one and drawn at
 * another, and that write lands in whatever else is there.
 *
 * ONE MAP CALL PER PAGE, and 3 MiB is 768 of them. That is ~1.5 ms once at
 * start-up, which is not worth a batching syscall and the ABI surface it would
 * add; if a 4K panel ever makes it 8000 calls, that is the moment to reconsider.
 *
 * THE FONT IS include/console_font.h, the same table the kernel blits and uploads
 * into the VGA font plane. Two copies of a font are two things that can disagree
 * about what a character looks like, and nothing notices until somebody reads a
 * screen.
 *
 * WRAP, NOT SCROLL, matching the VGA text path beside it exactly. That path has
 * never scrolled either (see vga_putc), so this is parity rather than a new
 * limitation, and fixing both is one change to make once rather than two
 * behaviours to keep in step. */
#define FB_VADDR   0x0000000100000000ULL   /* 4 GiB: clear of image/heap/stack */

static volatile uint32_t *fbp;      /* 0 until mapped */
static uint32_t fb_pitch_px, fb_w, fb_h, fb_scale = 1;
static uint16_t fb_cells[80 * 50];
static unsigned fb_pos;

/* The VGA 16-colour text palette as 0x00RRGGBB -- the levels a VGA DAC actually
 * produces, which is why they are written out rather than computed from a rule
 * that would merely look principled. */
static const uint32_t fb_pal[16] = {
    0x000000, 0x0000AA, 0x00AA00, 0x00AAAA,
    0xAA0000, 0xAA00AA, 0xAA5500, 0xAAAAAA,
    0x555555, 0x5555FF, 0x55FF55, 0x55FFFF,
    0xFF5555, 0xFF55FF, 0xFFFF55, 0xFFFFFF,
};

/* Paint one cell. Bounds-checked against the real geometry rather than the grid:
 * the grid is what this server believes and the geometry is what the hardware
 * has, and a mismatch must clip rather than scribble past the mapping. */
static void fb_blit(unsigned idx) {
    if (!fbp || idx >= 80u * 50u) return;
    uint16_t cell = fb_cells[idx];
    uint8_t ch = (uint8_t)(cell & 0xFF), attr = (uint8_t)(cell >> 8);
    uint32_t fg = fb_pal[attr & 0x0F], bg = fb_pal[(attr >> 4) & 0x07];

    uint32_t cw = 8u * fb_scale, chh = 8u * fb_scale;
    uint32_t px0 = (idx % 80u) * cw, py0 = (idx / 80u) * chh;
    if (px0 + cw > fb_w || py0 + chh > fb_h) return;

    const uint8_t *g = &font_8x8[ch][0];
    for (uint32_t ry = 0; ry < chh; ry++) {
        uint8_t bits = g[ry / fb_scale];
        volatile uint32_t *row = fbp + (uint64_t)(py0 + ry) * fb_pitch_px + px0;
        for (uint32_t rx = 0; rx < cw; rx++)
            row[rx] = (bits & (0x80u >> (rx / fb_scale))) ? fg : bg;
    }
}

static void fb_putc(char c) {
    if (c == '\n')      fb_pos = (fb_pos / 80 + 1) * 80;
    else if (c == '\r') fb_pos = (fb_pos / 80) * 80;
    else {
        fb_cells[fb_pos] = (uint16_t)((VGA_ATTR << 8) | (uint8_t)c);
        fb_blit(fb_pos);
        fb_pos++;
    }
    if (fb_pos >= 80u * 50u) fb_pos = 0;    /* wrap, exactly as vga_putc does */
}

/* ---- VGA text framebuffer -------------------------------------------------- */
#define VGA_PADDR  0xB8000UL
#define VGA_VADDR  0xB8000UL      /* identity-map the framebuffer into the user half */
#define VGA_CELLS  (80 * 50)
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

/* ---- the timestamped boot log, continued in ring 3 --------------------------
 *
 * The kernel puts "[    S.uuuuuu] " in front of every line it accepts
 * (print_core in src/kernel/terminal.c). The console changes hands part way
 * through the boot -- the moment we map the VGA framebuffer, the kernel stops
 * driving the hardware -- and everything after that point arrives here instead.
 * If only the kernel stamped, the boot log would lose its timestamps at an
 * instant nothing in the log marks, and WHICH LINES lost them would depend on
 * scheduling: `init: console_server launched` is written by init on another CPU
 * and lands on either side of our SYS_MAP_PHYS from one boot to the next. A
 * format that is decided by a race is not a format.
 *
 * So the server stamps too, in the same shape, from the only clock ring 3 has
 * (see hstamp() in libhorus.c for why that clock is coarse and why that is the
 * right trade). It stops when init says the boot log is over -- CON_OP_BOOT_DONE
 * -- or when anyone reads from the console, whichever comes first.
 *
 * WHY THIS CANNOT BE SPLIT. The 2.6a hazard is a marker emitted as two writes
 * with another writer's output landing between them. Here the prefix and the
 * line it belongs to are emitted by ONE task in ONE pass of con_putc, and after
 * the handover this task is the only writer of the UART -- that is the whole
 * point of the handover (finding #126). Nothing schedulable can get between
 * them: a client's next CON_OP_WRITE cannot be served until this one returns.
 * (kfault_str/panic_ch still bypass every lock in the system by design; that is
 * 2.6c and is neither improved nor worsened here.) */
#ifdef CONSOLE_TIMESTAMPS_LEGACY
/* CONTROL ARM -- never ship. The pre-2026-09-06 console: no line is stamped on
 * either side of the handover. Its kernel half is in src/kernel/terminal.c; one
 * flag sets both because the claim being falsified spans both rings (a boot log
 * whose every line is timestamped), and an arm that removed only one half would
 * leave the other half's lines stamped and pass for half the right reason. */
static int con_stamping = 0;
#else
static int con_stamping = 1;      /* until CON_OP_BOOT_DONE, or the first read */
#endif
static int con_line_start = 1;

/* One byte to both outputs, expanding \n to \r\n on serial. No stamping: this is
 * what the prefix itself is written with. */
static void con_emit(char c) {
    if (c == '\n') ser_putc('\r');
    ser_putc(c);
    /* Whichever display this machine has. On a framebuffer the VGA text window
     * does not exist, and writing to it would be a store into a mapping that is
     * not a display -- silent, and the screen stays black. */
    if (fbp) fb_putc(c);
    else     vga_putc(c);
}

/* Emit one console byte, opening each line with a timestamp while the console is
 * still a boot log. A '\n' at the start of a line stays a blank line -- a bare
 * prefix on an empty row is noise, and the gate skips blank lines for the same
 * reason. Control bytes (the '\b' of a backspace echo) never open a line. */
static void con_putc(char c) {
    if (con_stamping && con_line_start && ((unsigned char)c >= ' ' || c == '\t')) {
        char st[HSTAMP_MAX];
        unsigned n = hstamp(st);
        for (unsigned i = 0; i < n; i++) con_emit(st[i]);
        con_line_start = 0;
    }
    if (c == '\n') con_line_start = 1;
    else if ((unsigned char)c >= ' ' || c == '\t') con_line_start = 0;
    con_emit(c);
}
static void con_write(const uint8_t *data, unsigned len) {
    for (unsigned i = 0; i < len; i++) con_putc((char)data[i]);
}
static void ser_puts(const char *s) { while (*s) con_putc(*s++); }

/* A decimal, straight to the console this server drives.
 *
 * NOT kput. kput goes to fd 1, and from the instant this server's first map of
 * a display succeeds the kernel has handed it the console -- so a kput from
 * HERE reaches the kernel log ring and nothing else. That is the same silence
 * `sys_console_release` exists for, and it swallowed the framebuffer report on
 * its first run: the line was written, and no gate could ever have seen it. */
static void ser_u32(uint32_t v) {
    char b[11]; int n = 0;
    if (!v) { con_putc('0'); return; }
    while (v) { b[n++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (n) con_putc(b[--n]);
}

/* ---- input ----------------------------------------------------------------- */
/* Read one console character. Serial RX is polled (the COM1 line-status data-ready
 * bit, then the data register) exactly as the in-kernel console_getc does — this
 * is what the headless system and the tests drive. When nothing is ready we yield
 * the CPU rather than busy-spin, so the (preemptible, ring-3) wait does not starve
 * the rest of the system the way the old unpreemptible ring-0 console read did.
 *
 * Keyboard (PS/2) input stays with the kernel for now; moving it here needs the
 * IRQ->notification bridge wired so the kernel stops draining the controller
 * (a follow-up). See docs/design/console-server.md. */
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
    con_stamping = 0;          /* someone is typing at it: it is a terminal now */
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

/* ---- raw ("full-screen") terminal mode ------------------------------------- */
/* Read raw key bytes: block for the first, then drain the rest of the burst that
 * is already sitting in the UART, so a multi-byte key (an arrow is ESC '[' 'A')
 * comes back in one reply and a curses program can decode it without a timer. No
 * echo and no line editing — the program owns the screen. */
static int con_read_raw(uint8_t *out, unsigned max) {
    con_stamping = 0;          /* same backstop as con_getline */
    if (max == 0) return 0;
    if (max > CON_LINE_MAX) max = CON_LINE_MAX;
    unsigned n = 0;
    out[n++] = (uint8_t)con_getc();                 /* block for at least one byte */
    while (n < max && (inb(COM1_LSR) & 0x01))        /* grab the rest of the burst */
        out[n++] = inb(COM1);
    return (int)n;
}

/* Emit bytes verbatim to the serial terminal — no '\n'->'\r\n' translation, since
 * a full-screen app manages its own line endings and cursor escapes. Serial only:
 * the interactive VT terminal is on the serial line, and passing escape bytes to
 * the VGA text grid would just render them as glyphs (VGA is not the surface a
 * curses app targets, and `make run` runs with -display none). */
static void con_write_raw(const uint8_t *data, unsigned len) {
    for (unsigned i = 0; i < len; i++) ser_putc((char)data[i]);
}

/* ---- helpers --------------------------------------------------------------- */

#ifdef CONSOLE_ISOLATION_TEST
/* Blast-radius proof (Phase 6 close-out). The console driver used to run in ring 0,
 * where a bug had the same reach as one in the capability system. Now that it is a
 * ring-3 server, a fault in it is just a ring-3 fault: the kernel delivers it to
 * this handler (or, with none, tears down only this task) and keeps running -- it
 * cannot reach kernel memory or the capability system. Deliberately fault to show
 * that concretely. The PASS marker is written through the kernel console because
 * the whole point is that the kernel is still alive to print it. */
static void con_isolation_handler(void) {
    kput("CONSOLE_ISOLATION: PASS (console driver fault contained in ring 3)\n");
    sys_exit();
}
static void con_isolation_fault(void) {
    if (sys_signal((uintptr_t)&con_isolation_handler) != 0) {
        kput("CONSOLE_ISOLATION: FAIL register\n"); sys_exit();
    }
    kput("CONSOLE_ISOLATION: console_server faulting on purpose...\n");
    *(volatile int *)0 = 0;   /* NULL write -> #PF -> delivered to the handler at ring 3 */
    kput("CONSOLE_ISOLATION: FAIL not-faulted\n"); sys_exit();
}
#endif

void _start(void) {
    /* Take native port I/O first — everything below (serial, VGA registers) needs
     * it.
     *
     * Retry rather than give up on the first refusal. `init` spawns us and only
     * THEN grants us CAP_IO_DEVICE (SYS_SPAWN makes the child runnable
     * immediately, and the two SYS_CAP_GRANTs follow), so with SMP we can reach
     * this line on another core *before* the grant lands and be refused for a
     * capability we are about to be given. On one core the grants always precede
     * our first run, which is why this only ever surfaced as an intermittent
     * multi-core boot hang: we parked forever, nothing drove the console, and the
     * boot timed out before the shell banner.
     *
     * Yielding between attempts lets init run and finish endowing us. This waits
     * for authority to *arrive*; it never widens it — the kernel's CAP_IO_DEVICE
     * check is unchanged, and after the bound we fail closed exactly as before.
     * Because init grants the IPC gate (slot 3) before CAP_IO_DEVICE (slot 10),
     * seeing the port grant succeed also means the gate is already in place. */
    int granted = 0;
    for (int attempt = 0; attempt < CON_GRANT_RETRIES; attempt++) {
        if (sys_ioport_grant(CAPSLOT_IO_DEVICE) == 0) { granted = 1; break; }
        sys_yield();
    }
    if (!granted) { kput("CONSOLE_SELFTEST: FAIL grant\n"); for (;;) sys_yield(); }

    /* WHAT KIND OF DISPLAY THIS MACHINE HAS, asked before anything is mapped.
     *
     * Reported and not yet acted on: this server still drives the VGA text
     * window below, and teaching it to blit pixels is the next change. The call
     * is here now because it is what makes that change possible -- a driver
     * cannot render into a framebuffer whose width, height, pitch and depth it
     * has no way to learn, and until this syscall there was no way.
     *
     * SYS_ERR_NOENT is the ordinary answer, not a failure: every machine that
     * booted in EGA text says it, which is all of them by default. So a
     * non-zero return is reported and the server carries on to the VGA path
     * exactly as before -- this line must not be able to break a boot that
     * worked yesterday. */
    {
        struct fb_geometry fbg;
#ifdef CONSOLE_FB_ABSENT
        /* CONTROL ARM -- never ship. console_server as it was before
         * 2026-09-08: it never asks what the display is, so on a machine with
         * no VGA text window it maps one anyway, fails its own round-trip check
         * and parks. The kernel's boot log stays on the screen because nothing
         * in ring 3 ever cleared it, and there is no shell. */
        int frc = -1;
        (void)sys_fb_info;
#else
        int frc = sys_fb_info(CAPSLOT_IO_DEVICE, &fbg);
#endif
        if (frc != 0) {
            kput("CONSOLE_FB: no linear framebuffer; the VGA text window it is\n");
        } else if (fbg.bpp != 32) {
            /* REFUSED, NOT APPROXIMATED. 24bpp needs a byte-wise store and
             * 15/16bpp needs channel packing; each is a different blitter, and
             * on a machine with no serial port a console that draws WRONG is
             * harder to diagnose than one that says it did not start. */
            kput("CONSOLE_FB: unsupported pixel depth; the VGA text window it is\n");
        } else {
            /* WHERE it is comes from the device's own MMIO ranges -- the
             * framebuffer is the range that is neither VGA window. Reading the
             * address from the device rather than from SYS_FB_INFO is what keeps
             * one fact to one source; see the note above the blitter. */
            struct dev_info di;
            uint64_t base = 0, len = 0;
            if (sys_device_info(CAPSLOT_IO_DEVICE, &di) == 0) {
                for (unsigned i = 0; i < di.n_mmio; i++) {
                    if (di.mmio[i].base == 0xA0000ULL || di.mmio[i].base == 0xB8000ULL) continue;
                    base = di.mmio[i].base; len = di.mmio[i].len; break;
                }
            }
            if (base == 0) {
                kput("CONSOLE_FB: FAIL the platform device declares no framebuffer range\n");
            } else {
                uint64_t need = (uint64_t)fbg.height * fbg.pitch;
                if (need > len) need = len;         /* never map past what is declared */
                unsigned pages = (unsigned)((need + 4095) / 4096), mapped = 0;
                for (unsigned i = 0; i < pages; i++) {
                    if (sys_map_phys(CAPSLOT_IO_DEVICE, base + (uint64_t)i * 4096,
                                     FB_VADDR + (uint64_t)i * 4096, 4096,
                                     MAP_PHYS_WRITE) != 0) break;
                    mapped++;
                }
                if (mapped != pages) {
                    /* A partial map may already have taken the console, exactly
                     * as the VGA path's does. Hand it back before reporting, or
                     * the marker reaches the klog and nothing else. */
                    sys_console_release(CAPSLOT_IO_DEVICE);
                    ser_puts("CONSOLE_FB: FAIL map\n");
                } else {
                    fbp = (volatile uint32_t *)(uintptr_t)FB_VADDR;
                    fb_pitch_px = fbg.pitch / 4u;
                    fb_w = fbg.width; fb_h = fbg.height;
                    fb_scale = (fbg.width >= 1600u) ? 2u : 1u;
                    if (fbg.width < 80u * 8u * fb_scale || fbg.height < 50u * 8u * fb_scale)
                        fb_scale = 1u;
                    for (unsigned i = 0; i < 80u * 50u; i++)
                        fb_cells[i] = (uint16_t)((VGA_ATTR << 8) | ' ');
                    for (unsigned i = 0; i < 80u * 50u; i++) fb_blit(i);
                    /* ser_puts, not kput: the map above has already taken the
                     * console, so a kput here is written into the kernel log
                     * ring and is heard by nobody -- which is what happened on
                     * this line's first run. */
                    ser_puts("CONSOLE_FB: linear framebuffer ");
                    ser_u32(fbg.width); ser_puts("x"); ser_u32(fbg.height);
                    ser_puts("x"); ser_u32(fbg.bpp);
                    ser_puts(" pitch "); ser_u32(fbg.pitch);
                    ser_puts(" scale "); ser_u32(fb_scale); ser_puts("\n");
                }
            }
        }
    }

    /* Map the VGA text framebuffer (two 4 KiB frames: an 80x50 buffer is 8000
     * bytes) into our own address space. */
    if (sys_map_phys(CAPSLOT_IO_DEVICE, VGA_PADDR,          VGA_VADDR,          4096, MAP_PHYS_WRITE) != 0 ||
        sys_map_phys(CAPSLOT_IO_DEVICE, VGA_PADDR + 0x1000, VGA_VADDR + 0x1000, 4096, MAP_PHYS_WRITE) != 0) {
        /* A partial map may already have taken the console -- ownership is
         * granted on the FIRST successful VGA map, so the second call failing
         * leaves us owning a console we cannot drive. Hand it back before
         * reporting, or this marker reaches the klog and nothing else. */
        sys_console_release(CAPSLOT_IO_DEVICE);
        kput("CONSOLE_SELFTEST: FAIL map\n"); for (;;) sys_yield();
    }
    /* Prove the mapping is the real framebuffer: write + read back the last cell
     * (it is in the second mapped frame).
     *
     * SKIPPED ON A PIXEL DISPLAY, where there is no text window to round-trip
     * and the check would fail on a console that is working perfectly. That is
     * not hypothetical: it is exactly what `CONSOLE_SELFTEST: FAIL vga` was on
     * every framebuffer boot before this, a correct check asked the wrong
     * question. The framebuffer's own proof is that its pixels are on the
     * screen, which `make smoke-fb-console-server` checks by looking at them. */
    if (fbp) goto display_ready;
    vga[VGA_CELLS - 1] = (uint16_t)((VGA_ATTR << 8) | '.');
#ifdef CONSOLE_VGA_CHECK_FAIL
    /* Control arm: force the round-trip to fail without touching the hardware,
     * which is what a firmware-set graphics mode does to the legacy text window.
     * See make smoke-console-handover. */
    if (1) {
#else
    if (vga[VGA_CELLS - 1] != (uint16_t)((VGA_ATTR << 8) | '.')) {
#endif
        /* THE MAP ABOVE ALREADY TOOK THE CONSOLE. Without handing it back this
         * marker goes to the kernel log ring and nowhere else, and the machine
         * shows nothing at all -- which is exactly what a framebuffer-mode boot
         * looked like on 2026-09-07, undiagnosable from the wire. */
        sys_console_release(CAPSLOT_IO_DEVICE);
        kput("CONSOLE_SELFTEST: FAIL vga\n"); for (;;) sys_yield();
    }

display_ready:
    /* From here on the console output is ours, produced entirely in ring 3. */
    ser_puts(fbp ? "[console_server] ready (ring-3; owns serial + a linear framebuffer)\n"
                 : "[console_server] ready (ring-3; owns serial + VGA framebuffer)\n");

#ifdef KDIAG_RING3_PROBE
    /* Test-only, and it is the whole of the authority pair.
     *
     * COM3 (0x3E8) is the kernel's diagnostic channel, and what keeps ring 3 out
     * of it is one thing only: src/kernel/pci.c does not declare the port among
     * the platform device's, so the SYS_IOPORT_GRANT above never opens the TSS
     * I/O bitmap for it. That is a sentence about a file, and a sentence about a
     * file is exactly the kind of security claim that goes untested until it
     * stops being true.
     *
     * So the write is ATTEMPTED in both directions, and the flag that moves is
     * the kernel's. With KDIAG_PORTS_GRANTABLE the port is declared, our
     * existing grant covers it with no new syscall and no new capability, and
     * the sentinel lands in the kernel's channel. Without it the same
     * instruction faults. Attempting it in both is the difference between "ring
     * 3 did not write the channel" and "ring 3 CANNOT" -- only the second is a
     * property, and only the second is what SECURITY.md is allowed to say.
     *
     * A sentinel rather than a count of shredded markers, deliberately: the
     * question is "did ring 3 REACH the channel", and a string ring 3 wrote
     * answers it with no arithmetic and no assumption about how a split
     * scores. */
    for (int i = 0; i < 200; i++) {
        const char *p = "KDIAGRING3";
        while (*p) { outb(0x3E8, (uint8_t)*p); p++; }
    }
#endif

#ifdef CONSOLE_ISOLATION_TEST
    con_isolation_fault();   /* prove a console-driver fault stays contained in ring 3 */
#endif

    struct con_request  rq;
    struct con_response rp;
    for (;;) {
        /* Sleep until a request arrives (roadmap 1.3). This used to be a
         * non-blocking recv plus sys_yield(), with a comment explaining that a
         * second busy-spin server alongside fs_server starves the shell under
         * emulation. That comment was describing this item: the yield stopped the
         * spin from being tight, but the server was still RUNNABLE at every
         * scheduling decision, competing for turns it had no work to do with.
         * Blocking removes it from the run queue entirely.
         *
         * A negative return is PERMANENT here -- SYS_IPC_RECV_BLOCK never returns
         * IPC_AGAIN, so there is nothing transient to retry. Looping on it would
         * be exactly the G-8 wedge: an authority refusal turned into a silent
         * infinite loop. The only way to get one is to lose the listen
         * capability, which a console server cannot continue without, so say so
         * and exit rather than spin invisibly. */
        int r = sys_ipc_recv_block(CAPSLOT_CONSOLE_EP, (char *)&rq, sizeof(rq));
        if (r < 0) {
            ser_puts("[console_server] listen capability lost; exiting\n");
            sys_exit();
        }

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
        } else if (rq.op == CON_OP_READ_RAW) {
            rp.rc = con_read_raw(rp.data, rq.len ? rq.len : (CON_LINE_MAX - 1));
        } else if (rq.op == CON_OP_WRITE_RAW) {
            unsigned n = rq.len; if (n > CON_IO_MAX) n = CON_IO_MAX;
            con_write_raw(rq.data, n);
            rp.rc = (int)n;
        } else if (rq.op == CON_OP_WINSZ) {
            rp.rc = (CON_ROWS << 16) | CON_COLS;
        } else if (rq.op == CON_OP_BOOT_DONE) {
            /* The boot log ends and the session begins: stop stamping. Idempotent
             * on purpose -- init sends it once, but a second sender costs nothing
             * and a server that refused the repeat would be a wedge waiting for
             * an init that retries a transient IPC failure. */
            con_stamping = 0;
            rp.rc = 0;
        } else {
            rp.rc = -1;
        }
        /* Reply to THIS request's sender by kernel-recorded identity; retry on the
         * transient "client still blocking" race ONLY. A permanent refusal must
         * not be spun on — the console server wedging silently takes the console
         * with it. See the IPC retry contract in syscall.h (finding G-8). */
        {
            unsigned tries = 0;
            int rr;
            while ((rr = sys_ipc_reply_to(CAPSLOT_CONSOLE_EP, (const char *)&rp, sizeof(rp))) < 0) {
                if (!ipc_transient(rr)) break;          /* permanent: drop the reply */
                if (++tries > 2000000u) break;          /* transient, but not forever */
                sys_yield();
            }
        }
        /* Do not let a just-read password linger in the reply buffer between
         * requests (it was already delivered to the caller). */
        if (was_pass) umemset(rp.data, 0, sizeof(rp.data));
    }
}
