#include "kernel.h"

/* VGA text buffer at physical 0xB8000, reached through the higher-half alias.
 * Not the raw low address: the kernel prints from syscall context, i.e. while
 * running on the faulting task's CR3, and PHYS_KVA is the mapping guaranteed to
 * exist in every address space. The low identity map happens to resolve it today
 * only because create_user_pagedir still replicates low memory into each task. */
static volatile uint16_t* const VIDEO_MEMORY = (uint16_t*)PHYS_KVA(0xB8000);
static int cursor_x = 0;
static int cursor_y = 0;

#define VGA_COLS 80
#define VGA_ROWS 50

static uint8_t current_attr = 0x0F;
static uint8_t last_serial_attr = 0x0F;

static char klog_buf[16384];
static uint32_t klog_head = 0;
static uint32_t klog_len = 0;

static void klog_append(char c) {
    klog_buf[klog_head] = c;
    klog_head = (klog_head + 1) % sizeof(klog_buf);
    if (klog_len < sizeof(klog_buf)) klog_len++;
}

/* Copy up to `max` bytes of the kernel message ring, starting at logical byte
 * `offset` from the oldest retained byte, into the kernel buffer `dst`. Returns
 * the number of bytes copied (0 at/after the end). Backs SYS_DMESG, which reads
 * the log in small chunks so a caller never needs a multi-KiB user buffer. */
uint32_t klog_copy(char *dst, uint32_t offset, uint32_t max) {
    if (offset >= klog_len) return 0;
    uint32_t avail = klog_len - offset;
    uint32_t n = avail < max ? avail : max;
    uint32_t oldest = (klog_head + (uint32_t)sizeof(klog_buf) - klog_len) % (uint32_t)sizeof(klog_buf);
    uint32_t start = (oldest + offset) % (uint32_t)sizeof(klog_buf);
    for (uint32_t i = 0; i < n; i++) {
        dst[i] = klog_buf[(start + i) % (uint32_t)sizeof(klog_buf)];
    }
    return n;
}

/* ---- console mutual exclusion + hardware ownership -------------------------
 *
 * print() drives shared state (cursor, colour, klog) and, when the kernel owns
 * the console, the COM1 FIFO + VGA text buffer. Two things break once SMP is the
 * default and more than one CPU runs at once:
 *
 *   1. Two CPUs can be inside print() simultaneously — a kernel log on the BSP
 *      vs. a ring-3 task's SYS_WRITE on an AP — and interleave their bytes
 *      character by character. A leaf spinlock makes each print()/clear_screen()
 *      atomic across CPUs.
 *
 *   2. Once the ring-3 console_server takes native port I/O over the console
 *      (SYS_IOPORT_GRANT), it drives the SAME UART + VGA buffer with its own
 *      hands. A kernel lock cannot reach a ring-3 writer, so the only way to keep
 *      the console single-writer is for the kernel to stop touching the hardware
 *      while a ring-3 owner exists. It still records every byte to klog, so the
 *      kernel log and panic dumps stay complete; ownership is released if the
 *      owner dies (task_teardown), so the shell's in-kernel console fallback
 *      keeps login working even if the server crashes.
 *
 * The lock saves/restores IF locally instead of using spin_lock()'s global
 * irq-depth counter: print() is reached from interrupt and exception context, so
 * releasing must not unconditionally re-enable interrupts, and must not perturb a
 * caller that already holds an IF-clearing lock. */
static volatile uint32_t console_lock = 0;
static volatile int console_owner_task = 0;   /* ring-3 task driving the console HW; 0 => kernel drives it */

static uint64_t console_lock_acquire(void) {
    uint64_t rflags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(rflags) :: "memory");
    __asm__ volatile ("cli" ::: "memory");
    while (__sync_lock_test_and_set(&console_lock, 1))
        while (console_lock) __asm__ volatile ("pause" ::: "memory");
    return rflags;
}
static void console_lock_release(uint64_t rflags) {
    __sync_lock_release(&console_lock);
    if (rflags & (1ull << 9))          /* only re-enable IF if the caller had it set */
        __asm__ volatile ("sti" ::: "memory");
}

/* A ring-3 task took native port I/O over the console (SYS_IOPORT_GRANT): it now
 * owns the hardware, so the kernel stops driving serial + VGA. */
void console_set_owner(int tid) { console_owner_task = tid; }

/* The owning task died (task_teardown): reclaim the console for the kernel so the
 * in-kernel print()/console fallback works again. No-op if `tid` was not the owner. */
void console_clear_owner(int tid) { if (console_owner_task == tid) console_owner_task = 0; }

/* True while a ring-3 console server owns the hardware. The kernel's own console
 * input path (console_getc and the SYS_GET_LINE/SYS_GET_PASS/SYS_READ handlers)
 * fails closed when this holds: the owner is the sole reader of the serial UART,
 * so a kernel-side read would race it byte-for-byte and split a typed line. */
int console_hw_owned(void) { return console_owner_task != 0; }

/* Is THIS task the owner? Asked by SYS_CONSOLE_RELEASE, which must refuse a
 * caller that holds the device capability but not the console -- otherwise one
 * task could mute another's display by handing back a console it never took. */
int console_owner_is(int tid) { return console_owner_task != 0 && console_owner_task == tid; }

static const uint8_t font_8x8[256][8] = {
     ['!'] = {0x00,0x10,0x10,0x10,0x10,0x00,0x10,0x00},
     ['"'] = {0x00,0x28,0x28,0x00,0x00,0x00,0x00,0x00},
     ['#'] = {0x00,0x28,0x28,0x7C,0x28,0x7C,0x28,0x00},
     ['$'] = {0x10,0x3C,0x50,0x38,0x14,0x78,0x10,0x00},
     ['%'] = {0x00,0x44,0x48,0x10,0x20,0x44,0x08,0x00},
     ['&'] = {0x00,0x30,0x48,0x50,0x20,0x54,0x48,0x34},
     ['\''] = {0x00,0x10,0x10,0x00,0x00,0x00,0x00,0x00},
     ['('] = {0x00,0x0C,0x10,0x10,0x10,0x10,0x0C,0x00},
     [')'] = {0x00,0x30,0x08,0x08,0x08,0x08,0x30,0x00},
     ['*'] = {0x00,0x44,0x28,0x7C,0x28,0x44,0x00,0x00},
     ['+'] = {0x00,0x00,0x10,0x10,0x7C,0x10,0x10,0x00},
     [','] = {0x00,0x00,0x00,0x00,0x00,0x18,0x20,0x00},
     ['-'] = {0x00,0x00,0x00,0x7C,0x00,0x00,0x00,0x00},
     ['.'] = {0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00},
     ['/'] = {0x00,0x04,0x08,0x10,0x20,0x40,0x00,0x00},

    
    ['0'] = {0x00,0x38,0x44,0x4C,0x54,0x64,0x38,0x00},
    ['1'] = {0x00,0x10,0x30,0x10,0x10,0x10,0x38,0x00},
    ['2'] = {0x00,0x38,0x44,0x04,0x18,0x20,0x7C,0x00},
    ['3'] = {0x00,0x38,0x44,0x04,0x18,0x44,0x38,0x00},
    ['4'] = {0x00,0x08,0x18,0x28,0x7C,0x08,0x08,0x00},
    ['5'] = {0x00,0x7C,0x40,0x78,0x04,0x44,0x38,0x00},
    ['6'] = {0x00,0x18,0x20,0x40,0x78,0x44,0x38,0x00},
    ['7'] = {0x00,0x7C,0x04,0x08,0x10,0x20,0x20,0x00},
    ['8'] = {0x00,0x38,0x44,0x38,0x44,0x44,0x38,0x00},
    ['9'] = {0x00,0x38,0x44,0x3C,0x04,0x08,0x30,0x00},

    
    [':'] = {0x00,0x00,0x10,0x00,0x00,0x10,0x00,0x00},
    [';'] = {0x00,0x00,0x10,0x00,0x00,0x10,0x20,0x00},
    ['<'] = {0x00,0x00,0x0C,0x30,0x40,0x30,0x0C,0x00},
    ['='] = {0x00,0x00,0x00,0x7C,0x00,0x7C,0x00,0x00},
    ['>'] = {0x00,0x00,0x60,0x18,0x04,0x18,0x60,0x00},
    ['?'] = {0x00,0x38,0x44,0x04,0x18,0x00,0x10,0x00},
    ['@'] = {0x00,0x38,0x44,0x54,0x5C,0x40,0x3C,0x00},

    
    ['A'] = {0x00,0x18,0x24,0x42,0x7E,0x42,0x42,0x00},
    ['B'] = {0x00,0x78,0x44,0x78,0x44,0x44,0x78,0x00},
    ['C'] = {0x00,0x38,0x44,0x40,0x40,0x44,0x38,0x00},
    ['D'] = {0x00,0x78,0x44,0x44,0x44,0x44,0x78,0x00},
    ['E'] = {0x00,0x7C,0x40,0x78,0x40,0x40,0x7C,0x00},
    ['F'] = {0x00,0x7C,0x40,0x78,0x40,0x40,0x40,0x00},
    ['G'] = {0x00,0x38,0x44,0x40,0x5C,0x44,0x38,0x00},
    ['H'] = {0x00,0x44,0x44,0x7C,0x44,0x44,0x44,0x00},
    ['I'] = {0x00,0x38,0x10,0x10,0x10,0x10,0x38,0x00},
    ['J'] = {0x00,0x1C,0x08,0x08,0x08,0x48,0x30,0x00},
    ['K'] = {0x00,0x44,0x48,0x70,0x48,0x44,0x44,0x00},
    ['L'] = {0x00,0x40,0x40,0x40,0x40,0x40,0x7C,0x00},
    ['M'] = {0x00,0x44,0x6C,0x54,0x44,0x44,0x44,0x00},
    ['N'] = {0x00,0x44,0x64,0x54,0x4C,0x44,0x44,0x00},
    ['O'] = {0x00,0x38,0x44,0x44,0x44,0x44,0x38,0x00},
    ['P'] = {0x00,0x78,0x44,0x78,0x40,0x40,0x40,0x00},
    ['Q'] = {0x00,0x38,0x44,0x44,0x54,0x48,0x34,0x00},
    ['R'] = {0x00,0x78,0x44,0x78,0x50,0x48,0x44,0x00},
    ['S'] = {0x00,0x38,0x44,0x30,0x08,0x44,0x38,0x00},
    ['T'] = {0x00,0x7C,0x10,0x10,0x10,0x10,0x10,0x00},
    ['U'] = {0x00,0x44,0x44,0x44,0x44,0x44,0x38,0x00},
    ['V'] = {0x00,0x44,0x44,0x28,0x28,0x10,0x10,0x00},
    ['W'] = {0x00,0x44,0x44,0x54,0x54,0x28,0x28,0x00},
    ['X'] = {0x00,0x44,0x28,0x10,0x10,0x28,0x44,0x00},
    ['Y'] = {0x00,0x44,0x28,0x10,0x10,0x10,0x10,0x00},
    ['Z'] = {0x00,0x7C,0x08,0x10,0x20,0x40,0x7C,0x00},

    
    ['['] = {0x00,0x38,0x20,0x20,0x20,0x20,0x38,0x00},
    ['\\'] = {0x00,0x40,0x20,0x10,0x08,0x04,0x00,0x00},
    [']'] = {0x00,0x38,0x08,0x08,0x08,0x08,0x38,0x00},
    ['^'] = {0x00,0x10,0x28,0x44,0x00,0x00,0x00,0x00},
    ['_'] = {0x00,0x00,0x00,0x00,0x00,0x00,0x7C,0x00},
    ['`'] = {0x00,0x20,0x10,0x00,0x00,0x00,0x00,0x00},

    
    ['a'] = {0x00,0x00,0x38,0x04,0x3C,0x44,0x3C,0x00},
    ['b'] = {0x00,0x40,0x40,0x78,0x44,0x44,0x78,0x00},
    ['c'] = {0x00,0x00,0x38,0x44,0x40,0x44,0x38,0x00},
    ['d'] = {0x00,0x04,0x04,0x3C,0x44,0x44,0x3C,0x00},
    ['e'] = {0x00,0x00,0x38,0x44,0x7C,0x40,0x38,0x00},
    ['f'] = {0x00,0x0C,0x10,0x38,0x10,0x10,0x10,0x00},
    ['g'] = {0x00,0x00,0x3C,0x44,0x44,0x3C,0x04,0x38},
    ['h'] = {0x00,0x40,0x40,0x78,0x44,0x44,0x44,0x00},
    ['i'] = {0x00,0x10,0x00,0x30,0x10,0x10,0x38,0x00},
    ['j'] = {0x00,0x08,0x00,0x18,0x08,0x08,0x48,0x30},
    ['k'] = {0x00,0x40,0x44,0x48,0x70,0x48,0x44,0x00},
    ['l'] = {0x00,0x30,0x10,0x10,0x10,0x10,0x38,0x00},
    ['m'] = {0x00,0x00,0x68,0x54,0x54,0x54,0x54,0x00},
    ['n'] = {0x00,0x00,0x78,0x44,0x44,0x44,0x44,0x00},
    ['o'] = {0x00,0x00,0x38,0x44,0x44,0x44,0x38,0x00},
    ['p'] = {0x00,0x00,0x78,0x44,0x44,0x78,0x40,0x40},
    ['q'] = {0x00,0x00,0x3C,0x44,0x44,0x3C,0x04,0x04},
    ['r'] = {0x00,0x00,0x58,0x64,0x40,0x40,0x40,0x00},
    ['s'] = {0x00,0x00,0x3C,0x40,0x38,0x04,0x78,0x00},
    ['t'] = {0x00,0x20,0x20,0x78,0x20,0x24,0x18,0x00},
    ['u'] = {0x00,0x00,0x44,0x44,0x44,0x44,0x38,0x00},
    ['v'] = {0x00,0x00,0x44,0x44,0x28,0x28,0x10,0x00},
    ['w'] = {0x00,0x00,0x44,0x54,0x54,0x28,0x28,0x00},
    ['x'] = {0x00,0x00,0x44,0x28,0x10,0x28,0x44,0x00},
    ['y'] = {0x00,0x00,0x44,0x44,0x44,0x3C,0x04,0x38},
    ['z'] = {0x00,0x00,0x7C,0x08,0x10,0x20,0x7C,0x00},

    
    ['{'] = {0x00,0x0C,0x10,0x60,0x10,0x10,0x0C,0x00},
    ['|'] = {0x00,0x10,0x10,0x10,0x10,0x10,0x10,0x00},
    ['}'] = {0x00,0x60,0x10,0x0C,0x10,0x10,0x60,0x00},
    ['~'] = {0x00,0x00,0x00,0x34,0x48,0x00,0x00,0x00},
};

static void load_8x8_font(void) {
    
    outb(0x3C4, 0x02); uint8_t seq2 = inb(0x3C5);
    outb(0x3C4, 0x04); uint8_t seq4 = inb(0x3C5);
    outb(0x3CE, 0x04); uint8_t gc4  = inb(0x3CF);
    outb(0x3CE, 0x05); uint8_t gc5  = inb(0x3CF);
    outb(0x3CE, 0x06); uint8_t gc6  = inb(0x3CF);

    
    outb(0x3C4, 0x00); outb(0x3C5, 0x01);

    
    outb(0x3C4, 0x01); uint8_t clock = inb(0x3C5);
    outb(0x3C5, clock | 0x20);

    
    outb(0x3C4, 0x02); outb(0x3C5, 0x04);   
    outb(0x3C4, 0x04); outb(0x3C5, 0x06);   

    
    outb(0x3CE, 0x04); outb(0x3CF, 0x02);
    outb(0x3CE, 0x05); outb(0x3CF, 0x00);
    outb(0x3CE, 0x06); outb(0x3CF, 0x00);

    
    uint8_t *dst = (uint8_t *)PHYS_KVA(0xA0000);   /* VGA font plane */
    for (int ch = 0; ch < 256; ch++) {
        for (int row = 0; row < 8; row++) {
            dst[(ch * 32) + row] = font_8x8[ch][row];
        }
    }

    
    outb(0x3C4, 0x00); outb(0x3C5, 0x03);

    
    outb(0x3C4, 0x02); outb(0x3C5, seq2);
    outb(0x3C4, 0x04); outb(0x3C5, seq4);
    outb(0x3CE, 0x04); outb(0x3CF, gc4);
    outb(0x3CE, 0x05); outb(0x3CF, gc5);
    outb(0x3CE, 0x06); outb(0x3CF, gc6);

    
    outb(0x3C4, 0x01); outb(0x3C5, clock & ~0x20);

    
    inb(0x3DA);
    outb(0x3C0, 0x20);
}

static void scroll_screen(void);
static void update_cursor(void);
static void serial_wait(void);
static void vga_initialize_text_mode_80x50(void);

void outb(uint16_t port, uint8_t val) {
    asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

char console_getc(void) {
    for (;;) {
        if (inb(0x3FD) & 1) {
            return (char)inb(0x3F8);
        }


        if (kb_head != kb_tail) {
            char c = keyboard_buffer[kb_head];
            kb_head = (kb_head + 1) % 256;
            return c;
        }

        /* Nothing pending: sleep the CPU until the next interrupt instead of
         * spinning hot. A bare poll here pegged a host core at 100% under
         * emulation — an idle prompt was enough to overheat the host — and
         * wastes power on real hardware. Still do NOT call the cooperative
         * yield()/schedule(): console input arrives from hardware (the keyboard
         * IRQ or the serial UART), not from another task, so the waiter must
         * stay the current task. A cooperative switch here would run on this
         * task's kernel stack under the peer's CR3 and copy_to_user the byte
         * into the wrong address space, intermittently hanging or corrupting the
         * reader.
         *
         * `sti; hlt` is atomic — sti defers enabling interrupts until after the
         * following instruction, so no wakeup is lost between the two — and the
         * keyboard/serial IRQ or the 100 Hz timer wakes us to re-poll (serial is
         * polled, so its latency is bounded by the tick, <= 10 ms). Interrupts
         * are enabled only across the halt and the caller's prior interrupt
         * state is restored, so this never newly enables interrupts for the rest
         * of the syscall. A ring-0 spin is not preempted, so a timer tick just
         * re-checks and returns here rather than switching tasks — the same
         * invariant the old spin relied on. */
        uint64_t rflags;
        __asm__ volatile ("pushfq; pop %0" : "=r"(rflags) :: "memory");
        __asm__ volatile ("sti; hlt" ::: "memory");
        if (!(rflags & (1ull << 9)))   /* caller had IF clear -> restore it */
            __asm__ volatile ("cli" ::: "memory");
    }
}

/* ---- The framebuffer console ------------------------------------------------
 *
 * A pixel display driven from the SAME 80x50 cell grid the VGA text console
 * uses, so every caller of print() is unchanged and the two modes differ only
 * in where a cell lands. The kernel keeps a shadow of that grid here rather
 * than reading it back out of the display: on a machine in a graphics mode the
 * legacy text window at 0xB8000 is not a display and may not even be decoded,
 * so it is neither a place to store state nor a place to read it from.
 *
 * FONT-AGNOSTIC ON PURPOSE. The blitter takes width, height and a bitmap
 * pointer, so replacing the 8x8 font with a taller one is a data change and not
 * a code change. That matters here specifically: the font this ships with is
 * `font_8x8` below, which is ASCII-only, draws 7 pixels wide in an 8-pixel cell
 * and CARRIES NO PROVENANCE -- see THIRD_PARTY.md. Replacing it is a separate
 * commit, and this is what makes that commit small.
 *
 * BIT ORDER IS MSB-FIRST, and it is not a guess: this same table is uploaded
 * into the VGA font plane at 0xA0000 by vga_initialize_text_mode_80x50, where
 * the hardware reads bit 7 as the leftmost pixel. A blitter that disagreed with
 * that would mirror every glyph, and the two paths would disagree about what
 * the same bytes mean.
 *
 * SCALE is 1:1 below 1600 pixels wide and 2x at or above it, so a dense modern
 * panel does not render an unreadably small grid. If the chosen scale does not
 * FIT the grid, it falls back to 1:1 rather than drawing off the edge, and if
 * 1:1 does not fit either the framebuffer console is simply not started. Every
 * cell blit is bounds-checked against the real width and height as well: the
 * geometry came from firmware, and a write past the end of this mapping is a
 * write into whatever the next 2 MiB page holds. */
struct console_font { const uint8_t *bits; uint8_t w, h; };

static struct console_font g_font;
static uint32_t *g_fbp;             /* framebuffer as 32-bit pixels; 0 = inactive */
static uint32_t  g_fb_pitch_px;     /* pitch in PIXELS, not bytes */
static uint32_t  g_fb_w, g_fb_h;
static uint32_t  g_scale = 1;
static uint16_t  fb_cells[VGA_ROWS * VGA_COLS];
static int       g_fb_console;      /* 1 once the framebuffer console is live */
static int       g_cur_y = -1, g_cur_x = -1;   /* where the cursor is drawn */

int console_is_framebuffer(void) { return g_fb_console; }

/* The standard VGA 16-colour text palette as 0x00RRGGBB. Written out rather
 * than computed: these are the colours a VGA DAC produces for attribute values
 * 0..15, and every terminal in the world renders them approximately this way.
 * The bright half is not "the dark half doubled" -- 0xAA and 0x55 are the
 * hardware's own levels -- so a formula here would be a subtly different
 * palette that merely looked principled. */
static const uint32_t vga_palette[16] = {
    0x000000, 0x0000AA, 0x00AA00, 0x00AAAA,
    0xAA0000, 0xAA00AA, 0xAA5500, 0xAAAAAA,
    0x555555, 0x5555FF, 0x55FF55, 0x55FFFF,
    0xFF5555, 0xFF55FF, 0xFFFF55, 0xFFFFFF,
};

/* Paint one glyph at a pixel origin. The one place pixels are written, so the
 * self-test below exercises the code the console actually draws with rather
 * than a second copy of it that could be right while the first is wrong.
 *
 * BIT 7 IS THE LEFTMOST PIXEL. Not a guess: this same table is uploaded into
 * the VGA font plane, where the hardware reads it that way, so a blitter that
 * disagreed would mirror every glyph while the text console rendered correctly
 * -- two paths disagreeing about what the same bytes mean. It is also invisible
 * on serial, which is why the gate for it checks PIXELS. */
static void fb_draw_glyph(uint32_t px0, uint32_t py0, uint8_t ch,
                          uint32_t fg, uint32_t bg) {
    uint32_t cw  = (uint32_t)g_font.w * g_scale;
    uint32_t chh = (uint32_t)g_font.h * g_scale;
    if (px0 + cw > g_fb_w || py0 + chh > g_fb_h) return;

    const uint8_t *glyph = g_font.bits + (uint32_t)ch * g_font.h;
    for (uint32_t ry = 0; ry < chh; ry++) {
        uint8_t bits = glyph[ry / g_scale];
        uint32_t *row = g_fbp + (uint64_t)(py0 + ry) * g_fb_pitch_px + px0;
        for (uint32_t rx = 0; rx < cw; rx++) {
#ifdef FB_CONSOLE_MIRRORED
            /* CONTROL ARM -- never ship. LSB-first: bit 0 as the leftmost pixel,
             * which mirrors every glyph. The classic framebuffer font defect,
             * and one no serial log can show -- the console reports itself
             * started and every message is present and correct in the log while
             * the screen is unreadable. */
            row[rx] = (bits & (1u << (rx / g_scale))) ? fg : bg;
#else
            row[rx] = (bits & (0x80u >> (rx / g_scale))) ? fg : bg;
#endif
        }
    }
}

/* Paint one cell. Bounds-checked against the real geometry, not against the
 * grid: the grid is what the console believes and the geometry is what the
 * hardware has, and a mismatch must clip rather than scribble. */
static void fb_blit_cell(int y, int x) {
    if (!g_fb_console || y < 0 || x < 0 || y >= VGA_ROWS || x >= VGA_COLS) return;

    uint16_t cell = fb_cells[y * VGA_COLS + x];
    uint8_t  ch   = (uint8_t)(cell & 0xFF);
    uint8_t  attr = (uint8_t)(cell >> 8);
    uint32_t fg   = vga_palette[attr & 0x0F];
    uint32_t bg   = vga_palette[(attr >> 4) & 0x07];

    fb_draw_glyph((uint32_t)x * (uint32_t)g_font.w * g_scale,
                  (uint32_t)y * (uint32_t)g_font.h * g_scale, ch, fg, bg);
}

/* A framebuffer has no CRTC cursor, so one is drawn: an underline in the
 * foreground colour across the bottom of the cell. Erasing is a re-blit of the
 * cell it was over, which is why the position it was last drawn at is
 * remembered -- repainting the whole grid to move a cursor would be visible. */
static void fb_draw_cursor(void) {
    if (!g_fb_console) return;
    if (g_cur_y >= 0) fb_blit_cell(g_cur_y, g_cur_x);
    g_cur_y = cursor_y; g_cur_x = cursor_x;
    if (cursor_y < 0 || cursor_x < 0 || cursor_y >= VGA_ROWS || cursor_x >= VGA_COLS) return;

    uint32_t cw = (uint32_t)g_font.w * g_scale;
    uint32_t chh = (uint32_t)g_font.h * g_scale;
    uint32_t px0 = (uint32_t)cursor_x * cw;
    uint32_t py0 = (uint32_t)cursor_y * chh;
    if (px0 + cw > g_fb_w || py0 + chh > g_fb_h) return;

    uint16_t cell = fb_cells[cursor_y * VGA_COLS + cursor_x];
    uint32_t fg = vga_palette[(cell >> 8) & 0x0F];
    for (uint32_t ry = chh - (g_scale * 2u); ry < chh; ry++) {
        uint32_t *row = g_fbp + (uint64_t)(py0 + ry) * g_fb_pitch_px + px0;
        for (uint32_t rx = 0; rx < cw; rx++) row[rx] = fg;
    }
}

/* Repaint every cell. Used on start-up and after a scroll. */
static void fb_repaint(void) {
    if (!g_fb_console) return;
    for (int y = 0; y < VGA_ROWS; y++)
        for (int x = 0; x < VGA_COLS; x++) fb_blit_cell(y, x);
    g_cur_y = -1;
    fb_draw_cursor();
}

/* Start the framebuffer console, if there is one to start.
 *
 * REFUSES RATHER THAN APPROXIMATES. 32 bits per pixel only: 24bpp needs a
 * byte-wise store and 15/16bpp needs channel packing, and each is a different
 * blitter. Writing one of them untested would be worse than not claiming the
 * mode -- the console is the only way to report anything on a machine with no
 * serial port, so a console that draws WRONG is harder to diagnose than one
 * that never started and said so. */
void fb_console_init(void) {
    const struct fb_info *fb = fb_info();
    if (!fb->valid || fb->type != MB2_FB_RGB) return;
    uint64_t va = fb_vaddr();
    if (va == 0) return;
    if (fb->bpp != 32) {
        print("fb: "); print_decimal(fb->bpp);
        print("-bit pixels are not supported; console stays on VGA text\n");
        return;
    }

    g_font.bits = &font_8x8[0][0];
    g_font.w = 8;
    g_font.h = 8;

    g_scale = (fb->width >= 1600u) ? 2u : 1u;
    if (fb->width  < (uint32_t)VGA_COLS * g_font.w * g_scale ||
        fb->height < (uint32_t)VGA_ROWS * g_font.h * g_scale)
        g_scale = 1;
    if (fb->width  < (uint32_t)VGA_COLS * g_font.w ||
        fb->height < (uint32_t)VGA_ROWS * g_font.h) {
        print("fb: the display is too small for an 80x50 grid; console stays on VGA text\n");
        return;
    }

    g_fbp         = (uint32_t *)(uintptr_t)va;
    g_fb_pitch_px = fb->pitch / 4u;
    g_fb_w        = fb->width;
    g_fb_h        = fb->height;

    /* The shadow starts as the blank screen clear_screen would have drawn, and
     * the whole display is painted from it -- including the region outside the
     * grid, which firmware left holding whatever it left holding. */
    for (int i = 0; i < VGA_ROWS * VGA_COLS; i++) fb_cells[i] = (uint16_t)((current_attr << 8) | ' ');
    g_fb_console = 1;
    for (uint32_t py = 0; py < g_fb_h; py++) {
        uint32_t *row = g_fbp + (uint64_t)py * g_fb_pitch_px;
        for (uint32_t px = 0; px < g_fb_w; px++) row[px] = vga_palette[(current_attr >> 4) & 0x07];
    }
    fb_repaint();

#ifdef FB_CONSOLE_SELFTEST
    /* Draw a known glyph BELOW the 80x50 grid, in the region the console never
     * touches, so the boot log cannot scroll over it before the host looks.
     * 'L' specifically: it is strongly left-heavy in any font that draws an L at
     * all -- a stem down the left, a foot to the right -- so the host can test
     * for a mirrored blitter without knowing which font is loaded. That keeps
     * the check alive across a font replacement, which is the next commit. */
    fb_draw_glyph(0, (uint32_t)VGA_ROWS * (uint32_t)g_font.h * g_scale + 8u,
                  (uint8_t)'L', vga_palette[15], vga_palette[0]);
    print("fb: selftest glyph drawn below the grid\n");
#endif
    print("fb: console on the framebuffer, ");
    print_decimal((uint32_t)VGA_COLS); print("x"); print_decimal((uint32_t)VGA_ROWS);
    print(" cells, "); print_decimal(g_font.w); print("x"); print_decimal(g_font.h);
    print(" font at "); print_decimal(g_scale); print("x\n");
}

/* The console's cell grid, addressed the same way in both modes.
 *
 * In text mode these ARE the VGA text plane, exactly as before. In framebuffer
 * mode they are the shadow above and every write also paints. Introduced so the
 * four places that used to write VIDEO_MEMORY directly do not each need to know
 * which mode they are in. */
static inline uint16_t cell_get(int y, int x) {
    return g_fb_console ? fb_cells[y * VGA_COLS + x]
                        : VIDEO_MEMORY[y * VGA_COLS + x];
}
static inline void cell_put(int y, int x, uint16_t v) {
    if (g_fb_console) { fb_cells[y * VGA_COLS + x] = v; fb_blit_cell(y, x); }
    else VIDEO_MEMORY[y * VGA_COLS + x] = v;
}

static void update_cursor(void) {
    if (g_fb_console) { fb_draw_cursor(); return; }
    uint16_t pos = cursor_y * VGA_COLS + cursor_x;
    outb(0x3D4, 14);
    outb(0x3D5, pos >> 8);
    outb(0x3D4, 15);
    outb(0x3D5, pos & 0xFF);
}

void terminal_init(void) {
    vga_initialize_text_mode_80x50();
    clear_screen();
}

static void vga_initialize_text_mode_80x50(void) {
    outb(0x3C2, 0x67);

    outb(0x3C4, 0x00); outb(0x3C5, 0x03);
    outb(0x3C4, 0x01); outb(0x3C5, 0x00);
    outb(0x3C4, 0x02); outb(0x3C5, 0x03);
    outb(0x3C4, 0x03); outb(0x3C5, 0x00);
    outb(0x3C4, 0x04); outb(0x3C5, 0x02);

    
    load_8x8_font();

    outb(0x3D4, 0x11);
    uint8_t vsync = inb(0x3D5) & 0x7F;
    outb(0x3D5, vsync);

    
    static const uint8_t crtc_80x50[25] = {
        0x5F, 0x4F, 0x50, 0x82, 0x55, 0x81, 0xBF, 0x1F,
        0x00, 0x47, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00,
        0x9C, 0x8E, 0x8F, 0x28, 0x0F, 0x96, 0xB9, 0xA3,
        0xFF
    };
    for (int i = 0; i < 25; i++) {
        outb(0x3D4, (uint8_t)i);
        outb(0x3D5, crtc_80x50[i]);
    }

    outb(0x3D4, 0x11);
    outb(0x3D5, inb(0x3D5) | 0x80);

    
    outb(0x3D4, 0x09);
    outb(0x3D5, 0x07);

    
    outb(0x3D4, 0x14);
    outb(0x3D5, 0x00);

    outb(0x3CE, 0x00); outb(0x3CF, 0x00);
    outb(0x3CE, 0x01); outb(0x3CF, 0x00);
    outb(0x3CE, 0x02); outb(0x3CF, 0x00);
    outb(0x3CE, 0x03); outb(0x3CF, 0x00);
    outb(0x3CE, 0x04); outb(0x3CF, 0x00);
    outb(0x3CE, 0x05); outb(0x3CF, 0x10);
    outb(0x3CE, 0x06); outb(0x3CF, 0x0E);
    outb(0x3CE, 0x07); outb(0x3CF, 0x00);
    outb(0x3CE, 0x08); outb(0x3CF, 0xFF);

    inb(0x3DA);
    for (int i = 0; i < 16; i++) {
        outb(0x3C0, (uint8_t)i);
        outb(0x3C0, (uint8_t)i);
    }
    outb(0x3C0, 0x10); outb(0x3C0, 0x0C);
    outb(0x3C0, 0x11); outb(0x3C0, 0x00);
    outb(0x3C0, 0x12); outb(0x3C0, 0x0F);
    outb(0x3C0, 0x13); outb(0x3C0, 0x08);
    outb(0x3C0, 0x14); outb(0x3C0, 0x00);

    inb(0x3DA);
    outb(0x3C0, 0x20);

    
    outb(0x3D4, 0x0A); outb(0x3D5, 0x00);
    outb(0x3D4, 0x0B); outb(0x3D5, 0x07);
}

/* How many polls to give the UART before giving up on it.
 *
 * WHY IT MUST BE BOUNDED. serial_wait runs from emit_char, inside
 * console_lock_acquire(), which holds `cli`. An unbounded spin there is not a
 * slow console -- it is the whole machine stopped with interrupts disabled and
 * nothing on screen, which is the least diagnosable failure this kernel can
 * have. On a laptop with no serial port there is no second channel on which to
 * notice it.
 *
 * WHY IT HAS NEVER FIRED, WHICH IS NOT THE SAME AS BEING SAFE. A port that
 * decodes nothing reads back 0xFF, and 0xFF & 0x20 is non-zero, so an ABSENT
 * UART leaves the loop on its first read -- that is why this has survived every
 * boot on hardware that has no COM1 at all. The hazard is the port that DOES
 * decode and never drains: a wedged device, or firmware that left the UART in a
 * state it does not leave. That case had no bound.
 *
 * THE BYTE IS WRITTEN ANYWAY ON TIMEOUT. The console is a diagnostic, and a
 * kernel that stops making progress in order to finish a log line has traded the
 * thing being diagnosed for the diagnosis. Writing into a UART that never
 * asserted THRE may lose the byte, which is the acceptable half of that trade.
 * When the UART works this loop exits on the first read and nothing changes. */
#define SERIAL_TX_SPINS 200000u

static void serial_wait(void) {
    for (uint32_t i = 0; i < SERIAL_TX_SPINS; i++) {
#ifdef SERIAL_TX_NEVER_DRAINS
        /* Control arm: poll the register but never accept the answer, which is
         * the wedged-UART case. The outb below still happens, so the arm's own
         * assertion stays observable -- an arm that silenced the console could
         * not tell a working bound from a hung machine. */
        (void)inb(0x3FD);
#else
        if (inb(0x3FD) & 0x20) return;
#endif
    }
}

void serial_write_char(char c) {
    serial_wait();
    outb(0x3F8, c);
}

static void serial2_wait(void) {
    for (uint32_t i = 0; i < SERIAL_TX_SPINS; i++) {
#ifdef SERIAL_TX_NEVER_DRAINS
        (void)inb(0x2FD);
#else
        if (inb(0x2FD) & 0x20) return;
#endif
    }
}

void serial2_write_char(char c) {
    serial2_wait();
    outb(0x2F8, c);
}

char serial2_read_char(void) {
    /* Hardware wait on COM2 — spin without the cooperative scheduler, for the
     * same reason as console_getc(): the byte comes from the UART, not a task,
     * so this reader must remain the current task (a cooperative switch here
     * would leave a peer's CR3/current active on our kernel stack). */
    while ((inb(0x2FD) & 1) == 0) {
        __asm__ volatile ("pause");
    }
    return inb(0x2F8);
}

static void serial_update_colour(void) {
    if (current_attr == last_serial_attr) return;

    uint8_t fg = current_attr & 0x0F;
    uint8_t bg = (current_attr >> 4) & 0x0F;

    serial_write_char(0x1B);
    serial_write_char('[');
    serial_write_char('0');
    serial_write_char(';');

    if (fg >= 8) {
        serial_write_char('9');
        serial_write_char('0' + (fg - 8));
    } else {
        serial_write_char('3');
        serial_write_char('0' + fg);
    }
    serial_write_char(';');

    serial_write_char('4');
    serial_write_char('0' + (bg & 7));
    serial_write_char('m');

    last_serial_attr = current_attr;
}

/* ---- Linux-style boot/kernel-log timestamps -------------------------------
 *
 * The prefix is "[    S.uuuuuu] " with MICROSECOND resolution, sourced from the
 * TSC (like Linux). The 100 Hz PIT tick is not running for most of early boot
 * (interrupts come up late), so a tick-based clock reads 0.000000 for every
 * early line; the TSC increments from the first instruction. `kmsg_clock_init()`
 * calibrates the TSC frequency once against PIT channel 2 -- the same ~10 ms
 * gate `lapic_timer_calibrate` uses -- and records the boot epoch. Call it once,
 * early, before the first line is printed. Under TCG the TSC is virtual but
 * self-consistent with the emulated PIT, so timestamps still advance
 * monotonically.
 *
 * THE STAMP IS APPLIED BY THE WRITER, NOT BY THE CALLER (2026-09-06). Until then
 * a line was timestamped only if its author remembered to call kmsg(), and most
 * did not: the boot console mixed `[    0.002417] boot: 25 boot modules loaded`
 * with `  [ OK ] boot modules verified ...` from crypto.c and main.c, and with
 * every ring-3 line arriving through SYS_WRITE, which has no way to call kmsg()
 * at all. A rule the caller must remember is a rule that decays; print_core()
 * now stamps the first character of every line it accepts, so there is one place
 * to get it right and no way to opt out by accident. kmsg()/kmsg_begin() are
 * gone with the same commit -- they would have double-stamped, and their whole
 * job is now done by the writer.
 *
 * WHY THE STAMP IS EMITTED INSIDE print_core's CRITICAL SECTION and not by a
 * second call in front of it. `kmsg_begin(); print(msg);` was two separate
 * `console_lock` acquisitions, so a ring-3 SYS_WRITE on another CPU could land
 * between the prefix and the text of a kernel line -- the 2.6a hazard, in the
 * kernel, on every timestamped line the system printed. Stamping from inside the
 * loop that is already holding the lock makes prefix+text atomic against every
 * other writer of this console: kernel print() on any CPU, and every ring-3
 * SYS_WRITE, both of which reach the hardware only through this function. (It
 * does NOT serialise against `kfault_str`/`panic_ch`, which bypass the lock by
 * design; that is docs/LIMITATIONS.md 2.6c and is unchanged either way.) */
static uint64_t boot_tsc0  = 0;
static uint64_t tsc_per_us = 0;   /* 0 until calibrated => timestamps read 0 */

static inline uint64_t rd_tsc(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

void kmsg_clock_init(void) {
    /* PIT channel 2, mode 0, counting ~10 ms (11932 ticks @ 1.193182 MHz). We
     * poll OUT2 (port 0x61 bit 5) rather than take an interrupt, so this runs
     * before the PIC/IDT are up. The speaker stays disabled and port 0x61 is
     * restored afterwards. */
    uint8_t p61 = inb(0x61);
    outb(0x61, (uint8_t)((p61 & 0xFC) | 0x01));    /* gate2 on, speaker off */
    outb(0x43, 0xB0);                              /* ch2, lo/hi, mode 0 */
    outb(0x42, (uint8_t)(11932u & 0xFF));
    outb(0x42, (uint8_t)(11932u >> 8));
    uint64_t t0 = rd_tsc();
    while (!(inb(0x61) & 0x20)) { }                /* wait for OUT2 high */
    uint64_t cycles = rd_tsc() - t0;               /* TSC ticks in ~10 ms */
    outb(0x61, p61);                               /* restore port 0x61 */
    tsc_per_us = cycles / 10000u;                  /* 10 ms == 10000 us */
    if (tsc_per_us == 0) tsc_per_us = 1;           /* guard div-by-zero */
    boot_tsc0 = rd_tsc();
}

/* Whole PIT ticks (10 ms each) elapsed since the kernel's boot epoch.
 *
 * QUANTISED DELIBERATELY, and that is the entire point of the function: it
 * exists so SYS_CLOCK_GETTIME can share the console timestamps' epoch without
 * anyone gaining a finer number than the PIT already hands out. The
 * microsecond value it divides never leaves this file except under
 * CLOCK_TSC_RESOLUTION, which is a control arm.
 *
 * Read once, on the first timer tick (scheduler.c), to fix the offset between
 * "since boot" and "since the timer started". Those differed by 1.07 s on the
 * boot measured on 2026-09-06 -- almost all of it SMP bring-up -- which is why
 * a ring-3 stamp read 0.09 on a line the kernel would have stamped 1.16, and
 * why a boot log that changed hands went BACKWARDS in the middle. */
uint64_t kmsg_uptime_ticks(void) {
    uint64_t us = tsc_per_us ? (rd_tsc() - boot_tsc0) / tsc_per_us : 0;
    return us / (1000000u / PIT_TICK_HZ);
}

#ifdef CLOCK_TSC_RESOLUTION
/* Microseconds since boot from the calibrated TSC. Exists ONLY for the
 * CLOCK_TSC_RESOLUTION control arm (roadmap 2.2): it is the cycle-accurate
 * clock SYS_CLOCK_GETTIME deliberately does not expose, so it is compiled out
 * of every ordinary build rather than sitting there waiting to be called. */
uint64_t kmsg_uptime_us(void) {
    return tsc_per_us ? (rd_tsc() - boot_tsc0) / tsc_per_us : 0;
}
#endif

/* Render "[    S.uuuuuu] " into `buf` (needs 24 bytes) and return its length.
 * The exact same field widths are produced in ring 3 by hstamp() in
 * userspace/libhorus.c, because the console changes hands mid-boot and a reader
 * must not be able to tell which writer stamped a line by looking at it.
 * tools/check_console_timestamps.py holds both to one regex. */
static int kmsg_stamp(char *buf) {
    uint64_t us   = tsc_per_us ? (rd_tsc() - boot_tsc0) / tsc_per_us : 0;
    uint32_t sec  = (uint32_t)(us / 1000000u);
    uint32_t frac = (uint32_t)(us % 1000000u);     /* microseconds */
    int n = 0;
    buf[n++] = '[';
    /* right-align the seconds in a width-5 field (the classic printk look) */
    char digits[10];
    int dl = 0;
    if (sec == 0) {
        digits[dl++] = '0';
    } else {
        uint32_t v = sec;
        char tmp[10];
        int tl = 0;
        while (v) { tmp[tl++] = (char)('0' + (v % 10u)); v /= 10u; }
        while (tl) digits[dl++] = tmp[--tl];
    }
    for (int i = dl; i < 5; i++) buf[n++] = ' ';
    for (int i = 0; i < dl; i++) buf[n++] = digits[i];
    buf[n++] = '.';
    /* six-digit zero-padded microseconds */
    for (uint32_t d = 100000u; d >= 1u; d /= 10u) buf[n++] = (char)('0' + (frac / d) % 10u);
    buf[n++] = ']';
    buf[n++] = ' ';
    buf[n]   = 0;
    return n;
}

/* Emit ONE byte to the klog and (when the kernel still drives the hardware) to
 * the VGA text buffer and COM1. Split out of print_core so the timestamp prefix
 * can go through exactly the same path as the text it precedes, inside the same
 * lock. Callers hold `console_lock`. */
static void emit_char(char c, int to_klog, int drive_hw) {
    /* The kernel log survives the handoff to ring 3: this append is placed
     * BEFORE the drive_hw test on purpose, so a kernel diagnostic is still
     * recorded once console_server owns the wire. That placement is also
     * what made [H-2] reachable when the caller was ring 3. */
    if (to_klog) klog_append(c);

    if (!drive_hw) return;

    if (cursor_y >= VGA_ROWS || cursor_x >= VGA_COLS) {
        scroll_screen();
    }

    if (c == '\n') {
        cursor_x = 0;
        cursor_y++;
    } else if (c == '\r') {
        cursor_x = 0;
    } else if (c == '\b') {

        if (cursor_x > 0) {
            cursor_x--;
        } else if (cursor_y > 0) {
            cursor_y--;
            cursor_x = VGA_COLS - 1;
        }
    } else {
        if (cursor_y < VGA_ROWS && cursor_x < VGA_COLS) {
            cell_put(cursor_y, cursor_x, (uint16_t)((current_attr << 8) | (uint8_t)c));
        }
        cursor_x++;
    }

    if (cursor_x >= VGA_COLS) {
        cursor_x = 0;
        cursor_y++;
    }
    if (cursor_y >= VGA_ROWS) {
        scroll_screen();
    }

    if (c == '\n') {
        serial_write_char('\r');
        serial_write_char('\n');
    } else {
        serial_update_colour();
        serial_write_char(c);
    }
}

/* Where the next byte falls in the line, so the writer knows when to stamp. Not
 * per-caller state: the console is one line of text whoever is printing to it,
 * and print() is re-entered from every CPU and from ring 3. Guarded by
 * `console_lock` like the cursor beside it. */
static int at_line_start = 1;

/* Set while dump_kernel_log() replays the ring back to the console. Those bytes
 * were stamped when they were first accepted; stamping the replay would put a
 * second, later prefix in front of every recovered line and misdate the log a
 * maintainer is reading it to reconstruct. */
static int replaying_klog = 0;

/* The console writer. `to_klog` decides whether the bytes are also recorded in
 * the kernel message ring, and that is an AUTHORITY decision, not a formatting
 * one -- see print_from_user() below and finding [H-2]. Kernel-origin output
 * always records; ring-3 output records only if the writing task holds
 * CAP_KERNEL_LOG with WRITE.
 *
 * Every line it accepts is timestamped -- see the block above kmsg_stamp() for
 * why the stamp is applied here rather than by the caller, and why it must be
 * emitted without releasing the lock. */
static void print_core(const char* str, int to_klog) {
    uint64_t flags = console_lock_acquire();
    /* Snapshot ownership once for the whole call so a line is emitted whole to one
     * sink, never split across a handoff. `drive_hw` false => a ring-3 server owns
     * the console; we only record to klog and leave the wire to it. */
    int drive_hw = (console_owner_task == 0);

    while (*str) {
        char c = *str;

#ifndef CONSOLE_TIMESTAMPS_LEGACY
        /* Stamp the first PRINTABLE byte of each line. A '\n' arriving at the
         * start of a line is a deliberate blank line and stays blank -- a
         * timestamp alone on a row is noise, and the gate that requires the
         * format skips blank lines for the same reason. Control bytes ('\b'
         * from the console read echo, '\r') never open a line either. */
        if (at_line_start && !replaying_klog && ((unsigned char)c >= ' ' || c == '\t')) {
            char st[24];
            int n = kmsg_stamp(st);
            for (int i = 0; i < n; i++) emit_char(st[i], to_klog, drive_hw);
            at_line_start = 0;
        }
#endif
        if (c == '\n') at_line_start = 1;
        else if ((unsigned char)c >= ' ' || c == '\t') at_line_start = 0;

        emit_char(c, to_klog, drive_hw);
        str++;
    }
    if (drive_hw) update_cursor();
    console_lock_release(flags);
}

/* Kernel-origin output. Always recorded to klog: every caller is ring 0, and the
 * log is the kernel's own record of what it did. */
void print(const char* str) { print_core(str, 1); }

/* Ring-3-origin output (the SYS_WRITE fd 1 path, and nothing else).
 *
 * `may_klog` is the caller's proved authority to append to the kernel message
 * ring, not a preference: h_write() resolves it through cap_lookup() and passes
 * 0 when the writing task holds no CAP_KERNEL_LOG with WRITE. Finding [H-2] was
 * that this distinction did not exist -- h_write called print(), print() called
 * klog_append() unconditionally, and so any unprivileged ring-3 task could write
 * lines into `dmesg` that a reader cannot tell from kernel diagnostics, and could
 * flood the 16 KiB ring to evict genuine ones. That is an anti-forensics
 * primitive against the log a maintainer reads after an incident, and the read
 * side of the same ring had required CAP_KERNEL_LOG since [I-1].
 *
 * The console still takes the bytes either way. Writing to the terminal is not
 * the authority in question and is deliberately ungated (docs/SYSCALLS.md);
 * writing to the KERNEL'S LOG is, and it fails closed. */
void print_from_user(const char* str, int may_klog) { print_core(str, may_klog != 0); }

void println(const char* str) { print(str); print("\n"); }

void clear_screen(void) {
    uint64_t flags = console_lock_acquire();
    if (console_owner_task == 0) {
        for (int y = 0; y < VGA_ROWS; y++)
            for (int x = 0; x < VGA_COLS; x++)
                cell_put(y, x, (uint16_t)((current_attr << 8) | ' '));
        cursor_x = 0; cursor_y = 0; update_cursor();
    }
    console_lock_release(flags);
}

void print_hex(uint64_t n) {
    char buf[17]; const char* hex = "0123456789ABCDEF";
    for (int i = 15; i >= 0; i--) { buf[i] = hex[n & 0xF]; n >>= 4; }
    buf[16] = '\0';
    print("0x"); print(buf);
}

void print_hex64(uint64_t n) {
    char buf[17]; const char* hex = "0123456789ABCDEF";
    for (int i = 15; i >= 0; i--) { buf[i] = hex[n & 0xF]; n >>= 4; }
    buf[16] = '\0';
    print("0x"); print(buf);
}

void print_char(char c) {
    char s[2] = {c, 0};
    print(s);
}

void set_text_colour(uint8_t attr) {
    current_attr = attr;
}

void print_decimal(uint64_t n) {
    char buf[21];
    int i = 20;
    buf[i] = 0;
    if (n == 0) {
        buf[--i] = '0';
    } else {
        int digits = 0;
        while (n > 0 && digits < 20) {
            buf[--i] = '0' + (n % 10);
            n /= 10;
            digits++;
        }
    }
    print(&buf[i]);
}

static void scroll_screen(void) {
    for (int y = 1; y < VGA_ROWS; y++) {
        for (int x = 0; x < VGA_COLS; x++) {
            cell_put(y - 1, x, cell_get(y, x));
        }
    }
    for (int x = 0; x < VGA_COLS; x++) {
        cell_put(VGA_ROWS - 1, x, (uint16_t)((current_attr << 8) | ' '));
    }
    cursor_y = VGA_ROWS - 1;
    cursor_x = 0;
    update_cursor();
}

void print_hrule(uint8_t color) {
    uint8_t old = current_attr;
    set_text_colour(color);
    for (int i = 0; i < VGA_COLS; i++) {
        print_char('=');
    }
    println("");
    set_text_colour(old);
}

void print_blanks(int count) {
    for (int i = 0; i < count; i++) {
        println("");
    }
}

void print_section(const char* title, uint8_t title_color) {
    set_text_colour(title_color);
    print(">> ");
    set_text_colour(0x0F);
    println(title);
    set_text_colour(title_color);
    print("   ");
    for (int i = 0; i < 70; i++) print_char('-');
    println("");
    set_text_colour(0x0F);
}

void dump_kernel_log(void) {
    uint8_t old = current_attr;
    print_hrule(0x0A);
    set_text_colour(0x0A);
    println("=== kernel log (recent output; survives clear and scroll) ===");
    set_text_colour(0x0F);

    if (klog_len == 0) {
        println("(log empty)");
    } else {
        /* Replay verbatim: these bytes already carry the timestamp they were
         * accepted with, and a second, now-later prefix in front of each one
         * would misdate exactly the record this dump exists to recover. */
        replaying_klog = 1;
        uint32_t start = (klog_head + sizeof(klog_buf) - klog_len) % sizeof(klog_buf);
        uint32_t pos = start;
        for (uint32_t i = 0; i < klog_len; i++) {
            print_char(klog_buf[pos]);
            pos = (pos + 1) % sizeof(klog_buf);
        }
        
        if (klog_len > 0) {
            char last = klog_buf[(klog_head + sizeof(klog_buf) - 1) % sizeof(klog_buf)];
            if (last != '\n' && last != '\r') {
                println("");
            }
        }
        replaying_klog = 0;
    }

    print_hrule(0x08);
    set_text_colour(old);
}
