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

static void update_cursor(void) {
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

static void serial_wait(void) {
    while ((inb(0x3FD) & 0x20) == 0) {}
}

void serial_write_char(char c) {
    serial_wait();
    outb(0x3F8, c);
}

static void serial2_wait(void) {
    while ((inb(0x2FD) & 0x20) == 0) {}
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

void print(const char* str) {
    uint64_t flags = console_lock_acquire();
    /* Snapshot ownership once for the whole call so a line is emitted whole to one
     * sink, never split across a handoff. `drive_hw` false => a ring-3 server owns
     * the console; we only record to klog and leave the wire to it. */
    int drive_hw = (console_owner_task == 0);

    while (*str) {
        char c = *str;
        klog_append(c);   /* always: the kernel log survives the handoff to ring 3 */

        if (!drive_hw) { str++; continue; }

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
                VIDEO_MEMORY[cursor_y * VGA_COLS + cursor_x] = (current_attr << 8) | (uint8_t)c;
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

        str++;
    }
    if (drive_hw) update_cursor();
    console_lock_release(flags);
}

void println(const char* str) { print(str); print("\n"); }

void clear_screen(void) {
    uint64_t flags = console_lock_acquire();
    if (console_owner_task == 0) {
        for (int i = 0; i < VGA_COLS * VGA_ROWS; i++) VIDEO_MEMORY[i] = (current_attr << 8) | ' ';
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
            VIDEO_MEMORY[(y-1) * VGA_COLS + x] = VIDEO_MEMORY[y * VGA_COLS + x];
        }
    }
    for (int x = 0; x < VGA_COLS; x++) {
        VIDEO_MEMORY[(VGA_ROWS-1) * VGA_COLS + x] = (current_attr << 8) | ' ';
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
    }

    print_hrule(0x08);
    set_text_colour(old);
}
