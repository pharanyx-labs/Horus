#include "kernel.h"

#define PAGE_PRESENT   (1 << 0)
#define RECURSIVE_PD_VADDR  0xFFFFF000
#define RECURSIVE_PT_VADDR  0xFFC00000

typedef uint32_t pde_t;
typedef uint32_t pte_t;

#define PAGE_COW       (1 << 9)

int handle_demand_page_fault(uint32_t fault_addr, uint32_t err_code);

__attribute__((weak))
int rust_handle_demand_page_fault(uint32_t fault_addr, uint32_t err_code, bool is_cow, uint16_t ref_count) {
    (void)is_cow; (void)ref_count;
    return handle_demand_page_fault(fault_addr, err_code);
}

struct idt_entry {
    uint16_t base_low;
    uint16_t sel;
    uint8_t  always0;
    uint8_t  flags;
    uint16_t base_high;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    addr_t   base;
} __attribute__((packed));

static struct idt_entry idt[256];
static struct idt_ptr idt_ptr;

struct idt_entry64 {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t zero;
} __attribute__((packed));

static struct idt_entry64 idt64[256] __attribute__((aligned(16)));
static struct idt_ptr idt64_ptr;

void setup_early_idt64(void) { }

char keyboard_buffer[256];
uint32_t kb_head = 0;
uint32_t kb_tail = 0;

static uint8_t ps2_e0_prefix;

static char ps2_translate(uint8_t sc) {
    if (ps2_e0_prefix) {
        ps2_e0_prefix = 0;
        if (sc >= 0x80) return 0; 
        if (sc == 0x53) return 0x7F; 
        
        return 0;
    }
    if (sc == 0xE0) {
        ps2_e0_prefix = 1;
        return 0;
    }
    if (sc >= 0x80) return 0; 

    if (sc == 0x0E) return '\b';
    if (sc == 0x0F) return '\t';
    if (sc == 0x01) return 0x1B; 

    if (sc >= 0x02 && sc <= 0x0B) return "1234567890"[sc-0x02];
    if (sc >= 0x10 && sc <= 0x19) return "qwertyuiop"[sc-0x10];
    if (sc >= 0x1E && sc <= 0x26) return "asdfghjkl"[sc-0x1E];
    if (sc >= 0x2C && sc <= 0x32) return "zxcvbnm"[sc-0x2C];

    if (sc == 0x39) return ' ';
    if (sc == 0x1C) return '\n';

    if (sc == 0x0C) return '-';
    if (sc == 0x0D) return '=';
    if (sc == 0x1A) return '[';
    if (sc == 0x1B) return ']';
    if (sc == 0x2B) return '\\';
    if (sc == 0x27) return ';';
    if (sc == 0x28) return '\'';
    if (sc == 0x29) return '`';
    if (sc == 0x33) return ',';
    if (sc == 0x34) return '.';
    if (sc == 0x35) return '/';

    return 0;
}

extern void idt_load(addr_t);
extern void isr0(void); extern void isr1(void); extern void isr2(void); extern void isr3(void);
extern void isr4(void); extern void isr5(void); extern void isr6(void); extern void isr7(void);
extern void isr8(void); extern void isr9(void); extern void isr10(void); extern void isr11(void);
extern void isr12(void); extern void isr13(void); extern void isr14(void); extern void isr15(void);
extern void isr16(void); extern void isr17(void); extern void isr18(void); extern void isr19(void);
extern void isr20(void); extern void isr21(void); extern void isr22(void); extern void isr23(void);
extern void isr24(void); extern void isr25(void); extern void isr26(void); extern void isr27(void);
extern void isr28(void); extern void isr29(void); extern void isr30(void); extern void isr31(void);
extern void isr32(void); extern void isr33(void); extern void isr34(void); extern void isr35(void);
extern void isr36(void); extern void isr37(void); extern void isr38(void); extern void isr39(void);
extern void isr40(void); extern void isr41(void); extern void isr42(void); extern void isr43(void);
extern void isr44(void); extern void isr45(void); extern void isr46(void); extern void isr47(void);
extern void isr128(void);

extern tcb_t tasks[MAX_TASKS];
extern void schedule(void);

void interrupt_handler(struct regs *r);
void page_fault_handler(struct regs *r);

void segfault_park(void);

struct interrupt_frame64 {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t int_no;
    uint64_t err_code;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

void interrupt_handler64(struct interrupt_frame64 *frame)
{
    uint64_t vector = frame->int_no;
    uint64_t *g = (uint64_t *)frame;
    uint64_t vec2 = (vector == 0x80) ? 0x80 : g[15];

    int cur = get_current_task();
    if ((frame->cs & 3) != 0 && cur > 0 && cur < MAX_TASKS) {
        tasks[cur].eip = (uint32_t)frame->rip;
        tasks[cur].esp = (uint32_t)frame->rsp;
    }

    if (vector == 14) {
        page_fault_handler((struct regs *)frame);
    } else if (vector == 32) {
        timer_handler();
        outb(0x20, 0x20);
    } else if (vector == 33) {
        /* Only consume a scancode when the controller output buffer is full,
         * so a spurious IRQ never re-reads a stale byte. */
        if (inb(0x64) & 1) {
            uint8_t scancode = inb(0x60);
            char c = ps2_translate(scancode);
            if (c) {
                keyboard_buffer[kb_tail] = c;
                kb_tail = (kb_tail + 1) % 256;
                if (kb_tail == kb_head) kb_head = (kb_head + 1) % 256;
            }
        }
        outb(0x20, 0x20);
    } else if (vector == 0x80 || vec2 == 0x80) {
        struct regs r;
        r.eax = (uint32_t)frame->rax;
        r.ebx = (uint32_t)frame->rbx;
        r.ecx = (uint32_t)frame->rcx;
        r.edx = (uint32_t)frame->rdx;
        r.esi = (uint32_t)frame->rsi;
        r.edi = (uint32_t)frame->rdi;
        r.ebp = (uint32_t)frame->rbp;
        r.esp = (uint32_t)frame->rsp;
        r.eip = (uint32_t)frame->rip;
        r.eflags = (uint32_t)frame->rflags;
        r.int_no = 0x80;
        r.err_code = (uint32_t)frame->err_code;
        r.useresp = (uint32_t)frame->rsp;
        r.cs = (uint32_t)frame->cs;
        r.ds = r.es = r.fs = r.gs = r.ss = 0x30;
        syscall_handler(&r);
        frame->rax = (uint64_t)r.eax;
    } else if (vector < 32) {
        
        if ((frame->cs & 3) != 0 && get_current_task() > 0) {
            int killed = get_current_task();
            tasks[killed].state = 0;
            schedule();
            if (killed > 0) tasks[0].state = 1;
            frame->rip    = (uint64_t)resume_shell_after_fault;
            frame->cs     = 0x08;
            frame->rflags = 0x202;
            frame->rsp    = tasks[0].kernel_stack_top;
            frame->ss     = 0x10;
        } else {
            println("64-bit EXCEPTION vector=");
            print_hex64(vector);
            println(" err=");
            print_hex64(frame->err_code);
            println(" RIP=");
            print_hex64(frame->rip);
            println(" CS=");
            print_hex64(frame->cs);
            println("");
            println("KERNEL FATAL EXCEPTION - halting");
            for (;;) { asm volatile("cli; hlt"); }
        }
    } else {
        if (vector >= 40) outb(0xA0, 0x20);
        outb(0x20, 0x20);
    }
}

void segfault_park(void) {
    for (;;) {
        asm volatile("sti; hlt");
    }
}

void pic_init(void) {
    outb(0x20, 0x11); outb(0xA0, 0x11);
    outb(0x21, 0x20); outb(0xA1, 0x28);
    outb(0x21, 0x04); outb(0xA1, 0x02);
    outb(0x21, 0x01); outb(0xA1, 0x01);
    outb(0x21, 0xFC);
    outb(0xA1, 0xFF);
}

static void keyboard_init(void) {
    uint8_t status;

    while (inb(0x64) & 2);
    outb(0x64, 0xAD);
    while (inb(0x64) & 2);
    outb(0x64, 0xA7);

    while (inb(0x64) & 1) { inb(0x60); }

    while (inb(0x64) & 2);
    outb(0x64, 0x20);
    status = inb(0x60);

    status |= (1 << 0);
    status &= ~(1 << 1);
    status |= (1 << 6);

    while (inb(0x64) & 2);
    outb(0x64, 0x60);
    outb(0x60, status);

    while (inb(0x64) & 2);
    outb(0x64, 0xAE);

    while (inb(0x64) & 2);
    outb(0x60, 0xF4);

    int got_ack = 0;
    int timeout = 100000;
    while (timeout-- > 0) {
        if (inb(0x64) & 1) {
            uint8_t ack = inb(0x60);
            if (ack == 0xFA) { got_ack = 1; break; }
        }
    }

    while (inb(0x64) & 1) { inb(0x60); }
    (void)got_ack;
}

static void serial_init(void) {
    outb(0x3F9, 0x00);
    outb(0x3FB, 0x80);
    outb(0x3F8, 0x03);
    outb(0x3F9, 0x00);
    outb(0x3FB, 0x03);
    outb(0x3FA, 0xC7);
    outb(0x3FC, 0x0B);

    outb(0x2F9, 0x00);
    outb(0x2FB, 0x80);
    outb(0x2F8, 0x03);
    outb(0x2F9, 0x00);
    outb(0x2FB, 0x03);
    outb(0x2FA, 0xC7);
    outb(0x2FC, 0x0B);
}

static void idt_set_gate(uint8_t num, addr_t base, uint16_t sel, uint8_t flags) {
    idt[num].base_low  = base & 0xFFFF;
    idt[num].base_high = (base >> 16) & 0xFFFF;
    idt[num].sel       = sel;
    idt[num].always0   = 0;
    idt[num].flags     = flags;
}

static void idt64_set_gate(uint8_t num, uint64_t handler, uint16_t sel, uint8_t ist, uint8_t type_attr)
{
    idt64[num].offset_low  = handler & 0xFFFF;
    idt64[num].selector    = sel;
    idt64[num].ist         = ist;
    idt64[num].type_attr   = type_attr;
    idt64[num].offset_mid  = (handler >> 16) & 0xFFFF;
    idt64[num].offset_high = (handler >> 32) & 0xFFFFFFFF;
    idt64[num].zero        = 0;
}

void idt_init64(void)
{

    for (int i = 0; i < 256; i++) {
        idt64[i].offset_low = 0;
        idt64[i].selector = 0;
        idt64[i].ist = 0;
        idt64[i].type_attr = 0;
        idt64[i].offset_mid = 0;
        idt64[i].offset_high = 0;
        idt64[i].zero = 0;
    }

    extern void isr0(void);  extern void isr1(void);  extern void isr2(void);  extern void isr3(void);
    extern void isr4(void);  extern void isr5(void);  extern void isr6(void);  extern void isr7(void);
    extern void isr8(void);  extern void isr9(void);  extern void isr10(void); extern void isr11(void);
    extern void isr12(void); extern void isr13(void); extern void isr14(void); extern void isr15(void);
    extern void isr16(void); extern void isr17(void); extern void isr18(void); extern void isr19(void);
    extern void isr20(void); extern void isr21(void); extern void isr22(void); extern void isr23(void);
    extern void isr24(void); extern void isr25(void); extern void isr26(void); extern void isr27(void);
    extern void isr28(void); extern void isr29(void); extern void isr30(void); extern void isr31(void);

    idt64_set_gate(0,  (uint64_t)isr0,  0x08, 0, 0x8E);
    idt64_set_gate(1,  (uint64_t)isr1,  0x08, 0, 0x8E);
    idt64_set_gate(2,  (uint64_t)isr2,  0x08, 2, 0x8E); 
    idt64_set_gate(3,  (uint64_t)isr3,  0x08, 0, 0x8E);
    idt64_set_gate(4,  (uint64_t)isr4,  0x08, 0, 0x8E);
    idt64_set_gate(5,  (uint64_t)isr5,  0x08, 0, 0x8E);
    idt64_set_gate(6,  (uint64_t)isr6,  0x08, 0, 0x8E);
    idt64_set_gate(7,  (uint64_t)isr7,  0x08, 0, 0x8E);
    idt64_set_gate(8,  (uint64_t)isr8,  0x08, 1, 0x8E); 
    idt64_set_gate(9,  (uint64_t)isr9,  0x08, 0, 0x8E);
    idt64_set_gate(10, (uint64_t)isr10, 0x08, 0, 0x8E);
    idt64_set_gate(11, (uint64_t)isr11, 0x08, 0, 0x8E);
    idt64_set_gate(12, (uint64_t)isr12, 0x08, 3, 0x8E); 
    idt64_set_gate(13, (uint64_t)isr13, 0x08, 1, 0x8E); 
    idt64_set_gate(14, (uint64_t)isr14, 0x08, 1, 0x8E); 
    extern void isr128(void);
    idt64_set_gate(0x80, (uint64_t)isr128, 0x08, 0, 0xEE);
    idt64_set_gate(15, (uint64_t)isr15, 0x08, 0, 0x8E);
    idt64_set_gate(16, (uint64_t)isr16, 0x08, 0, 0x8E);
    idt64_set_gate(17, (uint64_t)isr17, 0x08, 0, 0x8E);
    idt64_set_gate(18, (uint64_t)isr18, 0x08, 0, 0x8E);
    idt64_set_gate(19, (uint64_t)isr19, 0x08, 0, 0x8E);
    idt64_set_gate(20, (uint64_t)isr20, 0x08, 0, 0x8E);
    idt64_set_gate(21, (uint64_t)isr21, 0x08, 0, 0x8E);
    idt64_set_gate(22, (uint64_t)isr22, 0x08, 0, 0x8E);
    idt64_set_gate(23, (uint64_t)isr23, 0x08, 0, 0x8E);
    idt64_set_gate(24, (uint64_t)isr24, 0x08, 0, 0x8E);
    idt64_set_gate(25, (uint64_t)isr25, 0x08, 0, 0x8E);
    idt64_set_gate(26, (uint64_t)isr26, 0x08, 0, 0x8E);
    idt64_set_gate(27, (uint64_t)isr27, 0x08, 0, 0x8E);
    idt64_set_gate(28, (uint64_t)isr28, 0x08, 0, 0x8E);
    idt64_set_gate(29, (uint64_t)isr29, 0x08, 0, 0x8E);
    idt64_set_gate(30, (uint64_t)isr30, 0x08, 0, 0x8E);
    idt64_set_gate(31, (uint64_t)isr31, 0x08, 0, 0x8E);

    extern void isr32(void); extern void isr33(void);
    idt64_set_gate(32, (uint64_t)isr32, 0x08, 0, 0x8E);
    idt64_set_gate(33, (uint64_t)isr33, 0x08, 0, 0x8E);

    extern void isr128(void);
    idt64_set_gate(0x80, (uint64_t)isr128, 0x08, 0, 0xEE);

    idt64_ptr.limit = sizeof(idt64) - 1;
    idt64_ptr.base  = (addr_t)&idt64[0];

    __asm__ volatile ("lidt %0" : : "m"(idt64_ptr));

    keyboard_init();
}

void idt_init(void) {
    idt_ptr.limit = sizeof(struct idt_entry) * 256 - 1;
    idt_ptr.base  = (addr_t)&idt[0];

    idt_set_gate(0, (addr_t)isr0, 0x08, 0x8E);
    idt_set_gate(1, (addr_t)isr1, 0x08, 0x8E);
    idt_set_gate(2, (addr_t)isr2, 0x08, 0x8E);
    idt_set_gate(3, (addr_t)isr3, 0x08, 0x8E);
    idt_set_gate(4, (addr_t)isr4, 0x08, 0x8E);
    idt_set_gate(5, (addr_t)isr5, 0x08, 0x8E);
    idt_set_gate(6, (addr_t)isr6, 0x08, 0x8E);
    idt_set_gate(7, (addr_t)isr7, 0x08, 0x8E);
    idt_set_gate(8, (addr_t)isr8, 0x08, 0x8E);
    idt_set_gate(9, (addr_t)isr9, 0x08, 0x8E);
    idt_set_gate(10, (addr_t)isr10, 0x08, 0x8E);
    idt_set_gate(11, (addr_t)isr11, 0x08, 0x8E);
    idt_set_gate(12, (addr_t)isr12, 0x08, 0x8E);
    idt_set_gate(13, (addr_t)isr13, 0x08, 0x8E);
    idt_set_gate(14, (addr_t)isr14, 0x08, 0x8E);
    idt_set_gate(15, (addr_t)isr15, 0x08, 0x8E);
    idt_set_gate(16, (addr_t)isr16, 0x08, 0x8E);
    idt_set_gate(17, (addr_t)isr17, 0x08, 0x8E);
    idt_set_gate(18, (addr_t)isr18, 0x08, 0x8E);
    idt_set_gate(19, (addr_t)isr19, 0x08, 0x8E);
    idt_set_gate(20, (addr_t)isr20, 0x08, 0x8E);
    idt_set_gate(21, (addr_t)isr21, 0x08, 0x8E);
    idt_set_gate(22, (addr_t)isr22, 0x08, 0x8E);
    idt_set_gate(23, (addr_t)isr23, 0x08, 0x8E);
    idt_set_gate(24, (addr_t)isr24, 0x08, 0x8E);
    idt_set_gate(25, (addr_t)isr25, 0x08, 0x8E);
    idt_set_gate(26, (addr_t)isr26, 0x08, 0x8E);
    idt_set_gate(27, (addr_t)isr27, 0x08, 0x8E);
    idt_set_gate(28, (addr_t)isr28, 0x08, 0x8E);
    idt_set_gate(29, (addr_t)isr29, 0x08, 0x8E);
    idt_set_gate(30, (addr_t)isr30, 0x08, 0x8E);
    idt_set_gate(31, (addr_t)isr31, 0x08, 0x8E);

    idt_set_gate(32, (addr_t)isr32, 0x08, 0x8E);
    idt_set_gate(33, (addr_t)isr33, 0x08, 0x8E);
    idt_set_gate(34, (addr_t)isr34, 0x08, 0x8E);
    idt_set_gate(35, (addr_t)isr35, 0x08, 0x8E);
    idt_set_gate(36, (addr_t)isr36, 0x08, 0x8E);
    idt_set_gate(37, (addr_t)isr37, 0x08, 0x8E);
    idt_set_gate(38, (addr_t)isr38, 0x08, 0x8E);
    idt_set_gate(39, (addr_t)isr39, 0x08, 0x8E);
    idt_set_gate(40, (addr_t)isr40, 0x08, 0x8E);
    idt_set_gate(41, (addr_t)isr41, 0x08, 0x8E);
    idt_set_gate(42, (addr_t)isr42, 0x08, 0x8E);
    idt_set_gate(43, (addr_t)isr43, 0x08, 0x8E);
    idt_set_gate(44, (addr_t)isr44, 0x08, 0x8E);
    idt_set_gate(45, (addr_t)isr45, 0x08, 0x8E);
    idt_set_gate(46, (addr_t)isr46, 0x08, 0x8E);
    idt_set_gate(47, (addr_t)isr47, 0x08, 0x8E);

    idt_set_gate(0x80, (addr_t)isr128, 0x08, 0xEE);

    pic_init();
    keyboard_init();
    serial_init();
    idt_load((addr_t)&idt_ptr);

    asm volatile("sti");
}

void page_fault_handler(struct regs *r) {
    addr_t fault_addr;
    asm volatile("mov %%cr2, %0" : "=r"(fault_addr));

    uint32_t err = r->err_code;
    int cur = get_current_task();
#if defined(__x86_64__)
    if (cur > 0 && (fault_addr >= USER_AREA_BASE || fault_addr >= 0xA00000)) {
        int action = rust_handle_demand_page_fault(fault_addr, err, 0, 1);
        if (action == 0 || action == 1) {
            if (handle_demand_page_fault(fault_addr, err) == 0) {
                return;
            }
        } else if (action == 2) {
            return;
        }
    }
#else
    if ((err & 1) == 0 && cur > 0 && fault_addr >= USER_AREA_BASE) {
        bool is_cow = false;
        uint16_t ref_count = 1;

        uint32_t pd_index = fault_addr >> 22;
        uint32_t pt_index = (fault_addr >> 12) & 0x3FF;
        pde_t *pd = (pde_t *)(addr_t)RECURSIVE_PD_VADDR;
        if ((pd[pd_index] & PAGE_PRESENT) != 0) {
            pte_t *pt = (pte_t *)((addr_t)RECURSIVE_PT_VADDR + (pd_index * PAGE_SIZE));
            pte_t entry = pt[pt_index];
            if ((entry & (1 << 9)) != 0) {
                is_cow = true;
            }
            ref_count = 1;
        }

        int action = rust_handle_demand_page_fault(fault_addr, err, is_cow, ref_count);

        if (action == 0 || action == 1) {
            if (handle_demand_page_fault(fault_addr, err) == 0) {
                return;
            }
        } else if (action == 2) {
            return;
        }
    }
#endif
    bool allowed = rust_validate_page_fault(cur, fault_addr, err);

    if (!allowed) {
        int killed = get_current_task();
        if (killed == 0 || (((struct regs *)r)->cs & 3) == 0) {
            println("PAGE FAULT at ");
            print_hex(fault_addr);
            println(" err=");
            print_hex(err);
            println(" task=");
            print_hex(killed);
            println("Rejected by validator - killing task ");
            print_hex(killed);
            println("");
        }
        tasks[killed].state = 0;
        schedule();
        if (killed > 0) tasks[0].state = 1;

#if defined(__x86_64__)
        struct interrupt_frame64 *f64 = (struct interrupt_frame64 *)r;
        if ((killed > 0) && (f64->cs & 3)) {
            f64->rip    = (uint64_t)resume_shell_after_fault;
            f64->cs     = 0x08;
            f64->rflags = 0x202;
            f64->rsp    = tasks[0].kernel_stack_top;
            f64->ss     = 0x10;
        }
#endif
        if (killed == 0) {
            asm volatile("cli; hlt");
        }
        return;
    }

    asm volatile("cli; hlt");
}

void interrupt_handler(struct regs *r) {
    if (r->int_no == 0x80) {
        syscall_handler(r);
    } else if (r->int_no == 14) {
        page_fault_handler(r);
    } else if (r->int_no < 32) {
        if (r->int_no == 1) {
            return;
        }
        println("Exception! Vector: ");
        print_hex(r->int_no);
        println(" at EIP=");
        print_hex(r->eip);
        println("");
        asm volatile("cli; hlt");
    } else if (r->int_no >= 32 && r->int_no < 48) {
        if (r->int_no == 32) {
            if (get_current_task() < MAX_TASKS && !tasks[get_current_task()].in_kernel) {
                uint32_t uesp = r->useresp;
                if (uesp > 0x400000 && (r->cs & 3) == 3) {
                    tasks[get_current_task()].esp = uesp;
                    tasks[get_current_task()].eip = r->eip;
                }
            }
            timer_handler();
        } else if (r->int_no == 33) {
            uint8_t scancode = inb(0x60);
            char c = ps2_translate(scancode);
            if (c) {
                keyboard_buffer[kb_tail] = c;
                kb_tail = (kb_tail + 1) % 256;
                if (kb_tail == kb_head) kb_head = (kb_head + 1) % 256;
            }
        }
        if (r->int_no >= 40) outb(0xA0, 0x20);
        outb(0x20, 0x20);
    }
}
