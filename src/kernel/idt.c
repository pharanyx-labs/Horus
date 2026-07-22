#include "kernel.h"

int handle_demand_page_fault(uint64_t fault_addr, uint32_t err_code);

struct idt_ptr {
    uint16_t limit;
    addr_t   base;
} __attribute__((packed));

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

/* IRQ -> userspace notification bridge (J4, driver privilege separation): a task
 * holding CAP_IO_DEVICE can register (SYS_IRQ_REGISTER) to be sent an async
 * notification each time a hardware IRQ fires, so a ring-3 driver (the console
 * server) can service the device instead of the kernel. Only IRQ0 (timer, for a
 * periodic serial re-poll wake) and IRQ1 (keyboard) are routable.
 *
 * sys_notify is safe to call from the ISR: syscalls and IRQs both run behind
 * interrupt gates (IF=0), so no code on this CPU can be holding ipc_lock when the
 * ISR takes it (no same-CPU deadlock); under SMP it is ordinary brief spinlock
 * contention. See docs/proposals/console-server.md. */
#define IRQ_NOTIFY_MAX 2      /* index 0 = IRQ0 (timer), 1 = IRQ1 (keyboard) */
struct irq_notify_reg { int task; uint32_t slot; uint32_t badge; int active; };
static struct irq_notify_reg irq_reg[IRQ_NOTIFY_MAX];
extern int sys_notify(uint32_t notif_slot, uint32_t badge);

/* Register `task` to receive notification (`slot`, `badge`) on `irq`. Called by
 * the SYS_IRQ_REGISTER handler, which has already enforced CAP_IO_DEVICE. */
int irq_notify_register(int irq, int task, uint32_t slot, uint32_t badge) {
    if (irq < 0 || irq >= IRQ_NOTIFY_MAX) return -1;
    irq_reg[irq].task   = task;
    irq_reg[irq].slot   = slot;
    irq_reg[irq].badge  = badge;
    irq_reg[irq].active = 1;
    return 0;
}

/* Drop any IRQ registrations owned by `task`. Called from task_teardown so a dead
 * task's slot cannot keep receiving IRQ notifications (or leak onto a later task
 * that reuses the notification slot). */
void irq_notify_clear_task(int task) {
    for (int i = 0; i < IRQ_NOTIFY_MAX; i++)
        if (irq_reg[i].active && irq_reg[i].task == task)
            irq_reg[i].active = 0;
}

static inline void irq_notify_fire(int irq) {
    if (irq_reg[irq].active)
        sys_notify(irq_reg[irq].slot, irq_reg[irq].badge);
}

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

#ifdef SMP
extern void lapic_eoi(void);                    /* scheduler.c */
extern volatile unsigned long ap_timer_ticks;   /* scheduler.c */
extern void smp_ack_shootdown(void);            /* scheduler.c */
#endif

/* Returns non-zero kernel %rsp to resume on (task switch), or 0 to keep frame. */
uint64_t page_fault_handler(struct interrupt_frame64 *f64);

void segfault_park(void);

/* Redirect a ring-3 fault into the task's registered signal handler instead of
 * killing it. Returns 1 if delivered (the caller must return into the handler),
 * 0 to fall through to the normal kill path. Preconditions enforced here:
 *   - the fault came from ring 3 (cs & 3),
 *   - the task is not already inside a handler (in_signal) -- a fault *in* the
 *     handler is NOT redirected, so a faulting handler cannot loop,
 *   - a handler is registered and its address is inside the user code window
 *     (validated in safe Rust; fail closed).
 * On delivery the full pre-signal trap frame is saved for SYS_SIGRETURN, and the
 * live frame is rewritten to enter the handler in ring 3 with the signal number
 * in ebx and the faulting address in ecx. cs/ss are unchanged, so the handler
 * runs at ring 3 -- no new privilege is granted. rsp is the interrupted user
 * stack, UNLESS the task registered an alternate signal stack (SYS_SIGALTSTACK)
 * and is not already running on it, in which case the handler runs on that stack
 * (SS_ONSTACK) so a corrupt or overflowed primary stack cannot stop the handler
 * from running; sigreturn clears the on-stack flag. */
int try_deliver_fault_signal(struct interrupt_frame64 *frame, int cur,
                             uint32_t signum, uint64_t fault_addr) {
    if (cur <= 0 || cur >= MAX_TASKS) return 0;
    if ((frame->cs & 3) == 0)         return 0;   /* ring-0 fault: never */
    if (tasks[cur].in_signal)         return 0;   /* fault inside handler -> kill */
    /* uint64_t: sig_handler is a full user code address, and narrowing it here
     * would compare a truncated value against the task's real image bounds. */
    uint64_t h = tasks[cur].sig_handler;
    if (h == 0 || !rust_signal_handler_addr_ok(h, tasks[cur].image_base,
                                                  tasks[cur].image_end)) return 0;

    /* Pick the handler's stack before saving the frame, so sig_frame keeps the
     * interrupted rsp for an exact SYS_SIGRETURN. Align the altstack top to 16
     * bytes minus 8 to reproduce the rsp%16==8 a normal call-entry would give. */
    uint64_t hrsp = frame->rsp;
    if (tasks[cur].sig_altstack_size && !tasks[cur].sig_on_stack) {
        hrsp = ((uint64_t)tasks[cur].sig_altstack_sp +
                (uint64_t)tasks[cur].sig_altstack_size) & ~0xFULL;
        hrsp -= 8;
        tasks[cur].sig_on_stack = 1;
    }

    tasks[cur].sig_frame = *frame;     /* full context for SYS_SIGRETURN */
    tasks[cur].in_signal = 1;

    frame->rip     = (uint64_t)h;
    frame->rsp     = hrsp;                  /* interrupted stack, or the altstack */
    frame->rbx     = (uint64_t)signum;     /* ebx = signal number */
    frame->rcx     = fault_addr;           /* ecx = faulting address (0 if n/a) */
    frame->rflags |= 0x200;                /* ensure IF set while the handler runs */
    return 1;
}

static uint64_t interrupt_handler64_inner(struct interrupt_frame64 *frame)
{
    uint64_t vector = frame->int_no;
    uint64_t *g = (uint64_t *)frame;
    uint64_t vec2 = (vector == 0x80) ? 0x80 : g[15];

    int cur = get_current_task();
    if ((frame->cs & 3) != 0 && cur > 0 && cur < MAX_TASKS) {
        tasks[cur].eip = frame->rip;
        tasks[cur].esp = frame->rsp;
    }

    if (vector == 14) {
        uint64_t pf_rsp = page_fault_handler(frame);
        if (pf_rsp) return pf_rsp;
    } else if (vector == 32) {
        /* Timer (IRQ0). EOI first so the PIC keeps delivering ticks even
         * across a task switch, then let the preemptive scheduler decide
         * whether to switch. preempt_on_tick returns the kernel %rsp to resume
         * on: the current frame (no switch) or the next task's saved frame. */
        outb(0x20, 0x20);
        timer_handler();
        /* Wake a registered driver (e.g. the console server's serial re-poll)
         * before the scheduler decides who runs next, so a newly-runnable waiter
         * is eligible on this same tick. */
        irq_notify_fire(0);
        return preempt_on_tick((uint64_t)frame, frame->cs);
    } else if (vector == 33) {
        if (irq_reg[1].active) {
            /* A userspace driver owns the keyboard: leave the scancode in the PS/2
             * output buffer for it to inb(0x60) itself (the buffer staying full
             * naturally gates the next IRQ until it reads), and just EOI + notify.
             * The kernel does not translate or buffer it here. */
            outb(0x20, 0x20);
            irq_notify_fire(1);
        } else {
            /* No driver registered: the in-kernel console reader owns the key.
             * Only consume a scancode when the controller output buffer is full,
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
        }
#ifdef SMP
    } else if (vector == 0x40) {
        /* LAPIC timer: the application processors' preemption tick (the legacy
         * PIC IRQ0 only reaches the BSP). EOI to the local APIC, then let the
         * preemptive scheduler decide whether to switch this CPU's task. */
        lapic_eoi();
        __sync_fetch_and_add(&ap_timer_ticks, 1ul);
        return preempt_on_tick((uint64_t)frame, frame->cs);
    } else if (vector == 0xFB) {
        /* TLB-shootdown IPI: a remote CPU changed a shared mapping. Flush this
         * CPU's TLB (reload CR3 drops all non-global entries) and acknowledge. */
        uint64_t cr3;
        __asm__ volatile ("mov %%cr3, %0" : "=r"(cr3));
        __asm__ volatile ("mov %0, %%cr3" :: "r"(cr3) : "memory");
        smp_ack_shootdown();
        lapic_eoi();
        return (uint64_t)frame;
#endif
    } else if (vector == 0x80 || vec2 == 0x80) {
        int scur = get_current_task();
        if ((uint32_t)frame->rax == SYS_SIGRETURN && scur > 0 && scur < MAX_TASKS
            && tasks[scur].in_signal) {
            /* Handled ahead of the dispatch, not via the syscall table:
             * restoring the pre-signal context replaces the ENTIRE live trap
             * frame -- rip, rsp and every register -- and then returns it
             * untouched, so it has nothing to do with the table's
             * argument/return-value convention. Exact resume of the
             * interrupted instruction. */
            *frame = tasks[scur].sig_frame;
            tasks[scur].in_signal = 0;
            tasks[scur].sig_on_stack = 0;   /* left the alternate signal stack */
            return (uint64_t)frame;
        }
        /* Dispatch on the real trap frame. This used to marshal the frame into
         * a 32-bit `struct regs`, call the handler on that copy, and write two
         * fields back -- which silently truncated every register to 32 bits.
         * Handlers now read arguments from, and write their return value to,
         * the frame the CPU actually pushed. SYS_WAIT_NOTIFY still returns its
         * badge in rbx; it just writes it directly now. */
        int ipc_caller = get_current_task();
        syscall_handler(frame);
        /* SYS_EXEC_NAMED replaced the caller's image in place and fabricated a
         * fresh ring-3 context for it at the top of its kernel stack — which is
         * the SAME memory as this trap `frame`. Resume that context via the
         * saved-frame path (installs the new CR3 + kernel stack). */
        if (g_exec_reenter_task > 0) {
            int t = g_exec_reenter_task;
            g_exec_reenter_task = -1;
            return exec_reenter_switch(t);
        }
        /* SYS_YIELD: voluntary full-context switch (same path as preemption). */
        if (g_want_yield == ipc_caller) {
            g_want_yield = -1;
            return sched_yield_switch(ipc_caller, (uint64_t)frame);
        }
        /* SYS_IPC_CALL / SYS_WAIT_NOTIFY / SYS_WAIT: handlers set pending_block
         * only. ipc_block_switch saves the frame first, then publishes the
         * waiter so a cross-CPU wake cannot race a null/stale saved_ksp. */
        if (ipc_caller > 0 && ipc_caller < MAX_TASKS) {
            int st = (int)tasks[ipc_caller].state;
            if (tasks[ipc_caller].pending_block != 0 ||
                st == TASK_BLOCKED_IPC || st == TASK_BLOCKED_NOTIF ||
                st == TASK_BLOCKED_WAIT) {
                return ipc_block_switch(ipc_caller, (uint64_t)frame);
            }
            /* SYS_EXIT / SYS_KILL-self: the caller terminated itself. It is dead;
             * do not iretq back into it. Resume the next runnable task via its
             * saved trap frame (the same mechanism the timer uses); if nothing
             * else is runnable, fall back to the kernel reaper on task 0's stack. */
            if (st == 0) {
                uint64_t rsp = task_exit_switch(ipc_caller);
                if (rsp) return rsp;
                frame->rip    = (uint64_t)resume_shell_after_fault;
                frame->cs     = 0x08;
                frame->rflags = 0x202;
                frame->rsp    = tasks[0].kernel_stack_top;
                frame->ss     = 0x10;
                return (uint64_t)frame;
            }
        }
    } else if (vector < 32) {

        if ((frame->cs & 3) != 0 && get_current_task() > 0) {
            int cur = get_current_task();
            uint32_t signum = (vector == 6) ? SIG_ILL : SIG_SEGV; /* #UD vs other */
            /* Fail-safe: a faulting console owner loses the console, so the kernel
             * drives it again. This holds whether the task is torn down (below) or
             * survives via a fault-signal handler — a driver that just faulted may
             * be compromised and must not keep muting the kernel's own console
             * (which is how the blast-radius self-test reports containment). */
            console_clear_owner(cur);
            if (!try_deliver_fault_signal(frame, cur, signum, 0)) {
                int killed = cur;
                /* Tear the task down — marks it dead AND wakes any SYS_WAIT
                 * waiter (e.g. init supervising the shell) — then resume the
                 * next runnable task via its saved frame, exactly as the
                 * SYS_EXIT path does. The old code raw-set state=0 and spun the
                 * cooperative schedule(), which never woke a blocked waiter, so
                 * a faulting shell left a blocking init asleep forever. */
                /* Say something before the task disappears. A ring-3 fault with
                 * no handler used to kill the task in total silence, which made a
                 * crashed init/shell look like a hang and cost real debugging time.
                 * Deliberately worded to avoid the smoke suite's failure regex
                 * (PAGE FAULT / Exception! Vector / PANIC / Rejected by validator):
                 * the faulter and signal tests fault ON PURPOSE and must stay green,
                 * so this is a diagnostic, not a failure marker. */
                print("[task "); print_decimal((uint64_t)killed);
                print(" '"); print(tasks[killed].name);
                print("' killed: ring-3 trap vector "); print_decimal(vector);
                print(" at rip="); print_hex64(frame->rip);
                print(" rsp="); print_hex64(frame->rsp);
                print("]\n");
                task_teardown(killed);
                uint64_t rsp = task_exit_switch(killed);
                if (rsp) return rsp;
                /* Nothing else runnable: fall back to the kernel reaper/idle on
                 * task 0's stack. */
                frame->rip    = (uint64_t)resume_shell_after_fault;
                frame->cs     = 0x08;
                frame->rflags = 0x202;
                frame->rsp    = tasks[0].kernel_stack_top;
                frame->ss     = 0x10;
            }
            /* else: signal delivered -> fall through to `return frame`, and the
             * ISR epilogue iretq's into the handler at ring 3. */
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

    /* Default (non-timer, non-switching) path: resume on the same trap frame,
     * i.e. return exactly into the interrupted context. */
    return (uint64_t)frame;
}

/* FPU/SSE context switch. Wraps the dispatcher rather than living inside it
 * because the dispatcher has many exit points (timer switch, IPC block, yield,
 * exec re-enter, exit switch) and every one of them can resume a DIFFERENT task
 * than the one that trapped; doing it here means there is exactly one place that
 * has to be right.
 *
 * Save on entry from ring 3, restore on return to ring 3 -- keyed on the CURRENT
 * task at each moment, which is what makes a switch work: the handler may have
 * changed it, so the restore reads the task we are actually about to iretq into.
 * A ring-0 -> ring-0 interrupt is skipped entirely: the kernel owns no FPU state
 * (it is built -mno-sse), so there is nothing to save and nothing to restore. */
uint64_t interrupt_handler64(struct interrupt_frame64 *frame)
{
    int from_user = (frame->cs & 3) != 0;
    if (from_user) fpu_save(get_current_task());

    uint64_t rsp = interrupt_handler64_inner(frame);

    struct interrupt_frame64 *out = (struct interrupt_frame64 *)rsp;
    if (out && (out->cs & 3) != 0) fpu_restore(get_current_task());
    return rsp;
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

/* Program PIT channel 0 for a fixed periodic tick so the preemptive scheduler
 * has a deterministic quantum instead of the undefined power-on reload value.
 * 1193182 Hz / 11932 ~= 100 Hz => a 10 ms time slice. Mode 3 (square wave),
 * lobyte/hibyte access. */
#define PIT_TICK_HZ 100
void pit_init(void) {
    uint32_t divisor = 1193182u / PIT_TICK_HZ;
    if (divisor > 0xFFFF) divisor = 0xFFFF;
    outb(0x43, 0x36);                         /* ch0, lo/hi, mode 3, binary */
    outb(0x40, (uint8_t)(divisor & 0xFF));
    outb(0x40, (uint8_t)((divisor >> 8) & 0xFF));
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

#ifdef SMP
    extern void isr64(void);    /* LAPIC timer (per-CPU preemption tick) */
    extern void isr251(void);   /* TLB-shootdown IPI */
    idt64_set_gate(0x40, (uint64_t)isr64,  0x08, 0, 0x8E);
    idt64_set_gate(0xFB, (uint64_t)isr251, 0x08, 0, 0x8E);
#endif

    idt64_ptr.limit = sizeof(idt64) - 1;
    idt64_ptr.base  = (addr_t)&idt64[0];

    __asm__ volatile ("lidt %0" : : "m"(idt64_ptr));

    keyboard_init();
    serial_init();   /* COM1/COM2 baud setup (the 64-bit boot's only caller) */
    pit_init();      /* periodic timer tick for preemptive scheduling */
}

/* Load the shared kernel IDT on an application processor. The IDT table is
 * global and identical for every CPU, so an AP just points IDTR at it. */
void ap_load_idt(void) {
    __asm__ volatile ("lidt %0" :: "m"(idt64_ptr) : "memory");
}

/* `f64` is the real trap frame. This used to be declared as `struct regs *`
 * while callers passed an interrupt_frame64 and cast -- the two layouts differ,
 * so `r->err_code` read a garbage field (always 0). That went unnoticed until
 * the copy-on-write path needed the write bit, and was worked around by casting
 * back to the real type to read err_code. The parameter now has the type the
 * caller actually passes, so there is nothing left to cast and nothing left to
 * read from the wrong offset. */
uint64_t page_fault_handler(struct interrupt_frame64 *f64) {
    addr_t fault_addr;
    asm volatile("mov %%cr2, %0" : "=r"(fault_addr));

    uint32_t err = (uint32_t)f64->err_code;
    int cur = get_current_task();
    /* Gate the pager on the per-task validator, not a fixed address window.
     *
     * This used to be a hardcoded `[USER_AREA_BASE, USER_HEAP_BASE + max)` —
     * [4 MiB, 80 MiB) — which was fine only while every image lived down there.
     * With image-base ASLR placing the image anywhere in the user half, a
     * legitimate fault in a high image fell outside the window, the pager was
     * never asked, and the task was torn down as if it had jumped somewhere
     * wild. And silently: a ring-3 fault prints nothing (only ring-0 / task-0
     * faults do), so the whole system just wedged with no init.
     *
     * rust_validate_page_fault already knows exactly what is pageable for this
     * task — its own image, heap and stack — so it is both the correct gate and
     * the value `allowed` needs below. It cannot over-admit the way an address
     * window could: the kernel's .bss is not in any task's user regions. */
    bool allowed = (cur > 0 && cur < MAX_TASKS) &&
        rust_validate_page_fault(fault_addr, err,
                                 tasks[cur].image_base, tasks[cur].image_end,
                                 tasks[cur].heap_start,
                                 tasks[cur].heap_end);
    if (allowed && handle_demand_page_fault(fault_addr, err) == 0) {
        return 0;
    }

    /* Fail-safe: a real ring-3 fault in the console owner reclaims the console for
     * the kernel, whether the task then survives via a handler (below) or is torn
     * down (task_teardown, further down). A driver that just faulted may be
     * compromised and must not keep muting the kernel's own console — which is how
     * the blast-radius self-test reports containment. (#PF is handled here, ahead
     * of the generic ring-3 fault path, so the reclaim is repeated in both.) */
    if (cur > 0 && (f64->cs & 3)) console_clear_owner(cur);

    /* Deliver SIGSEGV to a registered ring-3 handler instead of killing the
     * task (and without printing the fault banner). Only for a fault the
     * validator rejected: one it approved but the pager could not resolve is a
     * kernel-side inconsistency, not something to hand a task's handler. */
    if (!allowed && cur > 0 && (f64->cs & 3) &&
        try_deliver_fault_signal(f64, cur, SIG_SEGV, fault_addr)) {
        return 0;
    }

    int killed = get_current_task();
    if (killed == 0 || (f64->cs & 3) == 0) {
        println("PAGE FAULT at ");
        print_hex(fault_addr);
        println(" err=");
        print_hex(err);
        println(" task=");
        print_hex(killed);
        println(allowed ? "Approved by validator but unmappable - killing task "
                        : "Rejected by validator - killing task ");
        print_hex(killed);
        println("");
    }

    /* Kill the task, never the machine.
     *
     * We land here two ways: the validator rejected the address (a real access
     * violation — a wild pointer, a stack overflow, the kernel .bss shadow at
     * 0x570000 that a ring-3 task could once use to halt the kernel), or it
     * approved an in-region address the pager still could not map (out of physical
     * pages). The first is a clean SIGSEGV (offered above); the second is fatal.
     * Both used to be able to fall through to the `cli; hlt` below and stop the
     * kernel dead; neither is fatal to the system now.
     *
     * Note this is deliberately not conditioned on `f64->cs & 3`: the faulting
     * access can be a *supervisor* one (the kernel touching a bad user address
     * mid-syscall on this task's CR3, err bit 2 clear). Blaming only ring-3
     * faults would leave exactly that case halting the machine.
     *
     * Only a fault with no task to blame (cur == 0, the kernel's own context)
     * still halts — there is nothing to kill and continuing would be worse. */
    if (killed > 0) {
        task_teardown(killed);
        uint64_t rsp = task_exit_switch(killed);
        if (rsp) return rsp;
        f64->rip    = (uint64_t)resume_shell_after_fault;
        f64->cs     = 0x08;
        f64->rflags = 0x202;
        f64->rsp    = tasks[0].kernel_stack_top;
        f64->ss     = 0x10;
        return 0;
    }

    asm volatile("cli; hlt");
    return 0;
}

