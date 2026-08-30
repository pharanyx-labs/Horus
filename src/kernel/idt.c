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
 * holding a CAP_IO_DEVICE that DECLARES a line can register (SYS_IRQ_REGISTER) to
 * be sent an async notification each time that hardware IRQ fires, so a ring-3
 * driver services the device instead of the kernel. Every line 0..15 is routable
 * since 2026-08-28; before that only IRQ0 and IRQ1 were even unmasked at the PIC,
 * so a PCI line could not be delivered whatever a driver held.
 *
 * sys_notify is safe to call from the ISR: syscalls and IRQs both run behind
 * interrupt gates (IF=0), so no code on this CPU can be holding ipc_lock when the
 * ISR takes it (no same-CPU deadlock); under SMP it is ordinary brief spinlock
 * contention. See docs/design/console-server.md. */
struct irq_notify_reg { int task; uint32_t slot; uint32_t badge; int active; };
static struct irq_notify_reg irq_reg[IRQ_NOTIFY_MAX];
extern int sys_notify(uint32_t notif_slot, uint32_t badge);

/* ---- 8259 line masking --------------------------------------------------
 *
 * Which lines are unmasked is AUTHORITY, and it is why these live here rather
 * than being set once in pic_init. Until 2026-08-28 the master was programmed
 * 0xFC at boot -- IRQ 0 and 1 unmasked, everything else masked including bit 2,
 * the cascade -- so no PCI line could be DELIVERED whatever capability a driver
 * held (docs/LIMITATIONS.md 2.13, now closed). A line is unmasked when
 * SYS_IRQ_REGISTER accepts a capability for it, and masked again when that
 * registration goes away.
 *
 * Lines 8-15 arrive through the slave PIC on master line 2, so unmasking one of
 * them also means unmasking the cascade; masking the last of them does NOT mask
 * the cascade again, because leaving it unmasked costs nothing and getting the
 * bookkeeping wrong costs a line that silently stops being delivered. */
static void pic_set_masked(int irq, int masked) {
    if (irq < 0 || irq > 15) return;

    /* One entry point, two controllers. When an I/O APIC is up it OWNS routing
     * and the 8259 is fully masked, so masking must go to the redirection table
     * or it writes a register nothing consults -- a line that stays live while
     * the kernel believes it masked one, which is S46's storm arriving through a
     * bookkeeping error rather than a missing check. */
    if (ioapic_active()) { ioapic_set_irq(irq, masked); return; }

    uint16_t port = (irq < 8) ? 0x21 : 0xA1;
    uint8_t  bit  = (uint8_t)(1u << (irq & 7));
    uint8_t  m    = inb(port);
    if (masked) m |= bit; else m = (uint8_t)(m & ~bit);
    outb(port, m);
    if (!masked && irq >= 8) {
        uint8_t mm = inb(0x21);
        outb(0x21, (uint8_t)(mm & ~(1u << 2)));   /* the cascade */
    }
}

/* Acknowledge an interrupt to whichever controller delivered it.
 *
 * The LAPIC's EOI register when the I/O APIC is routing, the 8259's when it is
 * not. Sending the wrong one is not a no-op: EOIing the PIC while the LAPIC
 * holds the in-service bit leaves that priority level blocked, and every
 * lower-priority interrupt after it is silently dropped. */
static void irq_eoi(uint64_t vector) {
    if (ioapic_active()) {
        *(volatile uint32_t *)0xFEE000B0UL = 0;   /* LAPIC EOI */
        return;
    }
    if (vector >= 40) outb(0xA0, 0x20);
    outb(0x20, 0x20);
}

/* Register `task` to receive notification (`slot`, `badge`) on `irq`, and unmask
 * the line. Called by the SYS_IRQ_REGISTER handler, which has already enforced
 * that the caller holds a CAP_IO_DEVICE naming a device that DECLARES this line
 * (S43) -- so the unmask below is the capability taking effect in hardware. */
int irq_notify_register(int irq, int task, uint32_t slot, uint32_t badge) {
    if (irq < 0 || irq >= IRQ_NOTIFY_MAX) return -1;
    irq_reg[irq].task   = task;
    irq_reg[irq].slot   = slot;
    irq_reg[irq].badge  = badge;
    irq_reg[irq].active = 1;
    pic_set_masked(irq, 0);
    return 0;
}

/* Drop any IRQ registrations owned by `task`, and MASK the lines they held.
 *
 * Called from task_teardown. The mask is the load-bearing half: a legacy PCI
 * interrupt is level-triggered, so a device whose driver has died keeps the line
 * asserted forever. Leaving it unmasked with nobody to service it is an
 * interrupt storm that no later task can stop -- the machine simply stops making
 * progress. A dead driver must take its line down with it.
 *
 * IRQ 0 is exempt: the timer is the preemption tick and masking it would stop the
 * scheduler. Nothing registers for IRQ 0 except a console server asking for a
 * periodic wake, and the kernel needs that line regardless of who is listening. */
void irq_notify_clear_task(int task) {
    for (int i = 0; i < IRQ_NOTIFY_MAX; i++)
        if (irq_reg[i].active && irq_reg[i].task == task) {
            irq_reg[i].active = 0;
            if (i != 0) pic_set_masked(i, 1);
        }
}

/* Re-unmask a line after its driver has serviced the device. The authority check
 * is the caller's (h_irq_ack); by here the capability has already been shown to
 * name a device that declares this line, and to belong to the task that holds the
 * registration. */
int irq_notify_ack(int irq, int task) {
    if (irq < 0 || irq >= IRQ_NOTIFY_MAX) return -1;
    if (!irq_reg[irq].active || irq_reg[irq].task != task) return -1;
    pic_set_masked(irq, 0);
    return 0;
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

#ifdef KFAULT_INJECT
/* Test-only. Reproduces G-8's signature on purpose: a supervisor read of a low
 * address, taken on a timer tick AFTER a ring-3 console_server owns the
 * console. That last condition is the whole point -- it is the only state in
 * which the kernel's fault report used to be inaudible, and therefore the only
 * state in which "the report reached the wire" is a claim worth gating.
 *
 * 0x94 is not arbitrary: it is the exact address G-8 faults on, so a passing
 * gate and a real occurrence produce the same line.
 *
 * Absent from every shipping configuration; KFAULT_INJECT is set by
 * `make smoke-kfault` and nothing else. */
static void kfault_inject_tick(void) {
    static unsigned owned_ticks = 0;
    if (!console_hw_owned()) return;
    if (++owned_ticks != (unsigned)KFAULT_INJECT_TICKS) return;
    volatile uint64_t *p = (volatile uint64_t *)0x94UL;
    (void)*p;
}
#endif

#ifdef RESUME_RSP_INJECT
/* Test-only. Forces the dispatcher's resume %rsp to a bogus value ONCE, after
 * the console handover, so the floor guard in interrupt_handler64 can be gated
 * in seconds instead of waited on at G-8's ~1-in-150.
 *
 * The value is 4 for the same reason kfault_inject_tick() uses 0x94: it is the
 * literal value the 2026-08-13 capture recorded (cpu 0, resume %rsp = 4), so a
 * passing gate and a real occurrence produce the same line.
 *
 * The injection is deliberately placed on the RETURN of the dispatcher rather
 * than inside a switch path. This gate's question is "is the guard audible when
 * it fires", not "which path produces the bad value" -- the latter is still open
 * (G-8) and is not something a test-only hook is entitled to assume.
 *
 * RESUME_RSP_INJECT_PRECLAIM=1 takes the permanent panic claim first, which is
 * the state another CPU's fatal exception leaves behind. That is the arm that
 * witnesses the defect this file fixes: before it, the guard's report was
 * bracketed with fatal=1 and lost the claim silently, so nothing reached the
 * wire at all.
 *
 * Absent from every shipping configuration; set by `make smoke-resume-guard*`
 * and nothing else. */
static uint64_t resume_rsp_inject(uint64_t rsp)
{
    /* volatile, and not a literal `return 4`: with a constant the compiler folds
     * `4 < 0xFFFF800000000000` at compile time and jumps straight into the
     * guard's report, so the arm would prove the REPORT works while never
     * executing the cmp/jae a real occurrence goes through. An opaque value
     * makes the gate exercise the same two instructions.
     *
     * The value is settable because the guard has two halves to witness and 4
     * only exercises one of them. RESUME_RSP_INJECT_VALUE=-7 drives the ceiling
     * added for the negative case -- which is the value a real boot produced,
     * so that arm and a real occurrence still print the same line. */
    static volatile uint64_t bogus = (uint64_t)(RESUME_RSP_INJECT_VALUE);
    static volatile int fired = 0;
    static unsigned owned_ticks = 0;

    if (fired) return rsp;
    if (!console_hw_owned()) return rsp;
    if (++owned_ticks < (unsigned)RESUME_RSP_INJECT_TICKS) return rsp;
    if (__sync_lock_test_and_set(&fired, 1)) return rsp;
#ifdef RESUME_RSP_INJECT_PRECLAIM
    kfault_claim_permanently_for_test();
#endif
    return bogus;
}
#endif

/* ---- Is this a resume %rsp the ISR epilogue may legally load? --------------
 *
 * The guard used to ask only `rsp < 0xFFFF800000000000ULL`: a floor, no ceiling.
 * That catches a returned 0, 1 or 4 and misses every small NEGATIVE value,
 * because -7 is 0xFFFFFFFFFFFFFFF9 and sits *above* the floor. The comment above
 * the old test said it was there to catch "a returned 0/1/-1", and it caught two
 * of those three. Observed, not theorised: a boot of the PROC_SELFTEST workload
 * at -smp 4 put -7 into %rsp, sailed through the guard, and faulted at rsp-8
 * inside the epilogue's first push with a banner naming the stub and nothing
 * about where the value came from -- exactly the obscurity this guard exists to
 * remove.
 *
 * So bound it at both ends, and bound it from the LINKER rather than a constant:
 * a stack that MOVES still satisfies a section-derived bound, while one allocated
 * somewhere new fails loudly instead of silently widening the guard.
 *
 * TWO RANGES, and the second one is the whole lesson of this function.
 *
 * The first version of this guard used [__bss_start, __bss_end) alone, on the
 * stated premise that "every kernel stack in a 64-bit context is a .bss array",
 * listing stack_top, ist{1,2,3}_stack_top and early_handler_stack_top together as
 * multiboot.S .bss objects. Four of those five are. The IST stacks are NOT: they
 * are emitted in multiboot.S's .data block beside gdt64/tss64, well below
 * __bss_start (0x...1a8000 against a __bss_start of 0x...1b0000 in the build that
 * caught this). The premise was checked against the .bss arrays it named and never
 * against the three objects it got wrong.
 *
 * IST1 serves #DF/#GP/#PF. So a bss-only bound rejects the legal resume %rsp of
 * every page fault taken through IST1 -- and this guard's response to a rejection
 * is to halt the CPU, fail-closed. The kernel therefore died on the first ring-3
 * page fault of any workload that took one: `CAPTEST: PASS 100 checks` became
 * "PANIC: dispatcher returned a bogus resume rsp=0xffffffff801a9f50", which is an
 * address 0xf50 into ist1_stack_bottom's page and about as legal as a resume value
 * gets. Ten CI gates went red together, all of them userspace workloads.
 *
 * The bug is instructive because the guard's own witnesses could not see it. Both
 * arms inject a bogus value and ask whether the report APPEARS -- they measure
 * false negatives. Nothing asked whether the guard stays silent on a LEGAL value,
 * so a predicate that rejected everything would have passed every test the commit
 * shipped with. smoke-resume-guard-ist is that missing arm; see TESTS.md.
 *
 * The two legal ranges:
 *
 *   [__bss_start, __bss_end)          stack_top and early_handler_stack_* plus
 *                                     per_task_kstacks[] (paging.c) and
 *                                     ap_idle_stacks[] (smp.c) -- every task
 *                                     stack, task 0's included, and every
 *                                     per-CPU idle/park stack.
 *   [ist1_stack_guard, ist3_stack_top) the IST cluster, in .data.
 *
 * The IST bracket spans the three guard pages as well as the three stacks. That
 * is deliberate and not a widening worth avoiding: kern_fixed_stack_guards_init()
 * unmaps those pages, so a resume onto one faults on the very first push whether
 * this predicate accepts it or not. Six contiguous pages named by two linker
 * symbols is cheaper on a path that runs at every interrupt return than three
 * separate range tests, and multiboot.S carries the comment that keeps the
 * cluster contiguous.
 *
 * (boot_stack_top is in .boot.data, but it is the 32-bit early stack and long
 * mode is entered before interrupt_handler64 exists, so it is never a resume
 * value.)
 *
 * RESUME_GUARD_FLOOR_ONLY=1 restores the floor-only test -- the missing ceiling,
 * on demand -- and is what `make smoke-resume-guard-negative-control` builds.
 * RESUME_GUARD_BSS_ONLY=1 restores the bss-only bound described above, the
 * false-positive on demand, for `make smoke-resume-guard-ist-control`.
 * RESUME_GUARD_DISABLE removes the guard entirely, which is a different arm with
 * a different question (see smoke-resume-guard). */
static int resume_rsp_is_bogus(uint64_t rsp)
{
#ifdef RESUME_GUARD_FLOOR_ONLY
    return rsp < 0xFFFF800000000000ULL;
#else
    extern uint8_t __bss_start[], __bss_end[];
    if (rsp >= (uint64_t)(uintptr_t)__bss_start &&
        rsp <  (uint64_t)(uintptr_t)__bss_end)
        return 0;
#ifndef RESUME_GUARD_BSS_ONLY
    extern uint8_t ist1_stack_guard[], ist3_stack_top[];
    if (rsp >= (uint64_t)(uintptr_t)ist1_stack_guard &&
        rsp <  (uint64_t)(uintptr_t)ist3_stack_top)
        return 0;
#endif
    /* The per-task kernel stacks. They were `.bss` until the region below
     * high_pdpt[511] replaced the static array, and the `.bss` test above was
     * the whole bound for them -- this is the THIRD guard encoding "a kernel
     * stack is a .bss array", after ksp_is_bogus and kern_addr_present in
     * scheduler.c and paging.c. All three had to learn the region together, and
     * all three failed LOUDLY rather than silently when they had not: the first
     * boot after the move panicked here, on the first switch to task 1, with a
     * resume value that was entirely legitimate.
     *
     * That is the direction this guard is built to fail in, and it is worth
     * keeping in mind for the mirror case: a guard that had defaulted to
     * "accept" for addresses it could not classify would have gone quiet on
     * exactly the stacks it exists to check, and nothing would have said so. */
    if (kstack_region_contains_ksp(rsp)) return 0;
    return 1;
#endif
}

/* The ring-0 stack this CPU parks on when the task it was running dies and
 * task_exit_switch() finds nothing else runnable. Reached from three places (the
 * SYS_EXIT path, the ring-3 trap kill, and the page-fault kill), all of which
 * resume at resume_shell_after_fault() -> kernel_idle().
 *
 * All three used tasks[0].kernel_stack_top, which is ONE stack. Two CPUs that
 * take the path both park on it, both run `sti; hlt` there, and both push a trap
 * frame at the same address on the next tick -- two CPUs executing ring-0 code on
 * one kernel stack, which is S20, and which the g_kstack_inflight mask cannot
 * see because it is keyed on task ids and task 0 is legitimately the current task
 * on several CPUs at once.
 *
 * sched_note_park() records the choice and fails closed if another CPU is
 * already parked on the same stack, so the property is checked and not merely
 * intended. */
static uint64_t kernel_park_rsp(void)
{
#if defined(SMP) && !defined(KSTACK0_SHARED_PARK)
    /* Per-CPU, which is the fix. ap_park_stack_top() is the same stack
     * enter_cpu_idle() already parks this CPU on, so the fault path joins the
     * kernel's one park mechanism instead of keeping a worse second one. */
    extern uint64_t ap_park_stack_top(int cpu);
    uint64_t rsp = ap_park_stack_top(this_cpu());
#else
    /* KSTACK0_SHARED_PARK=1 restores the shared park -- the defect, on demand --
     * and is what `make smoke-kstack-park-control` builds. Also the uniprocessor
     * path, where there is no second CPU to share with and task 0's stack is the
     * right (and guarded) answer. */
    uint64_t rsp = tasks[0].kernel_stack_top;
#endif
#ifdef KSTACK0_PARK_TRACE
    /* Test-only: how often is this path reached at all, and by which CPU? The
     * answer decides whether the shared park is a live hazard or a latent one,
     * and it is not something to assume in either direction. Absent from every
     * shipping configuration. */
    kfault_begin(0);
    kfault_str("\nPARKTRACE cpu="); kfault_dec(this_cpu());
    kfault_str(" rsp=");             kfault_hex(rsp);
    kfault_str(" task=");            kfault_task(get_current_task());
    kfault_str("\n");
    kfault_end(0);
#endif
#ifdef SMP
    sched_note_park(rsp);
#endif
    return rsp;
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
        irq_eoi(32);
        timer_handler();
#ifdef KFAULT_INJECT
        kfault_inject_tick();
#endif
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
            irq_eoi(33);
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
            irq_eoi(33);
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
#ifdef IRQ_POLICY_AUDIT
        irq_milestone("first-syscall-entry");
#endif
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
        /* Per-CPU: this only ever returns an exec armed by THIS core. As a shared
         * global it returned whichever exec happened to be pending anywhere, and
         * the wrong core would then resume another core's task on that core's
         * live trap frame -- finding [G-9]. See the note in kspawn.c. */
        {
            int t = exec_reenter_take();
            if (t > 0) return exec_reenter_switch(t);
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
                frame->rsp    = kernel_park_rsp();
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
                /* That print() only reaches the klog once console_server owns the
                 * console, so it is invisible to a serial capture of a live
                 * session. The record below is what a supervisor can actually
                 * read back (SYS_TASK_EXIT_INFO). */
                struct task_exit_cause cause = {
                    TASK_EXIT_FAULT, (uint32_t)vector, 0, frame->rip, 0
                };
                task_teardown(killed, &cause);
                uint64_t rsp = task_exit_switch(killed);
                if (rsp) return rsp;
                /* Nothing else runnable: park this CPU in the kernel reaper/idle
                 * loop. See kernel_park_rsp() for why the stack is per-CPU. */
                frame->rip    = (uint64_t)resume_shell_after_fault;
                frame->cs     = 0x08;
                frame->rflags = 0x202;
                frame->rsp    = kernel_park_rsp();
                frame->ss     = 0x10;
            }
            /* else: signal delivered -> fall through to `return frame`, and the
             * ISR epilogue iretq's into the handler at ring 3. */
        } else {
            /* A trap below vector 32 taken at CPL 0 (or with no task to blame):
             * #GP, #UD, #DF and friends in the kernel's own code. This halts,
             * so if the report goes to the klog the machine simply stops with
             * nothing on the wire -- a fatal kernel bug and a hang are then
             * indistinguishable to every harness in the tree. Straight at the
             * UART. */
            kfault_begin(1);
            kfault_str("\n64-bit EXCEPTION vector="); kfault_dec((int)vector);
            kfault_str(" err=");  kfault_hex(frame->err_code);
            kfault_str(" task="); kfault_task(get_current_task());
            kfault_frame(frame);
            kfault_claims(get_current_task());
            kfault_str("\nKERNEL FATAL EXCEPTION - halting\n");
            kfault_end(1);
        }
    } else if (vector >= MSI_VECTOR_BASE &&
               vector < MSI_VECTOR_BASE + MSI_VECTOR_COUNT) {
        /* A message-signalled interrupt. EOI to the LAPIC and deliver -- no mask,
         * because an MSI is a message rather than a level: one write, one
         * interrupt, and no line left asserted to re-deliver. S46's masking exists
         * for the INTx case and would be ceremony here.
         *
         * msi_dispatch drops a message whose route is gone (a dead driver), which
         * is the fail-closed outcome: the device keeps sending into nothing rather
         * than a later task inheriting the previous owner's wakeups. */
        *(volatile uint32_t *)0xFEE000B0UL = 0;   /* LAPIC EOI */
        (void)msi_dispatch(vector);
    } else if (vector >= 34 && vector <= 47 && irq_reg[vector - 32].active) {
        /* ---- A REGISTERED PCI (or other legacy) LINE -----------------------
         *
         * MASK THE LINE BEFORE ACKNOWLEDGING IT, and leave it masked until the
         * driver says it has serviced the device (SYS_IRQ_ACK). This is the
         * whole design and it is a security property, not a performance one.
         *
         * A legacy PCI interrupt is LEVEL-TRIGGERED and shared. The device holds
         * the line asserted until its driver touches the right register. If the
         * kernel merely EOIs, the PIC re-delivers immediately, and it keeps
         * re-delivering: the CPU never returns to ring 3, the driver never runs,
         * and so the line is never cleared. The machine stops making progress and
         * nothing short of a reset recovers it.
         *
         * That failure is reachable from a capability that is supposed to be
         * narrow -- a driver that registers for its line and then simply does not
         * service the device denies the whole machine. Masking here converts it
         * into a device that stops working, which is the fail-closed shape: the
         * blast radius of a broken driver is its own hardware.
         *
         * It also makes acknowledgement AUTHORITY, which is why SYS_IRQ_ACK is
         * capability-gated and why only the registration's owner may unmask.
         *
         * The notification is sent after the mask so a driver that is already
         * spinning in SYS_WAIT_NOTIFY cannot be woken, service the device and ack
         * before the mask lands -- which would leave the line masked with nobody
         * left to unmask it. */
        int line = vector - 32;
#ifndef IRQ_NO_MASK_ON_FIRE
        pic_set_masked(line, 1);
#endif
        irq_eoi(vector);
        irq_notify_fire(line);
    } else {
        irq_eoi(vector);
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
#ifdef SMP
    /* ---- Two CPUs on one kernel stack (finding G-8) -------------------------
     *
     * We are executing on the current task's kernel stack: the CPU pushed this
     * trap frame at the top of it, and every C frame below is ours. If another CPU
     * is *also* still on that stack -- because it switched away from this task and
     * has not yet reached isr_common_stub64's `movq %rax,%rsp` -- then the frames
     * are about to be written by two cores at once, at the same depth, running the
     * same functions. Nothing downstream can detect that: the return addresses and
     * the stack canary land back at their own slots with their own values, so the
     * frames validate and the `ret`s go where they should. Only the data is wrong,
     * and the first datum that leaves is the resume %rsp on its way to the ISR
     * epilogue -- which is G-8's entire observed signature.
     *
     * So it is caught here, at the collision, rather than three functions later at
     * an `iretq` with a selector index of 0x871. Fail closed: this is memory
     * corruption in progress across a privilege boundary, and there is no state to
     * repair -- the other CPU's live frames cannot be un-shared.
     *
     * Cost on the common path is one load and a bit test. The holder scan runs
     * only once the bit for THIS task is already set, and requiring a holder that
     * is not this CPU is what makes the report mean "two CPUs" rather than "a bit
     * was set": a stale bit belonging to this CPU is not a collision with anyone.
     *
     * Reported under the BOUNDED claim for the reason the resume-rsp guard below is --
     * the failure this watches for is exactly the kind that leaves another CPU
     * halted holding the permanent one, and a guard silenced by the failure it is
     * watching for is not an instrument. */
    {
        /* The bit for THIS task, rather than "is any bit set anywhere" followed
         * by a shift. The old form loaded the whole mask first, which was only
         * possible while the mask was one word -- and while it was one word, the
         * shift silently aliased task 64 onto task 0 the moment MAX_TASKS grew.
         * Asking about the current task directly is the same one load and bit
         * test, and it cannot be wrong about which task it answered for. */
        int t = get_current_task();
        if (kstack_inflight_task(t)) {
            int me = this_cpu();
            int holder = sched_kstack_holder(t);
            if (holder >= 0 && holder != me) {
                /* Both parties to a collision see it, and both would report the
                 * same task and the same pair of CPUs, so the second report only
                 * garbles the first: the bounded claim prints past its budget by
                 * design, and two concurrent reporters interleave byte-by-byte
                 * into "task= entering-cpu=3-2145272000". Observed, not feared --
                 * it is what the first run of smoke-kstack-race-control produced.
                 *
                 * This is deduplication, not the muteness #143 fixed, and the
                 * difference is worth stating because the code shape is identical.
                 * There, the guard's report was lost to a claim taken by an
                 * UNRELATED fatal fault on another CPU, so the event went entirely
                 * unreported. Here the claim is taken by this same detector,
                 * reporting this same collision, under the bounded bracket that
                 * always emits -- so the event is guaranteed to reach the wire
                 * exactly once. The loser has nothing to add and halting it is
                 * fail-closed anyway: it is the other half of a shared stack. */
                static volatile int kstack_reported = 0;
                if (__sync_lock_test_and_set(&kstack_reported, 1))
                    for (;;) __asm__ volatile ("cli; hlt");
                kfault_begin(0);
                kfault_str("\nPANIC: two CPUs on one kernel stack task=");
                kfault_task(t);
                kfault_str(" entering-cpu=");   kfault_dec(me);
                kfault_str(" unwinding-cpu=");  kfault_dec(holder);
                kfault_str("\n  trapped from:"); kfault_frame(frame);
                kfault_claims(t);
                kfault_str("\nKERNEL FATAL SHARED KERNEL STACK - halting\n");
                kfault_end(0);
                for (;;) __asm__ volatile ("cli; hlt");
            }
        }
    }
#endif

    int from_user = (frame->cs & 3) != 0;
    if (from_user) fpu_save(get_current_task());

    uint64_t rsp = interrupt_handler64_inner(frame);
#ifdef RESUME_RSP_INJECT
    rsp = resume_rsp_inject(rsp);
#endif

    /* Every return from the dispatcher is a kernel %rsp that isr_common_stub64
     * loads and immediately pops 15 registers from. A bogus value does not fail at
     * the mistake: it faults inside the ISR epilogue at an address near zero, with
     * a banner naming the stub and telling you nothing about which switch path
     * produced it. (Or earlier still, on the out->cs read just below -- rsp==4
     * faults at 0x94, which is exactly what a reproduce-and-symbolise cycle spent
     * an hour chasing.) A legal value lies in `.bss` (the AP idle and IST stacks)
     * or in the per-task kernel-stack region; a returned 0/1/-1 or a wild value
     * lies in neither.
     * This comment used to say "kernel stacks are higher-half, so anything below
     * that is [bogus]", which was the floor-only rationale and named the blind
     * spot without noticing it: -7 is 0xFFFF...F9, which is not below anything.
     * See resume_rsp_is_bogus() for the bound and why it comes from the linker.
     *
     * RESUME_GUARD_DISABLE compiles the guard out. Test-only, and the control arm
     * for `make smoke-resume-guard`: with the same injected bogus value and no
     * guard, the kernel reproduces the silence on demand. See TESTS.md. */
#ifndef RESUME_GUARD_DISABLE
    if (resume_rsp_is_bogus(rsp)) {
        /* Was println() -- and this guard exists precisely to catch a fault
         * that has only ever been observed during a live session, when
         * println() reaches nothing but the klog. A guard whose report is
         * inaudible where it fires cannot be distinguished from one that never
         * fired, which is how "the floor guard did not catch it" became a
         * hypothesis rather than an observation.
         *
         * That was still true after the move to kfault: this report was bracketed
         * kfault_begin(1)/kfault_end(1), and begin(1) is panic_begin(), whose claim
         * is PERMANENT and whose losers halt WITHOUT PRINTING. So a CPU that had
         * already died fatally -- for the same underlying reason, a bogus resume
         * value one microsecond earlier -- left this guard mute on every other CPU
         * for the rest of the boot. The 2026-08-13 two-event capture is exactly that
         * shape: cpu 3 took a fatal #GP and halted holding the claim, and the only
         * report that got out afterwards (cpu 0's #PF) was the one bracketed with
         * fatal=0. A guard silenced by the failure it is watching for is not an
         * instrument.
         *
         * So: report under the BOUNDED claim -- which is what makes it audible
         * behind another CPU's permanent one -- release it, and only then halt.
         * Halting is unchanged behaviour (kfault_end(1) already did it, and it is
         * fail-closed: iretq onto a value we have just rejected is the one thing
         * that must not happen). What changes is that the line gets out first. */
        int cur = get_current_task();
#ifdef RESUME_GUARD_LEGACY_FATAL
        /* Test-only: the pre-fix bracket, kept buildable so the claim above is a
         * measurement and not a story. `make smoke-resume-guard-legacy` builds it
         * with the preclaim arm and requires the report NOT to be heard. */
        kfault_begin(1);
#else
        kfault_begin(0);
#endif
        kfault_str("\nPANIC: dispatcher returned a bogus resume rsp=");
        kfault_hex(rsp);
        kfault_str(" task=");          kfault_task(cur);
        if (cur >= 0 && cur < MAX_TASKS) {
            kfault_str(" state=");         kfault_dec((int)tasks[cur].state);
            kfault_str(" pending_block="); kfault_dec((int)tasks[cur].pending_block);
        }
        kfault_str("\n  trapped from:"); kfault_frame(frame);
        kfault_claims(cur);
        kfault_str("\nKERNEL FATAL RESUME RSP - halting\n");
#ifdef RESUME_GUARD_LEGACY_FATAL
        kfault_end(1);                  /* never returns */
#else
        kfault_end(0);
#endif
        /* Fail closed, and never fall through to the out->cs read below: at
         * rsp==4 that read faults at 0x94 all by itself, which is how this
         * defect spent a cycle being mistaken for a near-null dereference. */
        for (;;) __asm__ volatile ("cli; hlt");
    }
#endif

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
 * lobyte/hibyte access.
 *
 * PIT_TICK_HZ moved to src/include/kernel.h on 2026-08-24: SYS_CLOCK_GETTIME
 * converts the tick count to seconds with it, so a local #define here would be
 * the same constant written down twice -- and the clock would silently report
 * the wrong time if only one of them changed. */
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

    idt64_set_gate(32, (uint64_t)isr32, 0x08, 0, 0x8E);
    idt64_set_gate(33, (uint64_t)isr33, 0x08, 0, 0x8E);

    /* IRQ 2..15. The stubs isr34..isr47 have existed in lowlevel64.S since the
     * IDT was written; nothing ever installed a GATE for them, because the PIC
     * masked every line above 1 so none could arrive.
     *
     * Unmasking a PCI line without this is not "the interrupt is ignored" -- a
     * vector with no gate raises #GP, and the #GP is attributed to whatever was
     * interrupted, so the first PCI interrupt KILLS AN INNOCENT RING-3 TASK at a
     * random instruction. That is how this was found: netd died with
     * "ring-3 trap vector 13" on the store immediately after it enabled its
     * device's interrupt, and the store was not the problem.
     *
     * Installed unconditionally rather than when a driver registers: a gate for a
     * masked line costs nothing and can never fire, whereas a line unmasked one
     * instruction before its gate exists is exactly the window above. */
    /* MSI vectors 48..63, for the reason the paragraph above gives: a vector with
     * no gate raises #GP against whatever was interrupted, so the first message a
     * device sent would kill an innocent task. Installed unconditionally, because
     * a gate for a vector nothing is programmed to raise costs nothing and can
     * never fire, whereas a device programmed one instruction before its gate
     * exists is exactly that window. */
    extern void isr48(void); extern void isr49(void); extern void isr50(void);
    extern void isr51(void); extern void isr52(void); extern void isr53(void);
    extern void isr54(void); extern void isr55(void); extern void isr56(void);
    extern void isr57(void); extern void isr58(void); extern void isr59(void);
    extern void isr60(void); extern void isr61(void); extern void isr62(void);
    extern void isr63(void);
    static void (*const msi_stubs[])(void) = {
        isr48, isr49, isr50, isr51, isr52, isr53, isr54, isr55,
        isr56, isr57, isr58, isr59, isr60, isr61, isr62, isr63
    };
    for (unsigned v = 0; v < sizeof(msi_stubs)/sizeof(msi_stubs[0]); v++)
        idt64_set_gate((uint8_t)(MSI_VECTOR_BASE + v), (uint64_t)msi_stubs[v],
                       0x08, 0, 0x8E);

    extern void isr34(void); extern void isr35(void); extern void isr36(void);
    extern void isr37(void); extern void isr38(void); extern void isr39(void);
    extern void isr40(void); extern void isr41(void); extern void isr42(void);
    extern void isr43(void); extern void isr44(void); extern void isr45(void);
    extern void isr46(void); extern void isr47(void);
    static void (*const irq_stubs[])(void) = {
        isr34, isr35, isr36, isr37, isr38, isr39, isr40,
        isr41, isr42, isr43, isr44, isr45, isr46, isr47
    };
    for (unsigned v = 0; v < sizeof(irq_stubs)/sizeof(irq_stubs[0]); v++)
        idt64_set_gate((uint8_t)(34 + v), (uint64_t)irq_stubs[v], 0x08, 0, 0x8E);

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
#ifdef KFAULT_LEGACY_PRINTLN
        /* The CONTROL ARM: the report as it was, through println(). Kept
         * buildable so the claim "the report is audible during a live session"
         * can be falsified in-tree rather than asserted -- `make
         * smoke-kfault-legacy` boots this arm and requires the report to be
         * ABSENT from the wire. Same role EP_QUEUE_SLOTS=1 plays for roadmap
         * 1.3 and IRQ_LEGACY_GLOBAL_LOCK for 1.1. Never a shipping config. */
        println("PAGE FAULT at ");
        print_hex(fault_addr);
        println(" err=");
        print_hex(err);
        println(" task=");
        print_hex(killed);
        println(" rip=");
        print_hex(f64->rip);
        println(" rsp=");
        print_hex(f64->rsp);
        println(allowed ? "Approved by validator but unmappable - killing task "
                        : "Rejected by validator - killing task ");
        print_hex(killed);
        println("");
#else
        /* A #PF at CPL 0 is a KERNEL defect -- the kernel dereferenced
         * something bad -- even when a ring-3 task is current and gets killed
         * for it below. Report it straight at the UART, not through println():
         * print() is klog-only once console_server owns the console, so this
         * banner was silent during every live session, which is the only time
         * G-8's supervisor fault has ever been seen. The whole diagnosis was
         * being computed and thrown away.
         *
         * kfault_frame() adds rip, cs, rflags, rsp, rbp and the CPU. Symbolise
         * rip against THE SAME kernel.elf that produced it:
         *     nm -n kernel.elf | awk -v a=<rip> '...'   (or addr2line -e kernel.elf) */
        kfault_begin(killed == 0);        /* no task to blame -> we are halting */
        kfault_str("\nPAGE FAULT at "); kfault_hex(fault_addr);
        kfault_str(" err=");            kfault_hex(err);
        kfault_str("(");                kfault_pf_err(err);
        kfault_str(") task=");          kfault_task(killed);
        kfault_frame(f64);
        kfault_claims(killed);
        kfault_str(allowed ? "\nApproved by validator but unmappable - killing task "
                           : "\nRejected by validator - killing task ");
        kfault_dec(killed);
        kfault_str("\n");
        if (killed == 0) kfault_end(1);   /* nothing to kill: halts, never returns */
        kfault_end(0);
#endif
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
        /* The banner above is printed only for a ring-0 / task-0 fault, so a
         * ring-3 task killed here dies in total silence — the case that made
         * G-8 signature A look like a hang. Record it. */
        struct task_exit_cause cause = {
            TASK_EXIT_PAGEFAULT, 14, (uint32_t)err, f64->rip, (uint64_t)fault_addr
        };
        task_teardown(killed, &cause);
        uint64_t rsp = task_exit_switch(killed);
        if (rsp) return rsp;
        f64->rip    = (uint64_t)resume_shell_after_fault;
        f64->cs     = 0x08;
        f64->rflags = 0x202;
        f64->rsp    = kernel_park_rsp();
        f64->ss     = 0x10;
        return 0;
    }

    asm volatile("cli; hlt");
    return 0;
}

