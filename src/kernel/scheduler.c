#include "kernel.h"

tcb_t tasks[MAX_TASKS];
int current_task = 0;
int percpu_current_task[MAX_CPUS];

#ifdef SMP
/* Which CPU is currently running each task (-1 == not running anywhere). The SMP
 * scheduler's mutual-exclusion guard: preempt_on_tick only ever claims a task
 * whose entry is -1, so a task's single kernel stack + saved trap frame are
 * never touched by two CPUs at once. Managed under the scheduler lock. */
int task_running_cpu[MAX_TASKS];

/* Bitmask of CPUs that have run at least one user task (bit c == CPU c). The SMP
 * self-test reads it to confirm work actually landed on more than one core. */
volatile unsigned smp_cpus_ran_tasks = 0;
#endif

static uint8_t kernel_stacks[MAX_TASKS][KERNEL_STACK_SIZE] __attribute__((aligned(16)));

spinlock_t scheduler_lock;
spinlock_t page_lock;
spinlock_t cap_lock;
spinlock_t endpoint_lock;
spinlock_t storage_lock;

addr_t current_kernel_stack_top = 0;  

void scheduler_lock_acquire(void);
void scheduler_lock_release(void);

struct endpoint endpoints[MAX_ENDPOINTS];

uint32_t system_ticks = 0;

void scheduler_init(void) {
    for (int i = 0; i < MAX_TASKS; i++) {
        tasks[i].state = 0;
        tasks[i].esp = 0;
        tasks[i].eip = 0;
        tasks[i].cap_tcb = 0;
        tasks[i].cr3 = 0;
        tasks[i].priority = 1;
        tasks[i].cspace = 0;
        tasks[i].cspace_size = 0;
        tasks[i].heap_start = 0;
        tasks[i].heap_current = 0;
        tasks[i].heap_end = 0;
        tasks[i].name[0] = 0;
        tasks[i].waiter = -1;
        tasks[i].blocked_on = -1;
        tasks[i].ipc_role = 0;
        tasks[i].in_kernel = 0;
        tasks[i].blocked_on_notif = -1;
        tasks[i].auth_fail_count = 0;
        tasks[i].auth_lockout_until = 0;
    }

    create_task(0, 0, 0, 0);

    tasks[0].uid = 0;
    tasks[0].gid = 0;

    users_init();

    for (int i = 0; i < MAX_ENDPOINTS; i++) {
        endpoints[i].has_message = 0;
        endpoints[i].msg_len = 0;
        endpoints[i].sender_task = -1;
        endpoints[i].last_sender = -1;
    }

    
    for (int c = 0; c < MAX_CPUS; c++) percpu_current_task[c] = 0;
    percpu_current_task[0] = 0;
    current_task = 0;
    scheduler_lock = (spinlock_t){0};
    page_lock = (spinlock_t){0};
    cap_lock = (spinlock_t){0};
    endpoint_lock = (spinlock_t){0};
    storage_lock = (spinlock_t){0};

    current_kernel_stack_top = KERNEL_TSS_STACK;
}

void create_task(int id, addr_t entry, addr_t stack_top, addr_t image_base) {
    if (id >= MAX_TASKS) return;

    /* Record the (possibly ASLR-randomized) image base before create_user_pagedir
     * runs, so it premaps the image window at the right virtual address. Default
     * to the fixed low base for task 0 / callers that don't relocate. */
    tasks[id].image_base = image_base ? (uint32_t)image_base : (uint32_t)USER_AREA_BASE;
    tasks[id].image_end  = tasks[id].image_base;   /* refined by the loader once the image size is known */

    tasks[id].state = 1;
    tasks[id].esp = (addr_t)(stack_top ? (stack_top - 256) : 0);
    tasks[id].eip = entry;
    tasks[id].cap_tcb = id;

    /* Each task owns a distinct kernel stack (shared kernel mapping, present in
     * every address space). Pin it now so the TSS RSP0 and the preemptive
     * scheduler's saved/fabricated trap frame agree on one address. */
    tasks[id].kernel_stack_top = (uint64_t)&kernel_stacks[id][KERNEL_STACK_SIZE - 16];
    tasks[id].saved_ksp = 0;
    tasks[id].runnable_ctx = 0;
    tasks[id].sig_handler = 0;   /* no signal handler until the task registers one */
    tasks[id].in_signal = 0;
    tasks[id].pending_sig = 0;    /* no async signal queued */

create_user_pagedir(id);

    static struct capability cspace_pool[MAX_TASKS][256];
    tasks[id].cspace = cspace_pool[id];
    tasks[id].cspace_size = 256;

    /* Zero the entire cspace before installing initial capabilities.
     * cspace_pool is static (zeroed at BSS init) but task slots are reused:
     * a dead task's CAP_USER/CAP_CONSOLE/etc. would otherwise survive into
     * the next task spawned at the same index, granting it unearned authority. */
    for (int s = 0; s < 256; s++) {
        tasks[id].cspace[s].type       = CAP_NULL;
        tasks[id].cspace[s].rights     = 0;
        tasks[id].cspace[s].object     = 0;
        tasks[id].cspace[s].badge      = 0;
        tasks[id].cspace[s].serial     = 0;
        tasks[id].cspace[s].generation = 0;
    }

    tasks[id].cspace[0].type   = CAP_TCB;
    tasks[id].cspace[0].rights = CAP_RIGHT_ALL;
    tasks[id].cspace[0].object = id;
    tasks[id].cspace[0].badge  = 0;
    tasks[id].cspace[0].serial = (0xB0000000U | ((uint32_t)id << 16) | 0U);
    tasks[id].cspace[0].generation = 0;

    tasks[id].cspace[3].type   = CAP_FRAME;
    tasks[id].cspace[3].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC;
    tasks[id].cspace[3].object = USER_AREA_BASE;
    tasks[id].cspace[3].badge  = 0;
    tasks[id].cspace[3].serial = (0xB0000000U | ((uint32_t)id << 16) | 3U);
    tasks[id].cspace[3].generation = 0;

    tasks[id].cspace[4].type   = CAP_ENDPOINT;
    tasks[id].cspace[4].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    tasks[id].cspace[4].object = 0;
    tasks[id].cspace[4].badge  = 0;
    tasks[id].cspace[4].serial = (0xB0000000U | ((uint32_t)id << 16) | 4U);
    tasks[id].cspace[4].generation = 0;

    tasks[id].cspace[5].type   = CAP_ENDPOINT;
    tasks[id].cspace[5].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    tasks[id].cspace[5].object = 1;
    tasks[id].cspace[5].badge  = 0;
    tasks[id].cspace[5].serial = (0xB0000000U | ((uint32_t)id << 16) | 5U);
    tasks[id].cspace[5].generation = 0;

    
    if (id == 0) {
        tasks[id].cspace[8].type   = CAP_CONSOLE;
        tasks[id].cspace[8].rights = CAP_RIGHT_ALL;
        tasks[id].cspace[8].object = 0;
        tasks[id].cspace[8].badge  = 0;
        tasks[id].cspace[8].serial = 0xC0DE0008U;
        tasks[id].cspace[8].generation = 0;

        tasks[id].cspace[9].type   = CAP_ENCRYPTED_STORAGE;
        tasks[id].cspace[9].rights = CAP_RIGHT_ALL;
        tasks[id].cspace[9].object = 0;
        tasks[id].cspace[9].badge  = 0;
        tasks[id].cspace[9].serial = 0xC0DE0009U;
        tasks[id].cspace[9].generation = 0;
    }
}

void create_user_task(int id, addr_t entry, addr_t stack_top) {
    create_task(id, entry, stack_top, USER_AREA_BASE);
}

static uint64_t aslr_rng_state[2] = { 0x1234567890ABCDEFULL, 0xFEDCBA0987654321ULL };

uint64_t read_tsc(void) {
    uint32_t lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static uint64_t aslr_rand(void) {
    uint64_t x = aslr_rng_state[0];
    uint64_t y = aslr_rng_state[1];

    aslr_rng_state[0] = y;
    x ^= x << 23;
    x ^= x >> 17;
    x ^= y ^ (y >> 26);
    aslr_rng_state[1] = x + y;

    uint64_t combined = x + y;
    combined ^= combined >> 17;
    combined *= 0x2545F4914F6CDD1DULL;

    return (addr_t)(combined >> 32);
}

uint32_t aslr_random_offset(uint32_t max_pages) {
    if (max_pages == 0) return 0;
    return (aslr_rand() % max_pages) * PAGE_SIZE;
}

void aslr_mix_entropy(uint64_t val) {
    uint64_t t = read_tsc();
    aslr_rng_state[0] ^= val * 0x9E3779B97F4A7C15ULL;
    aslr_rng_state[1] ^= (val >> 32) * 0xC2B2AE3D27D4EB4FULL ^ t;
    (void)aslr_rand();
}

void timer_handler(void) {
    system_ticks++;
}

uint32_t get_system_ticks(void) {
    return system_ticks;
}

/* ----------------------------------------------------------------------------
 * Preemptive scheduling
 *
 * The timer ISR (idt.c, vector 32) calls preempt_on_tick() with the current
 * task's full trap frame. We switch tasks *only* when the tick interrupted
 * ring-3 code: at that instant the task holds no kernel spinlock (spin_lock
 * disables interrupts, so the timer can't fire inside a critical section) and
 * its entire state is captured by the trap frame the CPU + isr_common_stub64
 * pushed onto its per-task kernel stack. A tick that lands in ring 0 (mid
 * syscall / interrupt handler) is never a switch point -- we just tick and
 * return -- which keeps the kernel effectively non-preemptible and avoids all
 * reentrancy hazards. Switching is a pure kernel-%rsp swap: save the current
 * frame pointer, load the next task's, and let the ISR epilogue pop+iretq into
 * it. No spinlock is taken here (interrupts are already disabled in the gate).
 * ------------------------------------------------------------------------- */

static volatile int preempt_enabled = 0;

/* Arm the timer switch. Called once the boot path is past its delicate
 * single-threaded init and a user task is (about to be) running. Until then a
 * tick only advances system_ticks. */
void sched_enable_preemption(void) {
    preempt_enabled = 1;
}

static inline uint64_t task_kstack_top(int id) {
    if (tasks[id].kernel_stack_top) return tasks[id].kernel_stack_top;
    return (uint64_t)&kernel_stacks[id][KERNEL_STACK_SIZE - 16];
}

/* Fabricate an initial, resumable interrupt trap frame at the top of task
 * `id`'s kernel stack, so the timer switch can iretq into a freshly spawned
 * user task exactly as if it had just been preempted at its entry point. cs/ss
 * are the 32-bit user segments (userspace is compatibility-mode), IF is set so
 * the task is itself preemptible, and all GP registers start zeroed. */
void sched_prepare_user_context(int id, uint64_t entry, uint64_t user_rsp) {
    if (id < 0 || id >= MAX_TASKS) return;
    uint64_t top = task_kstack_top(id) & ~0xFULL;
    struct interrupt_frame64 *f =
        (struct interrupt_frame64 *)(top - sizeof(struct interrupt_frame64));

    f->r15 = f->r14 = f->r13 = f->r12 = f->r11 = f->r10 = f->r9 = f->r8 = 0;
    f->rbp = f->rdi = f->rsi = f->rdx = f->rcx = f->rbx = f->rax = 0;
    f->int_no   = 0;
    f->err_code = 0;
    f->rip      = entry;
    f->cs       = 0x2b;          /* 32-bit user code (GDT 0x28 | RPL 3) */
    f->rflags   = 0x202;         /* IF set, reserved bit 1 */
    f->rsp      = user_rsp;
    f->ss       = 0x33;          /* 32-bit user data (GDT 0x30 | RPL 3) */

    tasks[id].saved_ksp     = (uint64_t)f;
    tasks[id].runnable_ctx  = 1;
}

#ifdef SMP
int this_cpu(void);   /* defined below */

/* Gate for cross-CPU task scheduling. APs come online and take timer ticks
 * immediately, but they only start *pulling runnable tasks* once the BSP has
 * populated the runnable pool and set this — which closes the window where an
 * AP could grab a task the BSP launched (via lretq) but not yet claimed. Normal
 * SMP boot leaves it 0 (APs idle, BSP runs the shell); the SMP self-test turns
 * it on after spawning its pool of workers. */
volatile int smp_sched_enabled = 0;

/* Raw test-and-set on the scheduler lock for use *inside* an interrupt handler,
 * where IF is already clear (the gate is an interrupt gate): unlike spin_lock()
 * it must not touch IF, or the ISR epilogue's iretq would race a re-entry. */
static void sched_raw_lock(void) {
    while (__sync_lock_test_and_set(&scheduler_lock.locked, 1))
        while (scheduler_lock.locked) __asm__ volatile ("pause");
}
static void sched_raw_unlock(void) { __sync_lock_release(&scheduler_lock.locked); }
#endif

/* Async signal delivery. When a ring-3 task is about to resume, redirect it into
 * its registered handler if SYS_SIGNAL queued one. Reuses the fault-signal path:
 * try_deliver_fault_signal rewrites the trap frame to enter the handler (signal
 * number in ebx) and saves the pre-signal frame for SYS_SIGRETURN. Left pending
 * if the task is already inside a handler (delivered after it returns). */
extern int try_deliver_fault_signal(struct interrupt_frame64 *frame, int cur,
                                    uint32_t signum, uint64_t fault_addr);
static void deliver_pending_signal(uint64_t frame_ptr, int tid) {
    if (tid <= 0 || tid >= MAX_TASKS) return;
    uint32_t sig = tasks[tid].pending_sig;
    if (sig == 0) return;
    struct interrupt_frame64 *f = (struct interrupt_frame64 *)frame_ptr;
    if ((f->cs & 3) != 3) return;   /* only into a ring-3 frame */
    if (try_deliver_fault_signal(f, tid, sig, 0)) {
        tasks[tid].pending_sig = 0;
    }
}

/* Called from the timer ISR. Returns the kernel %rsp the ISR epilogue should
 * resume on: the same frame when we don't switch, or the next task's saved
 * frame when we do. */
uint64_t preempt_on_tick(uint64_t frame_rsp, uint64_t interrupted_cs) {
    if (!preempt_enabled) return frame_rsp;
#ifndef SMP
    if ((interrupted_cs & 3) != 3) return frame_rsp;   /* only preempt ring 3 */

    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) return frame_rsp;

    /* Deliver any signal queued for the running task before it resumes. */
    deliver_pending_signal(frame_rsp, cur);

    /* Round-robin: the next runnable user task (id != 0) with a resumable
     * context. */
    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (cur + i) % MAX_TASKS;
        if (cand == 0 || cand == cur) continue;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 && tasks[cand].runnable_ctx
            && tasks[cand].saved_ksp) {
            next = cand;
            break;
        }
    }
    if (next < 0) return frame_rsp;   /* nobody else runnable -> keep running */

    /* Save the outgoing task's frame, install the incoming task's address
     * space + kernel stack, and hand its saved frame back to the ISR epilogue.
     * Kernel stacks and the task array live in the shared kernel mapping that
     * is present in every address space, so this stays valid across switch_cr3
     * even though we are still executing on the outgoing task's kernel stack. */
    tasks[cur].saved_ksp    = frame_rsp;
    tasks[cur].runnable_ctx = 1;

    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    current_kernel_stack_top = kstop;
    set_current_task(next);
    return tasks[next].saved_ksp;
#else
    /* SMP: any CPU may run any task, so selection + claim is serialised under the
     * scheduler lock and a task is only ever taken when task_running_cpu[] shows
     * it running nowhere. The shared runnable pool + this per-CPU pull is the
     * load-balancing mechanism: an idle AP grabs whatever work is available. The
     * BSP (cpu 0) is never pulled out of its ring-0 idle/kernel context by the
     * timer -- only its ring-3 tasks are preempted -- which preserves the exact
     * single-CPU boot flow; the APs do the multi-core work. */
    int cpu = this_cpu();
    if (!smp_sched_enabled) return frame_rsp;
    int ring3 = ((interrupted_cs & 3) == 3);
    if (!ring3 && cpu == 0) return frame_rsp;

    sched_raw_lock();
    int cur = percpu_current_task[cpu];

    /* Defensively claim the task we are currently running, so another CPU cannot
     * grab a task that was launched onto this CPU outside the timer path. */
    if (cur > 0 && cur < MAX_TASKS && task_running_cpu[cur] < 0)
        task_running_cpu[cur] = cpu;

    int next = -1;
    for (int i = 1; i <= MAX_TASKS; i++) {
        int cand = (cur + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 &&
            tasks[cand].runnable_ctx && tasks[cand].saved_ksp && task_running_cpu[cand] < 0) {
            next = cand;
            break;
        }
    }
    if (next < 0) { sched_raw_unlock(); return frame_rsp; }   /* keep running cur */

    /* Save + release the outgoing task if it was a real user task in ring 3. A
     * ring-0 (idle) context is stateless and simply abandoned. */
    if (cur > 0 && cur < MAX_TASKS && ring3) {
        tasks[cur].saved_ksp    = frame_rsp;
        tasks[cur].runnable_ctx = 1;
        task_running_cpu[cur]   = -1;
    }

    task_running_cpu[next] = cpu;
    smp_cpus_ran_tasks |= (1u << cpu);
    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    if (cpu == 0) current_kernel_stack_top = kstop;
    set_current_task(next);
    uint64_t ksp = tasks[next].saved_ksp;
    sched_raw_unlock();
    return ksp;
#endif
}

/* Called from interrupt_handler64 after a blocking SYS_IPC_CALL.  The caller's
 * state is already TASK_BLOCKED_IPC and runnable_ctx is 0.  Save frame_rsp as
 * its saved_ksp, find the next runnable task, switch to it, and return its
 * saved_ksp so the ISR epilogue resumes that task via iretq. */
uint64_t ipc_block_switch(int blocked_task, uint64_t frame_rsp) {
#ifdef SMP
    /* Serialise against preempt_on_tick / other CPUs' block-switches (same raw
     * scheduler lock) and only take a task no other CPU is running. */
    sched_raw_lock();
    int cpu = this_cpu();
    tasks[blocked_task].saved_ksp = frame_rsp;
    task_running_cpu[blocked_task] = -1;   /* blocking: release it */

    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (blocked_task + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == TASK_RUNNABLE && tasks[cand].cr3 != 0 &&
                tasks[cand].runnable_ctx && tasks[cand].saved_ksp && task_running_cpu[cand] < 0) {
            next = cand;
            break;
        }
    }
    if (next < 0) {
        /* Nothing else runnable here: revert the block (caller spins at user
         * level until the server catches up) and keep the task on this CPU. */
        tasks[blocked_task].state        = TASK_RUNNABLE;
        tasks[blocked_task].runnable_ctx = 1;
        task_running_cpu[blocked_task]   = cpu;
        sched_raw_unlock();
        return frame_rsp;
    }

    task_running_cpu[next] = cpu;
    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    if (cpu == 0) current_kernel_stack_top = kstop;
    set_current_task(next);
    uint64_t ksp = tasks[next].saved_ksp;
    sched_raw_unlock();
    return ksp;
#else
    tasks[blocked_task].saved_ksp = frame_rsp;

    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (blocked_task + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == TASK_RUNNABLE && tasks[cand].cr3 != 0 &&
                tasks[cand].runnable_ctx && tasks[cand].saved_ksp) {
            next = cand;
            break;
        }
    }
    if (next < 0) {
        /* No other runnable task.  Revert the block so the caller doesn't
         * deadlock permanently — it will spin at user level until the server
         * catches up. */
        tasks[blocked_task].state       = TASK_RUNNABLE;
        tasks[blocked_task].runnable_ctx = 1;
        return frame_rsp;
    }

    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
    current_kernel_stack_top = kstop;
    set_current_task(next);

    return tasks[next].saved_ksp;
#endif
}

void aslr_init_seed(void) {
    /* Seed the ASLR PRNG from the central CSPRNG (RDRAND / TSC-jitter seeded)
     * rather than a bare TSC read, which is observable from ring 3 and would
     * let userspace predict layout offsets. */
    secure_random_bytes(aslr_rng_state, sizeof(aslr_rng_state));
    /* Avoid the degenerate all-zero xorshift state. */
    if (aslr_rng_state[0] == 0 && aslr_rng_state[1] == 0) {
        aslr_rng_state[0] = 0x9E3779B97F4A7C15ULL;
        aslr_rng_state[1] = 0xC2B2AE3D27D4EB4FULL ^ read_tsc();
    }
}

/* Randomize an initial user stack pointer downward from `top`, staying within
 * the mapped stack window (the low-stack region maps 32 pages below the top, so
 * a few pages + sub-page of jitter is always backed). Result is 16-byte aligned
 * for ABI compliance. */
addr_t aslr_random_stack_top(addr_t top) {
    uint32_t page_off = aslr_random_offset(ASLR_MAX_STACK_RANDOM_PAGES);
    uint32_t sub_off = (uint32_t)(rust_rng_u64() & 0xFF0u); /* up to ~4080, 16-aligned */
    addr_t t = top - (addr_t)(page_off + sub_off);
    return t & ~((addr_t)0xF);
}

void print_boot_timestamp(void) {
    uint32_t ms = system_ticks;
    uint32_t sec = ms / 1000;
    uint32_t frac = ms % 1000;

    print("[ ");
    if (sec < 10) print("   ");
    else if (sec < 100) print("  ");
    else if (sec < 1000) print(" ");
    print_decimal(sec);
    print(".");
    if (frac < 10) print("00");
    else if (frac < 100) print("0");
    print_decimal(frac);
    print(" ] ");
}

void context_switch(int next) {
    
    int cur = get_current_task();
    if (next == cur || tasks[next].state != 1) return;

    asm volatile(
        "xor %%eax, %%eax\n"
        "xor %%ebx, %%ebx\n"
        "xor %%ecx, %%ecx\n"
        "xor %%edx, %%edx\n"
        ::: "eax", "ebx", "ecx", "edx", "memory"
    );

    asm volatile("mov %%esp, %0" : "=m"(tasks[cur].esp) : : "memory");
    tasks[cur].eip = (addr_t)__builtin_return_address(0);

    set_current_task(next);

    uintptr_t kstack_top = tasks[next].kernel_stack_top;
    if (kstack_top == 0) {
        kstack_top = (addr_t)&kernel_stacks[next][KERNEL_STACK_SIZE - 16];
    }
    set_tss_kernel_stack(kstack_top);
    current_kernel_stack_top = kstack_top;

    if (tasks[next].cr3 != 0 && next != 0) switch_cr3(tasks[next].cr3);
}

void schedule(void) {
    scheduler_lock_acquire();
    int cur = get_current_task();

    
    int next = -1;
    for (int i = 0; i < MAX_TASKS; i++) {
        int cand = (cur + 1 + i) % MAX_TASKS;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 && cand != 0) {
            next = cand;
            break;
        }
    }
    if (next < 0) {
        next = (cur + 1) % MAX_TASKS;
        while (next != cur && tasks[next].state != 1) {
            next = (next + 1) % MAX_TASKS;
        }
    }
    if (next < 0 || tasks[next].state != 1) {
        next = cur;
    }

    if (next != cur && tasks[next].cr3 != 0 && next != 0) {
        uintptr_t kstack_top = tasks[next].kernel_stack_top;
        if (kstack_top == 0) {
            kstack_top = (addr_t)&kernel_stacks[next][KERNEL_STACK_SIZE - 16];
        }
        set_tss_kernel_stack(kstack_top);
        current_kernel_stack_top = kstack_top;
        int do_launch = (cur == 0);
        if (!do_launch) {
            switch_cr3(tasks[next].cr3);
        }
        set_current_task(next);
        addr_t user_rsp = tasks[next].esp ? tasks[next].esp : (addr_t)0x007ff000;
        uint64_t launch_cr3 = tasks[next].cr3;
        scheduler_lock_release();
        if (do_launch) {

            __asm__ volatile (
                "movw $0x3f8, %%dx\n"
                "movb $'=', %%al; outb %%al, %%dx\n"
                "movb $'=', %%al; outb %%al, %%dx\n"
                "movb $'=', %%al; outb %%al, %%dx\n"
                "movb $' ', %%al; outb %%al, %%dx\n"
                "movb $'H', %%al; outb %%al, %%dx\n"
                "movb $'o', %%al; outb %%al, %%dx\n"
                "movb $'r', %%al; outb %%al, %%dx\n"
                "movb $'u', %%al; outb %%al, %%dx\n"
                "movb $'s', %%al; outb %%al, %%dx\n"
                "movb $' ', %%al; outb %%al, %%dx\n"
                "movb $'L', %%al; outb %%al, %%dx\n"
                "movb $'o', %%al; outb %%al, %%dx\n"
                "movb $'g', %%al; outb %%al, %%dx\n"
                "movb $'i', %%al; outb %%al, %%dx\n"
                "movb $'n', %%al; outb %%al, %%dx\n"
                "movb $0x0a, %%al; outb %%al, %%dx\n"
                ::: "rax", "rdx", "memory"
            );
            {
                uint64_t rip = (uint64_t)tasks[next].eip;
                uint64_t rspv = (uint64_t)user_rsp;
                uint64_t ucr3 = launch_cr3;
                __asm__ volatile (
                    "mov %2, %%cr3\n\t"
                    "mov $0x33, %%ax\n\t"
                    "mov %%ax, %%ds\n\t"
                    "mov %%ax, %%es\n\t"
                    "mov %%ax, %%fs\n\t"
                    "mov %%ax, %%gs\n\t"
                    "mov %1, %%rsp\n\t"
                    "pushq $0x33\n\t"
                    "pushq %1\n\t"
                    "pushq $0x2b\n\t"
                    "pushq %0\n\t"
                    "lretq\n\t"
                    :: "r"(rip), "r"(rspv), "r"(ucr3) : "memory", "ax"
                );
            }
        }
        return;
    }

    if (next != cur) {
        if (tasks[next].cr3 != 0 && next != 0) {
            
            switch_cr3(tasks[next].cr3);
            uintptr_t kstack_top = tasks[next].kernel_stack_top;
            if (kstack_top == 0) {
                kstack_top = (addr_t)&kernel_stacks[next][KERNEL_STACK_SIZE - 16];
            }
            set_tss_kernel_stack(kstack_top);
            current_kernel_stack_top = kstack_top;
            set_current_task(next);
        } else if (tasks[cur].cr3 != 0) {
            
            
            
            set_current_task(next);
        } else {
            context_switch(next);
        }
    } else if (tasks[0].state != 1) {
        tasks[0].state = 1;
        if (0 != cur) {
            context_switch(0);
        }
    }
    scheduler_lock_release();
}

void yield(void) {
    schedule();
}

/* Terminate task `id`: wake a SYS_WAIT waiter blocked on it, drop its signal
 * handler, mark it dead, and (SMP) release its running-CPU guard so no core will
 * reselect it. The caller (SYS_EXIT / SYS_KILL) is responsible for switching the
 * CPU away from the task if it happens to be the one currently running. */
void task_teardown(int id) {
    if (id <= 0 || id >= MAX_TASKS) return;

    int w = tasks[id].waiter;
    if (w >= 0 && w < MAX_TASKS) {
        /* Unblock a SYS_WAIT waiter: make it runnable and resumable so the
         * scheduler resumes it via the trap frame ipc_block_switch saved when it
         * blocked (it returns from SYS_WAIT with eax already 0). */
        if (tasks[w].state == TASK_BLOCKED_WAIT) {
            tasks[w].state        = TASK_RUNNABLE;
            tasks[w].runnable_ctx = 1;
        }
        tasks[id].waiter = -1;
    }

    tasks[id].sig_handler = 0;
    tasks[id].in_signal   = 0;
    tasks[id].state       = 0;   /* dead: the scheduler will not select it */
    tasks[id].runnable_ctx = 0;  /* and it has no resumable context any more */
    tasks[id].saved_ksp    = 0;
#ifdef SMP
    task_running_cpu[id]  = -1;  /* release the SMP mutual-exclusion guard */
#endif
}

/* Switch away from a task that has just terminated (SYS_EXIT / SYS_KILL-self),
 * called from interrupt_handler64 with the dead task's trap frame. The dead
 * frame is abandoned (not saved); we resume the next runnable task via its saved
 * trap frame — the same iretq mechanism the timer and blocking IPC use — and
 * return its kernel %rsp for the ISR epilogue. Returns 0 if nothing else is
 * runnable, so the caller can fall back to the kernel idle/reaper. */
uint64_t task_exit_switch(int dead) {
#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
#endif
    int next = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        int cand = (dead + i) % MAX_TASKS;
        if (cand == 0) continue;
        if (tasks[cand].state == 1 && tasks[cand].cr3 != 0 && tasks[cand].runnable_ctx
            && tasks[cand].saved_ksp
#ifdef SMP
            && task_running_cpu[cand] < 0
#endif
           ) { next = cand; break; }
    }
    if (next < 0) {
#ifdef SMP
        sched_raw_unlock();
#endif
        return 0;   /* nothing else to run — caller idles */
    }
#ifdef SMP
    task_running_cpu[next] = cpu;
#endif
    switch_cr3(tasks[next].cr3);
    uint64_t kstop = task_kstack_top(next);
    set_tss_kernel_stack(kstop);
#ifdef SMP
    if (cpu == 0) current_kernel_stack_top = kstop;
#else
    current_kernel_stack_top = kstop;
#endif
    set_current_task(next);
    uint64_t ksp = tasks[next].saved_ksp;
#ifdef SMP
    sched_raw_unlock();
#endif
    return ksp;
}

/* Enter task `t` via the fresh ring-3 context sched_prepare_user_context just
 * fabricated for it — used by SYS_EXEC_NAMED, which replaced the task's image in
 * place. Mirrors task_exit_switch's tail (install the address space + kernel
 * stack, hand the saved frame to the ISR epilogue) but re-enters the *same* task
 * rather than switching away. Returns the kernel %rsp for the ISR epilogue. */
uint64_t exec_reenter_switch(int t) {
    if (t <= 0 || t >= MAX_TASKS) return 0;
#ifdef SMP
    sched_raw_lock();
    int cpu = this_cpu();
    task_running_cpu[t] = cpu;
#endif
    switch_cr3(tasks[t].cr3);
    uint64_t kstop = task_kstack_top(t);
    set_tss_kernel_stack(kstop);
#ifdef SMP
    if (cpu == 0) current_kernel_stack_top = kstop;
#else
    current_kernel_stack_top = kstop;
#endif
    set_current_task(t);
    uint64_t ksp = tasks[t].saved_ksp;
#ifdef SMP
    sched_raw_unlock();
#endif
    return ksp;
}

int this_cpu(void) {

    volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
    uint32_t id_reg = lapic[0x20 / 4];
    uint32_t cpu = (id_reg >> 24) & 0xFF;
    if (cpu >= MAX_CPUS) cpu = 0;
    return (int)cpu;
}

int get_current_task(void) {
    int c = this_cpu();
    if (c < 0 || c >= MAX_CPUS) c = 0;
    return percpu_current_task[c];
}

void set_current_task(int v) {
    int c = this_cpu();
    if (c < 0 || c >= MAX_CPUS) c = 0;
    percpu_current_task[c] = v;
    
    if (c == 0) current_task = v;
}

void scheduler_lock_acquire(void) { spin_lock(&scheduler_lock); }
void scheduler_lock_release(void) { spin_unlock(&scheduler_lock); }


static volatile int irq_lock_depth = 0;

void spin_lock(spinlock_t *lock) {
    __asm__ volatile ("cli" ::: "memory");
    irq_lock_depth++;
    while (__sync_lock_test_and_set(&lock->locked, 1)) {
        while (lock->locked) { __asm__ volatile ("pause" ::: "memory"); }
    }
}
void spin_unlock(spinlock_t *lock) {
    __sync_lock_release(&lock->locked);

    if (irq_lock_depth > 0 && --irq_lock_depth == 0) {
        __asm__ volatile ("sti" ::: "memory");
    }
}

/* ===== SMP: application-processor bringup ================================== *
 * The BSP copies the real-mode trampoline (src/boot/ap_trampoline.S) to
 * AP_TRAMP_PHYS, publishes three qword cells the trampoline consumes, then wakes
 * every AP at once with a broadcast INIT-SIPI-SIPI ("all excluding self", so no
 * APIC-id enumeration / MADT parse is needed).  Each AP walks itself up to long
 * mode, picks a private idle stack by LAPIC id, and enters ap_entry64().  All of
 * this is gated on SMP=1; the default build is single-CPU and never wakes an AP.
 *
 * smp_cpus_online counts CPUs that finished bringup (BSP starts it at 1) and is
 * the source of truth for smp_get_online_count() and the TLB-shootdown path. */
static volatile int smp_cpus_online = 1;

/* Set once the local APIC is up on the BSP (so this_cpu() is safe to call).
 * Gates the per-CPU TSS routing in set_tss_kernel_stack(); stays 0 in the
 * single-CPU default build. Read by gdt.c. */
volatile int smp_active = 0;

/* Low-memory cells shared with the trampoline. MUST match ap_trampoline.S. */
#define AP_TRAMP_PHYS        0x8000UL
#define AP_STACK_BASE_CELL   0x8FD8UL
#define AP_CR3_CELL          0x8FE0UL
#define AP_ENTRY_CELL        0x8FE8UL
#define AP_IDLE_STACK_SIZE   0x4000UL

static inline void lapic_write(uint32_t reg, uint32_t val) {
    volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
    lapic[reg / 4] = val;
}
static inline uint32_t lapic_read(uint32_t reg) {
    volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
    return lapic[reg / 4];
}

/* Enable the local APIC: clear the task-priority register (accept every vector)
 * and set the spurious-interrupt vector register (enable bit 8 + vector 0xFF).
 * Run once by the BSP and once by every AP. */
static void lapic_enable(void) {
    lapic_write(0x80, 0);                                    /* TPR = 0 */
    lapic_write(0xF0, (lapic_read(0xF0) & 0xFFFFFF00) | 0x100 | 0xFF);
}

static void lapic_enable_bsp(void) { lapic_enable(); }

/* Signal end-of-interrupt to the local APIC (write 0 to the EOI register).
 * Called from the vector-0x40 LAPIC-timer path in idt.c. */
void lapic_eoi(void) { lapic_write(0xB0, 0); }

static void smp_busy_delay(int iters) {
    for (volatile int d = 0; d < iters; d++) __asm__ volatile ("pause");
}

#ifdef SMP
/* Per-CPU idle stacks. APs index by LAPIC id (see ap_trampoline.S), so MAX_CPUS
 * slots cover ids 0..MAX_CPUS-1; slot 0 (the BSP's) is unused on this path. */
static uint8_t ap_idle_stacks[MAX_CPUS][AP_IDLE_STACK_SIZE] __attribute__((aligned(16)));

extern uint8_t ap_trampoline_start[], ap_trampoline_end[];
extern void ap_load_kernel_segments(void);   /* lowlevel64.S */
void ap_load_idt(void);                       /* idt.c */
void setup_ap_tss(int cpu, uintptr_t rsp0);   /* gdt.c */

/* Count of LAPIC-timer ticks taken across all APs — the SMP self-test reads it
 * to confirm the APs are actually being interrupted (and thus preemptible). */
volatile unsigned long ap_timer_ticks = 0;

/* LAPIC timer registers + the calibrated initial count for a ~100 Hz tick. */
#define LAPIC_TIMER_LVT    0x320
#define LAPIC_TIMER_INIT   0x380
#define LAPIC_TIMER_CUR    0x390
#define LAPIC_TIMER_DIV    0x3E0
#define LAPIC_TIMER_VECTOR 0x40
static uint32_t lapic_timer_count = 0;

/* Measure the LAPIC timer frequency against PIT channel 2 (a one-shot mode-0
 * countdown gated on port 0x61) and record the count for a ~10 ms period. Run
 * once on the BSP before the APs start their periodic timers. */
static void lapic_timer_calibrate(void) {
    lapic_write(LAPIC_TIMER_DIV, 0x3);                       /* divide by 16 */
    lapic_write(LAPIC_TIMER_LVT, (1u << 16) | LAPIC_TIMER_VECTOR);  /* masked */

    uint8_t p61 = inb(0x61);
    outb(0x61, (uint8_t)((p61 & 0xFD) | 0x01));   /* gate2 on, speaker off */
    outb(0x43, 0xB0);                              /* ch2, lo/hi, mode 0 */
    uint16_t cnt = 11932;                          /* ~10 ms @ 1.193182 MHz */
    outb(0x42, (uint8_t)(cnt & 0xFF));
    outb(0x42, (uint8_t)(cnt >> 8));

    lapic_write(LAPIC_TIMER_INIT, 0xFFFFFFFFu);    /* start LAPIC countdown */
    while (!(inb(0x61) & 0x20)) { }                /* wait for PIT OUT2 high */
    uint32_t remaining = lapic_read(LAPIC_TIMER_CUR);
    lapic_write(LAPIC_TIMER_INIT, 0);              /* stop */

    lapic_timer_count = 0xFFFFFFFFu - remaining;   /* ticks in ~10 ms => 100 Hz */
    if (lapic_timer_count < 1000) lapic_timer_count = 1000000;  /* sane fallback */
}

/* Start this CPU's LAPIC timer in periodic mode at the calibrated rate. */
static void lapic_timer_start_periodic(void) {
    lapic_write(LAPIC_TIMER_DIV, 0x3);                              /* divide by 16 */
    lapic_write(LAPIC_TIMER_LVT, (1u << 17) | LAPIC_TIMER_VECTOR);  /* periodic */
    lapic_write(LAPIC_TIMER_INIT, lapic_timer_count ? lapic_timer_count : 1000000);
}

/* The AP idle context: sit with interrupts enabled so the LAPIC timer keeps
 * firing. Each tick runs preempt_on_tick(), which pulls a runnable task onto
 * this CPU when one is available. Reached both as the AP's initial context and
 * whenever it has no task to run. */
void ap_idle_loop(void) {
    for (;;) __asm__ volatile ("sti; hlt");
}

/* 64-bit C entry for every AP, reached from the trampoline on the AP's private
 * idle stack.  Adopt the shared kernel GDT/IDT, install a per-CPU TSS (own RSP0
 * + IST fault stacks), enable the local APIC + its periodic timer, check in, and
 * drop into the idle loop where timer ticks drive the scheduler. */
void ap_entry64(void) {
    ap_load_kernel_segments();    /* shared kernel GDT: CS=0x08, data=0x10 */
    ap_load_idt();                /* shared kernel IDT */

    int cpu = this_cpu();
    uintptr_t idle_top = (uintptr_t)&ap_idle_stacks[0][0]
                       + (uintptr_t)(cpu + 1) * AP_IDLE_STACK_SIZE;
    setup_ap_tss(cpu, idle_top);  /* per-CPU TSS + IST, ltr'd */

    lapic_enable();
    lapic_timer_start_periodic();

    __sync_fetch_and_add(&smp_cpus_online, 1);

    ap_idle_loop();               /* timer ticks now schedule tasks onto this CPU */
}

/* Broadcast INIT then two SIPIs to "all excluding self" (ICR destination
 * shorthand 0b11).  Wakes every AP without an APIC-id list. */
static void lapic_broadcast_init_sipi(uint8_t vector) {
    lapic_write(0x300, 0x000C4500);                /* INIT assert, all-excl-self */
    smp_busy_delay(500000);                        /* ~10 ms settle */
    lapic_write(0x300, 0x000C4600 | vector);       /* SIPI #1 */
    smp_busy_delay(50000);
    lapic_write(0x300, 0x000C4600 | vector);       /* SIPI #2 (spec: send twice) */
    smp_busy_delay(50000);
}

static void smp_start_aps(void) {
    /* No task is running on any CPU yet. */
    for (int i = 0; i < MAX_TASKS; i++) task_running_cpu[i] = -1;

    /* Calibrate the LAPIC timer once (on the BSP, using the PIT) so every AP can
     * start its periodic timer at a known ~100 Hz rate. */
    lapic_timer_calibrate();

    /* Stage the trampoline at its real-mode SIPI load address. */
    uint8_t *dst = (uint8_t *)AP_TRAMP_PHYS;
    uint32_t n = (uint32_t)(ap_trampoline_end - ap_trampoline_start);
    for (uint32_t i = 0; i < n; i++) dst[i] = ap_trampoline_start[i];

    /* Publish the cells the trampoline reads (CR3, entry, idle-stack base). */
    uint64_t cr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(cr3));
    *(volatile uint64_t *)AP_CR3_CELL        = cr3;
    *(volatile uint64_t *)AP_ENTRY_CELL      = (uint64_t)(uintptr_t)&ap_entry64;
    *(volatile uint64_t *)AP_STACK_BASE_CELL = (uint64_t)(uintptr_t)&ap_idle_stacks[0][0];
    __asm__ volatile ("mfence" ::: "memory");

    lapic_broadcast_init_sipi((uint8_t)(AP_TRAMP_PHYS >> 12));   /* vector 0x08 */

    /* Wait (bounded) for the APs to check in. */
    for (int spins = 0; spins < 200 && smp_cpus_online < MAX_CPUS; spins++)
        smp_busy_delay(20000);

    print("[smp] CPUs online: ");
    print_hex((uint64_t)smp_cpus_online);
    print("\n");
}
#endif /* SMP */

void smp_bringup(void) {
    lapic_enable_bsp();
#ifdef SMP
    /* LAPIC is mapped (paging_init) and now enabled, so this_cpu() is safe and
     * per-CPU TSS routing can turn on before any AP or context switch runs. */
    smp_active = 1;
    smp_start_aps();
#endif

    println("[ok] kernel ready, starting init...");
#ifdef PREEMPT_SELFTEST
    /* Gated: spawn two non-yielding ring-3 tracers and prove the timer
     * time-slices them (prints PREEMPT_SELFTEST: PASS). Does not return -- it
     * launches into ring 3 and the tasks run forever. */
    preempt_selftest();
#elif defined(SIGNAL_SELFTEST)
    /* Gated: spawn a task that faults on purpose and prove its registered
     * handler runs instead of the task being killed (SIGNAL_SELFTEST: PASS). */
    signal_selftest();
#elif defined(FS_SELFTEST)
    /* Gated: spawn the userspace fs_server plus a client that drives it over
     * IPC (mkdir/create/write/read/readdir/lookup/delete) against the kernel's
     * encrypted object store, proving the Phase 2 stack end-to-end
     * (prints FS_SELFTEST: PASS). */
    fs_selftest();
#elif defined(NEWLIB_SELFTEST)
    /* Gated: spawn hello_newlib (newlib + posix + malloc on Horus) and confirm
     * printf/sprintf/malloc/string ops all work end-to-end (prints
     * NEWLIB_SELFTEST: PASS to serial). */
    newlib_selftest();
#elif defined(SMP_SELFTEST)
    /* Gated: spawn a pool of forever-looping workers and prove the application
     * processors pull and run them concurrently (prints SMP_SELFTEST: PASS). */
    smp_selftest();
#elif defined(PROC_SELFTEST)
    /* Gated: drive SYS_EXIT + SYS_KILL from ring 3 and confirm both children
     * reach the dead state (prints PROC_SELFTEST: PASS). */
    proc_selftest();
#else
#ifdef ELF_SELFTEST
    /* Gated: verify try_elf_load's W^X enforcement on a real ELF before the
     * (never-returning) drop to the userspace shell. This is the actual
     * pre-userspace point — smp_bringup() spawns the shell and lretq's to
     * ring 3, so it never returns to kernel_main. */
    elf_loader_selftest();
#endif
    spawn_initial_userspace_init();
#endif
}

void tlb_shootdown(uint64_t vaddr) {
    __asm__ volatile ("invlpg (%0)" :: "r"(vaddr) : "memory");
}

#ifdef SMP
/* TLB-shootdown acknowledgement protocol.
 *
 * The initiator serialises on shootdown_lock (a raw test-and-set that does NOT
 * disable interrupts), sets smp_shootdown_pending to the number of other CPUs,
 * broadcasts vector 0xFB, and spins until every receiver has flushed and
 * decremented the counter. Because the lock does not mask interrupts and the
 * single caller (below) is invoked with interrupts enabled and no scheduler lock
 * held, an initiator waiting for acks -- or waiting for the lock -- still
 * services other CPUs' shootdown IPIs, so two initiators cannot wedge each
 * other. A bounded spin is a final backstop against a wedged CPU. */
static volatile int shootdown_lock = 0;
volatile int smp_shootdown_pending = 0;

/* Receiver side (idt.c, vector 0xFB), after flushing its TLB. */
void smp_ack_shootdown(void) {
    __sync_fetch_and_sub(&smp_shootdown_pending, 1);
}
#endif

/* Flush `vaddr` locally and, on a multi-CPU system, ask every other CPU to flush
 * too and wait for them to acknowledge before returning -- so once this returns
 * no CPU can still hold a stale translation for `vaddr`. On a single-CPU system
 * it is just a local invlpg.
 *
 * MUST be called with interrupts enabled and no scheduler/​page lock held (see
 * the protocol note above); it is therefore NOT used on the switch_cr3 fast path
 * (a local CR3 reload already flushes the local TLB). */
void smp_maybe_shootdown(uint64_t vaddr) {
    tlb_shootdown(vaddr);
#ifdef SMP
    if (smp_get_online_count() > 1) {
        while (__sync_lock_test_and_set(&shootdown_lock, 1))
            __asm__ volatile ("pause");              /* IF stays set: still service IPIs */
        smp_shootdown_pending = smp_get_online_count() - 1;
        __asm__ volatile ("mfence" ::: "memory");
        lapic_write(0x300, 0x000C0000 | 0xFB);       /* all-excluding-self, vec 0xFB */
        for (int i = 0; i < 100000000 && smp_shootdown_pending > 0; i++)
            __asm__ volatile ("pause");
        __sync_lock_release(&shootdown_lock);
    }
#endif
}

int smp_get_online_count(void) {
    return smp_cpus_online;
}
