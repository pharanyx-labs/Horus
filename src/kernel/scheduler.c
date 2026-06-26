#include "kernel.h"

tcb_t tasks[MAX_TASKS];
int current_task = 0;  
int percpu_current_task[MAX_CPUS];

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

#if defined(__x86_64__)
    create_task(0, 0, 0);
#else
    create_task(0, USER_VIRT_BASE + 3, DEMO_TASK_STACK_TOP);
#endif

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

void create_task(int id, addr_t entry, addr_t stack_top) {
    if (id >= MAX_TASKS) return;

    tasks[id].state = 1;
    tasks[id].esp = (addr_t)(stack_top ? (stack_top - 256) : 0);
    tasks[id].eip = entry;
    tasks[id].cap_tcb = id;

create_user_pagedir(id);

    static struct capability cspace_pool[MAX_TASKS][256];
    tasks[id].cspace = cspace_pool[id];
    tasks[id].cspace_size = 256;

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
    create_task(id, entry, stack_top);
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
    return 0;
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

static volatile int smp_cpus_online = 1;

#define AP_TRAMP_PHYS 0x8000UL
#define AP_COMM_CR3   0x510UL

static const uint8_t ap_trampoline_blob[512] = {
    
    0xFA,                         
    0x31,0xC0,                    
    0x8E,0xD8,                    
    0x8E,0xC0,                    
    0x8E,0xD0,                    
    0x0F,0x01,0x16,0xF0,0x81,     
    0x0F,0x20,0xC0,               
    0x0C,0x01,                    
    0x0F,0x22,0xC0,               
    
    0xBA,0xF8,0x03,               
    0xB0,0x50,                    
    0xEE,                         
    0xB0,0x45,                    
    0xEE,
    0xEA,0x28,0x80,0x08,0x00,     
    
    
    0xBA,0xF8,0x03,0xB0,0x33,0xEE,0xB0,0x32,0xEE,
    0x66,0xB8,0x18,0x00,          
    0x66,0x8E,0xD8, 0x66,0x8E,0xC0, 0x66,0x8E,0xD0, 0x66,0x8E,0xE0, 
    0x0F,0x20,0xE0,               
    0x0D,0xA0,0x00,0x00,0x00,     
    0x0F,0x22,0xE0,               
    
    0xBA,0xF8,0x03,0xB0,0x43,0xEE,0xB0,0x34,0xEE,
    0xB9,0x80,0x00,0x00,0xC0,     
    0x0F,0x32,                    
    0x0D,0x00,0x01,0x00,0x00,     
    0x0F,0x30,                    
    
    0xBA,0xF8,0x03,0xB0,0x45,0xEE,0xB0,0x46,0xEE,
    0xA1,0x10,0x05,0x00,0x00,     
    0x0F,0x22,0xD8,               
    
    0xBA,0xF8,0x03,0xB0,0x43,0xEE,0xB0,0x52,0xEE,
    0x0F,0x20,0xC0,               
    0x0D,0x00,0x00,0x00,0x80,     
    0x0F,0x22,0xC0,               
    
    0xBA,0xF8,0x03,               
    0xB0,0x50,                    
    0xEE,
    0xB0,0x47,                    
    0xEE,
    0xEA,0x97,0x80,0x10,0x00,     
    
    
    0x48,0xBA,0xF8,0x03,0x00,0x00,0x00,0x00,0x00,0x00,  
    0xB0,0x36,                    
    0xEE,
    0xB0,0x34,                    
    0xEE,
    
    0xB0,0x4A,0xEE,0xB0,0x4D,0xEE, 
    0x48,0x31,0xC0,               
    0xB8,0x18,0x00,0x00,0x00,     
    0x8E,0xD8,0x8E,0xC0,0x8E,0xD0,0x8E,0xE0, 
    
    0xB0,0x50,0xEE,0xB0,0x54,0xEE, 
    
    0x48,0xC7,0xC4,0x00,0x00,0x02,0x00,   
    0xB0,0x41,0xEE,0xB0,0x50,0xEE,        
    
    0x48,0xB8,0x00,0x00,0xE0,0xFE,0x00,0x00,0x00,0x00, 
    0x31,0xC9,                         
    0x89,0x88,0x80,0x02,0x00,0x00,     
    0x8B,0x90,0xF0,0x00,0x00,0x00,     
    0x81,0xE2,0x00,0xFF,0xFF,0xFF,     
    0x81,0xCA,0xFF,0x01,0x00,0x00,     
    0x89,0x90,0xF0,0x00,0x00,0x00,     
    0x89,0x88,0x80,0x02,0x00,0x00,     
    0xB0,0x4C,0xEE,0xB0,0x45,0xEE,     
    
    0x48,0xB8,0x20,0x05,0x00,0x00,0x00,0x00,0x00,0x00, 
    0xFE,0x00,                          
    0xB0,0x42,0xEE,0xB0,0x50,0xEE,     
    0xFA,                               
    0xF4,                               
    0xEB,0xFD,                          
    
    
};

static uint8_t ap_gdt32[32] = {
    0,0,0,0,0,0,0,0,                         
    0xFF,0xFF,0x00,0x00,0x00,0x9A,0xCF,0x00, 
    0xFF,0xFF,0x00,0x00,0x00,0x9A,0xAF,0x00, 
    0xFF,0xFF,0x00,0x00,0x00,0x92,0xCF,0x00  
};

void ap_entry64(void) {
    __asm__ volatile ("movq $0x20000, %%rsp" ::: "memory");

    __asm__ volatile (
        "movw $0x3f8, %%dx\n"
        "movb $'A', %%al; outb %%al, %%dx\n"
        "movb $'P', %%al; outb %%al, %%dx\n"
        "movb $'6', %%al; outb %%al, %%dx\n"
        "movb $'4', %%al; outb %%al, %%dx\n"
        "movb $'E', %%al; outb %%al, %%dx\n"
        "movb $'N', %%al; outb %%al, %%dx\n"
        ::: "rax","rdx","memory"
    );

    volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
    lapic[0x280/4] = 0;
    lapic[0xF0/4] = (lapic[0xF0/4] & 0xFFFFFF00) | 0xFF | 0x100;
    lapic[0x280/4] = 0;

    int cpu = this_cpu();
    if (cpu <= 0 || cpu >= MAX_CPUS) cpu = 1;

    __sync_fetch_and_add(&smp_cpus_online, 1);

    __asm__ volatile (
        "movw $0x3f8, %%dx\n"
        "movb $'O', %%al; outb %%al, %%dx\n"
        "movb $'K', %%al; outb %%al, %%dx\n"
        ::: "rax","rdx","memory"
    );

    for (;;) {
        __asm__ volatile ("cli; hlt" ::: "memory");
    }
}

static void lapic_enable_bsp(void) {
    volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
    
    lapic[0x280/4] = 0;
    
    lapic[0xF0/4] = (lapic[0xF0/4] & 0xFFFFFF00) | 0xFF | 0x100;
    lapic[0x280/4] = 0; 
}

static void lapic_send_init(uint32_t apic_id) {
    volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
    lapic[0x280/4] = 0; 
    
    __asm__ volatile ("movw $0x3f8, %%dx; movb $'I', %%al; outb %%al, %%dx; movb $'H', %%al; outb %%al, %%dx" ::: "rax","rdx","memory");
    lapic[0x310/4] = (apic_id << 24); 
    __asm__ volatile ("movw $0x3f8, %%dx; movb $'I', %%al; outb %%al, %%dx; movb $'1', %%al; outb %%al, %%dx" ::: "rax","rdx","memory");
    lapic[0x300/4] = 0x00004500U;     
    for (volatile int d=0; d<400000; d++) { __asm__ volatile("pause"); }
    __asm__ volatile ("movw $0x3f8, %%dx; movb $'I', %%al; outb %%al, %%dx; movb $'2', %%al; outb %%al, %%dx" ::: "rax","rdx","memory");
    lapic[0x300/4] = 0x00004500U;     
    for (volatile int d=0; d<400000; d++) { __asm__ volatile("pause"); }
}

static void lapic_send_sipi(uint32_t apic_id, uint8_t vector) {
    volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
    lapic[0x280/4] = 0; 
    
    __asm__ volatile ("movw $0x3f8, %%dx; movb $'S', %%al; outb %%al, %%dx; movb $'H', %%al; outb %%al, %%dx" ::: "rax","rdx","memory");
    lapic[0x310/4] = (apic_id << 24);
    lapic[0x300/4] = 0x00004600U | vector;  
    __asm__ volatile ("movw $0x3f8, %%dx; movb $'S', %%al; outb %%al, %%dx; movb $'1', %%al; outb %%al, %%dx" ::: "rax","rdx","memory");
    __asm__ volatile ("movw $0x3f8, %%dx; movb $'.', %%al; outb %%al, %%dx" ::: "rax","rdx","memory");
    for (volatile int d = 0; d < 600000; d++) { __asm__ volatile("pause"); }
    __asm__ volatile ("movw $0x3f8, %%dx; movb $'.', %%al; outb %%al, %%dx" ::: "rax","rdx","memory");
    
    lapic[0x300/4] = 0x00004600U | vector;
    __asm__ volatile ("movw $0x3f8, %%dx; movb $'S', %%al; outb %%al, %%dx; movb $'2', %%al; outb %%al, %%dx" ::: "rax","rdx","memory");
    for (volatile int d = 0; d < 600000; d++) { __asm__ volatile("pause"); }
    
    __asm__ volatile ("movw $0x3f8, %%dx; movb $'S', %%al; outb %%al, %%dx; movb $'D', %%al; outb %%al, %%dx" ::: "rax","rdx","memory");
}

void smp_bringup(void) {
    lapic_enable_bsp();

    
    uint64_t cr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(cr3) : : "memory");
    
    uint32_t cr3_low = (uint32_t)cr3;
    __asm__ volatile (
        "movl %0, (%1)"
        :: "r"(cr3_low), "r"(AP_COMM_CR3)
        : "memory"
    );

    
    uint8_t *dst = (uint8_t *)AP_TRAMP_PHYS;
    
    for (int i = 0; i < (int)sizeof(ap_trampoline_blob); i++) dst[i] = ap_trampoline_blob[i];

    
    uint16_t *gdt_lim = (uint16_t *)(dst + 0x1F0);
    uint32_t *gdt_base = (uint32_t *)(dst + 0x1F2);
    *gdt_lim = sizeof(ap_gdt32) - 1;
    *gdt_base = (uint32_t)(AP_TRAMP_PHYS + 0x200); 
    
    uint8_t *gdt_dst = (uint8_t *)(AP_TRAMP_PHYS + 0x200);
    for (int i = 0; i < 32; i++) gdt_dst[i] = ap_gdt32[i];

    
    extern void ap_entry64(void);
    uint64_t ap_target = (uint64_t)(uintptr_t)&ap_entry64;
    __asm__ volatile (
        "movq %0, (%1)"
        :: "r"(ap_target), "r"(0x528UL)
        : "memory"
    );
    
    __asm__ volatile (
        "movb $1, (%0)"
        :: "r"(0x520UL)
        : "memory"
    );


    
    (void)lapic_send_init; (void)lapic_send_sipi;


    for (volatile int d=0; d < 100000; d++) {
        __asm__ volatile("pause");
    }

    println("[ok] kernel ready, starting init...");
    spawn_initial_userspace_shell();
}

void tlb_shootdown(uint64_t vaddr) {
    __asm__ volatile ("invlpg (%0)" :: "r"(vaddr) : "memory");
}

void smp_maybe_shootdown(uint64_t vaddr) {
    tlb_shootdown(vaddr);
    if (smp_get_online_count() > 1) {
        __asm__ volatile ("mfence" ::: "memory");
        volatile uint32_t *lapic = (volatile uint32_t *)0xFEE00000UL;
        lapic[0x300/4] = 0x000C0000 | 0xFB;
    }
}

int smp_get_online_count(void) {
    uint8_t cell;
    
    __asm__ volatile ("movb 0x520, %0" : "=q"(cell) : : "memory");
    if (cell > 0) {
        
        if ((int)cell > smp_cpus_online) smp_cpus_online = (int)cell;
        return (int)cell;
    }
    return smp_cpus_online;
}
