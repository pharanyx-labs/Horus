/* selftest.c -- gated in-kernel self-tests (ELF loader / preemption / SMP /
 * process lifecycle / signals / filesystem / newlib). Every block is compiled
 * only under its -D*_SELFTEST switch, so the default build yields an (almost)
 * empty object. Split out of syscall.c. */
#include "syscall_internal.h"
#if defined(FS_SELFTEST) || defined(NEWLIB_SELFTEST)
#include "fs_proto.h"   /* FS_EP_REQ/FS_EP_REP for the FS self-test harnesses */
#endif

#ifdef ELF_SELFTEST
/* In-kernel self-test of the ELF loader's W^X enforcement (gated; never in the
 * ship build). Loads a real multi-segment ELF (userspace/elftest.elf, embedded
 * in multiboot.S) through the production do_spawn -> try_elf_load path, then
 * inspects the resulting page-table entries to prove try_elf_load honoured each
 * PT_LOAD's p_flags: .text R+X (executable), .data R+W+NX, .rodata R(O)+NX.
 * Because EFER.NXE is asserted enabled at boot, correct NX/WRITE bits mean the
 * CPU will enforce W^X. Prints ELF_SELFTEST: PASS / FAIL <reason> to serial;
 * the headless smoke test (make smoke-elf) asserts on PASS. */
#define SELFTEST_PTE_PRESENT  (1ULL << 0)
#define SELFTEST_PTE_WRITE    (1ULL << 1)
#define SELFTEST_PTE_USER     (1ULL << 2)
#define SELFTEST_PTE_NX       (1ULL << 63)
#define SELFTEST_PTE_PHYS     0x000FFFFFFFFFF000ULL

static int selftest_read_byte(uint64_t cr3, uint64_t vaddr, uint8_t *out) {
    uint64_t pte = user_lookup_pte(cr3, vaddr);
    if (!(pte & SELFTEST_PTE_PRESENT)) return -1;
    uint64_t phys = (pte & SELFTEST_PTE_PHYS) | (vaddr & 0xFFF);
    *out = *(volatile uint8_t *)(uintptr_t)phys;   /* user phys is identity-mapped under the kernel pml4 */
    return 0;
}

static int selftest_read_u32(uint64_t cr3, uint64_t vaddr, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t b;
        if (selftest_read_byte(cr3, vaddr + i, &b) != 0) return -1;
        v |= (uint32_t)b << (i * 8);
    }
    *out = v;
    return 0;
}

void elf_loader_selftest(void) {
    extern uint8_t embedded_elftest_start[];
    extern uint8_t embedded_elftest_end[];
    uint32_t sz = (uint32_t)(embedded_elftest_end - embedded_elftest_start);

    print("ELF_SELFTEST: begin\n");
    if (sz == 0 || sz > MAX_PROGRAM_SIZE) { print("ELF_SELFTEST: FAIL embed-size\n"); return; }

    /* Stage the raw ELF and arm it; try_elf_load recomputes the real entry. */
    for (uint32_t i = 0; i < sz; i++) loader_staging[i] = embedded_elftest_start[i];
    armed_hdr.entry = 0;
    armed_hdr.size  = sz;
    armed_hdr.name[0] = 'e'; armed_hdr.name[1] = 'l'; armed_hdr.name[2] = 'f';
    armed_hdr.name[3] = 't'; armed_hdr.name[4] = 0;
    program_armed = 1;

    int saved = get_current_task();
    int pid = do_spawn();                 /* runs the real try_elf_load + W^X pass */
    if (pid <= 0) { print("ELF_SELFTEST: FAIL spawn\n"); set_current_task(saved); return; }

    uint64_t cr3  = tasks[pid].cr3;
    uint32_t base = tasks[pid].image_base;   /* ASLR-randomized load base */

    /* Parse the three PT_LOAD program headers from the staged (base-0) ELF to
     * locate each segment by its permission flags, so the checks hold at the
     * randomized base (identify by PF_X -> text, PF_W -> data, R-only -> rodata). */
    const uint8_t *est = loader_staging;
    uint32_t e_phoff = elf_rd32(est + 28);
    uint16_t e_phnum = (uint16_t)est[44] | ((uint16_t)est[45] << 8);
    uint32_t text_va = 0xFFFFFFFFu, ro_va = 0xFFFFFFFFu, data_va = 0xFFFFFFFFu;
    for (uint16_t i = 0; i < e_phnum && i < 16; i++) {
        const uint8_t *p = est + e_phoff + (uint32_t)i * 32;
        if (elf_rd32(p) != 1) continue;            /* PT_LOAD */
        uint32_t va = elf_rd32(p + 8);
        uint32_t fl = elf_rd32(p + 24);
        if      (fl & 1u) text_va = va;            /* PF_X */
        else if (fl & 2u) data_va = va;            /* PF_W */
        else              ro_va   = va;            /* R only */
    }

    int ok = 1;
    const char *why = "";
    if (text_va == 0xFFFFFFFFu || ro_va == 0xFFFFFFFFu || data_va == 0xFFFFFFFFu) {
        ok = 0; why = "phdr-missing";
    }

    uint64_t pte_text = 0, pte_data = 0, pte_ro = 0;
    if (ok) {
        pte_text = user_lookup_pte(cr3, (uint64_t)base + text_va);
        pte_data = user_lookup_pte(cr3, (uint64_t)base + data_va);
        pte_ro   = user_lookup_pte(cr3, (uint64_t)base + ro_va);

        if      (!((pte_text & SELFTEST_PTE_PRESENT) && (pte_text & SELFTEST_PTE_USER))) { ok = 0; why = "text-absent"; }
        else if (!((pte_data & SELFTEST_PTE_PRESENT) && (pte_data & SELFTEST_PTE_USER))) { ok = 0; why = "data-absent"; }
        else if (!((pte_ro   & SELFTEST_PTE_PRESENT) && (pte_ro   & SELFTEST_PTE_USER))) { ok = 0; why = "rodata-absent"; }
        /* W^X execute bits: code executable (NX clear), data/rodata non-exec. */
        else if (pte_text & SELFTEST_PTE_NX)    { ok = 0; why = "text-noexec"; }
        else if (!(pte_data & SELFTEST_PTE_NX)) { ok = 0; why = "data-executable"; }
        else if (!(pte_ro   & SELFTEST_PTE_NX)) { ok = 0; why = "rodata-executable"; }
        /* write bits: data writable, rodata read-only. */
        else if (!(pte_data & SELFTEST_PTE_WRITE)) { ok = 0; why = "data-readonly"; }
        else if (pte_ro & SELFTEST_PTE_WRITE)      { ok = 0; why = "rodata-writable"; }
    }

    /* Content spot-check: markers copied to the right (randomized) vaddrs. The
     * data segment holds selfptr (4 bytes) then the 0xD2 marker. */
    if (ok) {
        uint8_t b;
        if (selftest_read_byte(cr3, (uint64_t)base + ro_va, &b) != 0 || b != 0x5A)      { ok = 0; why = "rodata-marker"; }
        else if (selftest_read_byte(cr3, (uint64_t)base + data_va + 4, &b) != 0 || b != 0xD2) { ok = 0; why = "data-marker"; }
    }

    /* Relocation check: selfptr (first word of .data) was linked as &rodata_marker
     * (link vaddr == ro_va) and must have been fixed up to base + ro_va by the
     * loader's R_386_RELATIVE handling. If relocation were skipped it would still
     * hold the small link-time value (< base) and this fails. */
    if (ok) {
        uint32_t selfptr = 0;
        uint8_t b;
        if (selftest_read_u32(cr3, (uint64_t)base + data_va, &selfptr) != 0) { ok = 0; why = "selfptr-read"; }
        else if (selfptr != base + ro_va)                                   { ok = 0; why = "selfptr-not-relocated"; }
        else if (selftest_read_byte(cr3, selfptr, &b) != 0 || b != 0x5A)     { ok = 0; why = "selfptr-target"; }
    }

    if (ok) {
        print("ELF_SELFTEST: PASS\n");
    } else {
        print("ELF_SELFTEST: FAIL "); print(why); print("\n");
    }

    /* Free the throwaway task slot so the scheduler never runs it. */
    tasks[pid].state = 0;
    set_current_task(saved);
}
#endif /* ELF_SELFTEST */

#ifdef PREEMPT_SELFTEST
/* ---- Preemptive-scheduling self-test (PREEMPT_SELFTEST builds only) --------
 * Spawn two independent copies of the embedded preempttest payload. Each one
 * busy-spins in ring 3 and periodically calls SYS_PREEMPT_TRACE *without ever
 * yielding*. The only way control can pass from one to the other is the timer
 * preempting it, so repeated alternation between the two task ids in the trace
 * proves preemption is live. h_preempt_trace prints the PASS marker once it has
 * seen enough back-and-forth. Without preemption only the first task would ever
 * run and the marker would never appear (smoke then fails on timeout). */

static volatile int pt_first_id     = -1;
static volatile int pt_second_id    = -1;
static volatile int pt_last_id      = -1;
static volatile int pt_transitions  = 0;
static volatile int pt_done         = 0;

void h_preempt_trace(struct regs *r) {
    int id = get_current_task();
    if (pt_first_id < 0) pt_first_id = id;
    else if (pt_second_id < 0 && id != pt_first_id) pt_second_id = id;

    if (pt_last_id >= 0 && id != pt_last_id) pt_transitions++;
    pt_last_id = id;

    if (!pt_done && pt_transitions >= 6 && pt_first_id >= 0 && pt_second_id >= 0) {
        pt_done = 1;
        print("PREEMPT_SELFTEST: PASS transitions=");
        print_decimal(pt_transitions);
        print(" tasks=");
        print_decimal(pt_first_id);
        print(",");
        print_decimal(pt_second_id);
        print("\n");
    }
    r->eax = 0;
}

/* Arm the embedded flat payload and spawn one instance; returns its pid. */
static int preempt_spawn_one(uint32_t entry, uint32_t size, const uint8_t *payload) {
    for (uint32_t i = 0; i < size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = entry;
    armed_hdr.size  = size;
    armed_hdr.name[0] = 'p'; armed_hdr.name[1] = 't'; armed_hdr.name[2] = 0;
    program_armed = 1;
    return do_spawn();
}

void preempt_selftest(void) {
    extern uint8_t embedded_preempttest_bin_start[];
    extern uint8_t embedded_preempttest_bin_end[];
    uint32_t full_sz = (uint32_t)(embedded_preempttest_bin_end - embedded_preempttest_bin_start);

    print("PREEMPT_SELFTEST: begin\n");
    if (full_sz < 44) { print("PREEMPT_SELFTEST: FAIL embed-size\n"); for (;;) asm volatile("hlt"); }

    const uint8_t *bin = embedded_preempttest_bin_start;
    uint32_t magic   = *(const uint32_t *)bin;
    uint32_t h_entry = *(const uint32_t *)(bin + 4);
    uint32_t h_size  = *(const uint32_t *)(bin + 8);
    if (magic != 0x55524F48)                     { print("PREEMPT_SELFTEST: FAIL magic\n"); for (;;) asm volatile("hlt"); }
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) { print("PREEMPT_SELFTEST: FAIL size\n");  for (;;) asm volatile("hlt"); }
    if (full_sz < 44 + h_size) h_size = full_sz - 44;
    const uint8_t *payload = bin + 44;

    int a = preempt_spawn_one(h_entry, h_size, payload);
    int b = preempt_spawn_one(h_entry, h_size, payload);
    if (a <= 0 || b <= 0) { print("PREEMPT_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }

    /* Launch task A into ring 3 via its fabricated trap frame; the timer then
     * time-slices A and B. Does not return. */
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* PREEMPT_SELFTEST */

#ifdef SMP_SELFTEST
/* ---- SMP self-test (SMP_SELFTEST builds only) -----------------------------
 * The application processors are already online (smp_bringup). Spawn a pool of
 * forever-looping worker tasks, open the cross-CPU scheduling gate, and confirm
 * the APs actually pull and run those workers: they must be observed running on
 * at least two distinct CPUs while the APs' LAPIC timer keeps ticking. The
 * workers reuse the preemption-test payload, so each also does an int-0x80
 * syscall from ring 3 on an AP -- exercising per-CPU TSS RSP0 delivery. Prints
 * "SMP_SELFTEST: PASS ..." for `make smoke-smp`. The BSP stays in ring 0 here
 * (its cpu-0 ring-0 context is never pulled into a task), so it monitors freely
 * while the APs do the work. */
static int smp_spawn_worker(uint32_t entry, uint32_t size, const uint8_t *payload) {
    for (uint32_t i = 0; i < size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = entry;
    armed_hdr.size  = size;
    armed_hdr.name[0] = 'w'; armed_hdr.name[1] = 'k'; armed_hdr.name[2] = 0;
    program_armed = 1;
    return do_spawn();
}

void smp_selftest(void) {
    extern uint8_t embedded_preempttest_bin_start[];
    extern uint8_t embedded_preempttest_bin_end[];
    extern volatile int smp_sched_enabled;
    extern volatile unsigned smp_cpus_ran_tasks;
    extern volatile unsigned long ap_timer_ticks;

    int online = smp_get_online_count();
    print("SMP_SELFTEST: begin online="); print_decimal(online); print("\n");
    if (online < 2) { print("SMP_SELFTEST: FAIL no-aps\n"); for (;;) asm volatile("hlt"); }

    uint32_t full_sz = (uint32_t)(embedded_preempttest_bin_end - embedded_preempttest_bin_start);
    if (full_sz < 44) { print("SMP_SELFTEST: FAIL embed-size\n"); for (;;) asm volatile("hlt"); }
    const uint8_t *bin = embedded_preempttest_bin_start;
    uint32_t magic   = *(const uint32_t *)bin;
    uint32_t h_entry = *(const uint32_t *)(bin + 4);
    uint32_t h_size  = *(const uint32_t *)(bin + 8);
    if (magic != 0x55524F48)                     { print("SMP_SELFTEST: FAIL magic\n"); for (;;) asm volatile("hlt"); }
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) { print("SMP_SELFTEST: FAIL size\n");  for (;;) asm volatile("hlt"); }
    if (full_sz < 44 + h_size) h_size = full_sz - 44;
    const uint8_t *payload = bin + 44;

    /* Spawn one worker per online CPU so an AP always has work to pull. Preserve
     * the kernel address space across do_spawn (which installs the new task's
     * CR3) so the BSP keeps monitoring on the kernel page tables. */
    uint64_t kcr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(kcr3));
    int spawned = 0;
    for (int i = 0; i < online; i++) {
        if (smp_spawn_worker(h_entry, h_size, payload) > 0) spawned++;
    }
    __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");
    if (spawned < 2) { print("SMP_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    print("SMP_SELFTEST: spawned="); print_decimal(spawned); print(" workers\n");

    /* Arm preemption and open the gate: the APs now pull workers on each tick. */
    sched_enable_preemption();
    smp_sched_enabled = 1;

    unsigned long t0 = ap_timer_ticks;
    for (int spins = 0; spins < 4000; spins++) {
        for (volatile int d = 0; d < 200000; d++) __asm__ volatile ("pause");
        unsigned mask = smp_cpus_ran_tasks;
        int distinct = 0;
        for (int c = 0; c < 32; c++) if (mask & (1u << c)) distinct++;
        if (distinct >= 2 && ap_timer_ticks > t0 + 10) {
            /* Multi-core scheduling proven. Now exercise the TLB-shootdown
             * round-trip: broadcast to the (busy, interrupts-enabled) APs and
             * confirm every one flushed and acknowledged. */
            extern volatile int smp_shootdown_pending;
            extern void smp_maybe_shootdown(uint64_t);
            smp_maybe_shootdown(0x1000);
            int shootdown_ok = (smp_shootdown_pending == 0);
            if (!shootdown_ok) {
                print("SMP_SELFTEST: FAIL shootdown pending=");
                print_decimal(smp_shootdown_pending); print("\n");
                for (;;) asm volatile("hlt");
            }
            print("SMP_SELFTEST: PASS online="); print_decimal(online);
            print(" cpus_ran=0x"); print_hex(mask);
            print(" distinct="); print_decimal(distinct);
            print(" ap_ticks="); print_decimal((uint32_t)ap_timer_ticks);
            print(" shootdown=ok");
            print("\n");
            for (;;) asm volatile("hlt");
        }
    }
    print("SMP_SELFTEST: FAIL timeout cpus_ran=0x"); print_hex(smp_cpus_ran_tasks);
    print(" ap_ticks="); print_decimal((uint32_t)ap_timer_ticks); print("\n");
    for (;;) asm volatile("hlt");
}
#endif /* SMP_SELFTEST */

#ifdef PROC_SELFTEST
/* Spawn a registered (spawn_table) program from the kernel, keeping the kernel
 * address space across do_spawn (which installs the new task's CR3 and makes it
 * current). Returns the new pid. */
static int proc_spawn_named(const char *name) {
    uint64_t kcr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(kcr3));
    set_current_task(0);                 /* so do_spawn's spawner-cap grant is skipped */
    int pid = (arm_named_binary(name) == 0) ? do_spawn() : -1;
    __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");
    return pid;
}

/* Spawn a HORU-headered embedded image with an explicit task name. */
static int proc_spawn_embed(const uint8_t *start, const uint8_t *end, const char *nm) {
    uint32_t full = (uint32_t)(end - start);
    if (full < 44) return -1;
    uint32_t magic   = *(const uint32_t *)start;
    uint32_t h_entry = *(const uint32_t *)(start + 4);
    uint32_t h_size  = *(const uint32_t *)(start + 8);
    if (magic != 0x55524F48 || h_size == 0 || h_size > MAX_PROGRAM_SIZE) return -1;
    if (full < 44 + h_size) h_size = full - 44;

    uint64_t kcr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(kcr3));
    set_current_task(0);
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = start[44 + i];
    armed_hdr.entry = h_entry;
    armed_hdr.size  = h_size;
    int k = 0;
    for (; nm[k] && k < 31; k++) armed_hdr.name[k] = nm[k];
    armed_hdr.name[k] = 0;
    program_armed = 1;
    int pid = do_spawn();
    __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");
    return pid;
}

/* ---- Process-control self-test (PROC_SELFTEST builds only) -----------------
 * The kernel spawns three tasks: a "hello" child that finishes with sys_exit, a
 * "looper" child (the preemption-test payload) that loops forever, and the
 * proctest driver. The driver is granted CAP_AUDIT (to read task state) and a
 * CAP_TCB capability to the looper (to terminate it), then dropped to ring 3. It
 * confirms the hello child exits and that it can SYS_KILL the looper via that
 * capability, printing PROC_SELFTEST: PASS. (The driver does not spawn anything
 * itself — ring-3 spawn is deferred to the init/exec stage.) Entry into
 * ring 3 does not return. */
void proc_selftest(void) {
    extern uint8_t embedded_proctest_bin_start[];
    extern uint8_t embedded_proctest_bin_end[];
    extern uint8_t embedded_preempttest_bin_start[];
    extern uint8_t embedded_preempttest_bin_end[];

    print("PROC_SELFTEST: begin\n");

    int hello_id = proc_spawn_named("hello");
    int loop_id  = proc_spawn_embed(embedded_preempttest_bin_start, embedded_preempttest_bin_end, "looper");
    int a        = proc_spawn_embed(embedded_proctest_bin_start,   embedded_proctest_bin_end,   "proc");
    if (hello_id <= 0 || loop_id <= 0 || a <= 0) { print("PROC_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }

    /* Grant the driver a real CAP_AUDIT (root slot 7) so SYS_GET_TASK_INFO can
     * read the children's state — but NOT admin, so the kill must go through a
     * genuine CAP_TCB capability — plus a CAP_TCB to the looper child (root slot
     * 0 is the primordial TCB cap), scoped to loop_id. Both get fresh serials so
     * cap_lookup accepts them. */
    extern int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
    cap_install_from_root(a, 7, 7, 0);            /* CAP_AUDIT: read task info   */
    cap_install_from_root(a, 16, 0, (uint32_t)loop_id);  /* CAP_TCB -> captest   */
    tasks[a].uid = 0;

    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* PROC_SELFTEST */

#ifdef SIGNAL_SELFTEST
/* ---- Signal-handling self-test (SIGNAL_SELFTEST builds only) ---------------
 * Spawn the sigtest payload: it registers a ring-3 fault handler and then does
 * a null-pointer write. Without signal handling that fault kills the task;
 * with it, the kernel redirects the task into its handler, which prints
 * "SIGNAL_SELFTEST: PASS". Entry into ring 3 does not return. */
void signal_selftest(void) {
    extern uint8_t embedded_sigtest_bin_start[];
    extern uint8_t embedded_sigtest_bin_end[];
    uint32_t full_sz = (uint32_t)(embedded_sigtest_bin_end - embedded_sigtest_bin_start);

    print("SIGNAL_SELFTEST: launch\n");
    if (full_sz < 44) { print("SIGNAL_SELFTEST: FAIL embed-size\n"); for (;;) asm volatile("hlt"); }

    const uint8_t *bin = embedded_sigtest_bin_start;
    uint32_t magic   = *(const uint32_t *)bin;
    uint32_t h_entry = *(const uint32_t *)(bin + 4);
    uint32_t h_size  = *(const uint32_t *)(bin + 8);
    if (magic != 0x55524F48)                     { print("SIGNAL_SELFTEST: FAIL magic\n"); for (;;) asm volatile("hlt"); }
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) { print("SIGNAL_SELFTEST: FAIL size\n");  for (;;) asm volatile("hlt"); }
    if (full_sz < 44 + h_size) h_size = full_sz - 44;

    const uint8_t *payload = bin + 44;
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = h_entry;
    armed_hdr.size  = h_size;
    armed_hdr.name[0] = 's'; armed_hdr.name[1] = 'i'; armed_hdr.name[2] = 'g'; armed_hdr.name[3] = 0;
    program_armed = 1;

    int a = do_spawn();
    if (a <= 0) { print("SIGNAL_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }

    /* Launch into ring 3 via the fabricated full trap frame. */
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* SIGNAL_SELFTEST */

#if defined(FS_SELFTEST) || defined(NEWLIB_SELFTEST)
/* ---- Selftest spawn helper (FS_SELFTEST / NEWLIB_SELFTEST builds only) -----
 * Stage an embedded, headered PIE binary and spawn it; returns the new pid. */

static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm) {
    uint32_t full = (uint32_t)(end - start);
    if (full < 44) return -1;
    uint32_t magic   = *(const uint32_t *)start;
    uint32_t h_entry = *(const uint32_t *)(start + 4);
    uint32_t h_size  = *(const uint32_t *)(start + 8);
    if (magic != 0x55524F48) return -1;
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) return -1;
    if (full < 44 + h_size) h_size = full - 44;

    const uint8_t *payload = start + 44;
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = h_entry;           /* recomputed by try_elf_load for the PIE ELF */
    armed_hdr.size  = h_size;
    int k = 0;
    while (k < 31 && nm[k]) { armed_hdr.name[k] = nm[k]; k++; }
    armed_hdr.name[k] = 0;
    program_armed = 1;
    return do_spawn();
}
#endif /* FS_SELFTEST || NEWLIB_SELFTEST */

#ifdef FS_SELFTEST
void fs_selftest(void) {
    extern uint8_t embedded_fsserver_bin_start[], embedded_fsserver_bin_end[];
    extern uint8_t embedded_fsclient_bin_start[], embedded_fsclient_bin_end[];

    print("FS_SELFTEST: begin\n");

    int srv = fs_spawn_embedded(embedded_fsserver_bin_start, embedded_fsserver_bin_end, "fsserver");
    if (srv <= 0) { print("FS_SELFTEST: FAIL spawn-server\n"); for (;;) asm volatile("hlt"); }
    tasks[srv].uid = 0;
    /* Provision the server: an endpoint cap for the IPC gate (slot 3) and for
     * registration (slot 4, bound to FS_EP_REQ), a CAP_USER admin cap (slot 6)
     * for SYS_REGISTER_FS_SERVER, and an all-rights cap (slot 7) to satisfy the
     * object-store gate. */
    cap_install_from_root(srv, 3, 2, 0);          /* root_cnode[2] = CAP_ENDPOINT   */
    cap_install_from_root(srv, 4, 2, FS_EP_REQ);
    cap_install_from_root(srv, 6, 6, 0);          /* root_cnode[6] = CAP_USER (ALL) */
    cap_install_from_root(srv, 7, 8, 0);          /* root_cnode[8] = ALL rights     */

#ifdef CONC_SELFTEST
    /* Multi-client concurrency test: spawn a coordinator (spawn arg 0) plus three
     * worker clients (args 1..3), each uid 0 with a delegated endpoint cap, all
     * hammering the single server at once. Each worker verifies it receives ITS
     * OWN replies (SYS_IPC_REPLY_TO routes by the request's kernel-recorded
     * sender); the coordinator waits for every worker's done-marker and prints
     * CONC_SELFTEST: PASS. */
    for (int i = 0; i <= 3; i++) {
        int c = fs_spawn_embedded(embedded_fsclient_bin_start, embedded_fsclient_bin_end, "fsclient");
        if (c <= 0) { print("CONC_SELFTEST: FAIL spawn-client\n"); for (;;) asm volatile("hlt"); }
        tasks[c].uid       = 0;
        tasks[c].spawn_arg = (uint32_t)i;       /* 0 = coordinator, 1..3 = workers */
        cap_install_from_root(c, 3, 2, 0);      /* endpoint cap for the IPC gate */
    }
#else
    int cli = fs_spawn_embedded(embedded_fsclient_bin_start, embedded_fsclient_bin_end, "fsclient");
    if (cli <= 0) { print("FS_SELFTEST: FAIL spawn-client\n"); for (;;) asm volatile("hlt"); }
    tasks[cli].uid = 0;
    /* Delegate an endpoint cap into the client's slot 3 so its IPC calls pass
     * the capability gate. (This is the spawner delegating authority — the
     * capability model in practice. sys_connect_fs_server can't target slot 3,
     * which slots 0-3 reserve; reconciling that with the slot-3 IPC gate is a
     * follow-up.) */
    cap_install_from_root(cli, 3, 2, 0);
#endif

    /* Launch the server; when it blocks in IPC the full-context path runs the
     * client(s). Does not return. */
    sched_enable_preemption();
    sched_enter_user(srv);
}
#endif /* FS_SELFTEST */

#ifdef WAL_CRASHTEST
/* Journal crash-recovery test — two boots against one persistent disk.
 *
 * Boot 1 (fresh disk): create an inode, then write its first block with the
 * commit "crash" armed — journal_commit makes the transaction durable (writes the
 * commit header) and then halts BEFORE applying it to the home locations. So on
 * disk the update is committed-in-journal but not-yet-applied.
 *
 * Boot 2 (same disk): storage_unlock's journal_recover replays that committed
 * transaction (idempotent redo); we read the block back and confirm the write
 * survived the crash. Proves redo recovery end-to-end. `make smoke-fs-wal` asserts
 * "WAL_CRASHTEST: PASS" on boot 2. */
void wal_crashtest(void) {
    extern int g_wal_crash_armed;
    extern int storage_fresh_format;
    static const char MARK[16] = "WAL-REDO-OK-2468";

    print("WAL_CRASHTEST: begin\n");
    if (storage_unlock("waltestpw", 9) != 0) {
        print("WAL_CRASHTEST: FAIL unlock\n"); for (;;) asm volatile ("hlt");
    }
    mounted_fs_t *mfs = storage_get_mounted_fs();

    if (storage_fresh_format) {
        int64_t ino = storage_alloc_inode(mfs->bd, &mfs->sb);
        if (ino < 1) { print("WAL_CRASHTEST: FAIL alloc\n"); for (;;) asm volatile ("hlt"); }
        on_disk_inode_t nd;
        for (size_t i = 0; i < sizeof(nd); i++) ((uint8_t *)&nd)[i] = 0;
        nd.type = 1; nd.mode = 0100600; nd.links = 1;
        storage_write_inode(mfs->bd, &mfs->sb, (uint64_t)ino, &nd);

        uint8_t buf[512];
        for (int i = 0; i < 512; i++) buf[i] = 0;
        for (int i = 0; i < 16; i++)  buf[i] = (uint8_t)MARK[i];

        print("WAL_CRASHTEST: boot1 armed; committing then crashing\n");
        g_wal_crash_armed = 1;
        storage_write_file_block(mfs, (uint64_t)ino, 0, buf);   /* commits, then halts */
        print("WAL_CRASHTEST: FAIL no-crash\n");                /* unreachable */
    } else {
        uint8_t buf[512];
        if (storage_read_file_block(mfs, 1, 0, buf) != 0) {
            print("WAL_CRASHTEST: FAIL read\n");
        } else {
            int ok = 1;
            for (int i = 0; i < 16; i++) if (buf[i] != (uint8_t)MARK[i]) ok = 0;
            print(ok ? "WAL_CRASHTEST: PASS\n" : "WAL_CRASHTEST: FAIL content\n");
        }
    }
    for (;;) asm volatile ("hlt");
}
#endif /* WAL_CRASHTEST */

/* ---- Large-file / double-indirect self-test (BIGFILE_SELFTEST builds only) --
 * Single boot against the ephemeral RAM store (storage_init already formatted +
 * mounted + unlocked it). Allocate one inode and write blocks spanning every
 * mapping region — direct (0, 11), single-indirect boundaries (12, 75), and the
 * point of this test, double-indirect (76 = first, then deep: 200, 1000, 3000) —
 * then read them back. Each block is stamped with its logical block number and a
 * number-derived body pattern, so a block that lands at the wrong physical
 * location reads as wrong content. Also confirms an unwritten hole reads as
 * absent (not another block's data) and that freeing the whole tree succeeds.
 * Prints BIGFILE_SELFTEST: PASS; `make smoke-fs-large` asserts on it. */
#ifdef BIGFILE_SELFTEST
void bigfile_selftest(void) {
    print("BIGFILE_SELFTEST: begin\n");

    mounted_fs_t *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || !mfs->unlocked) {
        print("BIGFILE_SELFTEST: FAIL not-ready\n"); for (;;) asm volatile ("hlt");
    }

    int64_t ino = storage_alloc_inode(mfs->bd, &mfs->sb);
    if (ino < 1) { print("BIGFILE_SELFTEST: FAIL alloc-inode\n"); for (;;) asm volatile ("hlt"); }
    {
        on_disk_inode_t nd;
        for (size_t i = 0; i < sizeof(nd); i++) ((uint8_t *)&nd)[i] = 0;
        nd.type = 1; nd.mode = 0100644; nd.links = 1;
        storage_write_inode(mfs->bd, &mfs->sb, (uint64_t)ino, &nd);
    }

    static const uint64_t blocks[] = { 0, 11, 12, 75, 76, 200, 1000, 3000 };
    const unsigned N = sizeof(blocks) / sizeof(blocks[0]);

    for (unsigned i = 0; i < N; i++) {
        uint64_t b = blocks[i];
        uint8_t buf[BLOCK_SIZE];
        for (int j = 0; j < BLOCK_SIZE; j++) buf[j] = (uint8_t)(b * 7u + (unsigned)j);
        for (int j = 0; j < 8; j++)          buf[j] = (uint8_t)(b >> (j * 8));   /* stamp */
        if (storage_write_file_block(mfs, (uint64_t)ino, b, buf) != 0) {
            print("BIGFILE_SELFTEST: FAIL write blk=0x"); print_hex(b); print("\n");
            for (;;) asm volatile ("hlt");
        }
    }

    /* Contiguous span deep in the double-indirect region (crosses several
     * single-indirect blocks). This makes the free below release ~130 data
     * blocks plus their pointer blocks in one journal transaction; every block
     * freed clears the same single block-bitmap sector, so the writes coalesce
     * and the transaction stays well under the 16-sector journal limit rather
     * than overflowing (a large-file free must never abort). */
    for (uint64_t b = 400; b < 530; b++) {
        uint8_t buf[BLOCK_SIZE];
        for (int j = 0; j < 8; j++) buf[j] = (uint8_t)(b >> (j * 8));   /* stamp */
        if (storage_write_file_block(mfs, (uint64_t)ino, b, buf) != 0) {
            print("BIGFILE_SELFTEST: FAIL span-write blk=0x"); print_hex(b); print("\n");
            for (;;) asm volatile ("hlt");
        }
    }

    for (unsigned i = 0; i < N; i++) {
        uint64_t b = blocks[i];
        uint8_t rb[BLOCK_SIZE];
        if (storage_read_file_block(mfs, (uint64_t)ino, b, rb) != 0) {
            print("BIGFILE_SELFTEST: FAIL read blk=0x"); print_hex(b); print("\n");
            for (;;) asm volatile ("hlt");
        }
        uint64_t stamp = 0;
        for (int j = 0; j < 8; j++) stamp |= ((uint64_t)rb[j]) << (j * 8);
        if (stamp != b) {
            print("BIGFILE_SELFTEST: FAIL stamp blk=0x"); print_hex(b); print("\n");
            for (;;) asm volatile ("hlt");
        }
        if (rb[100] != (uint8_t)(b * 7u + 100u)) {
            print("BIGFILE_SELFTEST: FAIL body blk=0x"); print_hex(b); print("\n");
            for (;;) asm volatile ("hlt");
        }
    }

    /* Spot-check the contiguous span read-back (stamp at a mid-span block). */
    {
        uint8_t rb[BLOCK_SIZE];
        if (storage_read_file_block(mfs, (uint64_t)ino, 465, rb) != 0) {
            print("BIGFILE_SELFTEST: FAIL span-read\n"); for (;;) asm volatile ("hlt");
        }
        uint64_t stamp = 0;
        for (int j = 0; j < 8; j++) stamp |= ((uint64_t)rb[j]) << (j * 8);
        if (stamp != 465) { print("BIGFILE_SELFTEST: FAIL span-stamp\n"); for (;;) asm volatile ("hlt"); }
    }

    /* A never-written hole in the double-indirect range must read as absent. */
    {
        uint8_t rb[BLOCK_SIZE];
        if (storage_read_file_block(mfs, (uint64_t)ino, 1500, rb) == 0) {
            print("BIGFILE_SELFTEST: FAIL hole-readable\n"); for (;;) asm volatile ("hlt");
        }
    }

    if (storage_free_inode_blocks(mfs, (uint64_t)ino) != 0) {
        print("BIGFILE_SELFTEST: FAIL free\n"); for (;;) asm volatile ("hlt");
    }

    print("BIGFILE_SELFTEST: PASS\n");
    for (;;) asm volatile ("hlt");
}
#endif /* BIGFILE_SELFTEST */

/* ---- Newlib smoke test (NEWLIB_SELFTEST builds only) ---------------------- */
#ifdef NEWLIB_SELFTEST
void newlib_selftest(void) {
    extern uint8_t embedded_hello_newlib_bin_start[], embedded_hello_newlib_bin_end[];
    extern uint8_t embedded_fsserver_bin_start[], embedded_fsserver_bin_end[];

    print("NEWLIB_SELFTEST: begin\n");

    /* Bring up the userspace fs_server so the client can exercise the real
     * newlib file paths (open/write/close/unlink). Provisioned exactly as in
     * fs_selftest: an endpoint cap for the IPC gate (slot 3) and registration
     * (slot 4, bound to FS_EP_REQ), a CAP_USER admin cap (slot 6), and an
     * all-rights cap (slot 7) for the object-store gate. */
    int srv = fs_spawn_embedded(embedded_fsserver_bin_start, embedded_fsserver_bin_end, "fsserver");
    if (srv <= 0) { print("NEWLIB_SELFTEST: FAIL spawn-server\n"); for (;;) asm volatile("hlt"); }
    tasks[srv].uid = 0;
    cap_install_from_root(srv, 3, 2, 0);
    cap_install_from_root(srv, 4, 2, FS_EP_REQ);
    cap_install_from_root(srv, 6, 6, 0);
    cap_install_from_root(srv, 7, 8, 0);

    int pid = fs_spawn_embedded(embedded_hello_newlib_bin_start,
                                embedded_hello_newlib_bin_end,
                                "hello_newlib");
    print("NEWLIB_SELFTEST: pid="); print_hex(pid); print("\n");
    if (pid <= 0) {
        print("NEWLIB_SELFTEST: FAIL spawn\n");
        for (;;) asm volatile("hlt");
    }
    tasks[pid].uid = 0;
    /* Delegate an endpoint cap into the client's slot 3 so its fs_server IPC
     * passes the capability gate (the RAM store is auto-unlocked at boot and the
     * client is kernel-attested uid 0, so no login is needed). */
    cap_install_from_root(pid, 3, 2, 0);

    /* Enter the server; when it blocks in IPC recv the full-context path runs
     * the client, whose FS requests wake the server. Does not return. */
    print("NEWLIB_SELFTEST: launching\n");
    sched_enable_preemption();
    sched_enter_user(srv);
}
#endif /* NEWLIB_SELFTEST */

