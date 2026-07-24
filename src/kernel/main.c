


#include "kernel.h"

/* Absolute symbol from linker64.ld; its ADDRESS is the linker's KERNEL_VMA. */
extern char __kernel_vma_from_linker[];
extern tcb_t tasks[MAX_TASKS];
extern int current_task;
extern void set_tss_kernel_stack(uintptr_t);
extern uint8_t gdt64_start[];
extern uint8_t tss64[];

#ifdef DEBUG_SHELL
void __attribute__((noreturn)) shell_prompt_loop(void) {
    print("> ");
    while (1) {
        char cmd[128];
        int len = 0;

        while (len < 127) {
            char ch = console_getc();

            if (ch == '\r' || ch == '\n') {
                print("\n");
                break;
            }
            if (ch == '\b' || ch == 0x7F) {
                if (len > 0) { len--; print("\b \b"); }
                continue;
            }
            if (ch < 32 || ch > 126) continue;

            print_char(ch);
            cmd[len++] = ch;
        }
        cmd[len] = 0;

        if (cmd[0] != 0) {
            process_user_command(cmd);
        }
        print("> ");
    }
}
#endif

void __attribute__((noreturn)) resume_shell_after_fault(void) {
#ifdef DEBUG_SHELL
    set_current_task(0);  
    set_tss_kernel_stack(tasks[0].kernel_stack_top);
    shell_prompt_loop();
#else
    /* Task teardown (and waiter wake) already happened on the fault path.
     * Park this CPU; there is no cooperative schedule() path any more. */
    kernel_idle();
#endif
}

/* Prove the higher-half relocation actually took, before anything depends on it.
 *
 * Three ways it can be silently wrong, all of which produce a working-looking
 * kernel that corrupts memory later rather than failing here:
 *   - linker64.ld's KERNEL_VMA and kernel_vma.h's disagree (the linker script
 *     cannot include the header, so the two are duplicated);
 *   - the kernel is somehow still executing through the low identity map;
 *   - virt_to_phys does not invert phys_to_virt, so a VA->PA conversion feeding
 *     CR3 or a page-table entry is off.
 * Checked at the top of boot, on the serial console, in the smoke-test idiom. */
static void assert_higher_half(void) {
    uint64_t vma_c  = (uint64_t)KERNEL_VMA;
    uint64_t vma_ld = (uint64_t)(uintptr_t)&__kernel_vma_from_linker;
    uint64_t here   = (uint64_t)(uintptr_t)&assert_higher_half;

    if (vma_ld != vma_c) {
        print("HIGHHALF: FAIL linker KERNEL_VMA="); print_hex64(vma_ld);
        print(" != kernel_vma.h ");                 print_hex64(vma_c);
        print("\n");
        for (;;) asm volatile("cli; hlt");
    }
    if (here < vma_c) {
        print("HIGHHALF: FAIL executing below KERNEL_VMA at ");
        print_hex64(here); print("\n");
        for (;;) asm volatile("cli; hlt");
    }
    if (virt_to_phys(phys_to_virt(0x1234)) != 0x1234) {
        print("HIGHHALF: FAIL virt_to_phys/phys_to_virt do not round-trip\n");
        for (;;) asm volatile("cli; hlt");
    }
    kmsg_begin();
    print("boot: high-half OK, kernel at "); print_hex64(here);
    print(" phys ");                          print_hex64(virt_to_phys(here));
    print("\n");
}

/* ---- Multiboot2 memory map -> physical pool size --------------------------
 * GRUB passes the multiboot2 magic in eax and a pointer to the boot-information
 * structure in ebx; _start saves both (saved_mb_magic / saved_mb_info). Walk the
 * structure's tags for the memory-map tag (type 6), find the largest available
 * (type 1) region that covers USER_PHYS_BASE, and return how many PAGE_SIZE
 * frames the pool can take from [USER_PHYS_BASE, region_top), clamped to the
 * PHYS_KVA window. Returns 0 if the map cannot be trusted (not multiboot2, no
 * pointer, no usable region), so the caller keeps the conservative default
 * rather than assuming RAM that may not exist. The info block is low physical
 * RAM, read through PHYS_KVA — valid from boot, before paging_init runs. */
#define MB2_BOOT_MAGIC     0x36d76289u
#define MB2_TAG_END        0u
#define MB2_TAG_MODULE     3u
#define MB2_TAG_MMAP       6u
#define MB2_MEM_AVAILABLE  1u

struct mb2_tag        { uint32_t type; uint32_t size; };
struct mb2_mmap_entry { uint64_t base; uint64_t len; uint32_t type; uint32_t reserved; };

/* Boot-module table, filled by the same tag walk that sizes the pool. Kept in
 * .bss as 24 * ~48 bytes of descriptors — the module *payloads* stay where GRUB
 * put them and are never copied into the image. */
static struct boot_module g_boot_modules[MAX_BOOT_MODULES];
static uint32_t           g_boot_module_count = 0;
static uint64_t           g_boot_module_top   = 0;

uint32_t boot_module_count(void) { return g_boot_module_count; }
uint64_t boot_module_top(void)   { return g_boot_module_top; }

const struct boot_module *boot_module_get(uint32_t index) {
    if (index >= g_boot_module_count) return 0;
    return &g_boot_modules[index];
}

/* The SHA-256 manifest of the modules this kernel was built to ship. Generated
 * at build time from the same BOOT_MODULES list the ISO is assembled from; empty
 * (BOOT_MODULE_DIGEST_COUNT == 0) for a build that ships none. */
#include "boot_module_manifest.h"

static int module_name_eq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}

/*
 * Verify every recorded boot module against the embedded manifest (audit A4).
 *
 * A module is an attacker-reachable payload: GRUB drops it in RAM from the ISO,
 * and the fs_server writes it into the store as a ROOT-OWNED file — an
 * executable under /bin that the shell will run. Boot-chain provenance is not
 * integrity, so a module is exposed to userspace only if it matches this
 * kernel's own manifest exactly: same destination path, same size, same
 * SHA-256. Anything else — a payload swapped in the ISO, an extra module bolted
 * on, a module this kernel never attested to — is left unverified and refused by
 * SYS_BOOT_MODULE_INFO/READ.
 *
 * Fail-closed in every direction: an empty manifest (a kernel built without
 * modules) verifies nothing, so every module it is handed is refused. Payloads
 * are hashed here, once, before anything can read them; the syscalls then only
 * consult the flag.
 *
 * Returns the number of modules that failed verification.
 */
uint32_t boot_module_verify_all(void) {
    uint32_t failed = 0;

    for (uint32_t i = 0; i < g_boot_module_count; i++) {
        struct boot_module *m = &g_boot_modules[i];
        m->verified = 0;

        uint64_t span = m->end - m->start;
        if (span == 0 || span > 0xFFFFFFFFULL) { failed++; continue; }
        uint32_t size = (uint32_t)span;

        /* Via a local, not the macro directly: in a module-free build the macro is
         * the literal 0, and `d < 0u` trips -Wtype-limits ("always false"). */
        const uint32_t ndigests = BOOT_MODULE_DIGEST_COUNT;
        for (uint32_t d = 0; d < ndigests; d++) {
            const struct boot_module_digest *e = &BOOT_MODULE_DIGESTS[d];
            if (e->size != size) continue;
            if (!module_name_eq(m->name, e->path)) continue;

            /* Hash the payload where GRUB left it, through the PHYS_KVA window
             * (the same access the read syscall uses). */
            uint8_t got[32];
            if (rust_sha256((const uint8_t *)PHYS_KVA(m->start), (size_t)size, got) != 0) break;
            /* Constant-time compare for uniformity with the rest of the tree;
             * these are public hashes, so it is hygiene rather than necessity. */
            if (rust_ct_eq(got, e->sha256, sizeof(got))) { m->verified = 1; }
            break;      /* (path,size) identifies the entry; no second candidate */
        }

        if (!m->verified) {
            failed++;
            print("  [WARN] boot module refused (no manifest match): ");
            print(m->name);
            println("");
        }
    }

    if (failed == 0 && g_boot_module_count > 0) {
        print("  [ OK ] boot modules verified against the embedded manifest: ");
        print_decimal(g_boot_module_count);
        println("");
    }
    return failed;
}

/* Record one type-3 module tag. Rejects anything whose extent is not a sane
 * ascending range inside the PHYS_KVA window — a module the pager cannot reach
 * is worse than no module, and mod_start/mod_end come from outside the kernel. */
static void mb_record_module(const uint8_t *info, uint32_t off, uint32_t tag_size) {
    if (g_boot_module_count >= MAX_BOOT_MODULES) return;
    if (tag_size < 16) return;                       /* type+size+start+end */

    uint64_t start = *(const uint32_t *)(info + off + 8);
    uint64_t end   = *(const uint32_t *)(info + off + 12);
    if (end <= start) return;
    /* GRUB places modules wherever it likes — in practice just below the 16 MiB
     * pool base, not above it. Accept anything in low RAM above 1 MiB (the BIOS/
     * real-mode area) and within the PHYS_KVA window, so the pager can reach it.
     * A module inside the pool [USER_PHYS_BASE, …) is separately held back from the
     * free list (phys_in_boot_module); one below it needs no reservation. */
    if (start < 0x100000ULL) return;                 /* below usable RAM */
    if (end > PHYS_POOL_CEIL) return;                /* unreachable through PHYS_KVA */

    struct boot_module *m = &g_boot_modules[g_boot_module_count];
    m->start = start;
    m->end   = end;

    /* The tag's trailing string is the module2 cmdline — the utility name. It is
     * NUL-terminated inside the tag, but treat the tag extent as the real bound
     * and terminate ourselves rather than trusting the terminator is there. */
    const char *s = (const char *)(info + off + 16);
    uint32_t avail = tag_size - 16;
    uint32_t i = 0;
    while (i < avail && i < BOOT_MODULE_NAME_MAX - 1 && s[i]) { m->name[i] = s[i]; i++; }
    m->name[i] = 0;

    uint64_t top = (end + PAGE_SIZE - 1) & ~((uint64_t)PAGE_SIZE - 1);
    if (top > g_boot_module_top) g_boot_module_top = top;
    g_boot_module_count++;
}

/* One walk over the boot-information tags: sizes the physical pool from the
 * memory map (return value, in frames) and fills the boot-module table as a side
 * effect. Returns 0 if the map cannot be trusted, so the caller keeps the
 * conservative default rather than assuming RAM. */
static uint32_t mb_scan_boot_info(void) {
    if (saved_mb_magic != MB2_BOOT_MAGIC || saved_mb_info == 0) return 0;

    const uint8_t *info = (const uint8_t *)PHYS_KVA((uint64_t)saved_mb_info);
    uint32_t total = *(const uint32_t *)info;
    if (total < 8 || total > (1u << 20)) return 0;   /* sanity: <= 1 MiB of tags */

    uint64_t region_top = 0;
    uint32_t off = 8;   /* skip total_size + reserved */
    while ((uint64_t)off + sizeof(struct mb2_tag) <= total) {
        const struct mb2_tag *tag = (const struct mb2_tag *)(info + off);
        if (tag->type == MB2_TAG_END) break;
        if (tag->size < sizeof(struct mb2_tag) || (uint64_t)off + tag->size > total) break;

        if (tag->type == MB2_TAG_MODULE) {
            mb_record_module(info, off, tag->size);
        } else if (tag->type == MB2_TAG_MMAP) {
            uint32_t entry_size = *(const uint32_t *)(info + off + 8);
            if (entry_size >= sizeof(struct mb2_mmap_entry)) {
                for (uint32_t e = off + 16; (uint64_t)e + entry_size <= (uint64_t)off + tag->size;
                     e += entry_size) {
                    const struct mb2_mmap_entry *m = (const struct mb2_mmap_entry *)(info + e);
                    if (m->type != MB2_MEM_AVAILABLE) continue;
                    uint64_t end = m->base + m->len;
                    /* The region spanning USER_PHYS_BASE (16 MiB) is where the pool lives. */
                    if (m->base <= (uint64_t)USER_PHYS_BASE && end > (uint64_t)USER_PHYS_BASE
                        && end > region_top)
                        region_top = end;
                }
            }
        }
        off += (tag->size + 7u) & ~7u;   /* tags are 8-byte aligned */
    }

    if (region_top <= (uint64_t)USER_PHYS_BASE) return 0;
    if (region_top > PHYS_POOL_CEIL) region_top = PHYS_POOL_CEIL;   /* PHYS_KVA window */
    return (uint32_t)((region_top - (uint64_t)USER_PHYS_BASE) / PAGE_SIZE);
}

void kernel_main(uint32_t mb_info) {
    (void)mb_info;   /* the pointer is taken from saved_mb_info (see _start) */

    asm volatile(
        "xor %%rax,%%rax\n mov %%rax,%%dr0\n mov %%rax,%%dr1\n mov %%rax,%%dr2\n"
        "mov %%rax,%%dr3\n mov %%rax,%%dr6\n mov %%rax,%%dr7\n"
        "pushfq\n andq $~0x100,(%%rsp)\n popfq\n" ::: "rax","memory");

    terminal_init();
    kmsg("Horus secure microkernel (x86_64) booting");
    assert_higher_half();

    idt_init64();
    pic_init();

    /* One walk of the multiboot2 tags before paging_init builds its free list:
     * size the physical page pool from the E820 memory map AND record any boot
     * modules GRUB loaded. On a boot we cannot parse, keep the conservative
     * 64 MiB default (unchanged behaviour) rather than assume RAM. */
    uint32_t e820_pages = mb_scan_boot_info();
    if (e820_pages) phys_set_pool_pages(e820_pages);
    {
        uint32_t used = e820_pages ? e820_pages : USER_PHYS_DEFAULT_PAGES;
        kmsg_begin();
        print("mem: physical pool ");
        print_decimal(used / 256);        /* frames * 4 KiB / 1 MiB */
        print(" MiB (");
        print_decimal(used);
        print(e820_pages ? " frames, from E820)\n" : " frames, default: no E820)\n");
    }
    if (g_boot_module_count) {
        kmsg_begin();
        print("boot: modules ");
        print_decimal(g_boot_module_count);
        for (uint32_t i = 0; i < g_boot_module_count; i++) {
            print(" ");
            print(g_boot_modules[i].name);
            print("@");
            print_hex64(g_boot_modules[i].start);
        }
        print("\n");
    }
    /* Integrity-check the modules before anything can read one. Runs here, right
     * after the tag walk that recorded them and well before init/fs_server exist,
     * so no unverified payload is ever reachable over SYS_BOOT_MODULE_READ. */
    boot_module_verify_all();

    paging_init();

    /* Measured boot (roadmap 2.2): record the reproducible boot hash chain — a
     * kernel-identity token and the just-verified boot-module manifest — into the
     * TPM's PCRs, so the boot state can be attested at runtime. Placed right after
     * paging_init: the TPM MMIO mapping needs the physical allocator and the low
     * identity map that paging_init installs. Best-effort — a no-op without a TPM,
     * still long before any userspace (or the store unlock that stages 2-3 gate on
     * these measurements) exists. */
    tpm_measured_boot();
#ifdef PIPE_SELFTEST
    /* Fast in-kernel exercise of the pipe object (roadmap userspace: pipelines).
     * Boot continues; make smoke-pipe asserts on the PIPE_SELFTEST marker. */
    pipe_selftest();
#endif
#ifdef TPM_SELFTEST
    /* Seal a known value under a PolicyPCR(PCR8,PCR9) and unseal it under the live
     * PCRs, proving the TPM seal/unseal path (roadmap 2.2 stage 2). Boot continues;
     * make smoke-tpm-seal-roundtrip asserts on the marker. */
    tpm_seal_selftest();
#endif
#ifdef E820_SELFTEST
    /* Boot continues; make smoke-e820 asserts on the marker. Proves the pool
     * grew past the pre-E820 default from the parsed memory map. */
    e820_selftest();
#endif
    fpu_init_template();   /* the x87/SSE image every new task starts from */
    tss_io_bitmap_init();  /* prefill the console I/O-port allowlist (stays inactive
                            * until a task with a port grant is switched in) */
    cap_init();
    cpu_detect_features();
    cpu_enable_protections();
#ifdef CPU_SELFTEST
    cpu_protections_selftest();   /* boot continues; make smoke-cpu asserts on it */
#endif
#ifdef WX_SELFTEST
    /* After paging_init (which installs the W^X tables) and after
     * cpu_enable_protections, so CR0.WP is set and the bits it inspects are the
     * ones actually in force. Boot continues; make smoke-wx asserts on it. */
    wx_selftest();
#endif   /* SMEP/SMAP — must follow feature detection */
    entropy_init();
    /* Must follow entropy_init (needs the CSPRNG) and must run from a frame
     * that never returns — kernel_main is both. See stack_protector_init. */
    stack_protector_init();
#ifdef STACKGUARD_SELFTEST
    /* Immediately after the re-seed, so it reads the live guard. Boot continues;
     * make smoke-stackguard asserts on it. */
    stackguard_selftest();
#endif
    init_syscall_instruction_path();
#ifdef TPM_KEK_SELFTEST
    /* Prove the TPM-sealed KEK (roadmap 2.2 stage 3) before storage_init sets up
     * the real vdisk. Boot continues; make smoke-tpm-seal asserts on the marker. */
    storage_tpm_kek_selftest();
#endif
#ifndef MINIMAL_SECURE
    ramfs_init();   /* -> storage_init(): probes for an ATA disk (persistent) and
                     * falls back to the ephemeral RAM vdisk when none is present */
#endif
    scheduler_init();
#ifdef ASPACE_SELFTEST
    /* After scheduler_init: it zeroes tasks[], which would wipe the cr3 the test
     * installs. Boot continues; make smoke-aspace asserts on the marker. */
    aspace_selftest();
#endif
    smp_bringup();
    __asm__ volatile ("sti" ::: "memory");
    aslr_init_seed();
    set_current_task(0);
    /* Note: the 64-bit boot reaches userspace via smp_bringup() above, which
     * spawns the shell and never returns; the ELF_SELFTEST hook lives there.
     * This branch is the fallback path. */
#ifdef DEBUG_SHELL
    shell_prompt_loop();
#else
    /* Normal boot never reaches here: smp_bringup() already dropped into
     * ring 3 via sched_enter_user. This is only the fallback if that path
     * returned (e.g. embed missing). Idle — do not cooperative-schedule. */
    spawn_initial_userspace_init();
    kernel_idle();
#endif
}
