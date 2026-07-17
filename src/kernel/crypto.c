#include "kernel.h"

static uint32_t cpu_features_ecx = 0;
static uint32_t cpu_features_edx = 0;
static uint32_t cpu_features_ebx = 0;
static uint32_t ext_features_edx = 0;

platform_info_t platform;

/* ECX is an *input* to CPUID as well as an output: on subleaf-bearing leaves
 * (7, 0xD, 0x1F...) it selects the subleaf. Binding it here rather than letting
 * it carry over is not a tidy-up — leaf 7 reports max_subleaf = 0, and an
 * out-of-range subleaf reads back as all zeros, so a stale ECX silently turns
 * a feature query into "this CPU has nothing". Every leaf that ignores ECX is
 * unaffected by pinning it to 0. */
static void cpuid_count(uint32_t leaf, uint32_t subleaf,
                        uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    __asm__ volatile (
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(subleaf)
    );
}

static void cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    cpuid_count(leaf, 0, eax, ebx, ecx, edx);
}

void cpu_detect_features(void) {
    uint32_t eax, ebx, ecx, edx;

    cpuid(1, &eax, &ebx, &ecx, &edx);
    cpu_features_ecx = ecx;
    cpu_features_edx = edx;
    cpu_features_ebx = ebx;

    platform.family   = (eax >> 8) & 0xF;
    platform.model    = (eax >> 4) & 0xF;
    platform.stepping = eax & 0xF;

    cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
    ext_features_edx = edx;
    platform.has_long_mode = (edx & (1 << 29)) != 0;

    uint32_t v[4] = {0};
    cpuid(0, &v[0], &v[1], &v[2], &v[3]);
    char *p = platform.vendor;
    *(uint32_t*)p = v[1]; p += 4;
    *(uint32_t*)p = v[3]; p += 4;
    *(uint32_t*)p = v[2]; p += 4;
    *p = 0;

    /* Subleaf spelled out: leaf 7 is subleaf-bearing, and this call previously
     * inherited whatever ECX the cpuid(0) above returned — the tail of the
     * vendor string ("cAMD"/"ntel"). That is far past max_subleaf, so EBX read
     * back as 0 and both features looked absent on every boot. */
    cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
    platform.has_smap = (ebx & (1 << 20)) != 0;
    platform.has_smep = (ebx & (1 << 7))  != 0;
    platform.has_umip = (ecx & (1 << 2))  != 0;
}

/*
 * Enable the CR4 user/supervisor protections. MUST be called after
 * cpu_detect_features() (which fills platform.has_smep/has_smap/has_umip), and
 * is the only place that turns these on:
 *   SMEP (CR4.20) — ring 0 cannot execute ring-3 (user) pages, blocking a large
 *                   class of privilege-escalation exploits that redirect kernel
 *                   execution into attacker-controlled userspace code.
 *   SMAP (CR4.21) — ring 0 cannot read/write user pages except inside an
 *                   explicit stac/clac window (the kernel already brackets user
 *                   copies with clac/stac).
 *   UMIP (CR4.11) — ring 3 cannot execute SGDT/SIDT/SLDT/STR/SMSW. Those five
 *                   need no privilege but hand out the linear addresses of the
 *                   GDT, IDT, LDT and TSS, which is exactly the leak that turns
 *                   a corruption primitive into a targeted one. Ring 0 is
 *                   unaffected; nothing in ring 3 has any business asking.
 */
void cpu_enable_protections(void) {
    unsigned long cr4;
    __asm__ volatile ("mov %%cr4, %0" : "=r"(cr4));
    if (platform.has_umip) cr4 |= (1UL << 11);
    if (platform.has_smep) cr4 |= (1UL << 20);
    if (platform.has_smap) cr4 |= (1UL << 21);
    __asm__ volatile ("mov %0, %%cr4" :: "r"(cr4) : "memory");
}

int cpu_has_aesni(void) {
    return (cpu_features_ecx & (1 << 25)) != 0;
}

static inline void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t lo = (uint32_t)value;
    uint32_t hi = (uint32_t)(value >> 32);
    __asm__ volatile ("wrmsr" : : "c"(msr), "a"(lo), "d"(hi) : "memory");
}

void init_syscall_instruction_path(void) {

    
    uint64_t star = ((uint64_t)0x08 << 32) | ((uint64_t)0x10 << 48);
    wrmsr(0xC0000081, star);

    extern void syscall_entry(void);
    wrmsr(0xC0000082, (uint64_t)(uintptr_t)&syscall_entry);

    wrmsr(0xC0000084, 0x200ULL); 
}

void platform_detect(void) {
    for (int i = 0; i < (int)sizeof(platform); i++) ((uint8_t*)&platform)[i] = 0;

    cpu_detect_features();

    platform.has_aesni         = cpu_has_aesni();
    platform.has_tsc           = (cpu_features_edx & (1 << 4)) != 0;
    platform.has_sse           = (cpu_features_edx & (1 << 25)) != 0;
    platform.has_sse2          = (cpu_features_edx & (1 << 26)) != 0;
    platform.has_sse4_2        = (cpu_features_ecx & (1 << 20)) != 0;
    platform.has_rdrand        = (cpu_features_ecx & (1 << 30)) != 0;

    if (!platform.has_smap) {
        uint32_t eax2, ebx2, ecx2, edx2;
        cpuid(7, &eax2, &ebx2, &ecx2, &edx2);
        platform.has_smap = (ebx2 & (1 << 20)) != 0;
    }

    uint32_t v[4] = {0};
    cpuid(0, &v[0], &v[1], &v[2], &v[3]);
    char *p = platform.vendor;
    *(uint32_t*)p = v[1]; p += 4;
    *(uint32_t*)p = v[3]; p += 4;
    *(uint32_t*)p = v[2]; p += 4;
    *p = 0;

    uint32_t eax, ebx, ecx, edx;
    cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
    platform.has_long_mode = (edx & (1 << 29)) != 0;

    platform.has_invariant_tsc = 0;

    if (cpu_features_edx & (1 << 28)) {
        platform.num_logical_cpus = (cpu_features_ebx >> 16) & 0xFF;
    } else {
        platform.num_logical_cpus = 1;
    }
    platform.num_physical_cpus = platform.num_logical_cpus;

    platform.total_memory_bytes = 0;
}

void platform_print_summary(void) {
    set_text_colour(0x0F);
    print("  [ OK ] Platform: ");
    print(platform.vendor);
    print("  ");
    if (platform.has_long_mode) {
        print("64-bit capable");
    } else {
        print("32-bit only");
    }
    print("  CPUs:");
    print_decimal(platform.num_logical_cpus);
    if (platform.has_aesni) print("  AES-NI");
    if (platform.has_tsc) print("  TSC");
    if (platform.has_smap) print("  SMAP");
    println("");
}

/*
 * The kernel's bulk symmetric cipher used to live here as a hand-rolled
 * "AES-128" — but neither path was AES: the AES-NI path fed `aesenc` a bogus
 * key schedule (no SubWord/Rcon expansion), and the software fallback was an
 * unaudited ARX permutation. Both have been removed. Encryption-at-rest now
 * uses the ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD implemented in safe
 * Rust (rust/src/aead.rs, exposed as rust_aead_seal/rust_aead_open), composing
 * primitives that are validated against their RFC known-answer vectors. AES-NI
 * detection (cpu_has_aesni / platform.has_aesni) is retained for reporting.
 */

void secure_zero(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;

    __asm__ volatile ("" : : "r"(p) : "memory");

}

/* ------------------------------------------------------------------------- */
/* Entropy collection and the central CSPRNG bridge.                          */
/*                                                                            */
/* The CSPRNG itself (ChaCha20, fast-key-erasure) lives in safe Rust          */
/* (rust/src/rng.rs). This file is only responsible for gathering raw         */
/* entropy from the hardware and feeding it in. Sources, best-effort:         */
/*   * RDRAND  — true hardware RNG, used when CPUID advertises it;            */
/*   * TSC jitter — repeated rdtsc reads separated by tiny busy loops capture */
/*                  non-deterministic interrupt/microarchitectural timing;    */
/*   * boot counters and a stack address as weak additional whitening.        */
/* Note: raw TSC alone is predictable from ring 3, so it is NEVER used        */
/* directly as randomness — it only feeds the CSPRNG, whose output userspace  */
/* cannot reconstruct without the (secret, reseeded) pool state.              */
/* ------------------------------------------------------------------------- */

int cpu_has_rdrand(void) {
    return (cpu_features_ecx & (1 << 30)) != 0;
}

static void entropy_gather_and_seed(void) {
    uint8_t buf[96];
    size_t n = 0;

    /* 1) Hardware RNG, if present (8 draws => 64 bytes). */
    if (cpu_has_rdrand()) {
        for (int i = 0; i < 8 && n + 8 <= sizeof(buf); i++) {
            uint64_t v = 0;
            if (rust_rdrand_u64(&v)) {
                for (int b = 0; b < 8; b++) buf[n++] = (uint8_t)(v >> (b * 8));
            }
        }
    }

    /* 2) TSC jitter: sample rdtsc separated by short, variable busy loops so
     *    interrupt timing perturbs the low bits. */
    for (int i = 0; i < 4 && n + 8 <= sizeof(buf); i++) {
        uint64_t t = read_tsc();
        for (int b = 0; b < 8; b++) buf[n++] = (uint8_t)(t >> (b * 8));
        volatile uint32_t spin = (uint32_t)(t & 0x7F) + 17u;
        while (spin--) { __asm__ volatile ("pause" ::: "memory"); }
    }

    /* 3) Weak whitening: boot tick count and a live stack address. */
    if (n + 8 <= sizeof(buf)) {
        uint32_t ticks = get_system_ticks();
        uintptr_t sp = (uintptr_t)&buf;
        uint64_t mix = ((uint64_t)ticks << 32) ^ (uint64_t)sp;
        for (int b = 0; b < 8; b++) buf[n++] = (uint8_t)(mix >> (b * 8));
    }

    rust_rng_add_entropy(buf, n);
    secure_zero(buf, sizeof(buf));
}

void entropy_init(void) {
    entropy_gather_and_seed();
    /* Fail closed rather than ever hand out keys from the hardcoded startup
     * state. TSC jitter always contributes entropy, so this should be
     * unreachable; if the CSPRNG is somehow still unseeded, halt instead of
     * letting predictable "randomness" flow into pepper/salt/nonce derivation. */
    if (!rust_rng_is_seeded()) {
        print("PANIC: CSPRNG failed to seed; halting to avoid weak key material\n");
        for (;;) __asm__ volatile ("cli; hlt");
    }
}

/* ---- Stack protector ------------------------------------------------------
 *
 * GCC reads __stack_chk_guard on entry to a protected function, stores a copy
 * below the return address, and re-reads the global on exit to compare. That
 * read-back is the constraint that shapes everything here: the guard cannot be
 * changed while any protected frame is live, or that frame would compare a
 * fresh global against the stale copy it saved and kill itself on the way out.
 *
 * Note this only reaches the symbol at all because CFLAGS carries
 * -mstack-protector-guard=global. GCC's default on x86-64 reads the canary from
 * %gs:0x28, which in a kernel with no per-CPU GS base is a garbage address —
 * and defining this variable would have had no effect whatsoever, because
 * nothing would reference it. */
uintptr_t __stack_chk_guard = 0x9c2f5a1e7b40d3e6ULL;

/* GCC's callback when a canary check fails. By definition the calling frame's
 * return address is already corrupt, so returning is not an option. Fail closed
 * the same way entropy_init does — and "PANIC" is in the smoke harness's
 * FAULT_RE, so a smash anywhere turns CI red rather than scrolling past. */
void __attribute__((noreturn)) __stack_chk_fail(void) {
    print("PANIC: stack smashing detected; halting\n");
    for (;;) __asm__ volatile ("cli; hlt");
}

/* Swap the compile-time guard for a CSPRNG draw. The build is reproducible, so
 * the constant above is a published value: it catches accidents but not anyone
 * who has read the binary. A random guard catches both.
 *
 * Two constraints pin where this may be called from:
 *   - after entropy_init(), since the CSPRNG must be seeded; and
 *   - from a frame that never returns, per the read-back note above.
 * kernel_main is the one site satisfying both — it calls this immediately after
 * entropy_init() and never returns (smp_bringup enters ring 3, and the fallback
 * ends in kernel_idle). Every frame that ran before this point has already
 * returned against the old guard, and every frame after sees only the new one.
 *
 * This function must carry no canary itself, for exactly the reason it exists:
 * it would load the old guard on entry and check the new one on exit. */
__attribute__((no_stack_protector))
void stack_protector_init(void) {
    uintptr_t g = 0;
    secure_random_bytes(&g, sizeof(g));
    /* A zero guard is indistinguishable from an uninitialised one and would
     * quietly weaken every check, so keep the compile-time value instead. */
    if (g == 0) return;
    __stack_chk_guard = g;
}

void entropy_add_sample(uint64_t s) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(s >> (i * 8));
    rust_rng_add_entropy(b, sizeof(b));
}

void secure_random_bytes(void *out, size_t n) {
    if (!out || n == 0) return;
    rust_rng_fill((uint8_t *)out, n);
}
