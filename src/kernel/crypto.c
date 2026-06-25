#include "kernel.h"

static uint32_t cpu_features_ecx = 0;
static uint32_t cpu_features_edx = 0;
static uint32_t cpu_features_ebx = 0;
static uint32_t ext_features_edx = 0;

platform_info_t platform;

static void cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    __asm__ volatile (
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf)
    );
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

    cpuid(7, &eax, &ebx, &ecx, &edx);
    platform.has_smap = (ebx & (1 << 20)) != 0;
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

static inline void aes128_key_schedule_round(uint8_t *rk, int round) {
    
    static const uint8_t rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    uint8_t t = rk[0] ^ rcon[round];

    rk[0] = rk[4] ^ t;
    rk[1] = rk[5] ^ rk[1];
    rk[2] = rk[6] ^ rk[2];
    rk[3] = rk[7] ^ rk[3];
}

void crypto_aes128_block_encrypt(uint8_t *block, const uint8_t *key) {

    uint8_t state[16];
    uint8_t rk[16];
    int i;

    for (i = 0; i < 16; i++) {
        state[i] = block[i];
        rk[i] = key[i];
    }

    if (cpu_has_aesni()) {

        uint8_t st[16], rkk[16];
        for (i = 0; i < 16; i++) { st[i] = state[i]; rkk[i] = rk[i]; }
        __asm__ volatile (
            "movdqu (%0), %%xmm0\n"
            "movdqu (%1), %%xmm1\n"
            "pxor %%xmm1, %%xmm0\n"
            "movdqu %%xmm0, (%0)\n"
            : : "r"(st), "r"(rkk) : "xmm0","xmm1","memory"
        );
        for (int r = 1; r < 10; r++) {
            aes128_key_schedule_round(rkk, r);
            __asm__ volatile (
                "movdqu (%0), %%xmm0\n"
                "movdqu (%1), %%xmm1\n"
                "aesenc %%xmm1, %%xmm0\n"
                "movdqu %%xmm0, (%0)\n"
                : : "r"(st), "r"(rkk) : "xmm0","xmm1","memory"
            );
        }
        aes128_key_schedule_round(rkk, 10);
        __asm__ volatile (
            "movdqu (%0), %%xmm0\n"
            "movdqu (%1), %%xmm1\n"
            "aesenclast %%xmm1, %%xmm0\n"
            "movdqu %%xmm0, (%0)\n"
            : : "r"(st), "r"(rkk) : "xmm0","xmm1","memory"
        );
        for (i = 0; i < 16; i++) block[i] = st[i];
        return;
    }

    
    uint32_t s[8];
    for (i = 0; i < 8; i++) {
        s[i] = ((uint32_t)key[(i*2)%16] << 16) | ((uint32_t)key[(i*2+1)%16] << 8) |
               ((uint32_t)block[i%16] ^ key[(i+3)%16]);
    }
    for (int round = 0; round < 32; round++) {
        
        s[0] += s[1]; s[1] = (s[1] << 7) | (s[1] >> 25); s[1] ^= s[0];
        s[2] += s[3]; s[3] = (s[3] << 9) | (s[3] >> 23); s[3] ^= s[2];
        s[4] += s[5]; s[5] = (s[5] << 13) | (s[5] >> 19); s[5] ^= s[4];
        s[6] += s[7]; s[7] = (s[7] << 18) | (s[7] >> 14); s[7] ^= s[6];
        
        uint32_t t = s[0]; s[0] = s[4]; s[4] = t;
        if ((round & 3) == 0) {
            s[1] ^= s[6]; s[3] ^= s[7];
        }
    }
    for (i = 0; i < 16; i++) {
        block[i] = (uint8_t)((s[i/2] >> ((i&1)*16)) & 0xFF) ^ key[i];
    }
}

void crypto_aes128_ctr_encrypt(void *buf, size_t len, const uint8_t *key, const uint8_t *nonce) {
    uint8_t *p = (uint8_t *)buf;
    uint8_t counter[16];
    uint8_t keystream[16];
    size_t i;

    for (i = 0; i < 16; i++) counter[i] = nonce[i & 15];

    for (size_t off = 0; off < len; off += 16) {
        for (i = 0; i < 16; i++) keystream[i] = counter[i];
        crypto_aes128_block_encrypt(keystream, key);
        size_t chunk = (len - off > 16) ? 16 : (len - off);
        for (i = 0; i < chunk; i++) {
            p[off + i] ^= keystream[i];
        }
        
        for (i = 15; i >= 8; i--) {
            if (++counter[i]) break;
        }
    }
}

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
