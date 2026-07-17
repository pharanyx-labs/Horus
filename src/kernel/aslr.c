/* aslr.c -- kernel ASLR PRNG (xorshift128+ seeded from the CSPRNG).
 *
 * Split out of scheduler.c: the layout-randomisation entropy source used by the
 * loader/spawn paths to pick image and stack offsets. Self-contained; state is
 * file-local and reseeded via aslr_init_seed()/aslr_mix_entropy().
 */
#include "kernel.h"

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
    /* The final xorshift folds the high bits down, so the low half is as mixed
     * as the high. This used to `return combined >> 32`, discarding half the
     * output and capping every offset derived from it below 4 GiB — invisible
     * while the whole user window was 8 MiB. */
    combined ^= combined >> 31;

    return (addr_t)combined;
}

/* A page-aligned random offset in [0, max_pages) pages.
 *
 * Rejection-sampled rather than `rand() % max_pages`. Modulo folds 2^64 onto
 * max_pages, and unless max_pages divides 2^64 the low residues get one extra
 * value each — so the bottom of the window is fractionally likelier than the
 * top. At the old 480 the skew was ~2^-55 and irrelevant; the point is that it
 * scales with max_pages, and the window this now feeds is millions of pages
 * wide. Discarding the unfair tail costs one extra draw with probability
 * (2^64 mod max_pages)/2^64 — unmeasurable, and it makes the distribution exact
 * rather than nearly-exact-at-this-size. */
addr_t aslr_random_offset(uint64_t max_pages) {
    if (max_pages == 0) return 0;
    /* Largest multiple of max_pages that fits in 2^64; draws at or above it are
     * the short tail that would bias the fold. */
    uint64_t limit = UINT64_MAX - (UINT64_MAX % max_pages);
    uint64_t r;
    do {
        r = aslr_rand();
    } while (r >= limit);
    return (addr_t)((r % max_pages) * PAGE_SIZE);
}

void aslr_mix_entropy(uint64_t val) {
    uint64_t t = read_tsc();
    aslr_rng_state[0] ^= val * 0x9E3779B97F4A7C15ULL;
    aslr_rng_state[1] ^= (val >> 32) * 0xC2B2AE3D27D4EB4FULL ^ t;
    (void)aslr_rand();
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
