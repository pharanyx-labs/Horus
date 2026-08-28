#include "syscall.h"

/*
 * XMM register-file isolation self-test -- SECURITY.md S16, FPU_SELFTEST builds.
 *
 * S16 says "a task cannot read another's XMM register file", and until this test
 * existed its witness column in SECURITY.md was a literal em-dash: a security
 * claim with nothing binding it to the code. `fpu_save` / `fpu_restore`
 * (src/kernel/scheduler.c) were real, called from the ring-transition path in
 * idt.c, and exercised by nothing. That is the [C-1] failure mode -- a documented
 * property with no test -- which is what roadmap 4.12's invariant registry exists
 * to make impossible to repeat.
 *
 * TWO HALVES, and they are different claims:
 *
 *   CONFIDENTIALITY (S16 proper). `fpupeer` reads its OWN xmm registers at first
 *   entry and requires that none of them holds this task's sentinel. If the
 *   kernel did not restore the peer's register file on the way back to ring 3,
 *   the peer would simply find whatever the previously-running task left in the
 *   physical registers -- which is this task's data.
 *
 *   INTEGRITY. This task loads a sentinel, is switched away and back many times,
 *   and requires its registers to be unchanged. A kernel that leaks in the
 *   direction above generally destroys in this one too, but they are separable:
 *   dropping only the SAVE loses this task's state without exposing it to
 *   anyone, and dropping only the RESTORE exposes it without losing it. One
 *   control arm each.
 *
 * ---- WHY THE WHOLE SEQUENCE IS ONE ASM BLOCK ------------------------------
 *
 * Userspace here is compiled with SSE2 as the baseline (unlike the kernel, which
 * is -mno-sse), so the compiler is entitled to use xmm registers for its own
 * purposes at any point. Loading the sentinel in one asm statement, yielding in
 * C, and reading back in another would be a test of whatever GCC happened to
 * leave in those registers -- and it would pass or fail on optimisation
 * settings rather than on kernel behaviour. Putting the load, the yields and the
 * store in a single `asm volatile` removes the question: no compiler-generated
 * instruction can run between them.
 *
 * `int $0x80` is an interrupt gate and the trap frame saves and restores every
 * general-purpose register, so the loop counter survives the syscall; only rax
 * comes back changed, carrying the return value.
 *
 * ---- THE PEER IS RESUMED FROM INSIDE THAT BLOCK, AND THAT IS THE ORDERING ---
 *
 * The peer is spawned suspended and released HERE, after the sentinel is in the
 * registers and before the first yield. Nothing else orders the two: the peer
 * samples its registers a bounded number of times and then reports success, so
 * if it were runnable from the start it could spend its whole window while this
 * task was still in `fill_sentinel` -- finding nothing, and reporting no leak
 * having never once looked at a moment when there was one to see.
 *
 * That is not hypothetical. The first version of this test let `selftest_resume_all`
 * release both tasks together, and the leak arm reproduced on 2 boots in 3: the
 * miss was the peer's window closing before the sentinel existed. A gate that can
 * pass because it looked too early is worth nothing, and raising the sample count
 * would have hidden the race rather than removed it. `frametest` holds its peer
 * back for the same class of reason.
 */

#define XMM_REGS   16
#define XMM_BYTES  (XMM_REGS * 16)
#define YIELDS     64          /* switched away and back this many times */

static void report(const char *s) {
    int n = 0;
    while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* Distinctive per-register content: nothing the compiler or the FPU template
 * would produce by accident. Byte b of register r is (0xA5 ^ r) + b. */
static void fill_sentinel(unsigned char *p) {
    for (int r = 0; r < XMM_REGS; r++)
        for (int b = 0; b < 16; b++)
            p[r * 16 + b] = (unsigned char)(((0xA5u ^ (unsigned)r) + (unsigned)b) & 0xFF);
}

static int same(const unsigned char *a, const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

void _start(void) {
    static unsigned char want[XMM_BYTES] __attribute__((aligned(16)));
    static unsigned char got [XMM_BYTES] __attribute__((aligned(16)));

    fill_sentinel(want);

    /* The peer's task id, handed over at spawn (selftest.c sets spawn_arg). */
    long peer = (long)sys_spawn_arg();
    if (peer <= 0) { report("FPUTEST: FAIL no-peer-arg\n"); sys_exit(); }

    /* Load all sixteen, yield YIELDS times, read all sixteen back. The peer is
     * runnable throughout, so each yield is a real switch away and back. */
    __asm__ volatile (
        "movdqa   0(%0), %%xmm0\n\t"   "movdqa  16(%0), %%xmm1\n\t"
        "movdqa  32(%0), %%xmm2\n\t"   "movdqa  48(%0), %%xmm3\n\t"
        "movdqa  64(%0), %%xmm4\n\t"   "movdqa  80(%0), %%xmm5\n\t"
        "movdqa  96(%0), %%xmm6\n\t"   "movdqa 112(%0), %%xmm7\n\t"
        "movdqa 128(%0), %%xmm8\n\t"   "movdqa 144(%0), %%xmm9\n\t"
        "movdqa 160(%0), %%xmm10\n\t"  "movdqa 176(%0), %%xmm11\n\t"
        "movdqa 192(%0), %%xmm12\n\t"  "movdqa 208(%0), %%xmm13\n\t"
        "movdqa 224(%0), %%xmm14\n\t"  "movdqa 240(%0), %%xmm15\n\t"
        /* Release the peer NOW: sentinel loaded, not yet yielded. Its first
         * sample is therefore ordered after the load by construction. */
        "mov %4, %%rbx\n\t"
        "mov %5, %%eax\n\t"
        "int $0x80\n\t"
        "mov %2, %%rcx\n"
        "1:\n\t"
        "push %%rcx\n\t"
        "mov %3, %%eax\n\t"
        "int $0x80\n\t"
        "pop %%rcx\n\t"
        "dec %%rcx\n\t"
        "jnz 1b\n\t"
        "movdqa %%xmm0,   0(%1)\n\t"   "movdqa %%xmm1,  16(%1)\n\t"
        "movdqa %%xmm2,  32(%1)\n\t"   "movdqa %%xmm3,  48(%1)\n\t"
        "movdqa %%xmm4,  64(%1)\n\t"   "movdqa %%xmm5,  80(%1)\n\t"
        "movdqa %%xmm6,  96(%1)\n\t"   "movdqa %%xmm7, 112(%1)\n\t"
        "movdqa %%xmm8, 128(%1)\n\t"   "movdqa %%xmm9, 144(%1)\n\t"
        "movdqa %%xmm10,160(%1)\n\t"   "movdqa %%xmm11,176(%1)\n\t"
        "movdqa %%xmm12,192(%1)\n\t"   "movdqa %%xmm13,208(%1)\n\t"
        "movdqa %%xmm14,224(%1)\n\t"   "movdqa %%xmm15,240(%1)\n\t"
        :
        : "r"(want), "r"(got), "i"((long)YIELDS), "i"(SYS_YIELD),
          "r"(peer), "i"(SYS_TASK_RESUME)
        : "rax", "rbx", "rcx", "memory",
          "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
          "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15");

    if (!same(want, got, XMM_BYTES)) {
        report("FPUTEST: FAIL own-xmm-lost\n");
        sys_exit();
    }

    /* The peer prints its own verdict; this task's is only about itself. */
    report("FPUTEST: PASS own-xmm-preserved\n");
    sys_exit();
}
