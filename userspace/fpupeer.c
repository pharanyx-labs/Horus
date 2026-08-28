#include "syscall.h"

/*
 * The confidentiality half of SECURITY.md S16 -- "a task cannot read another's
 * XMM register file". FPU_SELFTEST builds only; see userspace/fputest.c for the
 * other half and for why that one is a single asm block.
 *
 * This task reads its OWN xmm registers and requires that none of them holds
 * `fputest`'s sentinel. It has never written them, so what it finds is whatever
 * the kernel put there on the way back to ring 3: its own restored register file
 * if `fpu_restore` ran, and the physical leftovers of the previously-running
 * task if it did not.
 *
 * ---- WHY THIS CHECK NEEDS NO CARE ABOUT THE COMPILER ----------------------
 *
 * `fputest` has to fight the compiler for its registers, because it is asserting
 * that a value it put there is still there and GCC may use xmm freely under the
 * SSE2 baseline. This side has the opposite shape: it asserts the ABSENCE of a
 * specific 256-byte pattern. Compiler-generated SSE cannot manufacture
 * `fputest`'s sentinel, so any instruction that runs before the read can only
 * make this check MISS a leak, never invent one -- and the control arm is what
 * establishes it does not miss.
 *
 * The registers are read repeatedly rather than once. A leak requires this task
 * to be scheduled at a moment when `fputest`'s values are the ones physically in
 * the register file, and one sample at entry might land before `fputest` has
 * loaded them at all. `fputest` yields 64 times with the sentinel loaded, so
 * sampling across a comparable span makes the interleaving the scheduler's
 * problem rather than a race this test has to win. Under the control arm it is
 * seen on the first sample in practice; the loop is what makes "not seen" mean
 * something.
 */

#define XMM_REGS   16
#define XMM_BYTES  (XMM_REGS * 16)
#define SAMPLES    96

static void report(const char *s) {
    int n = 0;
    while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* Must match fputest.c exactly. */
static void fill_sentinel(unsigned char *p) {
    for (int r = 0; r < XMM_REGS; r++)
        for (int b = 0; b < 16; b++)
            p[r * 16 + b] = (unsigned char)(((0xA5u ^ (unsigned)r) + (unsigned)b) & 0xFF);
}

static void xmm_store(unsigned char *p) {
    __asm__ volatile (
        "movdqa %%xmm0,   0(%0)\n\t"   "movdqa %%xmm1,  16(%0)\n\t"
        "movdqa %%xmm2,  32(%0)\n\t"   "movdqa %%xmm3,  48(%0)\n\t"
        "movdqa %%xmm4,  64(%0)\n\t"   "movdqa %%xmm5,  80(%0)\n\t"
        "movdqa %%xmm6,  96(%0)\n\t"   "movdqa %%xmm7, 112(%0)\n\t"
        "movdqa %%xmm8, 128(%0)\n\t"   "movdqa %%xmm9, 144(%0)\n\t"
        "movdqa %%xmm10,160(%0)\n\t"   "movdqa %%xmm11,176(%0)\n\t"
        "movdqa %%xmm12,192(%0)\n\t"   "movdqa %%xmm13,208(%0)\n\t"
        "movdqa %%xmm14,224(%0)\n\t"   "movdqa %%xmm15,240(%0)\n\t"
        :: "r"(p) : "memory");
}

void _start(void) {
    static unsigned char sentinel[XMM_BYTES] __attribute__((aligned(16)));
    static unsigned char seen    [XMM_BYTES] __attribute__((aligned(16)));

    fill_sentinel(sentinel);

    for (int s = 0; s < SAMPLES; s++) {
        xmm_store(seen);
        /* Any single register carrying the peer's 16 bytes is a leak. Checked
         * per register rather than over the whole file: a switch that restored
         * some registers and not others would still be a disclosure, and
         * requiring all 256 bytes to match would call that a pass. */
        for (int r = 0; r < XMM_REGS; r++) {
            int hit = 1;
            for (int b = 0; b < 16; b++)
                if (seen[r * 16 + b] != sentinel[r * 16 + b]) { hit = 0; break; }
            if (hit) {
                report("FPUTEST: FAIL peer-saw-sentinel\n");
                sys_exit();
            }
        }
        sys_yield();
    }

    report("FPUTEST: PASS no-xmm-leak\n");
    sys_exit();
}
