/* sealprobe.c -- SYS_MEM_SEAL's witness: a sealed page takes no write, and the
 * call reaches nothing but the caller's own image.
 *
 *   sealprobe data   seals a page of its own .data it has already written, then
 *                    writes it again. The write must fault. A fault handler says
 *                    so and exits; a write that returns is the seal not holding.
 *   sealprobe heap   asks to seal a heap page it owns and has written. The heap
 *                    is outside the image window, so the call must be refused.
 *
 * Under MEM_SEAL_KEEPS_WRITE=1 the data write lands, and under
 * MEM_SEAL_ANY_ADDRESS=1 the heap page is sealed; each arm of make
 * smoke-mem-seal requires its own sentence below.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/syscall.h"

/* Initialised, so it is .data and present in the image from the load, and two
 * pages long so one whole page-aligned page lies inside it wherever it lands. */
static volatile char region[8192] = { 1 };

static void say(const char *s) {
    (void)write(1, s, strlen(s));
}

/* Entered at ring 3 on the fault, in place of the kill.
 *
 * force_align_arg_pointer, because the kernel enters a handler on the
 * interrupted stack with no call in front of it, so %rsp has no promised
 * alignment, and newlib's write path uses SSE moves that fault on a misaligned
 * stack -- a fault INSIDE the handler, which kills the task silently. The length
 * is a constant for the same reason: strlen is SSE too. */
static const char fault_msg[] = "SEALPROBE: the sealed page refused the write\n";

__attribute__((force_align_arg_pointer))
static void on_fault(void) {
    (void)write(1, fault_msg, sizeof(fault_msg) - 1);
    sys_exit();
}

static volatile char *page_in(volatile char *p) {
    uintptr_t a = ((uintptr_t)p + 4095u) & ~(uintptr_t)4095u;
    return (volatile char *)a;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "data";

    if (strcmp(mode, "heap") == 0) {
        char *h = malloc(3 * 4096);
        if (!h) { say("SEALPROBE: FAIL malloc\n"); return 1; }
        volatile char *pg = page_in((volatile char *)h);
        pg[0] = 7;                                   /* present and private */
        if (sys_mem_seal((const void *)pg, 4096) == 0) {
            say("SEALPROBE: FAIL a page outside the image was sealed\n");
            return 1;
        }
        say("SEALPROBE: a heap page, outside the image, was refused\n");
        return 0;
    }

    volatile char *pg = page_in(region);
    pg[0] = 2;                                       /* written before the seal */
    int rc = sys_mem_seal((const void *)pg, 4096);
    if (rc != 0) { printf("SEALPROBE: FAIL could not seal its own .data (rc=%d)\n", rc); return 1; }
    if (pg[0] != 2) { say("SEALPROBE: FAIL the page changed when sealed\n"); return 1; }
    say("SEALPROBE: sealed a page of its own .data\n");
    if (sys_signal((uintptr_t)&on_fault) != 0) { say("SEALPROBE: FAIL no fault handler\n"); return 1; }
    pg[0] = 3;
    say("SEALPROBE: FAIL the sealed page took a write\n");
    return 1;
}
