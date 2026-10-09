/* swaphog -- a test program for swap (smoke-swap, docs/design/swap.md steps 2
 * and 2a).
 *
 * Writes SWAPHOG_MIB of heap, every page carrying a marker and a pattern only
 * that page has, then reads all of it back and checks every byte. Run on a
 * machine whose pool is smaller than that, the only way for it to pass is for
 * its pages to go out to swap and come back exactly as they were. The marker is
 * what the host searches the swap partition for afterwards: sealed, it cannot
 * appear there.
 *
 * `swaphog hold | swaphog after` is step 2a's witness, an idle task giving its
 * memory to a busy one. `hold` writes HOLD_MIB of its own pattern, says "ready"
 * down the pipe, and then sits idle, writing to the pipe until its reader is
 * gone; `after` waits for "ready" and then runs as above. The holder then checks
 * every byte it wrote, so a page the busy task's faults took from it must have
 * come back exactly.
 *
 * Linked against the shared libc like any program in /bin. Never shipped: it is
 * a boot module only under SWAP_HOG=1. */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define SWAPHOG_MIB   48u
#define HOLD_MIB      16u
#define PAGE          4096u
#define PAGES         (SWAPHOG_MIB * 256u)
#define HOLD_PAGES    (HOLD_MIB * 256u)

static const char MARK[] = "HORUS-SWAPHOG-MARKER-";

static void put_dec(char *out, unsigned v) {
    char d[12]; int n = 0;
    do { d[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    int k = 0;
    while (n) out[k++] = d[--n];
    out[k] = 0;
}

/* `salt` keeps the holder's pattern apart from the busy task's, so neither can
 * pass by reading the other's pages. */
static unsigned char expect_s(unsigned page, unsigned off, unsigned salt) {
    if (off < sizeof(MARK) - 1) return (unsigned char)MARK[off];
    return (unsigned char)((page * 131u + off * 7u + salt) & 0xFFu);
}
static unsigned char expect(unsigned page, unsigned off) { return expect_s(page, off, 0); }

static int g_fd = 1;

/* This task's id, straight from the kernel (SYS_GETPID, 20): the shared libc
 * exports no getpid, and a test program is not a reason to add one. */
static unsigned my_tid(void) {
    unsigned long r;
    __asm__ volatile ("int $0x80" : "=a"(r) : "a"(20UL), "b"(0UL), "c"(0UL), "d"(0UL) : "memory");
    return (unsigned)r;
}

static void out(const char *t) {
    (void)write(g_fd, t, strlen(t));
}

static void say(const char *a, unsigned v, const char *b) {
    char num[12];
    put_dec(num, v);
    out(a);
    out(num);
    out(b);
}

/* The idle half of step 2a's witness. Reports on stderr, since stdout is the
 * pipe to the busy half. */
static int hold(void) {
    g_fd = 2;
    /* Only as the first stage of a pipeline: on a terminal the writes below
     * would never fail, and the holder would never stop. */
    if (isatty(1)) { out("SWAPHOG: FAIL the holder's stdout is not a pipe\n"); return 1; }
    /* Which task this is, so the session can find the kernel saying that this
     * task, and not some other idle one, gave its pages back. */
    say("SWAPHOG: holder is task ", my_tid(), "\n");
    unsigned char *heap = malloc((size_t)HOLD_PAGES * PAGE);
    if (!heap) { out("SWAPHOG: FAIL the holder's heap would not grow\n"); return 1; }
    for (unsigned p = 0; p < HOLD_PAGES; p++)
        for (unsigned o = 0; o < PAGE; o++)
            heap[(unsigned long)p * PAGE + o] = expect_s(p, o, 77u);
    if (write(1, "ready\n", 6) != 6) { out("SWAPHOG: FAIL the holder could not signal\n"); return 1; }
    /* Idle until the busy task has finished: a write to the pipe waits while it
     * is full and fails once its reader has exited. */
    while (write(1, "x", 1) == 1) { }
    for (unsigned p = 0; p < HOLD_PAGES; p++) {
        for (unsigned o = 0; o < PAGE; o++) {
            if (heap[(unsigned long)p * PAGE + o] != expect_s(p, o, 77u)) {
                say("SWAPHOG: FAIL the holder's page ", p, " did not read back as written\n");
                return 1;
            }
        }
    }
    say("SWAPHOG: OK the idle holder's ", HOLD_MIB, " MiB came back intact\n");
    return 0;
}

/* Wait for the holder's "ready" on stdin before starting. */
static int await_ready(void) {
    char c;
    unsigned seen = 0;
    static const char want[] = "ready\n";
    while (seen < sizeof(want) - 1) {
        if (read(0, &c, 1) != 1) return -1;
        seen = (c == want[seen]) ? seen + 1 : (c == want[0] ? 1u : 0u);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "hold") == 0) return hold();
    if (argc > 1 && strcmp(argv[1], "after") == 0 && await_ready() != 0) {
        out("SWAPHOG: FAIL the holder never said ready\n");
        return 1;
    }
    unsigned char *heap = malloc((size_t)PAGES * PAGE);
    if (!heap) {
        out("SWAPHOG: FAIL the heap would not grow\n");
        return 1;
    }
    for (unsigned p = 0; p < PAGES; p++)
        for (unsigned o = 0; o < PAGE; o++)
            heap[(unsigned long)p * PAGE + o] = expect(p, o);
    say("SWAPHOG: wrote ", PAGES, " pages\n");
    for (unsigned p = 0; p < PAGES; p++) {
        for (unsigned o = 0; o < PAGE; o++) {
            if (heap[(unsigned long)p * PAGE + o] != expect(p, o)) {
                say("SWAPHOG: FAIL page ", p, " did not read back as written\n");
                return 1;
            }
        }
    }
    say("SWAPHOG: OK ", SWAPHOG_MIB, " MiB written and read back intact\n");
    return 0;
}
