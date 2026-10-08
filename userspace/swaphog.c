/* swaphog -- a test program for swap (smoke-swap, docs/design/swap.md step 2).
 *
 * Writes SWAPHOG_MIB of heap, every page carrying a marker and a pattern only
 * that page has, then reads all of it back and checks every byte. Run on a
 * machine whose pool is smaller than that, the only way for it to pass is for
 * its pages to go out to swap and come back exactly as they were. The marker is
 * what the host searches the swap partition for afterwards: sealed, it cannot
 * appear there.
 *
 * Linked against the shared libc like any program in /bin. Never shipped: it is
 * a boot module only under SWAP_HOG=1. */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define SWAPHOG_MIB   48u
#define PAGE          4096u
#define PAGES         (SWAPHOG_MIB * 256u)

static const char MARK[] = "HORUS-SWAPHOG-MARKER-";

static void put_dec(char *out, unsigned v) {
    char d[12]; int n = 0;
    do { d[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    int k = 0;
    while (n) out[k++] = d[--n];
    out[k] = 0;
}

static unsigned char expect(unsigned page, unsigned off) {
    if (off < sizeof(MARK) - 1) return (unsigned char)MARK[off];
    return (unsigned char)((page * 131u + off * 7u) & 0xFFu);
}

static void out(const char *t) {
    (void)write(1, t, strlen(t));
}

static void say(const char *a, unsigned v, const char *b) {
    char num[12];
    put_dec(num, v);
    out(a);
    out(num);
    out(b);
}

int main(void) {
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
