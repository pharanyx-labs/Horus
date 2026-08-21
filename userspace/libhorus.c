/* libhorus — implementation. See include/libhorus.h for why this exists and
 * what deliberately does not belong in it.
 *
 * Every function here is a verbatim lift of a definition that existed in two or
 * more freestanding programs, with the behaviour preserved exactly rather than
 * improved. That was the whole point of the change: the migration diff in each
 * program is a deletion plus an #include, so a reviewer can confirm no call site
 * changed meaning without reading this file. Improvements, if any are wanted,
 * are a separate commit with their own witness.
 */
#include "libhorus.h"

void umemset(void *d, int v, unsigned n) {
    uint8_t *p = d;
    while (n--) *p++ = (uint8_t)v;
}

void umemcpy(void *d, const void *s, unsigned n) {
    uint8_t *a = d;
    const uint8_t *b = s;
    while (n--) *a++ = *b++;
}

unsigned uslen(const char *s) {
    unsigned n = 0;
    while (s[n]) n++;
    return n;
}

int ustreq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

void ustrncpy(char *d, const char *s, unsigned n) {
#ifdef LIBHORUS_STRNCPY_UNTERMINATED
    /* CONTROL ARM -- never ship. C's strncpy() semantics: copy up to n bytes and
     * terminate only if the source fit. The destination is then left as a
     * non-string exactly in the case a caller is least likely to have tested,
     * and every ustreq()/uslen() on it afterwards runs off the end. Makes
     * smoke-libhorus fail at strncpy-truncate-unterminated. */
    unsigned i = 0;
    for (; i < n && s[i]; i++) d[i] = s[i];
    if (i < n) d[i] = 0;
#else
    /* The i + 1 < n bound is what reserves room for the terminator, and it is
     * also what makes n == 0 safe: the loop does not run and neither does the
     * store below it, so a zero-length destination is never written. Both
     * former copies had this shape; it is preserved rather than rewritten. */
    unsigned i = 0;
    if (n == 0) return;
    for (; i + 1 < n && s[i]; i++) d[i] = s[i];
    d[i] = 0;
#endif
}

void kput(const char *s) {
    sys_write(1, s, uslen(s));
}

void kputln(const char *s) {
    /* Two writes rather than one buffered line. A buffer here would need a
     * bound, and the callers' strings are already bounded by their own
     * storage -- adding a truncation point to save a syscall would trade a
     * cheap call for a way to lose the end of a diagnostic. fs_server's
     * former println() did exactly this, and it is kept. */
    sys_write(1, s, uslen(s));
    sys_write(1, "\n", 1);
}

void kput_int(int v) {
    char b[12];                 /* -2147483648 is 11 chars plus the NUL */
    int i = 0;
    unsigned u;

    if (v < 0) {
        kput("-");
        /* Negate in unsigned. -v is undefined for INT_MIN, and this path is
         * reachable: an IPC rc is an int a server chooses, and a diagnostic
         * that invokes UB while reporting a fault is a bad diagnostic. */
        u = (unsigned)-(unsigned)v;
    } else {
        u = (unsigned)v;
    }
    if (u == 0) { kput("0"); return; }

    char t[12];
    int n = 0;
    while (u) { t[n++] = (char)('0' + (u % 10)); u /= 10; }
    while (n) b[i++] = t[--n];
    b[i] = 0;
    kput(b);
}

void spin_delay_n(unsigned iters) {
    for (volatile unsigned i = 0; i < iters; i++) { }
}

void spin_delay(void) {
    spin_delay_n(40000u);
}

int ipc_call_retry(int ep_slot, uint32_t badge,
                   const void *req, unsigned req_len, void *rep) {
    /* sys_ipc_call takes a non-const message pointer; the request is not
     * modified by the call, and taking it const here is what lets a caller pass
     * a request it has finished building without casting at every site. */
    void *msg = (void *)(uintptr_t)req;
    unsigned tries = 0;
    int r;

    while ((r = sys_ipc_call(ep_slot, badge, msg, req_len, rep)) < 0) {
#ifdef LIBHORUS_RETRY_ANY
        /* CONTROL ARM -- never ship. The pre-libhorus loop, `while (r < 0)
         * spin_delay();`, which retries EVERY negative code including
         * SYS_ERR_PERM. This is finding G-8 signature C reproduced on demand: a
         * task denied an endpoint spins here forever instead of reporting, and
         * the refusal is indistinguishable from a hang. Under this flag
         * smoke-libhorus never reaches its marker -- which is the assertion,
         * because a test for a hang has nothing to compare. */
        spin_delay();
        continue;
#endif
        /* PERMANENT: return it unchanged and unretried. SYS_ERR_PERM here means
         * the caller holds no capability for this endpoint, or the wrong rights
         * on it, and that is the one event the capability system exists to make
         * visible. Retrying it forever is finding G-8 signature C -- a refusal
         * indistinguishable from a hang. Revoke a capability out from under a
         * task in the old loop and it wedged silently instead of reporting. */
        if (!ipc_transient(r)) return r;

        /* TRANSIENT, but still bounded. The mailbox being briefly full is
         * ordinary under concurrent clients; it never being free again is not,
         * and "retry until it works" is how the permanent case got hidden in
         * the first place. */
        if (++tries > IPC_RETRY_MAX) return IPC_ERR_RETRY_EXHAUSTED;
        spin_delay();
    }
    return r;
}
