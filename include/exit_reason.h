#ifndef HORUS_EXIT_REASON_H
#define HORUS_EXIT_REASON_H

#include "syscall.h"

/*
 * Rendering a struct task_exit_info as one human-readable line (finding G-8).
 *
 * This lives in a shared header rather than inside init.c for one reason: a
 * supervisor's diagnostic is only worth having if it is known to work at the
 * moment it is needed, and init's copy would otherwise be executed for the
 * first time during the very failure it exists to explain. G-8 has already been
 * misdiagnosed three times by trusting an unexercised observer, so the exact
 * function init prints with is the exact function the process-control self-test
 * asserts on (see userspace/proctest.c).
 *
 * The wording deliberately avoids the smoke suite's failure regexes (PAGE FAULT
 * / Exception! Vector / PANIC / Rejected by validator): tests that fault on
 * purpose must stay green, so this is a diagnostic line, not a failure marker.
 */

/* Append `v` to `buf` at *pos in `base` (10 or 16), NUL-terminated. */
static inline void exr_append_num(char *buf, int *pos, uint64_t v, int base) {
    char tmp[24];
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v) {
        int d = (int)(v % (uint64_t)base);
        tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        v /= (uint64_t)base;
    }
    while (n) buf[(*pos)++] = tmp[--n];
    buf[*pos] = 0;
}

static inline void exr_append_str(char *buf, int *pos, const char *s) {
    while (*s) buf[(*pos)++] = *s++;
    buf[*pos] = 0;
}

/*
 * Write "<why>" for `ei` into `buf`. Needs a buffer of at least 160 bytes; the
 * longest form is the page-fault one, with three 16-digit hex fields.
 *
 * Reports the reason it was actually given, including TASK_EXIT_NONE — an exit
 * with no recorded cause is itself a finding, and inventing a plausible reason
 * for it is exactly how the earlier G-8 readings went wrong.
 */
static inline void format_exit_reason(char *buf, const struct task_exit_info *ei) {
    int p = 0;
    buf[0] = 0;

    switch (ei->reason) {
    case TASK_EXIT_NORMAL:
        exr_append_str(buf, &p, "normal exit");
        break;
    case TASK_EXIT_KILLED:
        exr_append_str(buf, &p, "killed by task ");
        exr_append_num(buf, &p, ei->detail, 10);
        break;
    case TASK_EXIT_SIGNAL:
        exr_append_str(buf, &p, "uncaught signal ");
        exr_append_num(buf, &p, ei->detail, 10);
        break;
    case TASK_EXIT_FAULT:
        exr_append_str(buf, &p, "faulted, trap vector ");
        exr_append_num(buf, &p, ei->detail, 10);
        exr_append_str(buf, &p, " at rip=0x");
        exr_append_num(buf, &p, ei->rip, 16);
        break;
    case TASK_EXIT_PAGEFAULT:
        exr_append_str(buf, &p, "faulted on memory access at addr=0x");
        exr_append_num(buf, &p, ei->addr, 16);
        exr_append_str(buf, &p, " rip=0x");
        exr_append_num(buf, &p, ei->rip, 16);
        exr_append_str(buf, &p, " err=0x");
        exr_append_num(buf, &p, ei->err, 16);
        break;
    default:
        exr_append_str(buf, &p, "reason not recorded (code ");
        exr_append_num(buf, &p, (uint64_t)(uint32_t)ei->reason, 10);
        exr_append_str(buf, &p, ")");
        break;
    }
}

#endif /* HORUS_EXIT_REASON_H */
