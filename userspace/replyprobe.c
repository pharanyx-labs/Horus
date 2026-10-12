#include "syscall.h"

/*
 * Spawned by the process-control self-test (PROC_SELFTEST only) for
 * LIMITATIONS 1.32: a reply, and the sender identity SYS_IPC_SENDER reports,
 * name one incarnation of a task, never whatever later reuses its slot.
 *
 * The driver grants it a send capability to an endpoint the driver receives on,
 * in REPLYPROBE_SLOT_EP, and resumes it. It makes one call and blocks for the
 * answer. The driver runs it twice: the first incarnation's request is received
 * and the task is then killed with the call in flight; the second lands in the
 * same slot and makes its own call, which the driver never receives. The
 * driver's answer to the FIRST request must not complete the second call. If
 * this call ever returns with that answer, the kernel delivered a reply meant
 * for a dead task into its successor's call, and this says so by name.
 */
#define REPLYPROBE_SLOT_EP 20

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

void _start(void) {
    char req[8] = "request";
    char rep[256];
    for (int i = 0; i < (int)sizeof(rep); i++) rep[i] = 0;
    int rc = sys_ipc_call(REPLYPROBE_SLOT_EP, 0, req, sizeof(req), rep);
    if (rc >= 0 && rep[0] == 'S' && rep[1] == 'T' && rep[2] == 'A' && rep[3] == 'L' && rep[4] == 'E')
        report("PROC_SELFTEST: FAIL stale-reply-delivered-to-successor\n");
    else
        report("PROC_SELFTEST: replyprobe call returned\n");
    sys_exit();
}
