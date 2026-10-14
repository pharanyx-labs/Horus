/* The message shellwatch sends init when the shell dies (userspace/shellwatch.c,
 * docs/design/filesystem.md decision 19). Shared by the two, and by nothing else. */
#ifndef HORUS_SHELLWATCH_H
#define HORUS_SHELLWATCH_H

#include <stdint.h>
#include "syscall.h"

#define SHELLWATCH_MAGIC 0x53575448u   /* "SWTH" */

/* The slots init grants the watcher into, before it lets it run. */
#define SW_TCB_SLOT 16   /* CAP_TCB to the shell, READ only */
#define SW_EP_SLOT  17   /* send capability to init's session endpoint, tokened */

/* The token init mints the watcher's send capability with (SESS_TOKEN_WATCH), so
 * init tells this task's messages from the shell's by what the kernel attests. */
#include "session_proto.h"

struct shellwatch_msg {
    uint32_t magic;
    int32_t  target;     /* the tid the watcher waited on */
    int32_t  wait_rc;    /* SYS_WAIT's answer: 0 once the target is dead */
    uint32_t reserved;
    struct task_exit_info exit;   /* valid when wait_rc == 0 */
};
_Static_assert(sizeof(struct shellwatch_msg) <= 256, "must fit one IPC message (IPC_MSG_MAX)");

#endif
