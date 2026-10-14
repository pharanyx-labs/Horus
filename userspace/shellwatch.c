#include "syscall.h"
#include "shellwatch.h"

/*
 * shellwatch: how init hears that the shell has died, while init itself waits
 * for something else (docs/design/filesystem.md, decision 19; S140).
 *
 * WHY THIS EXISTS. init used to block in SYS_WAIT on the shell. Phase 1b step
 * 3(b) needs init to answer the shell's session requests too, and a task cannot
 * block in SYS_WAIT and SYS_IPC_RECV at once. So init blocks receiving on a
 * session endpoint it makes, and this small task does the waiting: it waits for
 * the shell, sends init the exit record, and exits.
 *
 * WHAT IT HOLDS, AND WHY THAT IS ALL. Two capabilities, both from init:
 *
 *   SW_TCB_SLOT  init's CAP_TCB to the shell, narrowed to READ. READ is what
 *                SYS_WAIT asks for and all it gets: granting into the shell,
 *                killing it or signalling it all need WRITE, so this task can
 *                watch the shell and do nothing to it.
 *   SW_EP_SLOT   a send capability to init's session endpoint, tokened, so init
 *                tells this task's messages from the shell's by the token the
 *                kernel attests, never by who claims to have sent them.
 *
 * The target's tid comes as the spawn argument; the capability, not the number,
 * is the authority (SYS_WAIT refuses a tid this task holds no CAP_TCB for).
 */

void _start(void) {
    struct shellwatch_msg m;
    for (unsigned z = 0; z < sizeof(m); z++) ((char *)&m)[z] = 0;
    m.magic = SHELLWATCH_MAGIC;

    int target = (int)sys_spawn_arg();
    int wr;
    while ((wr = sys_wait(target)) == SYS_ERR_INTR) { }
    m.wait_rc = wr;
    m.target = target;
    /* A refused wait leaves nothing to read: init is told the wait failed, and
     * it treats the shell as not known to be dead, as it always has. */
    if (wr == 0 && sys_task_exit_info(&m.exit) != 0) m.exit.reason = TASK_EXIT_NONE;

    /* IPC_AGAIN is the one retryable answer (a full mailbox); anything else is
     * permanent, and retrying it would be a wedge, not back-pressure. */
    int r;
    while ((r = sys_ipc_send(SW_EP_SLOT, &m, sizeof(m))) == IPC_AGAIN) sys_yield();
    sys_exit();
}
