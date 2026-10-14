/* How the shell asks init for its filesystem session at login, and gives it
 * back at logout (docs/design/filesystem.md §6.4, phase 1b step 3(b)). Shared by
 * init and the shell, and by nothing else.
 *
 * The shell holds one capability for this: a send capability to init's session
 * endpoint, minted with SESS_TOKEN_SHELL, which init grants it at launch. init
 * tells the shell's requests from the watcher's by the token the kernel attests
 * for the capability each came through (SYS_IPC_INVOKER), never by what a
 * message says, and it names the account by the uid the kernel attests for the
 * sender (SYS_IPC_SENDER, fixed by SYS_AUTH), never by a uid in the request: a
 * request carries no identity at all. */
#ifndef HORUS_SESSION_PROTO_H
#define HORUS_SESSION_PROTO_H

#include <stdint.h>

#define SESS_PROTO_MAGIC  0x53455353u   /* "SESS" */

/* The tokens init mints its endpoint's send capabilities with. 0 is never a
 * token (an untokened capability is init's own receive right). */
#define SESS_TOKEN_WATCH  1u            /* the shell's watcher (shellwatch.h) */
#define SESS_TOKEN_SHELL  2u            /* the shell */

/* The shell's slot for its send capability to init's session endpoint, one of
 * the fixed slots 24 to 31 a program may use (include/syscall.h). */
#define SESS_SHELL_SLOT   26

#define SESS_OP_OPEN      1   /* after a login: open this account's session    */
#define SESS_OP_END       2   /* at logout: revoke the session and end it       */

struct sess_request {
    uint32_t magic;
    uint32_t op;
};

#define SESS_CWD_MAX      64  /* FS_SESSION_PATH: init checks the two agree */

/* rc 0 and g != 0: a session is open, its root in slot 24 (CAPSLOT_FS_ROOT) and
 * its working directory in slot 25 (CAPSLOT_FS_CWD), whose absolute path is
 * `cwd`, NUL-terminated (a name for pwd, never authority).
 * rc 0 and g == 0: the policy gives this account nothing; no session is open.
 * rc < 0: refused or failed; no session is open. */
struct sess_reply {
    int32_t  rc;
    uint32_t g;          /* the session's grant set, 0 for none */
    uint32_t source;     /* FS_SESSION_SRC_*: which policy applied */
    uint32_t reserved;
    char     cwd[SESS_CWD_MAX];
};

#endif
