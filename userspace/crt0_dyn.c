/* crt0_dyn.c -- C runtime zero for a program LINKED against the shared libc
 * (docs/design/shared-libc.md §8).
 *
 * crt0_shared.c is the same idea for a program built against the stub archive,
 * where every library call is a thunk through an index-ordered table. This one is
 * for a program linked the ordinary way, against userspace/libc_link.so: its
 * references to library names are GOT slots the kernel left for us, and
 * horus_dynlink fills them by name and seals them before anything uses them.
 *
 * NOTHING BEFORE horus_dynlink MAY TOUCH THE LIBRARY: posix_init, exit and main
 * all go through slots it has not filled yet. A refusal is said through the
 * console endpoint rather than fd 2, which posix_init creates and which
 * therefore does not exist yet (crt0_shared.c has the history).
 */
#include "../include/posix.h"
#include "../include/syscall.h"
#include "../include/console_proto.h"
#include "dynlink.h"

extern int main(int argc, char **argv, char **envp);
extern void exit(int status);
extern void posix_init(void);

static char *empty_environ[] = { (char *)0 };
static char *no_argv[] = { (char *)"horus", (char *)0 };

static struct con_request  die_rq;
static struct con_response die_rp;

static void die(const char *why, const char *what) {
    const char *head = "crt0: the shared libc could not be linked: ";
    unsigned n = 0;
    for (const char *c = head; *c && n < CON_IO_MAX - 1; c++) die_rq.data[n++] = (uint8_t)*c;
    for (const char *c = why;  *c && n < CON_IO_MAX - 1; c++) die_rq.data[n++] = (uint8_t)*c;
    for (const char *c = what; c && *c && n < CON_IO_MAX - 1; c++) die_rq.data[n++] = (uint8_t)*c;
    die_rq.data[n++] = '\n';
    die_rq.magic = CON_PROTO_MAGIC;
    die_rq.op    = CON_OP_WRITE;
    die_rq.len   = n;
    (void)sys_ipc_call(CAPSLOT_CONSOLE_EP, 0, &die_rq, sizeof(die_rq), &die_rp);
    sys_exit();
}

void _start(void) {
    const char *unknown = 0;
    switch (horus_dynlink(&unknown)) {
    case 0: break;
    case DYNLINK_NO_CAP:  die("this program was given no library capability", 0); break;
    case DYNLINK_NO_DATA: die("no private copy of the library's data was mapped", 0); break;
    case DYNLINK_TEXT:    die("a page of the library's code could not be mapped", 0); break;
    case DYNLINK_ABI:     die("the library is not the one this program was built against", 0); break;
    case DYNLINK_UNKNOWN: die("the library exports no ", unknown); break;
    case DYNLINK_SEAL:    die("the resolved table could not be sealed", 0); break;
    default:              die("this program's dynamic section is malformed", 0); break;
    }

    posix_init();

    char **argv = 0;
    int argc = sys_get_argv(&argv);
    if (argc <= 0 || !argv) {
        argc = 1;
        argv = no_argv;
    }
    exit(main(argc, argv, empty_environ));
}
