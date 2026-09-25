/* crt0_shared.c -- C runtime zero for a program whose libc is the shared one.
 *
 * The static crt0.c calls posix_init() and main() directly, because both are
 * linked into the program. Neither is, here: main is, but every libc entry point
 * is a stub that jumps through the shared library's export table, and that table
 * does not exist until shlib_bind() fills it in.
 *
 * SO THE ORDER IS THE WHOLE FILE. shlib_bind() first, before anything that could
 * call a stub -- and note that "anything" includes the parts of this file that
 * look innocent: sys_get_argv is a raw syscall and is fine, but posix_init is a
 * stub, exit is a stub, and main is entirely made of them.
 *
 * A bind failure cannot be reported through libc, for the same reason. It writes
 * a fixed string with a raw syscall and exits: a program that carried on here
 * would fault somewhere inside a stub, at an address that explains nothing about
 * what actually went wrong.
 */

#include "../include/posix.h"
#include "../include/syscall.h"
#include "../include/console_proto.h"

extern int main(int argc, char **argv, char **envp);
extern void exit(int status);          /* stub -> the library's exit */
extern void posix_init(void);          /* stub -> the library's posix_init */
/* The program's OWN environment vector, and not the library's.
 *
 * `environ` is data, so a reference to the library's copy cannot be redirected
 * by a tail jump -- the same limit that keeps optarg/optind out of the table. It
 * is also not exported, so referencing it would simply fail to link.
 *
 * Defining an empty one here is correct rather than a workaround: the library's
 * environ is empty too (newlib_glue.c), this system has no environment to
 * inherit, and getenv() goes through a stub to the library, which reads the
 * library's copy. Both are empty, so there is nothing for the two to disagree
 * about -- and if that ever changes, this is the line that has to change with
 * it, which is why it is spelled out rather than shared. */
static char *empty_environ[] = { (char *)0 };

int shlib_bind(void);                  /* userspace/shlib_start.c */

static char *no_argv[] = { (char *)"horus", (char *)0 };

/* SAID TO THE CONSOLE ENDPOINT, NOT TO FD 2. This used to be sys_write(2, ...),
 * and fd 2 is a descriptor posix_init creates -- which has not run yet, because
 * it is a library call and the library is what just failed to bind. So every
 * refused bind was SILENT: the program printed nothing and exited, and the
 * operator saw a command that did nothing. Found 2026-09-25 driving the first
 * spawned shared-libc programs, where three different failures all looked the
 * same. The console endpoint is a capability every spawned task is given (the
 * spawn propagates it, send-only), so it is the one channel that exists here.
 * One write, the reason included, so it cannot be interleaved. */
static struct con_request  die_rq;
static struct con_response die_rp;

static void die(const char *why) {
    const char *head = "crt0_shared: could not bind the shared libc: ";
    unsigned n = 0;
    for (const char *c = head; *c && n < CON_IO_MAX - 1; c++) die_rq.data[n++] = (uint8_t)*c;
    for (const char *c = why;  *c && n < CON_IO_MAX - 1; c++) die_rq.data[n++] = (uint8_t)*c;
    die_rq.data[n++] = '\n';
    die_rq.magic = CON_PROTO_MAGIC;
    die_rq.op    = CON_OP_WRITE;
    die_rq.len   = n;
    (void)sys_ipc_call(CAPSLOT_CONSOLE_EP, 0, &die_rq, sizeof(die_rq), &die_rp);
    sys_exit();
}

void _start(void) {
    /* Before this returns 0, this program has no libc at all. */
    switch (shlib_bind()) {
    case 0: break;
    case SHLIB_BIND_NO_CAP:
        die("this program was given no library capability");
        break;
    case SHLIB_BIND_NO_DATA:
        die("no private copy of the library's data was mapped");
        break;
    case SHLIB_BIND_TEXT:
        die("a page of the library's code could not be mapped");
        break;
    default:
        die("the library's data is not initialised");
        break;
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
