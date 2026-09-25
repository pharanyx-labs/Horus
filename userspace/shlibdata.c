/* shlibdata.c -- is the shared libc's writable state this program's own?
 *
 * The data half of make smoke-shlib-inherit. errno lives in the library's
 * per-task data (newlib's struct _reent, reached through _impure_ptr), so it is
 * the most ordinary piece of library state a program can observe.
 *
 *   shlibdata set    sets errno to 4321 and exits. The value stays in whatever
 *                    page the library's data was.
 *   shlibdata get    reports errno as the program found it, before any library
 *                    call could change it. A fresh copy of the library's data
 *                    says 0. The previous program's page says 4321.
 *   shlibdata exec   sets errno to 4321, then replaces its own image with
 *                    `shlibdata get` through SYS_EXEC_IMAGE. The new image must
 *                    start from the template again (D5), so it says 0 too.
 *
 * `set` then `get` is S50 across spawns: two programs, two copies. It goes red
 * under SHLIB_DATA_TEMPLATE_SHARED=1, which maps the template itself into every
 * task. `exec` is the same property across an exec, and under
 * SHLIB_EXEC_NO_DATA=1 the new image has no data at all and refuses to bind.
 *
 * NO STDIO, ON PURPOSE. Everything is reported with write(2) and a number
 * formatted by hand. Under the shared-template arm, a previous program's stdio
 * buffers and malloc arena are in the page this one maps, and a printf would
 * follow a pointer into that program's heap and fault before saying anything.
 * The arm's defect would then look like a crash rather than like the leaked
 * errno it is, and a crash is also what an unpinned template looks like (the
 * pin arm). The witness has to report the value, so it avoids every library path
 * that holds a pointer across programs.
 */
#include <sys/errno.h>        /* newlib's: -I include puts the kernel's errno.h first */
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "../include/syscall.h"

#define MARK 4321

static void say(const char *a, int n, const char *b) {
    char buf[96];
    unsigned k = 0;
    for (const char *c = a; *c && k < sizeof(buf) - 16; c++) buf[k++] = *c;
    char num[12];
    unsigned d = 0, v = (unsigned)(n < 0 ? -n : n);
    do { num[d++] = (char)('0' + v % 10); v /= 10; } while (v && d < sizeof(num));
    if (n < 0) buf[k++] = '-';
    while (d) buf[k++] = num[--d];
    for (const char *c = b; *c && k < sizeof(buf) - 1; c++) buf[k++] = *c;
    (void)write(1, buf, k);
}

static int exec_self_get(void) {
    /* Read our own image through the library's POSIX glue and the filesystem
     * server, and hand it to the kernel whole. open/read rather than fread: the
     * export table carries what the shipped programs use. */
    int fd = open("/bin/shlibdata", O_RDONLY);
    if (fd < 0) { say("SHLIBDATA: FAIL cannot open /bin/shlibdata ", fd, "\n"); return 1; }
    size_t cap = 256 * 1024, n = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) { say("SHLIBDATA: FAIL malloc ", 0, "\n"); close(fd); return 1; }
    long got;
    while (n < cap && (got = read(fd, buf + n, cap - n)) > 0) n += (size_t)got;
    close(fd);
    if (n == 0 || n == cap) { say("SHLIBDATA: FAIL image size ", (int)n, "\n"); return 1; }

    char *av[] = { (char *)"shlibdata", (char *)"get", (char *)0 };
    say("SHLIBDATA: exec with errno=", MARK, "\n");
    errno = MARK;                        /* last: nothing after it touches errno */
    (void)sys_exec_image(buf, (uint32_t)n, 2, av);
    say("SHLIBDATA: FAIL exec returned ", 0, "\n");
    return 1;
}

int main(int argc, char **argv, char **envp) {
    /* FIRST, before any library call could change it. */
    int at_start = errno;
    (void)envp;
    const char *mode = argc > 1 ? argv[1] : "get";

    if (strcmp(mode, "set") == 0) {
        say("SHLIBDATA: set errno=", MARK, "\n");
        errno = MARK;                    /* last: nothing after it touches errno */
        return 0;
    }
    if (strcmp(mode, "exec") == 0) return exec_self_get();

    say("SHLIBDATA: errno=", at_start, " at start\n");
    return 0;
}
