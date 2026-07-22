#include "syscall.h"
#include "fs_proto.h"
#include "console_proto.h"
#include "malloc.h"

/* Wipe a password buffer so it does not outlive its use on the stack. Volatile,
 * because the plain `for (i) buf[i] = 0` this replaces is a dead store to a
 * local that is never read again — exactly what -O2 is entitled to delete. The
 * kernel has secure_zero for the same reason; freestanding userspace has no
 * libc to borrow one from. */
static void scrub(char *buf, size_t n) {
    volatile char *p = (volatile char *)buf;
    while (n--) *p++ = 0;
}

/* Retry budget for a console-server IPC round-trip. A live server on another core
 * answers on the first try; this only matters under SMP contention, where the
 * shell and the server rendezvous on a single-slot mailbox and the timing does not
 * always line up in a handful of yields. The kernel now fails its own console path
 * closed while the server owns the hardware (so it can't race the server on the
 * UART), which means there is no working in-kernel fallback while the server is
 * alive — these calls MUST reach it. Waiting is safe: if the server has actually
 * died, task teardown releases console ownership, the kernel path re-opens, and the
 * fallback below then works. Each try yields, so this never busy-spins. */
#define CON_MAX_RETRY 20000

/* Send `len` bytes to the ring-3 console_server (CON_OP_WRITE, well-known endpoint
 * CON_EP_REQ) using the shell's own default endpoint cap. Returns 0 if the server
 * accepted the whole write, -1 to fall back to the in-kernel console — so console
 * output is never lost even if the server is not up yet, unreachable, or errors.
 * Bounded retries keep a transient "mailbox full / not yet serving" condition from
 * hanging the shell. Part of moving the console into ring 3 (Phase 6); see
 * docs/proposals/console-server.md. */
static struct con_request  con_rq;   /* static: keep these off the shell's stack */
static struct con_response con_rp;
static int con_write_all(const char *s, size_t len) {
    size_t off = 0;
    do {
        size_t n = len - off;
        if (n > CON_IO_MAX) n = CON_IO_MAX;
        con_rq.magic = CON_PROTO_MAGIC;
        con_rq.op    = CON_OP_WRITE;
        con_rq.len   = (uint32_t)n;
        for (size_t i = 0; i < n; i++) con_rq.data[i] = (uint8_t)s[off + i];

        int rc = -1;
        for (int tries = 0; tries < CON_MAX_RETRY; tries++) {
            rc = sys_ipc_call(CON_EP_REQ, CON_EP_REP,
                              &con_rq, sizeof(con_rq), &con_rp);
            if (rc >= 0) break;
            sys_yield();   /* mailbox full: let console_server drain it */
        }
        if (rc < 0 || con_rp.magic != CON_PROTO_MAGIC || con_rp.rc != (int)n)
            return -1;   /* fall back to the in-kernel console */
        off += n;
    } while (off < len);
    return 0;
}

static void print(const char *s) {
    size_t l = 0; while (s[l]) l++;
    if (l == 0) return;
    if (con_write_all(s, l) != 0)
        sys_write(1, s, l);   /* fallback: in-kernel console (fd 1) */
}

/* Read one line from the ring-3 console_server: `op` is CON_OP_GETLINE (echoed)
 * or CON_OP_GETPASS (masked echo). The server does the terminal editing/echo and
 * replies with the line. Returns the length and fills `buf` (NUL-terminated), or
 * -1 so the caller falls back to the in-kernel console — so input still works if
 * the server is unreachable. Password bytes in the shared reply buffer are
 * scrubbed after use. */
static int con_read_line(uint32_t op, char *buf, unsigned max) {
    con_rq.magic = CON_PROTO_MAGIC;
    con_rq.op    = op;
    con_rq.len   = max;
    int rc = -1;
    for (int tries = 0; tries < CON_MAX_RETRY; tries++) {
        rc = sys_ipc_call(CON_EP_REQ, CON_EP_REP, &con_rq, sizeof(con_rq), &con_rp);
        if (rc >= 0) break;
        sys_yield();
    }
    if (rc < 0 || con_rp.magic != CON_PROTO_MAGIC || con_rp.rc < 0)
        return -1;   /* fall back to the in-kernel console reader */
    int n = con_rp.rc; if (n > (int)max) n = (int)max;
    for (int i = 0; i < n; i++) buf[i] = (char)con_rp.data[i];
    buf[n] = 0;
    scrub((char *)con_rp.data, sizeof(con_rp.data));   /* don't retain input (esp. passwords) */
    return n;
}

/* Console input, routed through console_server with an in-kernel fallback — the
 * input counterparts of print(). */
static int sh_get_line(char *buf, unsigned max) {
    int n = con_read_line(CON_OP_GETLINE, buf, max);
    return (n >= 0) ? n : sys_get_line(buf, max);
}
static int sh_get_pass(char *buf, unsigned max) {
    int n = con_read_line(CON_OP_GETPASS, buf, max);
    return (n >= 0) ? n : sys_get_pass(buf, max);
}

static void println(const char *s) {
    print(s);
    print("\n");
}

static int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static int strncmp(const char *a, const char *b, size_t n) {
    while (n > 0 && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

static const char* strstr(const char *haystack, const char *needle) {
    if (!*needle) return haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack, *n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return haystack;
    }
    return 0;
}


static int fss_connected = 0;
static uint32_t fss_ep_slot = 0;

static int fss_strlen(const char *s) { int l=0; while(s[l]) l++; return l; }
static void fss_strcpy(char *d, const char *s) { while((*d++ = *s++)); }

static int fss_connect(void) {
    if (fss_connected) return 0;
    fss_ep_slot = 20;
    /* sys_connect_fs_server mints a cap in slot fss_ep_slot so the kernel's
     * slot-3 check passes for SYS_IPC_CALL.  The actual send/receive uses the
     * well-known endpoint indices directly (FS_EP_REQ / FS_EP_REP). */
    int rc = sys_connect_fs_server(fss_ep_slot, 3);
    if (rc == 0) {
        fss_connected = 1;
        return 0;
    }
    return -1;
}

static int fss_call(struct fs_request *req, struct fs_response *rep) {
    if (!fss_connected) {
        if (fss_connect() != 0) return -1;
    }
    req->magic = FS_PROTO_MAGIC;
    /* Blocking IPC: send on FS_EP_REQ (4), block until reply arrives on
     * FS_EP_REP (5).  The kernel unblocks us and fills *rep atomically. */
    int r = sys_ipc_call(FS_EP_REQ, FS_EP_REP,
                         (const char *)req, sizeof(*req), (char *)rep);
    return (r < 0) ? r : 0;
}

static void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dest;
}

static size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static void print_decimal(uint32_t n) {
    char buf[11];
    int i = 10;
    buf[i] = '\0';
    if (n == 0) {
        buf[--i] = '0';
    } else {
        while (n > 0) {
            buf[--i] = '0' + (n % 10);
            n /= 10;
        }
    }
    print(&buf[i]);
}

/* ----- working directory (shell-side) ---------------------------------
 * The shell does its own path handling (it does not link posix.c). It tracks a
 * cwd inode for relative fs ops and a canonical absolute path string for `pwd`.
 * Directory ops below (ls/cat/mkdir/rm/touch) resolve names within sh_cwd_ino. */
#define SH_PATH_MAX 256
static uint32_t sh_cwd_ino = 0;
static char     sh_cwd_path[SH_PATH_MAX] = "/";

/* Normalize `arg` against sh_cwd_path into `out` (absolute). Resolves ".", "..",
 * a leading "/", and repeated slashes — pure string work (mirrors posix.c's
 * cwd_normalize). Returns 0 or -1 on overflow. */
static int sh_normalize(const char *arg, char *out) {
    char comps[16][FS_NAME_MAX];
    int  ncomp = 0;

    if (arg[0] != '/') {
        const char *q = sh_cwd_path;
        while (*q == '/') q++;
        while (*q) {
            int c = 0;
            while (*q && *q != '/' && c < FS_NAME_MAX - 1) comps[ncomp][c++] = *q++;
            comps[ncomp][c] = '\0';
            while (*q == '/') q++;
            if (c > 0) { if (ncomp >= 16) return -1; ncomp++; }
        }
    }

    const char *p = arg;
    while (*p == '/') p++;
    while (*p) {
        char comp[FS_NAME_MAX];
        int  c = 0;
        while (*p && *p != '/' && c < FS_NAME_MAX - 1) comp[c++] = *p++;
        comp[c] = '\0';
        while (*p == '/') p++;
        if (c == 0) continue;
        if (comp[0] == '.' && comp[1] == '\0') continue;
        if (comp[0] == '.' && comp[1] == '.' && comp[2] == '\0') { if (ncomp > 0) ncomp--; continue; }
        if (ncomp >= 16) return -1;
        memcpy(comps[ncomp], comp, (size_t)c + 1);
        ncomp++;
    }

    int o = 0;
    if (ncomp == 0) { out[0] = '/'; out[1] = '\0'; return 0; }
    for (int i = 0; i < ncomp; i++) {
        int l = fss_strlen(comps[i]);
        if (o + 1 + l >= SH_PATH_MAX) return -1;
        out[o++] = '/';
        memcpy(out + o, comps[i], (size_t)l);
        o += l;
    }
    out[o] = '\0';
    return 0;
}

/* Walk an absolute path from the root; every component must resolve to a
 * directory. Returns the final inode, or (uint32_t)-1 on any failure. */
static uint32_t sh_walk_abs_dir(const char *abspath) {
    uint32_t ino = 0;                 /* root */
    const char *p = abspath;
    while (*p == '/') p++;
    while (*p) {
        char comp[FS_NAME_MAX];
        int  c = 0;
        while (*p && *p != '/' && c < FS_NAME_MAX - 1) comp[c++] = *p++;
        comp[c] = '\0';
        while (*p == '/') p++;
        if (c == 0) continue;
        struct fs_request  rq = {0};
        struct fs_response rp;
        rq.op = FS_OP_LOOKUP; rq.dir_ino = ino; fss_strcpy(rq.name, comp);
        if (fss_call(&rq, &rp) < 0 || rp.rc < 0) return (uint32_t)-1;
        if (rp.type != FS_TYPE_DIR) return (uint32_t)-1;
        ino = rp.ino;
    }
    return ino;
}

/* ---- output typography -------------------------------------------------
 *
 * Horus's console is a fixed-width VGA text grid mirrored to serial, and the
 * terminal driver does not interpret ANSI escapes -- emitting them would print
 * literal garbage on the VGA side. So alignment and column discipline carry the
 * whole visual weight here; nothing below depends on colour. */

#define TERM_COLS 80

/* Print `s`, then pad with spaces to `width`. Over-long strings are printed in
 * full rather than truncated -- a name is more useful than a tidy column. */
static void print_pad(const char *s, int width) {
    print(s);
    int len = 0; while (s[len]) len++;
    for (int i = len; i < width; i++) print(" ");
}

/* ---- running ported coreutils programs ---------------------------------
 *
 * Real programs live as files in /bin, provisioned there from GRUB boot modules
 * (the ported GNU coreutils among them) — they are NOT baked into the kernel
 * image. A command whose first word names a file in /bin is loaded over the
 * fs_server and run as a child: its argv is marshalled onto the child's stack,
 * the shell blocks in SYS_WAIT until it exits, and its stdout goes to the shared
 * console so the output appears inline. The child reaches the fs_server on its
 * own (its libc fd layer connects on the first open()), so `wc file` and `head
 * file` read real files without the shell delegating anything.
 *
 * This is checked before the builtins, so a real /bin/<name> shadows a lighter
 * shell builtin of the same name; a name with no /bin file falls through to the
 * builtin (or an "unknown command"). */

/* An image must fit the kernel's staged-image cap (MAX_PROGRAM_SIZE, 8 MiB); the
 * newlib-linked coreutils binaries are ~400–600 KiB, well under it. */
#define SH_MAX_IMAGE (8u * 1024u * 1024u)

/* Read the whole file `ino` (`size` bytes) into `buf` via the fs_server, one
 * FS_IO_MAX chunk at a time. Returns 0 on success, -1 on a short read or error. */
static int sh_read_file(uint32_t ino, unsigned char *buf, uint32_t size) {
    uint32_t off = 0;
    struct fs_response rp;
    while (off < size) {
        uint32_t chunk = size - off;
        if (chunk > FS_IO_MAX) chunk = FS_IO_MAX;
        struct fs_request dq = {0};
        dq.op = FS_OP_READ; dq.ino = ino; dq.offset = off; dq.len = chunk;
        /* rc <= 0 is a real error or premature EOF (no progress); a rc SHORTER
         * than chunk is normal — FS_OP_READ never crosses a 512-byte block, so a
         * request that straddles one comes back partial. Keep reading from the new
         * offset rather than treating it as truncation. */
        if (fss_call(&dq, &rp) < 0 || rp.rc <= 0) return -1;
        uint32_t got = (uint32_t)rp.rc;
        if (got > chunk) got = chunk;
        memcpy(buf + off, rp.data, got);
        off += got;
    }
    return 0;
}

/* Tokenise `cmd` on spaces into argv (pointers into the caller-owned `store`,
 * which is overwritten with NUL-separated tokens). Returns argc (capped). */
#define CU_MAXARGS 16
static int tokenize(const char *cmd, char *store, int store_sz, char *argv[]) {
    int argc = 0, si = 0;
    const char *p = cmd;
    while (*p && argc < CU_MAXARGS - 1) {
        while (*p == ' ') p++;
        if (!*p) break;
        argv[argc++] = &store[si];
        while (*p && *p != ' ' && si < store_sz - 1) store[si++] = *p++;
        store[si++] = '\0';
        while (*p && *p != ' ') p++;   /* skip any tail that overran the store */
    }
    argv[argc] = 0;
    return argc;
}

/* If `cmd`'s first bare word names an executable file in /bin, load it and run it
 * as a child with the full argv, blocking until it exits; return 1. Returns 0
 * when the word is not a /bin file (or /bin does not exist yet, or the word
 * carries a path), so the caller falls through to the shell's own builtin of the
 * same name. Checked before the builtins precisely so a real /bin/<name> shadows
 * the lighter builtin whenever it is present. */
static int try_run_from_bin(const char *cmd) {
    char store[256];
    char *argv[CU_MAXARGS];
    int argc = tokenize(cmd, store, sizeof(store), argv);
    if (argc == 0) return 0;
    /* Only bare names resolve against /bin; an explicit path (./x, /bin/x) is for
     * `run`, and a builtin like `cd` must not be shadowed by a stray /bin file. */
    for (const char *q = argv[0]; *q; q++) if (*q == '/') return 0;

    uint32_t bin = sh_walk_abs_dir("/bin");
    if (bin == (uint32_t)-1) return 0;                    /* no /bin yet: use builtins */

    struct fs_request  rq = {0};
    struct fs_response rp;
    rq.op = FS_OP_LOOKUP; rq.dir_ino = bin; fss_strcpy(rq.name, argv[0]);
    if (fss_call(&rq, &rp) < 0 || rp.rc < 0 || rp.type != FS_TYPE_FILE) return 0;  /* not in /bin */
    uint32_t ino = rp.ino;

    struct fs_request sq = {0};
    sq.op = FS_OP_STAT; sq.ino = ino;
    if (fss_call(&sq, &rp) < 0 || rp.rc < 0) { print(argv[0]); println(": stat failed"); return 1; }
    uint32_t size = rp.size;
    if (size == 0 || size > SH_MAX_IMAGE) { print(argv[0]); println(": bad image size"); return 1; }

    unsigned char *buf = malloc(size);
    if (!buf) { print(argv[0]); println(": out of memory"); return 1; }
    if (sh_read_file(ino, buf, size) != 0) { print(argv[0]); println(": read failed"); free(buf); return 1; }

    int pid = sys_spawn_image(buf, size, argc, argv);
    free(buf);                                            /* kernel already staged the image */
    if (pid < 0) { print(argv[0]); println(": failed to spawn"); return 1; }
    /* Block until the child finishes so its output lands before the next prompt.
     * SYS_ERR_INTR (a signal interrupted the wait) is retried; any other return
     * means the child is already gone. */
    while (sys_wait(pid) == SYS_ERR_INTR) { }
    return 1;
}

/* If /usr/share/man/<name> exists in the store, print it verbatim and return 1;
 * otherwise return 0 so the caller falls back to the shell's built-in man page.
 * Man pages are plain-text files provisioned from GRUB boot modules, so `man tail`
 * works once /usr/share/man is populated, and still works (from the built-in
 * table) on a bare kernel that ships none. */
static int try_man_from_fs(const char *name) {
    uint32_t dir = sh_walk_abs_dir("/usr/share/man");
    if (dir == (uint32_t)-1) return 0;                    /* no /usr/share/man yet */

    struct fs_request  rq = {0};
    struct fs_response rp;
    rq.op = FS_OP_LOOKUP; rq.dir_ino = dir; fss_strcpy(rq.name, name);
    if (fss_call(&rq, &rp) < 0 || rp.rc < 0 || rp.type != FS_TYPE_FILE) return 0;
    uint32_t ino = rp.ino;

    struct fs_request sq = {0};
    sq.op = FS_OP_STAT; sq.ino = ino;
    if (fss_call(&sq, &rp) < 0 || rp.rc < 0) return 0;
    uint32_t size = rp.size;
    if (size == 0 || size > SH_MAX_IMAGE) return 0;

    unsigned char *buf = malloc(size);
    if (!buf) return 0;
    if (sh_read_file(ino, buf, size) != 0) { free(buf); return 0; }
    sys_write(1, (const char *)buf, size);                /* the page is already formatted */
    free(buf);
    return 1;
}

/* Print `s` right-aligned in `width`, for numeric columns where the digits
 * should line up on their last character. */
static void print_rpad(const char *s, int width) {
    int len = 0; while (s[len]) len++;
    for (int i = len; i < width; i++) print(" ");
    print(s);
}

/* Render a byte count the way a person reads it: exact below 1000, then one
 * decimal place with a unit suffix ("1.2K", "403K", "2.7M"). The point is that a
 * column of these is comparable at a glance, which a column of raw byte counts
 * is not. `out` needs 8 bytes. */
static void human_size(uint32_t bytes, char *out) {
    static const char unit[] = { 'B', 'K', 'M', 'G' };
    int u = 0;
    uint32_t whole = bytes, frac = 0;

    while (whole >= 1000 && u < 3) {
        frac  = ((whole % 1024) * 10) / 1024;   /* one decimal, truncated */
        whole = whole / 1024;
        u++;
    }

    int i = 0;
    if (u == 0) {                                /* plain byte count, no suffix */
        if (whole == 0) { out[i++] = '0'; }
        else {
            char tmp[12]; int t = 0;
            while (whole) { tmp[t++] = (char)('0' + whole % 10); whole /= 10; }
            while (t) out[i++] = tmp[--t];
        }
        out[i] = '\0';
        return;
    }

    char tmp[12]; int t = 0;
    if (whole == 0) tmp[t++] = '0';
    while (whole) { tmp[t++] = (char)('0' + whole % 10); whole /= 10; }
    while (t) out[i++] = tmp[--t];
    if (frac) { out[i++] = '.'; out[i++] = (char)('0' + frac); }
    out[i++] = unit[u];
    out[i] = '\0';
}

/* Octal renderer for a mode word, so `stat` can show 0644 alongside the
 * symbolic form. `print_decimal` cannot express a permission word usefully. */
static void print_octal(uint32_t v) {
    char tmp[12]; int t = 0;
    if (v == 0) tmp[t++] = '0';
    while (v) { tmp[t++] = (char)('0' + (v & 7)); v >>= 3; }
    char out[13]; int i = 0;
    while (t) out[i++] = tmp[--t];
    out[i] = '\0';
    print(out);
}

/* uid -> display name. Only uid 0 has a name every Horus system agrees on; the
 * rest are shown numerically rather than guessed at, since resolving them would
 * mean trusting a name the shell cannot verify. `out` needs 12 bytes. */
static void owner_name(uint32_t uid, char *out) {
    if (uid == 0) { out[0]='r'; out[1]='o'; out[2]='o'; out[3]='t'; out[4]='\0'; return; }
    int i = 0; char tmp[12]; int t = 0;
    if (uid == 0) tmp[t++] = '0';
    while (uid) { tmp[t++] = (char)('0' + uid % 10); uid /= 10; }
    while (t) out[i++] = tmp[--t];
    out[i] = '\0';
}

/* Mode string into a caller buffer (11 bytes), rather than straight to the
 * console, so it can be placed in an aligned column. */
static void fmt_perms(int is_dir, uint32_t mode, char *s) {
    static const char rwx[3] = { 'r', 'w', 'x' };
    s[0] = is_dir ? 'd' : '-';
    for (int i = 0; i < 9; i++)
        s[1 + i] = (mode & (1u << (8 - i))) ? rwx[i % 3] : '-';
    s[10] = '\0';
}

/* Split the argument tail `s` into up to two space-separated tokens, copied
 * NUL-terminated into a[amax]/b[bmax] (truncated to fit). Returns the token
 * count (0/1/2). */
static int split2(const char *s, char *a, int amax, char *b, int bmax) {
    while (*s == ' ') s++;
    int n = 0, i = 0;
    if (*s) { n = 1; while (*s && *s != ' ' && i < amax - 1) a[i++] = *s++; }
    a[i] = '\0';
    while (*s == ' ') s++;
    i = 0;
    if (*s) { n = 2; while (*s && *s != ' ' && i < bmax - 1) b[i++] = *s++; }
    b[i] = '\0';
    return n;
}

/* Look up `name` in the current directory. Returns its inode and (if type is
 * non-NULL) its FS_TYPE_*; returns (uint32_t)-1 if it does not exist. */
static uint32_t sh_lookup(const char *name, uint32_t *type) {
    struct fs_request  rq = {0};
    struct fs_response rp;
    rq.op = FS_OP_LOOKUP; rq.dir_ino = sh_cwd_ino; fss_strcpy(rq.name, name);
    if (fss_call(&rq, &rp) < 0 || rp.rc < 0) return (uint32_t)-1;
    if (type) *type = rp.type;
    return rp.ino;
}

/* One command row in the general list: 3-space indent, name padded to a fixed
 * column, then a short description. */
static void print_cmd(const char *name, const char *desc) {
    print("   ");
    print(name);
    int len = 0; while (name[len]) len++;
    for (int i = len; i < 22; i++) print(" ");
    println(desc);
}

/* One "Label:   text" line in detailed (help <topic>) output, label left-padded
 * to a fixed width so the text lines up. An empty label continues a block. */
static void help_line(const char *label, const char *text) {
    print("  ");
    print(label);
    int len = 0; while (label[len]) len++;
    for (int i = len; i < 10; i++) print(" ");   /* pad past the longest label ("See also:") */
    println(text);
}

static void help_rule(void) {
    println("  ==========================================================================");
}


/* ---- man pages ---------------------------------------------------------
 *
 * `help` is the categorised index; `man` is the reference. Pages follow the
 * usual section order (NAME / SYNOPSIS / DESCRIPTION / OPTIONS / EXIT STATUS /
 * SEE ALSO) so the shape is familiar, and the DESCRIPTION text says what is
 * actually true on Horus rather than repeating Unix folklore -- where an
 * operation is capability-gated or enforced by the fs_server against a
 * kernel-attested uid, the page says so, because that is the part a reader
 * cannot infer from the name.
 *
 * Section 1 is a user command, section 8 needs uid 0.
 */
struct man_page {
    const char *name;
    const char *sect;
    const char *summary;                 /* the whatis(1) one-liner */
    const char *synopsis;
    const char *const *desc;             /* NULL-terminated */
    const char *const *opts;             /* NULL-terminated, or NULL */
    const char *exit_status;             /* or NULL */
    const char *see_also;
};

static const char *const d_ls[] = {
    "List the entries of the current directory, sorted by name.",
    "Directories are shown with a trailing '/' and executables with a '*',",
    "so the type of an entry is visible without colour -- the console is a",
    "VGA text grid that does not interpret ANSI escapes.",
    "",
    "Entries you cannot stat are listed with their metadata shown as '?'",
    "rather than as zeroes, so an unreadable entry is never mistaken for an",
    "empty root-owned file.",
    0 };
static const char *const o_ls[] = {
    "-l    long format: mode, owner, size and name in aligned columns",
    0 };

static const char *const d_cat[] = {
    "Copy each FILE to standard output.",
    "",
    "The shell builtin reads through the fs_server, which checks read",
    "permission against your kernel-attested uid. A ported GNU coreutils",
    "cat(1) is also available in builds carrying the coreutils port; it is",
    "the real upstream implementation and supports its full option set.",
    0 };

static const char *const d_cd[] = {
    "Change the working directory. With no argument, go to the root (/).",
    "",
    "The shell resolves the path through the fs_server and only updates the",
    "working directory if the target exists and is a directory, so a failed",
    "cd leaves you where you were.",
    0 };

static const char *const d_pwd[] = { "Print the working directory.", 0 };

static const char *const d_mkdir[] = {
    "Create a directory.",
    "",
    "Requires write permission on the parent directory. The new directory is",
    "owned by your uid with mode 0755.",
    0 };

static const char *const d_rm[] = {
    "Remove a file, or an empty directory.",
    "",
    "Requires write permission on the parent directory. A non-empty directory",
    "is refused. Removing a name drops one link: a file with another name",
    "still exists until its last link goes (see link counts in stat(1)).",
    0 };

static const char *const d_touch[] = {
    "Create an empty file if it does not exist.",
    "The new file is owned by your uid with mode 0644.",
    0 };

static const char *const d_stat[] = {
    "Show a file's type, permissions, owner, size, link count and inode.",
    "",
    "The mode is printed both symbolically and in octal. The link count is",
    "the number of names referring to the inode; it is greater than one when",
    "hard links exist, and the data survives until the count reaches zero.",
    0 };

static const char *const d_cp[] = {
    "Copy a file. Reads the source and writes a new file at the destination,",
    "so the copy is owned by you regardless of who owned the original.",
    0 };
static const char *const d_mv[] = {
    "Rename a file. Both parent directories must be writable by you.",
    0 };
static const char *const d_wc[] = {
    "Count the lines, words and bytes in a file.",
    0 };
static const char *const d_echo[] = {
    "Print the arguments, separated by spaces, followed by a newline.",
    "",
    "With '>' the text is written to a file instead, creating it if needed.",
    "A ported GNU coreutils echo(1) is also available in builds carrying the",
    "coreutils port, with the full -n/-e/-E option set and backslash escapes.",
    0 };

static const char *const d_run[] = {
    "Load a program image from a file and execute it.",
    "",
    "The image is read through the fs_server and handed to the kernel, which",
    "validates it with the same ELF loader a named binary goes through: W^X",
    "is enforced per segment, bounds are checked, and relocations fail closed.",
    "Gated on the slot-3 WRITE|EXEC capability -- being able to read a file is",
    "not authority to execute it.",
    0 };

static const char *const d_spawn[] = {
    "Spawn an embedded binary by name, or the last image armed by receive(1).",
    "",
    "The child inherits your uid, and only the capabilities the spawner passes",
    "down. There is no ambient authority: a spawned task can do nothing its",
    "cspace does not name.",
    0 };

static const char *const d_ps[] = {
    "List visible tasks: pid, owner, name, state, heap use, capability count",
    "and flags. Your own task is marked with '*'.",
    "",
    "Visibility is authority-scoped. Without uid 0 you see only your own task",
    "-- task listings are an information leak like any other, so they are",
    "gated rather than shown in full to everyone.",
    0 };

static const char *const d_whoami[] = {
    "Print the uid and gid the kernel attests for this session.",
    "",
    "This is the identity established at login, reported by the kernel -- not",
    "a value the shell chose or a client can claim. Every permission check in",
    "the fs_server is made against it.",
    0 };

static const char *const d_sudo[] = {
    "Re-authenticate at a secure prompt and spawn an elevated image.",
    "",
    "The password is read by the kernel, never echoed, and never passes",
    "through the shell's input buffer.",
    0 };
static const char *const d_passwd[] = {
    "Change your password at a secure prompt.",
    "",
    "Passwords are stored as Argon2id hashes -- memory-hard, so an attacker",
    "who obtains the database cannot cheaply brute-force it -- and the change",
    "persists across reboots.",
    0 };
static const char *const d_useradd[] = {
    "Create a user account with the given uid and name. Requires uid 0.",
    0 };
static const char *const d_userdel[] = {
    "Delete a user account. Requires uid 0.",
    0 };
static const char *const d_rotate[] = {
    "Re-encrypt the storage volume under a freshly derived key. Requires uid 0.",
    0 };

static const char *const d_mem[] = {
    "Grow the heap by one page and touch it, demonstrating sbrk(2) and the",
    "demand pager: the page is not backed by physical memory until written.",
    0 };
static const char *const d_yield[] = {
    "Hand the CPU to another runnable task. Scheduling is preemptive, so this",
    "is a courtesy rather than a requirement.",
    0 };
static const char *const d_help[] = {
    "Without an argument, print the categorised command index.",
    "With one, print details for a command or a group (files, security,",
    "process, ipc, loader).",
    "",
    "For a full reference page on a single command, use man(1).",
    0 };
static const char *const d_man[] = {
    "Display the reference page for a command.",
    "",
    "man first looks for /usr/share/man/<name> in the filesystem -- where the",
    "ported coreutils and hier(7) install their pages -- and prints it. If there",
    "is no such file it falls back to a built-in table compiled into the shell,",
    "which documents the shell's own builtins and works before any filesystem is",
    "mounted. Use apropos(1) to search the built-in pages by keyword and",
    "whatis(1) for the one-line summary.",
    0 };
static const char *const d_apropos[] = {
    "Search the manual page names and summaries for a keyword and list every",
    "match with its one-line description.",
    0 };
static const char *const d_whatis[] = {
    "Print the one-line summary of a command, as shown by apropos(1).",
    0 };
static const char *const d_exit[] = {
    "End the session and return to the login prompt.",
    0 };

static const struct man_page man_pages[] = {
 { "ls","1","list directory entries","ls [-l]",d_ls,o_ls,
   "0 on success; non-zero if the directory could not be read.","cat(1), stat(1), cd(1)" },
 { "cat","1","print a file's contents","cat FILE",d_cat,0,
   "0 on success; non-zero if a file could not be read.","ls(1), wc(1), echo(1)" },
 { "cd","1","change the working directory","cd [DIR]",d_cd,0,0,"pwd(1), ls(1)" },
 { "pwd","1","print the working directory","pwd",d_pwd,0,0,"cd(1)" },
 { "mkdir","1","create a directory","mkdir DIR",d_mkdir,0,
   "0 on success; non-zero if the name exists or the parent is not writable.","rm(1), ls(1)" },
 { "rm","1","remove a file or empty directory","rm NAME",d_rm,0,
   "0 on success; non-zero if the name is missing, or a directory is not empty.","mkdir(1), stat(1)" },
 { "touch","1","create an empty file","touch FILE",d_touch,0,0,"echo(1), stat(1)" },
 { "stat","1","show a file's metadata","stat FILE",d_stat,0,0,"ls(1)" },
 { "cp","1","copy a file","cp SRC DST",d_cp,0,0,"mv(1)" },
 { "mv","1","rename a file","mv SRC DST",d_mv,0,0,"cp(1), rm(1)" },
 { "wc","1","count lines, words and bytes","wc FILE",d_wc,0,0,"cat(1)" },
 { "echo","1","print text, or write it to a file","echo TEXT [> FILE]",d_echo,0,0,"cat(1), touch(1)" },
 { "run","1","execute a program image from a file","run FILE",d_run,0,0,"spawn(1), ps(1)" },
 { "spawn","1","spawn an embedded binary","spawn [NAME]",d_spawn,0,0,"run(1), ps(1)" },
 { "ps","1","list visible tasks","ps",d_ps,0,0,"spawn(1), whoami(1)" },
 { "mem","1","grow the heap by one page","mem",d_mem,0,0,"ps(1)" },
 { "yield","1","hand the CPU to another task","yield",d_yield,0,0,"ps(1)" },
 { "whoami","1","show your attested uid and gid","whoami",d_whoami,0,0,"id(1), sudo(1), ps(1)" },
 { "id","1","show your attested uid and gid","id",d_whoami,0,0,"whoami(1)" },
 { "sudo","1","re-authenticate and elevate","sudo",d_sudo,0,0,"passwd(1), whoami(1)" },
 { "passwd","1","change your password","passwd",d_passwd,0,0,"sudo(1)" },
 { "useradd","8","create a user account","useradd UID NAME",d_useradd,0,0,"userdel(8), passwd(1)" },
 { "userdel","8","delete a user account","userdel UID",d_userdel,0,0,"useradd(8)" },
 { "rotate_keys","8","re-encrypt storage under a fresh key","rotate_keys",d_rotate,0,0,"passwd(1)" },
 { "help","1","print the command index","help [TOPIC]",d_help,0,0,"man(1), apropos(1)" },
 { "man","1","display a command's reference page","man COMMAND",d_man,0,0,"help(1), apropos(1), whatis(1)" },
 { "apropos","1","search the manual by keyword","apropos KEYWORD",d_apropos,0,0,"man(1), whatis(1)" },
 { "whatis","1","print a command's one-line summary","whatis COMMAND",d_whatis,0,0,"man(1), apropos(1)" },
 { "exit","1","end the session","exit",d_exit,0,0,"help(1)" },
};
#define MAN_COUNT ((int)(sizeof(man_pages)/sizeof(man_pages[0])))

static const struct man_page *man_find(const char *name) {
    for (int i = 0; i < MAN_COUNT; i++)
        if (strcmp(man_pages[i].name, name) == 0) return &man_pages[i];
    return 0;
}

/* Section heading, then an indented body -- the two-level indent is what makes
 * a man page scannable, so it is kept rather than flattened. */
static void man_section(const char *head) { println(""); println(head); }
static void man_body(const char *text)    { print("       "); println(text); }

static void man_render(const struct man_page *m) {
    println("");
    print(m->name); print("("); print(m->sect); print(")");
    for (int i = fss_strlen(m->name) + fss_strlen(m->sect) + 2; i < 62; i++) print(" ");
    print("HORUS"); println("");

    man_section("NAME");
    { char line[96]; int i = 0;
      for (const char *p = m->name; *p && i < 60; p++) line[i++] = *p;
      line[i++] = ' '; line[i++] = '-'; line[i++] = ' ';
      for (const char *p = m->summary; *p && i < 92; p++) line[i++] = *p;
      line[i] = 0; man_body(line); }

    man_section("SYNOPSIS");
    man_body(m->synopsis);

    man_section("DESCRIPTION");
    for (int i = 0; m->desc[i]; i++) man_body(m->desc[i]);

    if (m->opts) {
        man_section("OPTIONS");
        for (int i = 0; m->opts[i]; i++) man_body(m->opts[i]);
    }
    if (m->exit_status) {
        man_section("EXIT STATUS");
        man_body(m->exit_status);
    }
    man_section("SEE ALSO");
    man_body(m->see_also);
    println("");
}

/* Case-insensitive substring search, for apropos. */
static int man_contains(const char *hay, const char *needle) {
    if (!needle[0]) return 0;
    for (int i = 0; hay[i]; i++) {
        int j = 0;
        while (hay[i + j] && needle[j]) {
            char a = hay[i + j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
            j++;
        }
        if (!needle[j]) return 1;
    }
    return 0;
}

static void man_whatis(const char *name) {
    const struct man_page *m = man_find(name);
    if (!m) { print(name); println(": nothing appropriate."); return; }
    print("  "); print_pad(m->name, 14);
    print("("); print(m->sect); print(")  ");
    println(m->summary);
}

static void man_apropos(const char *kw) {
    int hits = 0;
    for (int i = 0; i < MAN_COUNT; i++) {
        if (man_contains(man_pages[i].name, kw) ||
            man_contains(man_pages[i].summary, kw)) {
            if (!hits) println("");
            print("  "); print_pad(man_pages[i].name, 14);
            print("("); print(man_pages[i].sect); print(")  ");
            println(man_pages[i].summary);
            hits++;
        }
    }
    if (!hits) { print(kw); println(": nothing appropriate."); }
    else println("");
}

/* The whole index, as whatis lines -- what `man -k .` would give you. */
static void man_index(void) {
    println("");
    println("  Manual pages (man <command> for the full page)");
    help_rule();
    for (int i = 0; i < MAN_COUNT; i++) {
        print("  "); print_pad(man_pages[i].name, 14);
        print("("); print(man_pages[i].sect); print(")  ");
        println(man_pages[i].summary);
    }
    println("");
    println("  Section 1 = user command, 8 = requires uid 0.");
    println("  apropos <keyword> searches these summaries; help shows them grouped.");
    println("");
}

static void show_general_help_us(void) {
    help_rule();
    println("   Horus Shell  -  capability-based, privilege-separated command reference");
    help_rule();
    println("");
    println("  FILES & TEXT   (the encrypted fs_server, mounted at / )");
    print_cmd("pwd",               "print the current directory");
    print_cmd("cd [dir]",          "change directory (cd with no arg goes to /)");
    print_cmd("ls [-l]",           "list the directory entries (-l: long format)");
    print_cmd("cat <file>",        "print a file's contents");
    print_cmd("touch <file>",      "create an empty file");
    print_cmd("mkdir <dir>",       "create a directory");
    print_cmd("rm <name>",         "delete a file or an empty directory");
    print_cmd("cp <src> <dst>",    "copy a file within the current directory");
    print_cmd("mv <src> <dst>",    "rename a file within the current directory");
    print_cmd("stat <file>",       "show type, mode, owner and size");
    print_cmd("wc <file>",         "count lines, words and bytes");
    print_cmd("echo <text>",       "print text to the console");
    print_cmd("echo <text> > <f>", "write text to a file (creates it if needed)");
    print_cmd("run <file>",        "load a program image from the FS and run it");
    print_cmd("fss, fss_ls, ...",  "low-level fs_server demo client ('help fss')");
    println("");
    println("  IDENTITY & SECURITY");
    print_cmd("whoami, id",        "show your login uid / gid");
    print_cmd("passwd",            "change your password (secure prompt)");
    print_cmd("sudo",              "re-authenticate (secure prompt), spawn elevated");
    print_cmd("rotate_keys",       "re-encrypt storage under a fresh key    (root)");
    print_cmd("useradd <uid> <n>", "create a user account                   (root)");
    print_cmd("userdel <uid>",     "delete a user account                   (root)");
    println("");
    println("  PROCESSES");
    print_cmd("ps",                "list visible tasks (non-root sees only its own)");
    print_cmd("spawn <name>",      "spawn an embedded binary (hello/captest/fs_server)");
    print_cmd("spawn",             "spawn the last image armed via 'receive'");
    print_cmd("mem",               "allocate a page from the heap (sbrk demo)");
    print_cmd("yield",             "voluntarily hand the CPU to another task");
    println("");
    println("  IPC & NOTIFICATIONS");
    print_cmd("ipc_send <msg>",    "send a message on endpoint 4");
    print_cmd("ipc_recv",          "receive a message on endpoint 4");
    print_cmd("notify <badge>",    "post an async notification badge on slot 4");
    print_cmd("wait_notify",       "block until a notification badge arrives");
    println("");
    println("  LOADER (over serial)   and   SESSION");
    print_cmd("receive",           "receive a program image over serial, arm it");
    print_cmd("load",              "receive + spawn in one step");
    print_cmd("help [topic]",      "this list, or details for a command or group");
    print_cmd("man <command>",     "full reference page for one command");
    print_cmd("apropos <keyword>", "search the manual pages by keyword");
    print_cmd("whatis <command>",  "one-line summary of a command");
    print_cmd("exit, logout",      "end the session, return to the login prompt");
    println("");
    println("  Legend:  <arg> required   (root) needs uid 0   / is the FS root");
    println("  Groups:  help files | security | process | ipc | loader");
    println("  Detail:  help <command>       e.g.   help run");
    println("  Manual:  man <command>        e.g.   man ls        (man = index)");
    help_rule();
}

static void show_topic_help_us(const char *topic) {
    char tbuf[32];
    int i = 0;
    while (*topic == ' ') topic++;
    while (*topic && *topic != ' ' && i < 31) { tbuf[i++] = *topic++; }
    tbuf[i] = 0;
    const char *t = tbuf;

    /* No word, or 'help help' / 'help man' -> the full command list. */
    if (t[0] == 0 || strcmp(t, "help") == 0 || strcmp(t, "?") == 0) {
        show_general_help_us();
        return;
    }

    println("");
    print("  Help topic: "); println(t);
    help_rule();

    /* ---- category groups: 'help files', 'help security', ... ---------- */
    if (strcmp(t,"files")==0 || strcmp(t,"file")==0 || strcmp(t,"fs")==0 || strcmp(t,"text")==0) {
        println("  Files live in the encrypted fs_server, rooted at / (inode 0). Every op is");
        println("  checked against your kernel-attested uid; root (uid 0) is the only bypass.");
        println("");
        print_cmd("ls",            "list directory entries");
        print_cmd("cat <file>",    "print a file's contents");
        print_cmd("touch <file>",  "create an empty file");
        print_cmd("mkdir <dir>",   "create a directory");
        print_cmd("rm <name>",     "delete a file or empty directory");
        print_cmd("echo .. > <f>", "write text to a file");
        print_cmd("run <file>",    "load and execute a program image");
        println("");
        println("  Detail:  help <command>    e.g.  help cat");
        return;
    }
    if (strcmp(t,"security")==0 || strcmp(t,"sec")==0 || strcmp(t,"identity")==0 ||
        strcmp(t,"user")==0 || strcmp(t,"users")==0) {
        println("  Authority comes only from your login identity and the capabilities you");
        println("  hold - never from what a command claims. uid 0 (root) is the sole admin.");
        println("");
        print_cmd("whoami, id",     "show your uid / gid");
        print_cmd("passwd",         "change your password");
        print_cmd("sudo <pw>",      "re-authenticate, spawn an elevated image");
        print_cmd("rotate_keys",    "re-encrypt storage under a fresh key    (root)");
        print_cmd("useradd/userdel","manage user accounts                    (root)");
        println("");
        println("  Detail:  help <command>    e.g.  help sudo");
        return;
    }
    if (strcmp(t,"process")==0 || strcmp(t,"processes")==0 || strcmp(t,"proc")==0) {
        println("  Every task runs at ring 3 in its own address space with only the caps it");
        println("  was granted - there is no ambient authority to create or signal tasks.");
        println("");
        print_cmd("ps",            "list visible tasks");
        print_cmd("spawn <name>",  "spawn an embedded binary");
        print_cmd("run <file>",    "run a program image from the FS");
        print_cmd("mem",           "grow the heap by a page (sbrk demo)");
        print_cmd("yield",         "hand the CPU to another task");
        println("");
        println("  Detail:  help <command>    e.g.  help spawn");
        return;
    }
    if (strcmp(t,"ipc")==0 || strcmp(t,"notifications")==0 || strcmp(t,"notification")==0) {
        println("  Tasks talk over capability-gated endpoints (synchronous messages) and");
        println("  notification slots (async single-badge signals); both need a slot-3 cap.");
        println("");
        print_cmd("ipc_send <msg>", "send a message on endpoint 4");
        print_cmd("ipc_recv",       "receive a message on endpoint 4");
        print_cmd("notify <badge>", "post an async badge on slot 4");
        print_cmd("wait_notify",    "block for a badge on slot 4");
        println("");
        println("  Detail:  help ipc_send | help notify");
        return;
    }
    if (strcmp(t,"loader")==0 || strcmp(t,"serial")==0) {
        println("  Programs can be streamed in over the serial loader port, staged, and then");
        println("  spawned - the kernel validates every image (W^X, bounds) before it runs.");
        println("");
        print_cmd("receive",       "receive an image over serial, arm it");
        print_cmd("spawn",         "spawn the armed image");
        print_cmd("load",          "receive + spawn in one step");
        println("");
        println("  Detail:  help receive | help load | help spawn");
        return;
    }

    /* ---- individual commands ------------------------------------------ */
    if (strcmp(t,"ls")==0) {
        help_line("Purpose:", "List the entries in the filesystem root.");
        help_line("Usage:",   "ls | ls -l");
        help_line("Notes:",   "Directories print with a trailing '/'. '-l' adds the mode");
        help_line("",         "(drwxr-xr-x), owning uid and size per entry. Reads go through");
        help_line("",         "the fs_server (running by default; else: spawn fs_server).");
        help_line("See also:","cat, mkdir, rm, files");
    } else if (strcmp(t,"cat")==0) {
        help_line("Purpose:", "Print a file's contents to the console.");
        help_line("Usage:",   "cat <file>");
        help_line("Example:", "cat /motd");
        help_line("Notes:",   "Needs read permission on the file (checked against your uid).");
        help_line("See also:","ls, echo, run");
    } else if (strcmp(t,"touch")==0) {
        help_line("Purpose:", "Create a new, empty file that you own.");
        help_line("Usage:",   "touch <file>");
        help_line("Example:", "touch /notes.txt");
        help_line("Notes:",   "Fails if the name already exists.");
        help_line("See also:","echo, mkdir, rm");
    } else if (strcmp(t,"mkdir")==0) {
        help_line("Purpose:", "Create a new directory.");
        help_line("Usage:",   "mkdir <dir>");
        help_line("Example:", "mkdir /work");
        help_line("See also:","ls, rm, touch");
    } else if (strcmp(t,"rm")==0) {
        help_line("Purpose:", "Delete a file, or an empty directory.");
        help_line("Usage:",   "rm <name>");
        help_line("Notes:",   "Needs write permission on the parent directory; a non-empty");
        help_line("",         "directory is refused - remove its contents first.");
        help_line("See also:","ls, mkdir");
    } else if (strcmp(t,"echo")==0) {
        help_line("Purpose:", "Print text, or write it to a file with '>'.");
        help_line("Usage:",   "echo <text>            print to the console");
        help_line("",         "echo <text> > <file>   write to a file (creates it)");
        help_line("Example:", "echo hello > /greeting");
        help_line("Notes:",   "Redirection overwrites from offset 0; it does not append.");
        help_line("See also:","cat, touch");
    } else if (strcmp(t,"run")==0) {
        help_line("Purpose:", "Load a program image from the FS and run it (execve-from-fd).");
        help_line("Usage:",   "run <file>");
        help_line("Example:", "run /bin/hello");
        help_line("Notes:",   "The shell reads the image over the fs_server, then the kernel");
        help_line("",         "validates it with the same loader a named binary uses (W^X,");
        help_line("",         "bounds, fail-closed relocations) and waits for it to finish.");
        help_line("See also:","spawn, cat");
    } else if (strcmp(t,"ps")==0) {
        help_line("Purpose:", "List the tasks you are allowed to see.");
        help_line("Usage:",   "ps");
        help_line("Notes:",   "Columns: PID UID NAME STATE HEAP CAPS FLAGS. '*' marks your");
        help_line("",         "task; STATE is run/blkd; FLAGS: K=in kernel, B<n>=blocked on");
        help_line("",         "task n, N=waiting on a notification. Non-root sees only itself.");
        help_line("See also:","spawn, whoami");
    } else if (strcmp(t,"spawn")==0) {
        help_line("Purpose:", "Launch an embedded binary, or the last image you armed.");
        help_line("Usage:",   "spawn <name>    hello | captest | fs_server");
        help_line("",         "spawn           the image armed via 'receive'");
        help_line("Example:", "spawn fs_server");
        help_line("Notes:",   "The child gets a fresh address space and only the capabilities");
        help_line("",         "the shell delegates - never the shell's full authority.");
        help_line("See also:","run, receive, load, ps");
    } else if (strcmp(t,"mem")==0) {
        help_line("Purpose:", "Grow the heap by one page to demonstrate sbrk.");
        help_line("Usage:",   "mem");
        help_line("Notes:",   "The heap is demand-paged; malloc is built on the same sbrk.");
    } else if (strcmp(t,"yield")==0) {
        help_line("Purpose:", "Voluntarily give up the CPU to another runnable task.");
        help_line("Usage:",   "yield");
        help_line("Notes:",   "Scheduling is preemptive, so this is a courtesy hand-off, not");
        help_line("",         "something other tasks depend on to run.");
    } else if (strcmp(t,"whoami")==0 || strcmp(t,"id")==0) {
        help_line("Purpose:", "Show your kernel-attested login identity.");
        help_line("Usage:",   "whoami    |    id");
        help_line("Notes:",   "This uid is fixed at login and cannot be forged; the fs_server");
        help_line("",         "and every privileged op are checked against it.");
        help_line("See also:","passwd, sudo, ps");
    } else if (strcmp(t,"passwd")==0) {
        help_line("Purpose:", "Change your own account password.");
        help_line("Usage:",   "passwd");
        help_line("Notes:",   "The new password is read without echo, hashed with Argon2id,");
        help_line("",         "and persists across reboots.");
    } else if (strcmp(t,"sudo")==0) {
        help_line("Purpose:", "Re-authenticate and spawn a privileged (armed) image.");
        help_line("Usage:",   "sudo            (prompts for your password, masked)");
        help_line("Notes:",   "Takes no argument: a password on the command line would be");
        help_line("",         "echoed to the console and the serial log. Verifies your");
        help_line("",         "password (lockout/throttle on failure), then spawns the");
        help_line("",         "armed image as uid 0 — so arm one first, or it has nothing");
        help_line("",         "to elevate and will say so.");
        help_line("See also:","spawn, receive, rotate_keys");
    } else if (strcmp(t,"rotate_keys")==0) {
        help_line("Purpose:", "Re-encrypt the mounted volume's blocks under a fresh key.");
        help_line("Usage:",   "rotate_keys");
        help_line("Notes:",   "Root only; needs an unlocked volume (post-login). Reports the");
        help_line("",         "number of blocks re-encrypted.");
    } else if (strcmp(t,"useradd")==0 || strcmp(t,"userdel")==0) {
        help_line("Purpose:", "Create or delete a user account (admin).");
        help_line("Usage:",   "useradd <uid> <name>    |    userdel <uid>");
        help_line("Example:", "useradd 1001 bob");
        help_line("Notes:",   "Requires uid 0. New accounts persist across reboots.");
        help_line("See also:","passwd, whoami");
    } else if (strcmp(t,"ipc_send")==0 || strcmp(t,"ipc_recv")==0 || strcmp(t,"ipc")==0) {
        help_line("Purpose:", "Exchange a message over a capability endpoint.");
        help_line("Usage:",   "ipc_send <msg>     send on endpoint 4");
        help_line("",         "ipc_recv           receive on endpoint 4");
        help_line("Notes:",   "Endpoints are single-slot mailboxes; both directions need a");
        help_line("",         "slot-3 endpoint capability. See 'help ipc' for the group.");
        help_line("See also:","notify, wait_notify");
    } else if (strcmp(t,"notify")==0 || strcmp(t,"wait_notify")==0) {
        help_line("Purpose:", "Send or wait on an async notification badge.");
        help_line("Usage:",   "notify <badge>     post a badge on notification slot 4");
        help_line("",         "wait_notify        block until a badge arrives on slot 4");
        help_line("Example:", "notify 42");
        help_line("Notes:",   "Badges OR together until consumed; a waiter wakes with the");
        help_line("",         "accumulated value. Needs a slot-3 capability.");
        help_line("See also:","ipc_send, ipc_recv");
    } else if (strcmp(t,"receive")==0) {
        help_line("Purpose:", "Receive a program image over the serial loader and arm it.");
        help_line("Usage:",   "receive");
        help_line("Notes:",   "Follow with 'spawn' to run it, or use 'load' to do both.");
        help_line("See also:","load, spawn");
    } else if (strcmp(t,"load")==0) {
        help_line("Purpose:", "Receive an image over serial and immediately spawn it.");
        help_line("Usage:",   "load");
        help_line("Notes:",   "Equivalent to 'receive' followed by 'spawn'.");
        help_line("See also:","receive, spawn");
    } else if (strcmp(t,"fss")==0 || strncmp(t,"fss_",4)==0) {
        help_line("Purpose:", "Low-level demo client that talks to the fs_server directly.");
        help_line("Usage:",   "fss | fss_connect | fss_ls | fss_cat <name>");
        help_line("",         "fss_write <file> <text> | fss_tree");
        help_line("Notes:",   "The high-level commands (ls, cat, ...) are what you normally");
        help_line("",         "want; fss_* just exposes the raw protocol for demonstration.");
        help_line("See also:","ls, cat, files");
    } else if (strcmp(t,"exit")==0 || strcmp(t,"logout")==0) {
        help_line("Purpose:", "End your session and return to the login prompt.");
        help_line("Usage:",   "exit    |    logout");
        help_line("Notes:",   "Your capabilities are dropped; the next user must log in.");
    } else if (strncmp(t,"cap_",4)==0 || strcmp(t,"fsroot")==0) {
        help_line("Purpose:", "Removed. The legacy in-memory capfs (fsroot / cap_*) is gone.");
        help_line("Instead:", "use the fs_server commands: ls, cat, rm, mkdir, touch.");
        help_line("See also:","files");
    } else {
        println("  No help entry for that word.");
        println("");
        println("  Groups:  help files | security | process | ipc | loader");
        println("  All:     help");
    }
}

static void handle_command(char *cmd) {

    /* A real /bin/<name> shadows the shell's own builtin of the same
     * name when it is embedded in this build (e.g. the real `wc` over the shell's
     * lighter one). Checked first; when the binary is absent this is a no-op and
     * the builtins below run as before. */
    if (try_run_from_bin(cmd)) return;

    if (strcmp(cmd, "man") == 0) {
        man_index();
    } else if (strncmp(cmd, "man ", 4) == 0) {
        const char *t = cmd + 4; while (*t == ' ') t++;
        /* Prefer a page on disk (/usr/share/man/<t>, e.g. the ported coreutils and
         * hier(7)); fall back to the built-in table (shell builtins, and any system
         * with no /usr/share/man). */
        if (!try_man_from_fs(t)) {
            const struct man_page *m = man_find(t);
            if (m) man_render(m);
            else {
                print("No manual entry for "); print(t); println("");
                println("Try: apropos <keyword>   or   help   for the command index.");
            }
        }
    } else if (strncmp(cmd, "whatis ", 7) == 0) {
        const char *t = cmd + 7; while (*t == ' ') t++;
        man_whatis(t);
    } else if (strcmp(cmd, "whatis") == 0) {
        println("whatis: usage: whatis <command>");
    } else if (strncmp(cmd, "apropos ", 8) == 0) {
        const char *t = cmd + 8; while (*t == ' ') t++;
        man_apropos(t);
    } else if (strcmp(cmd, "apropos") == 0) {
        println("apropos: usage: apropos <keyword>");
    } else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        show_general_help_us();
    } else if (strncmp(cmd, "help ", 5) == 0 || strncmp(cmd, "man ", 4) == 0 ||
               (cmd[0] == '?' && (cmd[1] == ' ' || cmd[1] == 0))) {
        const char *topic = cmd;
        if (cmd[0] == 'h') topic += 5;
        else if (cmd[0] == 'm') topic += 4;
        else topic += 1;
        show_topic_help_us(topic);
    } else if (strcmp(cmd, "exit") == 0) {
        println("Exiting userspace shell...");
        sys_exit();
    } else if (strcmp(cmd, "yield") == 0) {
        println("Yielding...");
        sys_yield();
    } else if (strcmp(cmd, "mem") == 0) {
        println("Userspace heap demo (using sbrk)");
        void *p = sys_sbrk(4096);
        if (p) {
            println("Allocated 4KB from userspace heap");
        } else {
            println("sbrk failed");
        }
    } else if (strcmp(cmd, "ps") == 0) {
        /* Same column discipline as ls -l: fixed widths via the shared padding
         * helpers rather than hand-counted spaces, which is what let the old
         * header drift out of line with its rows. */
        print("  "); print_pad("PID", 6); print_pad("OWNER", 8); print_pad("NAME", 16);
        print_pad("STATE", 7); print_rpad("HEAP", 7); print_rpad("CAPS", 6);
        print("  "); println("FLAGS");

        int mypid = sys_getpid();
        int saw_any = 0;
        for (int i = 0; i < 16; i++) {
            struct task_info info;
            int r = sys_get_task_info(i, &info);
            if (r == 0 && info.state != 0) {
                saw_any = 1;

                /* The current task is marked so a listing read out of context
                 * still says which line is you. */
                char pid[10]; int pi = 0;
                { uint32_t v = info.id; char t[10]; int ti = 0;
                  if (!v) t[ti++] = '0';
                  while (v) { t[ti++] = (char)('0' + v % 10); v /= 10; }
                  while (ti) pid[pi++] = t[--ti]; }
                if ((int)info.id == mypid) pid[pi++] = '*';
                pid[pi] = '\0';

                char owner[12], heap[8];
                owner_name(info.uid, owner);
                human_size(info.heap_used, heap);

                /* All four live states are named. The old code knew only two
                 * and printed "?" for the rest, so a task blocked on a
                 * notification or in SYS_WAIT looked like a kernel bug rather
                 * than a task doing exactly what it was told to. */
                const char *sn = info.state == TASK_RUNNABLE      ? "run"
                               : info.state == TASK_BLOCKED_IPC   ? "ipc"
                               : info.state == TASK_BLOCKED_NOTIF ? "notify"
                               : info.state == TASK_BLOCKED_WAIT  ? "wait"
                               : "?";

                print("  ");
                print_pad(pid, 6);
                print_pad(owner, 8);
                print_pad(info.name, 16);
                print_pad(sn, 7);
                print_rpad(heap, 7);
                { char caps[10]; int ci = 0; uint32_t v = info.caps_in_use; char t[10]; int ti = 0;
                  if (!v) t[ti++] = '0';
                  while (v) { t[ti++] = (char)('0' + v % 10); v /= 10; }
                  while (ti) caps[ci++] = t[--ti];
                  caps[ci] = '\0';
                  print_rpad(caps, 6); }

                /* Flags spell out what they mean rather than using bare letters:
                 * the listing is read by people, and "wait:3" beats "B3". */
                print("  ");
                if (info.in_kernel) print("kernel ");
                if (info.blocked_on >= 0) { print("wait:"); print_decimal((uint32_t)info.blocked_on); }
                else if (info.blocked_on_notif >= 0) print("notify");
                println("");
            }
        }
        if (!saw_any) {
            println("(limited visibility - only own task shown for non-admin)");
        }
    } else if (strcmp(cmd, "pwd") == 0) {
        println(sh_cwd_path);
    } else if (strcmp(cmd, "cd") == 0 || strncmp(cmd, "cd ", 3) == 0) {
        const char *arg = (cmd[2] == '\0') ? "/" : cmd + 3;
        while (*arg == ' ') arg++;
        if (*arg == '\0') arg = "/";
        char norm[SH_PATH_MAX];
        if (sh_normalize(arg, norm) != 0) {
            println("cd: path too long");
        } else {
            uint32_t ino = sh_walk_abs_dir(norm);
            if (ino == (uint32_t)-1) {
                print("cd: not a directory: "); println(arg);
            } else {
                sh_cwd_ino = ino;
                fss_strcpy(sh_cwd_path, norm);
            }
        }
    } else if (strcmp(cmd, "ls") == 0 || strcmp(cmd, "ls -l") == 0) {
        int long_fmt = (cmd[2] != '\0');   /* "ls -l" carries a 3rd char */

        /* Entries are collected before anything is printed. Column widths are a
         * property of the whole listing -- the widest name decides the layout --
         * so a streaming printer cannot align them, which is why the old one
         * emitted a ragged entry per line. */
        #define LS_MAX 128
        static struct {
            char     name[FS_NAME_MAX];
            uint32_t type, mode, uid, size;
            int      stat_ok;
        } ent[LS_MAX];
        int n = 0, truncated = 0;

        struct fs_request  rq = {0};
        struct fs_response rp;
        for (uint32_t idx = 0; idx < 4096; idx++) {
            rq.op = FS_OP_READDIR; rq.dir_ino = sh_cwd_ino; rq.offset = idx;
            /* Distinguish the ways this loop can stop: a broken IPC path, a
             * directory you cannot read, and a genuine end-of-directory once read
             * to the same silence, so a failure was indistinguishable from an
             * empty directory. Each failure now reports itself (below); only
             * running off the end is a normal stop, after which an empty directory
             * prints nothing at all. */
            int rc = fss_call(&rq, &rp);
            if (rc < 0) {
                if (!fss_connected) println("ls: spawn fs_server first");
                else { print("ls: fs_server call failed ("); print(sys_strerror(rc)); println(")"); }
                break;
            }
            /* NOENT here means the server walked past the last entry, which is
             * how a readdir ends. The server also returns NOENT for a directory
             * that does not exist -- the two are not distinguishable over the
             * wire -- but sh_cwd_ino is a directory `cd` already verified exists,
             * so for this caller it can only be end-of-directory. */
            if (rp.rc == SYS_ERR_NOENT) break;
            if (rp.rc < 0) {
                print("ls: "); print(sys_strerror(rp.rc)); println("");
                break;
            }
            if (n >= LS_MAX) { truncated = 1; break; }

            fss_strcpy(ent[n].name, rp.name);
            ent[n].type    = rp.type;
            ent[n].mode    = 0;
            ent[n].uid     = 0;
            ent[n].size    = 0;
            ent[n].stat_ok = 0;

            /* Stat every entry, not just in -l: the plain listing marks
             * directories and executables, which needs the mode. A denied stat
             * is recorded, not fatal -- you may list a directory whose entries
             * you cannot stat. */
            struct fs_request  sq = {0};
            struct fs_response sp;
            sq.op = FS_OP_STAT; sq.ino = rp.ino;
            if (fss_call(&sq, &sp) == 0 && sp.rc == 0) {
                ent[n].mode    = sp.mode;
                ent[n].uid     = sp.uid;
                ent[n].size    = sp.size;
                ent[n].stat_ok = 1;
            }
            n++;
        }

        /* Alphabetical, so a listing is reproducible and scannable rather than
         * ordered by whatever the directory happens to hold. Insertion sort:
         * bounded at LS_MAX and this is not a hot path. */
        for (int i = 1; i < n; i++) {
            for (int j = i; j > 0; j--) {
                const char *a = ent[j - 1].name, *b = ent[j].name;
                int k = 0;
                while (a[k] && a[k] == b[k]) k++;
                if ((unsigned char)a[k] <= (unsigned char)b[k]) break;
                for (unsigned t = 0; t < sizeof(ent[0]); t++) {
                    char *pa = (char *)&ent[j - 1], *pb = (char *)&ent[j];
                    char tmp = pa[t]; pa[t] = pb[t]; pb[t] = tmp;
                }
            }
        }

        if (n == 0) {
            /* An empty directory prints nothing, like ls(1) — the root now holds
             * the provisioned skeleton (/bin /etc /home /lib /usr), so a bare `ls`
             * shows a real filesystem. A read *failure* still surfaces below (it is
             * distinct from an empty directory), so a broken fs_server is not
             * silently mistaken for emptiness. */
        } else if (long_fmt) {
            /* Size column is sized to its widest value so the numbers line up. */
            int wsize = 4;   /* at least as wide as the "Size" heading */
            for (int i = 0; i < n; i++) {
                char hb[8]; human_size(ent[i].size, hb);
                int l = 0; while (hb[l]) l++;
                if (l > wsize) wsize = l;
            }

            print("  "); print_pad("Mode", 12); print_pad("Owner", 8);
            print_rpad("Size", wsize); print("  "); println("Name");

            for (int i = 0; i < n; i++) {
                int is_dir = (ent[i].type == FS_TYPE_DIR);
                char perms[11], owner[12], hb[8];

                if (ent[i].stat_ok) {
                    fmt_perms(is_dir, ent[i].mode, perms);
                    owner_name(ent[i].uid, owner);
                    human_size(ent[i].size, hb);
                } else {
                    /* Unreadable metadata is shown as unknown rather than as
                     * zeroes, which would read as a real (empty, root-owned)
                     * file. */
                    for (int k = 0; k < 10; k++) perms[k] = '?';
                    perms[10] = '\0';
                    owner[0] = '?'; owner[1] = '\0';
                    hb[0] = '-'; hb[1] = '\0';
                }

                print("  ");
                print_pad(perms, 12);
                print_pad(owner, 8);
                if (is_dir) { hb[0] = '-'; hb[1] = '\0'; }   /* a directory has no useful size here */
                print_rpad(hb, wsize);
                print("  ");
                print(ent[i].name);
                /* Trailing marker instead of colour: '/' directory, '*' executable. */
                if (is_dir) println("/");
                else if (ent[i].stat_ok && (ent[i].mode & 0111u)) println("*");
                else println("");
            }
        } else {
            /* Plain listing: pack names into as many columns as fit the console,
             * row-major, each padded to the widest name plus its type marker. */
            int w = 1;
            for (int i = 0; i < n; i++) {
                int l = 0; while (ent[i].name[l]) l++;
                l++;                                  /* room for the / or * marker */
                if (l > w) w = l;
            }
            int colw = w + 2;
            int cols = (TERM_COLS - 2) / colw;
            if (cols < 1) cols = 1;

            for (int i = 0; i < n; i++) {
                if (i % cols == 0) print("  ");
                char cell[FS_NAME_MAX + 2];
                int l = 0;
                while (ent[i].name[l] && l < FS_NAME_MAX) { cell[l] = ent[i].name[l]; l++; }
                if (ent[i].type == FS_TYPE_DIR) cell[l++] = '/';
                else if (ent[i].stat_ok && (ent[i].mode & 0111u)) cell[l++] = '*';
                cell[l] = '\0';

                int last_in_row = ((i % cols) == cols - 1) || (i == n - 1);
                if (last_in_row) println(cell);
                else print_pad(cell, colw);
            }
        }

        if (truncated) {
            print("  ... listing truncated at "); print_decimal(LS_MAX); println(" entries");
        }
    } else if (strncmp(cmd, "cat ", 4) == 0) {
        const char *name = cmd + 4;
        struct fs_request  rq = {0};
        struct fs_response rp;
        rq.op = FS_OP_LOOKUP; rq.dir_ino = sh_cwd_ino;
        fss_strcpy(rq.name, name);
        if (fss_call(&rq, &rp) < 0 || rp.rc < 0) {
            println("cat: file not found");
        } else {
            rq.op = FS_OP_READ; rq.ino = rp.ino;
            rq.offset = 0; rq.len = FS_IO_MAX;
            if (fss_call(&rq, &rp) < 0 || rp.rc < 0) {
                println("cat: read failed");
            } else {
                int l = rp.rc < FS_IO_MAX ? rp.rc : FS_IO_MAX - 1;
                rp.data[l] = 0;
                print((char *)rp.data);
                if (l == 0 || rp.data[l-1] != '\n') print("\n");
            }
        }
    } else if (strncmp(cmd, "mkdir ", 6) == 0) {
        const char *name = cmd + 6;
        struct fs_request  rq = {0};
        struct fs_response rp;
        rq.op = FS_OP_MKDIR; rq.dir_ino = sh_cwd_ino;
        fss_strcpy(rq.name, name);
        if (fss_call(&rq, &rp) < 0 || rp.rc < 0)
            println("mkdir: failed (name exists or server not running)");
        else { print("mkdir: created "); println(name); }
    } else if (strncmp(cmd, "rm ", 3) == 0) {
        const char *name = cmd + 3;
        struct fs_request  rq = {0};
        struct fs_response rp;
        rq.op = FS_OP_DELETE; rq.dir_ino = sh_cwd_ino;
        fss_strcpy(rq.name, name);
        if (fss_call(&rq, &rp) < 0 || rp.rc < 0)
            println("rm: failed (not found or server not running)");
        else { print("rm: removed "); println(name); }
    } else if (strncmp(cmd, "touch ", 6) == 0) {
        const char *name = cmd + 6;
        struct fs_request  rq = {0};
        struct fs_response rp;
        rq.op = FS_OP_CREATE; rq.dir_ino = sh_cwd_ino;
        fss_strcpy(rq.name, name);
        if (fss_call(&rq, &rp) < 0 || rp.rc < 0)
            println("touch: failed (already exists or server not running)");
        else { print("touch: created "); println(name); }
    } else if (strncmp(cmd, "stat ", 5) == 0) {
        const char *name = cmd + 5; while (*name == ' ') name++;
        uint32_t type, ino = sh_lookup(name, &type);
        if (ino == (uint32_t)-1) { println("stat: not found"); }
        else {
            struct fs_request  sq = {0};
            struct fs_response sp;
            sq.op = FS_OP_STAT; sq.ino = ino;
            if (fss_call(&sq, &sp) < 0 || sp.rc < 0) println("stat: failed");
            else {
                /* Labels padded to a common width so the values form a
                 * column, and the mode shown both symbolically and in octal --
                 * the two spellings answer different questions and printing one
                 * always means mentally converting it. */
                char perms[11], owner[12], hb[8];
                fmt_perms(type == FS_TYPE_DIR, sp.mode, perms);
                owner_name(sp.uid, owner);
                human_size(sp.size, hb);

                print("  "); print_pad("File:", 8); println(name);
                print("  "); print_pad("Type:", 8);
                println(type == FS_TYPE_DIR ? "directory" : "regular file");
                print("  "); print_pad("Mode:", 8); print(perms);
                print("  (0"); print_octal(sp.mode & 07777u); println(")");
                print("  "); print_pad("Owner:", 8); print(owner);
                print("  uid="); print_decimal(sp.uid);
                print(" gid="); print_decimal(sp.gid); println("");
                print("  "); print_pad("Size:", 8); print(hb);
                /* The exact count only adds something once the human form has
                 * rounded; below 1000 bytes they are the same number. */
                if (sp.size >= 1000) { print("  ("); print_decimal(sp.size); print(" bytes)"); }
                else if (sp.size != 1) print(" bytes");
                else print(" byte");
                println("");
                print("  "); print_pad("Links:", 8); print_decimal(sp.links ? sp.links : 1);
                println("");
                print("  "); print_pad("Inode:", 8); print_decimal(ino); println("");
            }
        }
    } else if (strncmp(cmd, "wc ", 3) == 0) {
        const char *name = cmd + 3; while (*name == ' ') name++;
        uint32_t type, ino = sh_lookup(name, &type);
        if (ino == (uint32_t)-1 || type != FS_TYPE_FILE) { println("wc: not a file"); }
        else {
            uint32_t off = 0, lines = 0, words = 0, bytes = 0;
            int inword = 0, ok = 1;
            for (;;) {
                struct fs_request  rq = {0};
                struct fs_response rp;
                rq.op = FS_OP_READ; rq.ino = ino; rq.offset = off; rq.len = FS_IO_MAX;
                if (fss_call(&rq, &rp) < 0 || rp.rc < 0) { ok = 0; break; }
                uint32_t got = (uint32_t)rp.rc;
                if (got > FS_IO_MAX) got = FS_IO_MAX;
                if (got == 0) break;
                for (uint32_t i = 0; i < got; i++) {
                    char c = (char)rp.data[i];
                    bytes++;
                    if (c == '\n') lines++;
                    if (c == ' ' || c == '\t' || c == '\n') inword = 0;
                    else if (!inword) { words++; inword = 1; }
                }
                off += got;
            }
            if (!ok) println("wc: read failed");
            else {
                print("  "); print_decimal(lines);
                print("  "); print_decimal(words);
                print("  "); print_decimal(bytes);
                print("  "); println(name);
            }
        }
    } else if (strncmp(cmd, "cp ", 3) == 0) {
        char src[FS_NAME_MAX], dst[FS_NAME_MAX];
        if (split2(cmd + 3, src, sizeof src, dst, sizeof dst) != 2) {
            println("cp: usage: cp <src> <dst>");
        } else {
            uint32_t stype, sino = sh_lookup(src, &stype);
            if (sino == (uint32_t)-1 || stype != FS_TYPE_FILE) { println("cp: source not a file"); }
            else {
                struct fs_request  cq = {0};
                struct fs_response cprp;
                cq.op = FS_OP_CREATE; cq.dir_ino = sh_cwd_ino; fss_strcpy(cq.name, dst);
                if (fss_call(&cq, &cprp) < 0 || cprp.rc < 0) { println("cp: cannot create dest (exists?)"); }
                else {
                    uint32_t dino = cprp.ino, off = 0;
                    int ok = 1;
                    for (;;) {
                        struct fs_request  rq = {0};
                        struct fs_response rp;
                        rq.op = FS_OP_READ; rq.ino = sino; rq.offset = off; rq.len = FS_IO_MAX;
                        if (fss_call(&rq, &rp) < 0 || rp.rc < 0) { ok = 0; break; }
                        uint32_t got = (uint32_t)rp.rc;
                        if (got > FS_IO_MAX) got = FS_IO_MAX;
                        if (got == 0) break;
                        struct fs_request  wq = {0};
                        struct fs_response wp;
                        wq.op = FS_OP_WRITE; wq.ino = dino; wq.offset = off; wq.len = got;
                        memcpy(wq.data, rp.data, got);
                        if (fss_call(&wq, &wp) < 0 || wp.rc < 0) { ok = 0; break; }
                        /* WRITE writes at most one block per call, so it may store
                         * fewer bytes than offered; advance by what it took and
                         * re-read the tail on the next pass. */
                        off += (uint32_t)wp.rc;
                    }
                    if (ok) { print("cp: copied to "); println(dst); }
                    else    { println("cp: copy failed"); }
                }
            }
        }
    } else if (strncmp(cmd, "mv ", 3) == 0) {
        char src[FS_NAME_MAX], dst[FS_NAME_MAX];
        if (split2(cmd + 3, src, sizeof src, dst, sizeof dst) != 2) {
            println("mv: usage: mv <src> <dst>");
        } else {
            struct fs_request  rq = {0};
            struct fs_response rp;
            rq.op = FS_OP_RENAME;
            rq.dir_ino = sh_cwd_ino;   /* old parent */
            rq.ino     = sh_cwd_ino;   /* new parent (same directory) */
            fss_strcpy(rq.name, src);
            fss_strcpy((char *)rq.data, dst);
            if (fss_call(&rq, &rp) < 0 || rp.rc < 0) println("mv: failed");
            else { print("mv: "); print(src); print(" -> "); println(dst); }
        }
    } else if (cmd[0] == 'e' && cmd[1] == 'c' && cmd[2] == 'h' && cmd[3] == 'o' && cmd[4] == ' ') {
        const char* rest = cmd + 5;
        const char* redirect = strstr(rest, " > ");
        if (redirect) {
            char text[FS_IO_MAX];
            char fname[FS_NAME_MAX];
            size_t tlen = (size_t)(redirect - rest);
            if (tlen >= sizeof(text)) tlen = sizeof(text)-1;
            memcpy(text, rest, tlen);
            text[tlen] = 0;
            const char* fstart = redirect + 3;
            size_t flen = strlen(fstart);
            if (flen >= sizeof(fname)) flen = sizeof(fname)-1;
            memcpy(fname, fstart, flen);
            fname[flen] = 0;

            struct fs_request  rq = {0};
            struct fs_response rp;
            rq.op = FS_OP_LOOKUP; rq.dir_ino = sh_cwd_ino;
            fss_strcpy(rq.name, fname);
            if (fss_call(&rq, &rp) < 0 || rp.rc < 0) {
                /* file doesn't exist yet — create it */
                rq.op = FS_OP_CREATE; rq.dir_ino = sh_cwd_ino;
                fss_strcpy(rq.name, fname);
                if (fss_call(&rq, &rp) < 0 || rp.rc < 0) {
                    println("echo: cannot create file"); goto echo_done;
                }
            }
            { /* write the text */
                uint32_t wlen = (uint32_t)tlen;
                if (wlen > FS_IO_MAX) wlen = FS_IO_MAX;
                rq.op = FS_OP_WRITE; rq.ino = rp.ino;
                rq.offset = 0; rq.len = wlen;
                memcpy(rq.data, text, wlen);
                if (fss_call(&rq, &rp) < 0 || rp.rc < 0)
                    println("echo: write failed");
            }
            echo_done:;
        } else {
            println(rest);
        }
    } else if (cmd[0] == 0) {
    } else if (strncmp(cmd, "ipc_send ", 9) == 0) {
        const char *p = cmd + 9;
        while (*p == ' ') p++;
        sys_ipc_send(4, p, strlen(p)+1);
        println("sent (or blocked on endpoint 4)");
    } else if (strcmp(cmd, "ipc_recv") == 0 || strncmp(cmd, "ipc_recv ", 9) == 0) {
        char buf[64];
        int n = sys_ipc_recv(4, buf, sizeof(buf)-1);
        if (n > 0) { buf[n]=0; print("recv: "); println(buf); }
        else println("no message (or blocked)");
    } else if (strncmp(cmd, "notify ", 7) == 0) {
        const char *p = cmd + 7;
        while (*p == ' ') p++;
        uint32_t badge = 0;
        while (*p >= '0' && *p <= '9') { badge = badge*10 + (*p-'0'); p++; }
        sys_notify(4, badge);
        println("notified");
    } else if (strcmp(cmd, "wait_notify") == 0 || strncmp(cmd, "wait_notify ", 12) == 0) {
        uint32_t badge = 0;
        sys_wait_notify(4, &badge);
        print("wait_notify badge="); print_decimal(badge); println("");
    } else if (strcmp(cmd, "whoami") == 0) {
        uint32_t uid = sys_getuid();
        print("uid=");
        print_decimal(uid);
        if (uid == 0) println(" (root)");
        else println("");
    } else if (strcmp(cmd, "id") == 0) {
        uint32_t uid = sys_getuid();
        print("uid="); print_decimal(uid);
        print(" gid=100");
        println("");
    } else if (strcmp(cmd, "sudo") == 0 || strncmp(cmd, "sudo ", 5) == 0) {
        /* The password is PROMPTED for, never taken from the command line.
         * `sudo <password>` used to be the interface, which put the password on
         * a line the terminal echoes to VGA *and mirrors to the serial log* —
         * so the one credential that grants uid 0 was written, in cleartext, to
         * the log of every session that used it. login and passwd have always
         * read passwords through sys_get_pass (masked echo); sudo was the odd
         * one out. Anything after "sudo" is now refused rather than silently
         * accepted, so a habitual `sudo hunter2` fails loudly instead of
         * leaking and working. */
        if (cmd[4] != 0) {
            println("sudo: takes no argument — it prompts for your password");
            println("      (passing it on the command line would echo it to the log)");
        } else {
            char sudopass[32];
            print("Password: ");
            int plen = sh_get_pass(sudopass, sizeof(sudopass) - 1);
            if (plen < 0) {
                println("sudo: input error");
            } else {
                sudopass[plen] = 0;
                int r = sys_sudo(sudopass);
                scrub(sudopass, sizeof(sudopass));
                if (r > 0) {
                    print("sudo: elevated spawn successful (pid ");
                    print_decimal(r);
                    println(")");
                } else if (r == SYS_ERR_AUTH) {
                    println("sudo: incorrect password or locked out");
                } else if (r == SYS_ERR_NOENT) {
                    println("sudo: authenticated, but no image is armed to elevate");
                    println("      arm one first (see 'help receive' / 'help spawn')");
                } else {
                    print("sudo: failed (");
                    print(sys_strerror(r));
                    println(")");
                }
            }
        }
    } else if (strncmp(cmd, "useradd ", 8) == 0) {
        const char *p = cmd + 8;
        uint32_t newuid = 0;
        char newname[32];
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { newuid = newuid*10 + (*p-'0'); p++; }
        while (*p == ' ') p++;
        int ni = 0;
        while (*p && *p != ' ' && ni < 31) { newname[ni++] = *p++; }
        newname[ni] = 0;

        int r = sys_useradd(newuid, 100, newname);
        if (r == 0) println("user added");
        else println("useradd failed");
    } else if (strncmp(cmd, "userdel ", 8) == 0) {
        const char *p = cmd + 8;
        uint32_t deluid = 0;
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { deluid = deluid*10 + (*p-'0'); p++; }
        int r = sys_userdel(deluid);
        println(r == 0 ? "user deleted" : "userdel failed");
    } else if (strcmp(cmd, "passwd") == 0 || strncmp(cmd, "passwd ", 7) == 0) {
        println("New password: ");
        char newp[32];
        int plen = sh_get_pass(newp, 31);
        if (plen > 0) {
            newp[plen] = 0;
            /* Change the CURRENT user's password, not uid 0.  The old code
             * always passed target=0, so non-root users got "passwd failed"
             * (kernel rejects uid!=self unless admin) and root accidentally
             * had an "admin only" passwd command. */
            uint32_t target = sys_getuid();
            int r = sys_passwd(target, newp);
            for (int i=0; i<32; i++) newp[i]=0;
            println(r == 0 ? "password changed" : "passwd failed");
        } else {
            println("passwd aborted");
        }
    } else if (strcmp(cmd, "rotate_keys") == 0) {
        int r = sys_rotate_keys();
        if (r >= 0) { print("rotate_keys: re-encrypted "); print_decimal((uint32_t)r); println(" blocks"); }
        else { println("rotate_keys: failed (no master key or no mounted FS)"); }
    } else if (strcmp(cmd, "fsroot") == 0 || strncmp(cmd, "fsroot ", 7) == 0 ||
               strncmp(cmd, "cap_", 4) == 0) {
        /* The legacy in-memory capfs (fsroot / cap_ls / cap_cat / cap_write /
         * cap_mint / cap_revoke / cap_create / cap_delete) was removed; the
         * encrypted fs_server is the filesystem now. */
        println("removed: use the fs_server commands (ls, cat, rm, mkdir, touch)");
    } else if (strcmp(cmd, "receive") == 0) {
        struct program_header h;
        int r = sys_receive_program(&h);
        if (r == 0) {
            print("Received '");
            print(h.name);
            print("' (");
            print_decimal(h.size);
            println(" bytes) - armed for spawn");
        } else if (r == -1) {
            println("Bad magic");
        } else if (r == -2) {
            println("Invalid size");
        } else {
            println("Receive error");
        }
    } else if (strcmp(cmd, "spawn") == 0 || strncmp(cmd, "spawn ", 6) == 0) {
        int pid;
        if (cmd[5] == ' ') {
            const char *name = cmd + 6;
            while (*name == ' ') name++;
            pid = sys_spawn_named(name);
            if (pid == SYS_ERR_NOENT) {
                print("spawn: unknown binary '");
                print(name);
                println("' (try: hello, captest, fs_server)");
                pid = 0;
            }
        } else {
            pid = sys_spawn();
        }
        if (pid > 0) {
            print("Spawned new task pid=");
            print_decimal(pid);
            println("");
        } else if (pid < 0) {
            println("Spawn failed (no armed image or no free task slot)");
        }
    } else if (strcmp(cmd, "load") == 0) {
        struct program_header h;
        int r = sys_receive_program(&h);
        if (r != 0) {
            println("Receive failed");
            return;
        }
        int pid = sys_spawn();
        if (pid > 0) {
            print("Loaded '");
            print(h.name);
            print("' as pid ");
            print_decimal(pid);
            println("");
        } else {
            println("Spawn failed after receive");
        }
    } else if (strncmp(cmd, "run ", 4) == 0) {
        /* execve-from-fd: read a program image from a file in the encrypted FS
         * (over the fs_server, exactly like `cat`), then hand the bytes to
         * SYS_SPAWN_IMAGE and wait for the child. The kernel validates the image
         * with the same loader a named binary uses, so no new trust is placed in
         * the file's contents. */
        const char *name = cmd + 4;
        while (*name == ' ') name++;
        struct fs_request  rq = {0};
        struct fs_response rp;

        /* Resolve the file's parent directory and final component. A name with a
         * '/' is a path: the parent is everything up to the last '/', walked from
         * the root for an absolute path (so `run /bin/hello` works), and the
         * component is the tail. A bare name resolves in the cwd. */
        const char *slash = 0;
        for (const char *q = name; *q; q++) if (*q == '/') slash = q;
        uint32_t dir_ino = sh_cwd_ino;
        const char *leaf = name;
        if (slash) {
            char parent[FS_NAME_MAX * 4];
            int  n = 0;
            if (slash == name) { parent[n++] = '/'; }          /* "/hello" -> parent "/" */
            else for (const char *q = name; q < slash && n < (int)sizeof(parent) - 1; q++) parent[n++] = *q;
            parent[n] = '\0';
            dir_ino = sh_walk_abs_dir(parent);
            if (dir_ino == (uint32_t)-1) { println("run: directory not found"); return; }
            leaf = slash + 1;
        }
        rq.op = FS_OP_LOOKUP; rq.dir_ino = dir_ino;
        fss_strcpy(rq.name, leaf);
        if (fss_call(&rq, &rp) < 0 || rp.rc < 0 || rp.type != FS_TYPE_FILE) {
            println("run: file not found (is fs_server running? try: spawn fs_server)");
            return;
        }
        uint32_t ino = rp.ino;

        struct fs_request sq = {0};
        sq.op = FS_OP_STAT; sq.ino = ino;
        if (fss_call(&sq, &rp) < 0 || rp.rc < 0) { println("run: stat failed"); return; }
        uint32_t size = rp.size;
        if (size == 0 || size > SH_MAX_IMAGE) { println("run: bad image size"); return; }

        unsigned char *buf = malloc(size);
        if (!buf) { println("run: out of memory"); return; }
        if (sh_read_file(ino, buf, size) != 0) { println("run: read failed"); free(buf); return; }

        int pid = sys_spawn_image(buf, size, 0, 0);
        free(buf);                                 /* kernel already staged the image */
        if (pid <= 0) { println("run: exec failed (not a valid program image?)"); return; }
        print("run: pid="); print_decimal(pid); println("");
        sys_wait(pid);
        println("run: done");
    } else if (strncmp(cmd, "fss", 3) == 0) {
        if (strcmp(cmd, "fss_connect") == 0 || strcmp(cmd, "fss") == 0) {
            if (fss_connect() == 0) {
                println("Connected to userspace FS server");
            } else {
                println("Failed to connect to FS server (is it running? try: spawn fs_server)");
            }
        } else if (strcmp(cmd, "fss_ls") == 0) {
            struct fs_request  req = {0};
            struct fs_response rep;
            req.op      = FS_OP_READDIR;
            req.dir_ino = 0;
            print("Userspace FS contents:\n");
            int found = 0;
            for (int idx = 0; idx < 256; idx++) {
                req.offset = (uint32_t)idx;
                if (fss_call(&req, &rep) < 0 || rep.rc < 0) break;
                print("  "); print(rep.name);
                print(rep.type == 2 ? "/\n" : "\n");
                found = 1;
            }
            if (!found) println("  (empty or server not connected)");
        } else if (strncmp(cmd, "fss_cat ", 8) == 0) {
            const char *name = cmd + 8;
            struct fs_request  req = {0};
            struct fs_response rep;
            req.op      = FS_OP_LOOKUP;
            req.dir_ino = 0;
            fss_strcpy(req.name, name);
            if (fss_call(&req, &rep) == 0 && rep.rc == 0) {
                uint32_t ino = rep.ino;
                req.op     = FS_OP_READ;
                req.ino    = ino;
                req.offset = 0;
                req.len    = FS_IO_MAX;
                if (fss_call(&req, &rep) == 0 && rep.rc > 0) {
                    int l = rep.rc < FS_IO_MAX ? rep.rc : FS_IO_MAX - 1;
                    rep.data[l] = 0;
                    print((char *)rep.data);
                    println("");
                } else {
                    println("read failed");
                }
            } else {
                println("file not found in userspace FS");
            }
        } else if (strncmp(cmd, "fss_write ", 10) == 0) {
            char *space = (char*)strstr(cmd + 10, " ");
            if (space) {
                *space = 0;
                const char *fname   = cmd + 10;
                const char *content = space + 1;
                struct fs_request  req = {0};
                struct fs_response rep;
                req.op      = FS_OP_LOOKUP;
                req.dir_ino = 0;
                fss_strcpy(req.name, fname);
                if (fss_call(&req, &rep) == 0 && rep.rc == 0) {
                    req.op     = FS_OP_WRITE;
                    req.ino    = rep.ino;
                    req.offset = 0;
                    int wlen = fss_strlen(content);
                    if (wlen > FS_IO_MAX) wlen = FS_IO_MAX;
                    req.len = (uint32_t)wlen;
                    fss_strcpy((char *)req.data, content);
                    fss_call(&req, &rep);
                    print("wrote ");
                    print_decimal(rep.rc > 0 ? rep.rc : 0);
                    println(" bytes to userspace FS");
                } else {
                    println("file not found (create it first with fss_create)");
                }
            } else {
                println("usage: fss_write <file> <text>");
            }
        } else if (strncmp(cmd, "fss_create ", 11) == 0) {
            const char *name = cmd + 11;
            struct fs_request  req = {0};
            struct fs_response rep;
            req.op      = FS_OP_CREATE;
            req.dir_ino = 0;
            fss_strcpy(req.name, name);
            if (fss_call(&req, &rep) == 0 && rep.rc == 0) {
                print("created: "); println(name);
            } else {
                println("create failed");
            }
        } else {
            println("fss commands: fss fss_connect fss_ls fss_cat <name> fss_write <file> <txt> fss_create <name>");
        }
    } else {
        println("Unknown command. Type 'help' or 'help <cmd>' for usage.");
    }
}

static uint32_t current_login_uid = 0;
static char current_login_name[32] = "root";

static void do_login(void) {
    char username[32];
    char password[128];
    int attempts = 0;
    const int max_attempts = 5;

    while (1) {
        print("\nhorus login: ");
        int ulen = sh_get_line(username, sizeof(username) - 1);
        if (ulen <= 0) continue;
        username[ulen] = 0;

        print("Password: ");
        int plen = sh_get_pass(password, sizeof(password) - 1);
        if (plen < 0) {
            println("Input error, try again.");
            continue;
        }
        password[plen] = 0;

        uint32_t got_uid = 0;
        int auth_ok = sys_auth(username, password, &got_uid);

        scrub(password, sizeof(password));   /* not a plain loop: -O2 elides dead stores */

        if (auth_ok == 0) {
            current_login_uid = got_uid;
            int j;
            for (j = 0; j < 31 && username[j]; j++) current_login_name[j] = username[j];
            current_login_name[j] = 0;

            print("\nWelcome, ");
            print(current_login_name);
            print("! You are ");
            println(got_uid == 0 ? "the administrator (root)." : "a standard user.");
            println("Type 'help' for available commands, 'logout' to end the session.");
            attempts = 0;
            return;
        }

        attempts++;
        print("Login incorrect (");
        print_decimal(max_attempts - attempts);
        println(" attempt(s) left).");

        if (attempts >= max_attempts) {
            println("Too many failed attempts. Please wait a moment...");
            for (volatile int d = 0; d < 20000000; d++) { }
            attempts = 0;
        }
    }
}

void _start(void) {
    println("");
    println("  +--------------------------------------------+");
    println("  |        Horus Secure Microkernel            |");
    println("  |  capability-based - privilege-separated    |");
    println("  +--------------------------------------------+");

    do_login();

    char cmd[128];

    while (1) {
        uint32_t uid = sys_getuid();
        print(current_login_name);
        print("@horus");
        if (uid == 0) print("# ");
        else print("$ ");
        int len = sh_get_line(cmd, sizeof(cmd));
        if (len < 0) {
            println("Input error");
            continue;
        }

        if (strcmp(cmd, "logout") == 0 || strcmp(cmd, "exit") == 0) {
            println("Logging out...");
            current_login_uid = 0;
            for (int i = 0; i < 32; i++) current_login_name[i] = 0;
            do_login();
            continue;
        }

        handle_command(cmd);
    }
}
