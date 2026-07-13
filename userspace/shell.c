#include "syscall.h"
#include "fs_proto.h"
#include "malloc.h"

static void print(const char *s) {
    size_t l = 0; while (s[l]) l++;
    sys_write(1, s, l);
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

static void show_general_help_us(void) {
    help_rule();
    println("   Horus Shell  -  capability-based, privilege-separated command reference");
    help_rule();
    println("");
    println("  FILES & TEXT   (the encrypted fs_server, mounted at / )");
    print_cmd("ls",                "list the directory entries");
    print_cmd("cat <file>",        "print a file's contents");
    print_cmd("touch <file>",      "create an empty file");
    print_cmd("mkdir <dir>",       "create a directory");
    print_cmd("rm <name>",         "delete a file or an empty directory");
    print_cmd("echo <text>",       "print text to the console");
    print_cmd("echo <text> > <f>", "write text to a file (creates it if needed)");
    print_cmd("run <file>",        "load a program image from the FS and run it");
    print_cmd("fss, fss_ls, ...",  "low-level fs_server demo client ('help fss')");
    println("");
    println("  IDENTITY & SECURITY");
    print_cmd("whoami, id",        "show your login uid / gid");
    print_cmd("passwd",            "change your password (secure prompt)");
    print_cmd("sudo <password>",   "re-authenticate and spawn an elevated image");
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
    print_cmd("exit, logout",      "end the session, return to the login prompt");
    println("");
    println("  Legend:  <arg> required   (root) needs uid 0   / is the FS root");
    println("  Groups:  help files | security | process | ipc | loader");
    println("  Detail:  help <command>       e.g.   help run");
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
    if (t[0] == 0 || strcmp(t, "help") == 0 || strcmp(t, "man") == 0 || strcmp(t, "?") == 0) {
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
        help_line("Usage:",   "ls");
        help_line("Notes:",   "Directories print with a trailing '/'. Reads go through the");
        help_line("",         "fs_server (running by default; else: spawn fs_server).");
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
        help_line("Usage:",   "sudo <password>");
        help_line("Notes:",   "Verifies your password (with lockout/throttle on failure);");
        help_line("",         "success also depends on an image having been armed first.");
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
    
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "man") == 0 || strcmp(cmd, "?") == 0) {
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
        println("PID  UID    NAME            STATE  HEAP      CAPS  FLAGS");
        int mypid = sys_getpid();
        int saw_any = 0;
        for (int i = 0; i < 16; i++) {
            struct task_info info;
            int r = sys_get_task_info(i, &info);
            if (r == 0 && info.state != 0) {
                saw_any = 1;
                if (info.id < 10) print(" ");
                print_decimal(info.id);
                if ((int)info.id == mypid) print("* "); else print("  ");
                /* UID column (root for 0), padded to 7 cols. */
                if (info.uid == 0) { print("root   "); }
                else {
                    print_decimal(info.uid);
                    int ulen = info.uid < 10 ? 1 : (info.uid < 100 ? 2 : (info.uid < 1000 ? 3 : 4));
                    for (int sp = ulen; sp < 7; sp++) print(" ");
                }
                print(info.name);
                int nlen = 0; while (info.name[nlen]) nlen++;
                for (int sp = nlen; sp < 16; sp++) print(" ");
                /* Named state (mirrors rust/src/ps.rs state_cstr). */
                const char *sn = info.state == 1 ? "run" : (info.state == 2 ? "blkd" : "?");
                print(sn);
                int snlen = 0; while (sn[snlen]) snlen++;
                for (int sp = snlen; sp < 7; sp++) print(" ");
                print_decimal(info.heap_used);
                print("      ");
                print_decimal(info.caps_in_use);
                print("    ");
                if (info.in_kernel) print("K ");
                if (info.blocked_on >= 0) { print("B"); print_decimal(info.blocked_on); }
                else if (info.blocked_on_notif >= 0) print("N");
                println("");
            }
        }
        if (!saw_any) {
            println("(limited visibility - only own task shown for non-admin)");
        }
    } else if (strcmp(cmd, "ls") == 0) {
        struct fs_request  rq = {0};
        struct fs_response rp;
        rq.op = FS_OP_READDIR; rq.dir_ino = 0;
        int n = 0;
        for (rq.offset = 0; rq.offset < 4096; rq.offset++) {
            if (fss_call(&rq, &rp) < 0 || rp.rc < 0) {
                if (rq.offset == 0 && !fss_connected)
                    println("ls: spawn fs_server first");
                break;
            }
            print(rp.name);
            print(rp.type == FS_TYPE_DIR ? "/\n" : "\n");
            n++;
        }
        if (n == 0 && fss_connected) println("(empty)");
    } else if (strncmp(cmd, "cat ", 4) == 0) {
        const char *name = cmd + 4;
        struct fs_request  rq = {0};
        struct fs_response rp;
        rq.op = FS_OP_LOOKUP; rq.dir_ino = 0;
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
        rq.op = FS_OP_MKDIR; rq.dir_ino = 0;
        fss_strcpy(rq.name, name);
        if (fss_call(&rq, &rp) < 0 || rp.rc < 0)
            println("mkdir: failed (name exists or server not running)");
        else { print("mkdir: created "); println(name); }
    } else if (strncmp(cmd, "rm ", 3) == 0) {
        const char *name = cmd + 3;
        struct fs_request  rq = {0};
        struct fs_response rp;
        rq.op = FS_OP_DELETE; rq.dir_ino = 0;
        fss_strcpy(rq.name, name);
        if (fss_call(&rq, &rp) < 0 || rp.rc < 0)
            println("rm: failed (not found or server not running)");
        else { print("rm: removed "); println(name); }
    } else if (strncmp(cmd, "touch ", 6) == 0) {
        const char *name = cmd + 6;
        struct fs_request  rq = {0};
        struct fs_response rp;
        rq.op = FS_OP_CREATE; rq.dir_ino = 0;
        fss_strcpy(rq.name, name);
        if (fss_call(&rq, &rp) < 0 || rp.rc < 0)
            println("touch: failed (already exists or server not running)");
        else { print("touch: created "); println(name); }
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
            rq.op = FS_OP_LOOKUP; rq.dir_ino = 0;
            fss_strcpy(rq.name, fname);
            if (fss_call(&rq, &rp) < 0 || rp.rc < 0) {
                /* file doesn't exist yet — create it */
                rq.op = FS_OP_CREATE; rq.dir_ino = 0;
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
    } else if (strncmp(cmd, "sudo ", 5) == 0) {
        const char *pass = cmd + 5;
        int r = sys_sudo(pass);
        if (r > 0) {
            println("sudo: elevated spawn successful (pid ");
            print_decimal(r);
            println(")");
        } else if (r == SYS_ERR_AUTH) {
            println("sudo: incorrect password or locked out");
        } else {
            print("sudo: failed (");
            print(sys_strerror(r));
            println(")");
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
        int plen = sys_get_pass(newp, 31);
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
        rq.op = FS_OP_LOOKUP; rq.dir_ino = 0;
        fss_strcpy(rq.name, name);
        if (fss_call(&rq, &rp) < 0 || rp.rc < 0 || rp.type != FS_TYPE_FILE) {
            println("run: file not found (is fs_server running? try: spawn fs_server)");
            return;
        }
        uint32_t ino = rp.ino;

        struct fs_request sq = {0};
        sq.op = FS_OP_STAT; sq.ino = ino;
        if (fss_call(&sq, &rp) < 0 || rp.rc < 0) { println("run: stat failed"); return; }
        uint32_t size = rp.size;
        if (size == 0 || size > (256u * 1024u)) { println("run: bad image size"); return; }

        unsigned char *buf = malloc(size);
        if (!buf) { println("run: out of memory"); return; }

        uint32_t off = 0;
        int ok = 1;
        while (off < size) {
            uint32_t chunk = size - off;
            if (chunk > FS_IO_MAX) chunk = FS_IO_MAX;
            struct fs_request dq = {0};
            dq.op = FS_OP_READ; dq.ino = ino; dq.offset = off; dq.len = chunk;
            if (fss_call(&dq, &rp) < 0 || rp.rc <= 0) { ok = 0; break; }
            uint32_t got = (uint32_t)rp.rc;
            if (got > chunk) got = chunk;
            memcpy(buf + off, rp.data, got);
            off += got;
            if (got < chunk) { ok = 0; break; }   /* short read: image truncated */
        }
        if (!ok) { println("run: read failed"); free(buf); return; }

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
        int ulen = sys_get_line(username, sizeof(username) - 1);
        if (ulen <= 0) continue;
        username[ulen] = 0;

        print("Password: ");
        int plen = sys_get_pass(password, sizeof(password) - 1);
        if (plen < 0) {
            println("Input error, try again.");
            continue;
        }
        password[plen] = 0;

        uint32_t got_uid = 0;
        int auth_ok = sys_auth(username, password, &got_uid);

        for (int i = 0; i < 128; i++) password[i] = 0;

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
        int len = sys_get_line(cmd, sizeof(cmd));
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
