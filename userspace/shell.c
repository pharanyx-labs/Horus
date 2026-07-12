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

static void print_cmd(const char *name, const char *desc) {
    print("  ");
    print(name);
    int len = 0; while (name[len]) len++;
    for (int i = len; i < 20; i++) print(" ");
    print("- ");
    println(desc);
}

static void show_general_help_us(void) {
    println("=== Horus Userspace Shell - Command Reference ===");
    println("");
    println("Core:");
    print_cmd("help, man, ?",     "Show this list or 'help <cmd>' for details");
    print_cmd("exit, logout",     "End session / return to login prompt");
    print_cmd("yield",            "Voluntarily yield the CPU");
    println("");
    println("Files & Text (via userspace fs_server):");
    print_cmd("ls",               "List files in the encrypted FS");
    print_cmd("cat <file>",       "Print a file's contents");
    print_cmd("touch <file>",     "Create an empty file");
    print_cmd("mkdir <dir>",      "Create a directory");
    print_cmd("rm <name>",        "Delete a file or directory");
    print_cmd("echo <t> > <f>",   "Write text to a file (creates if needed)");
    print_cmd("echo <text>",      "Print text to the console");
    println("");
    println("User & Security:");
    print_cmd("whoami, id",       "Show current uid (and gid)");
    print_cmd("sudo <password>",  "Elevate via armed image (auth path)");
    print_cmd("passwd",           "Change password (secure input)");
    print_cmd("rotate_keys",      "Re-encrypt storage blocks with master key");
    println("");
    println("User Management (admin):");
    print_cmd("useradd <u> <name>","Create user");
    print_cmd("userdel <uid>",    "Delete user");
    println("");
    println("Process & Loader:");
    print_cmd("ps",               "List visible tasks");
    print_cmd("mem",              "Heap demo (sbrk)");
    print_cmd("spawn <name>",     "Spawn embedded binary (hello, captest, fs_server)");
    print_cmd("run <file>",       "Load a program image from the FS and run it (execve-from-fd)");
    print_cmd("receive",          "Receive binary over serial (arms for spawn)");
    print_cmd("load",             "receive + spawn (serial, one step)");
    println("");
    println("IPC & Notifications:");
    print_cmd("ipc_send/recv",    "Synchronous endpoint IPC");
    print_cmd("notify <badge>",   "Send a notification badge (async)");
    print_cmd("wait_notify",      "Block until a notification badge arrives");
    println("");
    print_cmd("fss*",             "Low-level FS ops (fss_ls fss_cat fss_write ...)");
    println("");
    println("Note: Privileged ops require appropriate caps (often slot 3) or uid 0.");
    println("Type 'help <command>' for details on a topic.");
    println("=== End of help ===");
}

static void show_topic_help_us(const char *topic) {
    char tbuf[32];
    int i = 0;
    while (*topic == ' ') topic++;
    while (*topic && *topic != ' ' && i < 31) { tbuf[i++] = *topic++; }
    tbuf[i] = 0;
    const char *t = tbuf;

    println("=== Help: ");
    print(t);
    println(" ===");

    if (strcmp(t, "help") == 0 || strcmp(t, "man") == 0 || t[0] == 0) {
        show_general_help_us();
        return;
    }

    if (strcmp(t, "ps") == 0) {
        println("Description: List visible processes with uid, state, heap and caps.");
        println("Usage:       ps");
        println("Notes:       Non-root tasks see only themselves. Columns: PID UID NAME");
        println("             STATE HEAP CAPS FLAGS. * marks your task; STATE is run/blkd;");
        println("             FLAGS: K=in kernel, B<n>=blocked on task n, N=notify wait.");
    } else if (strcmp(t, "ls") == 0) {
        println("Description: List files and directories in the userspace encrypted filesystem.");
        println("Usage:       ls");
        println("Notes:       Requires fs_server to be running (spawn fs_server).");
        println("             Directories shown with trailing /.");
    } else if (strcmp(t, "cat") == 0) {
        println("Description: Print the contents of a file from the userspace filesystem.");
        println("Usage:       cat <file>");
        println("Notes:       Requires fs_server.");
    } else if (strcmp(t, "echo") == 0) {
        println("Description: Echo the remaining text back to the console.");
        println("Usage:       echo <text>");
    } else if (strcmp(t, "load") == 0) {
        println("Description: Receive a binary image then spawn it as a new task.");
        println("Usage:       load");
        println("Notes:       Connect to 4444 for the image, 4445 for the shell. Requires FRAME cap rights.");
    } else if (strcmp(t, "receive") == 0) {
        println("Description: Receive and arm a program image from the loader port.");
        println("Usage:       receive");
        println("Notes:       Follow with 'spawn' (or use the combined 'load' command).");
    } else if (strcmp(t, "spawn") == 0) {
        println("Description: Launch an embedded binary or a previously armed image.");
        println("Usage:       spawn <name>   -- spawn a named binary (hello, captest, fs_server)");
        println("             spawn          -- spawn whatever was last armed via 'receive'");
        println("Notes:       Child receives a fresh 4-level address space and restricted caps.");
    } else if (strcmp(t, "sudo") == 0) {
        println("Description: Authenticate and spawn an elevated (armed) image as a privileged task.");
        println("Usage:       sudo <password>");
        println("Notes:       Password is read securely; success depends on prior arming + auth setup.");
    } else if (strcmp(t, "rotate_keys") == 0) {
        println("Description: Re-encrypt all storage objects the user controls (ETM layer).");
        println("Usage:       rotate_keys");
        println("Notes:       Requires an active user master key from prior auth/sudo. Reports block count.");
    } else if (strncmp(t, "cap_", 4) == 0 || strcmp(t, "fsroot") == 0) {
        println("Description: Removed. The legacy in-memory capfs (fsroot/cap_*) no longer exists.");
        println("Usage:       use the fs_server commands instead: ls, cat, rm, mkdir, touch.");
    } else if (strcmp(t, "ipc_send") == 0 || strcmp(t, "ipc_recv") == 0 || strcmp(t, "ipc") == 0) {
        println("Description: Send or receive a message on a capability endpoint.");
        println("Usage:       ipc_send <slot> <msg>   |   ipc_recv <slot>");
        println("Notes:       Endpoints carry badges and grant rights for controlled cross-task exchange.");
    } else if (strcmp(t, "notify") == 0 || strcmp(t, "wait_notify") == 0) {
        println("Description: Fire or wait on an asynchronous notification (badge value).");
        println("Usage:       notify <slot> <badge>   |   wait_notify <slot>");
        println("Notes:       Lightweight async path; receiver parks until a matching notification arrives.");
    } else if (strcmp(t, "exit") == 0 || strcmp(t, "logout") == 0) {
        println("Description: Terminate the current login session and return to the login prompt.");
        println("Usage:       exit   (or: logout)");
    } else if (strcmp(t, "yield") == 0) {
        println("Description: Cooperatively yield so the kernel scheduler can run another task.");
        println("Usage:       yield");
    } else if (strcmp(t, "mem") == 0) {
        println("Description: Simple sbrk demo allocating from the userspace heap.");
        println("Usage:       mem");
    } else if (strcmp(t, "whoami") == 0 || strcmp(t, "id") == 0) {
        println("Description: Report the current login uid (and gid). root shown for uid 0.");
        println("Usage:       whoami   |   id");
    } else if (strcmp(t, "passwd") == 0) {
        println("Description: Change the password for the current uid using secure input.");
        println("Usage:       passwd");
    } else if (strcmp(t, "useradd") == 0 || strcmp(t, "userdel") == 0) {
        println("Description: Admin-only user database management (uid + name).");
        println("Usage:       useradd <uid> <name>   |   userdel <uid>");
        println("Notes:       Requires uid 0 and appropriate capability rights.");
    } else if (strcmp(t, "fss") == 0 || strncmp(t, "fss_", 4) == 0) {
        println("Description: Demo client for a userspace FS server (connect, ls, cat, write, tree).");
        println("Usage:       fss ; fss_connect ; fss_ls ; fss_cat <name> ; fss_write <f> <txt> ; fss_tree");
        println("Notes:       Requires a running fs_server.bin (receive+spawn it first).");
    } else {
        println("No specific help available for that topic.");
        println("Type 'help' to list available commands.");
    }

    println("=== End of topic help ===");
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
    } else if (strncmp(cmd, "ipc_recv ", 9) == 0) {
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
    } else if (strncmp(cmd, "wait_notify ", 12) == 0) {
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
