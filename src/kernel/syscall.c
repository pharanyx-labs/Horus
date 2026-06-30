#include "kernel.h"

static size_t kstrlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static void kstrcpy(char *dst, const char *src) {
    while (*src) {
        *dst++ = *src++;
    }
    *dst = 0;
}

static int kstrcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

#ifdef DEBUG_SHELL
static int kstrncmp(const char *a, const char *b, size_t n) {
    while (n > 0 && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}
#endif

#ifdef DEBUG_SHELL
static void help_line(const char *name, const char *desc) {
    print("  ");
    print(name);
    int len = 0; while (name[len]) len++;
    for (int i = len; i < 22; i++) print(" ");
    print("- ");
    println(desc);
}

/* Accurate list of what the in-kernel debug shell actually dispatches (see the
 * action handlers in process_user_command). Kept in sync with that switch; the
 * old one-liner advertised `fs`/`spawn` (never handled here) and omitted half
 * the real commands. "(cap)" marks ops gated on a capability. */
static void show_general_help(void) {
    set_text_colour(0x0B);
    println("Horus kernel debug shell - commands");
    set_text_colour(0x0F);
    println("Info:");
    help_line("help [cmd], man, ?",  "This list, or details for one command");
    help_line("version",            "Kernel version banner");
    help_line("uptime",             "System uptime in timer ticks");
    help_line("ps",                 "List tasks (full view needs CAP_CONSOLE)");
    help_line("caps",               "List this task's capability slots");
    help_line("dmesg, log",         "Dump the kernel log (cap: CAP_CONSOLE)");
    println("Session:");
    help_line("echo <text>",        "Print text back");
    help_line("clear",              "Clear the screen (cap: slot-3 WRITE)");
    help_line("yield",              "Yield the CPU to the scheduler");
    help_line("exit",               "Power off the machine (cap: CAP_CONSOLE)");
    println("Capabilities & tasks:");
    help_line("mint <d> <s> <r>",   "Mint cap: dest<-src slot with rights mask r");
    help_line("kill <pid>",         "Terminate a task (cap: CAP_CONSOLE)");
    help_line("load",               "Receive a binary on :4444 then spawn it");
    println("Storage:");
    help_line("rotate_keys",        "Re-encrypt your blocks (cap: CONSOLE+ENC_STORAGE)");
    set_text_colour(0x08);
    println("Numbers are decimal. 'rights' is a decimal bitmask (see ARCHITECTURE.md).");
    set_text_colour(0x0F);
}
#endif

#ifdef DEBUG_SHELL
static void show_topic_help(const char *topic) {
    while (*topic == ' ') topic++;
    if (kstrcmp(topic, "mint") == 0) {
        println("mint <dest> <src> <rights>");
        println("  Derive a new capability into slot <dest> from the cap in slot");
        println("  <src>, keeping at most <rights> (a decimal bitmask). The source");
        println("  must carry CAP_RIGHT_MINT; dest must be >= 4 (slots 0-3 reserved).");
        return;
    }
    if (kstrcmp(topic, "kill") == 0) {
        println("kill <pid>");
        println("  Terminate task <pid>. Requires CAP_CONSOLE (slot 8). You cannot");
        println("  kill pid 0 (the kernel/init task).");
        return;
    }
    if (kstrcmp(topic, "load") == 0) {
        println("load");
        println("  Wait on serial port 4444 for a headered program image, then spawn");
        println("  it as a new ring-3 task. Requires a FRAME cap (slot 3, WRITE|EXEC)");
        println("  and CAP_CONSOLE. Pipe a .bin built by tools/mkheadered to :4444.");
        return;
    }
    if (kstrcmp(topic, "rotate_keys") == 0) {
        println("rotate_keys");
        println("  Re-encrypt the storage blocks you own under a freshly derived key");
        println("  (ChaCha20+HMAC AEAD). Requires CAP_CONSOLE and CAP_ENCRYPTED_STORAGE.");
        return;
    }
    println("No per-topic help for that command. Showing the full list:");
    show_general_help();
}
#endif

#ifdef DEBUG_SHELL
static bool has_console_cap(void) {
    struct capability *c = cap_lookup(8, 0);
    return (c && c->type == CAP_CONSOLE);
}
#endif

extern tcb_t tasks[MAX_TASKS];

#ifdef DEBUG_SHELL
#define HISTORY_SIZE 8
#define CMD_MAX 128
static char cmd_history[HISTORY_SIZE][CMD_MAX];
static int history_count = 0;
static int history_pos = -1;
#endif

#ifdef DEBUG_SHELL
static void qemu_exit(int code) {
    outb(0x604, (uint8_t)code);
    outb(0x604, 0x00);
    asm volatile("lidt 0x0");
    asm volatile("int $0x0");
    for (;;) {
        asm volatile("cli; hlt");
    }
}
#endif

#define MAX_PROGRAM_SIZE (1024 * 1024)
static uint8_t loader_staging[MAX_PROGRAM_SIZE];
static struct program_header armed_hdr;
static int program_armed = 0;

static struct audit_event audit_log_buffer[AUDIT_LOG_SIZE];
static uint32_t audit_head = 0;
static uint32_t audit_count = 0;

void audit_log(uint32_t type, uint32_t object, int32_t result, const char *msg) {
    struct audit_event *e = &audit_log_buffer[audit_head];

    e->timestamp    = get_system_ticks();
    e->type         = type;
    e->subject_uid  = tasks[get_current_task()].uid;
    e->subject_task = get_current_task();
    e->object       = object;
    e->result       = result;

    if (msg) {
        size_t i;
        for (i = 0; i < sizeof(e->message) - 1 && msg[i]; i++) {
            e->message[i] = msg[i];
        }
        e->message[i] = 0;
    } else {
        e->message[0] = 0;
    }

    audit_head = (audit_head + 1) % AUDIT_LOG_SIZE;
    if (audit_count < AUDIT_LOG_SIZE) audit_count++;
}

#ifndef AUDIT_AUTH
#define AUDIT_AUTH          1
#define AUDIT_SUDO          2
#define AUDIT_USER_MGMT     3
#define AUDIT_CAP_OPERATION 4
#define AUDIT_FILE_ACCESS   5
#define AUDIT_IPC           6
#define AUDIT_FS            7
#define AUDIT_CAP_MINT      10
#define AUDIT_CAP_REVOKE    11
#define AUDIT_CAP_TRANSFER  12

#define AUDIT_IPC_GRANT     30
#define AUDIT_TASK_CREATE   40
#define AUDIT_TASK_EXIT     41
#endif
static struct user_account users[MAX_USERS];
static int user_count = 0;
static uint32_t next_uid = 1000;

uint8_t kernel_pepper[16];

static void generate_salt(uint8_t *salt, size_t len) {
    /* Per-password random salt drawn from the central CSPRNG (RDRAND/TSC-jitter
     * seeded), replacing the old predictable LCG-over-ticks generator. */
    secure_random_bytes(salt, len);
}

/* Password hash = PBKDF2-HMAC-SHA256(password, salt || pepper, iterations).
 *
 * - PBKDF2-HMAC-SHA256 is the audited primitive (RFC 8018), implemented in
 *   safe Rust; the previous 4096-round XOR-rotate construction was unaudited,
 *   fast to brute-force, and folded its output into only a-z characters.
 * - The 16-byte per-boot kernel pepper is concatenated into the salt so an
 *   attacker who exfiltrates the user database alone still lacks a secret
 *   needed to mount an offline dictionary attack.
 * - The raw 32-byte derived key is stored (PASS_HASH_LEN == 32), not an
 *   alphabetic projection, preserving full entropy.
 */
static void strong_password_hash(const char *password, const uint8_t *salt,
                                 const uint8_t *pepper, uint8_t *out_hash) {
    uint8_t combined_salt[PASS_SALT_LEN + 16];
    for (int i = 0; i < PASS_SALT_LEN; i++) combined_salt[i] = salt[i];
    for (int i = 0; i < 16; i++) combined_salt[PASS_SALT_LEN + i] = pepper[i];

    rust_password_hash((const uint8_t *)password, kstrlen(password),
                       combined_salt, sizeof(combined_salt),
                       PASSWORD_KDF_ITERATIONS, out_hash, PASS_HASH_LEN);

    secure_zero(combined_salt, sizeof(combined_salt));
}

static int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
    }
    return diff == 0;
}

int set_user_password(uint32_t uid, const char *new_password) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && users[i].uid == uid) {
            generate_salt(users[i].salt, PASS_SALT_LEN);
            strong_password_hash(new_password, users[i].salt, kernel_pepper,
                                 users[i].pass_hash);
            return 0;
        }
    }
    return -1;
}

static int verify_user_password(const char *name, const char *password) {
    struct user_account *u = NULL;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            int match = 1;
            for (size_t j = 0; j < 32 && name[j]; j++) {
                if (users[i].name[j] != name[j]) { match = 0; break; }
            }
            if (match && name[kstrlen(users[i].name)] == 0) {
                u = &users[i];
                break;
            }
        }
    }
    /* Run the same work whether or not the account exists, to deny an attacker
     * a timing oracle for username enumeration: always derive the (deliberately
     * expensive) PBKDF2 hash and run a constant-time compare. When the user is
     * absent we hash against a zero salt and compare the result against itself,
     * then discard the (necessarily "equal") outcome and fail. */
    static const uint8_t dummy_salt[PASS_SALT_LEN]; /* zero-initialized */
    uint8_t computed[PASS_HASH_LEN];
    const uint8_t *salt   = u ? u->salt      : dummy_salt;
    const uint8_t *expect = u ? u->pass_hash : computed;

    strong_password_hash(password, salt, kernel_pepper, computed);
    int eq = constant_time_compare(computed, expect, PASS_HASH_LEN);
    return (u && eq) ? 1 : 0;
}

#define USERDB_MAGIC 0x55534442
#define USERDB_TAG_LEN 32

/* Integrity tag over the user database = HMAC-SHA256(kernel_pepper, records).
 * Replaces the previous custom ARX construction. Valid records are serialized
 * in slot order into a fixed scratch buffer (matching the on-disk layout) and
 * authenticated as a single message. */
static void compute_userdb_tag(uint8_t *tag_out) {
    static uint8_t scratch[MAX_USERS * sizeof(struct user_account)];
    size_t off = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (!users[i].valid) continue;
        const uint8_t *rec = (const uint8_t *)&users[i];
        for (size_t j = 0; j < sizeof(struct user_account); j++) {
            scratch[off + j] = rec[j];
        }
        off += sizeof(struct user_account);
    }
    rust_hmac_sha256(kernel_pepper, sizeof(kernel_pepper), scratch, off, tag_out);
}

static int userdb_tag_valid(const uint8_t *tag_on_disk) {
    uint8_t computed[USERDB_TAG_LEN];
    compute_userdb_tag(computed);
    return constant_time_compare(computed, tag_on_disk, USERDB_TAG_LEN);
}

static void users_save_to_ramfs(void) {
    int fd = ramfs_open("passwd",0);
    if (fd < 0) {
        fd = ramfs_create("passwd",0);
        if (fd < 0) return;
    }

    uint32_t magic = USERDB_MAGIC;
    uint32_t count = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) count++;
    }

    ramfs_write(fd, &magic, sizeof(magic));
    ramfs_write(fd, &count, sizeof(count));

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            ramfs_write(fd, &users[i], sizeof(struct user_account));
        }
    }

    uint8_t tag[USERDB_TAG_LEN];
    compute_userdb_tag(tag);
    ramfs_write(fd, tag, USERDB_TAG_LEN);
}

static void users_persist(void) {
    users_save_to_ramfs();
}

static void users_load_from_ramfs(void) {
    int fd = ramfs_open("passwd",0);
    if (fd < 0) return;

    uint32_t magic = 0;
    uint32_t count = 0;
    if (ramfs_read(fd, &magic, sizeof(magic)) != sizeof(magic) ||
        magic != USERDB_MAGIC) {
        return;
    }
    if (ramfs_read(fd, &count, sizeof(count)) != sizeof(count) ||
        count > MAX_USERS) {
        return;
    }

    for (int i = 0; i < MAX_USERS; i++) users[i].valid = 0;
    user_count = 0;

    for (uint32_t i = 0; i < count; i++) {
        struct user_account tmp;
        if (ramfs_read(fd, &tmp, sizeof(tmp)) == sizeof(tmp)) {
            int slot = -1;
            for (int j = 0; j < MAX_USERS; j++) {
                if (!users[j].valid) { slot = j; break; }
                if (users[j].uid == tmp.uid) { slot = j; break; }
            }
            if (slot >= 0) {
                users[slot] = tmp;
                users[slot].valid = 1;
                user_count++;
                if (tmp.uid >= next_uid) next_uid = tmp.uid + 1;
            }
        }
    }

    uint8_t tag_on_disk[USERDB_TAG_LEN];
    if (ramfs_read(fd, tag_on_disk, USERDB_TAG_LEN) != USERDB_TAG_LEN ||
        !userdb_tag_valid(tag_on_disk)) {
        for (int i = 0; i < MAX_USERS; i++) users[i].valid = 0;
        user_count = 0;
        next_uid = 1000;
    }
}

void users_init(void) {
    for (int i = 0; i < MAX_USERS; i++) {
        users[i].valid = 0;
    }
    user_count = 0;
    next_uid = 1000;

    /* Per-boot secret pepper from the central CSPRNG (RDRAND/TSC-jitter seeded),
     * replacing the predictable LCG-over-ticks generator. */
    secure_random_bytes(kernel_pepper, sizeof(kernel_pepper));

    users[0].uid = 0;
    users[0].gid = 0;
    kstrcpy(users[0].name, "root");
    kstrcpy(users[0].home, "/");
    kstrcpy(users[0].shell, "/bin/shell");
    users[0].auth_fail_count = 0;
    users[0].auth_lockout_until = 0;
    users[0].valid = 1;

    set_user_password(0, "rootpass");
    user_count = 1;

    users[1].uid = 1000;
    users[1].gid = 100;
    kstrcpy(users[1].name, "user");
    kstrcpy(users[1].home, "/home/user");
    kstrcpy(users[1].shell, "/bin/shell");
    users[1].auth_fail_count = 0;
    users[1].auth_lockout_until = 0;
    users[1].valid = 1;
    set_user_password(1000, "password");
    user_count = 2;

    users_load_from_ramfs();

    int dev_idx = -1;
    for (int ii = 0; ii < MAX_USERS; ii++) {
        if (users[ii].valid && kstrcmp(users[ii].name, "user") == 0) { dev_idx = ii; break; }
    }
    if (dev_idx < 0) {
        for (int ii = 0; ii < MAX_USERS; ii++) if (!users[ii].valid) { dev_idx = ii; break; }
        if (dev_idx >= 0) {
            users[dev_idx].uid = 1000;
            users[dev_idx].gid = 100;
            kstrcpy(users[dev_idx].name, "user");
            set_user_password(dev_idx, "password");
            kstrcpy(users[dev_idx].home, "/home/user");
            users[dev_idx].auth_fail_count = 0;
            users[dev_idx].auth_lockout_until = 0;
            kstrcpy(users[dev_idx].shell, "/bin/shell");
            users[dev_idx].valid = 1;
            user_count = dev_idx + 1;
        }
    }
    if (dev_idx >= 0) {
        set_user_password(users[dev_idx].uid, "password");
        users_persist();
    }
}

static int loader_receive_to_staging(struct program_header *out_hdr) {
    struct program_header hdr;
    uint8_t *p = (uint8_t *)&hdr;

    p[0] = serial2_read_char();
    for (size_t i = 1; i < sizeof(hdr); i++) {
        p[i] = serial2_read_char();
    }

    if (hdr.magic != 0x55524F48) {
        return -1;
    }
    if (hdr.size == 0 || hdr.size > MAX_PROGRAM_SIZE) {
        return -2;
    }

    for (uint32_t i = 0; i < hdr.size; i++) {
        loader_staging[i] = serial2_read_char();
    }

    armed_hdr = hdr;
    program_armed = 1;

    if (out_hdr) {
        *out_hdr = hdr;
    }
    return 0;
}

static int current_user_is_admin(void) {

    struct capability *c = cap_lookup(6, CAP_RIGHT_ALL);
    if (c && c->type == CAP_USER) return 1;
    return tasks[get_current_task()].uid == 0;
}

int do_useradd(uint32_t uid, uint32_t gid, const char *name, const char *initial_password) {
    if (!current_user_is_admin()) return -1;
    if (user_count >= MAX_USERS) return -2;
    if (kstrlen(name) == 0 || kstrlen(name) >= 32) return -3;

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            if (users[i].uid == uid) return -4;
            if (kstrcmp(users[i].name, name) == 0) return -5;
        }
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (!users[i].valid) {
            users[i].uid = uid;
            users[i].gid = gid;
            kstrcpy(users[i].name, name);
            kstrcpy(users[i].home, "/home/");
            size_t hlen = kstrlen(users[i].home);
            kstrcpy(users[i].home + hlen, name);
            kstrcpy(users[i].shell, "/bin/shell");
            set_user_password(uid, initial_password);
            users[i].valid = 1;
            user_count++;
            if (uid >= next_uid) next_uid = uid + 1;
            users_persist();
            audit_log(AUDIT_USER_MGMT, uid, 0, "useradd");
            return 0;
        }
    }
    return -6;
}

int do_userdel(uint32_t uid) {
    if (!current_user_is_admin()) return -1;
    if (uid == 0) return -2;

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && users[i].uid == uid) {
            users[i].valid = 0;
            user_count--;
            users_persist();
            return 0;
        }
    }
    return -3;
}

int do_passwd(uint32_t target_uid, const char *new_password) {
    uint32_t my_uid = tasks[get_current_task()].uid;
    int is_admin = current_user_is_admin();

    if (!is_admin && my_uid != target_uid) return -1;

    int rc = set_user_password(target_uid, new_password);
    if (rc == 0) users_persist();
    return rc;
}

int sys_fs_mint_file(uint32_t dir_slot, uint32_t dest_slot, uint32_t new_rights) {
    struct capability *dir_cap = cap_lookup(dir_slot, CAP_RIGHT_FS_LOOKUP | CAP_RIGHT_MINT);
    if (!dir_cap) {
        audit_log(AUDIT_FS, dir_slot, -1, "mint denied: no dir cap or rights");
        return -1;
    }

    if (dest_slot < 4 || dest_slot >= 256) return -2;

    if (!cap_mint(dest_slot, dir_slot, new_rights)) {
        audit_log(AUDIT_FS, dest_slot, -2, "mint failed");
        return -2;
    }

    struct capability *dest = &tasks[get_current_task()].cspace[dest_slot];
    struct fs_object *obj = (struct fs_object *)dir_cap->object;
    dest->type = (obj && obj->type == FS_OBJ_DIR) ? CAP_DIR : CAP_FILE;

    audit_log(AUDIT_CAP_MINT, dest_slot, 0, "fs mint");
    return 0;
}

int sys_fs_lookup(uint32_t dir_slot, const char *name, uint32_t out_slot, uint32_t desired_rights) {
    if (out_slot < 4 || out_slot >= 256) return -1;

    struct capability *dir_cap = cap_lookup(dir_slot, CAP_RIGHT_FS_LOOKUP);
    if (!dir_cap) {
        audit_log(AUDIT_FS, dir_slot, -1, "lookup denied");
        return -1;
    }

    struct capability *out = &tasks[get_current_task()].cspace[out_slot];
    int rc = capfs_lookup(dir_cap, name, out, desired_rights);
    if (rc == 0) {
        audit_log(AUDIT_FS_LOOKUP, out_slot, 0, "lookup ok");
    } else {
        audit_log(AUDIT_FS_LOOKUP, dir_slot, rc, "lookup fail");
    }
    return rc;
}

int sys_fs_create(uint32_t dir_slot, const char *name, int type, uint32_t out_slot, uint32_t desired_rights) {
    if (out_slot < 4 || out_slot >= 256) return -1;
    if (type != FS_OBJ_FILE && type != FS_OBJ_DIR) return -9;

    struct capability *dir_cap = cap_lookup(dir_slot, CAP_RIGHT_FS_CREATE);
    if (!dir_cap) {
        audit_log(AUDIT_FS, dir_slot, -1, "create denied: no cap");
        return -1;
    }

    struct capability *out = &tasks[get_current_task()].cspace[out_slot];
    int rc = capfs_create(dir_cap, name, type, out, desired_rights);
    if (rc == 0) {
        audit_log(AUDIT_FS_CREATE, out_slot, 0, "create ok");
    } else {
        audit_log(AUDIT_FS_CREATE, dir_slot, rc, "create fail");
    }
    return rc;
}

int sys_fs_delete(uint32_t dir_slot, const char *name) {
    struct capability *dir_cap = cap_lookup(dir_slot, CAP_RIGHT_FS_DELETE);
    if (!dir_cap) {
        audit_log(AUDIT_FS, dir_slot, -1, "delete denied");
        return -1;
    }

    int rc = capfs_delete(dir_cap, name);
    audit_log(AUDIT_FS_DELETE, dir_slot, rc, rc==0 ? "delete" : "delete fail");
    return rc;
}

int sys_fs_readdir(uint32_t dir_slot, char *buf, uint32_t bufsize) {
    struct capability *dir_cap = cap_lookup(dir_slot, CAP_RIGHT_FS_LOOKUP);
    if (!dir_cap) return -1;
    if (!buf) return -1;

    /* Bounce through a kernel buffer instead of letting capfs_readdir write the
     * user pointer directly from ring 0 (that bypasses copy_to_user validation
     * and would #PF under SMAP). capfs_readdir guarantees pos+1 <= bufsize, so
     * copying rc+1 bytes carries the NUL terminator it writes at buf[pos]. */
    char kbuf[512];
    uint32_t to = bufsize > sizeof(kbuf) ? (uint32_t)sizeof(kbuf) : bufsize;
    int rc = capfs_readdir(dir_cap, kbuf, to);
    if (rc >= 0) {
        if (copy_to_user(buf, kbuf, (size_t)rc + 1) != 0) return -3;
    }
    return rc;
}

int sys_fs_get_root(uint32_t dest_slot, uint32_t rights) {
    struct capability *admin = cap_lookup(6, CAP_RIGHT_ALL);
    if (!admin && tasks[get_current_task()].uid != 0) {
        audit_log(AUDIT_FS, 0, -1, "get_root denied");
        return -1;
    }

    if (dest_slot < 4 || dest_slot >= 256) return -2;

    struct fs_object *root = fs_objects[0];
    if (!root) return -3;

    if (dest_slot >= CNODE_SIZE) return -2;

    struct capability *dest = &tasks[get_current_task()].cspace[dest_slot];
    dest->type   = CAP_DIR;
    dest->object = (addr_t)root;
    dest->rights = rights & (CAP_RIGHT_FS_LOOKUP | CAP_RIGHT_FS_CREATE | CAP_RIGHT_FS_DELETE |
                             CAP_RIGHT_FS_READ | CAP_RIGHT_FS_WRITE | CAP_RIGHT_MINT | CAP_RIGHT_REVOKE);
    dest->badge  = 0xF5000000U;
    dest->serial = cap_alloc_fresh_serial();
    dest->generation = 0;

    audit_log(AUDIT_FS, dest_slot, 0, "get_root");
    return 0;
}

int sys_fs_read(uint32_t file_slot, char *buf, uint32_t len) {
    if (file_slot >= 256 || !buf) return -1;
    struct capability *fc = cap_lookup(file_slot, CAP_RIGHT_FS_READ);
    if (!fc || fc->type != CAP_FILE) return -2;

    char kbuf[256];
    uint32_t to = len > 255 ? 255 : len;
    int rc = capfs_read(fc, kbuf, to);
    if (rc > 0) {
        if (copy_to_user(buf, kbuf, (size_t)rc) != 0) return -3;
    }
    audit_log(AUDIT_FS_READ, file_slot, rc >= 0 ? 0 : rc, "fs read");
    return rc;
}

int sys_fs_write(uint32_t file_slot, const char *buf, uint32_t len) {
    if (file_slot >= 256 || !buf) return -1;
    struct capability *fc = cap_lookup(file_slot, CAP_RIGHT_FS_WRITE);
    if (!fc || fc->type != CAP_FILE) return -2;

    char kbuf[256];
    uint32_t to = len > 255 ? 255 : len;
    if (copy_from_user(kbuf, buf, to) != 0) return -3;

    int rc = capfs_write(fc, kbuf, to);
    audit_log(AUDIT_FS_WRITE, file_slot, rc >= 0 ? 0 : rc, "fs write");
    return rc;
}

static int do_receive_program(struct program_header *hdr_out) {
    if (!hdr_out) return -3;

    program_armed = 0;

    int rc = loader_receive_to_staging(hdr_out);
    return rc;
}

static int try_elf_load(uint32_t load_base, uint32_t *out_entry)
{
    if (!out_entry) return -1;
    const uint8_t *st = loader_staging;
    
    if (st[0] != 0x7f || st[1] != 'E' || st[2] != 'L' || st[3] != 'F') return -2;

    uint8_t ei_class = st[4]; 
    uint8_t ei_data  = st[5]; 
    if (ei_data != 1) return -3; 

    
    uint16_t e_type = (uint16_t)st[16] | ((uint16_t)st[17] << 8);
    uint16_t e_machine = (uint16_t)st[18] | ((uint16_t)st[19] << 8);
    uint32_t e_entry32 = 0;
    uint64_t e_entry64 = 0;
    uint32_t e_phoff = 0;
    uint16_t e_phnum = 0;

    if (ei_class == 1) { 
        if (e_machine != 3 ) return -4;
        e_entry32 = (uint32_t)st[24] | ((uint32_t)st[25]<<8) | ((uint32_t)st[26]<<16) | ((uint32_t)st[27]<<24);
        e_phoff   = (uint32_t)st[28] | ((uint32_t)st[29]<<8) | ((uint32_t)st[30]<<16) | ((uint32_t)st[31]<<24);
        e_phnum   = (uint16_t)st[44] | ((uint16_t)st[45] << 8);
    } else if (ei_class == 2) { 
        if (e_machine != 62 ) return -4;
        e_entry64 = (uint64_t)st[24] | ((uint64_t)st[25]<<8) | ((uint64_t)st[26]<<16) | ((uint64_t)st[27]<<24) |
                    ((uint64_t)st[28]<<32) | ((uint64_t)st[29]<<40) | ((uint64_t)st[30]<<48) | ((uint64_t)st[31]<<56);
        e_phoff   = (uint32_t)st[32] | ((uint32_t)st[33]<<8) | ((uint32_t)st[34]<<16) | ((uint32_t)st[35]<<24);
        e_phnum   = (uint16_t)st[56] | ((uint16_t)st[57] << 8);
    } else {
        return -5;
    }

    if (e_type != 2  && e_type != 3 ) return -6;
    if (e_phnum == 0 || e_phnum > 8) return -7; 
    if (e_phoff == 0 || e_phoff > (MAX_PROGRAM_SIZE - 64)) return -8;

    
    uint32_t min_vaddr = 0xFFFFFFFFU;
    int have_load = 0;
    const uint8_t *ph = st + e_phoff;
    uint32_t phentsize = (ei_class == 1) ? 32 : 56;

    for (uint16_t i = 0; i < e_phnum; i++) {
        const uint8_t *p = ph + (uint32_t)i * phentsize;
        uint32_t p_type = p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
        if (p_type != 1 ) continue;
        uint32_t p_vaddr;
        if (ei_class == 1) {
            p_vaddr = (uint32_t)p[8] | ((uint32_t)p[9]<<8) | ((uint32_t)p[10]<<16) | ((uint32_t)p[11]<<24);
        } else {
            p_vaddr = (uint32_t)p[16] | ((uint32_t)p[17]<<8) | ((uint32_t)p[18]<<16) | ((uint32_t)p[19]<<24);
        }
        if (p_vaddr < min_vaddr) min_vaddr = p_vaddr;
        have_load = 1;
    }
    if (!have_load) return -9;

    uint32_t slide = load_base - (min_vaddr & ~0xFFFU);

    /* Record each loaded segment's mapped range and ELF p_flags so that, after
     * the bytes are copied in (which needs the pages writable), we can apply
     * W^X per page: code becomes read+execute, data/rodata read[+write]+NX.
     * e_phnum is capped at 8 above, so PT_LOAD segments fit in these arrays. */
    uint32_t seg_va[8], seg_memsz[8], seg_flags[8];
    int nseg = 0;

    for (uint16_t i = 0; i < e_phnum; i++) {
        const uint8_t *p = ph + (uint32_t)i * phentsize;
        uint32_t p_type = p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
        if (p_type != 1) continue;

        uint32_t p_offset=0, p_vaddr=0, p_filesz=0, p_memsz=0, p_flags=0;
        if (ei_class == 1) {
            p_offset = (uint32_t)p[4] | ((uint32_t)p[5]<<8) | ((uint32_t)p[6]<<16) | ((uint32_t)p[7]<<24);
            p_vaddr  = (uint32_t)p[8] | ((uint32_t)p[9]<<8) | ((uint32_t)p[10]<<16) | ((uint32_t)p[11]<<24);
            p_filesz = (uint32_t)p[16]| ((uint32_t)p[17]<<8)| ((uint32_t)p[18]<<16)| ((uint32_t)p[19]<<24);
            p_memsz  = (uint32_t)p[20]| ((uint32_t)p[21]<<8)| ((uint32_t)p[22]<<16)| ((uint32_t)p[23]<<24);
            p_flags  = (uint32_t)p[24]| ((uint32_t)p[25]<<8)| ((uint32_t)p[26]<<16)| ((uint32_t)p[27]<<24);
        } else {
            p_offset = (uint32_t)p[8] | ((uint32_t)p[9]<<8) | ((uint32_t)p[10]<<16) | ((uint32_t)p[11]<<24);
            p_vaddr  = (uint32_t)p[16]| ((uint32_t)p[17]<<8)| ((uint32_t)p[18]<<16)| ((uint32_t)p[19]<<24);
            p_filesz = (uint32_t)p[32]| ((uint32_t)p[33]<<8)| ((uint32_t)p[34]<<16)| ((uint32_t)p[35]<<24);
            p_memsz  = (uint32_t)p[40]| ((uint32_t)p[41]<<8)| ((uint32_t)p[42]<<16)| ((uint32_t)p[43]<<24);
            p_flags  = (uint32_t)p[4] | ((uint32_t)p[5]<<8)| ((uint32_t)p[6]<<16)| ((uint32_t)p[7]<<24);
        }

        if (p_memsz < p_filesz) return -10;
        if (p_offset + p_filesz > MAX_PROGRAM_SIZE) return -11;
        uint32_t dest_va = p_vaddr + slide;
        if (dest_va < USER_AREA_BASE || dest_va >= USER_MAX_VADDR) return -12;
        if (dest_va + p_memsz < dest_va) return -13; 

        /* Copy the segment's file bytes, then zero-fill the BSS tail, into
         * the target task's address space (current task == new_id here).
         * copy_to_user walks the page tables with present/user/write checks,
         * handles huge pages, switches to the kernel CR3 (SMAP-safe), and
         * fails closed on any unmapped page -- unlike the previous
         * hand-rolled walk, which masked each level without a present-bit
         * check and would dereference and write a garbage ring-0 physical
         * address for any non-present or huge-page mapping. */
        static const uint8_t elf_zero_fill[4096] = {0};
        const uint8_t *s = st + p_offset;
        for (uint32_t off = 0; off < p_filesz; ) {
            uint32_t chunk = p_filesz - off;
            if (chunk > USER_MEM_MAX_COPY) chunk = USER_MEM_MAX_COPY;
            if (copy_to_user((void *)(uintptr_t)(dest_va + off), s + off, chunk) != 0)
                return -15;
            off += chunk;
        }
        for (uint32_t off = p_filesz; off < p_memsz; ) {
            uint32_t chunk = p_memsz - off;
            if (chunk > sizeof(elf_zero_fill)) chunk = sizeof(elf_zero_fill);
            if (copy_to_user((void *)(uintptr_t)(dest_va + off), elf_zero_fill, chunk) != 0)
                return -15;
            off += chunk;
        }

        if (nseg < 8) {
            seg_va[nseg]    = dest_va;
            seg_memsz[nseg] = p_memsz;
            seg_flags[nseg] = p_flags;
            nseg++;
        }
    }

    /* W^X protection pass. Every page touched by a PT_LOAD segment is set to
     * the union of the permissions of the segments covering it (so a page
     * shared between, say, the end of .text and the start of .rodata keeps
     * whatever each needs). PF_W (0x2) -> writable, PF_X (0x1) -> executable;
     * absence of PF_X sets NX. The pages were just written via copy_to_user so
     * they are present; user_protect_page only downgrades permission bits. */
    for (int s = 0; s < nseg; s++) {
        uint32_t pstart = seg_va[s] & ~0xFFFu;
        uint32_t pend   = seg_va[s] + seg_memsz[s];
        for (uint32_t va = pstart; va < pend; va += 0x1000) {
            int writable = 0, executable = 0;
            for (int k = 0; k < nseg; k++) {
                uint32_t kstart = seg_va[k] & ~0xFFFu;
                uint32_t kend   = seg_va[k] + seg_memsz[k];
                if (va < kend && va + 0x1000u > kstart) {   /* page overlaps seg k */
                    if (seg_flags[k] & 0x2u) writable = 1;  /* PF_W */
                    if (seg_flags[k] & 0x1u) executable = 1;/* PF_X */
                }
            }
            user_protect_page((uint64_t)va, writable, executable);
        }
    }

    uint64_t final_entry = (ei_class == 1) ? ((uint64_t)e_entry32 + slide) : (e_entry64 + slide);
    if (final_entry >= USER_MAX_VADDR) return -14;
    *out_entry = (uint32_t)final_entry;
    return 0;
}

static int do_spawn(void) {
    if (!program_armed) {
        return -1;
    }

    int new_id = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        if (tasks[i].state == 0) {
            new_id = i;
            break;
        }
    }
    if (new_id < 0) {
        return -2;
    }

    uint64_t spawn_entropy = (uint64_t)armed_hdr.size;
    spawn_entropy ^= (uint64_t)armed_hdr.entry << 17;
    spawn_entropy ^= (uint64_t)new_id * 0x9E3779B97F4A7C15ULL;
    spawn_entropy ^= (uint64_t)get_system_ticks() << 11;
    spawn_entropy ^= (uint64_t)get_current_task();
    spawn_entropy ^= read_tsc();
    spawn_entropy ^= rust_rng_u64();

    aslr_mix_entropy(spawn_entropy);


    /* Load base is fixed: userspace binaries are non-PIE (linked at
     * USER_AREA_BASE), so they cannot be relocated. Stack base IS randomized
     * within the mapped low-stack window. */
    uint32_t load_base = USER_AREA_BASE;

    uint32_t stack_top = (uint32_t)aslr_random_stack_top(0x007ff000u);

    create_task(new_id, load_base + armed_hdr.entry, stack_top);

    set_current_task(new_id);
    
    uint32_t entry_point = armed_hdr.entry;
    uint32_t elf_entry = 0;
    int elf_loaded = (try_elf_load(load_base, &elf_entry) == 0);
    if (elf_loaded) {
        entry_point = elf_entry;
    } else {
        
        uint32_t copy_sz = armed_hdr.size;
        if (copy_sz > 0x200000) copy_sz = 0x200000;
        extern platform_info_t platform;
        uint64_t tcr30 = tasks[get_current_task()].cr3;
        if (platform.has_smap) { asm volatile("clac" ::: "memory"); }
        for (uint32_t off = 0; off < copy_sz; ) {
            uint32_t va = load_base + off;
            uint64_t dphys = (uint64_t)va;
            if (tcr30) {
                uint64_t *p4 = (uint64_t *)tcr30;
                uint64_t ii4 = ((uint64_t)va >> 39) & 0x1ff;
                uint64_t ee4 = p4[ii4];
                if (ee4 & 1) {
                    uint64_t *pp3 = (uint64_t *)(ee4 & ~0xfffULL);
                    uint64_t ii3 = ((uint64_t)va >> 30) & 0x1ff;
                    uint64_t ee3 = pp3[ii3];
                    if (ee3 & 1) {
                        uint64_t *pp2 = (uint64_t *)(ee3 & ~0xfffULL);
                        uint64_t ii2 = ((uint64_t)va >> 21) & 0x1ff;
                        uint64_t ee2 = pp2[ii2];
                        if (ee2 & 1) {
                            if (ee2 & (1ULL << 7)) {
                                dphys = (ee2 & ~0x1fffffULL) | ((uint64_t)va & 0x1fffffULL);
                            } else {
                                uint64_t *pp1 = (uint64_t *)(ee2 & ~0xfffULL);
                                uint64_t ii1 = ((uint64_t)va >> 12) & 0x1ff;
                                uint64_t ee1 = pp1[ii1];
                                if (ee1 & 1) {
                                    dphys = (ee1 & ~0xfffULL) | ((uint64_t)va & 0xfffULL);
                                }
                            }
                        }
                    }
                }
            }
            uint8_t *d = (uint8_t *)dphys;
            uint32_t poff = va & 0xfff;
            uint32_t chunk = 4096 - poff;
            if (chunk > copy_sz - off) chunk = copy_sz - off;
            for (uint32_t i = 0; i < chunk; i++) d[i] = loader_staging[off + i];
            off += chunk;
        }
        if (platform.has_smap) { asm volatile("stac" ::: "memory"); }
    }

    
    tasks[new_id].eip = elf_loaded ? entry_point : (load_base + entry_point);

    uint32_t img_end = load_base + ((armed_hdr.size + 0xFFF) & ~0xFFF);
    uint32_t heap_gap = aslr_random_offset(ASLR_MAX_HEAP_GAP_PAGES);
    tasks[new_id].heap_start   = img_end + 0x1000 + heap_gap;
    tasks[new_id].heap_current = tasks[new_id].heap_start;
    tasks[new_id].heap_end     = tasks[new_id].heap_start + 0x10000;

    if (armed_hdr.name[0] != 0) {
        int k = 0;
        while (k < 31 && armed_hdr.name[k]) {
            tasks[new_id].name[k] = armed_hdr.name[k];
            k++;
        }
        tasks[new_id].name[k] = 0;
    } else {
        tasks[new_id].name[0] = 'p'; tasks[new_id].name[1] = 'r';
        tasks[new_id].name[2] = 'o'; tasks[new_id].name[3] = 'g';
        tasks[new_id].name[4] = '0' + new_id; tasks[new_id].name[5] = 0;
    }

    program_armed = 0;

    uint32_t cap6_serial = 0;
    struct capability *creator_admin = cap_lookup(6, CAP_RIGHT_ALL);
    if (creator_admin && creator_admin->type == CAP_USER) {
        cap6_serial = cap_alloc_fresh_serial();
    }
    spin_lock(&cap_lock);
    if (creator_admin && creator_admin->type == CAP_USER) {
        tasks[new_id].cspace[6].type   = CAP_USER;
        tasks[new_id].cspace[6].rights = CAP_RIGHT_ALL;
        tasks[new_id].cspace[6].object = 0;
        tasks[new_id].cspace[6].badge  = creator_admin->serial ? creator_admin->serial : 0xC0DE0006U;
        tasks[new_id].cspace[6].serial = cap6_serial;
        tasks[new_id].cspace[6].generation = creator_admin->generation;
    }
    spin_unlock(&cap_lock);

    return new_id;
}

#ifdef ELF_SELFTEST
/* In-kernel self-test of the ELF loader's W^X enforcement (gated; never in the
 * ship build). Loads a real multi-segment ELF (userspace/elftest.elf, embedded
 * in multiboot.S) through the production do_spawn -> try_elf_load path, then
 * inspects the resulting page-table entries to prove try_elf_load honoured each
 * PT_LOAD's p_flags: .text R+X (executable), .data R+W+NX, .rodata R(O)+NX.
 * Because EFER.NXE is asserted enabled at boot, correct NX/WRITE bits mean the
 * CPU will enforce W^X. Prints ELF_SELFTEST: PASS / FAIL <reason> to serial;
 * the headless smoke test (make smoke-elf) asserts on PASS. */
#define SELFTEST_PTE_PRESENT  (1ULL << 0)
#define SELFTEST_PTE_WRITE    (1ULL << 1)
#define SELFTEST_PTE_USER     (1ULL << 2)
#define SELFTEST_PTE_NX       (1ULL << 63)
#define SELFTEST_PTE_PHYS     0x000FFFFFFFFFF000ULL

static int selftest_read_byte(uint64_t cr3, uint64_t vaddr, uint8_t *out) {
    uint64_t pte = user_lookup_pte(cr3, vaddr);
    if (!(pte & SELFTEST_PTE_PRESENT)) return -1;
    uint64_t phys = (pte & SELFTEST_PTE_PHYS) | (vaddr & 0xFFF);
    *out = *(volatile uint8_t *)(uintptr_t)phys;   /* user phys is identity-mapped under the kernel pml4 */
    return 0;
}

void elf_loader_selftest(void) {
    extern uint8_t embedded_elftest_start[];
    extern uint8_t embedded_elftest_end[];
    uint32_t sz = (uint32_t)(embedded_elftest_end - embedded_elftest_start);

    print("ELF_SELFTEST: begin\n");
    if (sz == 0 || sz > MAX_PROGRAM_SIZE) { print("ELF_SELFTEST: FAIL embed-size\n"); return; }

    /* Stage the raw ELF and arm it; try_elf_load recomputes the real entry. */
    for (uint32_t i = 0; i < sz; i++) loader_staging[i] = embedded_elftest_start[i];
    armed_hdr.entry = 0;
    armed_hdr.size  = sz;
    armed_hdr.name[0] = 'e'; armed_hdr.name[1] = 'l'; armed_hdr.name[2] = 'f';
    armed_hdr.name[3] = 't'; armed_hdr.name[4] = 0;
    program_armed = 1;

    int saved = get_current_task();
    int pid = do_spawn();                 /* runs the real try_elf_load + W^X pass */
    if (pid <= 0) { print("ELF_SELFTEST: FAIL spawn\n"); set_current_task(saved); return; }

    uint64_t cr3 = tasks[pid].cr3;

    /* elftest.ld pins these vaddrs; slide is 0 (min_vaddr == load_base). */
    uint64_t pte_text = user_lookup_pte(cr3, 0x400000);   /* .text   R+X */
    uint64_t pte_data = user_lookup_pte(cr3, 0x401000);   /* .data   R+W */
    uint64_t pte_ro   = user_lookup_pte(cr3, 0x402000);   /* .rodata R   */

    int ok = 1;
    const char *why = "";
    if      (!((pte_text & SELFTEST_PTE_PRESENT) && (pte_text & SELFTEST_PTE_USER))) { ok = 0; why = "text-absent"; }
    else if (!((pte_data & SELFTEST_PTE_PRESENT) && (pte_data & SELFTEST_PTE_USER))) { ok = 0; why = "data-absent"; }
    else if (!((pte_ro   & SELFTEST_PTE_PRESENT) && (pte_ro   & SELFTEST_PTE_USER))) { ok = 0; why = "rodata-absent"; }
    /* W^X execute bits: code executable (NX clear), data/rodata non-exec. */
    else if (pte_text & SELFTEST_PTE_NX)    { ok = 0; why = "text-noexec"; }
    else if (!(pte_data & SELFTEST_PTE_NX)) { ok = 0; why = "data-executable"; }
    else if (!(pte_ro   & SELFTEST_PTE_NX)) { ok = 0; why = "rodata-executable"; }
    /* write bits: data writable, rodata read-only. */
    else if (!(pte_data & SELFTEST_PTE_WRITE)) { ok = 0; why = "data-readonly"; }
    else if (pte_ro & SELFTEST_PTE_WRITE)      { ok = 0; why = "rodata-writable"; }

    /* Content spot-check: segment bytes copied to the correct vaddrs. */
    if (ok) {
        uint8_t b;
        if (selftest_read_byte(cr3, 0x401000, &b) != 0 || b != 0xD2)      { ok = 0; why = "data-marker"; }
        else if (selftest_read_byte(cr3, 0x402000, &b) != 0 || b != 'E')  { ok = 0; why = "rodata-marker"; }
    }

    if (ok) {
        print("ELF_SELFTEST: PASS\n");
    } else {
        print("ELF_SELFTEST: FAIL "); print(why); print("\n");
    }

    /* Free the throwaway task slot so the scheduler never runs it. */
    tasks[pid].state = 0;
    set_current_task(saved);
}
#endif /* ELF_SELFTEST */

static struct user_account *find_user_by_name(const char *name) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && kstrlen(users[i].name) == kstrlen(name)) {
            int match = 1;
            for (size_t j = 0; name[j]; j++) {
                if (users[i].name[j] != name[j]) { match = 0; break; }
            }
            if (match) return &users[i];
        }
    }
    return NULL;
}

static int verify_password(const char *name, const char *pass) {
    return verify_user_password(name, pass);
}


#define IPC_SPIN_LIMIT 200000

int sys_ipc_send(uint32_t ep, const void *msg, size_t len) {
    if (ep >= MAX_ENDPOINTS) return -1;
    if (len > IPC_MSG_MAX) len = IPC_MSG_MAX;
    struct endpoint *e = &endpoints[ep];

    /* Snapshot the authorizing write capability (slot 3) so we can confirm it
     * still holds the same identity after the yield loop below. Strictly
     * additive: if the caller has no such cap at entry we don't newly reject
     * (preserves the in-kernel shell caller); we only abort a send whose
     * authorizing cap was revoked/replaced mid-spin (lookup/use TOCTOU). */
    cap_snapshot_t auth = cap_snapshot(cap_lookup(3, CAP_RIGHT_WRITE));

    long spins = 0;
    while (e->has_message) {
        if (++spins > IPC_SPIN_LIMIT) return -2;
        yield();
    }

    if (auth.valid && !cap_revalidate(3, CAP_RIGHT_WRITE, &auth)) return -1;

    if (len > 0 && copy_from_user(e->msg, msg, len) != 0) return -1;
    e->msg_len = (int)len;
    e->sender_task = get_current_task();
    __asm__ volatile ("" ::: "memory");
    e->has_message = 1;          
    return 0;
}

int sys_ipc_recv(uint32_t ep, void *msg, size_t max_len) {
    if (ep >= MAX_ENDPOINTS) return -1;
    struct endpoint *e = &endpoints[ep];

    /* See sys_ipc_send: snapshot the authorizing read capability and revalidate
     * it after the yield loop so a revoke mid-spin aborts the receive. */
    cap_snapshot_t auth = cap_snapshot(cap_lookup(3, CAP_RIGHT_READ));

    long spins = 0;
    while (!e->has_message) {
        if (++spins > IPC_SPIN_LIMIT) return -2;
        yield();
    }

    if (auth.valid && !cap_revalidate(3, CAP_RIGHT_READ, &auth)) return -1;

    int len = e->msg_len;
    if (len > (int)max_len) len = (int)max_len;
    if (len < 0) len = 0;
    if (len > 0 && copy_to_user(msg, e->msg, (size_t)len) != 0) return -1;

    e->last_sender = e->sender_task;
    __asm__ volatile ("" ::: "memory");
    e->has_message = 0;          
    return len;
}

int sys_ipc_reply(uint32_t ep, const void *msg, size_t len) {

    return sys_ipc_send(ep, msg, len);
}
/* Notifications are not implemented yet. The SYS_NOTIFY / SYS_WAIT_NOTIFY
 * handlers still gate these on a capability (slot 3) before calling in; the
 * distinct SYS_ERR_NOSYS return makes "not implemented" unambiguous to callers
 * rather than colliding with -1 (denied/bad-arg). */
int sys_notify(uint32_t notif_slot, uint32_t badge) {
    (void)notif_slot; (void)badge;
    return SYS_ERR_NOSYS;
}
int sys_wait_notify(uint32_t notif_slot, uint32_t *out_badge) {
    (void)notif_slot; (void)out_badge;
    return SYS_ERR_NOSYS;
}

void syscall_handler64(void)
{
    uint64_t num;
    __asm__ volatile ("" : "=a"(num)); 
    switch ((uint32_t)num) {
        case 0:
            yield();
            __asm__ volatile ("" : : "a"(0));
            break;
        default:
            
            __asm__ volatile ("" : : "a"(-38) );
            break;
    }
}

/* ------------------------------------------------------------------------- *
 *  Per-syscall handlers.
 *
 *  Each handler is the extracted body of one dispatch case, so the switch in
 *  syscall_handler() is a thin table of one-liners and every syscall can be
 *  audited in isolation. This is a behaviour-preserving move: switch-level
 *  `break` became `return` (inner loop break/continue are unchanged), and the
 *  shared in_kernel bookkeeping still brackets the dispatch in syscall_handler.
 * ------------------------------------------------------------------------- */

/* SYS_GET_LINE (3): read a line from the console into the caller's buffer. */
static void h_get_line(struct regs *r) {
    struct capability *c = cap_lookup(8, CAP_RIGHT_READ);
    if (!c) c = cap_lookup(3, CAP_RIGHT_READ);
    if (!c) { r->eax = -1; return; }

    void *user_dest = (void *)(addr_t)r->ebx;
    uint32_t max_len = 127;
    char line[128];
    uint32_t len = 0;
    char ch;

    while (len < max_len) {
        ch = console_getc();

        if (ch == '\r' || ch == '\n') {
            print("\n");
            break;
        }

#ifdef DEBUG_SHELL
        if (ch == 0x1B) {
            while ((inb(0x3FD) & 1) == 0) { yield(); }
            char seq1 = inb(0x3F8);
            while ((inb(0x3FD) & 1) == 0) { yield(); }
            char seq2 = inb(0x3F8);

            if (seq1 == '[') {
                if (seq2 == 'A') {
                    if (history_count > 0) {
                        if (history_pos < 0) history_pos = history_count - 1;
                        else if (history_pos > 0) history_pos--;

                        for (uint32_t i = 0; i < len; i++) {
                            print("\b \b");
                        }
                        len = 0;
                        while (cmd_history[history_pos][len] && len < max_len - 1) {
                            line[len] = cmd_history[history_pos][len];
                            char echo[2] = {line[len], 0};
                            print(echo);
                            len++;
                        }
                        line[len] = 0;
                    }
                } else if (seq2 == 'B') {
                    if (history_pos >= 0) {
                        history_pos++;
                        if (history_pos >= history_count) {
                            history_pos = -1;
                            for (uint32_t i = 0; i < len; i++) print("\b \b");
                            len = 0;
                            line[0] = 0;
                        } else {
                            for (uint32_t i = 0; i < len; i++) print("\b \b");
                            len = 0;
                            while (cmd_history[history_pos][len] && len < max_len - 1) {
                                line[len] = cmd_history[history_pos][len];
                                char echo[2] = {line[len], 0};
                                print(echo);
                                len++;
                            }
                            line[len] = 0;
                        }
                    }
                }
            }
            continue;
        }
#endif
        if ((unsigned char)ch < 32 && ch != '\b' && ch != 0x7F) {
            continue;
        }

        if (ch == '\b' || ch == 0x7F) {
            if (len > 0) {
                len--;
                print("\b \b");
            }
            continue;
        }

        char echo[2] = {ch, 0};
        print(echo);
        line[len++] = ch;
    }

    line[len] = 0;

#ifdef DEBUG_SHELL
    if (len > 0) {
        if (history_count == HISTORY_SIZE) {
            for (int i = 0; i < HISTORY_SIZE - 1; i++) {
                for (int j = 0; j < CMD_MAX; j++) {
                    cmd_history[i][j] = cmd_history[i+1][j];
                }
            }
            history_count--;
        }
        for (uint32_t j = 0; j < CMD_MAX && j <= len; j++) {
            cmd_history[history_count][j] = line[j];
        }
        history_count++;
    }
    history_pos = -1;
#endif

    if (copy_to_user(user_dest, line, len + 1) != 0) {
        r->eax = -1;
    } else {
        r->eax = len;
    }
}

/* SYS_GET_SYSINFO (6): copy a zero-padded version string to the caller. */
static void h_sysinfo(struct regs *r) {
    const char *info = "Horus v0.4 | per-task paging + cspaces | Rust validators";
    /* Copy a zero-padded fixed-size buffer rather than 64 bytes straight
     * off the string literal: the literal is shorter than 64 bytes, so
     * the old copy leaked ~7 bytes of adjacent .rodata to userspace. */
    char infobuf[64];
    size_t ii = 0;
    for (; ii < sizeof(infobuf) - 1 && info[ii]; ii++) infobuf[ii] = info[ii];
    for (; ii < sizeof(infobuf); ii++) infobuf[ii] = 0;
    if (copy_to_user((void*)(addr_t)r->ebx, infobuf, sizeof(infobuf)) == 0) {
        r->eax = 0;
    } else {
        r->eax = -1;
    }
}

/* SYS_SBRK (10): grow/shrink the caller's heap within its fixed bounds. */
static void h_sbrk(struct regs *r) {
    int32_t increment = (int32_t)r->ebx;
    if (increment == 0) {
        r->eax = tasks[get_current_task()].heap_current;
        return;
    }

    uint32_t new_current = tasks[get_current_task()].heap_current + increment;
    if (new_current > tasks[get_current_task()].heap_end || new_current < tasks[get_current_task()].heap_start) {
        r->eax = 0;
    } else {
        uint32_t old = tasks[get_current_task()].heap_current;
        tasks[get_current_task()].heap_current = new_current;
        r->eax = old;
    }
}

/* SYS_WRITE (11): write to fd 1 (console). Length clamped to the scratch buf. */
static void h_write(struct regs *r) {
    int fd = r->ebx;
    void *buf = (void*)(addr_t)r->ecx;
    size_t len = r->edx;

    if (fd != 1) { r->eax = -1; return; }

    char kbuf[256];
    size_t to_copy = len > 255 ? 255 : len;
    if (copy_from_user(kbuf, buf, to_copy) != 0) {
        r->eax = -1;
        return;
    }
    kbuf[to_copy] = 0;
    print(kbuf);
    r->eax = to_copy;
}

/* SYS_READ (12): read from fd 0 (console line) or fd>=3 (ramfs, needs slot-3 read). */
static void h_read(struct regs *r) {
    int fd = r->ebx;
    void *buf = (void*)(addr_t)r->ecx;
    size_t len = r->edx;

    if (fd == 0) {
        char line[128];
        uint32_t got = 0;
        while (got < len && got < 127) {
            char ch = console_getc();
            if (ch == '\r' || ch == '\n') { print("\n"); break; }
            if (ch == '\b' || ch == 0x7F) { if (got > 0) { got--; print("\b \b"); } continue; }
            char echo[2] = {ch, 0}; print(echo);
            line[got++] = ch;
        }
        line[got] = 0;
        if (copy_to_user(buf, line, got + 1) != 0) r->eax = -1;
        else r->eax = got;
    } else if (fd >= 3) {
        struct capability *c = cap_lookup(3, CAP_RIGHT_READ);
        if (!c) { r->eax = -1; return; }
        char kbuf[256];
        size_t to_read = len > 255 ? 255 : len;
        int n = ramfs_read(fd, kbuf, to_read);
        if (n > 0) {
            if (copy_to_user(buf, kbuf, n) == 0) r->eax = n;
            else r->eax = -1;
        } else {
            r->eax = n;
        }
    } else {
        r->eax = -1;
    }
}

/* SYS_EXEC (14): create a task at an already-loaded image.
 * Capability (slot 3, WRITE|EXEC) is enforced centrally by the dispatch table. */
static void h_exec(struct regs *r) {
    uint32_t load_base = r->ebx;
    uint32_t entry_offset = r->ecx;
    (void)(r->edx);

    int new_id = -1;
    for (int i = 1; i < MAX_TASKS; i++) {
        if (tasks[i].state == 0) {
            new_id = i;
            break;
        }
    }
    if (new_id < 0) {
        r->eax = -1;
        return;
    }

    create_task(new_id, load_base + entry_offset, DEMO_TASK_STACK_TOP);

    tasks[new_id].heap_start = USER_HEAP_BASE + new_id * 0x10000;
    tasks[new_id].heap_current = tasks[new_id].heap_start;
    tasks[new_id].heap_end = tasks[new_id].heap_start + 0x10000;

    tasks[new_id].name[0] = 's'; tasks[new_id].name[1] = 'p';
    tasks[new_id].name[2] = 'a'; tasks[new_id].name[3] = 'w';
    tasks[new_id].name[4] = 'n'; tasks[new_id].name[5] = '0' + new_id;
    tasks[new_id].name[6] = 0;

    r->eax = new_id;
}

/* SYS_FS_LIST (16): list ramfs entries, honouring the caller's buffer size.
 * Capability (slot 3, READ) is enforced centrally by the dispatch table. */
static void h_fs_list(struct regs *r) {
    void *user_buf = (void*)(addr_t)r->ebx;
    size_t max_len = r->ecx;
    char kbuf[256];
    /* Honour the caller-supplied buffer size: format the listing into at
     * most max_len bytes (capped by the kernel scratch buffer) so the
     * subsequent copy_to_user never writes past the caller's buffer.
     * ramfs_list guarantees a NUL within the size it is given, so
     * n+1 <= cap holds. */
    size_t cap = max_len < sizeof(kbuf) ? max_len : sizeof(kbuf);
    if (cap == 0) { r->eax = 0; return; }
    int n = ramfs_list(kbuf, cap);
    if (n < 0) { r->eax = -1; return; }
    if (copy_to_user(user_buf, kbuf, n+1) == 0) r->eax = n;
    else r->eax = -1;
}

/* SYS_WAIT (17): block until task `tid` exits. */
static void h_wait(struct regs *r) {
    int tid = r->ebx;
    if (tid < 0 || tid >= MAX_TASKS || tid == get_current_task() || tasks[tid].state == 0) {
        r->eax = -1;
        return;
    }

    tasks[tid].waiter = get_current_task();
    tasks[get_current_task()].state = 0;

    while (tasks[get_current_task()].state == 0) {
        yield();
    }

    r->eax = 0;
}

/* SYS_GET_TASK_INFO (18): report task_info for `tid` (self, or any with admin/audit). */
static void h_task_info(struct regs *r) {
    int tid = r->ebx;
    struct task_info *out = (struct task_info*)(addr_t)r->ecx;

    if (tid < 0 || tid >= MAX_TASKS) {
        r->eax = -1;
        return;
    }

    int is_privileged = 0;
    struct capability *c = cap_lookup(6, CAP_RIGHT_ALL);
    if (c && c->type == CAP_USER) is_privileged = 1;
    if (!is_privileged) {
        c = cap_lookup(7, CAP_RIGHT_READ);
        if (c && c->type == CAP_AUDIT) is_privileged = 1;
    }

    if (!is_privileged && tid != get_current_task()) {
        r->eax = -3;
        return;
    }

    struct task_info info;
    for (size_t z = 0; z < sizeof(info); z++) ((uint8_t*)&info)[z] = 0;
    info.id = tid;
    info.state = tasks[tid].state;
    info.uid = tasks[tid].uid;
    info.gid = tasks[tid].gid;
    /* Do NOT leak the page-table physical base to ring-3: it reveals
     * the physical memory layout and aids exploitation. Field is kept
     * for ABI stability but always reported as 0; no consumer uses it. */
    info.cr3 = 0;
    info.heap_used = tasks[tid].heap_current - tasks[tid].heap_start;
    for (int k = 0; k < 31 && tasks[tid].name[k]; k++)
        info.name[k] = tasks[tid].name[k];
    info.name[31] = 0;
    info.eip = tasks[tid].eip;
    info.blocked_on = tasks[tid].blocked_on;
    info.blocked_on_notif = tasks[tid].blocked_on_notif;
    info.in_kernel = tasks[tid].in_kernel;
    info.caps_in_use = tasks[tid].caps_in_use;

    if (copy_to_user(out, &info, sizeof(info)) == 0) r->eax = 0;
    else r->eax = -1;
}

/* SYS_RUN (19): drop the current task to ring 3 at an already-loaded image.
 * Capability (slot 3, WRITE|EXEC) is enforced centrally by the dispatch table. */
static void h_run(struct regs *r) {
    uint32_t load_base = r->ebx;
    uint32_t entry = r->ecx;

    tasks[get_current_task()].heap_current = tasks[get_current_task()].heap_start;

    if (get_current_task() == 0) {
        r->eax = -1;
        return;
    }
    drop_to_ring3(load_base + entry, tasks[get_current_task()].esp);
    r->eax = 0;
}

/* SYS_RECEIVE_PROGRAM: stage a program image and return its header.
 * Capability (slot 3, WRITE|EXEC) is enforced centrally by the dispatch table. */
static void h_receive_program(struct regs *r) {
    void *user_hdr = (void *)(addr_t)r->ebx;
    struct program_header k_hdr;

    int rc = do_receive_program(&k_hdr);
    if (rc != 0) {
        r->eax = rc;
        return;
    }

    if (user_hdr) {
        if (copy_to_user(user_hdr, &k_hdr, sizeof(k_hdr)) != 0) {
            r->eax = -3;
            return;
        }
    }

    r->eax = 0;
}

/* SYS_AUTH: authenticate the calling task as a user (sets uid/gid on success). */
static void h_auth(struct regs *r) {
    uint32_t now = get_system_ticks();

    char uname[32];
    char upass[32];
    if (copy_from_user(uname, (void*)(addr_t)r->ebx, 31) != 0 ||
        copy_from_user(upass, (void*)(addr_t)r->ecx, 31) != 0) {
        r->eax = -1;
        return;
    }
    uname[31] = 0;
    upass[31] = 0;

    /* Global anti-spray cooldown: refuse all auth attempts kernel-wide
     * while it is active, so cycling usernames cannot dodge per-account
     * lockout. Policy + arithmetic live in rust/src/auth.rs. */
    if (rust_auth_global_locked(now)) {
        secure_zero(uname, sizeof(uname));
        secure_zero(upass, sizeof(upass));
        r->eax = -4;
        return;
    }

    struct user_account *u = find_user_by_name(uname);
    if (u && rust_auth_is_locked(u->auth_lockout_until, now)) {
        secure_zero(uname, sizeof(uname));
        secure_zero(upass, sizeof(upass));
        r->eax = -4;
        return;
    }

    if (verify_password(uname, upass)) {
        rust_auth_global_on_success();
        if (u) {
            u->auth_fail_count = 0;
            u->auth_lockout_until = 0;


            tasks[get_current_task()].uid = u->uid;
            tasks[get_current_task()].gid = u->gid;


            {
                char *mat = upass;
                size_t mlen = kstrlen(upass);
                derive_and_store_user_file_key(u->uid, mat, mlen);
            }

            if (r->edx) {
                uint32_t uid = u->uid;
                copy_to_user((void*)(addr_t)r->edx, &uid, sizeof(uid));
            }
            audit_log(AUDIT_AUTH, 0, 0, "login success");
        }
        r->eax = 0;
    } else {
        rust_auth_global_on_failure(now);
        if (u) {
            uint32_t new_count = u->auth_fail_count;
            uint64_t new_lockout = 0;
            rust_auth_on_failure(u->auth_fail_count, now, &new_count, &new_lockout);
            u->auth_fail_count = new_count;
            if (new_lockout) u->auth_lockout_until = (uint32_t)new_lockout;
        }
        audit_log(AUDIT_AUTH, 0, -1, "login failure");
        r->eax = -1;
    }
    /* Don't leave the cleartext password (and username) sitting in the
     * kernel stack frame after authentication completes. */
    secure_zero(uname, sizeof(uname));
    secure_zero(upass, sizeof(upass));
}

/* SYS_SUDO: re-auth the current user, then spawn an armed program as uid 0. */
static void h_sudo(struct regs *r) {
    uint32_t now = get_system_ticks();
    struct user_account *cur_user = NULL;
    uint32_t cur_uid = tasks[get_current_task()].uid;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && users[i].uid == cur_uid) {
            cur_user = &users[i];
            break;
        }
    }
    if (rust_auth_global_locked(now)) {
        r->eax = -4;
        return;
    }
    if (cur_user && rust_auth_is_locked(cur_user->auth_lockout_until, now)) {
        r->eax = -4;
        return;
    }

    char upass[32];
    if (copy_from_user(upass, (void*)(addr_t)r->ebx, 31) != 0) {
        secure_zero(upass, sizeof(upass));
        r->eax = -1;
        return;
    }
    upass[31] = 0;

    struct user_account *cur = cur_user;
    if (!cur) {
        uint32_t cur_uid2 = tasks[get_current_task()].uid;
        for (int i = 0; i < MAX_USERS; i++) {
            if (users[i].valid && users[i].uid == cur_uid2) {
                cur = &users[i];
                break;
            }
        }
    }
    if (!cur) {
        secure_zero(upass, sizeof(upass));
        r->eax = -1;
        return;
    }

    if (!verify_password(cur->name, upass)) {
        rust_auth_global_on_failure(now);
        if (cur_user) {
            uint32_t new_count = cur_user->auth_fail_count;
            uint64_t new_lockout = 0;
            rust_auth_on_failure(cur_user->auth_fail_count, now, &new_count, &new_lockout);
            cur_user->auth_fail_count = new_count;
            if (new_lockout) cur_user->auth_lockout_until = (uint32_t)new_lockout;
        }
        secure_zero(upass, sizeof(upass));
        r->eax = -2;
        return;
    }
    rust_auth_global_on_success();
    if (cur_user) {
        cur_user->auth_fail_count = 0;
        cur_user->auth_lockout_until = 0;
    }


    {
        char *mat = upass;
        size_t mlen = kstrlen(upass);
        derive_and_store_user_file_key(cur->uid, mat, mlen);

    }
    /* Password material is no longer needed past key derivation; clear it
     * from the kernel stack frame on every remaining exit path. */
    secure_zero(upass, sizeof(upass));
    audit_log(AUDIT_SUDO, 0, 0, "sudo success");

    if (!program_armed) {
        r->eax = -3;
        return;
    }

    int pid = do_spawn();
    if (pid > 0) {
        tasks[pid].uid = 0;
        tasks[pid].gid = 0;

        /* Allocate the three fresh serials BEFORE taking cap_lock:
         * cap_alloc_fresh_serial() grabs cap_lock itself and the lock
         * is not recursive, so calling it inside the locked region
         * (as this path previously did) deadlocks the kernel on the
         * first sudo. Same ordering do_spawn uses. */
        uint32_t s3 = cap_alloc_fresh_serial();
        uint32_t s6 = cap_alloc_fresh_serial();
        uint32_t s7 = cap_alloc_fresh_serial();

        spin_lock(&cap_lock);
        tasks[pid].cspace[3].type   = CAP_FRAME;
        /* Least privilege: a memory frame needs only read/write/execute,
         * not the mint/revoke/grant/audit bits CAP_RIGHT_ALL carried.
         * Mask comes from rust/src/auth.rs (single source of truth). */
        tasks[pid].cspace[3].rights = rust_sudo_frame_rights();
        tasks[pid].cspace[3].object = USER_VIRT_BASE;
        tasks[pid].cspace[3].badge  = 0;
        tasks[pid].cspace[3].serial = s3;
        tasks[pid].cspace[3].generation = 0;

        tasks[pid].cspace[6].type   = CAP_USER;
        tasks[pid].cspace[6].rights = CAP_RIGHT_ALL;
        tasks[pid].cspace[6].object = 0;
        tasks[pid].cspace[6].badge  = 0xC0DE0006U;
        tasks[pid].cspace[6].serial = s6;
        tasks[pid].cspace[6].generation = 0;

        tasks[pid].cspace[7].type   = CAP_TCB;
        tasks[pid].cspace[7].rights = CAP_RIGHT_ALL;
        tasks[pid].cspace[7].object = pid;
        tasks[pid].cspace[7].badge  = 0;
        tasks[pid].cspace[7].serial = s7;
        tasks[pid].cspace[7].generation = 0;
        spin_unlock(&cap_lock);
    }
    r->eax = pid;
}

/* SYS_GET_PASS: read a line with masked echo; scrubs the scratch buffer. */
static void h_get_pass(struct regs *r) {
    void *user_buf = (void *)(addr_t)r->ebx;
    uint32_t max_len = r->ecx;
    if (max_len > 127) max_len = 127;

    char line[128];
    uint32_t len = 0;
    char ch;

    while (len < max_len) {
        ch = console_getc();

        if (ch == '\r' || ch == '\n') {
            print("\n");
            break;
        }
        if (ch == '\b' || ch == 0x7F) {
            if (len > 0) { len--; print("\b \b"); }
            continue;
        }
        if ((unsigned char)ch < 32) continue;

        print("*");
        line[len++] = ch;
    }
    line[len] = 0;

    if (copy_to_user(user_buf, line, len + 1) != 0) {
        for (uint32_t i = 0; i < 128; i++) line[i] = 0;
        r->eax = -1;
        return;
    }

    for (uint32_t i = 0; i < 128; i++) line[i] = 0;

    r->eax = len;
}

/* SYS_READ_AUDIT: copy the audit ring buffer to userspace.
 * Capability (slot 7, READ, type CAP_AUDIT) is enforced centrally by the table. */
static void h_read_audit(struct regs *r) {
    struct audit_event *user_events = (struct audit_event *)(addr_t)r->ebx;
    uint32_t max = r->ecx;
    if (max > AUDIT_LOG_SIZE) max = AUDIT_LOG_SIZE;

    uint32_t out = 0;
    uint32_t start = (audit_head + AUDIT_LOG_SIZE - audit_count) % AUDIT_LOG_SIZE;

    for (uint32_t i = 0; i < audit_count && out < max; i++) {
        uint32_t idx = (start + i) % AUDIT_LOG_SIZE;
        if (copy_to_user(&user_events[out], &audit_log_buffer[idx], sizeof(struct audit_event)) == 0) {
            out++;
        }
    }
    r->eax = out;
}

/* SYS_BLOCK_READ: raw block read. The slot-7 CAP_BLOCK_DEV capability is
 * enforced centrally by the dispatch table; the uid==0 gate stays here (its
 * distinct -2 return is part of the ABI). */
static void h_block_read(struct regs *r) {
    uint64_t block = ((uint64_t)r->ebx << 32) | r->ecx;
    void *buf = (void*)(addr_t)r->edx;
    uint32_t len = r->esi;
    if (tasks[get_current_task()].uid != 0) {
        r->eax = -2;
        return;
    }
    uint8_t kbuf[BLOCK_SIZE];
    uint32_t to = len > BLOCK_SIZE ? BLOCK_SIZE : len;
    int rc = storage_block_read(block, kbuf);
    if (rc == 0) {
        if (copy_to_user(buf, kbuf, to) == 0) {
            r->eax = to;
        } else {
            r->eax = -3;
        }
    } else {
        r->eax = rc;
    }
}

/* SYS_BLOCK_WRITE: raw block write. The slot-7 CAP_BLOCK_DEV capability is
 * enforced centrally by the dispatch table; the uid==0 gate stays here (its
 * distinct -2 return is part of the ABI). */
static void h_block_write(struct regs *r) {
    if (tasks[get_current_task()].uid != 0) {
        r->eax = -2;
        return;
    }
    uint64_t block = ((uint64_t)r->ebx << 32) | r->ecx;
    const void *buf = (const void*)(addr_t)r->edx;
    uint32_t len = r->esi;
    uint8_t kbuf[BLOCK_SIZE];
    uint32_t to = len > BLOCK_SIZE ? BLOCK_SIZE : len;
    if (copy_from_user(kbuf, buf, to) != 0) {
        r->eax = -3;
        return;
    }
    int rc = storage_block_write(block, kbuf);
    r->eax = (rc == 0) ? (int)to : rc;
}

/* SYS_REGISTER_FS_SERVER: register the caller as the fs server. The admin
 * capability (slot 6, ALL, type CAP_USER) is enforced centrally by the table;
 * the per-call endpoint-slot lookup stays here. */
static void h_register_fs_server(struct regs *r) {
    uint32_t ep_slot = r->ebx;
    struct capability *ep = cap_lookup(ep_slot, CAP_RIGHT_READ | CAP_RIGHT_WRITE);
    if (!ep || ep->type != CAP_ENDPOINT) {
        r->eax = -2;
        return;
    }
    fs_server_task_id = get_current_task();
    fs_server_listen_ep_idx = ep->object;
    r->eax = 0;
}

/* SYS_CONNECT_FS_SERVER: mint an endpoint cap to the registered fs server. */
static void h_connect_fs_server(struct regs *r) {
    uint32_t dest_slot = r->ebx;
    uint32_t rights = r->ecx;
    if (fs_server_task_id < 0 || fs_server_listen_ep_idx < 0) {
        r->eax = -1;
        return;
    }
    if (dest_slot < 4 || dest_slot >= 256) {
        r->eax = -2;
        return;
    }
    struct capability *dest = &tasks[get_current_task()].cspace[dest_slot];
    dest->type   = CAP_ENDPOINT;
    dest->rights = rights & (CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_GRANT);
    dest->object = fs_server_listen_ep_idx;
    dest->badge  = 0xF51A0000U;
    r->eax = 0;
}

/* ---- Handlers for the remaining syscalls -------------------------------- *
 * Fixed (slot, rights[, type]) capability requirements are declared in
 * syscall_table[] below and enforced centrally before the handler runs, so
 * these bodies no longer repeat that check. Handlers whose authority is
 * dynamic (FS dir-slot from args; cap_mint/transfer/move/revoke target slot)
 * or self-authorizing (auth/sudo) carry SC_NONE and do their own checks. */

/* SYS_YIELD (0). */
static void h_yield(struct regs *r) { (void)r; yield(); }

/* cap mint/transfer/move/revoke (4/8/9/51): authority enforced inside the
 * cap_* primitives (caller_has_authority + per-right checks). */
static void h_cap_mint(struct regs *r) {
    bool ok = cap_mint(r->ebx, r->ecx, r->edx);
    r->eax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_MINT, r->ebx, ok ? 0 : -1, ok ? "cap mint" : "cap mint denied");
}
static void h_cap_transfer(struct regs *r) {
    bool ok = cap_transfer(r->ebx, r->ecx);
    r->eax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_TRANSFER, r->ebx, ok ? 0 : -1, ok ? "cap transfer" : "cap transfer denied");
}
static void h_cap_move(struct regs *r) {
    bool ok = cap_move(r->ebx, r->ecx);
    r->eax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_TRANSFER, r->ebx, ok ? 0 : -1, ok ? "cap move" : "cap move denied");
}
static void h_cap_revoke(struct regs *r) {
    /* The authoritative rights check (CAP_RIGHT_REVOKE on the target, kernel
     * exempt) and the no-ambient-authority guard live in cap_revoke(). */
    bool ok = cap_revoke(r->ebx);
    r->eax = ok ? 0 : -1;
    audit_log(AUDIT_CAP_REVOKE, r->ebx, ok ? 0 : -1, ok ? "cap revoke" : "cap revoke denied");
}

/* clear screen (5): slot-3 WRITE enforced by the table. */
static void h_clear(struct regs *r) {
    clear_screen();
    r->eax = 0;
}

/* debug command exec (7): only meaningful under DEBUG_SHELL. */
static void h_debug_exec(struct regs *r) {
    char cmd[128];
    if (copy_from_user(cmd, (void*)(addr_t)r->ebx, 127) != 0) {
        r->eax = -1;
        return;
    }
    cmd[127] = 0;
#ifdef DEBUG_SHELL
    r->eax = process_user_command(cmd);
#else
    r->eax = -1;
#endif
}

/* ramfs open (13): slot-3 READ enforced by the table. */
static void h_open(struct regs *r) {
    char path[64];
    if (copy_from_user(path, (void*)(addr_t)r->ebx, 63) != 0) {
        r->eax = -1; return;
    }
    path[63] = 0;
    r->eax = ramfs_open(path, 0);
}

/* ramfs create (15): slot-3 WRITE enforced by the table. */
static void h_ramfs_create(struct regs *r) {
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->ebx, 31) != 0) {
        r->eax = -1; return;
    }
    name[31] = 0;
    r->eax = ramfs_create(name, 0);
}

/* SYS_SPAWN (28): slot-3 WRITE|EXEC enforced by the table. */
static void h_spawn(struct regs *r) {
    int pid = do_spawn();
    if (pid > 0) {
        schedule();
    }
    r->eax = pid;
}

/* SYS_GETUID (29). */
static void h_getuid(struct regs *r) {
    r->eax = tasks[get_current_task()].uid;
}

/* SYS_IPC_SEND (21) / SYS_IPC_CALL (23): slot-3 WRITE enforced by the table. */
static void h_ipc_send(struct regs *r) {
    r->eax = sys_ipc_send(r->ebx, (const void*)(addr_t)r->ecx, r->edx);
}
/* SYS_IPC_RECV (22): slot-3 READ enforced by the table. */
static void h_ipc_recv(struct regs *r) {
    r->eax = sys_ipc_recv(r->ebx, (void*)(addr_t)r->ecx, r->edx);
}
/* SYS_IPC_REPLY (24): slot-3 WRITE enforced by the table. */
static void h_ipc_reply(struct regs *r) {
    r->eax = sys_ipc_reply(r->ebx, (const void*)(addr_t)r->ecx, r->edx);
}
/* SYS_NOTIFY (25): slot-3 WRITE enforced by the table. */
static void h_notify(struct regs *r) {
    r->eax = sys_notify(r->ebx, r->ecx);
}
/* SYS_WAIT_NOTIFY (26): slot-3 READ enforced by the table. */
static void h_wait_notify(struct regs *r) {
    uint32_t badge = 0;
    r->eax = sys_wait_notify(r->ebx, &badge);
    r->ebx = badge;
}

/* user management (33/34/35): admin/self check lives in do_useradd/userdel/passwd. */
static void h_useradd(struct regs *r) {
    uint32_t uid = r->ebx;
    uint32_t gid = r->ecx;
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->edx, 31) != 0) {
        r->eax = -1; return;
    }
    name[31] = 0;
    r->eax = do_useradd(uid, gid, name, "");
}
static void h_userdel(struct regs *r) {
    r->eax = do_userdel(r->ebx);
}
static void h_passwd(struct regs *r) {
    uint32_t target = r->ebx;
    char newpass[32];
    if (copy_from_user(newpass, (void*)(addr_t)r->ecx, 31) != 0) {
        r->eax = -1; return;
    }
    newpass[31] = 0;
    r->eax = do_passwd(target, newpass);
}

/* SYS_ROTATE_KEYS (36): slot-8 READ, type CAP_CONSOLE enforced by the table. */
static void h_rotate_keys(struct regs *r) {
    r->eax = (uint32_t)do_rotate_keys();
}

/* FS ops (38-45): authority is the per-call dir/file capability, checked inside
 * the sys_fs_* helpers (slot is an argument, so not table-expressible). */
static void h_fs_mint_file(struct regs *r) {
    r->eax = sys_fs_mint_file(r->ebx, r->ecx, r->edx);
}
static void h_fs_lookup(struct regs *r) {
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->ecx, 31) != 0) { r->eax = -1; return; }
    name[31] = 0;
    r->eax = sys_fs_lookup(r->ebx, name, r->edx, (addr_t)r->esi);
}
static void h_fs_create(struct regs *r) {
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->ecx, 31) != 0) { r->eax = -1; return; }
    name[31] = 0;
    r->eax = sys_fs_create(r->ebx, name, (int)r->edx, (addr_t)r->esi, (addr_t)r->edi);
}
static void h_fs_delete(struct regs *r) {
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->ecx, 31) != 0) { r->eax = -1; return; }
    name[31] = 0;
    r->eax = sys_fs_delete(r->ebx, name);
}
static void h_fs_readdir(struct regs *r) {
    r->eax = sys_fs_readdir(r->ebx, (char *)(addr_t)r->ecx, r->edx);
}
static void h_fs_get_root(struct regs *r) {
    r->eax = sys_fs_get_root(r->ebx, r->ecx);
}
static void h_fs_read(struct regs *r) {
    r->eax = sys_fs_read(r->ebx, (char *)(addr_t)r->ecx, r->edx);
}
static void h_fs_write(struct regs *r) {
    r->eax = sys_fs_write(r->ebx, (const char *)(addr_t)r->ecx, r->edx);
}

/* SYS_REGISTER_STORAGE_BACKEND (46): removed; ABI slot reserved, fails closed.
 * (Used to register a ring-3 fn-ptr the kernel called at CPL0 -- SMEP/TCB hole;
 * a userspace disk driver must be an IPC server, not an in-kernel callback.) */
static void h_register_storage_backend(struct regs *r) {
    r->eax = SYS_ERR_NOSYS;
}

/* ------------------------------------------------------------------------- *
 *  Capability-checked dispatch table.
 *
 *  Every syscall has exactly one entry. syscall_handler() validates the
 *  number, enforces the declared capability in ONE place, then calls the
 *  handler -- so a syscall physically cannot be reached without its check, and
 *  an unknown / reserved number (or a gap such as 1, 2, 20) fails closed.
 *
 *  slot == SC_NONE means there is no single fixed authorizing capability: the
 *  handler (or the helper it calls) performs its own authorization, noted per
 *  entry. A few entries declare the fixed part here and keep an extra,
 *  argument-dependent check in the handler (block uid==0, register-fs ep slot).
 * ------------------------------------------------------------------------- */
#define SC_NONE     0xFFFFu
#define SC_ANYTYPE  (-1)

typedef struct {
    void   (*fn)(struct regs *r);
    uint16_t slot;     /* authorizing cspace slot, or SC_NONE */
    uint32_t rights;   /* rights required at `slot` */
    int      ctype;    /* required capability type, or SC_ANYTYPE */
} syscall_desc_t;

#define SYSCALL_TABLE_SIZE 52

static const syscall_desc_t syscall_table[SYSCALL_TABLE_SIZE] = {
    [0]                            = { h_yield,                   SC_NONE, 0, SC_ANYTYPE },
    [SYS_GET_LINE]                 = { h_get_line,                SC_NONE, 0, SC_ANYTYPE }, /* slot 8 or 3 READ (fallback in handler) */
    [4]                            = { h_cap_mint,                SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_mint */
    [5]                            = { h_clear,                   3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [6]                            = { h_sysinfo,                 SC_NONE, 0, SC_ANYTYPE }, /* ambient version string */
    [7]                            = { h_debug_exec,              SC_NONE, 0, SC_ANYTYPE }, /* DEBUG_SHELL only */
    [8]                            = { h_cap_transfer,            SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_transfer */
    [9]                            = { h_cap_move,                SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_move */
    [SYS_SBRK]                     = { h_sbrk,                    SC_NONE, 0, SC_ANYTYPE }, /* own heap, bounds-checked */
    [SYS_WRITE]                    = { h_write,                   SC_NONE, 0, SC_ANYTYPE }, /* ambient console (fd 1) */
    [SYS_READ]                     = { h_read,                    SC_NONE, 0, SC_ANYTYPE }, /* fd 0 ambient; fd>=3 slot-3 READ in handler */
    [SYS_OPEN]                     = { h_open,                    3, CAP_RIGHT_READ, SC_ANYTYPE },
    [14]                           = { h_exec,                    3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [15]                           = { h_ramfs_create,            3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [16]                           = { h_fs_list,                 3, CAP_RIGHT_READ, SC_ANYTYPE },
    [SYS_WAIT]                     = { h_wait,                    SC_NONE, 0, SC_ANYTYPE },
    [SYS_GET_TASK_INFO]            = { h_task_info,               SC_NONE, 0, SC_ANYTYPE }, /* self, or admin/audit in handler */
    [SYS_EXEC]                     = { h_run,                     3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_IPC_SEND]                 = { h_ipc_send,                3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [SYS_IPC_RECV]                 = { h_ipc_recv,                3, CAP_RIGHT_READ,  SC_ANYTYPE },
    [SYS_IPC_CALL]                 = { h_ipc_send,                3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [SYS_IPC_REPLY]                = { h_ipc_reply,               3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [SYS_NOTIFY]                   = { h_notify,                  3, CAP_RIGHT_WRITE, SC_ANYTYPE },
    [SYS_WAIT_NOTIFY]              = { h_wait_notify,             3, CAP_RIGHT_READ,  SC_ANYTYPE },
    [SYS_RECEIVE_PROGRAM]          = { h_receive_program,         3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_SPAWN]                    = { h_spawn,                   3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE },
    [SYS_GETUID]                   = { h_getuid,                  SC_NONE, 0, SC_ANYTYPE },
    [SYS_AUTH]                     = { h_auth,                    SC_NONE, 0, SC_ANYTYPE }, /* self-authorizing */
    [SYS_SUDO]                     = { h_sudo,                    SC_NONE, 0, SC_ANYTYPE }, /* re-auth in handler */
    [SYS_GET_PASS]                 = { h_get_pass,                SC_NONE, 0, SC_ANYTYPE },
    [SYS_USERADD]                  = { h_useradd,                 SC_NONE, 0, SC_ANYTYPE }, /* admin check in do_useradd */
    [SYS_USERDEL]                  = { h_userdel,                 SC_NONE, 0, SC_ANYTYPE }, /* admin check in do_userdel */
    [SYS_PASSWD]                   = { h_passwd,                  SC_NONE, 0, SC_ANYTYPE }, /* admin/self in do_passwd */
    [SYS_ROTATE_KEYS]              = { h_rotate_keys,             8, CAP_RIGHT_READ, CAP_CONSOLE },
    [SYS_READ_AUDIT]               = { h_read_audit,              7, CAP_RIGHT_READ, CAP_AUDIT },
    [SYS_FS_MINT_FILE]             = { h_fs_mint_file,            SC_NONE, 0, SC_ANYTYPE }, /* dir cap in sys_fs_* */
    [SYS_FS_LOOKUP]                = { h_fs_lookup,               SC_NONE, 0, SC_ANYTYPE },
    [SYS_FS_CREATE]                = { h_fs_create,               SC_NONE, 0, SC_ANYTYPE },
    [SYS_FS_DELETE]                = { h_fs_delete,               SC_NONE, 0, SC_ANYTYPE },
    [SYS_FS_READDIR]               = { h_fs_readdir,              SC_NONE, 0, SC_ANYTYPE },
    [SYS_FS_GET_ROOT]              = { h_fs_get_root,             SC_NONE, 0, SC_ANYTYPE },
    [SYS_FS_READ]                  = { h_fs_read,                 SC_NONE, 0, SC_ANYTYPE },
    [SYS_FS_WRITE]                 = { h_fs_write,                SC_NONE, 0, SC_ANYTYPE },
    [SYS_REGISTER_STORAGE_BACKEND] = { h_register_storage_backend, SC_NONE, 0, SC_ANYTYPE },
    [SYS_BLOCK_READ]               = { h_block_read,              7, CAP_BLOCK_DEV, SC_ANYTYPE }, /* + uid 0 in handler */
    [SYS_BLOCK_WRITE]              = { h_block_write,             7, CAP_BLOCK_DEV, SC_ANYTYPE }, /* + uid 0 in handler */
    [SYS_REGISTER_FS_SERVER]       = { h_register_fs_server,      6, CAP_RIGHT_ALL, CAP_USER }, /* + ep lookup in handler */
    [SYS_CONNECT_FS_SERVER]        = { h_connect_fs_server,       SC_NONE, 0, SC_ANYTYPE },
    [SYS_CAP_REVOKE]               = { h_cap_revoke,              SC_NONE, 0, SC_ANYTYPE }, /* authority in cap_revoke */
};

/* Compile-time guard: the table must have a slot for every syscall number, so
 * no defined syscall can index past it and fall through the
 * `num < SYSCALL_TABLE_SIZE` bound into the deny path by accident.
 * SYS_CAP_REVOKE is currently the highest syscall number. Adding a higher one
 * (or shrinking the table) breaks the build here and forces you to grow
 * SYSCALL_TABLE_SIZE -- which lands you right next to the entries you must
 * fill in. (C cannot check the function pointer itself in a static assert; a
 * still-missing entry stays NULL and fails closed at runtime, and adding an
 * entry past the array bound is already a hard compiler error.) */
_Static_assert(SYSCALL_TABLE_SIZE == SYS_CAP_REVOKE + 1,
               "syscall_table size must equal (highest syscall number + 1): "
               "grow SYSCALL_TABLE_SIZE and add the new entry when adding a syscall");

void syscall_handler(struct regs *r) {
    if (get_current_task() < MAX_TASKS) {
        tasks[get_current_task()].in_kernel = 1;
    }

    uint32_t num = r->eax;
    const syscall_desc_t *d = (num < SYSCALL_TABLE_SIZE) ? &syscall_table[num] : (const syscall_desc_t *)0;

    if (!d || !d->fn) {
        /* Unknown, reserved, or unimplemented syscall number: fail closed. */
        r->eax = -1;
    } else if (d->slot != SC_NONE) {
        /* Central capability gate: a syscall cannot run without its declared
         * capability. Handlers no longer repeat this check. */
        struct capability *c = cap_lookup(d->slot, d->rights);
        if (!c || (d->ctype != SC_ANYTYPE && (int)c->type != d->ctype)) {
            r->eax = -1;
        } else {
            d->fn(r);
        }
    } else {
        d->fn(r);
    }

    if (get_current_task() < MAX_TASKS) {
        tasks[get_current_task()].in_kernel = 0;
    }
}

#ifdef DEBUG_SHELL
int process_user_command(const char *cmd) {
    while (*cmd == ' ') cmd++;

    if (cmd[0] == 0 || cmd[0] == '\n' || cmd[0] == '\r') {
        return 0;
    }

    
    if (kstrcmp(cmd, "help") == 0 || kstrcmp(cmd, "man") == 0 || cmd[0] == '?') {
        show_general_help();
        return 0;
    }
    if (kstrncmp(cmd, "help ", 5) == 0 || kstrncmp(cmd, "man ", 4) == 0 ||
        (cmd[0] == '?' && (cmd[1] == ' ' || cmd[1] == 0))) {
        const char *topic = cmd;
        if (cmd[0] == 'h') topic += 5;
        else if (cmd[0] == 'm') topic += 4;
        else topic += 1; 
        show_topic_help(topic);
        return 0;
    }

    int action = rust_handle_command((const uint8_t *)cmd, kstrlen(cmd));
    if (action == 43) {
        set_text_colour(0x0A);
        println("Horus v0.4 - x86 microkernel (per-task isolation + Rust policy)");
        set_text_colour(0x0F);
        return 0;
    }
    if (action == 45) {
        uint32_t ticks = get_system_ticks();
        print("Uptime: "); print_hex(ticks); println(" ticks");
        return 0;
    }
    if (action == 46) {
        
        bool can_see_all = has_console_cap();
        set_text_colour(0x0B);
        println("PID  UID    NAME            STATE  HEAP      CAPS  FLAGS");
        set_text_colour(0x0F);
        int cur = get_current_task();
        for (int i = 0; i < MAX_TASKS; i++) {
            if (tasks[i].state != 0) {
                if (!can_see_all && i != cur) continue;
                if (i < 10) print(" ");
                print_decimal(i);
                print("   ");
                /* UID, right-padded to a 7-col field (0 shown as root). */
                if (tasks[i].uid == 0) { print("root  "); }
                else { print_decimal(tasks[i].uid); for (int sp = (tasks[i].uid < 10 ? 1 : (tasks[i].uid < 100 ? 2 : (tasks[i].uid < 1000 ? 3 : 4))); sp < 6; sp++) print(" "); }
                print(" ");
                print(tasks[i].name);
                int nlen = 0; while (tasks[i].name[nlen]) nlen++;
                for (int sp = nlen; sp < 16; sp++) print(" ");
                /* Named state from the Rust ps policy (run/blkd/dead/?). */
                const char *sn = rust_task_state_name(tasks[i].state);
                print(sn);
                for (int sp = 0; sn[sp]; sp++) { /* pad name col */ }
                int snlen = 0; while (sn[snlen]) snlen++;
                for (int sp = snlen; sp < 7; sp++) print(" ");
                print_decimal(tasks[i].heap_current - tasks[i].heap_start);
                print("      ");
                print_decimal(tasks[i].caps_in_use);
                print("    ");
                if (tasks[i].in_kernel) print("K ");
                if (tasks[i].blocked_on >= 0) { print("B"); print_decimal(tasks[i].blocked_on); }
                else if (tasks[i].blocked_on_notif >= 0) print("N");
                println("");
            }
        }
        if (!can_see_all) {
            set_text_colour(0x0E);
            println("(Limited view: CAP_CONSOLE required for full system ps)");
            set_text_colour(0x0F);
        }
        return 0;
    }
    if (action == 47) {
        struct capability *cspace = tasks[get_current_task()].cspace;
        uint32_t size = tasks[get_current_task()].cspace_size ? tasks[get_current_task()].cspace_size : 256;

        print("Caps for task "); print_hex(get_current_task()); println(":");

        for (uint32_t i = 0; i < size && i < 16; i++) {
            struct capability *c = &cspace[i];
            if (c->type != CAP_NULL) {
                print("  ["); print_hex(i);
                print("] type="); print_hex(c->type);
                print(" rights="); print_hex(c->rights);
                print(" obj="); print_hex(c->object);
                println("");
            }
        }
        return 0;
    }
    if (action == 48) {
        struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE);
        if (!c) return -1;
        clear_screen();
        return 0;
    }
    if (action == 49) {
        
        if (!has_console_cap()) {
            println("Permission denied (CAP_CONSOLE required in slot 8)");
            return -1;
        }
        uint32_t id = 0;
        const char *p = cmd + 5;
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { id = id * 10 + (*p - '0'); p++; }

        if (id == 0 || id >= MAX_TASKS) {
            println("Invalid task id");
            return -1;
        }
        if (tasks[id].state == 0) {
            println("Task already dead");
            return 0;
        }
        if (tasks[id].waiter >= 0) {
            int w = tasks[id].waiter;
            if (tasks[w].state == 0) tasks[w].state = 1;
            tasks[id].waiter = -1;
        }

        tasks[id].state = 0;
        print("Killed "); print_hex(id); println("");
        if ((int)id == get_current_task()) schedule();
        return 0;
    }
    if (action == 1) {
        
        if (!has_console_cap()) {
            println("Permission denied (CAP_CONSOLE required for exit)");
            return -1;
        }
        println("Exiting...");
        qemu_exit(0);
        return 0;
    }

    if (action == 44) {
        const char *arg = cmd + 5;
        while (*arg == ' ') arg++;
        print(arg);
        println("");
        return 0;
    }
    if (action == 50) {
        uint32_t dest = 0, src = 0, rights = 0;
        const char *p = cmd + 5;
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { dest = dest * 10 + (*p - '0'); p++; }
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { src = src * 10 + (*p - '0'); p++; }
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { rights = rights * 10 + (*p - '0'); p++; }

        if (cap_mint(dest, src, rights)) {
            println("mint ok");
            return 0;
        } else {
            println("mint failed");
            return -1;
        }
    }

    if (action == 36) {
        
        if (!has_console_cap()) {
            println("Permission denied (CAP_CONSOLE required for rotate_keys)");
            return -1;
        }
        if (get_current_task() != 0 && !has_encrypted_storage_cap()) {
            println("Permission denied (CAP_ENCRYPTED_STORAGE required for rotate_keys)");
            return -1;
        }
        int n = do_rotate_keys();
        print("Rotated "); print_decimal((uint32_t)n); println(" blocks");
        return 0;
    }

    if (cmd[0] == 'y' && cmd[1] == 'i' && cmd[2] == 'e' && cmd[3] == 'l' && cmd[4] == 'd' &&
        (cmd[5] == 0 || cmd[5] == ' ')) {
        yield();
        return 0;
    }

    if (kstrcmp(cmd, "dmesg") == 0 || kstrcmp(cmd, "log") == 0) {
        
        if (!has_console_cap()) {
            println("Permission denied (CAP_CONSOLE required for dmesg)");
            return -1;
        }
        dump_kernel_log();
        return 0;
    }

    if (cmd[0] == 'l' && cmd[1] == 'o' && cmd[2] == 'a' && cmd[3] == 'd' && cmd[4] == 0) {
        struct capability *c = cap_lookup(3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC);
        if (!c) {
            println("Permission denied (need FRAME cap slot 3)");
            return -1;
        }
        if (!has_console_cap()) {
            println("Permission denied (CAP_CONSOLE also required to load/spawn)");
            return -1;
        }

        println("");
        println("QEMU VGA window shows output (close it with WM X; does not kill your shell tab).");
        println("Kernel shell is on 4445 (use this or another terminal): nc localhost 4445");
        println("Loader (for the program image) is on 4444 (second terminal):");
        println("  From Horus root: cat userspace/shell.bin | nc localhost 4444");
        println("  Inside userspace/: cat shell.bin | nc localhost 4444");
        println("Waiting on 4444 for the binary...");
        struct program_header h;
        int r = do_receive_program(&h);
        if (r != 0) {
            println("Receive failed or bad header");
            return -1;
        }
        print("Received '"); print(h.name); print("' ");
        print_decimal(h.size); println(" bytes - spawning...");
        int pid = do_spawn();
        if (pid > 0) {
            
            schedule();
            print("Spawned pid="); print_decimal(pid); println(" (revivable on fault)");
            return 0;
        } else {
            println("Spawn failed after receive");
            return -1;
        }
    }

    println("Unknown command. Type 'help' or 'help <cmd>' for usage.");
    return -1;
}
#endif

void spawn_initial_userspace_shell(void) {
    extern uint8_t embedded_shell_bin_start[];
    extern uint8_t embedded_shell_bin_end[];
    uint32_t full_sz = (uint32_t)(embedded_shell_bin_end - embedded_shell_bin_start);
    if (full_sz < 44) return;
    const uint8_t *bin = embedded_shell_bin_start;
    uint32_t magic = *(const uint32_t *)bin;
    uint32_t h_entry = *(const uint32_t *)(bin + 4);
    uint32_t h_size = *(const uint32_t *)(bin + 8);
    if (magic != 0x55524F48) return;
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) return;
    if (full_sz < 44 + h_size) h_size = full_sz - 44;
    armed_hdr.entry = h_entry;
    armed_hdr.size = h_size;
    const uint8_t *payload = bin + 44;
    for (uint32_t i = 0; i < h_size; i++) {
        loader_staging[i] = payload[i];
    }
    program_armed = 1;
    int pid = do_spawn();
    if (pid > 0) {
        uint32_t s8 = 0;
        uint32_t s9 = 0;
        if (tasks[0].cspace[8].type != CAP_NULL) s8 = cap_alloc_fresh_serial();
        if (tasks[0].cspace[9].type != CAP_NULL) s9 = cap_alloc_fresh_serial();
        spin_lock(&cap_lock);
        if (tasks[0].cspace && tasks[pid].cspace) {
            if (tasks[0].cspace[8].type != CAP_NULL) {
                tasks[pid].cspace[8] = tasks[0].cspace[8];
                tasks[pid].cspace[8].serial = s8;
            }
            if (tasks[0].cspace[9].type != CAP_NULL) {
                tasks[pid].cspace[9] = tasks[0].cspace[9];
                tasks[pid].cspace[9].serial = s9;
            }
        }
        spin_unlock(&cap_lock);


        {
            uint64_t rip = (uint64_t)tasks[pid].eip;
            uint64_t rspv = tasks[pid].esp ? (uint64_t)tasks[pid].esp : 0x007ff000ULL;
            uint64_t ucr3 = tasks[pid].cr3;
            uintptr_t kst = tasks[pid].kernel_stack_top ? tasks[pid].kernel_stack_top : KERNEL_TSS_STACK;
            set_tss_kernel_stack(kst);
            set_current_task(pid);
            __asm__ volatile (
                "mov %2, %%cr3\n\t"
                "mov $0x33, %%ax\n\t"
                "mov %%ax, %%ds\n\t mov %%ax, %%es\n\t mov %%ax, %%fs\n\t mov %%ax, %%gs\n\t"
                "mov %1, %%rsp\n\t"
                "pushq $0x33\n\t pushq %1\n\t pushq $0x2b\n\t pushq %0\n\t lretq\n\t"
                :: "r"(rip), "r"(rspv), "r"(ucr3) : "memory", "rax"
            );
        }
    }
}
