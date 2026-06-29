#ifndef USERSPACE_SYSCALL_H
#define USERSPACE_SYSCALL_H

#include <stdint.h>
#include <stddef.h>

struct task_info {
    uint32_t id;
    uint32_t state;
    uint32_t cr3;
    uint32_t heap_used;
    char     name[32];
    uint32_t eip;
    int      blocked_on;
    int      blocked_on_notif;
    int      in_kernel;
    uint32_t caps_in_use;
};

struct program_header {
    uint32_t magic;
    uint32_t entry;
    uint32_t size;
    char     name[32];
};

struct audit_event {
    uint32_t timestamp;
    uint32_t type;
    uint32_t subject_uid;
    uint32_t subject_task;
    uint32_t object;
    uint32_t result;
    char     message[48];
};

#define SYS_YIELD           0
#define SYS_PRINT           1
#define SYS_EXIT            2
#define SYS_GET_LINE        3
#define SYS_SBRK            10
#define SYS_WRITE           11
#define SYS_READ            12
#define SYS_OPEN            13
#define SYS_WAIT            17
#define SYS_GET_TASK_INFO   18
#define SYS_EXEC            19
#define SYS_GETPID          20

#define SYS_IPC_SEND   21
#define SYS_IPC_RECV   22
#define SYS_IPC_CALL   23
#define SYS_IPC_REPLY  24

#define SYS_NOTIFY          25
#define SYS_WAIT_NOTIFY     26
#define SYS_RECEIVE_PROGRAM 27
#define SYS_SPAWN           28

#define SYS_GETUID   29
#define SYS_AUTH     30
#define SYS_SUDO     31
#define SYS_GET_PASS 32

#define SYS_USERADD   33
#define SYS_USERDEL   34
#define SYS_PASSWD    35
#define SYS_ROTATE_KEYS   36  
#define SYS_READ_AUDIT    37
#define SYS_FS_MINT_FILE  38
#define SYS_FS_LOOKUP     39
#define SYS_FS_CREATE     40
#define SYS_FS_DELETE     41
#define SYS_FS_READDIR    42
#define SYS_FS_GET_ROOT   43
#define SYS_FS_READ       44
#define SYS_FS_WRITE      45
#define SYS_REGISTER_STORAGE_BACKEND 46
#define SYS_BLOCK_READ   47
#define SYS_BLOCK_WRITE  48
#define SYS_REGISTER_FS_SERVER 49
#define SYS_CONNECT_FS_SERVER  50

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
#define AUDIT_FS_LOOKUP     20
#define AUDIT_FS_CREATE     21
#define AUDIT_FS_DELETE     22
#define AUDIT_FS_READ       23
#define AUDIT_FS_WRITE      24
#define AUDIT_IPC_GRANT     30
#define AUDIT_TASK_CREATE   40
#define AUDIT_TASK_EXIT     41

static inline uint32_t syscall(uint32_t num, uint32_t a, uint32_t b, uint32_t c) {
    uint32_t ret;
    asm volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(a), "c"(b), "d"(c)
        : "memory"
    );
    return ret;
}

static inline uint32_t syscall6(uint32_t num, uint32_t a, uint32_t b, uint32_t c,
                                 uint32_t d, uint32_t e, uint32_t f) {
    uint32_t ret;
    asm volatile (
        "movl %5, %%esi\n"
        "movl %6, %%edi\n"
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(a), "c"(b), "d"(c), "r"(d), "r"(e), "r"(f)
        : "esi", "edi", "memory"
    );
    return ret;
}

static inline void sys_yield(void) {
    syscall(SYS_YIELD, 0, 0, 0);
}

static inline int sys_print(const char *s) {
    return syscall(SYS_PRINT, (uint32_t)s, 0, 0);
}

static inline void sys_exit(void) {
    syscall(SYS_EXIT, 0, 0, 0);
    for(;;);
}

static inline int sys_get_line(char *buf, size_t max) {
    return syscall(SYS_GET_LINE, (uint32_t)buf, max, 0);
}

static inline void *sys_sbrk(intptr_t increment) {
    return (void*)syscall(SYS_SBRK, (uint32_t)increment, 0, 0);
}

static inline int sys_write(int fd, const void *buf, size_t len) {
    return syscall(SYS_WRITE, (uint32_t)fd, (uint32_t)buf, (uint32_t)len);
}

static inline int sys_read(int fd, void *buf, size_t len) {
    return syscall(SYS_READ, (uint32_t)fd, (uint32_t)buf, (uint32_t)len);
}

static inline int sys_open(const char* path) {
    return syscall(SYS_OPEN, (uint32_t)path, 0, 0);
}

static inline int sys_wait(int task_id) {
    return syscall(SYS_WAIT, (uint32_t)task_id, 0, 0);
}

static inline int sys_get_task_info(int id, struct task_info *out) {
    return syscall(SYS_GET_TASK_INFO, (uint32_t)id, (uint32_t)out, 0);
}

static inline int sys_exec(uint32_t load_base, uint32_t entry) {
    return syscall(SYS_EXEC, load_base, entry, 0);
}

static inline int sys_getpid(void) {
    return syscall(SYS_GETPID, 0, 0, 0);
}

static inline int sys_ipc_send(int ep_slot, const void *msg, size_t len) {
    return syscall(SYS_IPC_SEND, (uint32_t)ep_slot, (uint32_t)msg, (uint32_t)len);
}

static inline int sys_ipc_recv(int ep_slot, void *msg, size_t max_len) {
    return syscall(SYS_IPC_RECV, (uint32_t)ep_slot, (uint32_t)msg, (uint32_t)max_len);
}

static inline int sys_ipc_call(int ep_slot, const void *send_msg, size_t send_len,
                               void *recv_msg, size_t recv_max) {
    (void)recv_msg; (void)recv_max;
    return syscall(SYS_IPC_CALL, (uint32_t)ep_slot, (uint32_t)send_msg, send_len);
}

static inline int sys_ipc_reply(int ep_slot, const void *msg, size_t len) {
    return syscall(SYS_IPC_REPLY, (uint32_t)ep_slot, (uint32_t)msg, (uint32_t)len);
}

static inline int sys_notify(int notif_slot, uint32_t badge) {
    return syscall(SYS_NOTIFY, (uint32_t)notif_slot, badge, 0);
}

static inline int sys_wait_notify(int notif_slot, uint32_t *out_badge) {
    return syscall(SYS_WAIT_NOTIFY, (uint32_t)notif_slot, (uint32_t)out_badge, 0);
}

static inline int sys_receive_program(struct program_header *hdr_out) {
    return syscall(SYS_RECEIVE_PROGRAM, (uint32_t)hdr_out, 0, 0);
}

static inline int sys_spawn(void) {
    return syscall(SYS_SPAWN, 0, 0, 0);
}

static inline uint32_t sys_getuid(void) {
    return syscall(SYS_GETUID, 0, 0, 0);
}

static inline int sys_auth(const char *user, const char *pass, uint32_t *out_uid) {
    return syscall(SYS_AUTH, (uint32_t)user, (uint32_t)pass, (uint32_t)out_uid);
}

static inline int sys_sudo(const char *pass) {
    return syscall(SYS_SUDO, (uint32_t)pass, 0, 0);
}

static inline int sys_get_pass(char *buf, size_t max) {
    return syscall(SYS_GET_PASS, (uint32_t)buf, max, 0);
}

static inline int sys_useradd(uint32_t uid, uint32_t gid, const char *name) {
    return syscall(SYS_USERADD, uid, gid, (uint32_t)name);
}

static inline int sys_userdel(uint32_t uid) {
    return syscall(SYS_USERDEL, uid, 0, 0);
}

static inline int sys_passwd(uint32_t target_uid, const char *newpass) {
    return syscall(SYS_PASSWD, target_uid, (uint32_t)newpass, 0);
}

static inline int sys_rotate_keys(void) {

    return syscall(SYS_ROTATE_KEYS, 0, 0, 0);
}

static inline int sys_read_audit(struct audit_event *events, uint32_t max_events) {
    return syscall(SYS_READ_AUDIT, (uint32_t)events, max_events, 0);
}

static inline int sys_fs_mint_file(uint32_t dir_slot, uint32_t dest_slot, uint32_t new_rights) {
    return syscall(SYS_FS_MINT_FILE, dir_slot, dest_slot, new_rights);
}

static inline int sys_fs_lookup(uint32_t dir_slot, const char *name, uint32_t out_slot, uint32_t desired_rights) {
    return syscall6(SYS_FS_LOOKUP, dir_slot, (uint32_t)name, out_slot, desired_rights, 0, 0);
}

static inline int sys_fs_create(uint32_t dir_slot, const char *name, int type, uint32_t out_slot, uint32_t desired_rights) {
    return syscall6(SYS_FS_CREATE, dir_slot, (uint32_t)name, (uint32_t)type, out_slot, desired_rights, 0);
}

static inline int sys_fs_delete(uint32_t dir_slot, const char *name) {
    return syscall(SYS_FS_DELETE, dir_slot, (uint32_t)name, 0);
}

static inline int sys_fs_readdir(uint32_t dir_slot, char *buf, uint32_t bufsize) {
    return syscall(SYS_FS_READDIR, dir_slot, (uint32_t)buf, bufsize);
}

static inline int sys_fs_get_root(uint32_t dest_slot, uint32_t rights) {
    return syscall(SYS_FS_GET_ROOT, dest_slot, rights, 0);
}

static inline int sys_fs_read(uint32_t file_slot, char *buf, uint32_t len) {
    return syscall(SYS_FS_READ, file_slot, (uint32_t)buf, len);
}

static inline int sys_fs_write(uint32_t file_slot, const char *buf, uint32_t len) {
    return syscall(SYS_FS_WRITE, file_slot, (uint32_t)buf, len);
}

/* sys_register_storage_backend() was removed: registering a userspace block
 * backend meant the kernel called ring-3 function pointers from ring 0 (an SMEP
 * violation and TCB escape). Syscall 46 now fails closed (SYS_ERR_NOSYS). The
 * #define is kept so the ABI slot stays reserved. */

static inline int sys_block_read(uint64_t block, void *buf, uint32_t len) {
    return (int)syscall6(SYS_BLOCK_READ, (uint32_t)(block >> 32), (uint32_t)block, (uint32_t)buf, len, 0, 0);
}

static inline int sys_block_write(uint64_t block, const void *buf, uint32_t len) {
    return (int)syscall6(SYS_BLOCK_WRITE, (uint32_t)(block >> 32), (uint32_t)block, (uint32_t)buf, len, 0, 0);
}

static inline int sys_register_fs_server(uint32_t ep_slot) {
    return syscall(SYS_REGISTER_FS_SERVER, ep_slot, 0, 0);
}

static inline int sys_connect_fs_server(uint32_t dest_slot, uint32_t rights) {
    return syscall(SYS_CONNECT_FS_SERVER, dest_slot, rights, 0);
}

#endif
