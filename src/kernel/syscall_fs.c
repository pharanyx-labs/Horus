/* syscall_fs.c -- filesystem + block-storage syscalls: the in-kernel capfs
 * operations (sys_fs_*), ramfs open/create/list, and the raw block +
 * encrypted object-store handlers. Split out of syscall.c. */
#include "syscall_internal.h"

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

    /* rust_cap_mint already copied dir_cap->type (CAP_DIR or CAP_FILE) into
     * dest->type. The old code additionally cast dir_cap->object to a raw
     * fs_object pointer to re-derive the type; after the capfs refactor
     * cap->object is a packed (idx|gen<<32) value, not a pointer, so the cast
     * produced a garbage address. The cap_mint copy is both correct and safe. */

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


void h_fs_list(struct regs *r) {
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

/* SYS_EXIT (2): terminate the calling task. Teardown runs here; the switch away
 * from the now-dead caller is done in interrupt_handler64, which detects
 * state == 0 on return from the syscall and redirects to the kernel reaper
 * (exactly as the ring-3 fault-kill path does). */

void h_block_read(struct regs *r) {
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
void h_block_write(struct regs *r) {
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
void h_register_fs_server(struct regs *r) {
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
void h_connect_fs_server(struct regs *r) {
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
    /* A fresh serial + generation is required or cap_lookup rejects the cap
     * (a serial-0 slot is treated as empty), which previously left the client
     * unable to pass the IPC capability gate. */
    uint32_t serial = cap_alloc_fresh_serial();
    struct capability *dest = &tasks[get_current_task()].cspace[dest_slot];
    dest->type   = CAP_ENDPOINT;
    dest->rights = rights & (CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_GRANT);
    dest->object = fs_server_listen_ep_idx;
    dest->badge  = 0xF51A0000U;
    dest->serial = serial;
    dest->generation = 0;
    r->eax = 0;
}

/* ---- Encrypted object-store API for the userspace FS server -------------- *
 * These expose the kernel's persistent, encrypted inode/block store to a ring-3
 * filesystem server WITHOUT ever handing it key material: the AEAD (volume key,
 * per-(ino,block) subkeys, nonces, tags) stays entirely in the kernel. The
 * server addresses storage by (inode, logical block) and implements all
 * filesystem semantics (names, directories, permissions) on top. Gated exactly
 * like the raw block syscalls — CAP_BLOCK_DEV in slot 7 (dispatch table) plus
 * the uid==0 check below — so only a privileged storage server can call them. */

void h_fs_inode_alloc(struct regs *r) {
    if (tasks[get_current_task()].uid != 0) { r->eax = (uint32_t)SYS_ERR_PERM; return; }
    uint32_t type = r->ebx;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }

    int64_t ino = storage_alloc_inode(mfs->bd, &mfs->sb);
    if (ino < 0) { r->eax = (uint32_t)SYS_ERR_IO; return; }   /* out of inodes */

    struct on_disk_inode inode;
    for (size_t i = 0; i < sizeof(inode); i++) ((uint8_t *)&inode)[i] = 0;
    inode.type  = type;
    inode.uid   = tasks[get_current_task()].uid;
    inode.gid   = tasks[get_current_task()].gid;
    inode.mode  = (type == 2) ? 0040755u : 0100644u;
    inode.links = 1;
    storage_write_inode(mfs->bd, &mfs->sb, (uint64_t)ino, &inode);

    r->eax = (uint32_t)(int32_t)ino;
}

void h_fs_inode_free(struct regs *r) {
    if (tasks[get_current_task()].uid != 0) { r->eax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino = r->ebx;
    if (ino == 0) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }   /* never free root */
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }
    r->eax = (storage_free_inode_blocks(mfs, ino) == 0) ? 0 : (uint32_t)SYS_ERR_IO;
}

void h_fblock_read(struct regs *r) {
    if (tasks[get_current_task()].uid != 0) { r->eax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino   = r->ebx;
    uint64_t block = r->ecx;
    void    *ubuf  = (void *)(addr_t)r->edx;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }

    uint8_t kbuf[BLOCK_SIZE];
    /* Fails on an unallocated hole or an authentication failure; the server
     * only reads blocks within a known size, so this is a genuine error. */
    if (storage_read_file_block(mfs, ino, block, kbuf) != 0) { r->eax = (uint32_t)SYS_ERR_NOENT; return; }
    if (copy_to_user(ubuf, kbuf, BLOCK_SIZE) != 0)           { r->eax = (uint32_t)SYS_ERR_FAULT; return; }
    r->eax = BLOCK_SIZE;
}

void h_fblock_write(struct regs *r) {
    if (tasks[get_current_task()].uid != 0) { r->eax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino   = r->ebx;
    uint64_t block = r->ecx;
    const void *ubuf = (const void *)(addr_t)r->edx;
    uint32_t len   = r->esi;
    if (len > BLOCK_SIZE) len = BLOCK_SIZE;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }

    uint8_t kbuf[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) kbuf[i] = 0;   /* zero-pad short writes */
    if (len > 0 && copy_from_user(kbuf, ubuf, len) != 0) { r->eax = (uint32_t)SYS_ERR_FAULT; return; }
    if (storage_write_file_block(mfs, ino, block, kbuf) != 0) { r->eax = (uint32_t)SYS_ERR_IO; return; }
    /* Logical file size is owned by the FS server (it may write full blocks for
     * read-modify-write); it sets size via SYS_FS_SET_SIZE. */
    r->eax = len;
}

void h_fs_set_size(struct regs *r) {
    if (tasks[get_current_task()].uid != 0) { r->eax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino  = r->ebx;
    uint64_t size = r->ecx;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->eax = (uint32_t)SYS_ERR_NOENT; return; }
    inode.size = size;
    if (storage_write_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->eax = (uint32_t)SYS_ERR_IO; return; }
    r->eax = 0;
}

/* SYS_FS_SET_META (74): persist an inode's owner (uid/gid) and permission bits.
 * Same gate as the rest of the object-store API — CAP_BLOCK_DEV (slot 7, table)
 * plus the uid==0 check here — so only the trusted filesystem server can call it.
 * The server is the reference monitor: it chooses the values (owner = the
 * kernel-attested creator at create time; chmod/chown only after authorising the
 * attested caller), and this writes them through. Only the low 12 permission bits
 * are caller-settable; the file-type bits are preserved, so a chmod can never
 * turn a directory into a regular file. */
void h_fs_set_meta(struct regs *r) {
    if (tasks[get_current_task()].uid != 0) { r->eax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino  = r->ebx;
    uint32_t mode = r->ecx;
    uint32_t uid  = r->edx;
    uint32_t gid  = r->esi;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->eax = (uint32_t)SYS_ERR_NOENT; return; }
    inode.mode = (inode.mode & ~0007777u) | (mode & 0007777u);
    inode.uid  = uid;
    inode.gid  = gid;
    if (storage_write_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->eax = (uint32_t)SYS_ERR_IO; return; }
    r->eax = 0;
}

void h_fs_stat(struct regs *r) {
    if (tasks[get_current_task()].uid != 0) { r->eax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino  = r->ebx;
    void    *uout = (void *)(addr_t)r->ecx;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->eax = (uint32_t)SYS_ERR_INVAL; return; }

    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->eax = (uint32_t)SYS_ERR_NOENT; return; }

    struct fs_stat st;
    st.size  = inode.size;
    st.type  = inode.type;
    st.mode  = inode.mode;
    st.uid   = inode.uid;
    st.gid   = inode.gid;
    st.links = inode.links;
    if (copy_to_user(uout, &st, sizeof(st)) != 0) { r->eax = (uint32_t)SYS_ERR_FAULT; return; }
    r->eax = 0;
}

/* ---- Handlers for the remaining syscalls -------------------------------- *
 * Fixed (slot, rights[, type]) capability requirements are declared in
 * syscall_table[] below and enforced centrally before the handler runs, so
 * these bodies no longer repeat that check. Handlers whose authority is
 * dynamic (FS dir-slot from args; cap_mint/transfer/move/revoke target slot)
 * or self-authorizing (auth/sudo) carry SC_NONE and do their own checks. */

/* SYS_YIELD (0). */

void h_open(struct regs *r) {
    char path[64];
    if (copy_from_user(path, (void*)(addr_t)r->ebx, 63) != 0) {
        r->eax = -1; return;
    }
    path[63] = 0;
    r->eax = ramfs_open(path, 0);
}

/* ramfs create (15): slot-3 WRITE enforced by the table. */
void h_ramfs_create(struct regs *r) {
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->ebx, 31) != 0) {
        r->eax = -1; return;
    }
    name[31] = 0;
    r->eax = ramfs_create(name, 0);
}

/* SYS_SPAWN (28): slot-3 WRITE|EXEC enforced by the table.
 * ebx = userspace pointer to a null-terminated binary name, or 0.
 * ecx = max bytes to read from the name (0 means up to 31).
 * If ebx is nonzero, arm the named embedded binary then spawn it.
 * If ebx is zero, spawn whatever is currently armed (legacy behaviour). */

void h_fs_mint_file(struct regs *r) {
    r->eax = sys_fs_mint_file(r->ebx, r->ecx, r->edx);
}
void h_fs_lookup(struct regs *r) {
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->ecx, 31) != 0) { r->eax = (uint32_t)SYS_ERR_FAULT; return; }
    name[31] = 0;
    r->eax = sys_fs_lookup(r->ebx, name, r->edx, (addr_t)r->esi);
}
void h_fs_create(struct regs *r) {
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->ecx, 31) != 0) { r->eax = (uint32_t)SYS_ERR_FAULT; return; }
    name[31] = 0;
    r->eax = sys_fs_create(r->ebx, name, (int)r->edx, (addr_t)r->esi, (addr_t)r->edi);
}
void h_fs_delete(struct regs *r) {
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->ecx, 31) != 0) { r->eax = (uint32_t)SYS_ERR_FAULT; return; }
    name[31] = 0;
    r->eax = sys_fs_delete(r->ebx, name);
}
void h_fs_readdir(struct regs *r) {
    r->eax = sys_fs_readdir(r->ebx, (char *)(addr_t)r->ecx, r->edx);
}
void h_fs_get_root(struct regs *r) {
    r->eax = sys_fs_get_root(r->ebx, r->ecx);
}
void h_fs_read(struct regs *r) {
    r->eax = sys_fs_read(r->ebx, (char *)(addr_t)r->ecx, r->edx);
}
void h_fs_write(struct regs *r) {
    r->eax = sys_fs_write(r->ebx, (const char *)(addr_t)r->ecx, r->edx);
}

/* SYS_REGISTER_STORAGE_BACKEND (46): removed; ABI slot reserved, fails closed.
 * (Used to register a ring-3 fn-ptr the kernel called at CPL0 -- SMEP/TCB hole;
 * a userspace disk driver must be an IPC server, not an in-kernel callback.) */
void h_register_storage_backend(struct regs *r) {
    r->eax = SYS_ERR_NOSYS;
}

