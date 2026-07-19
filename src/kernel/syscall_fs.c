/* syscall_fs.c -- filesystem + block-storage syscalls: the in-kernel capfs
 * operations (sys_fs_*), ramfs open/create/list, and the raw block +
 * encrypted object-store handlers. Split out of syscall.c. */
#include "syscall_internal.h"

/* The legacy in-memory capfs (sys_fs_mint_file / lookup / create / delete /
 * readdir / get_root / read / write) was a parallel capability filesystem
 * separate from the encrypted fs_server. It has been removed: the syscalls fail
 * closed (no dispatch-table entries) and the capfs engine is gone. h_fs_list
 * below is unrelated — it lists the small in-memory ramfs (syscall 16) that
 * still backs the sealed user database. */

void h_fs_list(struct interrupt_frame64 *r) {
    void *user_buf = (void*)(addr_t)r->rbx;
    size_t max_len = r->rcx;
    char kbuf[256];
    /* Honour the caller-supplied buffer size: format the listing into at
     * most max_len bytes (capped by the kernel scratch buffer) so the
     * subsequent copy_to_user never writes past the caller's buffer.
     * ramfs_list guarantees a NUL within the size it is given, so
     * n+1 <= cap holds. */
    size_t cap = max_len < sizeof(kbuf) ? max_len : sizeof(kbuf);
    if (cap == 0) { r->rax = 0; return; }
    int n = ramfs_list(kbuf, cap);
    if (n < 0) { r->rax = -1; return; }
    if (copy_to_user(user_buf, kbuf, n+1) == 0) r->rax = n;
    else r->rax = -1;
}

/* SYS_EXIT (2): terminate the calling task. Teardown runs here; the switch away
 * from the now-dead caller is done in interrupt_handler64, which detects
 * state == 0 on return from the syscall and redirects to the kernel reaper
 * (exactly as the ring-3 fault-kill path does). */

void h_block_read(struct interrupt_frame64 *r) {
    uint64_t block = ((uint64_t)r->rbx << 32) | r->rcx;
    void *buf = (void*)(addr_t)r->rdx;
    uint32_t len = r->rsi;
    if (tasks[get_current_task()].uid != 0) {
        r->rax = -2;
        return;
    }
    uint8_t kbuf[BLOCK_SIZE];
    uint32_t to = len > BLOCK_SIZE ? BLOCK_SIZE : len;
    int rc = storage_block_read(block, kbuf);
    if (rc == 0) {
        if (copy_to_user(buf, kbuf, to) == 0) {
            r->rax = to;
        } else {
            r->rax = -3;
        }
    } else {
        r->rax = rc;
    }
}

/* SYS_BLOCK_WRITE: raw block write. The slot-7 CAP_BLOCK_DEV capability is
 * enforced centrally by the dispatch table; the uid==0 gate stays here (its
 * distinct -2 return is part of the ABI). */
void h_block_write(struct interrupt_frame64 *r) {
    if (tasks[get_current_task()].uid != 0) {
        r->rax = -2;
        return;
    }
    uint64_t block = ((uint64_t)r->rbx << 32) | r->rcx;
    const void *buf = (const void*)(addr_t)r->rdx;
    uint32_t len = r->rsi;
    uint8_t kbuf[BLOCK_SIZE];
    uint32_t to = len > BLOCK_SIZE ? BLOCK_SIZE : len;
    if (copy_from_user(kbuf, buf, to) != 0) {
        r->rax = -3;
        return;
    }
    int rc = storage_block_write(block, kbuf);
    r->rax = (rc == 0) ? (int)to : rc;
}

/* SYS_REGISTER_FS_SERVER: register the caller as the fs server. The admin
 * capability (slot 6, ALL, type CAP_USER) is enforced centrally by the table;
 * the per-call endpoint-slot lookup stays here. */
void h_register_fs_server(struct interrupt_frame64 *r) {
    uint32_t ep_slot = r->rbx;
    struct capability *ep = cap_lookup(ep_slot, CAP_RIGHT_READ | CAP_RIGHT_WRITE);
    if (!ep || ep->type != CAP_ENDPOINT) {
        r->rax = -2;
        return;
    }
    fs_server_task_id = get_current_task();
    fs_server_listen_ep_idx = ep->object;
    r->rax = 0;
}

/* SYS_CONNECT_FS_SERVER: mint an endpoint cap to the registered fs server. */
void h_connect_fs_server(struct interrupt_frame64 *r) {
    uint32_t dest_slot = r->rbx;
    uint32_t rights = r->rcx;
    if (fs_server_task_id < 0 || fs_server_listen_ep_idx < 0) {
        r->rax = -1;
        return;
    }
    /* Install the endpoint cap through the locked, authority-checked, accounted
     * cap path (cap_install_endpoint) rather than a raw cspace store. Policy is
     * unchanged: any task may connect — the fs_server is a reference monitor
     * that authorizes every request by kernel-attested identity (SYS_IPC_SENDER),
     * so the endpoint alone grants no file access — but the cap must be written
     * with the same discipline as every other one: SMP-safe against a concurrent
     * global revoke, reserved-slot-checked, and counted against MAX_CAPS_PER_TASK.
     * A fresh serial + generation is required or cap_lookup treats the slot as
     * empty and the client cannot pass the IPC capability gate. Rights are masked
     * to R/W/GRANT here so the connect policy lives at the policy site. */
    uint32_t ep_rights = rights & (CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_GRANT);
    bool ok = cap_install_endpoint(dest_slot, (uint32_t)fs_server_listen_ep_idx,
                                   ep_rights, 0xF51A0000U);
    r->rax = ok ? 0 : -2;
}

/* ---- Encrypted object-store API for the userspace FS server -------------- *
 * These expose the kernel's persistent, encrypted inode/block store to a ring-3
 * filesystem server WITHOUT ever handing it key material: the AEAD (volume key,
 * per-(ino,block) subkeys, nonces, tags) stays entirely in the kernel. The
 * server addresses storage by (inode, logical block) and implements all
 * filesystem semantics (names, directories, permissions) on top. Gated exactly
 * like the raw block syscalls — CAP_BLOCK_DEV in slot 7 (dispatch table) plus
 * the uid==0 check below — so only a privileged storage server can call them. */

void h_fs_inode_alloc(struct interrupt_frame64 *r) {
    if (tasks[get_current_task()].uid != 0) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    uint32_t type = r->rbx;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    int64_t ino = storage_alloc_inode(mfs->bd, &mfs->sb);
    if (ino < 0) { r->rax = (uint32_t)SYS_ERR_IO; return; }   /* out of inodes */

    struct on_disk_inode inode;
    for (size_t i = 0; i < sizeof(inode); i++) ((uint8_t *)&inode)[i] = 0;
    inode.type  = type;
    inode.uid   = tasks[get_current_task()].uid;
    inode.gid   = tasks[get_current_task()].gid;
    inode.mode  = (type == 2) ? 0040755u : 0100644u;
    inode.links = 1;
    storage_write_inode(mfs->bd, &mfs->sb, (uint64_t)ino, &inode);

    r->rax = (uint32_t)(int32_t)ino;
}

/* SYS_FS_INODE_FREE (57): drop one hard-link reference to an inode.
 *
 * A regular file may have several names (see h_fs_inode_link), so removing one
 * name must not free the inode while others remain: decrement `links` and free
 * the inode + its data blocks only when the count reaches zero. A directory is
 * never hard-linked, so it is freed outright (its `links` is a fixed 1 the store
 * does not maintain as a dirent count). This is also the create-rollback path a
 * freshly allocated (links == 1) inode takes, which decrements straight to zero
 * and frees, exactly as before. A stored count of 0 or 1 frees, so a corrupt or
 * legacy inode can never be pinned unfreeable. */
void h_fs_inode_free(struct interrupt_frame64 *r) {
    if (tasks[get_current_task()].uid != 0) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino = r->rbx;
    if (ino == 0) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }   /* never free root */
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_NOENT; return; }

    if (inode.type != 2 /* dir */ && inode.links > 1) {
        inode.links--;
        r->rax = (storage_write_inode(mfs->bd, &mfs->sb, ino, &inode) == 0)
                     ? 0 : (uint32_t)SYS_ERR_IO;
        return;
    }
    r->rax = (storage_free_inode_blocks(mfs, ino) == 0) ? 0 : (uint32_t)SYS_ERR_IO;
}

/* SYS_FS_INODE_LINK (76): add one hard-link reference to an inode (increment its
 * on-disk link count), so a second directory entry can name the same file. Same
 * gate as the rest of the object-store API. A directory is refused — hard links
 * to directories would let a client build a cycle the tree walk cannot bound. */
void h_fs_inode_link(struct interrupt_frame64 *r) {
    if (tasks[get_current_task()].uid != 0) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino = r->rbx;
    if (ino == 0) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }   /* root is not hard-linked */
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_NOENT; return; }
    if (inode.type == 2 /* dir */ || inode.type == 0)            { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    if (inode.links == 0xFFFFFFFFu)                              { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    inode.links++;
    r->rax = (storage_write_inode(mfs->bd, &mfs->sb, ino, &inode) == 0)
                 ? 0 : (uint32_t)SYS_ERR_IO;
}

void h_fblock_read(struct interrupt_frame64 *r) {
    if (tasks[get_current_task()].uid != 0) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino   = r->rbx;
    uint64_t block = r->rcx;
    void    *ubuf  = (void *)(addr_t)r->rdx;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    uint8_t kbuf[BLOCK_SIZE];
    /* Fails on an unallocated hole or an authentication failure; the server
     * only reads blocks within a known size, so this is a genuine error. */
    if (storage_read_file_block(mfs, ino, block, kbuf) != 0) { r->rax = (uint32_t)SYS_ERR_NOENT; return; }
    if (copy_to_user(ubuf, kbuf, BLOCK_SIZE) != 0)           { r->rax = (uint32_t)SYS_ERR_FAULT; return; }
    r->rax = BLOCK_SIZE;
}

void h_fblock_write(struct interrupt_frame64 *r) {
    if (tasks[get_current_task()].uid != 0) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino   = r->rbx;
    uint64_t block = r->rcx;
    const void *ubuf = (const void *)(addr_t)r->rdx;
    uint32_t len   = r->rsi;
    if (len > BLOCK_SIZE) len = BLOCK_SIZE;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    uint8_t kbuf[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) kbuf[i] = 0;   /* zero-pad short writes */
    if (len > 0 && copy_from_user(kbuf, ubuf, len) != 0) { r->rax = (uint32_t)SYS_ERR_FAULT; return; }
    if (storage_write_file_block(mfs, ino, block, kbuf) != 0) { r->rax = (uint32_t)SYS_ERR_IO; return; }
    /* Logical file size is owned by the FS server (it may write full blocks for
     * read-modify-write); it sets size via SYS_FS_SET_SIZE. */
    r->rax = len;
}

void h_fs_set_size(struct interrupt_frame64 *r) {
    if (tasks[get_current_task()].uid != 0) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino  = r->rbx;
    uint64_t size = r->rcx;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_NOENT; return; }
    inode.size = size;
    if (storage_write_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_IO; return; }
    r->rax = 0;
}

/* SYS_FS_SET_META (74): persist an inode's owner (uid/gid) and permission bits.
 * Same gate as the rest of the object-store API — CAP_BLOCK_DEV (slot 7, table)
 * plus the uid==0 check here — so only the trusted filesystem server can call it.
 * The server is the reference monitor: it chooses the values (owner = the
 * kernel-attested creator at create time; chmod/chown only after authorising the
 * attested caller), and this writes them through. Only the low 12 permission bits
 * are caller-settable; the file-type bits are preserved, so a chmod can never
 * turn a directory into a regular file. */
void h_fs_set_meta(struct interrupt_frame64 *r) {
    if (tasks[get_current_task()].uid != 0) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino  = r->rbx;
    uint32_t mode = r->rcx;
    uint32_t uid  = r->rdx;
    uint32_t gid  = r->rsi;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_NOENT; return; }
    inode.mode = (inode.mode & ~0007777u) | (mode & 0007777u);
    inode.uid  = uid;
    inode.gid  = gid;
    if (storage_write_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_IO; return; }
    r->rax = 0;
}

void h_fs_stat(struct interrupt_frame64 *r) {
    if (tasks[get_current_task()].uid != 0) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    uint64_t ino  = r->rbx;
    void    *uout = (void *)(addr_t)r->rcx;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_NOENT; return; }

    struct fs_stat st;
    st.size  = inode.size;
    st.type  = inode.type;
    st.mode  = inode.mode;
    st.uid   = inode.uid;
    st.gid   = inode.gid;
    st.links = inode.links;
    if (copy_to_user(uout, &st, sizeof(st)) != 0) { r->rax = (uint32_t)SYS_ERR_FAULT; return; }
    r->rax = 0;
}

/* ---- Handlers for the remaining syscalls -------------------------------- *
 * Fixed (slot, rights[, type]) capability requirements are declared in
 * syscall_table[] below and enforced centrally before the handler runs, so
 * these bodies no longer repeat that check. Handlers whose authority is
 * dynamic (FS dir-slot from args; cap_mint/transfer/move/revoke target slot)
 * or self-authorizing (auth/sudo) carry SC_NONE and do their own checks. */

/* SYS_YIELD (0). */

void h_open(struct interrupt_frame64 *r) {
    char path[64];
    if (copy_from_user(path, (void*)(addr_t)r->rbx, 63) != 0) {
        r->rax = -1; return;
    }
    path[63] = 0;
    r->rax = ramfs_open(path, 0);
}

/* ramfs create (15): slot-3 WRITE enforced by the table. */
void h_ramfs_create(struct interrupt_frame64 *r) {
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->rbx, 31) != 0) {
        r->rax = -1; return;
    }
    name[31] = 0;
    r->rax = ramfs_create(name, 0);
}

/* SYS_SPAWN (28): slot-3 WRITE|EXEC enforced by the table.
 * ebx = userspace pointer to a null-terminated binary name, or 0.
 * ecx = max bytes to read from the name (0 means up to 31).
 * If ebx is nonzero, arm the named embedded binary then spawn it.
 * If ebx is zero, spawn whatever is currently armed (legacy behaviour). */

/* The legacy in-memory capfs handlers (h_fs_mint_file / lookup / create /
 * delete / readdir / get_root / read / write, syscalls 38-45) were removed with
 * the capfs engine; the dispatch-table entries are gone, so those numbers fail
 * closed. */

/* SYS_REGISTER_STORAGE_BACKEND (46): removed; ABI slot reserved, fails closed.
 * (Used to register a ring-3 fn-ptr the kernel called at CPL0 -- SMEP/TCB hole;
 * a userspace disk driver must be an IPC server, not an in-kernel callback.) */
void h_register_storage_backend(struct interrupt_frame64 *r) {
    r->rax = SYS_ERR_NOSYS;
}

