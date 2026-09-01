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

#ifdef RAMFS_SLOT3_GATE
/* Retired from the ship build with [H-3] (the dispatch entry) and with the
 * deletion of the user database's save/load pair (its last real consumer). The
 * body survives only for smoke-passwd-probe-control, which restores the four
 * slot-3 gates and needs something behind them. */
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
#endif /* RAMFS_SLOT3_GATE */

/* SYS_EXIT (2): terminate the calling task. Teardown runs here; the switch away
 * from the now-dead caller is done in interrupt_handler64, which detects
 * state == 0 on return from the syscall and redirects to the kernel reaper
 * (exactly as the ring-3 fault-kill path does). */

/* ---- The installer's two syscalls (roadmap 2.9, S72) ----------------------
 *
 * Both answer to CAP_STORAGE_FORMAT at CAPSLOT_STORAGE_FORMAT, enforced by the
 * dispatch table so neither handler repeats the check and neither can forget it.
 * Nothing else in this tree is granted that capability: init is endowed with it
 * from the root cnode and passes a copy to the installer alone.
 *
 * They are NOT gated on CAP_ENCRYPTED_STORAGE, which fs_server and the shell
 * both hold. Formatting from that capability would mean the filesystem server
 * could erase the filesystem, and a login shell could erase the volume it just
 * logged into -- which is the sentence S63 exists to make false.
 */

/* SYS_STORAGE_INFO (110): what volume this machine has. READ. */
void h_storage_info(struct interrupt_frame64 *r) {
    struct storage_info info;
    storage_query(&info);
    if (copy_to_user((void *)(addr_t)r->rbx, &info, sizeof(info)) != 0) {
        r->rax = (uint32_t)SYS_ERR_FAULT;
        return;
    }
    r->rax = 0;
}

/* SYS_STORAGE_FORMAT (111): destroy the volume on the attached device and lay a
 * new encrypted one down, sealed to `password`. WRITE.
 *
 * THE LENGTH BOUND IS NOT ARBITRARY, and getting it wrong would brick the
 * machine the installer just installed. h_auth copies 31 bytes of the typed
 * password and hands exactly that to storage_unlock, so a volume sealed to a
 * 40-character password could never be opened by a login: the operator would
 * type the password they chose and be refused forever, with nothing on the wire
 * saying why. The two paths must agree on the effective length, so this one
 * REFUSES what it cannot round-trip rather than silently truncating -- an
 * installer that quietly shortened the password would seal the volume to a
 * string the operator never chose.
 *
 * The password is copied into a kernel stack buffer and zeroed before return, on
 * every path including the refusals, the same discipline h_auth follows.
 */
void h_storage_format(struct interrupt_frame64 *r) {
    uint32_t plen = (uint32_t)r->rcx;

    /* Refuse before copying anything: an empty password seals a volume to
     * nothing, and an over-long one cannot be typed back at a login prompt. */
    if (plen == 0 || plen > STORAGE_FORMAT_PASSWORD_MAX) {
        r->rax = (uint32_t)SYS_ERR_INVAL;
        return;
    }

    char pw[STORAGE_FORMAT_PASSWORD_MAX + 1];
    if (copy_from_user(pw, (void *)(addr_t)r->rbx, plen) != 0) {
        secure_zero(pw, sizeof(pw));
        r->rax = (uint32_t)SYS_ERR_FAULT;
        return;
    }
    pw[plen] = 0;

    /* The deliberate act S63 named and left without a caller. It is set here and
     * not reset: a machine whose operator has said "format this disk" once is a
     * machine being installed, and storage_unlock consumes the permission by
     * clearing g_needs_format the moment a volume exists. */
    storage_authorize_format();

    int rc = storage_unlock(pw, plen);
    secure_zero(pw, sizeof(pw));
    r->rax = (uint64_t)(uint32_t)(rc == 0 ? 0 : rc);
}

void h_block_read(struct interrupt_frame64 *r) {
    uint64_t block = ((uint64_t)r->rbx << 32) | r->rcx;
    void *buf = (void*)(addr_t)r->rdx;
    uint32_t len = r->rsi;
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

/* SYS_BLOCK_WRITE: raw block write. Authorised solely by the object-store
 * capability (CAP_ENCRYPTED_STORAGE at CAPSLOT_AUDIT, by type) enforced centrally
 * in the dispatch table. The ambient uid==0 gate that used to sit here is gone
 * (finding I-1): authority is the capability, not the identity. */
void h_block_write(struct interrupt_frame64 *r) {
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
    struct capability *ep = cap_lookup(ep_slot, CAP_ENDPOINT, CAP_RIGHT_READ | CAP_RIGHT_WRITE);
    if (!ep) {
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
    /* WRITE ONLY — never READ (audit finding C-1).
     *
     * READ is the RECEIVE right on an endpoint. A client minted with READ on the
     * server's listen endpoint could dequeue other clients' requests
     * (SYS_IPC_RECV) and, because SYS_IPC_REPLY_TO also requires READ, forge the
     * server's replies into a victim's blocked SYS_IPC_CALL buffer. That is
     * exactly the C-1 attack. A client only ever needs to SEND to the service, so
     * it is minted WRITE-only and the caller-supplied `rights` cannot widen that.
     *
     * The client's replies come back on its own private reply endpoint, for which
     * it already holds a capability (slot 4) that nobody else has.
     *
     * Policy note: any task may still connect. The fs_server is a reference
     * monitor that authorises every request against the caller's kernel-attested
     * uid (SYS_IPC_SENDER), so a send-only channel to it confers no file access. */
    (void)rights;
    bool ok = cap_install_endpoint(dest_slot, (uint32_t)fs_server_listen_ep_idx,
                                   CAP_RIGHT_WRITE, 0xF51A0000U);
    r->rax = ok ? 0 : -2;
}

/* ---- Encrypted object-store API for the userspace FS server -------------- *
 * These expose the kernel's persistent, encrypted inode/block store to a ring-3
 * filesystem server WITHOUT ever handing it key material: the AEAD (volume key,
 * per-(ino,block) subkeys, nonces, tags) stays entirely in the kernel. The
 * server addresses storage by (inode, logical block) and implements all
 * filesystem semantics (names, directories, permissions) on top. Gated exactly
 * like the raw block syscalls: CAP_ENCRYPTED_STORAGE at CAPSLOT_AUDIT, enforced
 * by the dispatch table and by nothing else. There is no uid check here, and this
 * comment claimed one until 2026-08-29. Possession of that capability IS the
 * authority, which is the point of retiring ambient uid 0 ([I-1], [H-1]): the
 * gate is revocable and the uid was not. */

/* ---- the object store's OTHER precondition ------------------------------
 *
 * A volume has two states that both look like "there is a filesystem here", and
 * for a long time the eight handlers below tested only the first of them:
 *
 *   mounted  -- the superblock has been read and verified, so the geometry, the
 *               inode count and the metadata root are known.
 *   unlocked -- a key slot has been opened with somebody's password, so disk_key
 *               exists and the AEAD can run.
 *
 * A sealed ATA volume is MOUNTED AND LOCKED for the whole of every boot until a
 * login unlocks it. That is not an edge case, it is the normal state of an
 * installed machine between power-on and the password prompt, and it is the
 * state the store must answer nothing in.
 *
 * WHY THE MISSING CHECK WAS INVISIBLE. The AEAD layer catches it for FILE DATA:
 * storage_decrypt_block and storage_encrypt_block both test `unlocked` and fail
 * closed, so h_fblock_read/h_fblock_write were saved downstream by the layer
 * that needs the key. Nothing catches it for the INODE TABLE, which is written
 * through do_block_write with no crypto at all -- inode records are plaintext on
 * disk, so storage_read_inode and storage_write_inode work perfectly on a volume
 * nobody has opened. The half of the API with a key requirement enforced the
 * rule as a side effect of needing the key; the half without one enforced
 * nothing, and had no reason to look wrong.
 *
 * SO THE STORE FAILED OPEN IN BOTH DIRECTIONS on a locked volume. Reading:
 * SYS_FS_STAT answered with a real inode -- size, mode, uid, gid, type, links --
 * for any inode number on a sealed disk. Writing: SYS_FS_INODE_ALLOC,
 * SYS_FS_SET_META, SYS_FS_SET_SIZE, SYS_FS_INODE_LINK and SYS_FS_INODE_FREE all
 * edited the inode table of a volume that had never been opened. The gate on all
 * of them is CAP_ENCRYPTED_STORAGE, so this was never reachable from an ordinary
 * ring-3 task -- but "only the filesystem server can do it" is a statement about
 * who, and the rule here is about WHEN. A capability is not a password.
 *
 * HOW IT SURFACED, which is the part worth keeping. fs_server decides at startup
 * whether the store is usable by asking for the root inode:
 *
 *     if (sys_fs_stat(0, &root_st) == 0) { provision_boot_modules(); provisioned = 1; }
 *
 * On a sealed volume that stat SUCCEEDED, so the server ran its provisioning pass
 * against a locked store, every module's data write failed in the AEAD, and it
 * recorded itself as provisioned anyway -- which permanently disabled the
 * post-login retry its own comment describes as the sealed-ATA fallback. Install
 * a machine, power it off at the login prompt before the copy finishes, and /bin
 * is empty on that disk forever. Measured 2026-09-01: `cd bin; ls` empty on every
 * subsequent boot, and `[fs_server] some boot modules did not fit the store
 * volume` printed on machines where all 25 modules were in fact present, because
 * the same doomed pass ran on every boot. The server's test was reasonable; the
 * syscall's answer was wrong.
 *
 * THE RULE LIVES IN ONE PLACE, deliberately, and that is the whole repair.
 * Eight handlers each repeating `!mfs || !mfs->mounted` is eight chances to write
 * the predicate that was already written wrong eight times -- the same argument
 * S60 makes for folding the capability type check into cap_lookup. A handler that
 * wants the store now asks for an OPEN one and gets NULL otherwise.
 *
 * SYS_ERR_INVAL rather than SYS_ERR_PERM, matching the unmounted case it now
 * shares a return with. Both mean "there is no open store to act on", which is a
 * statement about the volume and not about the caller; the caller's authority was
 * already settled by the dispatch table before this ran. Callers test for zero,
 * so no existing client can tell the two apart, and inventing a distinction the
 * clients cannot use would be a wider ABI change than the defect warrants.
 *
 * THE RAW BLOCK API IS DELIBERATELY NOT CHANGED. h_block_read/h_block_write sit
 * BELOW the volume abstraction on purpose -- they move ciphertext, which is what
 * the journal and crash gates need them for -- and a raw read of an encrypted
 * block discloses nothing the disk does not already show anyone holding it.
 *
 * STORE_LOCKED_UNCHECKED=1 restores the mounted-only test. See
 * docs/BUILDING.md; never ship it. */
static struct mounted_fs *store_open(void)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) return NULL;
#ifndef STORE_LOCKED_UNCHECKED
    if (!mfs->unlocked) return NULL;
#endif
    return mfs;
}

void h_fs_inode_alloc(struct interrupt_frame64 *r) {
    uint32_t type = r->rbx;
    struct mounted_fs *mfs = store_open();
    if (!mfs) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

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
    uint64_t ino = r->rbx;
    if (ino == 0) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }   /* never free root */
    struct mounted_fs *mfs = store_open();
    if (!mfs) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

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
    uint64_t ino = r->rbx;
    if (ino == 0) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }   /* root is not hard-linked */
    struct mounted_fs *mfs = store_open();
    if (!mfs) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_NOENT; return; }
    if (inode.type == 2 /* dir */ || inode.type == 0)            { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    if (inode.links == 0xFFFFFFFFu)                              { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    inode.links++;
    r->rax = (storage_write_inode(mfs->bd, &mfs->sb, ino, &inode) == 0)
                 ? 0 : (uint32_t)SYS_ERR_IO;
}

void h_fblock_read(struct interrupt_frame64 *r) {
    uint64_t ino   = r->rbx;
    uint64_t block = r->rcx;
    void    *ubuf  = (void *)(addr_t)r->rdx;
    struct mounted_fs *mfs = store_open();
    if (!mfs) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    uint8_t kbuf[BLOCK_SIZE];
    /* Fails on an unallocated hole or an authentication failure; the server
     * only reads blocks within a known size, so this is a genuine error. */
    if (storage_read_file_block(mfs, ino, block, kbuf) != 0) { r->rax = (uint32_t)SYS_ERR_NOENT; return; }
    if (copy_to_user(ubuf, kbuf, BLOCK_SIZE) != 0)           { r->rax = (uint32_t)SYS_ERR_FAULT; return; }
    r->rax = BLOCK_SIZE;
}

void h_fblock_write(struct interrupt_frame64 *r) {
    uint64_t ino   = r->rbx;
    uint64_t block = r->rcx;
    const void *ubuf = (const void *)(addr_t)r->rdx;
    uint32_t len   = r->rsi;
    if (len > BLOCK_SIZE) len = BLOCK_SIZE;
    struct mounted_fs *mfs = store_open();
    if (!mfs) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    uint8_t kbuf[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) kbuf[i] = 0;   /* zero-pad short writes */
    if (len > 0 && copy_from_user(kbuf, ubuf, len) != 0) { r->rax = (uint32_t)SYS_ERR_FAULT; return; }
    if (storage_write_file_block(mfs, ino, block, kbuf) != 0) { r->rax = (uint32_t)SYS_ERR_IO; return; }
    /* Logical file size is owned by the FS server (it may write full blocks for
     * read-modify-write); it sets size via SYS_FS_SET_SIZE. */
    r->rax = len;
}

void h_fs_set_size(struct interrupt_frame64 *r) {
    uint64_t ino  = r->rbx;
    uint64_t size = r->rcx;
    struct mounted_fs *mfs = store_open();
    if (!mfs) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_NOENT; return; }
    inode.size = size;
    if (storage_write_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_IO; return; }
    r->rax = 0;
}

/* SYS_FS_SET_META (74): persist an inode's owner (uid/gid) and permission bits.
 * Same gate as the rest of the object-store API: CAP_ENCRYPTED_STORAGE at
 * CAPSLOT_AUDIT, from the dispatch table. There is no uid check here, and this
 * comment claimed one until 2026-08-29. Holding that capability is what makes a
 * caller the trusted filesystem server.
 * The server is the reference monitor: it chooses the values (owner = the
 * kernel-attested creator at create time; chmod/chown only after authorising the
 * attested caller), and this writes them through. Only the low 12 permission bits
 * are caller-settable; the file-type bits are preserved, so a chmod can never
 * turn a directory into a regular file. */
void h_fs_set_meta(struct interrupt_frame64 *r) {
    uint64_t ino  = r->rbx;
    uint32_t mode = r->rcx;
    uint32_t uid  = r->rdx;
    uint32_t gid  = r->rsi;
    struct mounted_fs *mfs = store_open();
    if (!mfs) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_NOENT; return; }
    inode.mode = (inode.mode & ~0007777u) | (mode & 0007777u);
    inode.uid  = uid;
    inode.gid  = gid;
    if (storage_write_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { r->rax = (uint32_t)SYS_ERR_IO; return; }
    r->rax = 0;
}

void h_fs_stat(struct interrupt_frame64 *r) {
    uint64_t ino  = r->rbx;
    void    *uout = (void *)(addr_t)r->rcx;
    struct mounted_fs *mfs = store_open();
    if (!mfs) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

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

#ifdef RAMFS_SLOT3_GATE
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
#endif /* RAMFS_SLOT3_GATE */

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

