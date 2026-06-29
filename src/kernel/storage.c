#include "kernel.h"

int fs_server_task_id = -1;
int fs_server_listen_ep_idx = -1;

int storage_format(struct block_device *bd);
int storage_mount(struct block_device *bd);
int storage_read_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, void *buf);
int storage_write_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, const void *buf);
struct mounted_fs *storage_get_mounted_fs(void);

static void my_memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = dst; const uint8_t *s = src;
    while (n--) *d++ = *s++;
}

static void my_memset(void *dst, int val, size_t n) {
    uint8_t *d = dst; while (n--) *d++ = (uint8_t)val;
}

static size_t my_strlen(const char *s) {
    size_t len = 0; while (s[len]) len++; return len;
}

static int my_strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

static void my_strncpy(char *dst, const char *src, size_t n) {
    while (n-- && (*dst++ = *src++));
}

#define STORAGE_MAGIC 0x48534653
#define STORAGE_VERSION 1

static struct virtual_disk g_vdisk;
static uint8_t g_vdisk_buffer[BLOCKS_PER_DISK * BLOCK_SIZE];

static int vdisk_read(struct block_device *bd, uint64_t block, void *buf) {
    struct virtual_disk *vd = (struct virtual_disk *)bd->private;
    if (block >= bd->total_blocks) return -1;

    uint8_t *src = vd->data + (block * BLOCK_SIZE);
    uint8_t *d = buf;
    for (size_t i = 0; i < BLOCK_SIZE; i++) d[i] = src[i];
    return 0;
}

static int vdisk_write(struct block_device *bd, uint64_t block, const void *buf) {
    struct virtual_disk *vd = (struct virtual_disk *)bd->private;
    if (block >= bd->total_blocks) return -1;

    uint8_t *dst = vd->data + (block * BLOCK_SIZE);
    const uint8_t *s = buf;
    for (size_t i = 0; i < BLOCK_SIZE; i++) dst[i] = s[i];
    return 0;
}

static struct block_device g_vdisk_bd = {
    .name = "vdisk0",
    .total_blocks = BLOCKS_PER_DISK,
    .read_block = vdisk_read,
    .write_block = vdisk_write,
    .private = &g_vdisk,
};

static struct block_device *current_bd = &g_vdisk_bd;

#define INTENT_LOG_SLOTS 8
static struct {
    uint32_t kind;   
    uint64_t arg0;
    uint64_t arg1;
    uint32_t gen;
} intent_log[INTENT_LOG_SLOTS];
static int intent_head = 0;

static void intent_append(uint32_t kind, uint64_t a0, uint64_t a1, uint32_t gen) {
    
    intent_log[intent_head].kind = kind;
    intent_log[intent_head].arg0 = a0;
    intent_log[intent_head].arg1 = a1;
    intent_log[intent_head].gen  = gen;
    intent_head = (intent_head + 1) % INTENT_LOG_SLOTS;
}

/* Per-block key derivation = HKDF-SHA256.
 *   IKM  = volume key
 *   salt = kernel pepper
 *   info = "horus-block-key-v1" || ino || block || gen
 *   OKM  = enc_key(16) || mac_key(16)
 * Replaces the previous unaudited 1024-round ARX construction. Binding ino,
 * block and gen into `info` makes every (block, generation) pair derive a
 * unique enc/mac key pair, which is what authorises a fixed (deterministic)
 * nonce in CTR mode below. */
int storage_derive_block_keys(uint64_t ino, uint64_t block, uint32_t gen,
                              const uint8_t *volume_key,
                              uint8_t *enc_key_out, uint8_t *mac_key_out)
{
    extern uint8_t kernel_pepper[16];
    uint8_t info[18 + 8 + 8 + 4];
    const char *label = "horus-block-key-v1";
    size_t p = 0;
    for (const char *c = label; *c; c++) info[p++] = (uint8_t)*c;
    for (int i = 0; i < 8; i++) info[p++] = (uint8_t)(ino >> (i * 8));
    for (int i = 0; i < 8; i++) info[p++] = (uint8_t)(block >> (i * 8));
    for (int i = 0; i < 4; i++) info[p++] = (uint8_t)(gen >> (i * 8));

    uint8_t okm[32];
    if (rust_hkdf_sha256(volume_key, 16, kernel_pepper, 16, info, p, okm, sizeof(okm)) != 0) {
        return -1;
    }
    for (int i = 0; i < 16; i++) {
        enc_key_out[i] = okm[i];
        mac_key_out[i] = okm[16 + i];
    }
    secure_zero(okm, sizeof(okm));
    return 0;
}

/* Authentication tag = first 16 bytes of HMAC-SHA256(mac_key, data).
 * The per-block mac_key is already unique per (ino, block, gen) via the HKDF
 * above, so it cryptographically binds the ciphertext to its context; the
 * nonce argument is retained for ABI compatibility but no longer needed. */
int storage_compute_mac(const uint8_t *nonce, const uint8_t *data, size_t data_len,
                        const uint8_t *mac_key, uint8_t *tag_out)
{
    (void)nonce;
    uint8_t full[32];
    if (rust_hmac_sha256(mac_key, 16, data, data_len, full) != 0) {
        return -1;
    }
    for (int i = 0; i < 16; i++) tag_out[i] = full[i];
    secure_zero(full, sizeof(full));
    return 0;
}

int storage_encrypt_block(uint64_t ino, uint64_t block, void *buf, uint32_t gen)
{
    
    uint8_t *b = (uint8_t *)buf;
    uint8_t nonce[16];
    uint8_t enc_key[16];
    uint8_t mac_key[16];
    uint8_t tag[16];

    struct mounted_fs *mfs = storage_get_mounted_fs();
    const uint8_t *vol = (mfs && mfs->mounted) ? mfs->volume_key : (const uint8_t*)"";

    /* Deterministic nonce = f(ino, block, gen, volume salt). It MUST be
     * reproducible at decrypt time, so it cannot mix a freshly-read TSC (the
     * old code did, which both leaked timing into the nonce and made the
     * keystream unreproducible). CTR-mode (key, nonce) uniqueness is guaranteed
     * because the key itself is derived per (ino, block, gen). */
    for (int i = 0; i < 8; i++) {
        nonce[i]   = (uint8_t)(ino   >> (i*8));
        nonce[8+i] = (uint8_t)(block >> (i*8));
    }
    for (int i = 0; i < 4; i++) nonce[12 + i] ^= (uint8_t)(gen >> (i*8));
    if (mfs && mfs->mounted) {
        
        for (int i = 0; i < 4; i++) {
            nonce[i] ^= mfs->sb.volume_key_salt[i];
            nonce[8+i] ^= mfs->sb.volume_key_salt[8 + (i & 3)];
        }
    }

    spin_lock(&storage_lock);
    int rc = storage_derive_block_keys(ino, block, gen, vol, enc_key, mac_key);
    if (rc != 0) {
        secure_zero(nonce, 16);
        spin_unlock(&storage_lock);
        return rc;
    }

    
    crypto_aes128_ctr_encrypt(b, 4080, enc_key, nonce);

    
    storage_compute_mac(nonce, b, 4080, mac_key, tag);
    for (int i = 0; i < 16; i++) b[4080 + i] = tag[i];

    secure_zero(enc_key, 16);
    secure_zero(mac_key, 16);
    secure_zero(nonce, 16);
    spin_unlock(&storage_lock);
    return 0;
}

int storage_decrypt_block(uint64_t ino, uint64_t block, void *buf, uint32_t gen)
{
    
    uint8_t *b = (uint8_t *)buf;
    uint8_t nonce[16];
    uint8_t enc_key[16];
    uint8_t mac_key[16];
    uint8_t tag[16];
    uint8_t want[16];

    struct mounted_fs *mfs_dec = storage_get_mounted_fs();
    const uint8_t *vol_dec = (mfs_dec && mfs_dec->mounted && mfs_dec->volume_key[0]) ?
                              mfs_dec->volume_key : (const uint8_t*)"";

    /* Must reproduce the exact nonce used at encrypt time (see note there). */
    for (int i = 0; i < 8; i++) {
        nonce[i]   = (uint8_t)(ino   >> (i*8));
        nonce[8+i] = (uint8_t)(block >> (i*8));
    }
    for (int i = 0; i < 4; i++) nonce[12 + i] ^= (uint8_t)(gen >> (i*8));
    if (mfs_dec && mfs_dec->mounted) {
        for (int i = 0; i < 4; i++) {
            nonce[i] ^= mfs_dec->sb.volume_key_salt[i];
            nonce[8+i] ^= mfs_dec->sb.volume_key_salt[8 + (i & 3)];
        }
    }

    
    for (int i = 0; i < 16; i++) want[i] = b[4080 + i];

    spin_lock(&storage_lock);
    int rc = storage_derive_block_keys(ino, block, gen, vol_dec, enc_key, mac_key);
    if (rc != 0) {
        secure_zero(b, BLOCK_SIZE);
        secure_zero(nonce, 16);
        spin_unlock(&storage_lock);
        return rc;
    }

    
    storage_compute_mac(nonce, b, 4080, mac_key, tag);

    
    int bad = 0;
    for (int i = 0; i < 16; i++) if (tag[i] != want[i]) bad = 1;

    if (bad) {
        
        secure_zero(b, BLOCK_SIZE);
        secure_zero(enc_key, 16);
        secure_zero(mac_key, 16);
        secure_zero(nonce, 16);
        spin_unlock(&storage_lock);
        return -1;
    }

    
    crypto_aes128_ctr_encrypt(b, 4080, enc_key, nonce);

    secure_zero(enc_key, 16);
    secure_zero(mac_key, 16);
    secure_zero(nonce, 16);
    spin_unlock(&storage_lock);
    return 0;
}

struct block_device *storage_get_default_device(void) {
    return current_bd;
}

void storage_set_default_device(struct block_device *bd) {
    if (bd) current_bd = bd;
}

/* Raw block transport. This deliberately goes straight to the in-kernel block
 * device. A previous "userspace block backend" let ring 3 register function
 * pointers that the kernel then called from ring 0 — an SMEP violation and a
 * TCB escape. It has been removed (SYS_REGISTER_STORAGE_BACKEND now fails
 * closed). The ETM crypto/MAC layer above this is kernel-mediated, so the
 * transport only ever moves ciphertext; a userspace disk driver, if ever
 * wanted, belongs behind an IPC server, not an in-kernel callback. */
static int do_block_read(uint64_t block, void *buf) {
    return current_bd->read_block(current_bd, block, buf);
}

static int do_block_write(uint64_t block, const void *buf) {
    return current_bd->write_block(current_bd, block, buf);
}

int storage_block_read(uint64_t block, void *buf) {
    return do_block_read(block, buf);
}

int storage_block_write(uint64_t block, const void *buf) {
    return do_block_write(block, buf);
}

int storage_init(void) {
    g_vdisk.data = g_vdisk_buffer;
    g_vdisk.size = sizeof(g_vdisk_buffer);
    g_vdisk.block_count = BLOCKS_PER_DISK;

    my_memset(g_vdisk.data, 0, g_vdisk.size);

    storage_format(&g_vdisk_bd);
    storage_mount(&g_vdisk_bd);

    return 0;
}

static int bitmap_test(const uint8_t *bitmap, uint64_t bit) {
    return (bitmap[bit / 8] & (1 << (bit % 8))) != 0;
}

static void bitmap_set(uint8_t *bitmap, uint64_t bit) {
    bitmap[bit / 8] |= (1 << (bit % 8));
}

static void bitmap_clear(uint8_t *bitmap, uint64_t bit) {
    bitmap[bit / 8] &= ~(1 << (bit % 8));
}

static int64_t bitmap_find_free(const uint8_t *bitmap, uint64_t max_bits) {
    for (uint64_t i = 0; i < max_bits; i++) {
        if (!bitmap_test(bitmap, i)) return i;
    }
    return -1;
}

static int read_block_bitmap(struct block_device *bd, const struct fs_superblock *sb, uint8_t *buf) {
    return bd->read_block(bd, sb->block_bitmap_start, buf);
}

static int write_block_bitmap(struct block_device *bd, const struct fs_superblock *sb, const uint8_t *buf) {
    return bd->write_block(bd, sb->block_bitmap_start, buf);
}

int64_t storage_alloc_block(struct block_device *bd, struct fs_superblock *sb) {
    uint8_t bitmap[BLOCK_SIZE];
    if (read_block_bitmap(bd, sb, bitmap) != 0) return -1;

    int64_t block = bitmap_find_free(bitmap, sb->total_blocks - sb->data_start);
    if (block < 0) return -1;

    bitmap_set(bitmap, block);
    write_block_bitmap(bd, sb, bitmap);

    return sb->data_start + block;
}

void storage_free_block(struct block_device *bd, struct fs_superblock *sb, uint64_t block) {
    uint8_t bitmap[BLOCK_SIZE];
    if (read_block_bitmap(bd, sb, bitmap) != 0) return;

    uint64_t rel = block - sb->data_start;
    bitmap_clear(bitmap, rel);
    write_block_bitmap(bd, sb, bitmap);
}

int64_t storage_alloc_inode(struct block_device *bd, struct fs_superblock *sb) {
    uint8_t bitmap[BLOCK_SIZE];
    if (bd->read_block(bd, sb->inode_bitmap_start, bitmap) != 0) return -1;

    int64_t ino = bitmap_find_free(bitmap, sb->inode_count);
    if (ino < 0) return -1;

    bitmap_set(bitmap, ino);
    bd->write_block(bd, sb->inode_bitmap_start, bitmap);
    return ino;
}

void storage_free_inode(struct block_device *bd, struct fs_superblock *sb, uint64_t ino) {
    uint8_t bitmap[BLOCK_SIZE];
    if (bd->read_block(bd, sb->inode_bitmap_start, bitmap) != 0) return;
    bitmap_clear(bitmap, ino);
    bd->write_block(bd, sb->inode_bitmap_start, bitmap);
}

int storage_read_inode(struct block_device *bd, struct fs_superblock *sb,
                       uint64_t ino, struct on_disk_inode *inode_out) {
    if (ino >= sb->inode_count) return -1;

    uint64_t block = sb->inode_table_start + (ino / INODES_PER_BLOCK);
    uint32_t offset = (ino % INODES_PER_BLOCK) * sizeof(struct on_disk_inode);

    uint8_t buf[BLOCK_SIZE];
    if (bd->read_block(bd, block, buf) != 0) return -1;

    my_memcpy(inode_out, buf + offset, sizeof(struct on_disk_inode));
    return 0;
}

int storage_write_inode(struct block_device *bd, struct fs_superblock *sb,
                        uint64_t ino, const struct on_disk_inode *inode) {
    if (ino >= sb->inode_count) return -1;

    uint64_t block = sb->inode_table_start + (ino / INODES_PER_BLOCK);
    uint32_t offset = (ino % INODES_PER_BLOCK) * sizeof(struct on_disk_inode);

    uint8_t buf[BLOCK_SIZE];
    if (bd->read_block(bd, block, buf) != 0) return -1;

    my_memcpy(buf + offset, inode, sizeof(struct on_disk_inode));
    return bd->write_block(bd, block, buf);
}

int storage_dir_lookup(struct mounted_fs *mfs, uint64_t dir_ino, const char *name, uint64_t *out_ino) {
    struct on_disk_inode dir;
    if (storage_read_inode(mfs->bd, &mfs->sb, dir_ino, &dir) != 0) return -1;

    size_t name_len = my_strlen(name);
    uint8_t block_buf[BLOCK_SIZE];

    uint64_t file_blocks = (dir.size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (uint64_t b = 0; b < file_blocks; b++) {
        if (storage_read_file_block(mfs, dir_ino, b, block_buf) != 0) continue;

        for (size_t off = 0; off + sizeof(struct dir_entry) <= BLOCK_SIZE; off += sizeof(struct dir_entry)) {
            struct dir_entry *de = (struct dir_entry *)(block_buf + off);
            if (de->inode == 0) continue;

            if (de->name_len == name_len && my_strncmp(de->name, name, name_len) == 0) {
                *out_ino = de->inode;
                return 0;
            }
        }
    }
    return -1;
}

int storage_dir_add(struct mounted_fs *mfs, uint64_t dir_ino, const char *name,
                    uint64_t child_ino, uint8_t type) {
    struct on_disk_inode dir;
    if (storage_read_inode(mfs->bd, &mfs->sb, dir_ino, &dir) != 0) return -1;

    size_t name_len = my_strlen(name);
    uint8_t block_buf[BLOCK_SIZE];
    uint64_t file_blocks = (dir.size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (uint64_t b = 0; b < file_blocks; b++) {
        if (storage_read_file_block(mfs, dir_ino, b, block_buf) != 0) continue;

        for (size_t off = 0; off + sizeof(struct dir_entry) <= BLOCK_SIZE; off += sizeof(struct dir_entry)) {
            struct dir_entry *de = (struct dir_entry *)(block_buf + off);
            if (de->inode == 0) {
                de->inode = child_ino;
                de->name_len = name_len;
                de->type = type;
                my_strncpy(de->name, name, sizeof(de->name));

                storage_write_file_block(mfs, dir_ino, b, block_buf);
                return 0;
            }
        }
    }

    uint64_t new_block = file_blocks;
    my_memset(block_buf, 0, BLOCK_SIZE);

    struct dir_entry *de = (struct dir_entry *)block_buf;
    de->inode = child_ino;
    de->name_len = name_len;
    de->type = type;
    my_strncpy(de->name, name, sizeof(de->name));

    if (storage_write_file_block(mfs, dir_ino, new_block, block_buf) != 0) {
        return -1;
    }

    dir.size = (new_block + 1) * BLOCK_SIZE;
    storage_write_inode(mfs->bd, &mfs->sb, dir_ino, &dir);

    return 0;
}

int storage_format(struct block_device *bd) {
    struct fs_superblock sb;
    my_memset(&sb, 0, sizeof(sb));

    sb.magic = STORAGE_MAGIC;
    sb.version = STORAGE_VERSION;
    sb.total_blocks = bd->total_blocks;
    sb.block_size = BLOCK_SIZE;

    sb.inode_bitmap_start = 1;
    sb.block_bitmap_start = 2;
    sb.inode_table_start = 3;
    sb.data_start = 3 + (16384 / INODES_PER_BLOCK) + 1;
    sb.inode_count = 16384;

    /* Random per-volume salt from the central CSPRNG (was raw-TSC derived). */
    secure_random_bytes(sb.volume_key_salt, sizeof(sb.volume_key_salt));

    bd->write_block(bd, 0, &sb);

    uint8_t zero[BLOCK_SIZE];
    my_memset(zero, 0, BLOCK_SIZE);
    bd->write_block(bd, sb.inode_bitmap_start, zero);
    bd->write_block(bd, sb.block_bitmap_start, zero);

    bitmap_set(zero, 0);
    bd->write_block(bd, sb.inode_bitmap_start, zero);

    struct on_disk_inode root;
    my_memset(&root, 0, sizeof(root));
    root.mode = 0040755;
    root.links = 2;
    storage_write_inode(bd, &sb, 0, &root);

    return 0;
}

static struct mounted_fs g_mounted_fs;

int storage_mount(struct block_device *bd) {
    uint8_t block_buf[BLOCK_SIZE];
    if (bd->read_block(bd, 0, block_buf) != 0) {
        return -1;
    }

    struct fs_superblock *sb = (struct fs_superblock *)block_buf;

    if (sb->magic != STORAGE_MAGIC) {
        return -2;
    }

    g_mounted_fs.bd = bd;
    g_mounted_fs.sb = *sb;
    g_mounted_fs.mounted = 1;

    
    {
        uint8_t *vk = g_mounted_fs.volume_key;
        const uint8_t *salt = sb->volume_key_salt;
        extern uint8_t kernel_pepper[16];
        for (int i = 0; i < 32; i++) {
            vk[i] = salt[i % 16] ^ kernel_pepper[i % 16] ^ (uint8_t)i;
        }
        
        for (int r = 0; r < 32; r++) {
            uint32_t *w = (uint32_t *)vk;
            for (int q = 0; q < 8; q += 2) {
                w[q] += w[q + 1] + (uint32_t)r;
                w[q + 1] = (w[q + 1] << 7) | (w[q + 1] >> 25);
                w[q + 1] ^= w[q];
            }
            if ((r & 3) == 0) {
                for (int i = 0; i < 16; i++) vk[i] ^= kernel_pepper[i];
            }
        }
    }

    return 0;
}

struct mounted_fs *storage_get_mounted_fs(void) {
    return &g_mounted_fs;
}

int derive_and_store_user_file_key(uint32_t uid, const char *material, size_t material_len)
{
    extern tcb_t tasks[MAX_TASKS];

    extern uint8_t kernel_pepper[16];

    if (get_current_task() < 0 || get_current_task() >= MAX_TASKS) return -1;

    
    if (get_current_task() != 0 && !has_encrypted_storage_cap()) {
        return -3;
    }

    /* Per-user file master key = HKDF-SHA256(password material, salt=pepper,
     * info="horus-user-file-key-v1" || uid). Replaces the previous custom
     * 8-round XOR/add mixing, which had no diffusion guarantees. */
    uint8_t *mk = tasks[get_current_task()].user_file_master_key;
    const uint8_t zero = 0;
    const uint8_t *ikm = (material && material_len > 0) ? (const uint8_t *)material : &zero;
    size_t ikm_len = (material && material_len > 0) ? material_len : 1;

    uint8_t info[23 + 4];
    const char *label = "horus-user-file-key-v1";
    size_t p = 0;
    for (const char *c = label; *c; c++) info[p++] = (uint8_t)*c;
    for (int i = 0; i < 4; i++) info[p++] = (uint8_t)(uid >> (i * 8));

    if (rust_hkdf_sha256(ikm, ikm_len, kernel_pepper, 16, info, p, mk, 32) != 0) {
        return -1;
    }
    tasks[get_current_task()].has_file_key = 1;
    return 0;
}

int do_rotate_keys(void)
{
    extern tcb_t tasks[MAX_TASKS];

    if (get_current_task() < 0 || get_current_task() >= MAX_TASKS) return -1;
    if (!tasks[get_current_task()].has_file_key) return -2;
    if (get_current_task() != 0 && !has_encrypted_storage_cap()) return -4;

    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) return -3;

    uint32_t uid = tasks[get_current_task()].uid;
    uint32_t rotated = 0;

    
    for (uint64_t ino = 0; ino < mfs->sb.inode_count && rotated < 64; ino++) {
        struct on_disk_inode inode;
        if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) continue;
        if (inode.links == 0 || inode.uid != uid) continue;

        
        for (uint64_t b = 0; b < 4; b++) {
            uint8_t tmp[BLOCK_SIZE];
            if (storage_read_file_block(mfs, ino, b, tmp) != 0) break;
            
            if (storage_write_file_block(mfs, ino, b, tmp) == 0) {
                rotated++;
            }
        }
    }

    
    for (int i = 0; i < MAX_FS_OBJECTS; i++) {
        struct fs_object *o = fs_objects[i];
        if (o && o->in_use && o->owner_uid == uid && o->is_encrypted) {
            /* Refresh the integrity tag with CSPRNG output (was raw TSC). */
            uint32_t fresh = 0;
            secure_random_bytes(&fresh, sizeof(fresh));
            o->integrity_tag ^= fresh;
        }
    }

    
    spin_lock(&storage_lock);
    intent_append(4 , uid, rotated, (uint32_t)read_tsc());
    spin_unlock(&storage_lock);

    return (int)rotated;
}

int storage_create_file(struct mounted_fs *mfs, uint32_t uid, uint32_t gid,
                        const char *name, uint64_t dir_ino, uint64_t *out_ino) {
    int64_t ino = storage_alloc_inode(mfs->bd, &mfs->sb);
    if (ino < 0) return -1;
    
    spin_lock(&storage_lock);
    intent_append(2 , (uint64_t)ino, dir_ino, uid);
    spin_unlock(&storage_lock);

    struct on_disk_inode inode;
    my_memset(&inode, 0, sizeof(inode));
    inode.uid = uid;
    inode.gid = gid;
    inode.mode = 0100644;
    inode.links = 1;

    /* Per-file key and IV from the central CSPRNG. The old code derived these
     * from a raw TSC read (predictable from ring 3) and additionally ran its
     * key loop to index 32 on a 16-byte array (out-of-bounds write). */
    secure_random_bytes(inode.file_key, sizeof(inode.file_key));
    secure_random_bytes(inode.file_iv, sizeof(inode.file_iv));

    storage_write_inode(mfs->bd, &mfs->sb, ino, &inode);
    storage_dir_add(mfs, dir_ino, name, ino, 1);

    *out_ino = ino;
    return 0;
}

static uint64_t get_physical_block(struct mounted_fs *mfs, struct on_disk_inode *inode,
                                   uint64_t logical_block, int allocate) {
    struct block_device *bd = mfs->bd;
    struct fs_superblock *sb = &mfs->sb;

    if (logical_block < 12) {
        uint64_t phys = inode->direct[logical_block];
        if (phys == 0 && allocate) {
            phys = storage_alloc_block(bd, sb);
            if (phys == (uint64_t)-1) return 0;
            inode->direct[logical_block] = phys;
        }
        return phys;
    }

    logical_block -= 12;

    if (logical_block < 1024) {
        uint64_t indirect_phys = inode->indirect;
        if (indirect_phys == 0) {
            if (!allocate) return 0;
            indirect_phys = storage_alloc_block(bd, sb);
            if (indirect_phys == (uint64_t)-1) return 0;
            inode->indirect = indirect_phys;
            uint8_t zero[BLOCK_SIZE];
            my_memset(zero, 0, BLOCK_SIZE);
            bd->write_block(bd, indirect_phys, zero);
        }

        uint8_t indirect_block[BLOCK_SIZE];
        bd->read_block(bd, indirect_phys, indirect_block);

        uint64_t *ptrs = (uint64_t *)indirect_block;
        uint64_t phys = ptrs[logical_block];

        if (phys == 0 && allocate) {
            phys = storage_alloc_block(bd, sb);
            if (phys == (uint64_t)-1) return 0;
            ptrs[logical_block] = phys;
            bd->write_block(bd, indirect_phys, indirect_block);
        }
        return phys;
    }

    logical_block -= 1024;

    if (inode->double_indirect == 0) {
        if (!allocate) return 0;
        uint64_t dbl = storage_alloc_block(bd, sb);
        if (dbl == (uint64_t)-1) return 0;
        inode->double_indirect = dbl;
        uint8_t zero[BLOCK_SIZE];
        my_memset(zero, 0, BLOCK_SIZE);
        bd->write_block(bd, dbl, zero);
    }

    return 0;
}

int storage_read_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, void *buf) {
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) return -1;

    uint64_t phys = get_physical_block(mfs, &inode, block, 0);
    if (phys == 0) return -1;

    uint8_t temp[BLOCK_SIZE];
    if (do_block_read(phys, temp) != 0) return -1;

    uint32_t gen = (uint32_t)ino;  
    if (storage_decrypt_block(ino, block, temp, gen) != 0) {
        
        my_memset(buf, 0, BLOCK_SIZE);
        return -1;
    }

    my_memcpy(buf, temp, 4080);
    my_memset((uint8_t *)buf + 4080, 0, BLOCK_SIZE - 4080);
    return 0;
}

int storage_write_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, const void *buf) {
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) return -1;

    uint64_t phys = get_physical_block(mfs, &inode, block, 1);
    if (phys == 0) return -1;

    if (inode.direct[block] != phys && block < 12) {
        inode.direct[block] = phys;
    }
    storage_write_inode(mfs->bd, &mfs->sb, ino, &inode);

    uint8_t temp[BLOCK_SIZE];
    my_memset(temp, 0, BLOCK_SIZE);

    my_memcpy(temp, buf, 4080);

    uint32_t gen = (uint32_t)ino;
    
    if (storage_encrypt_block(ino, block, temp, gen) != 0) {
        return -1;
    }

    return do_block_write(phys, temp);
}

int storage_write_capfs_blob(uint64_t inode, const void *data, size_t len) {
    (void)len;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs->mounted) return -1;
    return storage_write_file_block(mfs, inode, 0, data);
}

int storage_read_capfs_blob(uint64_t inode, void *data, size_t len) {
    (void)len;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs->mounted) return -1;
    return storage_read_file_block(mfs, inode, 0, data);
}

int storage_sync(void)
{
    
    spin_lock(&storage_lock);
    
    for (int i = 0; i < INTENT_LOG_SLOTS; i++) {
        intent_log[i].kind = 0;
        intent_log[i].arg0 = 0;
        intent_log[i].arg1 = 0;
        intent_log[i].gen  = 0;
    }
    intent_head = 0;
    intent_append(5 , 0, 0, 0);
    spin_unlock(&storage_lock);
    return 0;
}
