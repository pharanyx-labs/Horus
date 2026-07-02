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
/* Unused when STORAGE_ATA selects the ATA backend instead of the RAM vdisk. */
static uint8_t g_vdisk_buffer[BLOCKS_PER_DISK * BLOCK_SIZE] __attribute__((unused));

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

/* Per-physical-block AEAD metadata: the 12-byte nonce and 16-byte tag for each
 * encrypted block. Held in kernel RAM rather than stealing 28 bytes from the
 * 512-byte data block, so encryption stays length-preserving and the file/dir
 * layer keeps a full BLOCK_SIZE payload. The backing disk is itself an
 * ephemeral RAM buffer, so this table shares its lifetime; a reformat
 * re-randomises the volume key, so any stale (nonce,tag) simply fails to
 * authenticate (fail-closed) rather than ever decrypting wrongly. */
struct block_crypto_meta {
    uint8_t nonce[AEAD_NONCE_LEN];
    uint8_t tag[AEAD_TAG_LEN];
    uint8_t present;
};
static struct block_crypto_meta g_block_meta[BLOCKS_PER_DISK];

/* Per-block subkeys = HKDF-SHA256(ikm = volume key, salt = kernel pepper,
 * info = "horus-block-aead-v2" || ino || block) -> enc_key(32) || mac_key(32).
 * Binding (ino, block) into `info` gives every block independent keys, and the
 * split into two 32-byte subkeys keeps the AEAD's encryption and MAC keys
 * independent (required for the Encrypt-then-MAC composition to be sound). */
int storage_derive_block_keys(uint64_t ino, uint64_t block,
                              const uint8_t *vol_key, size_t vol_key_len,
                              uint8_t *enc_key32, uint8_t *mac_key32)
{
    extern uint8_t kernel_pepper[16];
    uint8_t info[19 + 8 + 8];
    const char *label = "horus-block-aead-v2";
    size_t p = 0;
    for (const char *c = label; *c; c++) info[p++] = (uint8_t)*c;
    for (int i = 0; i < 8; i++) info[p++] = (uint8_t)(ino >> (i * 8));
    for (int i = 0; i < 8; i++) info[p++] = (uint8_t)(block >> (i * 8));

    uint8_t okm[64];
    if (rust_hkdf_sha256(vol_key, vol_key_len, kernel_pepper, 16, info, p, okm, sizeof(okm)) != 0) {
        return -1;
    }
    for (int i = 0; i < 32; i++) {
        enc_key32[i] = okm[i];
        mac_key32[i] = okm[32 + i];
    }
    secure_zero(okm, sizeof(okm));
    return 0;
}

/* AAD = ino(8 LE) || block(8 LE): authenticates each block's logical location
 * so an authentic block cannot be replayed at a different (ino, block). */
static size_t storage_block_aad(uint64_t ino, uint64_t block, uint8_t *aad16)
{
    for (int i = 0; i < 8; i++) aad16[i]     = (uint8_t)(ino   >> (i * 8));
    for (int i = 0; i < 8; i++) aad16[8 + i] = (uint8_t)(block >> (i * 8));
    return 16;
}

/* Encrypt `buf` (full BLOCK_SIZE) in place with the ChaCha20 + HMAC-SHA256
 * AEAD, drawing a FRESH random nonce per write (so rewriting a block can never
 * reuse a keystream -- the two-time-pad flaw the old deterministic-nonce CTR
 * mode had), and recording (nonce,tag) in the metadata table keyed by physical
 * block. */
int storage_encrypt_block(uint64_t phys, uint64_t ino, uint64_t block, void *buf)
{
    if (phys >= BLOCKS_PER_DISK) return -1;
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) return -1;

    uint8_t enc_key[32], mac_key[32];
    uint8_t nonce[AEAD_NONCE_LEN], tag[AEAD_TAG_LEN], aad[16];

    spin_lock(&storage_lock);
    int rc = storage_derive_block_keys(ino, block, mfs->volume_key,
                                       sizeof(mfs->volume_key), enc_key, mac_key);
    if (rc != 0) {
        spin_unlock(&storage_lock);
        return rc;
    }

    secure_random_bytes(nonce, sizeof(nonce));
    size_t aad_len = storage_block_aad(ino, block, aad);

    rc = rust_aead_seal(enc_key, mac_key, nonce, aad, aad_len,
                        (uint8_t *)buf, BLOCK_SIZE, tag);
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    if (rc != 0) {
        spin_unlock(&storage_lock);
        return -1;
    }

    for (int i = 0; i < AEAD_NONCE_LEN; i++) g_block_meta[phys].nonce[i] = nonce[i];
    for (int i = 0; i < AEAD_TAG_LEN; i++)   g_block_meta[phys].tag[i]   = tag[i];
    g_block_meta[phys].present = 1;
    spin_unlock(&storage_lock);
    return 0;
}

/* Verify + decrypt `buf` (full BLOCK_SIZE) in place. Loads the per-block
 * (nonce,tag) recorded at encrypt time; a block never written through the AEAD,
 * or one whose tag/AAD/key no longer matches, fails closed (buf zeroed). */
int storage_decrypt_block(uint64_t phys, uint64_t ino, uint64_t block, void *buf)
{
    if (phys >= BLOCKS_PER_DISK) { secure_zero(buf, BLOCK_SIZE); return -1; }
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) { secure_zero(buf, BLOCK_SIZE); return -1; }

    uint8_t enc_key[32], mac_key[32];
    uint8_t nonce[AEAD_NONCE_LEN], tag[AEAD_TAG_LEN], aad[16];

    spin_lock(&storage_lock);
    if (!g_block_meta[phys].present) {
        spin_unlock(&storage_lock);
        secure_zero(buf, BLOCK_SIZE);
        return -1;
    }
    for (int i = 0; i < AEAD_NONCE_LEN; i++) nonce[i] = g_block_meta[phys].nonce[i];
    for (int i = 0; i < AEAD_TAG_LEN; i++)   tag[i]   = g_block_meta[phys].tag[i];

    int rc = storage_derive_block_keys(ino, block, mfs->volume_key,
                                       sizeof(mfs->volume_key), enc_key, mac_key);
    if (rc != 0) {
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        spin_unlock(&storage_lock);
        secure_zero(buf, BLOCK_SIZE);
        return rc;
    }

    size_t aad_len = storage_block_aad(ino, block, aad);
    rc = rust_aead_open(enc_key, mac_key, nonce, aad, aad_len,
                        (uint8_t *)buf, BLOCK_SIZE, tag);
    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    spin_unlock(&storage_lock);
    /* rust_aead_open zeroes buf itself on authentication failure. */
    return (rc == 0) ? 0 : -1;
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

#ifdef STORAGE_ATA
/* ATA-backed block device. A block is one 512-byte LBA sector (BLOCK_SIZE), so
 * the mapping is 1:1. Selected at build time with STORAGE_ATA=1; the crypto
 * metadata table (nonce/tag) still lives in kernel RAM this increment, so files
 * survive within a boot but cross-reboot persistence needs the meta persisted
 * too (documented follow-up). */
static int atadisk_read(struct block_device *bd, uint64_t block, void *buf) {
    (void)bd;
    return ata_read((uint32_t)block, buf, 1);
}
static int atadisk_write(struct block_device *bd, uint64_t block, const void *buf) {
    (void)bd;
    return ata_write((uint32_t)block, buf, 1);
}
static struct block_device g_ata_bd = {
    .name = "ata0",
    .total_blocks = BLOCKS_PER_DISK,
    .read_block = atadisk_read,
    .write_block = atadisk_write,
    .private = 0,
};
#endif

int storage_init(void) {
#ifdef STORAGE_ATA
    /* Persistent backing: probe the ATA disk. If it already holds a valid Horus
     * volume, mount it; otherwise format-on-first-boot then mount. */
    ata_init();
    current_bd = &g_ata_bd;
    if (storage_mount(&g_ata_bd) != 0) {
        if (storage_format(&g_ata_bd) != 0) return -1;
        if (storage_mount(&g_ata_bd) != 0) return -1;
    }
    return 0;
#else
    /* Default: ephemeral in-RAM virtual disk. */
    g_vdisk.data = g_vdisk_buffer;
    g_vdisk.size = sizeof(g_vdisk_buffer);
    g_vdisk.block_count = BLOCKS_PER_DISK;

    my_memset(g_vdisk.data, 0, g_vdisk.size);

    current_bd = &g_vdisk_bd;
    if (storage_format(&g_vdisk_bd) != 0) return -1;
    if (storage_mount(&g_vdisk_bd) != 0) return -1;

    return 0;
#endif
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

    int64_t block = bitmap_find_free(bitmap, sb->block_count);
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
    sb.inode_table_start  = 3;

    /* Geometry is computed from the device size instead of hardcoded. One bitmap
     * block addresses at most BLOCK_SIZE*8 (=4096) bits, so both the inode count
     * and the data region are bounded to a single bitmap block; multi-block
     * bitmaps (larger disks) are a documented follow-up. */
    const uint64_t BITS_PER_BLOCK = (uint64_t)BLOCK_SIZE * 8;

    uint64_t inodes = bd->total_blocks / 4;   /* ~1 inode per 4 blocks */
    if (inodes < 16) inodes = 16;
    if (inodes > BITS_PER_BLOCK) inodes = BITS_PER_BLOCK;
    uint64_t table_blocks = (inodes + INODES_PER_BLOCK - 1) / INODES_PER_BLOCK;
    inodes = table_blocks * INODES_PER_BLOCK;

    sb.inode_count = inodes;
    sb.data_start  = sb.inode_table_start + table_blocks;
    if (sb.data_start >= bd->total_blocks) return -1;   /* disk too small */

    uint64_t data_blocks = bd->total_blocks - sb.data_start;
    if (data_blocks > BITS_PER_BLOCK) data_blocks = BITS_PER_BLOCK;
    sb.block_count = data_blocks;

    /* Random per-volume salt from the central CSPRNG (was raw-TSC derived). */
    secure_random_bytes(sb.volume_key_salt, sizeof(sb.volume_key_salt));

    bd->write_block(bd, 0, &sb);

    uint8_t zero[BLOCK_SIZE];
    my_memset(zero, 0, BLOCK_SIZE);
    bd->write_block(bd, sb.block_bitmap_start, zero);

    /* Zero the whole inode table so inodes sharing a block with a freshly used
     * one read back clean (matters on a garbage ATA disk at first format). */
    for (uint64_t b = 0; b < table_blocks; b++) {
        bd->write_block(bd, sb.inode_table_start + b, zero);
    }

    /* inode 0 (root) is allocated in the inode bitmap. */
    bitmap_set(zero, 0);
    bd->write_block(bd, sb.inode_bitmap_start, zero);

    struct on_disk_inode root;
    my_memset(&root, 0, sizeof(root));
    root.type = 2;          /* directory */
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

    /* Volume key = HKDF-SHA256(ikm = kernel pepper, salt = on-disk per-volume
     * salt, info = "horus-volume-key-v1"). Replaces the previous homebrew ARX
     * mixing (which also wrote 32 bytes into this 16-byte field). The pepper is
     * the secret input, so the volume key is unpredictable without it; binding
     * the per-volume salt domain-separates distinct volumes. */
    {
        extern uint8_t kernel_pepper[16];
        const char *label = "horus-volume-key-v1";
        uint8_t info[19];
        size_t p = 0;
        for (const char *c = label; *c; c++) info[p++] = (uint8_t)*c;
        if (rust_hkdf_sha256(kernel_pepper, 16,
                             sb->volume_key_salt, sizeof(sb->volume_key_salt),
                             info, p,
                             g_mounted_fs.volume_key, sizeof(g_mounted_fs.volume_key)) != 0) {
            g_mounted_fs.mounted = 0;
            return -3;
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

    /* Double-indirect data mapping is not implemented (a documented follow-up),
     * so fail cleanly past the single-indirect range rather than allocating a
     * block we would then leak. Caps a file at 12 + 1024 blocks. */
    return 0;
}

int storage_read_file_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block, void *buf) {
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) return -1;

    uint64_t phys = get_physical_block(mfs, &inode, block, 0);
    if (phys == 0) return -1;

    uint8_t temp[BLOCK_SIZE];
    if (do_block_read(phys, temp) != 0) return -1;

    if (storage_decrypt_block(phys, ino, block, temp) != 0) {
        my_memset(buf, 0, BLOCK_SIZE);
        return -1;
    }

    my_memcpy(buf, temp, BLOCK_SIZE);
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
    my_memcpy(temp, buf, BLOCK_SIZE);

    if (storage_encrypt_block(phys, ino, block, temp) != 0) {
        return -1;
    }

    return do_block_write(phys, temp);
}

/* Free every data block an inode references (direct + single-indirect), clear
 * their per-block crypto metadata, then release the inode. Backs the FS
 * server's delete path via SYS_FS_INODE_FREE. */
int storage_free_inode_blocks(struct mounted_fs *mfs, uint64_t ino) {
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) return -1;

    for (int i = 0; i < 12; i++) {
        if (inode.direct[i]) {
            storage_free_block(mfs->bd, &mfs->sb, inode.direct[i]);
            if (inode.direct[i] < BLOCKS_PER_DISK) g_block_meta[inode.direct[i]].present = 0;
            inode.direct[i] = 0;
        }
    }
    if (inode.indirect) {
        uint8_t ib[BLOCK_SIZE];
        if (mfs->bd->read_block(mfs->bd, inode.indirect, ib) == 0) {
            uint64_t *ptrs = (uint64_t *)ib;
            for (unsigned k = 0; k < BLOCK_SIZE / sizeof(uint64_t); k++) {
                if (ptrs[k]) {
                    storage_free_block(mfs->bd, &mfs->sb, ptrs[k]);
                    if (ptrs[k] < BLOCKS_PER_DISK) g_block_meta[ptrs[k]].present = 0;
                }
            }
        }
        storage_free_block(mfs->bd, &mfs->sb, inode.indirect);
        if (inode.indirect < BLOCKS_PER_DISK) g_block_meta[inode.indirect].present = 0;
        inode.indirect = 0;
    }

    inode.size = 0;
    inode.links = 0;
    storage_write_inode(mfs->bd, &mfs->sb, ino, &inode);
    storage_free_inode(mfs->bd, &mfs->sb, ino);
    return 0;
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
