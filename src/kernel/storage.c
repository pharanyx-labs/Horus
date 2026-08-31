#include "kernel.h"

int fs_server_task_id = -1;
int fs_server_listen_ep_idx = -1;

static int storage_format_sealed(struct block_device *bd, const char *password, size_t plen);
int storage_mount(struct block_device *bd);
int storage_unlock(const char *password, size_t plen);
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

#define STORAGE_MAGIC   0x48534653

/* The smallest volume worth laying out: superblock, metadata region, TPM blob,
 * key slots, user table, Merkle nodes, journal, both bitmaps and the inode table
 * come to roughly forty blocks before a single byte of data. 512 blocks (2 MiB)
 * leaves a data region that is small but real. storage_format_sealed fails
 * closed on anything it cannot fit anyway; this exists so a too-small disk is
 * REPORTED as one rather than surfacing as a format that mysteriously fails. */
#define STORAGE_MIN_BLOCKS  512u
/* Which slot opened the volume this boot, and the uid sealed inside it. Set by
 * storage_unlock; read by storage_unlock_as so login can identify the caller
 * from the slot that opened rather than from a name it has not verified. */
static uint32_t g_unlocked_slot = 0;
static uint32_t g_unlocked_uid  = 0;

#define STORAGE_VERSION 12  /* v12: the volume is sized from the DISK rather than
                             * from BLOCKS_PER_DISK, and four things changed with
                             * it, every one of them moving bytes: an inode gained
                             * triple_indirect (248 bytes, 16 to a block instead
                             * of 2, so the whole inode table is at different
                             * offsets); the inode bitmap spans blocks, shifting
                             * every region after it; the superblock gained
                             * needs_fsck. A v11 volume read as v12 would find its
                             * inode table where its block bitmap is.
                             * v11: the rollback MAC is a MERKLE TREE over the
                             * metadata region, stored in its own block region,
                             * whose root replaces sb.meta_hmac in the
                             * superblock. The two-level construction it replaces
                             * hashed sb.meta_blocks * 32 bytes on every metadata
                             * write and held the same bytes in a whole-volume
                             * .bss array -- 1 MiB at 16 GiB, both of them. New
                             * region, new superblock field meaning, new
                             * preimages; nothing about a v10 volume can be read
                             * as a v11 one.
                             * v10: the crypto-metadata region is sized from the
                             * DEVICE (sb.meta_blocks = ceil(total_blocks /
                             * META_ENTRIES_PER_BLOCK)) instead of from
                             * BLOCKS_PER_DISK, and the top-level metadata HMAC
                             * covers sb.meta_blocks block MACs instead of a
                             * fixed-size array. Both change bytes a v9 volume
                             * has in different places, and the second changes
                             * the HMAC PREIMAGE -- so a v9 volume read as v10
                             * would fail its integrity check and be reported as
                             * partial metadata rollback, which is a far worse
                             * thing to tell someone than "unsupported version".
                             * v9: BLOCK_SIZE is 4 KiB, not 512 B. THE BUMP IS
                             * LOAD-BEARING, not bookkeeping: a v8 volume's
                             * blocks are 512 bytes, and without a version change
                             * it would pass the `version != STORAGE_VERSION`
                             * check and be reinterpreted at 4 KiB -- every
                             * offset wrong by 8x, on somebody's real disk. The
                             * refusal is what turns that into "unsupported"
                             * instead of "corrupted".
                             * v8: the user table is sealed on disk, so accounts
                             * survive a reboot (docs/LIMITATIONS.md 2.6).
                             * v7: LUKS-style key slots -- up to HORUS_KEYSLOTS passwords
                             * open one volume, each wrapping disk_key||uid in its own slot.
                             * A v6 volume is refused at mount, as every earlier version
                             * already was: the check is `version != STORAGE_VERSION`, so
                             * there is no compatibility path to write and none is pretended.
                             * v6: adds measured-boot TPM sealing (tpm_mode + blob block).
                             * A version bump reformats older volumes at first login,
                             * as every prior bump has (v4->v5 did the same). */

static struct virtual_disk g_vdisk;
/* The RAM vdisk's backing store lives in the physical pool (reserved by
 * init_user_page_allocator), not in .bss — so the volume can be larger than the
 * ~2 MiB a .bss array allowed. Set at boot to PHYS_KVA(pool staging reserve end).
 * Only touched on a diskless boot (the ATA backend uses the real device). */
uint8_t *g_vdisk_backing = 0;

/* Deferred-format state: storage_init() sets this when no valid disk is found,
 * then storage_unlock() (called at first login) formats+seals with the user's
 * password so disk_key is never committed to disk without a KEK. */
static int                  g_needs_format    = 0;
/* Deliberate authorisation to format a blank volume. An installer sets this;
 * a login does not. See storage_unlock. */
static int                  g_format_authorized = 0;
static struct block_device *g_needs_format_bd = NULL;

/* Set for the lifetime of a boot that runs on the ephemeral in-RAM vdisk (see
 * storage_init). That volume's "password" is a 256-bit CSPRNG value discarded
 * after unlock — there is nothing to brute-force, so the memory-hard Argon2id
 * step buys no security and only costs boot time. On this path derive_kek uses a
 * plain HKDF-SHA256 expansion of the full-entropy key instead. Stays 0 for any
 * real (ATA) disk, whose KEK comes from a low-entropy user password and MUST keep
 * Argon2id. Set once at boot, single-threaded; the vdisk is the only volume the
 * boot touches, so format and unlock derive the KEK the same way (a mismatch
 * would make the AEAD unwrap fail). */
static int g_vdisk_high_entropy_kek = 0;

/* Measured-boot TPM sealing (roadmap 2.2 stage 3). A persistent (ATA) volume is
 * formatted in TPM mode when a TPM is present, so its KEK gains a second factor
 * released only under a measured-good boot. The ephemeral vdisk is never sealed
 * (its key is a per-boot throwaway). g_tpm_force_seal lets the KEK self-test drive
 * the sealed path over the vdisk deterministically. */
static int g_tpm_force_seal = 0;

/* THE BOUND IS THE BACKING STORE, NOT THE ADVERTISED GEOMETRY.
 *
 * These two used to be the same number and stopped being one on 2026-08-31.
 * `g_vdisk_bd.total_blocks` was BLOCKS_PER_DISK -- the ceiling on the LARGEST
 * volume the crypto-metadata array can describe -- while the backing store is a
 * VDISK_BLOCKS-sized reservation in the physical pool. Raising BLOCK_SIZE to
 * 4 KiB was what split them: VDISK_BLOCKS was introduced precisely so the RAM
 * disk would not become 128 MiB of pool reservation as a side effect, and the
 * device's advertised size was left behind. A 32768-block device over a
 * 4096-block reservation accepts block 4096 and writes 4 KiB into the FREE PAGE
 * POOL that begins immediately after it -- reachable from ring 3 by writing
 * enough file data on any diskless boot, which is every CI boot.
 *
 * So the check tests `vd->block_count`, which is a property of the memory that
 * actually exists, as well as the geometry the device advertises. Both, not
 * either: `total_blocks` is what the filesystem lays itself out against, so a
 * device claiming more than it has is still a defect worth failing on, and
 * `block_count` is the one that cannot be wrong by construction. Falsified by
 * VDISK_TOTAL_UNBOUNDED=1 (make smoke-vdisk-bound-control). */
static int vdisk_read(struct block_device *bd, uint64_t block, void *buf) {
    struct virtual_disk *vd = (struct virtual_disk *)bd->private;
    if (block >= bd->total_blocks) return -1;
#ifndef VDISK_TOTAL_UNBOUNDED
    if (block >= vd->block_count) return -1;
#endif

    uint8_t *src = vd->data + (block * BLOCK_SIZE);
    uint8_t *d = buf;
    for (size_t i = 0; i < BLOCK_SIZE; i++) d[i] = src[i];
    return 0;
}

static int vdisk_write(struct block_device *bd, uint64_t block, const void *buf) {
    struct virtual_disk *vd = (struct virtual_disk *)bd->private;
    if (block >= bd->total_blocks) return -1;
#ifndef VDISK_TOTAL_UNBOUNDED
    if (block >= vd->block_count) return -1;   /* see vdisk_read */
#endif

    uint8_t *dst = vd->data + (block * BLOCK_SIZE);
    const uint8_t *s = buf;
    for (size_t i = 0; i < BLOCK_SIZE; i++) dst[i] = s[i];
    return 0;
}

/* The RAM vdisk has no volatile layer between vdisk_write and "the medium" —
 * the medium IS the RAM it just wrote to. So this genuinely succeeds rather than
 * being a stub. It is spelled out explicitly instead of left NULL because
 * raw_block_flush() fails closed on a NULL flush, and "this backend has nothing
 * to flush" and "this backend forgot to implement durability" must not look the
 * same to the journal. Note the vdisk is ephemeral by construction: it does not
 * survive a reboot at all, so there is no crash-atomicity claim to weaken. */
static int vdisk_flush(struct block_device *bd) {
    (void)bd;
    return 0;
}

/* VDISK_BLOCKS, not BLOCKS_PER_DISK: this device is exactly as large as the
 * reservation behind it. See vdisk_read for what the two being confused cost. */
static struct block_device g_vdisk_bd = {
    .name = "vdisk0",
#ifdef VDISK_TOTAL_UNBOUNDED
    /* THE DEFECT IS "MORE THAN THE BACKING", NOT A PARTICULAR NUMBER.
     *
     * This said BLOCKS_PER_DISK, which was the historical value and reproduced
     * exactly. When BLOCKS_PER_DISK became a 16 GiB ceiling the arm stopped
     * reproducing -- not because the defect was fixed but because it became
     * catastrophic: format lays a 16 GiB volume out over a 16 MiB reservation,
     * the metadata region alone runs a hundred megabytes past the end, and the
     * boot dies before the probe can say anything. An arm that kills the boot
     * witnesses nothing.
     *
     * Eight times the backing is the same defect at a size the probe survives:
     * the device advertises blocks it has no memory for, block VDISK_BLOCKS is
     * accepted, and the bytes land in the free page pool -- which is the claim.
     * A control arm has to track the shape of its defect, not the constant the
     * defect happened to be written with. */
    .total_blocks = VDISK_BLOCKS * 8,
#else
    .total_blocks = VDISK_BLOCKS,
#endif
    .read_block = vdisk_read,
    .write_block = vdisk_write,
    .flush = vdisk_flush,
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

/* Per-physical-block AEAD metadata: nonce (12), tag (16), present flag (1),
 * and 3 bytes of padding to reach exactly META_ENTRY_SIZE=32 bytes.  Packing
 * to 32 bytes lets META_ENTRIES_PER_BLOCK of them fill one filesystem block
 * exactly, so the on-disk region is a flat array of sb.meta_blocks blocks.  It is
 * written back inside the journal transaction that changed it, so it survives a
 * reboot AND a crash; a missing or corrupt entry causes AEAD to fail closed
 * (buffer zeroed, -1 returned) rather than ever decrypting wrongly. */
struct block_crypto_meta {
    uint8_t nonce[AEAD_NONCE_LEN];   /* 12 */
    uint8_t tag[AEAD_TAG_LEN];       /* 16 */
    uint8_t present;                  /*  1 */
    uint8_t _pad[3];                  /*  3 → total 32 = META_ENTRY_SIZE */
};
_Static_assert(sizeof(struct block_crypto_meta) == META_ENTRY_SIZE,
               "block_crypto_meta must be META_ENTRY_SIZE bytes");
/* Every member is a uint8_t, so the struct's alignment is 1 and a pointer to it
 * may be taken at any offset inside a cache line's raw image. Asserted rather
 * than assumed, because that is the only reason meta_entry_in() is allowed to
 * exist and a padding member of a wider type would silently break it. */
_Static_assert(_Alignof(struct block_crypto_meta) == 1,
               "block_crypto_meta must be byte-aligned to overlay a raw block image");

/* ---- the bounded metadata cache (stage 2, docs/design/meta-cache-merkle.md) --
 *
 * WHAT THIS REPLACED, AND WHAT THAT COST. Until 2026-08-31 this was
 * `g_block_meta[BLOCKS_PER_DISK]`, a COMPLETE in-RAM mirror of the on-disk
 * nonce/tag region: 32 bytes per block of the largest volume the kernel could
 * describe, whether or not the volume in front of it was that large. 1 MiB of
 * .bss at a 128 MiB volume, and 128 MiB at the 16 GiB volume this work exists to
 * reach -- against a linker budget of 16 MiB for the whole image's .bss. The
 * mirror was not merely large, it was the reason the volume size could not grow.
 *
 * A line holds ONE metadata block, byte for byte as it lives on the platter.
 * Keeping the raw image rather than a decoded array is deliberate: the write-back
 * is then a memcpy-free `do_block_write` of the line, the MAC input IS the line,
 * and there is no serialisation step that could disagree with the on-disk layout.
 *
 * THE PROPERTY THIS STRUCTURE HAS TO CARRY (SECURITY.md S65). A dirty line is
 * written back INTO THE JOURNAL TRANSACTION THAT DIRTIED IT, before that
 * transaction commits. journal_commit flushes; journal_abort discards. Two
 * consequences, both of which are the point:
 *
 *   - no line is ever dirty across a commit, so a crash cannot lose a metadata
 *     update that a committed transaction promised (failure modes E1/E4), and
 *   - the metadata write is inside the same atomic unit as the ciphertext and
 *     the inode it belongs to (failure mode E2), so a crash leaves the file
 *     wholly before or wholly after -- never with a data block the journal
 *     replayed and a nonce it did not.
 *
 * WHY THE JOURNAL IS NOW LOAD-BEARING IN A WAY IT WAS NOT. A complete mirror is
 * SELF-HEALING against a lost metadata write: it holds every entry, so the next
 * flush of that block regenerates the lost one from RAM. That was a real
 * property of the old design, it was written down nowhere, and a bounded cache
 * removes it -- once a line leaves RAM, the only copy is the one on disk. The
 * journal is what makes that safe, and META_CACHE_NO_WRITEBACK=1 is the arm that
 * shows it (docs/BUILDING.md).
 *
 * Eviction also writes a dirty line back. On every workload in this tree that
 * path is UNREACHABLE -- each transaction dirties one line and commits it, so a
 * line is clean by the time anything can evict it -- and it is kept as a backstop
 * for the day a transaction dirties more lines than the cache holds.
 * META_CACHE_EVICT_NOWB=1 removes it; that arm is measured and deliberately does
 * NOT gate, for the same reason SPAWN_STAGE_UNSERIALISED does not: a control arm
 * that cannot fail cannot gate. */
#define META_BLK_NONE  ((uint64_t)-1)

struct meta_cache_line {
    uint64_t meta_blk;              /* index into the region, or META_BLK_NONE */
    uint32_t stamp;                 /* LRU clock reading at last use */
    uint8_t  dirty;
    uint8_t  _pad[3];
    uint8_t  img[BLOCK_SIZE];       /* the block, exactly as it lives on disk */
};
static struct meta_cache_line g_meta_cache[META_CACHE_LINES];
static uint32_t g_meta_clock;
/* Evictions of an OCCUPIED line, since boot. Arm A asserts this is non-zero:
 * a working set that fits in the cache never evicts, so a run that verified
 * every block without evicting has tested nothing about eviction, and growing
 * the cache later would silently turn that gate into a no-op. */
static uint64_t g_meta_evictions;
/* Of those, how many were DIRTY. The eviction write-back below is believed
 * unreachable -- a transaction dirties one line and journal_commit writes it
 * back before anything can evict it -- and this counter is what makes that a
 * MEASUREMENT rather than an argument. Every crash-gate boot prints it; it has
 * been 0 in every run, which is why META_CACHE_EVICT_NOWB=1 does not gate. If
 * it ever prints non-zero, that arm has become reachable and should. */
static uint64_t g_meta_dirty_evictions;

static struct block_crypto_meta *meta_entry_in(struct meta_cache_line *l, uint64_t phys)
{
    return (struct block_crypto_meta *)
           (l->img + (phys % META_ENTRIES_PER_BLOCK) * META_ENTRY_SIZE);
}

uint64_t meta_cache_evictions(void)       { return g_meta_evictions; }
uint64_t meta_cache_dirty_evictions(void) { return g_meta_dirty_evictions; }

/* forward declarations — defined after do_block_read/do_block_write */
static struct meta_cache_line *meta_cache_get(uint64_t meta_blk);
static int  meta_cache_flush_line(struct meta_cache_line *l);
static int  meta_cache_flush_all(void);
static void meta_cache_drop_dirty(void);
static void meta_cache_reset(void);
static int  merkle_verify_leaf(uint64_t meta_blk, const uint8_t *img);
static int  merkle_update_leaf(uint64_t meta_blk, const uint8_t *img);
static int  merkle_flush_all(void);
static void merkle_drop_dirty(void);
static void merkle_cache_reset(void);
/* Is a journal transaction open? The transaction state is declared further down
 * with the journal itself; the crypto layer above needs to know whether there is
 * a commit coming that will write its dirty line back for it. */
static int journal_txn_open(void);
static int  derive_kek(const char *password, size_t plen,
                       const uint8_t *kek_salt, uint8_t *kek32);
static void storage_fsck_pass(struct mounted_fs *mfs);

/* Per-block subkeys = HKDF-SHA256(ikm = volume_key, salt = disk_key,
 * info = "horus-block-aead-v3" || ino || block) -> enc_key(32) || mac_key(32).
 *
 * Salt changed from kernel_pepper (per-boot ephemeral) to disk_key (per-format
 * stable).  The old v2 derivation made every block undecryptable after reboot
 * because kernel_pepper changes on every boot.  disk_key is stored in the
 * superblock and survives reboots, making ATA-backed files persistent.
 *
 * Security property: keys are unknown to anyone who cannot read disk_key from
 * the superblock.  For passphrase-gated unwrapping (so disk_key itself stays
 * secret without the passphrase), wrap it with a KEK — future work. */
int storage_derive_block_keys(uint64_t ino, uint64_t block,
                              const uint8_t *vol_key, size_t vol_key_len,
                              uint8_t *enc_key32, uint8_t *mac_key32)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || !mfs->unlocked) return -1;

    uint8_t info[19 + 8 + 8];
    const char *label = "horus-block-aead-v3";
    size_t p = 0;
    for (const char *c = label; *c; c++) info[p++] = (uint8_t)*c;
    for (int i = 0; i < 8; i++) info[p++] = (uint8_t)(ino   >> (i * 8));
    for (int i = 0; i < 8; i++) info[p++] = (uint8_t)(block >> (i * 8));

    uint8_t okm[64];
    if (rust_hkdf_sha256(vol_key, vol_key_len,
                         mfs->disk_key, sizeof(mfs->disk_key),
                         info, p, okm, sizeof(okm)) != 0) {
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
    if (!mfs || !mfs->mounted || !mfs->unlocked) return -1;

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

    /* Record nonce+tag in the resident line for this block's metadata block and
     * mark it dirty. The WRITE-BACK belongs to journal_commit, which stages it
     * into the very transaction that dirtied it -- so the nonce, the ciphertext,
     * the inode and the bitmap all commit as one unit and a crash leaves the file
     * wholly before or wholly after.
     *
     * This used to flush here, immediately, and the comment justified doing so by
     * the ordering it produced: a crash between the metadata write and the data
     * write left new-meta / old-ciphertext, which the AEAD rejects. That is
     * fail-closed but it is still a LOST BLOCK, and it was only ever the best
     * available answer because the flush was outside the caller's transaction in
     * spirit even though do_block_write staged it. Committing them together
     * removes the window rather than making it safe to land in. */
    struct meta_cache_line *l = meta_cache_get(phys / META_ENTRIES_PER_BLOCK);
    if (!l) { spin_unlock(&storage_lock); return -1; }
    struct block_crypto_meta *e = meta_entry_in(l, phys);
    for (int i = 0; i < AEAD_NONCE_LEN; i++) e->nonce[i] = nonce[i];
    for (int i = 0; i < AEAD_TAG_LEN; i++)   e->tag[i]   = tag[i];
    e->present = 1;
    for (int i = 0; i < 3; i++) e->_pad[i] = 0;   /* the MAC covers these bytes */
    l->dirty = 1;

    /* No transaction owns this update, so there is no commit to defer to and a
     * dirty line would sit in RAM with nothing coming to write it. Fail closed on
     * the write rather than report success for a nonce that is not on the disk:
     * the caller is about to store ciphertext only this nonce can open. */
    if (!journal_txn_open() && meta_cache_flush_line(l) != 0) {
        spin_unlock(&storage_lock);
        return -1;
    }
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
    if (!mfs || !mfs->mounted || !mfs->unlocked) { secure_zero(buf, BLOCK_SIZE); return -1; }

    uint8_t enc_key[32], mac_key[32];
    uint8_t nonce[AEAD_NONCE_LEN], tag[AEAD_TAG_LEN], aad[16];

    spin_lock(&storage_lock);
    struct meta_cache_line *l = meta_cache_get(phys / META_ENTRIES_PER_BLOCK);
    if (!l) {                       /* region unreadable — fail closed */
        spin_unlock(&storage_lock);
        secure_zero(buf, BLOCK_SIZE);
        return -1;
    }
    const struct block_crypto_meta *e = meta_entry_in(l, phys);
    if (!e->present) {
        spin_unlock(&storage_lock);
        secure_zero(buf, BLOCK_SIZE);
        return -1;
    }
    for (int i = 0; i < AEAD_NONCE_LEN; i++) nonce[i] = e->nonce[i];
    for (int i = 0; i < AEAD_TAG_LEN; i++)   tag[i]   = e->tag[i];

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
static int raw_block_read(uint64_t block, void *buf) {
    return current_bd->read_block(current_bd, block, buf);
}

static int raw_block_write(uint64_t block, const void *buf) {
    return current_bd->write_block(current_bd, block, buf);
}

/* Barrier: return 0 only when every preceding raw_block_write is on stable
 * media. Fails closed on a backend that supplies no flush op — see the comment
 * on block_device.flush. WAL_NO_FLUSH=1 is the control arm for [I-10]: it
 * compiles the barrier out and restores the pre-fix behaviour, in which the
 * journal's ordering constraints are enforced only by whatever the emulator
 * happens to do. It exists so the durability gates can be falsified on demand
 * and must never be set for a shipped build. */
static int raw_block_flush(void) {
#ifdef WAL_NO_FLUSH
    return 0;
#else
    if (!current_bd || !current_bd->flush) return -1;
    return current_bd->flush(current_bd);
#endif
}

/* ---- Write-ahead redo log (journal) --------------------------------------- *
 * A multi-block filesystem update (allocate a data block -> update the bitmap ->
 * link it in the inode -> write the per-block crypto metadata + its superblock
 * rollback tree -> write the ciphertext) touches up to a handful of separate
 * sectors. A crash partway through used to leave the volume inconsistent — and,
 * worst of all, could desync the metadata region from its rollback root, which makes
 * storage_unlock refuse to mount (a whole-volume brick).
 *
 * The journal makes each such update atomic. journal_begin() opens a
 * transaction; while one is open, do_block_write STAGES (block, content) in RAM
 * instead of writing home, and do_block_read returns staged content
 * (read-your-writes). journal_commit() then:
 *   1. writes the staged blocks into the journal data region;
 *      -- BARRIER A --
 *   2. writes the journal header — targets + a keyed HMAC over the payload — in
 *      one atomic sector: this is the commit point;
 *      -- BARRIER B --
 *   3. applies the staged writes to their home locations;
 *      -- BARRIER C --
 *   4. clears the header.
 * A crash before step 2 leaves home untouched (old state); after step 2, mount
 * replays the committed transaction (idempotent redo) to complete it — so the
 * filesystem is always either fully before or fully after the operation.
 *
 * Durability ([I-10]). The numbered steps are ordering constraints on what is on
 * STABLE MEDIA, not merely on the order the driver issued writes. A drive with a
 * volatile write cache may complete WRITEs in any order and lose all of them on
 * power failure, so each barrier is a real FLUSH CACHE and each one is load-
 * bearing in a different way:
 *
 *   A  is the write-ahead rule itself. Without it the header can reach the
 *      platter while the data sectors it commits are still in cache; recovery
 *      then finds a valid, correctly-HMAC'd transaction and redoes it from
 *      journal data that was never written — blind-writing stale content over
 *      good home blocks. This is the barrier that turns "the journal is
 *      write-ahead" from a claim into a fact, and it is the one an earlier
 *      revision of docs/ROADMAP.md 1.55 did not ask for.
 *   B  makes the commit point real. Until the header is durable there is nothing
 *      to replay, so applying home first risks a crash leaving home torn with no
 *      record that would repair it.
 *   C  protects the retire. Clearing the header while the home writes are still
 *      in cache discards the only copy that could replay them — a lost update
 *      that recovery cannot even detect.
 *
 * Barrier failure is NOT advisory. A and B failing abort the transaction with
 * home untouched. C failing leaves the header in place deliberately, so the next
 * mount replays it; see the comment at that call site for why that still returns
 * success. Until 2026-08-16 there were no barriers at all and the ATA driver had
 * no FLUSH CACHE opcode, so the guarantee held only under an emulator that
 * persisted every write on its own.
 *
 * Security: the header carries an HMAC keyed by journal_mac_key (derived from
 * disk_key), so an attacker with raw disk access cannot forge a committed
 * transaction that replay would blind-write to arbitrary blocks; every replay
 * target is bounds-checked to the fs body (never the superblock-below region,
 * never the journal itself). Staged data blocks are already ciphertext; staged
 * metadata is plaintext exactly as it lives on disk — no new disclosure. */
#define JOURNAL_MAGIC     0x4C52574Au        /* "JWRL" */
#define JOURNAL_DATA_MAX  16                  /* max home sectors one txn may touch */
#define JOURNAL_BLOCKS    (1 + JOURNAL_DATA_MAX)   /* header sector + data sectors */

struct journal_header {
    uint32_t magic;                      /* JOURNAL_MAGIC when a committed txn is present */
    uint32_t count;                      /* number of home sectors (1..JOURNAL_DATA_MAX) */
    uint64_t seq;                        /* monotonically increasing; also an HMAC input */
    uint64_t target[JOURNAL_DATA_MAX];   /* home block number for each staged sector */
    uint8_t  hmac[32];                   /* HMAC(journal_mac_key, seq||count||targets||data) */
};
_Static_assert(sizeof(struct journal_header) <= BLOCK_SIZE,
               "journal header must fit one sector");

static struct {
    int      active;
    int      overflow;                   /* a txn tried to touch > JOURNAL_DATA_MAX sectors */
    int      n;
    uint64_t target[JOURNAL_DATA_MAX];
    uint8_t  data[JOURNAL_DATA_MAX][BLOCK_SIZE];
} g_txn;
static uint64_t g_journal_seq = 1;

/* HMAC preimage scratch (seq||count||targets||data), guarded by storage_lock. */
static uint8_t g_jscratch[8 + 4 + JOURNAL_DATA_MAX * 8 + JOURNAL_DATA_MAX * BLOCK_SIZE];

static int do_block_read(uint64_t block, void *buf) {
    if (g_txn.active) {
        for (int i = g_txn.n - 1; i >= 0; i--)          /* newest staged write wins */
            if (g_txn.target[i] == block) { my_memcpy(buf, g_txn.data[i], BLOCK_SIZE); return 0; }
    }
    return raw_block_read(block, buf);
}

static int do_block_write(uint64_t block, const void *buf) {
    if (g_txn.active) {
        for (int i = 0; i < g_txn.n; i++)               /* coalesce repeat writes to a block */
            if (g_txn.target[i] == block) { my_memcpy(g_txn.data[i], buf, BLOCK_SIZE); return 0; }
        if (g_txn.n >= JOURNAL_DATA_MAX) { g_txn.overflow = 1; return -1; }
        g_txn.target[g_txn.n] = block;
        my_memcpy(g_txn.data[g_txn.n], buf, BLOCK_SIZE);
        g_txn.n++;
        return 0;
    }
    return raw_block_write(block, buf);
}

static int journal_txn_open(void) { return g_txn.active; }

static void journal_begin(void) {
    g_txn.active = 1; g_txn.overflow = 0; g_txn.n = 0;
}

static void journal_abort(void) {
    g_txn.active = 0; g_txn.overflow = 0; g_txn.n = 0;   /* discard staged writes; home untouched */
    /* The metadata this transaction dirtied belongs to an operation that did not
     * happen, so it must not survive into the next one. Dropping the lines rather
     * than reverting them is what makes that safe without keeping an undo copy:
     * the next lookup reloads from disk, which still holds the pre-transaction
     * image because home was never touched. */
    meta_cache_drop_dirty();
    /* The tree nodes those lines carried up to the root belong to the same
     * operation and go the same way. Dropping rather than reverting is safe for
     * the same reason: home was never touched, so the on-disk nodes are still
     * the pre-transaction ones. */
    merkle_drop_dirty();
}

static int journal_compute_hmac(const uint8_t *mac_key, uint64_t seq, uint32_t count,
                                const uint64_t *targets, const uint8_t (*data)[BLOCK_SIZE],
                                uint8_t out32[32]) {
    size_t off = 0;
    my_memcpy(g_jscratch + off, &seq,   8); off += 8;
    my_memcpy(g_jscratch + off, &count, 4); off += 4;
    for (uint32_t i = 0; i < count; i++) { my_memcpy(g_jscratch + off, &targets[i], 8); off += 8; }
    for (uint32_t i = 0; i < count; i++) { my_memcpy(g_jscratch + off, data[i], BLOCK_SIZE); off += BLOCK_SIZE; }
    return rust_hmac_sha256(mac_key, 32, g_jscratch, off, out32);
}

/* Crash-injection hook: WAL_CRASHTEST builds halt right after the commit header
 * is durable but before the home apply, to exercise redo recovery on next boot.
 * storage_fresh_format lets the two-boot test tell boot 1 (formatted a fresh
 * disk) from boot 2 (mounted the existing one). */
/* META_CRASH_DROP_ONE was the STAND-IN arm: it cleared one in-RAM entry and
 * skipped its write, to model what a bounded cache would do before there was
 * one. There is a cache now, so the arms act on the cache itself --
 * META_CACHE_NO_WRITEBACK, META_CACHE_WB_OUTSIDE_TXN, META_CACHE_EVICT_NOWB --
 * and the stand-in is gone rather than kept beside them. Two arms for one
 * failure mode, one of which can no longer reach the code that fails, is how a
 * gate ends up testing something other than what its name says. */

#ifdef WAL_CRASHTEST
int g_wal_crash_armed = 0;
int storage_fresh_format = 0;
#endif

/* Commit the open transaction (see the block comment above). Returns 0 on
 * success (or when nothing was staged), -1 on overflow / write error — in which
 * case nothing is applied to home and the caller should surface an error. */
static int journal_commit(void) {
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || mfs->sb.journal_start == 0) { journal_abort(); return -1; }
    if (g_txn.overflow) { journal_abort(); return -1; }

    /* Write back every dirty metadata line INTO THIS TRANSACTION, before any of
     * it is staged to the journal. This is the whole of the cache's durability
     * contract (S65): after this returns, no line is dirty, so a crash cannot
     * lose a metadata update that the commit below is about to promise.
     *
     * It runs before the `g_txn.n == 0` test on purpose -- flushing STAGES
     * writes, so a transaction that had staged nothing of its own can still have
     * something to commit afterwards, and testing first would drop it.
     *
     * META_CACHE_NO_WRITEBACK=1 removes it (and the eviction write-back with it),
     * which is Arm A: the dirty lines then never reach the disk at all and boot 2
     * cannot decrypt the blocks boot 1 wrote.
     * META_CACHE_WB_OUTSIDE_TXN=1 moves it past the end of this function instead,
     * where do_block_write goes straight home -- the metadata escapes the
     * transaction that owns it, and the crash point between the commit header and
     * the home apply then replays a ciphertext block whose nonce was never
     * written (failure mode E2). */
#if !defined(META_CACHE_NO_WRITEBACK) && !defined(META_CACHE_WB_OUTSIDE_TXN)
    if (meta_cache_flush_all() != 0) { journal_abort(); return -1; }
    /* The tree nodes the flush above dirtied travel in the same transaction. A
     * node written outside it would leave the root promising a metadata block
     * that a crash rolled back -- the same class of tear the journal exists to
     * prevent, one layer up. */
    if (merkle_flush_all() != 0)    { journal_abort(); return -1; }
#endif

    if (g_txn.n == 0)   { g_txn.active = 0; return 0; }

    uint32_t count = (uint32_t)g_txn.n;
    uint64_t jstart = mfs->sb.journal_start;

    /* 1. Journal data region. */
    for (uint32_t i = 0; i < count; i++)
        if (raw_block_write(jstart + 1 + i, g_txn.data[i]) != 0) { journal_abort(); return -1; }

    /* BARRIER A — the write-ahead rule. The staged data must be on stable media
     * before the header that commits it, or recovery redoes a valid transaction
     * from journal blocks that never landed. Home is untouched at this point, so
     * aborting here is free and leaves the volume in its pre-transaction state. */
    if (raw_block_flush() != 0) {
        println("WAL: FLUSH FAILED before commit header - transaction aborted");
        journal_abort();
        return -1;
    }

    /* 2. Commit header (one atomic sector). */
    struct journal_header hdr;
    my_memset(&hdr, 0, sizeof(hdr));
    hdr.magic = JOURNAL_MAGIC;
    hdr.count = count;
    hdr.seq   = g_journal_seq;
    for (uint32_t i = 0; i < count; i++) hdr.target[i] = g_txn.target[i];
    if (journal_compute_hmac(mfs->journal_mac_key, hdr.seq, count, hdr.target,
                             (const uint8_t (*)[BLOCK_SIZE])g_txn.data, hdr.hmac) != 0) {
        journal_abort(); return -1;
    }
    uint8_t hbuf[BLOCK_SIZE];
    my_memset(hbuf, 0, BLOCK_SIZE);
    my_memcpy(hbuf, &hdr, sizeof(hdr));
    if (raw_block_write(jstart, hbuf) != 0) { journal_abort(); return -1; }

    /* BARRIER B — make the commit point real before touching home. A crash after
     * this returns is recoverable by redo; a crash while home is being written
     * with the header still only in cache is not. Aborting here still leaves
     * home untouched: the header may or may not survive, but recovery either
     * finds nothing (old state) or replays the full transaction (new state), and
     * both are consistent. */
    if (raw_block_flush() != 0) {
        println("WAL: FLUSH FAILED at commit point - transaction aborted");
        journal_abort();
        return -1;
    }

#ifdef WAL_CRASHTEST
    if (g_wal_crash_armed) {
        /* Commit header is now durable — barrier B above returned success —
         * and the home apply below has NOT run. That is precisely the state a
         * power failure between steps 2 and 3 leaves, so boot 2 exercises redo.
         *
         * Ordering matters here and is the reason the harness can be
         * deterministic ([I-11]). Barrier B is a real FLUSH CACHE and it runs
         * BEFORE this line is printed, so when the marker reaches the serial
         * console the journal write the two-boot test cares about is already on
         * stable media. The harness may therefore end the run the moment it sees
         * the marker without racing anything — it asks QEMU to quit over QMP and
         * waits for the process to exit, rather than signalling it.
         *
         * Halting here, rather than trying to end QEMU from inside the guest, is
         * also deliberate. Roadmap 1.55 proposed `isa-debug-exit`; it does not
         * work. On QEMU 10.0.11 a byte write to port 0x604 does not terminate
         * the process, with or without -no-shutdown (measured both ways), and
         * the `lidt 0x0; int $0x0` triple-fault fallback that kshell.c:99 pairs
         * with it faults while READING the descriptor at address 0, so the
         * kernel's own page-fault handler catches it and prints a PAGE FAULT the
         * harness correctly treats as a failure. Both were tried and reverted.
         * Ending the guest is the harness's job (tools/qmp_quit.py); the guest's
         * job is to stop writing and say so, which is exactly what this does. */
        println("WAL_CRASHTEST: crashed-after-commit");
        for (;;) __asm__ volatile ("hlt");
    }
#endif

    /* 3. Apply to home locations. */
    for (uint32_t i = 0; i < count; i++)
        raw_block_write(g_txn.target[i], g_txn.data[i]);

    /* BARRIER C — home must be durable before the header that would replay it is
     * retired. If this fails we deliberately SKIP step 4 and leave the committed
     * header on disk: the next mount will find it, verify the HMAC and redo the
     * transaction, which is exactly the repair the situation calls for.
     *
     * This returns SUCCESS, and the asymmetry with A and B is deliberate. The
     * transaction IS committed — its header is durable and its effect will be
     * applied — so reporting failure to the caller would be a lie in the more
     * dangerous direction: userspace would be told the write did not happen and
     * would see it happen anyway after the next mount. The only thing that went
     * wrong is that the retire could not be confirmed, and the journal is
     * idempotent precisely so that an un-retired transaction is harmless. */
    if (raw_block_flush() != 0) {
        println("WAL: FLUSH FAILED after home apply - header left for replay");
        g_journal_seq++;
        g_txn.active = 0; g_txn.n = 0;
        /* No cache flush here even under META_CACHE_WB_OUTSIDE_TXN: the lines
         * were flushed into this transaction at the top and are already clean.
         * The arm's whole effect is where the flush happens, not how often. */
        return 0;
    }

    /* 4. Clear the header so recovery finds nothing to replay. */
    my_memset(hbuf, 0, BLOCK_SIZE);
    raw_block_write(jstart, hbuf);

    /* No barrier after step 4. If the cleared header is lost, the next mount
     * replays an already-applied transaction — idempotent redo over identical
     * content, which is a no-op. This is the one ordering edge that costs
     * nothing to get wrong, so it does not buy a flush. */

    g_journal_seq++;
    g_txn.active = 0; g_txn.n = 0;
#ifdef META_CACHE_WB_OUTSIDE_TXN
    /* The defect (E2): the transaction is closed, so do_block_write below goes
     * straight home rather than into the journal. Every value written is correct
     * and every check still runs -- what is gone is the ATOMICITY between the
     * metadata and the data it describes. */
    meta_cache_flush_all();
    merkle_flush_all();
#endif
    return 0;
}

int storage_block_read(uint64_t block, void *buf) {
    return raw_block_read(block, buf);
}

int storage_block_write(uint64_t block, const void *buf) {
    return raw_block_write(block, buf);
}

/* ---- metadata cache operations -------------------------------------------
 *
 * Called with storage_lock held on the encrypt/decrypt paths, and without it
 * from journal_commit -- the same serialisation g_jscratch relies on, which is
 * that ring-0 storage work is not preempted and the journal's own g_txn is a
 * single global with no lock of its own. Stated rather than implied, because
 * these buffers are static and that is the only thing making them safe.
 */

/* Write one line home and refresh the integrity chain over it. `do_block_write`
 * stages into the open transaction when there is one, which is what puts the
 * metadata update inside the same atomic unit as the data it describes. */
static int meta_cache_flush_line(struct meta_cache_line *l)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || mfs->sb.meta_start == 0) return -1;
    if (l->meta_blk == META_BLK_NONE) return 0;
    if (do_block_write(mfs->sb.meta_start + l->meta_blk, l->img) != 0) return -1;
    l->dirty = 0;
    /* Carry the new content up to the root. Failing here is NOT advisory: the
     * block is written and the tree would then disagree with it, which at the
     * next mount is indistinguishable from an attacker having rewound it. */
    return merkle_update_leaf(l->meta_blk, l->img);
}

static int meta_cache_flush_all(void)
{
    int rc = 0;
    for (unsigned i = 0; i < META_CACHE_LINES; i++) {
        struct meta_cache_line *l = &g_meta_cache[i];
        if (l->meta_blk != META_BLK_NONE && l->dirty)
            if (meta_cache_flush_line(l) != 0) rc = -1;
    }
    return rc;
}

/* Discard lines belonging to a transaction that did not happen (journal_abort).
 * Dropping rather than reverting is safe precisely because home was never
 * touched: the on-disk image is still the pre-transaction one. */
static void meta_cache_drop_dirty(void)
{
    for (unsigned i = 0; i < META_CACHE_LINES; i++) {
        if (g_meta_cache[i].dirty) {
            g_meta_cache[i].meta_blk = META_BLK_NONE;
            g_meta_cache[i].dirty    = 0;
        }
    }
}

/* Forget everything, without writing anything back. For format and for a failed
 * unlock, where the lines describe a volume that is either about to be
 * overwritten or has just been refused -- writing them back would be writing one
 * volume's metadata onto another's. */
static void meta_cache_reset(void)
{
    for (unsigned i = 0; i < META_CACHE_LINES; i++) {
        g_meta_cache[i].meta_blk = META_BLK_NONE;
        g_meta_cache[i].dirty    = 0;
        g_meta_cache[i].stamp    = 0;
    }
    g_meta_clock = 0;
}

/* The resident line for metadata block `meta_blk`, loading it on a miss and
 * evicting the least recently used line to make room. NULL means the metadata
 * for this block is not available, and every caller treats that as a refusal --
 * there is no path that proceeds without an entry.
 *
 * LRU by a monotonic stamp rather than a clock hand, because the cache is small
 * enough that a linear scan is far cheaper than the 4 KiB disk read a wrong
 * eviction costs, and exact LRU is one line of code where an approximation is
 * several. */
static struct meta_cache_line *meta_cache_get(uint64_t meta_blk)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || mfs->sb.meta_start == 0) return NULL;
    if (meta_blk >= mfs->sb.meta_blocks) return NULL;

    struct meta_cache_line *victim = NULL;
    for (unsigned i = 0; i < META_CACHE_LINES; i++) {
        struct meta_cache_line *l = &g_meta_cache[i];
        if (l->meta_blk == meta_blk) { l->stamp = ++g_meta_clock; return l; }
    }
    /* Miss. Prefer an empty line; otherwise the oldest. */
    for (unsigned i = 0; i < META_CACHE_LINES; i++) {
        if (g_meta_cache[i].meta_blk == META_BLK_NONE) { victim = &g_meta_cache[i]; break; }
    }
    if (!victim) {
        victim = &g_meta_cache[0];
        for (unsigned i = 1; i < META_CACHE_LINES; i++)
            if (g_meta_cache[i].stamp < victim->stamp) victim = &g_meta_cache[i];

        if (victim->dirty) {
            g_meta_dirty_evictions++;
#ifndef META_CACHE_EVICT_NOWB
#ifndef META_CACHE_NO_WRITEBACK
            /* Unreachable on every workload in this tree: a transaction dirties
             * one line and journal_commit writes it back before anything can
             * evict it. Kept because "no caller reaches it today" is a statement
             * about callers, not about the structure, and a cache that silently
             * drops a dirty line is the failure this whole stage is about. */
            if (meta_cache_flush_line(victim) != 0) return NULL;
#endif
#endif
        }
        g_meta_evictions++;
    }

    victim->meta_blk = meta_blk;
    victim->dirty    = 0;
    victim->stamp    = ++g_meta_clock;
    if (do_block_read(mfs->sb.meta_start + meta_blk, victim->img) != 0) {
        /* FAIL CLOSED, and note what the alternative would do. Leaving the line
         * installed with whatever bytes the failed read left in it makes an
         * unreadable metadata block look like "every block in it is absent" --
         * and the first write to any block it covers would then flush that
         * fiction back OVER the real region, destroying 128 blocks' nonces to
         * repair one failed read. Drop the line; the caller refuses. */
        victim->meta_blk = META_BLK_NONE;
        return NULL;
    }
    /* THE INTEGRATION POINT. A metadata block is trusted only when its content
     * hashes to the leaf the tree records for it, on the path from the root --
     * so a block rewound to a genuine earlier state of this volume is refused
     * here, and nothing downstream ever sees the stale nonces. Verified on LOAD
     * rather than at mount, which is what makes the unlock check O(1) instead of
     * a walk of the whole region. */
    if (merkle_verify_leaf(meta_blk, victim->img) != 0) {
        victim->meta_blk = META_BLK_NONE;
        return NULL;
    }
    return victim;
}

/* Derive the HMAC key for the metadata region:
 *   meta_mac_key = HKDF-SHA256(IKM=disk_key, salt=volume_key_salt, info="horus-meta-mac-v1")
 * disk_key and volume_key_salt are both on-disk stable values, so meta_mac_key
 * is the same across reboots for the same formatted volume. */
static int derive_meta_mac_key(const uint8_t *disk_key,   size_t dk_len,
                                const uint8_t *vk_salt,    size_t salt_len,
                                uint8_t       *out32)
{
    const char *label = "horus-meta-mac-v1";
    uint8_t info[18];
    size_t p = 0;
    for (const char *c = label; *c; c++) info[p++] = (uint8_t)*c;
    return rust_hkdf_sha256(disk_key, dk_len, vk_salt, salt_len, info, p, out32, 32);
}

/* journal_mac_key = HKDF-SHA256(disk_key, volume_key_salt, "horus-journal-mac-v1").
 * A distinct label from the meta-mac key so the two are independent. */
static int derive_journal_mac_key(const uint8_t *disk_key, size_t dk_len,
                                  const uint8_t *vk_salt,  size_t salt_len,
                                  uint8_t       *out32)
{
    const char *label = "horus-journal-mac-v1";
    uint8_t info[21];
    size_t p = 0;
    for (const char *c = label; *c; c++) info[p++] = (uint8_t)*c;
    return rust_hkdf_sha256(disk_key, dk_len, vk_salt, salt_len, info, p, out32, 32);
}

/* Replay any committed transaction left in the journal by a crash. Run at mount,
 * BEFORE the metadata region is loaded and its HMAC verified, so a transaction
 * that updated a meta sector and the tree above it is completed atomically.
 * Verifies the header's keyed HMAC and bounds-checks every target, so only a
 * genuine, kernel-authored, intact transaction is ever applied; anything else is
 * discarded (the operation is treated as never having happened). Idempotent. */
/* Returns 1 if a committed transaction was replayed, 0 otherwise. The caller
 * uses that to decide whether the volume was interrupted mid-operation. */
static int journal_recover(struct mounted_fs *mfs)
{
    int replayed = 0;
    if (!mfs || !mfs->mounted || mfs->sb.journal_start == 0) return 0;
    uint64_t jstart = mfs->sb.journal_start;

    uint8_t hbuf[BLOCK_SIZE];
    if (raw_block_read(jstart, hbuf) != 0) return 0;
    struct journal_header hdr;
    my_memcpy(&hdr, hbuf, sizeof(hdr));

    if (hdr.magic != JOURNAL_MAGIC) return 0;               /* nothing committed */
    if (hdr.count == 0 || hdr.count > JOURNAL_DATA_MAX) goto discard;

    /* Load the staged data and re-derive the HMAC over exactly what we would
     * apply; a torn/forged journal fails here and is discarded. */
    static uint8_t jdata[JOURNAL_DATA_MAX][BLOCK_SIZE];
    for (uint32_t i = 0; i < hdr.count; i++)
        if (raw_block_read(jstart + 1 + i, jdata[i]) != 0) goto discard;

    uint8_t want[32];
    if (journal_compute_hmac(mfs->journal_mac_key, hdr.seq, hdr.count, hdr.target,
                             (const uint8_t (*)[BLOCK_SIZE])jdata, want) != 0) goto discard;
    int bad = 0;
    for (int i = 0; i < 32; i++) bad |= (want[i] ^ hdr.hmac[i]);
    if (bad) goto discard;

    /* Every target must land in the filesystem body. Block 0 (the superblock) is
     * allowed because update_meta_block_mac stages it as part of a txn to keep
     * sb.meta_root in sync, and a valid journal HMAC proves the kernel authored the
     * transaction. But never inside the journal region, and never past the disk.
     * Fail closed on any out-of-range target. */
    for (uint32_t i = 0; i < hdr.count; i++) {
        uint64_t t = hdr.target[i];
        if (t >= mfs->sb.total_blocks) goto discard;
        if (t >= jstart && t < jstart + mfs->sb.journal_blocks) goto discard;
    }

    /* Redo. */
    for (uint32_t i = 0; i < hdr.count; i++)
        raw_block_write(hdr.target[i], jdata[i]);
    if (hdr.seq >= g_journal_seq) g_journal_seq = hdr.seq + 1;
    replayed = 1;                    /* the volume was interrupted mid-operation */

    /* Same constraint as BARRIER C in journal_commit: the redo must be on stable
     * media before the header authorising it is cleared. Recovery is where this
     * matters most — a crash during recovery that lost both the redo and the
     * header would leave the volume torn with nothing left to repair it, and the
     * next mount would see a clean journal over inconsistent home blocks. On
     * failure, leave the header alone so the next mount tries again. */
    if (raw_block_flush() != 0) {
        println("WAL: FLUSH FAILED after redo - header left for the next mount");
        return replayed;
    }

discard:
    my_memset(hbuf, 0, BLOCK_SIZE);
    raw_block_write(jstart, hbuf);   /* clear the header either way */
    return replayed;
}

/* ---- the Merkle rollback tree ---------------------------------------------
 *
 * Level 0's hashes are the metadata blocks' MACs; level k+1's are the hashes of
 * level k's node blocks; the top level is one block whose hash is sb.meta_root.
 *
 * WHAT MAKES IT A TREE RATHER THAN A PILE OF MACS. Every hash covers
 * (domain-separation tag, level, index, bytes) AND is checked against the value
 * its PARENT records, transitively up to the root. Position binding alone stops
 * two nodes being swapped; the parent chain is what stops a node that was
 * genuinely valid at an EARLIER time from verifying now, and that is the whole
 * attack -- a physical attacker rewinding part of the region writes bytes this
 * volume really did produce, so nothing about them is forged.
 * MERKLE_SKIP_PARENT_BIND=1 checks a metadata block against its own MAC and
 * skips the chain, which accepts exactly that replay and is the arm for it.
 *
 * Verification walks TOP-DOWN, from the root, rather than bottom-up from the
 * node wanted. Bottom-up needs the parent before it can judge the child and so
 * recurses; top-down is a loop, and more importantly it makes "verified" mean
 * "there is a path from the root to this node" by construction rather than by
 * an argument about the order of calls.
 */

static uint8_t g_mac_pre[8 + BLOCK_SIZE];   /* same serialisation as g_jscratch */

/* Per-level node-block counts, level 0 first, ending at the level with exactly
 * one block. Derived rather than stored: two numbers that can disagree are one
 * too many, and this is the derivation both format and mount use. Returns the
 * number of levels, or 0 if the volume is outside what the tree can describe. */
static uint32_t merkle_layout(uint64_t meta_blocks, uint64_t *counts)
{
    if (meta_blocks == 0) return 0;
    uint32_t levels = 0;
    uint64_t n = (meta_blocks + MERKLE_FANOUT - 1) / MERKLE_FANOUT;
    for (;;) {
        if (levels >= MERKLE_MAX_LEVELS) return 0;
        counts[levels++] = n;
        if (n == 1) break;
        n = (n + MERKLE_FANOUT - 1) / MERKLE_FANOUT;
    }
    return levels;
}

/* First block of `level` within the node region. Levels are contiguous from 0. */
static uint64_t merkle_level_base(const struct fs_superblock *sb, uint32_t level)
{
    uint64_t counts[MERKLE_MAX_LEVELS];
    uint32_t levels = merkle_layout(sb->meta_blocks, counts);
    uint64_t base = sb->merkle_start;
    for (uint32_t l = 0; l < level && l < levels; l++) base += counts[l];
    return base;
}

/* The hash recorded for one node or leaf. The tag and the (level, index) pair
 * are inside the preimage, so a node cannot be reused at another position and a
 * leaf's hash can never collide with an interior node's. Level 0 here means "a
 * metadata block"; level k+1 means "a node block of level k". */
static int merkle_hash(uint32_t level, uint64_t index, const uint8_t *mac_key,
                       const uint8_t *img, uint8_t out32[32])
{
    g_mac_pre[0] = 'M'; g_mac_pre[1] = 'K'; g_mac_pre[2] = 'L';
    g_mac_pre[3] = (uint8_t)level;
    for (int i = 0; i < 4; i++) g_mac_pre[4 + i] = (uint8_t)(index >> (i * 8));
    my_memcpy(g_mac_pre + 8, img, BLOCK_SIZE);
    return rust_hmac_sha256(mac_key, 32, g_mac_pre, sizeof(g_mac_pre), out32);
}

#define MERKLE_IDX_NONE ((uint64_t)-1)

struct merkle_line {
    uint32_t level;                 /* node-block level: 0 is the lowest */
    uint64_t index;                 /* or MERKLE_IDX_NONE when the line is free */
    uint32_t stamp;
    uint8_t  dirty;
    uint8_t  verified;              /* a path from the root reached this content */
    uint8_t  _pad[2];
    uint8_t  img[BLOCK_SIZE];
};
static struct merkle_line g_merkle_cache[MERKLE_CACHE_LINES];
static uint32_t g_merkle_clock;
static uint64_t g_merkle_evictions;

/* A verification walks one node per level and must hold every ancestor it has
 * already checked, or the walk evicts its own parent and the "verified" flag
 * stops meaning anything. */
_Static_assert(MERKLE_CACHE_LINES >= MERKLE_MAX_LEVELS + 2,
               "the node cache must hold a whole root-to-leaf path plus the line being loaded");

uint64_t merkle_node_evictions(void) { return g_merkle_evictions; }

static void merkle_cache_reset(void)
{
    for (unsigned i = 0; i < MERKLE_CACHE_LINES; i++) {
        g_merkle_cache[i].index    = MERKLE_IDX_NONE;
        g_merkle_cache[i].dirty    = 0;
        g_merkle_cache[i].verified = 0;
        g_merkle_cache[i].stamp    = 0;
    }
    g_merkle_clock = 0;
}

static int merkle_flush_line(struct merkle_line *l)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || mfs->sb.merkle_start == 0) return -1;
    if (l->index == MERKLE_IDX_NONE) return 0;
    if (do_block_write(merkle_level_base(&mfs->sb, l->level) + l->index, l->img) != 0) return -1;
    l->dirty = 0;
    return 0;
}

static int merkle_flush_all(void)
{
    int rc = 0;
    for (unsigned i = 0; i < MERKLE_CACHE_LINES; i++)
        if (g_merkle_cache[i].index != MERKLE_IDX_NONE && g_merkle_cache[i].dirty)
            if (merkle_flush_line(&g_merkle_cache[i]) != 0) rc = -1;
    return rc;
}

static void merkle_drop_dirty(void)
{
    for (unsigned i = 0; i < MERKLE_CACHE_LINES; i++)
        if (g_merkle_cache[i].dirty) {
            g_merkle_cache[i].index    = MERKLE_IDX_NONE;
            g_merkle_cache[i].dirty    = 0;
            g_merkle_cache[i].verified = 0;
        }
}

/* A resident line for (level, index), NOT yet verified. Pinning: a line whose
 * stamp is the current clock reading cannot be chosen as a victim, which is how
 * the top-down walk keeps the ancestors it has already checked. */
static struct merkle_line *merkle_line_for(uint32_t level, uint64_t index, int *was_resident)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || mfs->sb.merkle_start == 0) return NULL;

    for (unsigned i = 0; i < MERKLE_CACHE_LINES; i++) {
        struct merkle_line *l = &g_merkle_cache[i];
        if (l->index == index && l->level == level && l->index != MERKLE_IDX_NONE) {
            l->stamp = ++g_merkle_clock;
            if (was_resident) *was_resident = 1;
            return l;
        }
    }
    if (was_resident) *was_resident = 0;

    struct merkle_line *victim = NULL;
    for (unsigned i = 0; i < MERKLE_CACHE_LINES; i++)
        if (g_merkle_cache[i].index == MERKLE_IDX_NONE) { victim = &g_merkle_cache[i]; break; }
    if (!victim) {
        victim = &g_merkle_cache[0];
        for (unsigned i = 1; i < MERKLE_CACHE_LINES; i++)
            if (g_merkle_cache[i].stamp < victim->stamp) victim = &g_merkle_cache[i];
        if (victim->dirty && merkle_flush_line(victim) != 0) return NULL;
        g_merkle_evictions++;
    }

    victim->level    = level;
    victim->index    = index;
    victim->dirty    = 0;
    victim->verified = 0;
    victim->stamp    = ++g_merkle_clock;
    if (do_block_read(merkle_level_base(&mfs->sb, level) + index, victim->img) != 0) {
        victim->index = MERKLE_IDX_NONE;    /* fail closed; never a zero-filled node */
        return NULL;
    }
#ifdef MERKLE_NODE_TRUST_CACHED
    /* THE DEFECT (R1). `verified` becomes a RESIDENCY flag: a node is trusted
     * because it is in the cache, not because a path from the root reached it.
     *
     * This is one edit away from the correct code and it is the edit a
     * performance shortcut makes. Re-checking a node on every cache HIT is
     * genuinely wasteful, so the flag exists to skip it -- and setting the flag
     * where the line is filled, rather than where it is checked, skips the one
     * check that mattered. A node that is merely present then satisfies the
     * whole tree, and a replayed node -- bytes this volume really did produce,
     * at an earlier time -- is served as current. */
    victim->verified = 1;
#endif
    return victim;
}

/* A node block, verified against the path from the root. NULL means refused, and
 * every caller treats it as such -- there is no path that proceeds on a node it
 * could not place under the root.
 *
 * MERKLE_NODE_TRUST_CACHED=1 returns a resident line without ever having checked
 * it, so RESIDENCY becomes the trust criterion instead of the path. That is the
 * natural performance shortcut and it is precisely what lets a replay succeed. */
static struct merkle_line *merkle_node(uint32_t level, uint64_t index)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || mfs->sb.merkle_start == 0) return NULL;

    uint64_t counts[MERKLE_MAX_LEVELS];
    uint32_t levels = merkle_layout(mfs->sb.meta_blocks, counts);
    if (levels == 0 || level >= levels || index >= counts[level]) return NULL;

    /* Each ancestor's index, from the node wanted up to the top. */
    const uint32_t top = levels - 1;
    uint64_t path[MERKLE_MAX_LEVELS];
    path[level] = index;
    for (uint32_t l = level + 1; l <= top; l++) path[l] = path[l - 1] / MERKLE_FANOUT;

    struct merkle_line *parent = NULL;
    for (uint32_t l = top + 1; l-- > level; ) {
        struct merkle_line *line = merkle_line_for(l, path[l], NULL);
        if (!line) return NULL;

        /* Skipping the check on a line already placed under the root is the
         * whole value of the flag; MERKLE_NODE_TRUST_CACHED=1 is what happens
         * when the flag is set where the line is FILLED instead. */
        if (!line->verified) {
            uint8_t want[32];
            if (merkle_hash(l + 1, path[l], mfs->meta_mac_key, line->img, want) != 0) return NULL;
            const uint8_t *have = (l == top)
                ? mfs->sb.meta_root
                : parent->img + (path[l] % MERKLE_FANOUT) * 32;
            int bad = 0;
            for (int i = 0; i < 32; i++) bad |= (want[i] ^ have[i]);
            if (bad) return NULL;                   /* stale or forged: refuse */
            line->verified = 1;
        }
        parent = line;
        if (l == level) return line;
    }
    return NULL;                                    /* unreachable: level <= top */
}

/* The leaf hash for one metadata block, checked against level 0 of the tree.
 * Returns 0 when `img` is the CURRENT authentic content of metadata block
 * `meta_blk`, -1 otherwise. */
static int merkle_verify_leaf(uint64_t meta_blk, const uint8_t *img)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) return -1;

    uint8_t want[32];
    if (merkle_hash(0, meta_blk, mfs->meta_mac_key, img, want) != 0) return -1;

#ifdef MERKLE_SKIP_PARENT_BIND
    /* THE DEFECT: the leaf is checked against the level-0 node that records it,
     * and THAT NODE IS NOT PLACED UNDER THE ROOT. What survives is real: every
     * byte still has to have been produced by this volume with this key, the
     * index is still bound, so a forgery is still refused and two blocks still
     * cannot be swapped. What is gone is the only thing that distinguishes a
     * Merkle tree from a set of independent MACs -- the question of whether this
     * state is the CURRENT one. A genuine earlier state of the block, restored
     * together with the node that recorded it, then passes.
     *
     * Deliberately NOT `return 0`: an arm that checks nothing would also pass
     * under a forgery, and would then be witnessing "the check is absent" rather
     * than "the chain is absent" -- a weaker claim about a different rule. */
    struct merkle_line *l0 = merkle_line_for(0, meta_blk / MERKLE_FANOUT, NULL);
    if (!l0) return -1;
#else
    struct merkle_line *l0 = merkle_node(0, meta_blk / MERKLE_FANOUT);
    if (!l0) return -1;
#endif
    const uint8_t *have = l0->img + (meta_blk % MERKLE_FANOUT) * 32;
    int bad = 0;
    for (int i = 0; i < 32; i++) bad |= (want[i] ^ have[i]);
    return bad ? -1 : 0;
}

/* Record a new content hash for metadata block `meta_blk` and carry the change
 * up to the root. One hash and one staged write per level -- four of each at a
 * 16 GiB volume, against the megabyte the flat construction hashed. */
static int merkle_update_leaf(uint64_t meta_blk, const uint8_t *img)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || mfs->sb.merkle_start == 0) return -1;

    uint64_t counts[MERKLE_MAX_LEVELS];
    uint32_t levels = merkle_layout(mfs->sb.meta_blocks, counts);
    if (levels == 0) return -1;

    uint8_t h[32];
    if (merkle_hash(0, meta_blk, mfs->meta_mac_key, img, h) != 0) return -1;

    uint64_t idx = meta_blk;
    for (uint32_t l = 0; l < levels; l++) {
        uint64_t node_idx = idx / MERKLE_FANOUT;
        struct merkle_line *line = merkle_node(l, node_idx);
        if (!line) return -1;
        my_memcpy(line->img + (idx % MERKLE_FANOUT) * 32, h, 32);
        line->dirty = 1;
        /* The line's content just changed, so its own recorded hash must too --
         * and it stays `verified` because we are the ones who changed it and we
         * are about to record the new hash in its parent. */
        if (merkle_hash(l + 1, node_idx, mfs->meta_mac_key, line->img, h) != 0) return -1;
        idx = node_idx;
    }

    my_memcpy(mfs->sb.meta_root, h, 32);
    do_block_write(0, &mfs->sb);        /* superblock is always block 0 */
    return 0;
}

/* Build the whole tree over a region whose content is already on the device.
 * Used at format, where the region is freshly zeroed. Reads each metadata block
 * back rather than assuming its content, so format and mount hash the same bytes
 * -- the assumption is what made the old construction able to brick a volume
 * whose format left one byte unwritten. */
static int merkle_build(struct block_device *bd, struct fs_superblock *sb,
                        const uint8_t *mac_key)
{
    uint64_t counts[MERKLE_MAX_LEVELS];
    uint32_t levels = merkle_layout(sb->meta_blocks, counts);
    if (levels == 0) return -1;

    static uint8_t img[BLOCK_SIZE];
    static uint8_t node[BLOCK_SIZE];
    uint8_t h[32];

    uint64_t base = sb->merkle_start;
    for (uint32_t l = 0; l < levels; l++) {
        uint64_t children = (l == 0) ? sb->meta_blocks : counts[l - 1];
        uint64_t child_base = (l == 0) ? sb->meta_start : base - counts[l - 1];
        for (uint64_t n = 0; n < counts[l]; n++) {
            my_memset(node, 0, BLOCK_SIZE);
            for (uint64_t k = 0; k < MERKLE_FANOUT; k++) {
                uint64_t child = n * MERKLE_FANOUT + k;
                if (child >= children) break;       /* a short top node: zeros */
                if (bd->read_block(bd, child_base + child, img) != 0) return -1;
                if (merkle_hash(l, child, mac_key, img, h) != 0) return -1;
                my_memcpy(node + k * 32, h, 32);
            }
            if (bd->write_block(bd, base + n, node) != 0) return -1;
        }
        base += counts[l];
    }

    /* The root is the hash of the single top node block, which merkle_build has
     * just written -- read it back for the same reason the leaves are read back. */
    if (bd->read_block(bd, base - 1, node) != 0) return -1;
    if (merkle_hash(levels, 0, mac_key, node, sb->meta_root) != 0) return -1;
    return 0;
}

/* Verify the tree's top node against the root recorded in the superblock. That
 * is the WHOLE of the unlock-time check now, and it is O(1): everything below is
 * verified lazily, on the path from the root, when a metadata block is first
 * loaded. The old check read the entire region and hashed every byte of it at
 * every mount, which is the cost that stopped the volume growing. */
static int merkle_verify_root(void)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted) return -1;
    uint64_t counts[MERKLE_MAX_LEVELS];
    uint32_t levels = merkle_layout(mfs->sb.meta_blocks, counts);
    if (levels == 0) return -1;
    return merkle_node(levels - 1, 0) ? 0 : -1;
}

/* How many LBA sectors make one filesystem block. An ATA sector is 512 bytes by
 * definition; BLOCK_SIZE is the filesystem's unit and is 4 KiB, so the mapping
 * is 8:1 and NOT the 1:1 this file assumed until 2026-08-31.
 *
 * That assumption was the last of six places the 512-byte block was written
 * down, and the most consequential: atadisk_read passed the FS block number
 * straight to ata_read as an LBA and asked for one sector, so every read
 * fetched 512 bytes from an eighth of the intended offset into a 4096-byte
 * buffer. The RAM vdisk scales by block * BLOCK_SIZE and was always correct,
 * which is exactly why the four failing gates were precisely the ATA-backed
 * ones (persist, wal, keyslots, users-persist) while every RAM-disk gate
 * passed -- a signature worth reading before reaching for a debugger. */
#define ATA_SECTORS_PER_BLOCK  (BLOCK_SIZE / 512u)
_Static_assert(BLOCK_SIZE % 512u == 0,
               "BLOCK_SIZE must be a whole number of 512-byte ATA sectors");

/* THE LBA28 WALL, asserted rather than discovered on somebody's disk.
 *
 * ata_read_sector selects the drive with `0xE0 | ((lba >> 24) & 0x0F)`, which is
 * LBA28: 2^28 sectors, 128 GiB at 512 bytes each. Past that the top bits are
 * silently DROPPED and the transfer lands at lba mod 2^28 -- a read of the wrong
 * block that succeeds, which the AEAD then rejects, so the symptom would be a
 * volume that decrypts nothing above 128 GiB rather than an error naming the
 * cause. ata_read also takes a uint32_t lba, so the same value must fit there.
 *
 * At 16 GiB (BLOCKS_PER_DISK = 4194304) this is 33,554,432 sectors, comfortably
 * inside it. The assertion is here so that the NEXT raise of BLOCKS_PER_DISK
 * fails the build instead of the disk. An LBA48 driver (0x24/0x34 with the
 * 0xEA flush) is what lifts it. */
_Static_assert((uint64_t)BLOCKS_PER_DISK * ATA_SECTORS_PER_BLOCK <= 0x10000000ULL,
               "the ATA driver is LBA28: the volume must fit in 2^28 sectors (128 GiB)");
_Static_assert((uint64_t)BLOCKS_PER_DISK * ATA_SECTORS_PER_BLOCK <= 0xFFFFFFFFULL,
               "the LBA passed to ata_read/ata_write is a uint32_t");

/* ATA-backed block device (persistent). The per-block crypto metadata (nonce/tag)
 * is persisted: storage_encrypt_block dirties a resident metadata line and
 * journal_commit writes it back inside the owning transaction, and storage_unlock
 * verifies the region's HMAC against the disk, so files survive a reboot — proven by
 * `make smoke-fs-persist`. Compiled unconditionally; storage_init() selects it
 * at runtime when a disk is actually present. */
static int atadisk_read(struct block_device *bd, uint64_t block, void *buf) {
    (void)bd;
    return ata_read((uint32_t)(block * ATA_SECTORS_PER_BLOCK), buf,
                    ATA_SECTORS_PER_BLOCK);
}
static int atadisk_write(struct block_device *bd, uint64_t block, const void *buf) {
    (void)bd;
    return ata_write((uint32_t)(block * ATA_SECTORS_PER_BLOCK), buf,
                     ATA_SECTORS_PER_BLOCK);
}
static int atadisk_flush(struct block_device *bd) {
    (void)bd;
    return ata_flush();
}
/* SIZED FROM THE DISK AT PROBE TIME, not from a compile-time constant
 * (SECURITY.md S68).
 *
 * `total_blocks` was BLOCKS_PER_DISK, so every ATA volume was laid out as though
 * the medium held exactly that many blocks whatever it actually held -- wrong in
 * both directions. A smaller disk got a filesystem whose data region ran off the
 * end of it, and a larger one was silently truncated to the constant with
 * nothing said. BLOCKS_PER_DISK is a CEILING (the largest volume this kernel's
 * fixed-size arrays can describe); the disk decides the rest. storage_init fills
 * this in from ata_total_sectors() before the device is used.
 *
 * It also decouples the gates from the ceiling: raising BLOCKS_PER_DISK no
 * longer makes every persistence test allocate a volume that size. */
static struct block_device g_ata_bd = {
    .name = "ata0",
    .total_blocks = 0,          /* set by storage_init from IDENTIFY */
    .read_block = atadisk_read,
    .write_block = atadisk_write,
    .flush = atadisk_flush,
    .private = 0,
};


#ifdef VDISK_BOUND_SELFTEST
/* A block device may not accept a block it has no memory for (SECURITY.md S64).
 *
 * Two directions, because an inject-and-look arm on its own measures false
 * negatives only and a bound that rejects everything satisfies all of them
 * (the KSP_GUARD_ALWAYS lesson):
 *
 *   1. the LAST in-range block is writable and reads back  -- the bound is not
 *      simply refusing the device's own extent, and
 *   2. the first out-of-range block is REFUSED.
 *
 * Under VDISK_TOTAL_UNBOUNDED=1 the second write is accepted and the bytes land
 * in the free page pool that begins immediately after the reservation, which the
 * probe shows POSITIVELY by reading them back from there rather than by noting
 * that no refusal arrived. An assertion of absence is satisfied by a run that
 * never reached the code.
 *
 * Runs on the ephemeral RAM vdisk, which is what a diskless boot uses, and
 * restores whatever it displaced so the boot survives to print. */
void storage_vdisk_bound_selftest(void)
{
    if (!g_vdisk_backing || current_bd != &g_vdisk_bd) {
        print("VDISKBOUND: FAIL not running on the RAM vdisk\n");
        return;
    }

    static uint8_t pattern[BLOCK_SIZE];
    static uint8_t saved[BLOCK_SIZE];
    static uint8_t readback[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++) pattern[i] = (uint8_t)(0xC3u ^ (i & 0xFFu));

    /* 1. The last block the backing store actually holds. */
    const uint64_t last = (uint64_t)VDISK_BLOCKS - 1;
    if (g_vdisk_bd.read_block(&g_vdisk_bd, last, saved) != 0) {
        print("VDISKBOUND: FAIL the last in-range block could not be read\n");
        return;
    }
    if (g_vdisk_bd.write_block(&g_vdisk_bd, last, pattern) != 0) {
        print("VDISKBOUND: FAIL the last in-range block was refused\n");
        return;
    }
    if (g_vdisk_bd.read_block(&g_vdisk_bd, last, readback) != 0) {
        print("VDISKBOUND: FAIL the last in-range block could not be read back\n");
        return;
    }
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        if (readback[i] != pattern[i]) {
            print("VDISKBOUND: FAIL the last in-range block did not read back\n");
            return;
        }
    }
    g_vdisk_bd.write_block(&g_vdisk_bd, last, saved);   /* put the volume back */

    /* 2. One block past the backing store. The bytes it WOULD write start at
     * g_vdisk_backing + VDISK_BYTES, which is the first frame of the free page
     * pool -- so the arm can read them back from there and say so, rather than
     * inferring reach from a missing refusal. */
    uint8_t *past = g_vdisk_backing + VDISK_BYTES;
    for (size_t i = 0; i < BLOCK_SIZE; i++) saved[i] = past[i];

    int rc = g_vdisk_bd.write_block(&g_vdisk_bd, (uint64_t)VDISK_BLOCKS, pattern);
    if (rc == 0) {
        int landed = 1;
        for (size_t i = 0; i < BLOCK_SIZE; i++)
            if (past[i] != pattern[i]) { landed = 0; break; }
        for (size_t i = 0; i < BLOCK_SIZE; i++) past[i] = saved[i];   /* undo it */
        if (landed)
            print("VDISKBOUND: FAIL a write past the backing store reached the free page pool\n");
        else
            print("VDISKBOUND: FAIL a write past the backing store was accepted\n");
        return;
    }

    /* The advertised geometry is what storage_format_sealed lays the filesystem
     * out against, so a device claiming more than it holds is a defect even
     * where the transport refuses the write. Checked here rather than left to
     * the transport, because the two were the same number until 2026-08-31. */
    if (g_vdisk_bd.total_blocks != (uint64_t)VDISK_BLOCKS) {
        print("VDISKBOUND: FAIL the device advertises more blocks than it holds\n");
        return;
    }

    print("VDISKBOUND: PASS last-block-writable out-of-range-refused\n");
}
#endif /* VDISK_BOUND_SELFTEST */

int storage_init(void) {
    /* Persistent by default: probe for an ATA disk. If one is attached, use the
     * encrypted ATA store — it comes up mounted-but-locked and disk_key is only
     * unwrapped at login (storage_unlock), so files survive a reboot but the
     * volume stays sealed until a user authenticates. A fresh or foreign disk is
     * formatted+sealed at that first login (g_needs_format). If no disk is present
     * — a diskless or CI boot — fall back to the ephemeral in-RAM vdisk, which is
     * formatted and unlocked immediately with a per-boot throwaway key so the
     * system still comes up without a login. ata_init()'s probe is bounded, so a
     * floating/absent bus can never hang the boot. */
    if (ata_init()) {
        /* Fail closed on a disk that reports nothing: laying a filesystem out
         * against an unknown size is how the old compile-time constant went
         * wrong, and guessing again here would repeat it with extra steps. */
        uint32_t sectors = ata_total_sectors();
        uint64_t blocks  = (uint64_t)sectors / ATA_SECTORS_PER_BLOCK;
        if (blocks > (uint64_t)BLOCKS_PER_DISK) blocks = (uint64_t)BLOCKS_PER_DISK;
        if (blocks < STORAGE_MIN_BLOCKS) {
            kmsg("ata: disk reports too few sectors for a volume; ignoring it");
            goto no_disk;
        }
        g_ata_bd.total_blocks = blocks;
        {
            /* Say what size was chosen and why. A volume laid out against the
             * wrong number is invisible until something reads past the end, so
             * the number belongs on the wire at boot rather than in a debugger. */
            uint64_t mib = (blocks * (uint64_t)BLOCK_SIZE) / (1024u * 1024u);
            kmsg_begin();
            print("ata: volume sized from the disk: ");
            print_decimal(blocks);
            print(" blocks (");
            print_decimal(mib);
            print(" MiB)\n");
        }
        current_bd = &g_ata_bd;
        if (storage_mount(&g_ata_bd) != 0) {
            g_needs_format    = 1;   /* no valid v4 volume yet: seal it at first login */
            g_needs_format_bd = &g_ata_bd;
        }
        return 0;                    /* unlock deferred to login */
    }

no_disk:
    /* No disk: ephemeral in-RAM virtual disk, formatted and unlocked immediately
     * with a per-boot random password (the vdisk is never persisted, so the
     * password is discarded after unlock and no login is required to use it). Its
     * backing store is the pool reservation (g_vdisk_backing, set at paging_init),
     * not .bss, so the volume can exceed the old ~2 MiB .bss ceiling. */
    if (!g_vdisk_backing) return -1;   /* pool reserve not set up: refuse rather than fault */
    /* This boot runs on the ephemeral vdisk: its KEK comes from a full-entropy
     * random key, so derive_kek may skip Argon2id (see the flag's comment). */
    g_vdisk_high_entropy_kek = 1;
    g_vdisk.data        = g_vdisk_backing;
    g_vdisk.size        = VDISK_BYTES;
    g_vdisk.block_count = VDISK_BLOCKS;
    my_memset(g_vdisk.data, 0, g_vdisk.size);
    current_bd = &g_vdisk_bd;

    uint8_t boot_pass[32];
    secure_random_bytes(boot_pass, sizeof(boot_pass));
    if (storage_format_sealed(&g_vdisk_bd, (const char *)boot_pass,
                              sizeof(boot_pass)) != 0) {
        secure_zero(boot_pass, sizeof(boot_pass));
        return -1;
    }
    if (storage_mount(&g_vdisk_bd) != 0) {
        secure_zero(boot_pass, sizeof(boot_pass));
        return -1;
    }
    int rc = storage_unlock((const char *)boot_pass, sizeof(boot_pass));
    secure_zero(boot_pass, sizeof(boot_pass));
    return rc;
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

/* Bits addressable by one bitmap block. The data (block) allocator spans as many
 * bitmap blocks as sb->block_count needs — bitmap block `n` covers data-relative
 * blocks [n*BITS_PER_BITMAP_BLOCK, (n+1)*BITS_PER_BITMAP_BLOCK). */
#define BITS_PER_BITMAP_BLOCK   ((uint64_t)BLOCK_SIZE * 8)

/* Pointers in one indirect block. Defined here rather than beside
 * get_physical_block because storage_fsck_pass needs it several hundred lines
 * earlier, and a second open-coded BLOCK_SIZE/sizeof(uint64_t) is how one
 * constant becomes eight places that each believe it. */
#define PTRS_PER_BLOCK   (BLOCK_SIZE / (uint64_t)sizeof(uint64_t))

/* Levels of pointer block the reference walk may descend: single-indirect,
 * double-indirect, and the triple-indirect level stage 4 adds. Sizes the walk's
 * per-level buffers, so it is a bound on recursion depth and not merely
 * documentation. */
#define FSCK_MAX_DEPTH   3

static int read_block_bitmap_n(const struct fs_superblock *sb, uint64_t bm_idx, uint8_t *buf) {
    return do_block_read(sb->block_bitmap_start + bm_idx, buf);
}

static int write_block_bitmap_n(const struct fs_superblock *sb, uint64_t bm_idx, const uint8_t *buf) {
    return do_block_write(sb->block_bitmap_start + bm_idx, buf);
}

int64_t storage_alloc_block(struct block_device *bd, struct fs_superblock *sb) {
    (void)bd;
    uint8_t bitmap[BLOCK_SIZE];
    uint64_t remaining = sb->block_count;
    for (uint64_t bm = 0; remaining > 0; bm++) {
        uint64_t bits_here = remaining < BITS_PER_BITMAP_BLOCK ? remaining : BITS_PER_BITMAP_BLOCK;
        if (read_block_bitmap_n(sb, bm, bitmap) != 0) return -1;
        int64_t bit = bitmap_find_free(bitmap, bits_here);
        if (bit >= 0) {
            bitmap_set(bitmap, bit);
            write_block_bitmap_n(sb, bm, bitmap);
            return (int64_t)(sb->data_start + bm * BITS_PER_BITMAP_BLOCK + (uint64_t)bit);
        }
        remaining -= bits_here;
    }
    return -1;   /* volume full */
}

void storage_free_block(struct block_device *bd, struct fs_superblock *sb, uint64_t block) {
    (void)bd;
    uint64_t rel = block - sb->data_start;
    uint64_t bm  = rel / BITS_PER_BITMAP_BLOCK;
    uint64_t bit = rel % BITS_PER_BITMAP_BLOCK;
    uint8_t bitmap[BLOCK_SIZE];
    if (read_block_bitmap_n(sb, bm, bitmap) != 0) return;
    bitmap_clear(bitmap, bit);
    write_block_bitmap_n(sb, bm, bitmap);
}

/* Does any inode other than `ino` in the same TABLE BLOCK hold a bit? Used to
 * decide whether that table block has ever been written. */
static int inode_table_block_in_use(const struct fs_superblock *sb,
                                    const uint8_t *bm, uint64_t bm_base, uint64_t ino)
{
    uint64_t first = (ino / INODES_PER_BLOCK) * INODES_PER_BLOCK;
    for (uint64_t i = first; i < first + INODES_PER_BLOCK; i++) {
        if (i == ino || i >= sb->inode_count) continue;
        if (i < bm_base || i >= bm_base + BITS_PER_BITMAP_BLOCK) continue;
        if (bitmap_test(bm, i - bm_base)) return 1;
    }
    return 0;
}

int64_t storage_alloc_inode(struct block_device *bd, struct fs_superblock *sb) {
    (void)bd;
    uint8_t bitmap[BLOCK_SIZE];
    uint64_t remaining = sb->inode_count;
    for (uint64_t bm = 0; remaining > 0; bm++) {
        uint64_t base = bm * BITS_PER_BITMAP_BLOCK;
        uint64_t here = remaining < BITS_PER_BITMAP_BLOCK ? remaining : BITS_PER_BITMAP_BLOCK;
        if (do_block_read(sb->inode_bitmap_start + bm, bitmap) != 0) return -1;
        int64_t bit = bitmap_find_free(bitmap, here);
        if (bit >= 0) {
            uint64_t ino = base + (uint64_t)bit;

            /* ZERO THE TABLE BLOCK THE FIRST TIME ANYONE LANDS IN IT, instead of
             * zeroing the whole table at format. The table is 8 MiB at a 16 GiB
             * volume and format wrote every byte of it -- to a PIO disk, before
             * the login prompt -- so that an inode sharing a block with a fresh
             * one would not read back as garbage off a second-hand disk. That
             * requirement is real; doing it eagerly is not. The bitmap already
             * says whether the block has been used: if no OTHER inode in the
             * group holds a bit, nothing has ever been written there. */
            if (!inode_table_block_in_use(sb, bitmap, base, ino)) {
                uint8_t zero[BLOCK_SIZE];
                my_memset(zero, 0, BLOCK_SIZE);
                if (do_block_write(sb->inode_table_start + ino / INODES_PER_BLOCK, zero) != 0)
                    return -1;
            }

            bitmap_set(bitmap, bit);
            if (do_block_write(sb->inode_bitmap_start + bm, bitmap) != 0) return -1;
            return (int64_t)ino;
        }
        remaining -= here;
    }
    return -1;   /* no free inode */
}

void storage_free_inode(struct block_device *bd, struct fs_superblock *sb, uint64_t ino) {
    (void)bd;
    if (ino >= sb->inode_count) return;
    uint64_t bm  = ino / BITS_PER_BITMAP_BLOCK;
    uint64_t bit = ino % BITS_PER_BITMAP_BLOCK;
    uint8_t bitmap[BLOCK_SIZE];
    if (do_block_read(sb->inode_bitmap_start + bm, bitmap) != 0) return;
    bitmap_clear(bitmap, bit);
    do_block_write(sb->inode_bitmap_start + bm, bitmap);
}

int storage_read_inode(struct block_device *bd, struct fs_superblock *sb,
                       uint64_t ino, struct on_disk_inode *inode_out) {
    if (ino >= sb->inode_count) return -1;

    uint64_t block = sb->inode_table_start + (ino / INODES_PER_BLOCK);
    uint32_t offset = (ino % INODES_PER_BLOCK) * sizeof(struct on_disk_inode);

    uint8_t buf[BLOCK_SIZE];
    (void)bd; if (do_block_read(block, buf) != 0) return -1;

    my_memcpy(inode_out, buf + offset, sizeof(struct on_disk_inode));
    return 0;
}

int storage_write_inode(struct block_device *bd, struct fs_superblock *sb,
                        uint64_t ino, const struct on_disk_inode *inode) {
    if (ino >= sb->inode_count) return -1;

    uint64_t block = sb->inode_table_start + (ino / INODES_PER_BLOCK);
    uint32_t offset = (ino % INODES_PER_BLOCK) * sizeof(struct on_disk_inode);

    uint8_t buf[BLOCK_SIZE];
    (void)bd; if (do_block_read(block, buf) != 0) return -1;

    my_memcpy(buf + offset, inode, sizeof(struct on_disk_inode));
    return do_block_write(block, buf);
}

/* Test hooks shared by the storage witnesses. Guarded by the union of the
 * selftests that need them rather than by one of their names, so a second
 * witness does not have to depend on the first one's flag being set. */
#if defined(MERKLE_SELFTEST) || defined(FSCKREF_SELFTEST) || defined(BIGVOL_SELFTEST)
#define STORAGE_TEST_HOOKS 1
#endif

#ifdef STORAGE_TEST_HOOKS
static uint64_t get_physical_block(struct mounted_fs *mfs, struct on_disk_inode *inode,
                                   uint64_t logical_block, int allocate);
/* ---- Arm B's harness (docs/design/meta-cache-merkle.md §3) ------------------
 *
 * The property: an interior node is trusted only when it verifies against the
 * path to the CURRENT root. A node that was valid at an earlier time is not
 * valid now.
 *
 * WHAT MAKES THE ARM WORTH ANYTHING is that the replayed bytes are
 * INDEPENDENTLY VALID. If the harness replayed garbage, or a node whose own hash
 * did not check out, the refusal would come from the hash and the run would have
 * tested nothing about the tree -- a set of independent MACs would pass it too.
 * So the harness restores a genuine past state of this volume: a metadata block
 * AND the level-0 node that recorded it, both snapshotted while they were
 * current and correct. Nothing is forged; the only thing wrong with them is that
 * they are old.
 *
 * The tampering is done by the HOST between boots (`cp` and `dd` in the
 * Makefile), not by the kernel, because that is what a physical attacker with
 * the disk actually does. The kernel's only jobs are to say which two blocks to
 * snapshot and to carry a phase counter across the reboots.
 *
 * THE PHASE COUNTER lives in the block one past the end of the volume. The image
 * is deliberately one block longer than the device, so this is storage the
 * filesystem can never reach and the harness never has to reserve anything in a
 * layout that ships. It also means the phase survives a tamper that rewinds
 * filesystem state, which a phase file would not. */

/* Physical block backing (ino, block), so the harness can name the metadata
 * block that describes it. Selftest builds only: it exposes the allocator's
 * choices, which nothing in a shipping kernel has any business asking. */
uint64_t storage_test_phys_block(struct mounted_fs *mfs, uint64_t ino, uint64_t block)
{
    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) return 0;
    return get_physical_block(mfs, &inode, block, 0);
}

/* The two disk blocks that together are a consistent past state of one
 * metadata block: the block itself, and the level-0 node that records its hash. */
void storage_test_merkle_targets(struct mounted_fs *mfs, uint64_t phys,
                                 uint64_t *meta_block_out, uint64_t *node_block_out)
{
    uint64_t meta_blk = phys / META_ENTRIES_PER_BLOCK;
    *meta_block_out = mfs->sb.meta_start + meta_blk;
    *node_block_out = merkle_level_base(&mfs->sb, 0) + meta_blk / MERKLE_FANOUT;
}

/* The harness's phase counter, in the block one past the volume. raw_block_*
 * rather than do_block_*: this is outside the filesystem entirely and must never
 * be staged into a journal transaction that describes it. */
/* Leave the volume looking as though a crash landed inside a multi-transaction
 * operation, so the next mount runs the fsck sweep. That is the real trigger --
 * storage_free_inode_blocks sets exactly this flag and clears it when it
 * finishes -- so the witness exercises the true path rather than a test-only
 * one. */
void storage_test_arm_fsck(struct mounted_fs *mfs)
{
    mfs->sb.needs_fsck = 1;
    raw_block_write(0, &mfs->sb);
    raw_block_flush();
}

/* WHERE A MULTI-BOOT HARNESS KEEPS ITS PHASE COUNTER.
 *
 * It was the block one past BLOCKS_PER_DISK, which worked only while that
 * constant was every volume's size. Now the volume is sized from the disk, so
 * "one past the constant" is somewhere off the end of a small image and the read
 * fails -- which is how the fsck gate started reporting an unreadable scratch
 * block the moment the ceiling was raised.
 *
 * The TPM blob block instead: reserved unconditionally at format so that the
 * geometry does not depend on whether a TPM is present, and on a password-only
 * volume (tpm_mode == 0) it is zeroed and NOTHING EVER READS IT. It is inside
 * the volume, so it needs no games with the image size; it is not in the
 * metadata region or the tree, so a rollback tamper does not carry the phase
 * back with it; and it survives a reboot, which is the whole requirement.
 *
 * Refused outright on a sealed volume, where those bytes are the sealed blob. */
static uint64_t storage_test_scratch_block(const struct mounted_fs *mfs)
{
    if (mfs->sb.tpm_mode != 0) return 0;          /* the blob lives there; hands off */
    return 1 + mfs->sb.meta_blocks;               /* == tpm_blob_block, see format */
}

uint32_t storage_test_scratch_get(void)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    uint64_t blk = storage_test_scratch_block(mfs);
    if (blk == 0) return 0xFFFFFFFFu;
    static uint8_t buf[BLOCK_SIZE];
    if (raw_block_read(blk, buf) != 0) return 0xFFFFFFFFu;
    if (buf[0] != 'P' || buf[1] != 'H') return 0;    /* a fresh image: phase 0 */
    return buf[2];
}

void storage_test_scratch_set(uint32_t phase)
{
    struct mounted_fs *mfs = storage_get_mounted_fs();
    uint64_t blk = storage_test_scratch_block(mfs);
    if (blk == 0) return;
    static uint8_t buf[BLOCK_SIZE];
    my_memset(buf, 0, BLOCK_SIZE);
    buf[0] = 'P'; buf[1] = 'H'; buf[2] = (uint8_t)phase;
    raw_block_write(blk, buf);
    raw_block_flush();
}

/* Is this physical block marked allocated in the data bitmap? The fsck witness
 * asks the bitmap DIRECTLY rather than inferring from a later allocation,
 * because a freed-but-still-referenced block reads back perfectly well until
 * something else is given it -- so a read-back test would pass over the defect
 * and only fail once the allocator happened to collide. */
int storage_test_block_allocated(struct mounted_fs *mfs, uint64_t phys)
{
    if (phys < mfs->sb.data_start) return -1;
    uint64_t rel = phys - mfs->sb.data_start;
    if (rel >= mfs->sb.block_count) return -1;
    static uint8_t bm[BLOCK_SIZE];
    if (do_block_read(mfs->sb.block_bitmap_start + rel / BITS_PER_BITMAP_BLOCK, bm) != 0)
        return -1;
    return bitmap_test(bm, rel % BITS_PER_BITMAP_BLOCK) ? 1 : 0;
}
#endif /* STORAGE_TEST_HOOKS */

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

/* Defined below; declared here so the slot helpers can sit beside the wrap they
 * generalise rather than being separated from it by the KEK derivation. */
static int derive_kek(const char *password, size_t plen,
                      const uint8_t *kek_salt, uint8_t *kek32);
static int apply_tpm_kek_binding(struct block_device *bd,
                                 const struct fs_superblock *sb, uint8_t *kek32);

/* ---- key slots (SECURITY.md S61) ----------------------------------------
 *
 * The slot region is plaintext on disk in the sense that its BYTES are readable;
 * every slot's payload is AEAD-sealed under a password-derived KEK, so what a
 * stolen disk yields is a set of opaque wraps and nothing about how many
 * accounts exist beyond how many slots are marked active.
 */
static int keyslots_read(struct block_device *bd, const struct fs_superblock *sb,
                         fs_keyslot_t *out)
{
    if (!bd || !bd->read_block || sb->keyslot_start == 0) return -1;
    uint8_t blk[BLOCK_SIZE];
    uint8_t *dst = (uint8_t *)out;
    for (uint32_t i = 0; i < KEYSLOT_BLOCKS; i++) {
        if (bd->read_block(bd, sb->keyslot_start + i, blk) != 0) return -1;
        uint32_t off = i * BLOCK_SIZE;
        uint32_t len = sizeof(fs_keyslot_t) * HORUS_KEYSLOTS;
        if (off >= len) break;
        uint32_t n = (len - off) < BLOCK_SIZE ? (len - off) : BLOCK_SIZE;
        my_memcpy(dst + off, blk, n);
    }
    return 0;
}

static int keyslots_write(struct block_device *bd, const struct fs_superblock *sb,
                          const fs_keyslot_t *in)
{
    if (!bd || !bd->write_block || sb->keyslot_start == 0) return -1;
    uint8_t blk[BLOCK_SIZE];
    const uint8_t *src = (const uint8_t *)in;
    uint32_t len = sizeof(fs_keyslot_t) * HORUS_KEYSLOTS;
    for (uint32_t i = 0; i < KEYSLOT_BLOCKS; i++) {
        secure_zero(blk, sizeof(blk));
        uint32_t off = i * BLOCK_SIZE;
        if (off < len) {
            uint32_t n = (len - off) < BLOCK_SIZE ? (len - off) : BLOCK_SIZE;
            my_memcpy(blk, src + off, n);
        }
        if (bd->write_block(bd, sb->keyslot_start + i, blk) != 0) return -1;
    }
    return 0;
}

/* Seal disk_key||uid into `slot` under a KEK derived from `password`. The KEK
 * expansion and AEAD call are copied from the single-wrap path they replace,
 * deliberately unchanged. */
static int keyslot_seal(struct block_device *bd, const struct fs_superblock *sb,
                        fs_keyslot_t *slot, const char *password, size_t plen,
                        const uint8_t *disk_key, uint32_t uid)
{
    secure_random_bytes(slot->kek_salt, sizeof(slot->kek_salt));
    secure_random_bytes(slot->nonce,    sizeof(slot->nonce));

    uint8_t kek[32];
    if (derive_kek(password, plen, slot->kek_salt, kek) != 0) return -1;
    if (apply_tpm_kek_binding(bd, sb, kek) != 0) { secure_zero(kek, 32); return -1; }

    uint8_t wrap_keys[64];
    {
        const char *label = "horus-wrap-v1";
        uint8_t info[13]; size_t n = 0;
        for (const char *c = label; *c; c++) info[n++] = (uint8_t)*c;
        if (rust_hkdf_sha256(kek, 32, slot->kek_salt, sizeof(slot->kek_salt),
                             info, n, wrap_keys, 64) != 0) {
            secure_zero(kek, 32); return -1;
        }
    }
    secure_zero(kek, sizeof(kek));

    my_memcpy(slot->ct, disk_key, 32);
    slot->ct[32] = (uint8_t)(uid & 0xFF);
    slot->ct[33] = (uint8_t)((uid >> 8) & 0xFF);
    slot->ct[34] = (uint8_t)((uid >> 16) & 0xFF);
    slot->ct[35] = (uint8_t)((uid >> 24) & 0xFF);
    int rc = rust_aead_seal(wrap_keys, wrap_keys + 32, slot->nonce,
                            sb->volume_key_salt, sizeof(sb->volume_key_salt),
                            slot->ct, sizeof(slot->ct), slot->tag);
    secure_zero(wrap_keys, sizeof(wrap_keys));
    if (rc != 0) { secure_zero(slot->ct, sizeof(slot->ct)); return -1; }
    slot->active = 1;
    return 0;
}

/* Try one slot. 0 on success, with disk_key32 and *uid_out filled. */
static int keyslot_open(struct block_device *bd, const struct fs_superblock *sb,
                        const fs_keyslot_t *slot, const char *password, size_t plen,
                        uint8_t *disk_key32, uint32_t *uid_out)
{
    if (!slot->active) return -1;

    uint8_t kek[32];
    if (derive_kek(password, plen, slot->kek_salt, kek) != 0) return -1;
    if (apply_tpm_kek_binding(bd, sb, kek) != 0) { secure_zero(kek, 32); return -1; }

    uint8_t wrap_keys[64];
    {
        const char *label = "horus-wrap-v1";
        uint8_t info[13]; size_t n = 0;
        for (const char *c = label; *c; c++) info[n++] = (uint8_t)*c;
        if (rust_hkdf_sha256(kek, 32, slot->kek_salt, sizeof(slot->kek_salt),
                             info, n, wrap_keys, 64) != 0) {
            secure_zero(kek, 32); return -1;
        }
    }
    secure_zero(kek, sizeof(kek));

    uint8_t pt[36];
    my_memcpy(pt, slot->ct, sizeof(pt));
    int rc = rust_aead_open(wrap_keys, wrap_keys + 32, slot->nonce,
                            sb->volume_key_salt, sizeof(sb->volume_key_salt),
                            pt, sizeof(pt), slot->tag);
    secure_zero(wrap_keys, sizeof(wrap_keys));
    if (rc != 0) { secure_zero(pt, sizeof(pt)); return -1; }

    my_memcpy(disk_key32, pt, 32);
    if (uid_out) {
        *uid_out = (uint32_t)pt[32] | ((uint32_t)pt[33] << 8) |
                   ((uint32_t)pt[34] << 16) | ((uint32_t)pt[35] << 24);
    }
    secure_zero(pt, sizeof(pt));
    return 0;
}

/* Derive a 32-byte Key Encryption Key from password + kek_salt.
 * No kernel_pepper: the KEK must reproduce from the same inputs across reboots.
 * Domain-separated from the login hash by the different salt length (32B vs 32B
 * login_salt||pepper) and the different downstream use (wrapping vs verification).
 *
 * Normally Argon2id (memory-hard, resists brute force of a low-entropy password).
 * For the ephemeral vdisk, whose key is already 256 bits of CSPRNG output, a
 * memory-hard step adds nothing, so HKDF-SHA256 is used — cryptographically sound
 * for a high-entropy input and ~an order of magnitude cheaper at boot. */
static int derive_kek(const char *password, size_t plen,
                      const uint8_t *kek_salt, uint8_t *kek32)
{
    if (g_vdisk_high_entropy_kek) {
        /* HKDF(ikm=high-entropy key, salt=kek_salt, info="horus-kek-he-v1").
         * The info label is distinct from the "horus-wrap-v1" expansion below so
         * the KEK and the wrap subkeys stay domain-separated. */
        const char *label = "horus-kek-he-v1";
        uint8_t info[15]; size_t n = 0;
        for (const char *c = label; *c; c++) info[n++] = (uint8_t)*c;
        return rust_hkdf_sha256((const uint8_t *)password, plen,
                                kek_salt, 32, info, n, kek32, 32);
    }
    /* Uses kernel_argon2id (syscall.c) to share the single 4MiB scratch buffer.
     * No kernel_pepper: kek_salt is random per-format and stable across reboots,
     * so the same password always yields the same KEK from the same disk. */
    return kernel_argon2id((const uint8_t *)password, plen,
                           kek_salt, 32, kek32, 32);
}

/* Mix the TPM-sealed secret into the password-derived KEK for a TPM-mode volume
 * (roadmap 2.2 stage 3). Reads the sealed (pub||priv) blob from sb->tpm_blob_block
 * and asks the TPM to unseal it — which succeeds only under a measured-good boot
 * (PolicyPCR(PCR8,PCR9)) — then folds the released secret into kek in place:
 *   kek <- HKDF(ikm = password-KEK, salt = tpm_secret, info = "horus-kek-tpm-v1").
 * On a password-mode volume (tpm_mode != 1) this is a no-op. Returns 0 on success;
 * non-zero means the TPM refused (tampered measurement, or no TPM) and the caller
 * must leave the volume LOCKED — the same fail-closed surface as a wrong password,
 * reached before disk_key is ever unwrapped. */
static int apply_tpm_kek_binding(struct block_device *bd,
                                 const struct fs_superblock *sb, uint8_t *kek32)
{
    if (sb->tpm_mode != 1) return 0;

    if (sb->tpm_pub_len == 0 || sb->tpm_pub_len > TPM_SEALED_PUB_MAX ||
        sb->tpm_priv_len == 0 || sb->tpm_priv_len > TPM_SEALED_PRIV_MAX ||
        (uint32_t)sb->tpm_pub_len + (uint32_t)sb->tpm_priv_len > BLOCK_SIZE ||
        sb->tpm_blob_block == 0) return -1;

    uint8_t blk[BLOCK_SIZE];
    if (bd->read_block(bd, sb->tpm_blob_block, blk) != 0) return -1;

    struct tpm_sealed_blob blob;
    blob.pub_len  = sb->tpm_pub_len;
    blob.priv_len = sb->tpm_priv_len;
    my_memcpy(blob.pub,  blk,                blob.pub_len);
    my_memcpy(blob.priv, blk + blob.pub_len, blob.priv_len);

    uint8_t tpm_secret[32];
    if (tpm_unseal_secret(&blob, tpm_secret) != 0) return -1;   /* TPM denied -> locked */

    const char *label = "horus-kek-tpm-v1";
    uint8_t info[16]; size_t n = 0;
    for (const char *c = label; *c; c++) info[n++] = (uint8_t)*c;
    uint8_t mixed[32];
    int rc = rust_hkdf_sha256(kek32, 32, tpm_secret, 32, info, n, mixed, 32);
    if (rc == 0) my_memcpy(kek32, mixed, 32);
    secure_zero(mixed,      sizeof(mixed));
    secure_zero(tpm_secret, sizeof(tpm_secret));
    return rc;
}

/* Seal a fresh random secret under PolicyPCR(PCR8,PCR9), write the (pub||priv)
 * blob to blob_block, and record tpm_mode/lengths/location in sb. Called from
 * format when the volume opts into TPM mode. Returns 0 on success. */
static int format_seal_tpm(struct block_device *bd, struct fs_superblock *sb,
                           uint64_t blob_block)
{
    uint8_t tpm_secret[32];
    secure_random_bytes(tpm_secret, sizeof(tpm_secret));

    struct tpm_sealed_blob blob;
    int rc = tpm_seal_secret(tpm_secret, &blob);
    secure_zero(tpm_secret, sizeof(tpm_secret));
    if (rc != 0) return -1;
    if ((uint32_t)blob.pub_len + (uint32_t)blob.priv_len > BLOCK_SIZE) return -1;

    uint8_t blk[BLOCK_SIZE];
    my_memset(blk, 0, sizeof(blk));
    my_memcpy(blk,                blob.pub,  blob.pub_len);
    my_memcpy(blk + blob.pub_len, blob.priv, blob.priv_len);
    if (bd->write_block(bd, blob_block, blk) != 0) return -1;

    sb->tpm_mode       = 1;
    sb->tpm_pub_len    = blob.pub_len;
    sb->tpm_priv_len   = blob.priv_len;
    sb->tpm_blob_block = blob_block;
    return 0;
}

/* Format a block device and seal disk_key with the user's password.
 * disk_key is randomly generated, never stored in plaintext on disk.
 * KEK = Argon2id(password, kek_salt); wrapped = AEAD(KEK, disk_key). */
static int storage_format_sealed(struct block_device *bd,
                                  const char *password, size_t plen)
{
    struct fs_superblock sb;
    my_memset(&sb, 0, sizeof(sb));

    sb.magic = STORAGE_MAGIC;
    sb.version = STORAGE_VERSION;
    sb.total_blocks = bd->total_blocks;
    sb.block_size = BLOCK_SIZE;

    /* Block 0: superblock.  Blocks 1..sb.meta_blocks: crypto metadata region.
     * All other regions are shifted past it so the metadata lives at a fixed,
     * known offset regardless of disk geometry. */
    sb.meta_start         = 1;
    /* SIZED FROM THE DEVICE, not from BLOCKS_PER_DISK. The region needs one entry
     * per block this volume actually has; reserving META_BLOCKS_MAX instead gave a
     * 4096-block RAM disk a 256-block region, and at a 16 GiB BLOCKS_PER_DISK it
     * would ask a 16 MiB RAM disk for 32768 blocks and fail the "disk too small"
     * check below -- so a diskless boot would not come up. */
    sb.meta_blocks        = (uint32_t)((bd->total_blocks + META_ENTRIES_PER_BLOCK - 1)
                                       / META_ENTRIES_PER_BLOCK);
    if (sb.meta_blocks > META_BLOCKS_MAX) return -1;   /* device past this kernel's ceiling */
    /* v6: one block reserved right after the metadata region for the TPM sealed
     * blob (used only in tpm_mode; zeroed otherwise). Kept in the layout
     * unconditionally so geometry does not depend on whether a TPM is present. */
    uint64_t tpm_blob_block = 1 + sb.meta_blocks;
    /* v7: the key-slot region follows the TPM blob block, for the same reason
     * that block exists -- eight wraps do not fit in a 512-byte superblock. */
    sb.keyslot_start      = tpm_blob_block + 1;
    sb.keyslot_blocks     = KEYSLOT_BLOCKS;
    /* v8: the sealed user table follows the key slots. */
    sb.users_start        = sb.keyslot_start + KEYSLOT_BLOCKS;
    sb.users_blocks       = USERS_BLOCKS;
    /* v11: the Merkle node region follows the user table. Sized from the
     * metadata region, which is itself sized from the device -- so a bigger disk
     * buys a deeper tree rather than a bigger constant anywhere in RAM. */
    {
        uint64_t counts[MERKLE_MAX_LEVELS];
        uint32_t levels = merkle_layout(sb.meta_blocks, counts);
        if (levels == 0) return -1;      /* past what the tree can describe */
        uint64_t total = 0;
        for (uint32_t l = 0; l < levels; l++) total += counts[l];
        sb.merkle_start  = sb.users_start + USERS_BLOCKS;
        sb.merkle_blocks = (uint32_t)total;
        sb.merkle_levels = levels;
    }
    /* Write-ahead redo log sits right after the tree. */
    sb.journal_start      = sb.merkle_start + sb.merkle_blocks;
    sb.journal_blocks     = JOURNAL_BLOCKS;
    uint64_t after_j      = sb.journal_start + JOURNAL_BLOCKS;

    /* Geometry is computed from the device size. One bitmap block addresses
     * BLOCK_SIZE*8 bits. BOTH bitmaps span as many blocks as they need:
     *   inode_bitmap : ib_blocks blocks
     *   block_bitmap : bm_blocks blocks
     *   inode_table  : table_blocks blocks
     *   data         : the rest
     *
     * ONE INODE PER 32 BLOCKS, not per 4. At 4 KiB that is one file per 128 KiB
     * of volume, and it is a trade against FORMAT TIME and fsck's walk rather
     * than against disk: at 16 GiB, one-per-4 would be a million inodes and a
     * 16 MiB table, one-per-32 is 131072 and 2 MiB. The old ratio was chosen
     * when the cap below made it moot -- inodes were clamped to a single bitmap
     * block, 32768 of them, so a 16 GiB volume would have had one inode per 128
     * blocks whatever this number said. */
    const uint64_t BITS_PER_BLOCK = (uint64_t)BLOCK_SIZE * 8;

    uint64_t inodes = bd->total_blocks / 32;
    if (inodes < 16) inodes = 16;
    uint64_t table_blocks = (inodes + INODES_PER_BLOCK - 1) / INODES_PER_BLOCK;
    inodes = table_blocks * INODES_PER_BLOCK;
    uint64_t ib_blocks = (inodes + BITS_PER_BLOCK - 1) / BITS_PER_BLOCK;
    if (ib_blocks == 0) ib_blocks = 1;
    sb.inode_count          = inodes;
    sb.inode_bitmap_blocks  = (uint32_t)ib_blocks;

    sb.inode_bitmap_start = after_j;
    sb.block_bitmap_start = after_j + ib_blocks;

    /* Solve for the data-bitmap span: (bm_blocks + data_blocks) share `avail`,
     * and bm_blocks = ceil(data_blocks / BITS_PER_BLOCK). Iterating converges in a
     * couple of steps (bm_blocks is tiny next to data_blocks). */
    uint64_t fixed  = after_j + ib_blocks + table_blocks;   /* everything except bitmap + data */
    if (fixed >= bd->total_blocks) return -1;        /* disk too small */
    uint64_t avail  = bd->total_blocks - fixed;
    uint64_t bm_blocks = (avail + BITS_PER_BLOCK - 1) / BITS_PER_BLOCK;
    for (int it = 0; it < 8; it++) {
        uint64_t d = (avail > bm_blocks) ? avail - bm_blocks : 0;
        uint64_t nb = (d + BITS_PER_BLOCK - 1) / BITS_PER_BLOCK;
        if (nb == 0) nb = 1;
        if (nb == bm_blocks) break;
        bm_blocks = nb;
    }
    if (bm_blocks >= avail) return -1;               /* no room for data */
    uint64_t data_blocks = avail - bm_blocks;

    sb.inode_table_start = sb.block_bitmap_start + bm_blocks;
    sb.data_start        = sb.inode_table_start + table_blocks;
    if (sb.data_start >= bd->total_blocks) return -1;   /* disk too small */
    sb.block_count = data_blocks;

    /* Per-volume HKDF diversifier — random per-format, stable on disk. */
    secure_random_bytes(sb.volume_key_salt, sizeof(sb.volume_key_salt));

    /* Generate disk_key — root of all per-block key derivation.
     * Never written in plaintext to disk; sealed below with the user's KEK. */
    uint8_t disk_key[32];
    secure_random_bytes(disk_key, sizeof(disk_key));

    /* KEK = Argon2id(password, kek_salt).  kek_salt is random per-format but
     * contains no kernel_pepper so the same password always yields the same KEK
     * across reboots.  KEK is expanded to 64 bytes via HKDF then used as the
     * enc_key||mac_key pair for the wrapping AEAD. */
    secure_random_bytes(sb.kek_salt,          sizeof(sb.kek_salt));

    /* v6 — opt into TPM sealing for a persistent volume when a TPM is present. The
     * ephemeral high-entropy vdisk never seals (its key is a per-boot throwaway).
     * Sealed BEFORE the KEK is derived so apply_tpm_kek_binding (shared with the
     * unlock path) can fold the sealed secret into the KEK the same way both here
     * and at unlock. If sealing is not requested the reserved blob block stays
     * zero and tpm_mode stays 0 (unchanged password-only volume). */
    int want_tpm = g_tpm_force_seal || (tpm_present() && !g_vdisk_high_entropy_kek);
    if (want_tpm && format_seal_tpm(bd, &sb, tpm_blob_block) != 0) {
        secure_zero(disk_key, sizeof(disk_key));
        return -1;
    }
    {
        /* v7 -- seal disk_key into SLOT 0 rather than into the superblock. The
         * formatting password becomes the first of up to HORUS_KEYSLOTS that can
         * open this volume; uid 0 because whoever formats it is root here. Every
         * other slot is left zeroed, which is what `active == 0` means. */
        fs_keyslot_t slots[HORUS_KEYSLOTS];
        secure_zero(slots, sizeof(slots));
        if (keyslot_seal(bd, &sb, &slots[0], password, plen, disk_key, 0) != 0) {
            secure_zero(disk_key, sizeof(disk_key));
            secure_zero(slots, sizeof(slots));
            return -1;
        }
        if (keyslots_write(bd, &sb, slots) != 0) {
            secure_zero(disk_key, sizeof(disk_key));
            secure_zero(slots, sizeof(slots));
            return -1;
        }
        secure_zero(slots, sizeof(slots));
    }

    uint8_t zero[BLOCK_SIZE];
    my_memset(zero, 0, BLOCK_SIZE);

    /* Zero the crypto metadata region so every block starts with present=0.
     * THIS MUST HAPPEN BEFORE THE HMAC BELOW, and the ordering is the reason the
     * two can no longer disagree: merkle_build reads the region off the
     * device, so it hashes the bytes that are actually there rather than an
     * assumption about them. The old code hashed an all-zero in-RAM array and
     * wrote the region afterwards; the two happened to agree, and a volume whose
     * format left one byte of the region unwritten would have been bricked at its
     * first mount by a check that could not say why. */
    for (uint64_t m = 0; m < sb.meta_blocks; m++) {
        bd->write_block(bd, sb.meta_start + m, zero);
    }

    /* Nothing resident describes this volume yet, and anything resident describes
     * a different one. */
    meta_cache_reset();
    merkle_cache_reset();

    {
        uint8_t fmt_mac_key[32];
        if (derive_meta_mac_key(disk_key, sizeof(disk_key),
                                sb.volume_key_salt, sizeof(sb.volume_key_salt),
                                fmt_mac_key) != 0) {
            secure_zero(disk_key, sizeof(disk_key));
            return -1;
        }
        /* Builds the whole tree over the region just zeroed and leaves its root
         * in sb.meta_root. Reads each block back rather than assuming its
         * content, for the reason the zeroing moved above this in the first
         * place: format and mount must hash the same bytes, not two sources that
         * happen to agree. */
        int rc = merkle_build(bd, &sb, fmt_mac_key);
        secure_zero(fmt_mac_key, sizeof(fmt_mac_key));
        if (rc != 0) { secure_zero(disk_key, sizeof(disk_key)); return -1; }
    }
    secure_zero(disk_key, sizeof(disk_key));

    bd->write_block(bd, 0, &sb);

    /* v6: clear the reserved TPM blob block on a password-mode volume. In TPM mode
     * format_seal_tpm already wrote the sealed blob there — must not wipe it. */
    if (!want_tpm) bd->write_block(bd, tpm_blob_block, zero);

    /* Zero the journal region: a cleared header (magic 0) means "no committed
     * transaction to replay" — a fresh volume has nothing to recover. */
    for (uint32_t j = 0; j < sb.journal_blocks; j++) {
        bd->write_block(bd, sb.journal_start + j, zero);
    }

    /* Zero every block-bitmap block (the data allocator may span several). */
    for (uint64_t b = 0; b < bm_blocks; b++) {
        bd->write_block(bd, sb.block_bitmap_start + b, zero);
    }

    /* Zero every inode-BITMAP block. The TABLE is not zeroed here: at a 16 GiB
     * volume it is 2 MiB written to a PIO disk before the login prompt, and the
     * requirement it served -- an inode sharing a block with a freshly used one
     * must not read back as garbage off a second-hand disk -- is met instead by
     * storage_alloc_inode, which zeros a table block the first time any inode in
     * it is allocated. The bitmap is what says whether that has happened. */
    for (uint64_t b = 0; b < ib_blocks; b++) {
        bd->write_block(bd, sb.inode_bitmap_start + b, zero);
    }

    /* Root inode 0 is written directly rather than allocated, so the lazy
     * zeroing above never runs for its table block. Zero it here. */
    bd->write_block(bd, sb.inode_table_start, zero);

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

    /* Reject disks with the wrong magic or an older on-disk version.  A v1 disk
     * has no metadata region (meta_start=0) and would silently serve undecryptable
     * blocks after reboot.  Returning -2 here triggers storage_init to reformat,
     * which is the correct recovery for an incompatible layout. */
    if (sb->magic != STORAGE_MAGIC || sb->version != STORAGE_VERSION) {
        return -2;
    }

    /* THE VOLUME MUST FIT THE MEDIUM IT IS ON. Now that the device is sized from
     * IDENTIFY rather than from a constant, a superblock claiming more blocks
     * than the disk reports means the volume was formatted on a larger disk and
     * this one is a truncated copy -- every offset past the end reads as a
     * failure, and the data region's tail simply is not there. Refusing is the
     * only honest answer; mounting it would serve part of a filesystem and call
     * it whole. */
    if (sb->total_blocks > bd->total_blocks) {
        println("STORAGE: refusing a volume larger than the disk it is on");
        return -3;
    }

    g_mounted_fs.bd       = bd;
    g_mounted_fs.sb       = *sb;
    g_mounted_fs.mounted  = 1;
    g_mounted_fs.unlocked = 0;
    /* Key derivation deferred to storage_unlock() — we need the user's
     * password to unwrap disk_key before any crypto work can proceed. */
    return 0;
}

struct mounted_fs *storage_get_mounted_fs(void) {
    return &g_mounted_fs;
}

/* Called at first successful login.  If no valid v4 disk exists (g_needs_format)
 * formats and seals one with the user's password first; then unwraps disk_key,
 * derives volume_key + meta_mac_key, and verifies the metadata HMAC. */
/* An installer's explicit "yes, format this disk". Nothing else calls it. */
void storage_authorize_format(void) { g_format_authorized = 1; }

int storage_unlock(const char *password, size_t plen)
{
    if (g_needs_format) {
#ifndef STORAGE_AUTOFORMAT
        /* A LOGIN IS NOT CONSENT TO FORMAT A DISK (SECURITY.md S63).
         *
         * Until 2026-08-31 meeting an unformatted ATA volume at the login prompt
         * ran storage_format_sealed on the strength of whatever had been typed:
         * a mistyped password on a machine whose disk the kernel did not
         * recognise formatted it and became key slot 0. The volume was not
         * readable afterwards by the password its owner actually used, and
         * nothing said a format had happened.
         *
         * Recognising a volume is not the same as owning it, and neither is
         * failing to recognise one grounds for destroying it. Formatting is now
         * a deliberate act -- storage_authorize_format(), which an installer
         * calls and a login never does.
         *
         * THE EPHEMERAL VDISK IS NOT AFFECTED: it is formatted and unlocked
         * inside storage_init with a per-boot throwaway key and never reaches
         * g_needs_format at all, so a diskless boot still comes up.
         *
         * STORAGE_AUTOFORMAT=1 restores the old behaviour for the test targets
         * that boot a deliberately blank image, and is the control arm for
         * make smoke-storage-noformat. */
        if (!g_format_authorized) {
            print("STORAGE: refusing to format an unrecognised volume at login; "
                  "no format was authorised\n");
            return -6;
        }
#endif
        if (storage_format_sealed(g_needs_format_bd, password, plen) != 0) return -1;
        if (storage_mount(g_needs_format_bd) != 0) return -1;
        g_needs_format    = 0;
        g_needs_format_bd = NULL;
#ifdef WAL_CRASHTEST
        storage_fresh_format = 1;   /* this boot formatted a fresh disk (boot 1) */
#endif
    }

    struct mounted_fs *mfs = &g_mounted_fs;
    if (!mfs->mounted)  return -2;
    if (mfs->unlocked)  return 0;   /* idempotent: already unlocked */

    struct fs_superblock *sb = &mfs->sb;

#ifdef MEASURED_BOOT_REQUIRED
    /* A password-only volume is a DOWNGRADE when measured boot is required.
     *
     * The sealed path already fails closed in the other direction: a volume with
     * tpm_mode == 1 cannot be unlocked unless the TPM releases its secret under
     * PolicyPCR(8,9), so a tampered boot leaves it locked (S12). What nothing
     * checked is the reverse -- a volume that was never sealed unlocks on the
     * password alone, forever. Present a re-formatted disk to a machine that
     * requires measured boot and the requirement evaporates, because tpm_mode 0
     * makes apply_tpm_kek_binding a no-op.
     *
     * THE EPHEMERAL VDISK IS EXEMPT, and that is not a loophole: it exists only
     * in RAM for one boot, its key is a full-entropy random value generated on
     * this boot and discarded at power-off, and it is never written anywhere a
     * later boot could read. Sealing a key that cannot outlive the measurement
     * adds nothing to seal against. The exemption is the flag's ONE hole, so it
     * is named here rather than left implicit -- and MEASURED_VOLUME_EXEMPT_NONE=1
     * removes it, which is how the refusal below is falsified. */
    {
#ifdef MEASURED_VOLUME_EXEMPT_NONE
        int exempt = 0;
#else
        int exempt = g_vdisk_high_entropy_kek;
#endif
        if (!exempt && sb->tpm_mode != 1) {
            println("PANIC: measured boot required but the volume is not sealed "
                    "(password-only); refusing to unlock");
            return -9;
        }
    }
#endif

    /* Steps 1-3 — find the slot this password opens.
     *
     * Every slot is an independent wrap of the SAME disk_key under a KEK derived
     * from its own salt, so there is no way to tell which slot a password belongs
     * to without deriving. Active slots are tried in order and the first that
     * opens wins; inactive ones cost nothing, so a single-password volume does
     * exactly the one Argon2id it did before key slots existed.
     *
     * TIMING, STATED RATHER THAN CLAIMED AWAY: a wrong password costs one
     * derivation per ACTIVE slot, a right one stops early, so an observer who can
     * time a login learns roughly which slot index opened. LUKS has the same
     * property. It is not constant-time and this comment does not pretend it is;
     * making it so would mean always deriving every slot, which multiplies the
     * cost of the common case by HORUS_KEYSLOTS to hide an index from an observer
     * who, in the login case, is the person supplying the password.
     *
     * A tag mismatch is indistinguishable from a wrong password by construction,
     * so a failed unlock says only "no slot opened" and never which slot came
     * closest. */
    uint8_t disk_key[32];
    uint32_t slot_uid = 0;
    {
        fs_keyslot_t slots[HORUS_KEYSLOTS];
        if (keyslots_read(mfs->bd, sb, slots) != 0) {
            secure_zero(slots, sizeof(slots));
            return -3;
        }
        int opened = -1;
        for (uint32_t i = 0; i < HORUS_KEYSLOTS; i++) {
            if (keyslot_open(mfs->bd, sb, &slots[i], password, plen,
                             disk_key, &slot_uid) == 0) { opened = (int)i; break; }
        }
        secure_zero(slots, sizeof(slots));
        if (opened < 0) {
            secure_zero(disk_key, sizeof(disk_key));
            return -5;
        }
        g_unlocked_slot = (uint32_t)opened;
        g_unlocked_uid  = slot_uid;
    }

    /* Step 4 — Store plaintext disk_key in RAM; derive volume_key + meta_mac_key. */
    my_memcpy(mfs->disk_key, disk_key, 32);
    secure_zero(disk_key, sizeof(disk_key));

    {
        const char *label = "horus-volume-key-v2";
        uint8_t info[19]; size_t n = 0;
        for (const char *c = label; *c; c++) info[n++] = (uint8_t)*c;
        if (rust_hkdf_sha256(mfs->disk_key, 32,
                             sb->volume_key_salt, sizeof(sb->volume_key_salt),
                             info, n,
                             mfs->volume_key, sizeof(mfs->volume_key)) != 0) {
            secure_zero(mfs->disk_key, sizeof(mfs->disk_key));
            return -6;
        }
    }
    if (derive_meta_mac_key(mfs->disk_key, 32,
                            sb->volume_key_salt, sizeof(sb->volume_key_salt),
                            mfs->meta_mac_key) != 0) {
        secure_zero(mfs->disk_key,   sizeof(mfs->disk_key));
        secure_zero(mfs->volume_key, sizeof(mfs->volume_key));
        return -7;
    }
    if (derive_journal_mac_key(mfs->disk_key, 32,
                               sb->volume_key_salt, sizeof(sb->volume_key_salt),
                               mfs->journal_mac_key) != 0) {
        secure_zero(mfs->disk_key,   sizeof(mfs->disk_key));
        secure_zero(mfs->volume_key, sizeof(mfs->volume_key));
        secure_zero(mfs->meta_mac_key, sizeof(mfs->meta_mac_key));
        return -7;
    }

    /* Replay any committed transaction a crash left in the journal BEFORE the
     * metadata region is loaded and its HMAC checked — so an update that touched
     * a meta sector, the tree nodes above it and the root in the superblock is
     * completed as a unit and they always agree. */
    int replayed = journal_recover(mfs);
    /* Recovery may have re-applied a committed transaction that included the
     * superblock (its meta_root). Reload the in-RAM superblock so the root check
     * below compares against the post-recovery value, not the stale mount-time one. */
    {
        uint8_t sbbuf[BLOCK_SIZE];
        if (raw_block_read(0, sbbuf) == 0) my_memcpy(&mfs->sb, sbbuf, sizeof(mfs->sb));
    }

    /* Step 5 — Establish the root of the rollback tree, and nothing more.
     *
     * THIS IS O(1) NOW, and that is the change that lets a volume be large. The
     * check used to read the ENTIRE metadata region and hash every byte of it at
     * every mount -- at a 16 GiB volume that is 128 MiB of reads before the login
     * prompt. It reads one node block and compares one hash. Everything below the
     * root is verified LAZILY, on the path from the root, when a metadata block is
     * first loaded into the cache (see meta_cache_get), so nothing is trusted that
     * has not been placed under this root -- the verification did not get weaker,
     * it moved to the point of use.
     *
     * What that does change is WHEN a rollback is reported: a rewound block is
     * refused at the read that touches it rather than at mount. The volume still
     * never serves it. */
    meta_cache_reset();          /* nothing resident may describe an earlier mount */
    merkle_cache_reset();
    if (merkle_verify_root() != 0) {
        secure_zero(mfs->disk_key,      sizeof(mfs->disk_key));
        secure_zero(mfs->volume_key,    sizeof(mfs->volume_key));
        secure_zero(mfs->meta_mac_key,  sizeof(mfs->meta_mac_key));
        meta_cache_reset();
        merkle_cache_reset();
        return -9;   /* the tree does not stand under its own root */
    }

    mfs->unlocked = 1;

    /* THE SWEEP IS NOT FREE, so it runs when something says it is needed rather
     * than on every mount. It walked the whole inode table every time -- 2 MiB of
     * PIO reads at a 16 GiB volume before the login prompt, on a boot where
     * nothing was wrong.
     *
     * Two things say it is needed. A journal REPLAY means the volume was
     * interrupted mid-transaction. `sb.needs_fsck` means a crash landed inside an
     * operation that spans SEVERAL transactions -- which the chunked free is, and
     * which the journal alone cannot make atomic. Neither being set means every
     * operation either committed whole or did not happen, which is exactly what
     * the journal guarantees, so there is nothing for the sweep to find. */
    if (replayed || mfs->sb.needs_fsck) {
        kmsg_begin();
        print("storage: running the fsck sweep (");
        print(replayed ? "journal replayed" : "an interrupted multi-transaction operation");
        print(")\n");
        storage_fsck_pass(mfs);
        if (mfs->sb.needs_fsck) {
            mfs->sb.needs_fsck = 0;
            journal_begin();
            do_block_write(0, &mfs->sb);
            journal_commit();
        }
    }
    return 0;
}

#ifdef TPM_KEK_SELFTEST
/* Prove the TPM-sealed KEK end-to-end (roadmap 2.2 stage 3), deterministically and
 * without an ATA disk or a login: format the vdisk backing in TPM mode, unlock it
 * (the good-boot case → the TPM releases the sealed factor → disk_key unwraps),
 * then perturb PCR[9] and require a re-unlock to be REFUSED (the TPM denies the
 * unseal → wrong KEK → disk_key stays wrapped → volume locked). If the perturbed
 * re-unlock ever succeeds, the KEK was not actually bound to the measurement —
 * fail loudly. Runs before ramfs_init(), which then reformats the vdisk for real
 * (password/high-entropy) use, so normal boot is unaffected. */
void storage_tpm_kek_selftest(void)
{
    if (!tpm_present())    { println("TPM_KEK_SELFTEST: SKIP (no TPM)"); return; }
    if (!g_vdisk_backing)  { println("TPM_KEK_SELFTEST: SKIP (no vdisk backing)"); return; }

    g_vdisk_high_entropy_kek = 1;   /* fast HKDF base KEK for the test */
    g_tpm_force_seal         = 1;   /* force TPM sealing at format */
    g_vdisk.data        = g_vdisk_backing;
    g_vdisk.size        = VDISK_BYTES;
    g_vdisk.block_count = VDISK_BLOCKS;
    my_memset(g_vdisk.data, 0, g_vdisk.size);

    const char *pw = "kek-selftest-password";
    size_t pl = 0; for (const char *c = pw; *c; c++) pl++;

    int failed = 1;
    if (storage_format_sealed(&g_vdisk_bd, pw, pl) != 0) {
        println("TPM_KEK_SELFTEST: FAIL (format+seal)");
    } else if (storage_mount(&g_vdisk_bd) != 0) {
        println("TPM_KEK_SELFTEST: FAIL (mount)");
    } else if (storage_unlock(pw, pl) != 0) {
        println("TPM_KEK_SELFTEST: FAIL (measured-good boot did not unlock)");
    } else {
        /* Change the measurement; the same sealed blob must no longer release. */
        tpm_test_extend_boot_pcr();
        if (storage_mount(&g_vdisk_bd) != 0) {
            println("TPM_KEK_SELFTEST: FAIL (remount)");
        } else if (storage_unlock(pw, pl) == 0) {
            println("TPM_KEK_SELFTEST: FAIL (unlocked under wrong PCRs!)");
        } else {
            failed = 0;
        }
    }

    g_tpm_force_seal = 0;
    if (!failed) println("TPM_KEK_SELFTEST: PASS");
}
#endif

/* Sweep the inode bitmap and free any slot that is allocated but contains
 * stale data from an interrupted operation:
 *
 *   type == 0, all fields zero:
 *     storage_alloc_inode set the bitmap bit, but the kernel crashed before
 *     storage_write_inode ran.  The slot is still the zeroed bytes written at
 *     format time.  No data blocks were ever allocated (that happens at first
 *     write, after the inode is initialized), so clearing the bitmap bit is
 *     the complete fix.
 *
 *   type != 0, links == 0:
 *     storage_free_inode_blocks freed the data blocks and wrote back the inode
 *     with links=0, but the kernel crashed before storage_free_inode cleared the
 *     bitmap bit.  The data blocks are already freed; we just need to clear the
 *     bit to avoid a permanent "inode slot occupied" leak.
 *
 * Reads one inode table block per iteration (INODES_PER_BLOCK inodes each) to
 * avoid re-reading the same sector for every inode.  Writes the updated bitmap
 * only when at least one slot was reclaimed (dirty flag). */
/* ---- the reference walk (SECURITY.md S67) ------------------------------------
 *
 * fsck does not free the blocks of a live file.
 *
 * WHAT WAS WRONG WITH IT. It marked direct[0..11] and the single-indirect block
 * and its entries, and stopped -- so every block reachable only through
 * `double_indirect`, and the pointer blocks under it, was left UNMARKED and the
 * sweep below cleared its bitmap bit. A live file larger than 12 + PTRS_PER_BLOCK
 * blocks (2.048 MiB at 4 KiB; 38 KiB before the block size was raised) had its
 * blocks marked free at every unlock, and the allocator then handed them to the
 * next file that asked. The file kept reading correctly until that happened,
 * which is why nothing caught it: `smoke-fs-large` writes a double-indirect file
 * but never mounts the volume again, and `smoke-fs-persist` re-mounts but writes
 * a small one.
 *
 * The comment above it said "direct/single-indirect pointers", which is an
 * accurate description of incomplete code and therefore reads as deliberate.
 *
 * PER-LEVEL STATIC BUFFERS, NOT RECURSION ON THE STACK. Each level needs a
 * BLOCK_SIZE buffer, and three of them nested is 12 KiB against a 16 KiB BSP
 * kernel stack -- the stack that multiboot.S sizes and that #270 already
 * overflowed once. The buffers are indexed by depth; fsck is not reentrant. */
static uint8_t g_fsck_ptr_buf[FSCK_MAX_DEPTH][BLOCK_SIZE];

static void fsck_mark(uint8_t *referenced, uint64_t p,
                      uint64_t data_start, uint64_t block_count)
{
    if (p >= data_start && p < data_start + block_count)
        bitmap_set(referenced, p - data_start);
}

/* Mark a pointer block and everything it names. `depth` counts the levels of
 * pointer block BELOW this one: 0 means its entries are data blocks. */
static void fsck_mark_tree(uint8_t *referenced, uint64_t ptr_blk, unsigned depth,
                           uint64_t data_start, uint64_t block_count)
{
    if (ptr_blk < data_start || ptr_blk >= data_start + block_count) return;
    if (depth >= FSCK_MAX_DEPTH) return;             /* cannot happen; fail closed */
    bitmap_set(referenced, ptr_blk - data_start);    /* the pointer block itself */

    uint8_t *blk = g_fsck_ptr_buf[depth];
    if (do_block_read(ptr_blk, blk) != 0) return;
    uint64_t *ptrs = (uint64_t *)blk;
    for (unsigned k = 0; k < PTRS_PER_BLOCK; k++) {
        if (!ptrs[k]) continue;
        if (depth == 0) fsck_mark(referenced, ptrs[k], data_start, block_count);
        else            fsck_mark_tree(referenced, ptrs[k], depth - 1,
                                       data_start, block_count);
    }
}

/* How many times the sweep has run this boot. The S67 witness asserts this is
 * non-zero, and that assertion is not decoration: gating the sweep on
 * `replayed || needs_fsck` made `smoke-fsck-refs` pass WITHOUT RUNNING FSCK AT
 * ALL -- green for the wrong reason, in the same change that introduced the
 * gating. A gate for "fsck does not do X" is worthless if fsck did not run. */
static uint64_t g_fsck_runs;
uint64_t storage_fsck_runs(void) { return g_fsck_runs; }

static void storage_fsck_pass(struct mounted_fs *mfs)
{
    g_fsck_runs++;
    /* The inode bitmap spans blocks now, so the loop below tracks which one is
     * resident and writes it back before moving on. Reading only block 0 and
     * indexing it by inode number -- as this did -- silently tests bit
     * (ino mod 32768) for every inode past the first block, so an inode at 32768
     * would be judged by inode 0's bit. */
    uint8_t inode_bitmap[BLOCK_SIZE];
    uint64_t ib_resident = (uint64_t)-1;
    int inode_dirty = 0;

    /* Data blocks reachable from a live inode's direct/single-indirect pointers,
     * indexed by rel = phys - data_start (matching the block bitmap). Sized to the
     * whole volume, since the data region — and thus its bitmap — can now span
     * several blocks; block_count <= total_blocks <= BLOCKS_PER_DISK. */
    static uint8_t referenced[BLOCKS_PER_DISK / 8];
    my_memset(referenced, 0, sizeof(referenced));
    const uint64_t data_start  = mfs->sb.data_start;
    const uint64_t block_count = mfs->sb.block_count;

    uint64_t table_blocks =
        (mfs->sb.inode_count + INODES_PER_BLOCK - 1) / INODES_PER_BLOCK;

    for (uint64_t tb = 0; tb < table_blocks; tb++) {
        uint8_t blk[BLOCK_SIZE];
        if (do_block_read(mfs->sb.inode_table_start + tb, blk) != 0) continue;
        struct on_disk_inode *slots = (struct on_disk_inode *)blk;

        for (int i = 0; i < INODES_PER_BLOCK; i++) {
            uint64_t ino = tb * (uint64_t)INODES_PER_BLOCK + (uint64_t)i;
            if (ino >= mfs->sb.inode_count) continue;

            uint64_t ib = ino / BITS_PER_BITMAP_BLOCK;
            if (ib != ib_resident) {
                if (inode_dirty && ib_resident != (uint64_t)-1) {
                    do_block_write(mfs->sb.inode_bitmap_start + ib_resident, inode_bitmap);
                    inode_dirty = 0;
                }
                if (do_block_read(mfs->sb.inode_bitmap_start + ib, inode_bitmap) != 0) continue;
                ib_resident = ib;
            }
            if (!bitmap_test(inode_bitmap, ino % BITS_PER_BITMAP_BLOCK)) continue;

            struct on_disk_inode *nd = &slots[i];
            int alive = (nd->type != 0 && nd->links != 0);

            /* Reclaim an allocated inode slot left dangling by an interrupted
             * op (never the root inode 0): type==0 (bitmap set before the inode
             * was initialised) or links==0 (freed before the bitmap bit cleared).
             * Its data blocks, if any, are then reclaimed by the block sweep. */
            if (ino != 0 && !alive) {
                bitmap_clear(inode_bitmap, ino % BITS_PER_BITMAP_BLOCK);
                inode_dirty = 1;
                continue;
            }

            /* Live inode (including root): mark every data block it references,
             * through EVERY level of the mapping. A level missed here is a live
             * file's blocks handed to the next caller that allocates. */
            for (int d = 0; d < 12; d++)
                fsck_mark(referenced, nd->direct[d], data_start, block_count);
            if (nd->indirect)
                fsck_mark_tree(referenced, nd->indirect, 0, data_start, block_count);
#ifndef FSCK_SHALLOW_REFS
            if (nd->double_indirect)
                fsck_mark_tree(referenced, nd->double_indirect, 1,
                               data_start, block_count);
            if (nd->triple_indirect)
                fsck_mark_tree(referenced, nd->triple_indirect, 2,
                               data_start, block_count);
#endif
        }
    }

    if (inode_dirty && ib_resident != (uint64_t)-1)
        do_block_write(mfs->sb.inode_bitmap_start + ib_resident, inode_bitmap);

    /* Reclaim data blocks the bitmap marks allocated but no live inode references
     * (crash-orphaned: allocated before the operation that would link them
     * committed). Only clears bits; never touches a referenced block. The data
     * bitmap can span several blocks, so walk it a block at a time and write back
     * only the ones that changed. */
    for (uint64_t bm = 0, base = 0; base < block_count; bm++, base += BITS_PER_BITMAP_BLOCK) {
        uint8_t block_bitmap[BLOCK_SIZE];
        if (do_block_read(mfs->sb.block_bitmap_start + bm, block_bitmap) != 0) continue;
        uint64_t here = block_count - base;
        if (here > BITS_PER_BITMAP_BLOCK) here = BITS_PER_BITMAP_BLOCK;
        int bb_dirty = 0;
        for (uint64_t b = 0; b < here; b++) {
            uint64_t r = base + b;                 /* volume-relative data block */
            if (bitmap_test(block_bitmap, b) && !bitmap_test(referenced, r)) {
                bitmap_clear(block_bitmap, b);
                bb_dirty = 1;
            }
        }
        if (bb_dirty)
            do_block_write(mfs->sb.block_bitmap_start + bm, block_bitmap);
    }
}

#ifdef KEYSLOT_SELFTEST
/* Does this password open the volume, and if so which slot and whose uid?
 *
 * SELFTEST ONLY, and the guard is the point. It answers exactly what a real
 * unlock answers, so it leaks nothing new -- but it does so WITHOUT taking the
 * unlock path's state change, which is what makes it useful here: storage_unlock
 * is idempotent, so once one password has opened the volume no second password
 * can be tested in the same boot, and "several passwords open this volume" is
 * precisely the property under test. It also bypasses whatever rate limiting the
 * login path grows, which is why it is not compiled into a shipping kernel.
 */
int storage_keyslot_probe(const char *password, size_t plen,
                          uint32_t *uid_out, uint32_t *idx_out)
{
    struct mounted_fs *mfs = &g_mounted_fs;
    if (!mfs->mounted) return -1;
    fs_keyslot_t slots[HORUS_KEYSLOTS];
    if (keyslots_read(mfs->bd, &mfs->sb, slots) != 0) return -1;

    uint8_t dk[32]; uint32_t uid = 0; int found = -1;
    for (uint32_t i = 0; i < HORUS_KEYSLOTS; i++) {
        if (keyslot_open(mfs->bd, &mfs->sb, &slots[i], password, plen, dk, &uid) == 0) {
            found = (int)i; break;
        }
    }
    secure_zero(dk, sizeof(dk));
    secure_zero(slots, sizeof(slots));
    if (found < 0) return -1;
    if (uid_out) *uid_out = uid;
    if (idx_out) *idx_out = (uint32_t)found;
    return 0;
}
#endif

/* ---- the sealed user table (docs/LIMITATIONS.md 2.6) --------------------
 *
 * Sealed under HKDF(disk_key, "horus-users-v1") -- a key the volume already
 * protects, rather than a second secret to look after. That is the whole reason
 * the account hashes inside can stop being peppered per boot: encryption at rest
 * is doing the job the pepper was being asked to do, and unlike the pepper it
 * works on a machine with no TPM.
 *
 * Layout: [12-byte nonce][16-byte tag][4-byte length][ciphertext...] from
 * sb->users_start, over sb->users_blocks blocks.
 */
/* The whole table must fit ONE journal transaction, or the write cannot be
 * atomic and a crash tears it. Checked at compile time rather than discovered at
 * runtime: journal_commit does fail closed on overflow, but a save that can
 * never succeed is a worse thing to learn from a running machine. */
_Static_assert(1 + (MAX_USERS * sizeof(user_account_t) - (BLOCK_SIZE - 32)
                    + BLOCK_SIZE - 1) / BLOCK_SIZE <= JOURNAL_DATA_MAX,
               "the user table must fit in one journal transaction");

static int users_key(const struct mounted_fs *mfs, uint8_t *key64)
{
    const char *label = "horus-users-v1";
    uint8_t info[14]; size_t n = 0;
    for (const char *c = label; *c; c++) info[n++] = (uint8_t)*c;
    return rust_hkdf_sha256(mfs->disk_key, 32,
                            mfs->sb.volume_key_salt, sizeof(mfs->sb.volume_key_salt),
                            info, n, key64, 64);
}

int storage_users_save(const void *buf, uint32_t len)
{
    struct mounted_fs *mfs = &g_mounted_fs;
    if (!mfs->mounted || !mfs->unlocked) return -1;
    if (mfs->sb.users_start == 0 || len == 0)  return -1;
    if (32 + len > mfs->sb.users_blocks * BLOCK_SIZE) return -1;

    uint8_t key[64];
    if (users_key(mfs, key) != 0) return -2;

    static uint8_t ct[USERS_BLOCKS * BLOCK_SIZE];
    secure_zero(ct, sizeof(ct));
    my_memcpy(ct, buf, len);

    uint8_t nonce[12], tag[16];
    secure_random_bytes(nonce, sizeof(nonce));
    if (rust_aead_seal(key, key + 32, nonce,
                       mfs->sb.volume_key_salt, sizeof(mfs->sb.volume_key_salt),
                       ct, len, tag) != 0) {
        secure_zero(key, sizeof(key)); secure_zero(ct, sizeof(ct)); return -3;
    }
    secure_zero(key, sizeof(key));

    /* THROUGH THE JOURNAL, not around it.
     *
     * The first version of this function wrote all thirteen blocks with
     * bd->write_block -- the RAW path, which bypasses do_block_write and so
     * bypasses the write-ahead log entirely. A crash part-way left a new header
     * over partly-old ciphertext, the AEAD tag then failed, and the caller
     * treated that as "no table yet" and reseeded the compiled-in accounts. A
     * power cut during useradd silently rolled every account back to root/user.
     *
     * Staging them in one transaction makes the save atomic in the way the rest
     * of this filesystem already is: a crash leaves the table wholly before or
     * wholly after, and journal_recover redoes a committed-but-unapplied write.
     */
    uint8_t blk[BLOCK_SIZE];
    journal_begin();
    secure_zero(blk, sizeof(blk));
    my_memcpy(blk, nonce, 12);
    my_memcpy(blk + 12, tag, 16);
    blk[28] = (uint8_t)(len & 0xFF);        blk[29] = (uint8_t)((len >> 8) & 0xFF);
    blk[30] = (uint8_t)((len >> 16) & 0xFF); blk[31] = (uint8_t)((len >> 24) & 0xFF);
    uint32_t first = (BLOCK_SIZE - 32) < len ? (BLOCK_SIZE - 32) : len;
    my_memcpy(blk + 32, ct, first);
    if (do_block_write(mfs->sb.users_start, blk) != 0) {
        journal_abort(); secure_zero(ct, sizeof(ct)); return -4;
    }
    uint32_t done = first;
    for (uint32_t i = 1; i < mfs->sb.users_blocks && done < len; i++) {
        secure_zero(blk, sizeof(blk));
        uint32_t n = (len - done) < BLOCK_SIZE ? (len - done) : BLOCK_SIZE;
        my_memcpy(blk, ct + done, n);
        if (do_block_write(mfs->sb.users_start + i, blk) != 0) {
            journal_abort(); secure_zero(ct, sizeof(ct)); return -4;
        }
        done += n;
    }
    secure_zero(ct, sizeof(ct));
    return journal_commit() == 0 ? 0 : -5;
}

/* Returns 0 and fills `buf` when a sealed table is present and authentic;
 * negative when there is none, or when the tag does not verify. A tag failure
 * is NOT silently treated as "no accounts yet": that would let anyone who can
 * scribble on the region roll the machine back to its compiled-in defaults. */
int storage_users_load(void *buf, uint32_t len)
{
    struct mounted_fs *mfs = &g_mounted_fs;
    if (!mfs->mounted || !mfs->unlocked) return -1;
    if (mfs->sb.users_start == 0 || len == 0)  return -1;
    if (32 + len > mfs->sb.users_blocks * BLOCK_SIZE) return -1;

    uint8_t blk[BLOCK_SIZE];
    if (do_block_read(mfs->sb.users_start, blk) != 0) return -1;
    uint8_t nonce[12], tag[16];
    my_memcpy(nonce, blk, 12);
    my_memcpy(tag,   blk + 12, 16);
    uint32_t stored = (uint32_t)blk[28] | ((uint32_t)blk[29] << 8) |
                      ((uint32_t)blk[30] << 16) | ((uint32_t)blk[31] << 24);
    if (stored == 0 || stored != len) return -2;   /* none written yet */

    static uint8_t ct[USERS_BLOCKS * BLOCK_SIZE];
    secure_zero(ct, sizeof(ct));
    uint32_t first = (BLOCK_SIZE - 32) < len ? (BLOCK_SIZE - 32) : len;
    my_memcpy(ct, blk + 32, first);
    uint32_t done = first;
    for (uint32_t i = 1; i < mfs->sb.users_blocks && done < len; i++) {
        if (do_block_read(mfs->sb.users_start + i, blk) != 0) return -1;
        uint32_t n = (len - done) < BLOCK_SIZE ? (len - done) : BLOCK_SIZE;
        my_memcpy(ct + done, blk, n);
        done += n;
    }

    uint8_t key[64];
    if (users_key(mfs, key) != 0) return -2;
    int rc = rust_aead_open(key, key + 32, nonce,
                            mfs->sb.volume_key_salt, sizeof(mfs->sb.volume_key_salt),
                            ct, len, tag);
    secure_zero(key, sizeof(key));
    if (rc != 0) { secure_zero(ct, sizeof(ct)); return -3; }
    my_memcpy(buf, ct, len);
    secure_zero(ct, sizeof(ct));
    return 0;
}

#ifdef USERS_TAMPER_INJECT
/* Flip a byte of the sealed user table, as an attacker with disk access would.
 * Test-only; writes raw so the corruption is on the platter rather than staged. */
int storage_users_corrupt_for_test(void)
{
    struct mounted_fs *mfs = &g_mounted_fs;
    if (!mfs->mounted || mfs->sb.users_start == 0) return -1;
    uint8_t blk[BLOCK_SIZE];
    if (raw_block_read(mfs->sb.users_start, blk) != 0) return -1;
    blk[40] ^= 0xFF;                      /* inside the ciphertext, past the header */
    return raw_block_write(mfs->sb.users_start, blk);
}
#endif

/* Add a password that also opens this volume, and return its slot index.
 *
 * AUTHORITY: the volume must already be unlocked, which means the caller has
 * already presented a password that opens it. That is the whole gate, and it is
 * the right one -- disk_key is what a new slot wraps, so being able to add a
 * slot is exactly equivalent to already holding the key.
 *
 * The uid is sealed INSIDE the slot, so it is not discoverable from the disk.
 * The caller is expected to remember the returned index (the user table does),
 * because nothing else can find this slot again without its password.
 */
int storage_keyslot_add(const char *new_password, size_t nlen, uint32_t uid,
                        uint32_t *slot_out)
{
    struct mounted_fs *mfs = &g_mounted_fs;
    if (!mfs->mounted || !mfs->unlocked) return -1;
    if (!new_password || nlen == 0)      return -1;
    struct fs_superblock *sb = &mfs->sb;

    fs_keyslot_t slots[HORUS_KEYSLOTS];
    if (keyslots_read(mfs->bd, sb, slots) != 0) return -2;

    int free_idx = -1;
    for (uint32_t i = 0; i < HORUS_KEYSLOTS; i++)
        if (!slots[i].active) { free_idx = (int)i; break; }
    if (free_idx < 0) { secure_zero(slots, sizeof(slots)); return -3; }  /* full */

    if (keyslot_seal(mfs->bd, sb, &slots[free_idx], new_password, nlen,
                     mfs->disk_key, uid) != 0) {
        secure_zero(slots, sizeof(slots));
        return -4;
    }
    int rc = keyslots_write(mfs->bd, sb, slots);
    secure_zero(slots, sizeof(slots));
    if (rc != 0) return -5;
    if (slot_out) *slot_out = (uint32_t)free_idx;
    return 0;
}

/* Revoke one slot by index. The password it held stops opening this volume and
 * every other slot is untouched -- that is the property key slots exist for.
 *
 * BY INDEX, NOT BY UID, and that is forced rather than chosen: the uid lives
 * inside the AEAD, so finding "this user's slot" would need that user's
 * password. Whoever adds a slot records its index (the user table does); a slot
 * whose index is forgotten can only be cleared by wiping the region.
 *
 * REFUSES THE LAST ACTIVE SLOT. Removing it would leave a volume whose key
 * nothing on earth can unwrap -- the data is not deleted, it is beyond reach,
 * which is worse than a refusal because it looks like it worked. */
int storage_keyslot_remove(uint32_t idx)
{
    struct mounted_fs *mfs = &g_mounted_fs;
    if (!mfs->mounted || !mfs->unlocked) return -1;
    if (idx >= HORUS_KEYSLOTS)           return -1;
    struct fs_superblock *sb = &mfs->sb;

    fs_keyslot_t slots[HORUS_KEYSLOTS];
    if (keyslots_read(mfs->bd, sb, slots) != 0) return -2;
    if (!slots[idx].active) { secure_zero(slots, sizeof(slots)); return -3; }

    uint32_t active = 0;
    for (uint32_t i = 0; i < HORUS_KEYSLOTS; i++) if (slots[i].active) active++;
    if (active <= 1) { secure_zero(slots, sizeof(slots)); return -4; }

#ifdef KEYSLOT_REMOVE_NOOP
    /* CONTROL ARM -- never ship. Revocation that reports success and leaves the
     * slot openable. A revoked password still unlocks the volume, and nothing
     * says so: the count still drops if you only look at the flag, which is why
     * the witness probes the PASSWORD rather than counting slots. */
    (void)idx;
#else
    secure_zero(&slots[idx], sizeof(slots[idx]));   /* whole slot, not just the flag */
#endif
    int rc = keyslots_write(mfs->bd, sb, slots);
    secure_zero(slots, sizeof(slots));
    return rc == 0 ? 0 : -5;
}

/* How many slots can currently open this volume. Observability for the witness;
 * it reveals a count, never a uid. */
int storage_keyslot_count(void)
{
    struct mounted_fs *mfs = &g_mounted_fs;
    if (!mfs->mounted || !mfs->unlocked) return -1;
    fs_keyslot_t slots[HORUS_KEYSLOTS];
    if (keyslots_read(mfs->bd, &mfs->sb, slots) != 0) return -1;
    int n = 0;
    for (uint32_t i = 0; i < HORUS_KEYSLOTS; i++) if (slots[i].active) n++;
    secure_zero(slots, sizeof(slots));
    return n;
}

/* The uid sealed in the slot that opened this volume, and that slot's index.
 * Meaningful only after a successful storage_unlock. */
uint32_t storage_unlocked_uid(void)  { return g_unlocked_uid;  }
uint32_t storage_unlocked_slot(void) { return g_unlocked_slot; }

int storage_rekey(const char *new_password, size_t plen)
{
    struct mounted_fs *mfs = &g_mounted_fs;
    if (!mfs->mounted || !mfs->unlocked) return -1;
    struct fs_superblock *sb = &mfs->sb;

    /* v7: rekey the slot THIS boot opened, not "the" wrap -- there is no longer
     * a single one. Every other slot keeps working, which is the point of slots:
     * one user changing their password must not lock everybody else out. Before
     * key slots this function rewrote the volume's only wrap, so it could not
     * tell the two apart. */
    fs_keyslot_t slots[HORUS_KEYSLOTS];
    if (keyslots_read(mfs->bd, sb, slots) != 0) return -2;
    if (g_unlocked_slot >= HORUS_KEYSLOTS || !slots[g_unlocked_slot].active) {
        secure_zero(slots, sizeof(slots));
        return -2;
    }

    fs_keyslot_t fresh;
    secure_zero(&fresh, sizeof(fresh));
    if (keyslot_seal(mfs->bd, sb, &fresh, new_password, plen,
                     mfs->disk_key, g_unlocked_uid) != 0) {
        secure_zero(slots, sizeof(slots));
        secure_zero(&fresh, sizeof(fresh));
        return -3;
    }
    slots[g_unlocked_slot] = fresh;
    secure_zero(&fresh, sizeof(fresh));

    int rc = keyslots_write(mfs->bd, sb, slots);
    secure_zero(slots, sizeof(slots));
    return rc == 0 ? 0 : -4;
}

int derive_and_store_user_file_key(uint32_t uid, const char *material, size_t material_len)
{

    extern uint8_t kernel_pepper[16];

    if (get_current_task() < 0 || get_current_task() >= g_max_tasks) return -1;

    
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

    if (get_current_task() < 0 || get_current_task() >= g_max_tasks) return -1;
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

    /* (The legacy capfs fs_objects[] integrity-tag refresh was removed with the
     * capfs engine; only the encrypted object store above is rotated now.) */

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

/* A pointer block holds this many 64-bit block pointers. At BLOCK_SIZE=512 that
 * is 64 — NOT 1024. (An earlier single-indirect implementation used 1024 here,
 * which indexed a 512-byte stack buffer out of bounds for any file past block
 * 12+64; it was never hit because no test wrote a file that large.) */

/* One level of a pointer tree, allocating as it goes when asked.
 *
 * WHY A LOOP AND NOT A FOURTH COPY. The single- and double-indirect cases were
 * written out longhand, and the double case is the single one twice with the
 * names changed. A third copy for triple-indirect would be the same code a third
 * time, and the place a transcription slip lands is the level nothing exercises
 * until a file is a gigabyte long. `depth` is the number of pointer levels below
 * this block: 0 means its entries are data blocks.
 *
 * `*slot` is the inode field (or parent entry) naming this pointer block, read
 * and written in place, so a newly allocated block is linked by the caller that
 * asked for it rather than by a separate fix-up step. */
static uint64_t walk_ptr_tree(struct mounted_fs *mfs, uint64_t *slot,
                              unsigned depth, uint64_t index, int allocate)
{
    struct block_device *bd = mfs->bd;
    struct fs_superblock *sb = &mfs->sb;

    uint64_t ptr_blk = *slot;
    if (ptr_blk == 0) {
        if (!allocate) return 0;
        int64_t got = storage_alloc_block(bd, sb);
        if (got < 0) return 0;
        ptr_blk = (uint64_t)got;
        *slot = ptr_blk;
        uint8_t zero[BLOCK_SIZE];
        my_memset(zero, 0, BLOCK_SIZE);
        do_block_write(ptr_blk, zero);
    }

    /* One BLOCK_SIZE frame per level, and the recursion is bounded by
     * FSCK_MAX_DEPTH, so the deepest walk is three frames. The BSP kernel stack
     * is 16 KiB and #270 already overflowed it once, which is why the bound is a
     * named constant and not an assumption about how deep files get. */
    if (depth >= FSCK_MAX_DEPTH) return 0;
    uint8_t blk[BLOCK_SIZE];
    if (do_block_read(ptr_blk, blk) != 0) return 0;
    uint64_t *ptrs = (uint64_t *)blk;

    uint64_t span = 1;                          /* entries one slot covers */
    for (unsigned d = 0; d < depth; d++) span *= PTRS_PER_BLOCK;
    uint64_t slot_i = index / span;
    if (slot_i >= PTRS_PER_BLOCK) return 0;

    if (depth == 0) {
        uint64_t phys = ptrs[slot_i];
        if (phys == 0 && allocate) {
            int64_t got = storage_alloc_block(bd, sb);
            if (got < 0) return 0;
            phys = (uint64_t)got;
            ptrs[slot_i] = phys;
            do_block_write(ptr_blk, blk);
        }
        return phys;
    }

    uint64_t child = ptrs[slot_i];
    uint64_t before = child;
    uint64_t phys = walk_ptr_tree(mfs, &child, depth - 1, index % span, allocate);
    if (child != before) {                      /* the level below was allocated */
        ptrs[slot_i] = child;
        do_block_write(ptr_blk, blk);
    }
    return phys;
}

/* Fetch (and, when allocate!=0, lazily allocate) the physical block backing an
 * inode's logical block. Layout: 12 direct, then single-, double- and
 * triple-indirect trees of PTRS_PER_BLOCK fan-out each. Returns the physical
 * block number, or 0 on absent/unallocatable/out-of-range. Pointer blocks are
 * stored unencrypted -- they hold block numbers, not file data -- so they use
 * do_block_read/write directly. */
static uint64_t get_physical_block(struct mounted_fs *mfs, struct on_disk_inode *inode,
                                   uint64_t logical_block, int allocate) {
    if (logical_block < 12) {
        uint64_t phys = inode->direct[logical_block];
        if (phys == 0 && allocate) {
            int64_t got = storage_alloc_block(mfs->bd, &mfs->sb);
            if (got < 0) return 0;
            phys = (uint64_t)got;
            inode->direct[logical_block] = phys;
        }
        return phys;
    }
    logical_block -= 12;

    if (logical_block < PTRS_PER_BLOCK)
        return walk_ptr_tree(mfs, &inode->indirect, 0, logical_block, allocate);
    logical_block -= PTRS_PER_BLOCK;

    if (logical_block < PTRS_PER_BLOCK * PTRS_PER_BLOCK)
        return walk_ptr_tree(mfs, &inode->double_indirect, 1, logical_block, allocate);
    logical_block -= PTRS_PER_BLOCK * PTRS_PER_BLOCK;

    if (logical_block < PTRS_PER_BLOCK * PTRS_PER_BLOCK * PTRS_PER_BLOCK)
        return walk_ptr_tree(mfs, &inode->triple_indirect, 2, logical_block, allocate);

    /* Beyond triple-indirect: 12 + 512 + 512^2 + 512^3 blocks, half a terabyte at
     * a 4 KiB block. A hard ceiling, not a silent truncation -- and one no volume
     * this kernel can address will reach, so a file is bounded by the disk. */
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
    /* One atomic transaction: the data-block allocation (block bitmap), the inode
     * link, the per-block crypto metadata (+ the rollback tree above it), and the
     * ciphertext all commit together or not at all. A crash therefore leaves the
     * file either fully before or fully after this write — never with a dangling
     * block or a rollback root that no longer matches the metadata region. */
    journal_begin();

    struct on_disk_inode inode;
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { journal_abort(); return -1; }

    /* get_physical_block updates the inode's direct/indirect/double_indirect
     * mapping in place when it allocates, so just persist it. (The old explicit
     * inode.direct[block] fix-up here both duplicated that and indexed direct[]
     * out of bounds for block >= 12.) */
    uint64_t phys = get_physical_block(mfs, &inode, block, 1);
    if (phys == 0) { journal_abort(); return -1; }

    storage_write_inode(mfs->bd, &mfs->sb, ino, &inode);

    uint8_t temp[BLOCK_SIZE];
    my_memcpy(temp, buf, BLOCK_SIZE);

    if (storage_encrypt_block(phys, ino, block, temp) != 0) { journal_abort(); return -1; }
    if (do_block_write(phys, temp) != 0)                     { journal_abort(); return -1; }

    return journal_commit();
}

/* Free a pointer tree: every block it names, then the pointer blocks themselves,
 * deepest first. `depth` is the number of pointer levels below this block.
 *
 * Bounded by FSCK_MAX_DEPTH like the other tree walks, and for the same reason:
 * one BLOCK_SIZE frame per level against a 16 KiB kernel stack. */
static void free_ptr_tree(struct mounted_fs *mfs, uint64_t ptr_blk, unsigned depth)
{
    if (ptr_blk == 0 || depth >= FSCK_MAX_DEPTH) return;
    uint8_t blk[BLOCK_SIZE];
    if (do_block_read(ptr_blk, blk) == 0) {
        uint64_t *ptrs = (uint64_t *)blk;
        for (unsigned k = 0; k < PTRS_PER_BLOCK; k++) {
            if (!ptrs[k]) continue;
            if (depth == 0) storage_free_block(mfs->bd, &mfs->sb, ptrs[k]);
            else            free_ptr_tree(mfs, ptrs[k], depth - 1);
        }
    }
    storage_free_block(mfs->bd, &mfs->sb, ptr_blk);
}

/* Free every data block an inode references and release the inode.
 *
 * THE INODE IS KILLED FIRST, IN A TRANSACTION OF ITS OWN, and the ordering is
 * what makes the rest safe to do in pieces. Freeing a large file touches more
 * bitmap blocks than one journal transaction can hold -- at a 16 GiB volume the
 * data bitmap spans 128 blocks against JOURNAL_DATA_MAX of 16 -- so a single
 * atomic free is not merely expensive, it OVERFLOWS AND ABORTS, leaving the file
 * whole and the caller told it was deleted. The old comment reasoned that every
 * bitmap clear coalesces onto one sector, which was true of a volume with one
 * bitmap block and stopped being true when the data region grew.
 *
 * So: transaction 1 sets links = 0 and writes the inode. From that instant the
 * file is dead and storage_fsck_pass will finish the job after any crash -- it
 * already reclaims an inode with links == 0 and sweeps blocks no live inode
 * references. Then the blocks are freed in batches, each its own transaction,
 * and a final transaction clears the inode bitmap bit. A crash anywhere after
 * the first transaction leaves a dead inode and some already-freed blocks, which
 * is exactly the state fsck is written to repair.
 *
 * The other order -- free the blocks, then mark the inode dead -- is the one
 * that cannot be interrupted safely: a crash midway leaves blocks in the free
 * list that a LIVE inode still points at, and the next allocation hands one out
 * twice.
 *
 * The per-block crypto metadata of freed blocks is deliberately left untouched:
 * the block is deallocated, and storage_encrypt_block overwrites its metadata
 * with a fresh nonce when it is next allocated, so the stale entry is harmless.
 * Clearing it here would flush one metadata block (and the tree above it) per
 * freed block. */
int storage_free_inode_blocks(struct mounted_fs *mfs, uint64_t ino) {
    struct on_disk_inode inode;

    /* 1. Kill the inode, and say that a multi-transaction operation is in
     * flight, in the SAME transaction. A crash after this leaves needs_fsck set
     * and a dead inode, which is precisely the pair fsck repairs -- and setting
     * the flag separately would leave a window where the first is true and the
     * second is not. */
    journal_begin();
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { journal_abort(); return -1; }
    struct on_disk_inode dead = inode;
    dead.size = 0;
    dead.links = 0;
    if (storage_write_inode(mfs->bd, &mfs->sb, ino, &dead) != 0) { journal_abort(); return -1; }
    mfs->sb.needs_fsck = 1;
    do_block_write(0, &mfs->sb);
    if (journal_commit() != 0) return -1;

    /* 2. Release the blocks, a transaction at a time. Each batch is bounded by
     * how many distinct bitmap blocks it may touch, which is what the journal
     * actually limits -- so the batch size is expressed in bitmap blocks rather
     * than in data blocks, and a run of blocks sharing one bitmap block costs
     * one staged write however long it is. */
    journal_begin();
    for (int i = 0; i < 12; i++)
        if (inode.direct[i]) storage_free_block(mfs->bd, &mfs->sb, inode.direct[i]);
    if (journal_commit() != 0) return -1;

    for (unsigned lvl = 0; lvl < 3; lvl++) {
        uint64_t root = (lvl == 0) ? inode.indirect
                      : (lvl == 1) ? inode.double_indirect
                                   : inode.triple_indirect;
        if (!root) continue;
        journal_begin();
        free_ptr_tree(mfs, root, lvl);
        if (journal_commit() != 0) return -1;
    }

    /* 3. Clear the pointers and release the slot. */
    journal_begin();
    if (storage_read_inode(mfs->bd, &mfs->sb, ino, &inode) != 0) { journal_abort(); return -1; }
    for (int i = 0; i < 12; i++) inode.direct[i] = 0;
    inode.indirect = inode.double_indirect = inode.triple_indirect = 0;
    inode.size = 0;
    inode.links = 0;
    storage_write_inode(mfs->bd, &mfs->sb, ino, &inode);
    storage_free_inode(mfs->bd, &mfs->sb, ino);
    mfs->sb.needs_fsck = 0;          /* the operation completed; nothing dangling */
    do_block_write(0, &mfs->sb);
    return journal_commit();
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
