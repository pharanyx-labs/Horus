/* swap.c -- the sealed swap slot store (docs/design/swap.md, step 1).
 *
 * The swap partition is an array of 4 KiB slots. A page given to the store is
 * sealed with the kernel's AEAD under a key drawn at this boot and written to a
 * free slot; reading it back opens it, and refuses it unless it is exactly the
 * page last written there. What makes the refusal possible is that everything
 * the check needs stays in RAM: for each slot the 64-bit generation it was
 * written under and the 16-byte tag. The partition itself carries ciphertext and
 * nothing else, not even a header, so it cannot be told from noise without the
 * key, and the key is never written anywhere. Power-off destroys it.
 *
 *   - A block edited on the disk fails the tag.
 *   - A block copied from another slot fails it too: the slot index is in the
 *     nonce and in the authenticated data.
 *   - An older copy of the same slot written back fails it: its tag is not the
 *     one held in RAM, and its generation is not the one in the nonce.
 *
 * Nothing in this step takes a page from a task. It is the store the pager
 * (step 2) will use, and its own self-test (SWAP_SELFTEST) is how it is shown
 * to keep the three promises above before anything depends on them.
 *
 * Enabled from storage_unlock, on an installed boot only, with the partition
 * rust_gpt_find_swap found beside the unlocked volume (never over it). A live
 * boot opens no disk (S110) and an install boot is about to rewrite this one,
 * so neither gets here.
 *
 * LOCKING. swap_lock covers the slot table, the generation counter and the
 * bounce frame, and is held across the block I/O, whose driver takes its own
 * lock inside it (swap_lock -> ata_lock or sdhci_lock, .github/lock-order.yml).
 * Nothing here takes page_lock, and the pager will drop page_lock before it
 * calls in (docs/design/swap.md 3.5). */
#include "kernel.h"

int rust_aead_seal(const uint8_t *enc_key, const uint8_t *mac_key, const uint8_t *nonce,
                   const uint8_t *aad, size_t aad_len, uint8_t *buf, size_t len, uint8_t *tag_out);
int rust_aead_open(const uint8_t *enc_key, const uint8_t *mac_key, const uint8_t *nonce,
                   const uint8_t *aad, size_t aad_len, uint8_t *buf, size_t len, const uint8_t *tag);

_Static_assert(BLOCK_SIZE == PAGE_SIZE, "a swap slot is one block holding one page");

/* What RAM holds for one slot. gen 0 is a free slot: generations start at 1.
 * `refs` counts the page-table entries naming it: a fork shares a swapped-out
 * page between parent and child without reading it back (each gets its own
 * frame when it next touches the page), and the slot is free when the last
 * entry lets go. */
struct swap_slot {
    uint64_t gen;
    uint8_t  tag[16];
    uint32_t refs;
    uint32_t pad;
};
#define SLOTS_PER_FRAME  (PAGE_SIZE / sizeof(struct swap_slot))      /* 128 */
#define DIR_ENTRIES      (PAGE_SIZE / sizeof(uint32_t))              /* 1024 table frames a directory */
#define SWAP_DIRS        4u
/* The most slots used: 4 directories of 1024 table frames of 128 slots, 2 GiB
 * of swap. A bigger partition works; the rest of it is unused. */
#define SWAP_SLOTS_MAX   ((uint64_t)SWAP_DIRS * DIR_ENTRIES * SLOTS_PER_FRAME)

static spinlock_t swap_lock;
static int        g_swap_on;
static struct block_device *g_swap_dev;
static uint64_t   g_swap_base, g_swap_slots, g_swap_used, g_swap_hint;
static uint64_t   g_swap_gen;                 /* the last generation issued; never reused */
static uint8_t    g_swap_enc[32], g_swap_mac[32];
static uint32_t   g_swap_dir[SWAP_DIRS];      /* frames of uint32 table-frame addresses */
static uint8_t   *g_swap_bounce;              /* one pool frame: where a page is sealed and opened */

static struct swap_slot *slot_at(uint64_t i) {
    uint64_t frame_no = i / SLOTS_PER_FRAME;
    uint32_t *dir = (uint32_t *)PHYS_KVA(g_swap_dir[frame_no / DIR_ENTRIES]);
    struct swap_slot *t = (struct swap_slot *)PHYS_KVA(dir[frame_no % DIR_ENTRIES]);
    return &t[i % SLOTS_PER_FRAME];
}

/* The nonce is the slot and the generation; the authenticated data names both
 * again under a label, so a sealed swap page can never be taken for a sealed
 * volume block, whose keys differ anyway. */
static void seal_params(uint64_t slot, uint64_t gen, uint8_t nonce[12], uint8_t aad[24]) {
    for (int b = 0; b < 4; b++) nonce[b] = (uint8_t)(slot >> (8 * b));
    for (int b = 0; b < 8; b++) nonce[4 + b] = (uint8_t)(gen >> (8 * b));
    const char *label = "horuswap";
    for (int b = 0; b < 8; b++) aad[b] = (uint8_t)label[b];
    for (int b = 0; b < 8; b++) aad[8 + b]  = (uint8_t)(slot >> (8 * b));
    for (int b = 0; b < 8; b++) aad[16 + b] = (uint8_t)(gen >> (8 * b));
}

/* Seal `page` into `slot` under a fresh generation and write it. Caller holds
 * swap_lock. 0, or -1 when the write failed (the slot is then left as it was). */
static int seal_and_write(uint64_t slot, const void *page) {
    const uint8_t *src = (const uint8_t *)page;
    for (int i = 0; i < PAGE_SIZE; i++) g_swap_bounce[i] = src[i];
    uint64_t gen = ++g_swap_gen;
    uint8_t nonce[12], aad[24], tag[16];
    seal_params(slot, gen, nonce, aad);
#ifdef SWAP_SEAL_OFF
    /* CONTROL ARM, never ship: the page goes to the disk as it is. */
    for (int b = 0; b < 16; b++) tag[b] = 0;
#else
    if (rust_aead_seal(g_swap_enc, g_swap_mac, nonce, aad, sizeof(aad),
                       g_swap_bounce, PAGE_SIZE, tag) != 0) return -1;
#endif
    if (g_swap_dev->write_block(g_swap_dev, g_swap_base + slot, g_swap_bounce) != 0) return -1;
    struct swap_slot *s = slot_at(slot);
    s->gen = gen;
    for (int b = 0; b < 16; b++) s->tag[b] = tag[b];
    if (s->refs == 0) s->refs = 1;
    return 0;
}

static uint64_t g_swap_outs, g_swap_ins;

int swap_enabled(void) { return g_swap_on; }

/* Put a page in a free slot. 0 with *slot_out set; -1 when no slot is free or
 * the write failed, in which case nothing changed. */
int swap_put(const void *page, uint64_t *slot_out) {
    if (!g_swap_on) return -1;
    spin_lock(&swap_lock);
    uint64_t slot = g_swap_slots;
    for (uint64_t k = 0; k < g_swap_slots; k++) {
        uint64_t i = (g_swap_hint + k) % g_swap_slots;
        if (slot_at(i)->gen == 0) { slot = i; break; }
    }
    if (slot == g_swap_slots || seal_and_write(slot, page) != 0) {
        spin_unlock(&swap_lock);
        return -1;
    }
    g_swap_used++;
    g_swap_hint = slot + 1;
    uint64_t outs = ++g_swap_outs, ins = g_swap_ins;
    spin_unlock(&swap_lock);
    *slot_out = slot;
    /* Said at the first page out and every 4096th: enough for a reader of the
     * log (and smoke-swap) to know swap is working, without a line per page. */
    if (outs == 1 || (outs & 4095) == 0) {
        print("swap: ");
        print_decimal(outs);
        print(" pages out and ");
        print_decimal(ins);
        print(" back in so far\n");
    }
    return 0;
}

/* One more page-table entry names this slot (a fork). */
void swap_ref(uint64_t slot) {
    if (!g_swap_on) return;
    spin_lock(&swap_lock);
    if (slot < g_swap_slots && slot_at(slot)->gen != 0) slot_at(slot)->refs++;
    spin_unlock(&swap_lock);
}

/* Read a slot back into `page`. 0 when it is the page last put there; -1 when it
 * failed authentication (changed, moved or replayed), -2 when it could not be
 * read, -3 for a slot not in use. On any failure `page` is untouched and the
 * slot stays in use: what to do about it is the caller's decision. */
int swap_get(uint64_t slot, void *page) {
    if (!g_swap_on) return -3;
    spin_lock(&swap_lock);
    if (slot >= g_swap_slots || slot_at(slot)->gen == 0) { spin_unlock(&swap_lock); return -3; }
    if (g_swap_dev->read_block(g_swap_dev, g_swap_base + slot, g_swap_bounce) != 0) {
        spin_unlock(&swap_lock);
        return -2;
    }
    struct swap_slot *s = slot_at(slot);
    uint8_t nonce[12], aad[24];
    seal_params(slot, s->gen, nonce, aad);
    int rc = 0;
#ifndef SWAP_SEAL_OFF
    rc = rust_aead_open(g_swap_enc, g_swap_mac, nonce, aad, sizeof(aad),
                        g_swap_bounce, PAGE_SIZE, s->tag);
#endif
#ifdef SWAP_TAG_UNCHECKED
    /* CONTROL ARM, never ship: a block that fails its tag is taken anyway. */
    rc = 0;
#endif
    if (rc != 0) { spin_unlock(&swap_lock); return -1; }
    uint8_t *dst = (uint8_t *)page;
    for (int i = 0; i < PAGE_SIZE; i++) dst[i] = g_swap_bounce[i];
    g_swap_ins++;
    spin_unlock(&swap_lock);
    return 0;
}

/* One page-table entry lets go of a slot; the last one frees it. Nothing is
 * written: what is on the disk is ciphertext under a generation that RAM no
 * longer accepts. */
void swap_free(uint64_t slot) {
    if (!g_swap_on) return;
    spin_lock(&swap_lock);
    if (slot < g_swap_slots) {
        struct swap_slot *s = slot_at(slot);
        if (s->gen != 0 && s->refs > 1) {
            s->refs--;
        } else {
            if (s->gen != 0) g_swap_used--;
            s->gen = 0;
            s->refs = 0;
            for (int b = 0; b < 16; b++) s->tag[b] = 0;
        }
    }
    spin_unlock(&swap_lock);
}

#ifdef SWAP_SELFTEST
static void swap_selftest(void);
#endif

/* Turn swap on over `count` blocks of `dev` from `base`. Allocates the slot
 * table from the pool (24 bytes a slot) and draws the key. Any failure leaves
 * swap off and says so; a machine without swap is what there was before. */
void swap_enable(struct block_device *dev, uint64_t base, uint64_t count) {
    if (g_swap_on || !dev || count == 0) return;
    uint64_t slots = count < SWAP_SLOTS_MAX ? count : SWAP_SLOTS_MAX;
    uint64_t frames = (slots + SLOTS_PER_FRAME - 1) / SLOTS_PER_FRAME;
    uint64_t dirs = (frames + DIR_ENTRIES - 1) / DIR_ENTRIES;
    uint32_t bounce = alloc_user_physical_page();
    if (!bounce) goto no_memory;
    for (uint64_t d = 0; d < dirs; d++) {
        g_swap_dir[d] = alloc_user_physical_page();
        if (!g_swap_dir[d]) goto no_memory;
        uint32_t *dir = (uint32_t *)PHYS_KVA(g_swap_dir[d]);
        for (uint64_t e = 0; e < DIR_ENTRIES; e++) dir[e] = 0;
        for (uint64_t e = 0; e < DIR_ENTRIES && d * DIR_ENTRIES + e < frames; e++) {
            dir[e] = alloc_user_physical_page();
            if (!dir[e]) goto no_memory;
            uint8_t *t = (uint8_t *)PHYS_KVA(dir[e]);
            for (int i = 0; i < PAGE_SIZE; i++) t[i] = 0;    /* every slot free */
        }
    }
    g_swap_bounce = (uint8_t *)PHYS_KVA(bounce);
    secure_random_bytes(g_swap_enc, sizeof(g_swap_enc));
    secure_random_bytes(g_swap_mac, sizeof(g_swap_mac));
    g_swap_dev = dev;
    g_swap_base = base;
    g_swap_slots = slots;
    g_swap_used = g_swap_hint = g_swap_gen = 0;
    g_swap_on = 1;
    print("swap: ");
    print_decimal(slots / 256);
    print(" MiB in use of the swap partition, sealed under a key made at this boot\n");
#ifdef SWAP_SELFTEST
    swap_selftest();
#endif
    return;
no_memory:
    /* The frames already taken stay taken: a few pages, once, on a machine
     * that could not spare them, and freeing them would need a second walk
     * nothing else needs. Swap is simply off. */
    print("swap: no memory for the slot table; swap is off\n");
}

#ifdef SWAP_SELFTEST
/* SELFTEST, never ship (smoke-swap-store). Seal SWAP_TEST_PAGES pages carrying
 * a marker the host searches the partition for, read each back, and require a
 * changed block and a replayed block both to be refused. The marked pages are
 * left in their slots, so the host's scan of the disk image has them to find
 * if they were ever written in the clear. One line, one write. */
#define SWAP_TEST_PAGES 32u
static uint8_t g_st_page[PAGE_SIZE], g_st_back[PAGE_SIZE];

static void st_fill(uint32_t n) {
    const char *m = "HORUS-SWAP-PLAINTEXT-MARKER-";
    int k = 0;
    for (int i = 0; i < PAGE_SIZE; i++) {
        if (m[k] == 0) { g_st_page[i] = (uint8_t)('A' + (n % 26)); k = 0; continue; }
        g_st_page[i] = (uint8_t)m[k++];
    }
}

static void swap_selftest(void) {
    const char *why = 0;
    uint64_t slot = 0;
    for (uint32_t n = 0; n < SWAP_TEST_PAGES && !why; n++) {
        st_fill(n);
        if (swap_put(g_st_page, &slot) != 0) { why = "a page could not be put"; break; }
        if (swap_get(slot, g_st_back) != 0) { why = "a page did not read back"; break; }
        for (int i = 0; i < PAGE_SIZE; i++)
            if (g_st_back[i] != g_st_page[i]) { why = "a page read back changed"; break; }
    }
    /* A CHANGED BLOCK: one byte of a written slot inverted on the disk. */
    if (!why) {
        st_fill(99);
        if (swap_put(g_st_page, &slot) != 0) why = "the tamper page could not be put";
        else if (g_swap_dev->read_block(g_swap_dev, g_swap_base + slot, g_st_back) != 0) why = "the tamper slot could not be read";
        else {
            g_st_back[100] ^= 0x01;
            if (g_swap_dev->write_block(g_swap_dev, g_swap_base + slot, g_st_back) != 0) why = "the tamper slot could not be written";
            else if (swap_get(slot, g_st_back) != -1) why = "a changed block was accepted";
            swap_free(slot);
        }
    }
    /* A REPLAYED BLOCK: the slot's earlier ciphertext written back after a newer
     * page went into the same slot. */
    if (!why) {
        uint8_t *old = g_st_back;
        st_fill(98);
        if (swap_put(g_st_page, &slot) != 0) why = "the replay page could not be put";
        else if (g_swap_dev->read_block(g_swap_dev, g_swap_base + slot, old) != 0) why = "the replay slot could not be read";
        else {
            st_fill(97);
            spin_lock(&swap_lock);
            int w = seal_and_write(slot, g_st_page);
            spin_unlock(&swap_lock);
            if (w != 0) why = "the newer page could not be written";
            else if (g_swap_dev->write_block(g_swap_dev, g_swap_base + slot, old) != 0) why = "the old block could not be written back";
            else if (swap_get(slot, g_st_page) != -1) why = "a replayed block was accepted";
            swap_free(slot);
        }
    }
    char line[160];
    unsigned n = 0;
    const char *p = why ? "SWAP_SELFTEST: FAIL " : "SWAP_SELFTEST: OK 32 pages sealed and read back; a changed block and a replayed block were refused";
    while (*p && n < sizeof(line) - 2) line[n++] = *p++;
    if (why) while (*why && n < sizeof(line) - 2) line[n++] = *why++;
    line[n++] = '\n';
    line[n] = 0;
    print(line);
}
#endif
