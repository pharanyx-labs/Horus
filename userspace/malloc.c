/* userspace/malloc.c — first-fit coalescing allocator backed by sys_sbrk.
 *
 * Layout: every allocation is preceded by a 16-byte blk_t header.  All
 * blocks (free and in-use) are chained in physical address order so that
 * free() can coalesce with immediate neighbours in O(1).
 *
 * Alignment: all payload sizes are rounded up to 8 bytes so that the header
 * of the next block is always naturally aligned on 32-bit.
 *
 *   [ blk_t hdr ][ payload ... ][ blk_t hdr ][ payload ... ] ...
 *
 * The heap grows via sys_sbrk() in multiples of 4 KiB to amortise the
 * syscall overhead.  sbrk returns the OLD break, so a new block header is
 * placed at exactly the address returned by sbrk().
 */

#include "../include/malloc.h"
#include "../include/syscall.h"

typedef struct blk {
    uint32_t  size;   /* payload bytes (not including this header) */
    uint32_t  used;   /* 1 = allocated, 0 = free */
    struct blk *prev; /* previous block in address order; NULL if first */
    struct blk *next; /* next block in address order; NULL if last */
} blk_t;

#define BLK_HDR   ((uint32_t)sizeof(blk_t))  /* 16 bytes */
#define ALIGN8(n) (((uint32_t)(n) + 7u) & ~7u)
#define MIN_SPLIT (BLK_HDR + 8u)             /* minimum useful split remainder */
#define GROW_MIN  4096u                       /* sbrk granularity in bytes */

static blk_t *g_first = NULL;
static blk_t *g_last  = NULL;

/* Split block b so its payload is exactly `need` bytes and the remainder
 * becomes a new free block, but only if the remainder is large enough. */
static void maybe_split(blk_t *b, uint32_t need)
{
    if (b->size < need + MIN_SPLIT) return;
    blk_t *tail = (blk_t *)((char *)(b + 1) + need);
    tail->size = b->size - need - BLK_HDR;
    tail->used = 0;
    tail->prev = b;
    tail->next = b->next;
    if (tail->next) tail->next->prev = tail;
    else            g_last = tail;
    b->next = tail;
    b->size = need;
}

/* Extend the heap by at least `need` payload bytes.  Allocates in GROW_MIN
 * multiples.  Returns the new free block, or NULL on OOM. */
static blk_t *heap_grow(uint32_t need)
{
    uint32_t total = BLK_HDR + ALIGN8(need);
    if (total < GROW_MIN) total = GROW_MIN;
    /* Round up to GROW_MIN. */
    total = (total + GROW_MIN - 1u) & ~(GROW_MIN - 1u);

    blk_t *b = (blk_t *)sys_sbrk((intptr_t)total);
    if (b == (blk_t *)(intptr_t)-1) return NULL;

    b->size = total - BLK_HDR;
    b->used = 0;
    b->prev = g_last;
    b->next = NULL;
    if (g_last)  g_last->next = b;
    else         g_first = b;
    g_last = b;

    /* Coalesce with previous block if it is also free (can happen if a prior
     * sbrk call left a split remainder exactly at the old break). */
    if (b->prev && !b->prev->used) {
        blk_t *p = b->prev;
        p->size += BLK_HDR + b->size;
        p->next  = b->next;  /* NULL — b was g_last */
        g_last   = p;
        return p;
    }
    return b;
}

void *malloc(size_t n)
{
    if (n == 0) n = 1;
    uint32_t need = ALIGN8((uint32_t)n);

    /* First-fit scan over all blocks. */
    for (blk_t *b = g_first; b; b = b->next) {
        if (!b->used && b->size >= need) {
            maybe_split(b, need);
            b->used = 1;
            return b + 1;
        }
    }

    /* No fit found — grow the heap. */
    blk_t *b = heap_grow(need);
    if (!b) return NULL;
    maybe_split(b, need);
    b->used = 1;
    return b + 1;
}

void free(void *ptr)
{
    if (!ptr) return;
    blk_t *b = (blk_t *)ptr - 1;
    b->used = 0;

    /* Coalesce with next if free. */
    if (b->next && !b->next->used) {
        blk_t *n = b->next;
        b->size += BLK_HDR + n->size;
        b->next  = n->next;
        if (b->next) b->next->prev = b;
        else         g_last = b;
    }
    /* Coalesce with prev if free. */
    if (b->prev && !b->prev->used) {
        blk_t *p = b->prev;
        p->size += BLK_HDR + b->size;
        p->next  = b->next;
        if (p->next) p->next->prev = p;
        else         g_last = p;
    }
}

void *calloc(size_t nmemb, size_t size)
{
    size_t total = nmemb * size;
    void *ptr = malloc(total);
    if (!ptr) return NULL;
    char *p = (char *)ptr;
    for (size_t i = 0; i < total; i++) p[i] = 0;
    return ptr;
}

void *realloc(void *ptr, size_t new_size)
{
    if (!ptr)     return malloc(new_size);
    if (!new_size) { free(ptr); return NULL; }

    blk_t *b    = (blk_t *)ptr - 1;
    uint32_t need = ALIGN8((uint32_t)new_size);

    /* Already fits in this block. */
    if (b->size >= need) {
        maybe_split(b, need);
        return ptr;
    }

    /* Try to absorb the immediately following free block. */
    if (b->next && !b->next->used &&
        b->size + BLK_HDR + b->next->size >= need) {
        blk_t *n = b->next;
        b->size += BLK_HDR + n->size;
        b->next  = n->next;
        if (b->next) b->next->prev = b;
        else         g_last = b;
        maybe_split(b, need);
        return ptr;
    }

    /* Fall back to allocate-copy-free. */
    void *np = malloc(new_size);
    if (!np) return NULL;
    uint32_t copy_n = b->size < need ? b->size : need;
    char *s = (char *)ptr, *d = (char *)np;
    for (uint32_t i = 0; i < copy_n; i++) d[i] = s[i];
    free(ptr);
    return np;
}
