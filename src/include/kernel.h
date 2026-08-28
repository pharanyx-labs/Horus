#ifndef KERNEL_H
#define KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>


typedef uint64_t addr_t;
typedef uint64_t paddr_t;
typedef uint64_t vaddr_t;


#define BLOCK_SIZE              512
/* 32768 blocks x 512 B = 16 MiB volume (~14 MiB usable after metadata/journal/
 * inode-table/bitmap overhead). The DATA allocator uses a multi-block bitmap
 * (storage.c), so the data region is no longer capped at one bitmap block's 4096
 * bits; the inode allocator stays single-block (4096 inodes is ample for this
 * volume). Large enough to hold every ported coreutils binary in /bin at once
 * (~11 x ~450 KiB). The RAM vdisk's backing store moved out of .bss into a
 * physical-pool reservation (see VDISK_BYTES) so the volume can be this large
 * without blowing the __bss_end < USER_PHYS_BASE (16 MiB) ceiling; the per-block
 * crypto-meta array (g_block_meta) is ~1 MiB of .bss, and its rollback MAC is now
 * hierarchical so the per-write cost does not scale with the volume. */
#define BLOCKS_PER_DISK         32768
#define PAGE_SIZE               4096

/* ---- Kernel address translation --------------------------------------------
 *
 * KERNEL_VMA is the offset between a kernel symbol's link-time virtual address
 * and its physical address. The kernel is linked at KERNEL_VMA + 1 MiB but
 * loads at physical 1 MiB, so a kernel VA is NOT its physical address — a
 * `(uint64_t)&sym` handed to CR3 or written into a page-table entry would
 * install bits above 51 and take a reserved-bit fault.
 *
 * virt_to_phys/phys_to_virt are the conversion. MUST match KERNEL_VMA in
 * linker64.ld, which is the authority — the linker script explains why this
 * value and no other (-mcmodel=kernel).
 *
 * These are for KERNEL IMAGE addresses (symbols in .text/.data/.bss), which are
 * the ones the ± KERNEL_VMA relation holds for. They do NOT apply to the low
 * boot stage (.boot), which is linked VA == PA. To reach an arbitrary physical
 * page — a freshly allocated frame, a page table — use PHYS_KVA below. */
#include "kernel_vma.h"   /* KERNEL_VMA — shared with the boot assembly */
#define virt_to_phys(v)         ((uint64_t)(uintptr_t)(v) - (uint64_t)KERNEL_VMA)
#define phys_to_virt(p)         ((void *)(uintptr_t)((uint64_t)(p) + (uint64_t)KERNEL_VMA))

/* Higher-half alias of physical memory, valid in EVERY address space.
 *
 * multiboot.S builds pml4[511] -> high_pdpt -> high_pdpt[2] -> pd, and pd[k]
 * identity-maps k*2MiB with a supervisor huge page, so VA(511, 2, k, off)
 * reaches physical k*2MiB+off for the whole [0, 1 GiB) range.
 * create_user_pagedir copies pml4[256..511] into every task's PML4, so this
 * window resolves on a user CR3 too.
 *
 * This matters because the low identity map is NOT usable from a user CR3: a
 * task's page directory only covers [0, 16 MiB), while the user page pool
 * (USER_PHYS_BASE) starts AT 16 MiB. The demand pager runs on the faulting
 * task's CR3 and must read page tables and zero/copy freshly allocated frames —
 * all of which live in that pool. Reaching them through the low identity VA
 * faulted inside the fault handler, which then re-entered the page_lock it
 * already held with interrupts disabled and wedged the machine. Always use this
 * macro for physical access from the pager.
 *
 * Only covers [0, 1 GiB) — the extent of the boot `pd`. The user pool is capped
 * so its top stays inside this window (see PHYS_POOL_CEIL); every frame is
 * therefore reachable. A pool grown past 1 GiB would need this window extended
 * first. */
#define PHYS_KVA_BASE           0xFFFFFF8080000000ULL
#define PHYS_KVA(p)             ((void *)(PHYS_KVA_BASE + (uint64_t)(p)))

/* Physical page pool. It runs from USER_PHYS_BASE (16 MiB, above the kernel
 * image) upward. USER_PHYS_PAGES is the *array capacity* — the compile-time
 * ceiling on how many frames the pool metadata (free_page_stack, page_refcounts)
 * can track, and it fixes the .bss cost. The *actual* pool size is chosen at
 * boot from the multiboot2 E820 memory map (mb_detect_pool_pages ->
 * phys_set_pool_pages); on a diskless/unparsed boot it falls back to
 * USER_PHYS_DEFAULT_PAGES, the historical 64 MiB. The cap keeps the top below
 * PHYS_POOL_CEIL (1 GiB, the PHYS_KVA window) so every frame stays reachable. At
 * 131072 pages the metadata is ~768 KiB of .bss, comfortably under the ceiling
 * the linker ASSERT enforces (__bss_end <= USER_PHYS_BASE). */
#define USER_PHYS_BASE          0x01000000
#define USER_PHYS_PAGES         131072              /* array cap: 512 MiB pool */
#define USER_PHYS_DEFAULT_PAGES 16384               /* fallback: 64 MiB (pre-E820) */

/* Staged-program-image buffer. The loader stages a whole program file here
 * before validating and mapping it into a new address space. It used to be a
 * static .bss array (`loader_staging[MAX_PROGRAM_SIZE]`), which pinned the image
 * cap at ~1 MiB: .bss must end below USER_PHYS_BASE and only ~1.9 MiB of headroom
 * was left. Instead it is now a fixed region reserved at the *base of the
 * physical pool* — [USER_PHYS_BASE, USER_PHYS_BASE + LOADER_STAGING_BYTES) — that
 * init_user_page_allocator holds back from the free list and points
 * `loader_staging` at through the PHYS_KVA window. That decouples the image cap
 * from the .bss ceiling entirely: raising it just reserves a few more pool
 * frames (of the ~495 MiB E820 pool), costing no .bss. */
#define LOADER_STAGING_BYTES    (8u * 1024u * 1024u)          /* 8 MiB staged-image cap */
#define LOADER_STAGING_PAGES    (LOADER_STAGING_BYTES / PAGE_SIZE)
extern uint8_t *loader_staging;                               /* set at boot -> PHYS_KVA(USER_PHYS_BASE) */

/* The ephemeral RAM virtual disk's backing store. Sized to the whole volume
 * (BLOCKS_PER_DISK * BLOCK_SIZE), it used to be a static .bss array — fine at a
 * 2 MiB volume, but a larger volume would blow the `__bss_end < USER_PHYS_BASE`
 * (16 MiB) linker ASSERT. Like loader_staging it is now reserved in the physical
 * pool, right after the staging region, and reached through PHYS_KVA. Reserved
 * unconditionally (a fixed pool location is simplest); an ATA boot just never
 * touches it. Costs pool frames, not .bss. */
#define VDISK_BYTES             ((uint64_t)BLOCKS_PER_DISK * BLOCK_SIZE)
#define VDISK_PAGES             (VDISK_BYTES / PAGE_SIZE)
extern uint8_t *g_vdisk_backing;                             /* set at boot -> PHYS_KVA(USER_PHYS_BASE + LOADER_STAGING_BYTES) */

/* The untyped-memory arena: the RAM every retypable kernel object is carved out
 * of (roadmap 0.3, audit finding I-7). Reserved contiguously at the base of the
 * physical pool, right after the RAM vdisk, and reached through PHYS_KVA — the
 * same pattern loader_staging and g_vdisk_backing already use, and for the same
 * reason: kernel objects that live in `.bss` are bounded by the
 * `__bss_end <= USER_PHYS_BASE` (16 MiB) linker ASSERT, so every static object
 * table is a hard ceiling on system size that costs image budget whether or not
 * it is used. Pool RAM costs neither.
 *
 * 4 MiB holds 512 CNodes, or ~15000 endpoints, against the 512 KiB of `.bss` the
 * static cspace_pool alone used to cost. Sized generously because it is pool
 * frames out of a ~495 MiB E820 pool, not image bytes. */
#define UNTYPED_ARENA_BYTES     (4u * 1024u * 1024u)
#define UNTYPED_ARENA_PAGES     (UNTYPED_ARENA_BYTES / PAGE_SIZE)
extern uint8_t *g_untyped_arena;   /* set at boot -> PHYS_KVA(USER_PHYS_BASE + LOADER_STAGING_BYTES + VDISK_BYTES) */

/* Total pool frames held back at the base before the free list starts. */
#define POOL_RESERVE_PAGES      (LOADER_STAGING_PAGES + VDISK_PAGES + UNTYPED_ARENA_PAGES)

/* Boot modules. GRUB loads each `module2` line in grub.cfg into physical RAM and
 * describes it with a multiboot2 type-3 tag; mb_scan_boot_info() records them
 * here at boot. This is how program images reach the system WITHOUT being
 * incbin'd into kernel.elf: a module is ordinary RAM outside the image, so it
 * costs nothing against the 16 MiB budget the linker ASSERT enforces
 * (__bss_end <= USER_PHYS_BASE). init reads them over SYS_BOOT_MODULE and writes
 * them into the encrypted store; nothing executes a module in place.
 *
 * Module frames are held back from the physical pool's free list
 * (init_user_page_allocator), because GRUB places modules wherever it likes —
 * in practice just above the kernel image, i.e. inside the pool — and handing
 * one out as an anonymous user page would corrupt the image before init reads
 * it. Their extent also pushes the staged-image reserve upward. */
#define MAX_BOOT_MODULES        48
#define BOOT_MODULE_NAME_MAX    32
struct boot_module {
    uint64_t start;                        /* physical, inclusive */
    uint64_t end;                          /* physical, exclusive */
    char     name[BOOT_MODULE_NAME_MAX];   /* the module2 cmdline, truncated */
    uint8_t  verified;                     /* 1 iff it matched the embedded manifest */
};

/* One entry of the boot-module hash manifest embedded in the kernel image
 * (generated into src/kernel/boot_module_manifest.h by
 * tools/gen_module_manifest.sh at build time).
 *
 * A module arrives as an untrusted payload GRUB dropped in RAM, and the
 * fs_server writes it into the store as a ROOT-OWNED file — an executable under
 * /bin. Provenance alone is not integrity (audit A4), so at boot the kernel
 * hashes each module and requires an exact (path, size, SHA-256) match against
 * this table before exposing it over SYS_BOOT_MODULE_INFO/READ. No key is
 * involved by design: the manifest ships inside the reproducible kernel image,
 * so the image itself is the root of trust. */
struct boot_module_digest {
    const char *path;      /* destination path == the module2 cmdline */
    uint32_t    size;      /* exact payload byte count */
    uint8_t     sha256[32];
};

uint32_t boot_module_count(void);
const struct boot_module *boot_module_get(uint32_t index);
/* Hash every recorded module and mark it verified iff it matches the embedded
 * manifest. Call once at boot, after the multiboot tags are parsed and before
 * anything can read a module. Returns the number that failed (0 == all good). */
uint32_t boot_module_verify_all(void);
/* Highest physical address any module occupies, page-rounded (0 if none). */
uint64_t boot_module_top(void);

/* Identity-map the TPM TIS locality-0 MMIO page (0xFED40000) into a page directory
 * (NULL = kernel pml4) for the measured-boot driver and the storage KEK-sealing
 * path (src/kernel/tpm.c). Defined in paging.c. */
void ensure_tpm_tis_mapped(uint64_t *root_pml4);
#include "tpm.h"   /* measured boot (roadmap 2.2) — needs boot_module_digest above */

#ifdef TPM_KEK_SELFTEST
/* Drive the TPM-sealed KEK end-to-end over the vdisk (roadmap 2.2 stage 3). */
void storage_tpm_kek_selftest(void);
#endif

/* Floor keeps 16 MiB *usable* after the base reserves (staging + RAM vdisk), so
 * even a tiny E820 pool still boots with the historical headroom. */
#define PHYS_POOL_MIN_PAGES     (4096 + POOL_RESERVE_PAGES)   /* floor: 16 MiB usable + reserves */
#define PHYS_POOL_CEIL          0x40000000ULL       /* pool top must stay < 1 GiB (PHYS_KVA) */
#define CNODE_SIZE              256
#define MAX_TASKS               64
#define MAX_CAPS_PER_TASK       128
#define KERNEL_RESERVED_CAPS    4
#define MAX_REV_SETS            8

/* Number of lineage slots. Mirrors LINEAGE_SLOTS in rust/src/capability.rs,
 * which is the authoritative table; keep these two in sync. */
#define MAX_LINEAGES            4096
#define USER_VIRT_BASE          0x0000000000400000ULL
/* Loader ceiling: the exclusive top of the user half. A user segment must map
 * below this — the first address at or above it is the kernel half. This used
 * to be 0x800000 (8 MiB), a ceiling that WAS the ASLR window: an image had to
 * fit in [USER_AREA_BASE, USER_MAX_VADDR). The multi-level page-table walk lifts
 * that, so the loader's job here is only "is this a user address, not a kernel
 * one"; placement is decided by USER_IMAGE_ASLR_BASE + the entropy below. */
#define USER_MAX_VADDR          0x0000800000000000ULL
/* Fixed low base: the flat/non-PIE image fallback loads here (its addresses are
 * baked in), and it is the loader's floor — nothing maps below it. */
#define USER_AREA_BASE          0x400000ULL
/* PIE image-base ASLR window. The base is USER_IMAGE_ASLR_BASE + a random,
 * page-aligned offset in [0, ASLR_MAX_LOAD_RANDOM_PAGES) pages.
 *
 * It sits at 16 GiB, deliberately clear of the fixed low regions — the user
 * stack at ~8 MiB and the heap at USER_HEAP_BASE (16 MiB) — so the window can be
 * huge without colliding with them. That separation is why the image moved to
 * its own base rather than growing [USER_AREA_BASE, ...) in place: a wide window
 * anchored at 4 MiB would have swallowed the stack and heap. */
#define USER_IMAGE_ASLR_BASE    0x0000000400000000ULL
/* Fallback/initial kernel stack for the TSS RSP0/ESP0: the real boot stack,
 * which the boot code installs as the initial RSP/ESP and which is therefore
 * always mapped. Using the linker symbol instead of a magic high address keeps
 * the value valid (and mapped) on both 32- and 64-bit, and avoids truncating a
 * 64-bit address into the 32-bit legacy TSS esp0 field. The former value,
 * 0xFFFF8000FFFFF000, both overflowed uint32_t and pointed at unmapped memory,
 * so any path that fell back to it would have triple-faulted. */
extern uint8_t stack_top[];
#define KERNEL_TSS_STACK        ((uintptr_t)stack_top)
#define USER_ASPACE_PREMAP_PAGES 32
/* Upper bound on the image-window premap (staged_image_span_pages clamps to it).
 * 16 MiB is far above any real loaded span (MAX_PROGRAM_SIZE caps the file at
 * 1 MiB; only .bss extends memsz past that), and it bounds a crafted ELF header
 * claiming a huge p_memsz from asking the premap to allocate the whole pool. */
#define USER_IMAGE_MAX_PAGES     4096
#define KERNEL_STACK_SIZE 32768
#define MAX_USERS               32
/* USER_HEAP_HIGH_BASE=1 moves every heap above the 4 GiB line, which is what
 * makes finding [I-2] reachable instead of latent (roadmap 1.5). 8 GiB is chosen
 * deliberately: above 2^32, and below USER_IMAGE_ASLR_BASE (16 GiB) so it cannot
 * collide with the image window. It stays inside PML4[0], so no new top-level
 * paging work is needed -- the demand-fault walker allocates the PDPT, PD and PT
 * below it, exactly as it already does for the image at 16 GiB.
 *
 * Before the 1.5 fix this build cannot allocate at all: sbrk computed the new
 * break in 32 bits, so `heap_current + n` wrapped to a small value, failed the
 * `new_current < heap_start` test, and returned -1 for every request. That total
 * failure is the control arm -- see `make smoke-heap64`. */
#ifdef USER_HEAP_HIGH_BASE
#define USER_HEAP_BASE              0x0000000200000000ULL   /* 8 GiB */
#else
#define USER_HEAP_BASE              0x0000000001000000ULL   /* 16 MiB */
#endif
#define USER_MEM_MAX_COPY           (64*1024)
#define ASLR_HIGH_STACK_BASE        0x00007ff000000000ULL
#define USER_HIGH_STACK_WINDOW      (16*1024*1024ULL)
/* Image-base ASLR entropy: 2^30 page-aligned positions = 30 bits, up from the
 * 8.91 (log2 480) the single-page-table premap allowed. 2^30 pages is a 4 TiB
 * span above USER_IMAGE_ASLR_BASE, well inside the user half. The old value was
 * `512 - USER_ASPACE_PREMAP_PAGES` — the slots left in one 2 MiB PD entry — so
 * the entropy figure was a restatement of the page-table layout, not a choice.
 * It is a choice now. */
#define ASLR_MAX_LOAD_RANDOM_PAGES  (1ULL << 30)
#define ASLR_MAX_STACK_RANDOM_PAGES 4
#define ASLR_MAX_HEAP_GAP_PAGES     8
#define DEMO_TASK_STACK_TOP         0x00007fffe0000000ULL
#define AUDIT_LOG_SIZE          256
#define PASS_SALT_LEN           16
#define PASS_HASH_LEN           32
/* On-disk inodes are 240 bytes, so only 2 fit in a 512-byte block. (The old
 * `BLOCK_SIZE/128 = 4` overran the block buffer when writing inode 2 or 3.)
 * A _Static_assert next to the struct definition pins this to sizeof. */
#define INODES_PER_BLOCK        2
uint32_t rust_get_user_page_protection(uint32_t t, uint64_t v);
bool rust_user_page_is_noexec(uint64_t vaddr);
int rust_validate_fs_operation(uint32_t task_id, uint32_t op, uint32_t rights, const uint8_t *name, size_t nlen);
/* Endpoint index space.
 *
 * [0, REPLY_EP_BASE)                  service endpoints (well-known + general)
 * [REPLY_EP_BASE, REPLY_EP_BASE+MAX_TASKS)  one PRIVATE reply endpoint per task
 *
 * The per-task reply region exists because a blocking SYS_IPC_CALL parks the
 * caller on a reply endpoint's single `blocked_waiter` field. Clients used to
 * share one well-known reply endpoint (FS_EP_REP), so two concurrent callers
 * overwrote each other's waiter; correctness survived only because
 * SYS_IPC_REPLY_TO routes by kernel-recorded sender identity and never consulted
 * that field. Giving every task its own reply endpoint removes the collision
 * structurally, and — with capability addressing (finding C-1) — means a task can
 * only ever block on, and be woken through, an endpoint no other task holds a
 * capability for. reply_ep_for_task() is the single mapping. */
#define MAX_ENDPOINTS   128
#define REPLY_EP_BASE   64
#define IPC_MSG_MAX     256

/* Retyped endpoints live in their own index range ABOVE the static table, so an
 * object index unambiguously says which storage it names and the migration can
 * proceed one object type at a time (roadmap 0.3). endpoint_by_index() is the
 * single resolver; nothing indexes endpoints[] directly any more.
 *
 * The dynamic range is not a second fixed table — the ceiling below only bounds
 * the descriptor array, and the OBJECTS are carved from untyped memory a task
 * must hold a CAP_UNTYPED for. That is the whole point of I-7: a task's kernel
 * memory is attributable to authority it holds, not to a global array everyone
 * shares. */
#define MAX_DYN_ENDPOINTS      256
#define DYN_EP_BASE            MAX_ENDPOINTS
#define EP_INDEX_MAX           (DYN_EP_BASE + MAX_DYN_ENDPOINTS)

/* The private reply endpoint belonging to task `tid`, or -1 if out of range. */
static inline int reply_ep_for_task(int tid) {
    return (tid > 0 && tid < MAX_TASKS) ? (REPLY_EP_BASE + tid) : -1;
}

/* Well-known service endpoint / notification objects. These MUST match the
 * userspace protocol headers (include/fs_proto.h, include/console_proto.h) —
 * they name the same kernel objects from the other side of the syscall boundary.
 *
 * NB: these are OBJECT indices, not cspace slots. Since finding C-1 they are no
 * longer reachable by naming them in a syscall: a task must hold a CAP_ENDPOINT
 * (or CAP_NOTIFICATION) whose `object` is one of these. They are declared here
 * only so the kernel can mint the primordial roots. */
#define FS_EP_REQ       4    /* filesystem service request endpoint  */
#define CON_EP_REQ      6    /* console service request endpoint     */
#define NOTIF_FS_READY  0    /* init <-> fs_server provisioning rendezvous */

/* ---- Canonical capability slot map ----------------------------------------
 *
 * The slots the kernel installs directly, and the slots init delegates into. A
 * single authority for both sides; userspace mirrors these in include/syscall.h
 * as CAPSLOT_*. Everything not listed is free for a task's own use.
 *
 * Slots 0-3 are kernel-reserved (mint/transfer refuse to write them). */
#define CAPSLOT_TCB         0    /* CAP_TCB on self                            */
#define CAPSLOT_FRAME       3    /* CAP_FRAME for the task's image window      */
#define CAPSLOT_REPLY_EP    4    /* CAP_ENDPOINT: this task's PRIVATE reply ep */
#define CAPSLOT_CONSOLE_EP  5    /* CAP_ENDPOINT: console service              */
#define CAPSLOT_USER        6    /* CAP_USER admin                             */
#define CAPSLOT_AUDIT       7    /* CAP_AUDIT / object-store (server-specific)  */
#define CAPSLOT_CONSOLE     8    /* CAP_CONSOLE                                */
#define CAPSLOT_STORAGE     9    /* CAP_ENCRYPTED_STORAGE                      */
#define CAPSLOT_IO_DEVICE  10    /* CAP_IO_DEVICE: the task's primary device    */
#define CAPSLOT_IO_DEVICE_ALT 22 /* CAP_IO_DEVICE: a SECOND device, for a task
                                  * that legitimately drives two (devcaptest).
                                  * The slot is a convention, not authority --
                                  * the capability in it is                    */
#define CAPSLOT_NOTIFY     11    /* CAP_NOTIFICATION: fs-ready rendezvous      */
#define CAPSLOT_FS_LISTEN  12    /* CAP_ENDPOINT: fs service listen (server)   */
#define CAPSLOT_KERNEL_LOG 16    /* CAP_KERNEL_LOG   (dmesg; shell)            */
#define CAPSLOT_BOOT_MODULE 17   /* CAP_BOOT_MODULE  (provisioning; fs_server) */
#define CAPSLOT_DEBUG      19   /* CAP_DEBUG        (observation; shell/capview) */
#define CAPSLOT_UNTYPED    18    /* CAP_UNTYPED: kernel-object memory (init)   */
#define CAPSLOT_REPLY      21    /* CAP_REPLY: one-shot right to answer the
                                 * request just received (minted by RECV,
                                 * consumed by REPLY_TO). Server-side only. */

/* Task states. */
#define TASK_DEAD          0
#define TASK_RUNNABLE      1
#define TASK_BLOCKED_IPC   2   /* blocked inside SYS_IPC_CALL waiting for a reply */
#define TASK_BLOCKED_NOTIF 3   /* blocked inside SYS_WAIT_NOTIFY waiting for a badge */
#define TASK_BLOCKED_WAIT  4   /* blocked inside SYS_WAIT until the target task exits */

/* ---- Why a task died (finding G-8) ----------------------------------------
 *
 * A task used to disappear without recording a reason anywhere a supervisor
 * could reach. `SYS_WAIT` returns 0 for every death alike, so `init` could say
 * only "shell exited, relaunching" — which is why a crashed shell and a hung
 * one look identical in a serial capture, and why G-8 signature A spent two
 * days being read as a livelock.
 *
 * The kernel did have *something* to say on one of the paths: the generic
 * ring-3 trap handler prints `[task N '<name>' killed: ...]`. But `print()`
 * only records to the klog once a ring-3 console server owns the console
 * (terminal.c) — so during a live session that line never reaches the wire.
 * The ring-3 #PF kill path does not print at all: its banner is gated on a
 * ring-0 / task-0 fault. A shell killed by a page fault mid-`write` is
 * therefore completely silent, which is exactly the observed signature.
 *
 * So the cause is recorded here, structurally, and handed to the supervisor
 * in band via SYS_TASK_EXIT_INFO — where it can be printed through
 * console_server like any other output, with no second writer on the UART. */
#define TASK_EXIT_NONE      0   /* no death recorded (nothing has been waited on) */
#define TASK_EXIT_NORMAL    1   /* SYS_EXIT: the task ended itself                */
#define TASK_EXIT_KILLED    2   /* SYS_KILL by another task; detail = killer tid  */
#define TASK_EXIT_SIGNAL    3   /* uncaught signal, default action; detail = signum*/
#define TASK_EXIT_FAULT     4   /* ring-3 trap, no handler; detail = trap vector  */
#define TASK_EXIT_PAGEFAULT 5   /* #PF killed the task; detail = 14, addr = CR2   */

/* The cause a teardown site reports. Every task_teardown() call site must state
 * one: a task can no longer die without saying why. */
struct task_exit_cause {
    uint32_t reason;    /* TASK_EXIT_*                                   */
    uint32_t detail;    /* vector / signum / killer tid, per reason      */
    uint32_t err;       /* #PF error code; 0 otherwise                   */
    uint64_t rip;       /* faulting RIP; 0 when not a fault              */
    uint64_t addr;      /* faulting address (#PF only); 0 otherwise      */
};

/* What SYS_TASK_EXIT_INFO hands to a supervisor. Mirrors struct task_exit_info
 * in include/syscall.h — keep the two in step. */
struct task_exit_info {
    int32_t  tid;       /* the task that died                            */
    int32_t  reason;    /* TASK_EXIT_*                                   */
    uint32_t detail;
    uint32_t err;
    uint64_t rip;
    uint64_t addr;
    char     name[32];  /* the dead task's name, captured before reuse   */
};

/* ---- Endpoints: a bounded FIFO, not a single mailbox slot (roadmap 1.3, [I-5])
 *
 * An endpoint used to hold exactly ONE in-flight message. Every additional
 * sender got -2 ("try again") and polled from ring 3, so N clients on one server
 * spent their slices colliding rather than working: contention was a busy-wait,
 * and fair service could not be expressed at all — the queue that would order
 * requests did not exist, so "who goes next" was decided by whoever the scheduler
 * happened to run.
 *
 * Now each endpoint owns a bounded ring of EP_QUEUE_SLOTS messages. A sender only
 * sees -2 when the queue is genuinely FULL, which under normal service it is not,
 * so the common contention case stops being a retry loop and becomes an enqueue.
 * Bounded is the point: the depth is fixed at compile time, so a sender cannot
 * make the kernel allocate, and a server that stops receiving cannot be used to
 * grow kernel memory without limit. Back-pressure at the bound is still -2.
 *
 * Each slot carries its OWN sender id. That is not bookkeeping convenience: the
 * reply path authorises by kernel-recorded sender identity, so a queued message
 * has to remember who sent it rather than sharing one field that the next sender
 * would overwrite. `last_sender` remains the identity of the most recently
 * DEQUEUED message — what SYS_IPC_SENDER and SYS_IPC_REPLY_TO answer about. */
/* Overridable so the depth can be A/B'd against the behaviour it replaced:
 * EP_QUEUE_SLOTS=1 degenerates the ring to exactly the old single-slot mailbox,
 * which is what the queue's benefit is measured against. A knob that can restore
 * the previous design is also the cheapest falsification of the claim that the
 * new one is an improvement. */
#ifndef EP_QUEUE_SLOTS
#define EP_QUEUE_SLOTS  4
#endif

struct ep_msg {
    int32_t  len;                  /* payload length in bytes */
    int32_t  sender;               /* task that deposited it (kernel-recorded) */
    uint8_t  data[IPC_MSG_MAX];
};

struct endpoint {
    struct ep_msg q[EP_QUEUE_SLOTS];
    uint32_t head;             /* index of the next message to dequeue */
    uint32_t count;            /* messages currently queued (0..EP_QUEUE_SLOTS) */
    int      last_sender;      /* sender of the most recently dequeued message */
    int      blocked_waiter;   /* task id blocked in SYS_IPC_CALL on this endpoint, -1=none */
};
extern struct endpoint endpoints[MAX_ENDPOINTS];

/* Resolve an endpoint object index to its storage: the static compat table below
 * DYN_EP_BASE, an untyped-backed retyped object above it. NULL if the index is
 * out of range or names a dynamic slot that holds no live object — callers must
 * check, because a retyped endpoint can be destroyed while an index derived from
 * a stale capability still names it. */
struct endpoint *endpoint_by_index(uint32_t idx);

/* ---- Pipes (shell pipelines) ---------------------------------------------
 * A bounded, in-kernel byte pipe. Ends are capabilities (CAP_PIPE, direction in
 * the rights bit). Back-pressure is by SYS_ERR_AGAIN + a userspace yield-retry
 * (posix.c), NOT by kernel blocking — this deliberately keeps pipes clear of the
 * delicate SMP block/wake machinery. A bounded ring + fixed pool means no
 * unbounded kernel memory. reader_ends / writer_ends count the live end caps of
 * each direction across all cspaces (incremented on create/grant, decremented on
 * SYS_PIPE_CLOSE and task_teardown); a reader sees EOF when writer_ends hits 0,
 * a writer sees SYS_ERR_PIPE when reader_ends hits 0. */
#define MAX_PIPES        32
#define PIPE_BUF_BYTES   4096
struct pipe {
    int      in_use;
    uint32_t head;                 /* next byte to read  */
    uint32_t count;                /* bytes currently buffered */
    uint32_t reader_ends;          /* live read-end caps  */
    uint32_t writer_ends;          /* live write-end caps */
    uint8_t  buf[PIPE_BUF_BYTES];
};
extern struct pipe pipes[MAX_PIPES];

/* Pool lifecycle + byte movement. Return values are byte counts (>=0) or a
 * negative SYS_ERR_*. read: 0 == EOF (all writers closed); SYS_ERR_AGAIN == empty
 * but writers remain. write: SYS_ERR_AGAIN == full but a reader remains;
 * SYS_ERR_PIPE == no reader left. */
int  pipe_alloc(void);                                   /* -> pipe index, or -1 */
void pipe_end_ref(int idx, int is_writer);               /* +1 that direction     */
void pipe_end_unref(int idx, int is_writer);             /* -1; frees at 0/0      */
int  pipe_read(int idx, uint8_t *dst, uint32_t len);
int  pipe_write(int idx, const uint8_t *src, uint32_t len);
/* Close every CAP_PIPE end in a dying task's cspace (task_teardown). */
void pipe_close_task_ends(int task_id);
#ifdef PIPE_SELFTEST
void pipe_selftest(void);   /* in-kernel pipe mechanics exercise (smoke-pipe) */
#endif

#define MAX_NOTIFICATIONS 64
struct notification {
    uint32_t pending_badge;    /* accumulated badge bits not yet consumed */
    int      blocked_waiter;   /* task id blocked in SYS_WAIT_NOTIFY here, -1=none */
};
extern struct notification notifications[MAX_NOTIFICATIONS];

/* Retyped notifications, same split as endpoints above. */
#define MAX_DYN_NOTIFICATIONS  256
#define DYN_NOTIF_BASE         MAX_NOTIFICATIONS
#define NOTIF_INDEX_MAX        (DYN_NOTIF_BASE + MAX_DYN_NOTIFICATIONS)
struct notification *notification_by_index(uint32_t idx);

/* ---- Untyped memory and retyping (roadmap 0.3, audit finding I-7) ----------
 *
 * Every kernel object used to be an entry in a fixed `.bss` array — tasks[64],
 * endpoints[128], notifications[64], cspace_pool[64][256]. That has three
 * consequences, and none of them is about size:
 *
 *   1. There is no retyping discipline. An object's storage is decided at
 *      compile time, so "who may create a kernel object" is not a question the
 *      capability graph can answer.
 *   2. There is no per-task kernel-memory accounting. A task that allocates
 *      endpoints consumes a system-wide resource no capability names, so
 *      kernel-memory exhaustion is neither attributable nor preventable.
 *   3. The ceiling is global and unmovable. Raising any table costs `.bss`
 *      against a 16 MiB linker ASSERT that the whole image shares.
 *
 * Following seL4: a CAP_UNTYPED capability names a physical region, and
 * SYS_RETYPE carves typed objects out of it. A task can only create kernel
 * objects in memory it holds untyped authority over, and the object's lifetime
 * is governed by the capabilities naming it, not by a slot index being free.
 *
 * Allocation within an untyped region is a BUMP POINTER, exactly as in seL4:
 * destroying an object does not return its bytes. Reclaiming a region means
 * revoking the untyped capability itself, which destroys every object derived
 * from it and resets the watermark. That is what makes reclamation safe without
 * a free list: there is no moment at which a live object shares bytes with a
 * fresh one, so a stale capability can never be resolved onto a reallocated
 * object of a different type.
 */
#define CAP_UNTYPED             16

/* Retypable object classes. Values are ABI: they are the `type` argument of
 * SYS_RETYPE and are mirrored in include/syscall.h. */
#define KOBJ_CNODE              1    /* CNODE_SIZE capability slots (a cspace)  */
#define KOBJ_ENDPOINT           2    /* struct endpoint                          */
#define KOBJ_NOTIFICATION       3    /* struct notification                      */
#define KOBJ_FRAME              4    /* one PAGE_SIZE frame, mappable into ring 3 */
#define KOBJ_TYPE_MAX           4

/* ---- Frame objects (roadmap 2.1, audit finding F-2.1) ---------------------
 *
 * A frame is one PAGE_SIZE-aligned page carved out of an untyped region, named
 * by a CAP_FRAME, and mapped into a task's address space by SYS_MAP_FRAME. It
 * is what makes shared memory between mutually distrusting tasks expressible:
 * both hold a capability for the same frame index, and the rights each holds
 * decide what its own PTE is allowed to say.
 *
 * WHY THE OBJECT IS AN INDEX AND NOT A PHYSICAL ADDRESS. It would be shorter to
 * put the frame's physical address straight in capability_t.object and map it.
 * That is exactly the shape of the C-1 defect, and it would have been reachable
 * on day one: EVERY task is born holding a CAP_FRAME in slot 3 whose object is
 * USER_AREA_BASE (see create_task), a legacy cap that names a virtual window
 * and authorises nothing. Under an address-valued object, passing slot 3 to
 * SYS_MAP_FRAME would ask the kernel to map physical 0x400000 -- low memory,
 * below the pool -- into ring 3, and the only thing standing between that and a
 * kernel-memory disclosure would be an allowlist somebody remembered to write.
 *
 * An index instead makes the refusal a BOUND, checked against a table the
 * kernel populates: 0x400000 is four orders of magnitude past FRAME_INDEX_MAX,
 * so the legacy cap is refused by arithmetic rather than by an allowlist. The
 * base is 1 rather than 0 for the same reason a fresh endpoint does not claim
 * task 0 as its sender: a zeroed capability must not resolve to a real object.
 *
 * frametest checks that refusal on every boot, and FRAME_INDEX_UNCHECKED=1
 * removes the bound so the legacy cap resolves -- which is what makes the check
 * a test rather than an assertion. */
#define MAX_DYN_FRAMES         256
#define DYN_FRAME_BASE         1
#define FRAME_INDEX_MAX        (DYN_FRAME_BASE + MAX_DYN_FRAMES)

/* A frame names a RUN of contiguous pages, not a single page (roadmap 2.1's
 * "region object wants a length"). One capability, one length, one contiguous
 * physical extent -- which is what a shared buffer, and later a DMA target,
 * actually needs. `pages == 1` is the ordinary case and is what every retype
 * that does not ask for a length gets.
 *
 * The ceiling is deliberately modest. UNTYPED_ARENA_BYTES is 4 MiB TOTAL, shared
 * with every cspace, endpoint and notification in the system, so a frame that
 * could span the arena would be a denial-of-service against every other object
 * class dressed up as a feature. 64 pages is 256 KiB. The untyped region a task
 * holds is still the security bound on how much it can carve; this is the bound
 * on how much ONE object may be, which is a different question and the one the
 * bump allocator cares about. */
#define MAX_FRAME_PAGES        64

/* The arena page backing frame index `idx`, or NULL if `idx` names no live
 * frame. The single resolver: nothing indexes the frame table directly. */
void *frame_by_index(uint32_t idx);

/* Physical address of the page `frame_by_index` returned, for the map path.
 * Returns 0 for a dead or out-of-range index -- and 0 is not a frame, so a
 * caller that forgets to check still fails closed. */
uint64_t frame_phys_by_index(uint32_t idx);

/* How many contiguous pages frame `idx` spans, or 0 for a dead or out-of-range
 * index. Every caller that walks a frame's pages asks THIS rather than assuming
 * 1 -- a map path that mapped `frame_phys_by_index(i)` and stopped would hand a
 * caller one page of a buffer it believes is whole. */
uint32_t frame_pages_by_index(uint32_t idx);

/* Whether `phys` is a page of the untyped arena -- the memory every kernel object
 * is carved from. The arena lives inside the user page pool and so shares
 * page_refcounts[] with anonymous pages, which is exactly why the generic page
 * machinery has to be able to ask. */
int phys_in_untyped_arena(uint64_t phys);

/* How many untyped regions the kernel can describe. Small by design: this bounds
 * the DESCRIPTORS, not the memory they govern — one descriptor can name an
 * arbitrarily large region. Index 0 is the kernel's own bootstrap region and no
 * capability is ever minted for it. */
#define MAX_UNTYPED             8
#define UNTYPED_KERNEL          0    /* kernel bootstrap: per-task cspaces. Unreachable from ring 3. */
#define UNTYPED_ROOT            1    /* the user-facing region; init holds the primordial cap */

struct untyped {
    uint64_t base;        /* arena offset of the region, bytes                  */
    uint64_t size;        /* extent of the region, bytes                        */
    uint64_t watermark;   /* bytes handed out; never decreases except on reset  */
    uint32_t objects;     /* live objects carved from this region               */
    int      in_use;
};
extern struct untyped untypeds[MAX_UNTYPED];

/* The SYS_UNTYPED_INFO payload. MUST stay byte-identical to the copy in
 * include/syscall.h — the kernel fills this layout and ring-3 reads it across
 * copy_to_user, exactly like struct task_info. */
struct untyped_info {
    uint64_t size;        /* total bytes in the region      */
    uint64_t watermark;   /* bytes consumed                 */
    uint64_t free;        /* size - watermark               */
    uint32_t objects;     /* live objects carved from it    */
    uint32_t reserved;    /* pad to an 8-byte multiple      */
};

/* Carve up the arena and publish the two boot regions. Called from kernel_main
 * after paging_init (which sets g_untyped_arena) and before scheduler_init
 * (which needs UNTYPED_KERNEL to allocate task 0's cspace). */
void untyped_init(void);

/* Allocate one KOBJ_* object from untyped region `u`, returning a pointer into
 * the arena (zeroed) or NULL if the region cannot satisfy it. `out_index` gets
 * the object index a capability will name (a dynamic endpoint/notification
 * index; unused for KOBJ_CNODE). Kernel-internal: the syscall path goes through
 * untyped_retype(), which additionally enforces the capability. */
void *kobj_alloc(uint32_t untyped_index, uint32_t kobj_type, uint32_t pages,
                 uint32_t *out_index);

/* The SYS_RETYPE body: carve `count` objects of `kobj_type` out of the untyped
 * region named by `untyped_slot` in the CALLER's cspace, installing a capability
 * for each into dest_slot..dest_slot+count-1. Returns the number created, or a
 * negative SYS_ERR_*. Authority is the CAP_UNTYPED in `untyped_slot` — the slot
 * argument IS the gate, as for the IPC syscalls (finding C-1). */
int untyped_retype(uint32_t untyped_slot, uint32_t kobj_type, uint32_t count,
                   uint32_t pages, uint32_t dest_slot);

/* Fill *out for the untyped region named by `untyped_slot` in the caller's
 * cspace. Returns 0, or a negative SYS_ERR_*. */
int untyped_info(uint32_t untyped_slot, struct untyped_info *out);

/* Mark-and-sweep the capability graph and destroy every retyped endpoint /
 * notification no live capability names any more. This is what makes object
 * lifetimes capability-governed rather than index-governed. Called after any
 * operation that can drop the last capability to an object: cap_revoke and
 * task_teardown. Cheap enough to run unconditionally — a revoke already sweeps
 * every cspace in the system.
 *
 * Deliberately a sweep and not a refcount: a refcount has to be incremented on
 * every mint/transfer/grant and decremented on every revoke/null across both the
 * C and Rust halves of the capability implementation, and a single missed site is
 * either a leak or a use-after-free. Reachability is computed from the same graph
 * the security argument is stated over, so it cannot disagree with it. */
void kobj_gc(void);

/* Live retyped-object counts, for the self-test to assert destruction actually
 * happened rather than assuming it. */
uint32_t kobj_live_count(uint32_t kobj_type);

/* The untyped tables are locked unconditionally, from the first allocation of
 * the boot onwards. They were not until 2026-08-18: locking was armed at the end
 * of scheduler_init, because a boot-window lock would have tripped the
 * unconditional `sti` spin_unlock used to end with (finding C-3.1, closed by
 * roadmap 1.1 on 2026-08-11). See the locking note at the top of
 * src/kernel/untyped.c before reintroducing any such window. */

/* Canonical task_info ABI. MUST stay byte-identical to the copy in
 * include/syscall.h — the kernel fills this
 * layout and ring-3 reads it across copy_to_user (SYS_GET_TASK_INFO). A prior
 * mismatch (kernel and userspace had different field orders) made `ps` read
 * garbage; keep all three in sync. */
struct task_info {
    uint32_t id;
    uint32_t state;
    uint32_t uid;
    uint32_t gid;
    uint32_t cr3;
    uint32_t eip;
    uint32_t heap_used;
    uint32_t caps_in_use;
    int      in_kernel;
    int      blocked_on;
    int      blocked_on_notif;
    char     name[32];
};
struct dir_entry { char name[32]; uint32_t ino; uint32_t type; uint32_t name_len; uint32_t inode; };
typedef struct platform_info {
    int family, model, stepping;
    int has_long_mode;
    char vendor[13];
    int has_smap;
    int has_smep;
    int has_umip;
    int has_l1d_flush;   /* CPUID.7.0:EDX[28] — IA32_FLUSH_CMD L1D flush */
    int has_ibpb;        /* CPUID.7.0:EDX[26] — IA32_PRED_CMD indirect-branch barrier */
    int has_md_clear;    /* CPUID.7.0:EDX[10] — VERW clears store/fill/load buffers (MDS) */
    int has_htt;         /* CPUID.1:EDX[28]  — HT/SMT capable (co-residency caveat) */
    int smt_shift;       /* # of low APIC-ID bits identifying the SMT thread within a core (0 = no SMT) */
    int has_aesni;
    int has_tsc;
    int has_sse;
    int has_sse2;
    int has_sse4_2;
    int has_rdrand;
    int has_invariant_tsc;
    int num_logical_cpus;
    int num_physical_cpus;
    uint64_t total_memory_bytes;
} platform_info_t;
extern platform_info_t platform;
#define MAX_CPUS 4
/* Physical load address of the AP trampoline blob (the SIPI vector's target).
 * Shared because two subsystems need it: smp.c stages the blob here, and
 * paging.c keeps exactly this page of the low identity map present and
 * executable — an AP far-jumps into it *after* enabling paging, so it is the
 * only low address the kernel still executes from. MUST match ap_trampoline.S. */
#define AP_TRAMP_PHYS 0x8000UL
void users_init(void);


#define SYS_YIELD           0
#define SYS_PRINT           1
#define SYS_EXIT            2
#define SYS_GET_LINE        3
/* Named 2026-08-23. These six dispatch entries were written as bare numeric
 * indices — `[5]`, `[6]`, `[7]`, `[14]`, `[15]`, `[16]` — and the coverage
 * deriver reads the table for `[SYS_NAME]`, so it could not see them: five live
 * handlers in the ship build that no coverage rule could name, classify or
 * require evidence for. Exactly the hole SECURITY.md S25 records for
 * SYS_CAP_MINT/TRANSFER/MOVE, in the same table, still open next door. The
 * numbers are unchanged — this is a naming change, not an ABI change — and
 * `tools/check_syscall_coverage.py` now refuses a bare numeric entry outright so
 * the hole cannot reopen. */
#define SYS_CLEAR           5   /* clear the screen; slot-3 WRITE */
#define SYS_SYSINFO         6   /* kernel version/build readout   */
#define SYS_DEBUG_EXEC      7   /* DEBUG_SHELL only; -1 otherwise */
#define SYS_EXEC_LEGACY     14  /* pre-ELF (load_base, entry) exec */
#define SYS_RAMFS_CREATE    15  /* RAMFS_SLOT3_GATE only ([H-3])  */
#define SYS_RAMFS_LIST      16  /* RAMFS_SLOT3_GATE only ([H-3])  */
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

/* Distinct return code for syscalls whose capability check passed but whose
 * backing operation is not implemented (vs. -1 = denied/bad-arg). */
#include "errno.h"   /* shared, descriptive syscall error codes (SYS_ERR_*) */
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
/* Capability-algebra syscalls. 4/8/9 predate the SYS_* naming and lived in the
 * dispatch table as bare numeric literals; they are named here because roadmap
 * 2.1 made SYS_CAP_MINT reachable from ring 3, and a syscall userspace can call
 * should not be a magic number on the kernel side. Authority for all four is
 * enforced inside the cap_* primitives, not by a dispatch-table slot. */
#define SYS_CAP_MINT            4
#define SYS_CAP_TRANSFER        8
#define SYS_CAP_MOVE            9
#define SYS_CAP_REVOKE         51
#define SYS_AUDIT_DIGEST       52
#define SYS_PREEMPT_TRACE      53   /* PREEMPT_SELFTEST builds only; NOSYS otherwise */
#define SYS_SIGACTION          54   /* register this task's own fault-signal handler */
#define SYS_SIGRETURN          55   /* resume the pre-signal context (from a handler) */
/* Encrypted object-store API for the userspace FS server (see include/syscall.h). */
#define SYS_FS_INODE_ALLOC     56
#define SYS_FS_INODE_FREE      57
#define SYS_FBLOCK_READ        58
#define SYS_FBLOCK_WRITE       59
#define SYS_FS_STAT            60
#define SYS_FS_SET_SIZE        61
#define SYS_BRK                62
#define SYS_KILL               63   /* terminate a task; gated on a CAP_TCB cap to it */
#define SYS_EXEC_NAMED         64   /* replace the caller's image with a named embedded binary */
#define SYS_CAP_GRANT          65   /* delegate a capability into a supervised child's cspace */
#define SYS_SIGNAL             66   /* send a signal to a task held via CAP_TCB (async delivery) */
#define SYS_SIGMASK            67   /* (how, mask) -> old mask; block/unblock this task's own signals */
#define SYS_SPAWN_ARG          68   /* () -> the one-word argument this task was spawned with */
#define SYS_GET_ARGV           69   /* (char ***out) -> argc; writes the argv[] base to *out */
#define SYS_SPAWN_IMAGE        70   /* (image, len, arg, argv, argc) -> pid; spawn a child from a caller-supplied program image */
#define SYS_EXEC_IMAGE         71   /* (image, len, 0, argv, argc) -> replace the caller's own image with a caller-supplied one; no return on success */
#define SYS_SIGALTSTACK        72   /* (ss_sp, ss_size) -> 0; register this task's own alternate signal stack (ss_size 0 disables) */
#define SYS_IPC_SENDER         73   /* (ep, uint32_t *out_gid) -> uid; kernel-attested identity of the last sender on `ep` (unforgeable, set at login) */
#define SYS_FS_SET_META        74   /* (ino, mode, uid, gid) -> 0; persist an inode's owner/mode (object-store server only: uid 0 + CAP_BLOCK_DEV) */
#define SYS_IPC_REPLY_TO       75   /* (req_ep, msg, len) -> 0; reply to the task that sent the last request on req_ep (routed by kernel-recorded sender, not a shared reply endpoint) — multi-client safe */
#define SYS_FS_INODE_LINK      76   /* (ino) -> 0; increment an inode's hard-link count (object-store server only: uid 0 + CAP_BLOCK_DEV) */
#define SYS_BOOT_MODULE_INFO   77   /* (index, struct boot_module_info*) -> module count; store owner only (uid 0 + CAP_BLOCK_DEV) */
#define SYS_BOOT_MODULE_READ   78   /* (index, offset, buf, len) -> bytes copied from a boot module; store owner only (uid 0 + CAP_BLOCK_DEV) */
#define SYS_MAP_PHYS           79   /* (dev_slot, paddr, vaddr, len, flags) -> 0; map one frame DECLARED BY the device named in dev_slot into the caller's own address space (CAP_IO_DEVICE + WRITE). See src/kernel/pci.c, docs/design/console-server.md */
#define SYS_IOPORT_GRANT       80   /* (dev_slot) -> 0; grant the caller native ring-3 in/out on the ports declared by the device named in dev_slot, via the TSS I/O bitmap (CAP_IO_DEVICE + WRITE) */
#define SYS_DEVICE_INFO       102   /* (dev_slot, struct dev_info*) -> 0; report what the device named by the CAP_IO_DEVICE at dev_slot declares -- ids, MMIO ranges, port ranges, IRQ lines -- and nothing about any other device (CAP_IO_DEVICE + READ) */
#define SYS_DEVICE_ENABLE     103   /* (dev_slot, flags) -> 0; set the three PCI decode bits (IO/MEM/BUSMASTER) of the device named in dev_slot, and nothing else in configuration space (CAP_IO_DEVICE + WRITE) */
#define DMA_ADDR_NO_MAP        0x1u  /* SYS_DMA_ADDR: report, do not map (control arm) */
#define SYS_IRQ_ACK           105   /* (dev_slot, irq) -> 0; the driver has serviced its device, so unmask the line. A registered line is masked by the kernel when it fires and stays masked until this call, which is what stops an unserviced level-triggered device livelocking the machine (CAP_IO_DEVICE + WRITE naming a device that declares the line, AND the registration must be the caller's) */
#define SYS_DMA_ADDR          104   /* (dev_slot, frame_slot, uint64_t*) -> 0; the bus address at which that device reaches that frame. Needs BOTH capabilities: the answer is a physical address, and a bus-mastering device already reaches all of memory, so the disclosure adds nothing to a caller who holds one */
#define SYS_IRQ_REGISTER       81   /* (dev_slot, irq, notif_slot, badge) -> 0; route an IRQ the named device declares to an async notification so a ring-3 driver services it (CAP_IO_DEVICE + WRITE) */
#define SYS_CONSOLE_OWNED      82   /* () -> 1 if a ring-3 console server owns the console hardware (fd-1 output must route through it), else 0; read-only status, self-authorizing */
#define SYS_PIPE               83   /* () -> (read_slot<<16)|write_slot; create a pipe, install a read-end + write-end CAP_PIPE in the caller's cspace */
#define SYS_PIPE_READ          84   /* (slot, buf, len) -> bytes read; 0 = EOF (no writers), SYS_ERR_AGAIN = empty but writers remain */
#define SYS_PIPE_WRITE         85   /* (slot, buf, len) -> bytes written; SYS_ERR_AGAIN = full but reader remains, SYS_ERR_PIPE = no reader */
#define SYS_PIPE_CLOSE         86   /* (slot) -> 0; drop a pipe-end cap and unref that end (EOF/EPIPE to the peer when it hits 0) */
#define SYS_STDIO_INFO         87   /* () -> bit0: stdin is a pipe (slot 8); bit1: stdout is a pipe (slot 9); read by posix_init */
#define SYS_TASK_RESUME        89   /* (tid) -> 0; make a spawned-but-suspended child schedulable. Needs a CAP_TCB to the target (or admin), exactly like SYS_KILL. Spawn leaves a child suspended so its supervisor can endow it before it runs. */
#define SYS_RETYPE             90   /* (untyped_slot, kobj_type, count, dest_slot) -> objects created; carve kernel objects out of untyped memory. Authority is the CAP_UNTYPED at untyped_slot (WRITE). */
#define SYS_MAP_FRAME          95   /* (frame_slot, vaddr, rights) -> 0; map the KOBJ_FRAME named by a CAP_FRAME into the caller's own address space (roadmap 2.1). Authority is the capability the caller names, resolved in syscall_vm.c. */
#define SYS_UNMAP_FRAME        96   /* (frame_slot, vaddr) -> 0; remove that mapping. The PTE must name this capability's own frame. */
#define SYS_MAP_REGION         99   /* (first_slot, count, vaddr, rights) -> 0; map `count` CAP_FRAMEs from consecutive cspace slots at consecutive pages (roadmap 2.1). ALL OR NOTHING: any page that cannot be mapped withdraws every page the call already mapped, so a caller holding an error holds the address space it started with. The argument for that policy, and why it is the opposite of SYS_RETYPE's, is at the handler in syscall_vm.c. */
#define SYS_FRAME_PAGES       100   /* (frame_slot) -> pages (>0); the length of the frame the CAP_FRAME at `frame_slot` names (roadmap 2.1). Authority is that capability, resolved in syscall_vm.c -- never a frame index the caller supplies, which would be finding C-1's shape and an object-existence oracle over other tasks' frames. */
#define SYS_FORK              101   /* () -> child tid in the parent, 0 in the child; duplicate the caller's address space copy-on-write (roadmap 2.3). No capability of its own: a task may always make a copy of ITSELF, and the child is endowed exactly as SYS_SPAWN endows one -- never more than the caller holds. Refuses while the caller has a CAP_FRAME mapped; see clone_user_aspace in paging.c. */
#define SYS_CLOCK_GETTIME      98   /* (clock_id, struct horus_timespec*) -> 0; monotonic time since boot (roadmap 2.2). No capability: coarse by design, see the struct. */
#define SYS_CAP_ENUMERATE      97   /* (tid, slot, struct cap_info*) -> 0; read one capability slot of task `tid` (roadmap 3.6). CAP_DEBUG (READ) at CAPSLOT_DEBUG. Reports type/rights/serial/badge/generation and whether the slot is occupied; see struct cap_info for what it deliberately does not report. */
#define SYS_UNTYPED_INFO       91   /* (untyped_slot, struct untyped_info*) -> 0; size/watermark/free of the region named at untyped_slot (READ). */
#define SYS_DMESG              88   /* (buf, offset, max) -> bytes; copy a chunk of the kernel message ring at `offset` to buf. ROOT ONLY (uid==0), else SYS_ERR_PERM */
#define SYS_IRQ_POLICY_INFO    92   /* (struct irq_policy_info*) -> 0; roadmap 1.1 audit counters. IRQ_POLICY_AUDIT builds only; NOSYS otherwise. CAP_KERNEL_LOG (READ), same class as dmesg. */
#define SYS_TASK_EXIT_INFO     93   /* (struct task_exit_info*) -> 0; why the last task this caller waited on died (finding G-8). Self-scoped: no capability, waiting already entitled the caller to observe it. */
#define SYS_IPC_RECV_BLOCK     94   /* (ep_slot, buf, max) -> len; blocking SYS_IPC_RECV (roadmap 1.3). CAP_ENDPOINT + READ, enforced per-slot in the handler like every other IPC syscall. */

/* ---- roadmap 2.2: a monotonic clock ---------------------------------------
 *
 * Time since boot, and ONLY since boot. There is no wall clock here: nothing
 * reads an RTC and nothing attests one, so a `CLOCK_REALTIME` would be a number
 * with the shape of a date and no claim behind it. `SYS_CLOCK_GETTIME` refuses
 * every clock id but `HORUS_CLOCK_MONOTONIC`, fail-closed like any other
 * unknown case.
 *
 * RESOLUTION IS 10 ms, AND THAT IS A SECURITY DECISION RATHER THAN A LIMITATION
 * OF THE HARDWARE. `cpu_enable_protections` sets CR4.TSD precisely so ring 3
 * cannot execute RDTSC: it removes "the cycle-accurate timer that cache/covert-
 * channel attacks between mutually distrusting ring-3 tasks lean on"
 * (src/kernel/crypto.c). Handing back a nanosecond clock through a syscall
 * would give that timer back through the front door. So this is derived from
 * the PIT tick counter at PIT_TICK_HZ, not from the TSC, and `nsec` is always a
 * multiple of 10,000,000.
 *
 * That is not a claim of side-channel safety. The TSD comment already says the
 * mitigation is partial -- a counting thread still builds a finer timer -- and
 * this changes nothing about that. It declines to make it easy.
 *
 * `sec`/`nsec` rather than a plain millisecond count so the shape matches
 * POSIX `clock_gettime`, which is what a libc will want to sit on. */
/* The PIT channel-0 tick rate: the scheduler's quantum AND the clock's
 * resolution, which is why it lives here rather than in idt.c. 100 Hz = 10 ms.
 * `1000000000 / PIT_TICK_HZ` must be exact, or nsec loses time every tick. */
#define PIT_TICK_HZ 100
_Static_assert(1000000000u % PIT_TICK_HZ == 0,
               "PIT_TICK_HZ must divide 1e9 exactly, or the clock drifts");

#define HORUS_CLOCK_MONOTONIC 1

struct horus_timespec {
    uint64_t sec;
    uint32_t nsec;      /* always a multiple of 10,000,000 -- see above */
    uint32_t reserved;  /* pad to 16 bytes; zeroed */
};

/* ---- roadmap 3.6: reading the capability graph out, in band ---------------
 *
 * One slot of one task's cspace. `SYS_CAP_ENUMERATE` fills this in for a caller
 * holding CAP_DEBUG; a `capview` tool walks slot 0..CNODE_SIZE-1 over each task
 * and prints the graph.
 *
 * WHAT IT DELIBERATELY DOES NOT REPORT is `object`. For most types that field is
 * an index into a kernel table -- a frame-table index since [F-2.1], an endpoint
 * index, a task id -- but "most" is not a security argument, and the legacy
 * CAP_FRAME in slot 3 still carries USER_AREA_BASE, an address. Withholding it
 * costs the graph nothing that matters: `serial` and `badge` ARE the edges, so
 * derivation is fully visible without naming what each node points at. The same
 * reasoning suppresses `cr3` and another task's `eip` in struct task_info
 * (finding I-4).
 *
 * `occupied` rather than testing type != CAP_NULL in ring 3: the caller should
 * not have to know the kernel's internal null encoding to walk a cspace. */
struct cap_info {
    uint32_t slot;        /* the slot this describes                          */
    uint32_t occupied;    /* 0 = empty slot; 1 = a live capability            */
    uint32_t type;        /* CAP_* type, 0 when empty                         */
    uint32_t rights;      /* CAP_RIGHT_* bitmask                              */
    uint32_t serial;      /* this capability's identity (a graph node)        */
    uint32_t badge;       /* its parent's serial (a graph edge), 0 at a root  */
    uint32_t generation;  /* lineage generation recorded at mint              */
    uint32_t reserved;    /* pad to a 32-byte multiple                        */
};

/* ---- roadmap 1.1: reading the interrupt-policy audit out, in band ----------
 *
 * The counters used to be printed from the timer ISR straight at the UART,
 * around the single-writer console rather than through it. That split the shell
 * prompt and hung the harness measuring it, and the numbers it did publish were
 * the boot window of a session that never ran a command (see docs/ROADMAP.md
 * §1.1). This syscall is the readout that replaces it: userspace asks, whenever
 * it likes, and prints through console_server like any other program -- so a
 * session-scale total is obtainable without a second writer existing at all.
 *
 * NB the counters are volatile globals updated without atomics under SMP (that
 * is part of finding C-3 itself), so a snapshot is indicative, not exact. */
#define IRQ_POLICY_SITE_SLOTS  12

struct irq_policy_site_info {
    uint64_t ra;                 /* return address of the spin_unlock caller */
    uint32_t hits;
    uint32_t _pad;
};

struct irq_policy_info {
    uint32_t accidental;         /* depth-0 releases that ENABLED IF the caller had masked
                                  * (legacy lock only; 0 with the per-CPU lock) */
    uint32_t suppressed;         /* the same releases, SUPPRESSED by the per-CPU IF-preserving
                                  * lock (0 in a legacy build). accidental + suppressed is the
                                  * same population either way -- that is what makes the two
                                  * builds comparable on one workload (roadmap 1.1 step 3) */
    uint32_t benign;             /* ... that restored IF=1 to a caller who already had it */
    uint32_t sites;              /* distinct accidental sites recorded (<= IRQ_POLICY_SITE_SLOTS) */
    uint32_t ticks;              /* system_ticks at the moment of the snapshot */
    struct irq_policy_site_info site[IRQ_POLICY_SITE_SLOTS];
};

#ifdef IRQ_POLICY_AUDIT
void irq_policy_snapshot(struct irq_policy_info *out);
#endif

/* Reserved cspace slots a spawner wires a child's pipe stdio into (do_spawn),
 * read back by the child's posix_init via SYS_STDIO_INFO. create_task assigns
 * 0,3,4,5,8,9 and init grants 6,7,10,11 to servers; 14/15 are always free. */
#define STDIN_PIPE_SLOT         14
#define STDOUT_PIPE_SLOT        15
/* tcb.stdio_flags bits: which of the child's fd0/fd1 was spawned as a pipe. */
#define STDIO_STDIN_PIPE        0x1u
#define STDIO_STDOUT_PIPE       0x2u

/* SYS_MAP_PHYS `flags` word (must match include/syscall.h). READ is the floor;
 * WRITE adds the writable bit. Device MMIO is always mapped non-executable. */
#define MAP_PHYS_READ           0x1u
#define MAP_PHYS_WRITE          0x2u

/* Minimum size of a registered alternate signal stack (SYS_SIGALTSTACK); smaller
 * requests fail closed so a handler always has room for at least a shallow frame. */
#define SIG_ALTSTACK_MIN       2048
/* Inode metadata returned by SYS_FS_STAT (mirrors struct fs_stat in
 * include/syscall.h — keep byte-identical). */
struct fs_stat {
    uint64_t size;
    uint32_t type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t links;
};

/* Boot-module descriptor returned by SYS_BOOT_MODULE_INFO (mirrors struct
 * boot_module_info in include/syscall.h — keep byte-identical). Distinct from the
 * kernel-internal struct boot_module above, which also carries physical extent. */
#define BOOT_MODULE_INFO_NAME_MAX 32
struct boot_module_info {
    uint32_t size;
    char     name[BOOT_MODULE_INFO_NAME_MAX];
};

/* Signal numbers delivered to a registered handler on a ring-3 fault. */
#define SIG_ILL                 4   /* illegal instruction (#UD) */
#define SIG_KILL                9   /* uncatchable terminate (SYS_SIGNAL: always default-kills) */
#define SIG_USR1               10   /* application-defined, for task-to-task signalling */
#define SIG_SEGV               11   /* invalid memory access (page fault / #GP) */
#define SIG_USR2               12   /* second application-defined signal */
#define SIG_TERM               15   /* polite terminate (default action if no handler) */
#define SIG_MAX                31   /* signal numbers are 1..31 */

/* SYS_SIGMASK `how` argument: how the supplied mask combines with the current
 * blocked set. */
#define SIG_SETMASK             0   /* replace the blocked set with `mask` */
#define SIG_BLOCK               1   /* add `mask` to the blocked set */
#define SIG_UNBLOCK             2   /* remove `mask` from the blocked set */

#define CAP_NULL                0
#define CAP_TCB                 1
#define CAP_NOTIFICATION        2
#define CAP_ENDPOINT            3
#define CAP_FRAME               4
#define CAP_USER                6
#define CAP_AUDIT               7
#define CAP_CONSOLE             8
#define CAP_ENCRYPTED_STORAGE   9
#define CAP_REVOCATION          10
#define CAP_BLOCK_DEV           11
/* Hardware device authority: the right to touch a physical device (map a device
 * MMIO frame into a user address space, and — in later console-server jobs — hold
 * a port-I/O grant / claim an IRQ line). Distinct from CAP_CONSOLE, which is only
 * a software privilege token for the kernel shell. Only a driver server is ever
 * endowed with it. See docs/design/console-server.md. */
#define CAP_IO_DEVICE           12
/* A pipe end (roadmap userspace: shell pipelines). object = pipe index; the
 * direction is the rights bit: CAP_RIGHT_READ = read end, CAP_RIGHT_WRITE = write
 * end. Only a task holding the end cap can read/write that pipe (zero-trust). The
 * capability algebra treats the type opaquely, so this is a C-side type only. */
#define CAP_PIPE                13

/* Authority that used to be ambient `uid == 0` (audit finding I-1).
 *
 * Nine syscall handlers gated on the caller's uid rather than on a held
 * capability, so root was a second authority axis running parallel to the
 * capability graph — which meant the graph was NOT a complete description of who
 * could do what, defeating much of the point of having one. Each of these types
 * replaces one of those gates, is minted once in the primordial root cnode, and
 * is delegated by init to exactly the task that needs it. */
/* ---- One-shot reply authority (roadmap 1.3, [I-5]) -------------------------
 *
 * `object` = the task blocked in SYS_IPC_CALL that this capability authorises a
 * reply to. Minted by SYS_IPC_RECV into CAPSLOT_REPLY of the RECEIVING task, and
 * CONSUMED (the slot nulled) by SYS_IPC_REPLY_TO.
 *
 * What this changes. The reply used to be routed by `endpoints[ep].last_sender`
 * — a mutable field on the endpoint, overwritten by the next receive. Replying
 * to the right client was therefore a CONVENTION the server had to honour
 * ("must precede the next recv, which would overwrite last_sender"), not a
 * property the kernel enforced. The bounded queue made that sharper: a server
 * may now dequeue several requests, and only the newest was nameable.
 *
 * Holding this capability IS the right to reply, so:
 *   - a task cannot reply to a client it never received from — it has no cap;
 *   - it cannot reply TWICE to one request — the first reply consumes the cap;
 *   - it cannot reply to the wrong client — the cap names the client, and
 *     nothing the server does afterwards can retarget it.
 *
 * That is the difference between forgery being gated and forgery being
 * impossible to express. Note it is deliberately NOT delegatable in any useful
 * sense: it names one blocked caller and dies on use. */
#define CAP_REPLY               17

#define CAP_KERNEL_LOG          14   /* SYS_DMESG: read the kernel message ring   */
#define CAP_BOOT_MODULE         15   /* SYS_BOOT_MODULE_INFO / _READ               */
/* CAP_DEBUG (roadmap 3.6): authority to OBSERVE, and nothing else.
 *
 * It gates cross-task introspection and `SYS_CAP_ENUMERATE`, which reads out
 * another task's capability slots. Before this, `ps` worked because init handed
 * the shell a CAP_AUDIT -- the capability that also rotates the audit chain's
 * keys and reads the log -- so "show me the process list" carried the authority
 * to tamper with the record of what happened. That is a bundling mistake, not an
 * ambient one: the gate was real, it just named far more authority than the
 * caller needed.
 *
 * Deliberately READ-only in the root cnode, so no delegation can widen it into
 * anything that writes. Observation is not control: CAP_DEBUG cannot kill,
 * spawn, mint, revoke, or map. */
#define CAP_DEBUG               18   /* observation only: task info, cspace readout */

#define CAP_RIGHT_READ          (1u << 0)
#define CAP_RIGHT_WRITE         (1u << 1)
#define CAP_RIGHT_EXEC          (1u << 2)
#define CAP_RIGHT_GRANT         (1u << 3)
#define CAP_RIGHT_MINT          (1u << 4)
#define CAP_RIGHT_REVOKE        (1u << 5)
#define CAP_RIGHT_AUDIT_WRITE   (1u << 6)
#define CAP_RIGHT_ALL           (0xFFFFFFFFu)

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




typedef struct user_account {
    char     name[32];
    uint32_t uid;
    uint32_t gid;
    uint32_t auth_lockout_until;
    uint32_t auth_fail_count;
    uint8_t  salt[16];
    int      valid;
    uint8_t  pass_hash[32];   
    char     home[64];
    char     shell[32];
} user_account_t;


typedef struct audit_event {
    uint32_t type;
    uint32_t kind;
    uint32_t uid;
    uint32_t subject_uid;
    int      subject_task;
    uint64_t object;
    int      result;
    uint64_t timestamp;
    uint64_t arg0;
    uint64_t arg1;
    char     path[64];
    char     message[128];
} audit_event_t;


typedef struct program_header {
    uint32_t type;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint32_t flags;
    uint32_t align;
    char     name[32];      
    uint64_t size;          
    uint32_t magic;         
    uint32_t entry;
} program_header_t;


typedef struct capability {
    uint32_t type;
    uint32_t rights;
    uint64_t object;
    uint32_t badge;
    uint32_t serial;
    uint32_t generation;
} capability_t;

/* Immutable identity snapshot of a capability, taken at lookup time and
 * reconfirmed at use time via cap_revalidate() to defend against lookup/use
 * TOCTOU. `object` is uint64_t to match capability_t.object exactly. */
typedef struct cap_snapshot {
    uint32_t serial;
    uint32_t generation;
    uint64_t object;
    int      valid;
} cap_snapshot_t;


/* Full interrupt trap frame pushed by isr_common_stub64 (src/kernel/lowlevel64.S):
 * the 15 general-purpose registers, then the vector + error code, then the CPU's
 * iret frame. A pointer to this is what interrupt_handler64 receives and what
 * the preemptive scheduler and the signal path save/restore per task. */
struct interrupt_frame64 {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t int_no;
    uint64_t err_code;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

typedef struct tcb {
    uint32_t state;
    uint32_t caps_in_use;
    capability_t *cspace;
    uint32_t cspace_size;
    uint64_t tsc_base;
    /* User addresses and CR3 are 64-bit. They were uint32_t while userspace was
     * i386-only; anything above 4 GiB silently truncated, and the kernel-side
     * plumbing is being widened ahead of the ring-3 ABI so the two moves are
     * separable. `priority` and `cap_tcb` are not addresses and stay 32-bit. */
    uint64_t esp; uint64_t eip; uint64_t cr3; uint32_t priority; uint32_t cap_tcb; int auth_fail_count; int auth_lockout_until; int ipc_role;
    
    uint32_t uid;
    uint32_t gid;
    char     name[32];
    uint8_t  user_file_master_key[32];
    int      has_file_key;

    
    uint64_t heap_start;
    uint64_t heap_current;
    uint64_t heap_end;

    
    int      in_kernel;
    int      blocked_on;
    int      blocked_on_notif;
    int      waiter;

    /* Death record (finding G-8). `exit_info` describes how THIS task died and
     * is written by task_teardown; it stays valid while the slot reads
     * TASK_DEAD, which is exactly the window SYS_WAIT's already-dead fast path
     * needs. `wait_exit_info` is the copy handed to this task as a *supervisor*
     * — the cause of the last task it waited on.
     *
     * Two fields rather than one because a task slot is reused: init relaunches
     * the shell the moment its wait returns, and do_spawn may hand the corpse's
     * slot straight to the replacement. Reading the cause out of the dead task's
     * slot after that point would report the living shell. Copying it onto the
     * waiter at teardown makes the record outlive the body. */
    struct task_exit_info exit_info;
    struct task_exit_info wait_exit_info;
    /* Port-I/O grant (SYS_IOPORT_GRANT): the index of the ONE device whose ports
     * this task may in/out natively at ring 3, or IODEV_NONE for no grant. The
     * context switch (set_current_task -> tss_set_io_device) loads that device's
     * ranges into the running CPU's TSS bitmap and flips iomap_base to match, so
     * no other task inherits the grant and no grant reaches a second device.
     *
     * One field, not a boolean plus an index: the grant and what it is a grant TO
     * cannot then disagree, and the "no grant" state is not a value any real
     * device index can collide with. */
    uint64_t io_device;


    uint64_t kernel_stack_top;

    /* Preemptive scheduling: `saved_ksp` is the kernel-stack pointer at which
     * this task's full interrupt trap frame sits while it is not running (set
     * either by the timer ISR when the task is preempted, or fabricated at
     * spawn for a task that has not run yet). `runnable_ctx` is 1 once such a
     * resumable frame exists. The timer ISR resumes a task by loading
     * `saved_ksp` into %rsp and running the interrupt epilogue (pop regs;
     * iretq). See scheduler.c and src/kernel/lowlevel64.S. */
    uint64_t saved_ksp;
    uint32_t runnable_ctx;

    /* Signal handling: deliver a ring-3 fault to a user handler instead of the
     * summary kill. `sig_handler` is the handler's ring-3 entry (0 = none; the
     * task registers its own via SYS_SIGACTION). `in_signal` is set while a
     * handler runs, so a fault *inside* the handler falls through to the kill
     * path (no recursion). `sig_frame` is the full trap frame captured at
     * delivery, restored by SYS_SIGRETURN. See idt.c / syscall.c. */
    uint64_t sig_handler;
    uint32_t in_signal;
    struct interrupt_frame64 sig_frame;

    /* FXSAVE image: this task's x87/SSE register file (xmm0-15, MXCSR, ...).
     *
     * The trap frame saves general-purpose registers only, so without this a
     * task's xmm state was simply destroyed by whatever ran next -- another task
     * or the kernel itself. That was invisible while userspace was i386 (no SSE2
     * in the baseline), but under -m64 SSE2 IS the baseline and gcc keeps live
     * values in xmm across calls: the fs client held a broadcast byte in xmm0
     * across sys_ipc_call and stored the fs_server's leftover xmm0 as file data
     * -- silent on-disk corruption that every checksum agreed with
     * (smoke-fs-conc). It is also a confidentiality leak in the other direction:
     * one task's register file must not be readable by the next.
     *
     * 16-byte aligned because FXSAVE/FXRSTOR #GP on a misaligned operand. */
    uint8_t fpu_state[512] __attribute__((aligned(16)));

    /* ASLR: per-task randomized image load base (and end), chosen at spawn for
     * PIE (ET_DYN) images. create_user_pagedir premaps the image window at
     * `image_base`; the flat/non-PIE fallback keeps the fixed USER_AREA_BASE. */
    uint64_t image_base;
    uint64_t image_end;
    /* Number of pages create_user_pagedir premaps for the image window — the
     * loaded span of the staged image (staged_image_span_pages), so the whole
     * image, not just a fixed 128 KiB, is present for the loader's copy_to_user.
     * 0 means "use the USER_ASPACE_PREMAP_PAGES default" (task 0, flat demos). */
    uint32_t image_premap_pages;

    /* Blocking IPC: set by h_ipc_call before yielding, consumed by ipc_block_switch
     * when the reply arrives and the waiter is resumed. */
    uint64_t ipc_reply_buf;    /* userspace ptr in the waiter's address space */

    /* Block intent recorded by a syscall handler *before* the frame is saved.
     * Non-zero (a TASK_BLOCKED_* value) means interrupt_handler64 must call
     * ipc_block_switch, which saves the trap frame first and only then publishes
     * the waiter so a cross-CPU notifier cannot patch a stale saved_ksp.
     * Object is in blocked_on (reply ep or wait tid) or blocked_on_notif. */
    uint32_t pending_block;

    /* Blocking RECEIVE (roadmap 1.3). TASK_BLOCKED_IPC covers two waits that use
     * the same mechanism -- a task parked until a message lands on an endpoint --
     * but that must complete differently:
     *
     *   ipc_recv_block == 0  a CLIENT inside SYS_IPC_CALL waiting for its reply.
     *   ipc_recv_block == 1  a SERVER inside SYS_IPC_RECV_BLOCK waiting for a
     *                        request. Completing this one must additionally record
     *                        the sender as the endpoint's last_sender and mint the
     *                        one-shot CAP_REPLY naming it, exactly as the polling
     *                        SYS_IPC_RECV does -- otherwise a server woken from a
     *                        block would hold no right to answer the request it
     *                        was just handed.
     *
     * A flag rather than a separate TASK_BLOCKED_* state deliberately: every
     * existing path that handles TASK_BLOCKED_IPC (teardown, ipc_unpublish_block,
     * the scheduler, the claim auditor) then keeps working unchanged, instead of a
     * new state having to be added to each of them and one being missed.
     *
     * `ipc_recv_max` is the receiver's buffer size. The reply path can use
     * IPC_MSG_MAX because a reply buffer is always that big by contract; a
     * receiver names its own, so truncation has to respect it. */
    uint32_t ipc_recv_block;
    uint32_t ipc_recv_max;

    /* Async signals. `pending_sigs` is a bitmask of queued signals (bit N =
     * signal N pending, 1..31), set by SYS_SIGNAL (gated on a CAP_TCB to this
     * task) or the fault path; the lowest-numbered *unmasked* one is delivered
     * into `sig_handler` when this task next returns to ring 3. `sig_mask` is the
     * set of currently-blocked signals (SYS_SIGMASK); a blocked signal stays
     * pending until unblocked. SIG_KILL can never be blocked. Carved from padding
     * so the struct size is unchanged. */
    uint32_t pending_sigs;
    uint32_t sig_mask;

    /* One-word argument handed to a task at spawn (SYS_SPAWN edx), retrieved by
     * the child via SYS_SPAWN_ARG. A fast path alongside the full argv below. */
    uint32_t spawn_arg;

    /* Which of this task's stdio fds the spawner wired to a pipe (STDIO_*_PIPE
     * bits). Set in do_spawn after granting the pipe ends into slots 8/9; read by
     * the child's posix_init via SYS_STDIO_INFO. 0 = both default to the console. */
    uint32_t stdio_flags;

    /* Full argument vector. The kernel marshals the spawner's argv strings onto
     * the child's initial user stack at spawn and records the count and the
     * user vaddr of the argv[] pointer array here; the child reads them with
     * SYS_GET_ARGV. Both 0 when spawned without arguments. */
    uint32_t argc;
    uint64_t argv_ptr;

    /* Alternate signal stack (SYS_SIGALTSTACK). When sig_altstack_size is
     * non-zero, a signal delivered while the task is not already running on the
     * altstack enters its handler on [sig_altstack_sp, +sig_altstack_size)
     * instead of the interrupted user stack; sig_on_stack is the SS_ONSTACK
     * guard, set on delivery to the altstack and cleared by SYS_SIGRETURN so a
     * nested signal does not re-use (and corrupt) the frame already on it. All
     * zero => run handlers on the interrupted stack (previous behaviour). */
    uint64_t sig_altstack_sp;
    uint32_t sig_altstack_size;
    uint32_t sig_on_stack;

    uint8_t  padding[8];
} tcb_t;

extern tcb_t tasks[MAX_TASKS];


/* Lineage/generation tracking is owned by the safe-Rust authority
 * (rust/src/capability.rs). The legacy C `lineages[]` table and its helpers
 * (lineage_register/lineage_revoke/next_lineage_id) have been removed to avoid a
 * C/Rust desync that allowed use-after-revoke; use rust_lineage_check /
 * rust_lineage_bump instead. */


typedef struct block_device {
    char name[32];
    uint64_t total_blocks;
    int (*read_block)(struct block_device *bd, uint64_t block, void *buf);
    int (*write_block)(struct block_device *bd, uint64_t block, const void *buf);
    /* Force every write already accepted by write_block onto stable media.
     * Returns 0 only if that succeeded. Every backend must supply this — a NULL
     * flush is treated as a failure by raw_block_flush(), not as a no-op, so a
     * new block device cannot silently inherit "durability not implemented"
     * while the journal keeps advertising crash atomicity. */
    int (*flush)(struct block_device *bd);
    void *private;
} block_device_t;

typedef struct virtual_disk {
    uint8_t *data;
    uint64_t size;
    uint64_t block_count;
} virtual_disk_t;

typedef struct fs_superblock {
    uint32_t magic;
    uint32_t version;            /* 4 = disk_key wrapped by password-derived KEK (LUKS-style) */
    uint64_t meta_start;         /* first block of the nonce/tag metadata region */
    uint32_t meta_blocks;        /* number of blocks in that region */
    uint32_t _pad;
    /* v5: write-ahead redo log. Multi-block updates (bitmap + inode + meta block +
     * data + this superblock's meta_hmac) are staged, committed to this region
     * with an HMAC-authenticated header, then applied to their home locations —
     * so a crash leaves the filesystem either fully before or fully after the
     * operation, and the meta_hmac can never desync (which previously bricked the
     * volume). One header sector + journal_blocks-1 data sectors. */
    uint64_t journal_start;
    uint32_t journal_blocks;
    uint32_t _pad_j;
    uint64_t inode_bitmap_start;
    uint64_t block_bitmap_start;
    uint64_t data_bitmap_start;
    uint64_t inode_table_start;
    uint64_t data_start;
    uint64_t inode_count;
    uint64_t block_count;
    uint64_t total_blocks;
    uint32_t block_size;
    uint8_t  volume_key_salt[16]; /* per-volume HKDF diversifier */
    uint8_t  volume_key[16];      /* unused; kept for struct layout compat */
    uint32_t generation;
    /* v4: password-wrapped disk key — disk_key never stored in plaintext on disk.
     * disk_key is the root of all block key and metadata MAC derivation; it is
     * sealed here with a KEK = Argon2id(password, kek_salt) so the volume is
     * unreadable without the passphrase, even with physical disk access. */
    uint8_t  kek_salt[32];           /* Argon2id salt for KEK (no kernel_pepper: must
                                       * be reproducible across reboots from the same pwd) */
    uint8_t  wrapped_key_nonce[12];  /* AEAD nonce for disk_key sealing */
    uint8_t  wrapped_key_ct[32];     /* AEAD ciphertext of disk_key[32] */
    uint8_t  wrapped_key_tag[16];    /* AEAD auth tag; wrong pwd → open fails → locked */
    uint8_t  meta_hmac[32];          /* HMAC-SHA256(meta_mac_key, g_block_meta[]);
                                       * recomputed on every metadata flush, verified on
                                       * unlock to detect partial nonce/tag rollback */
    /* v6: measured-boot TPM sealing (roadmap 2.2). When tpm_mode == 1 the KEK is
     * two-factor — HKDF(password-KEK, tpm_secret) — where tpm_secret is TPM2-sealed
     * under a PolicyPCR(PCR8,PCR9) and released only under a measured-good boot. The
     * sealed (public||private) blob lives in its own block (tpm_blob_block), not
     * here — a 512-byte superblock has no room for it. tpm_mode == 0 is the
     * unchanged password-only volume. */
    uint8_t  tpm_mode;               /* 0 = password only, 1 = TPM-sealed KEK */
    uint8_t  _tpm_pad;
    uint16_t tpm_pub_len;            /* bytes of TPM2B_PUBLIC in the blob block */
    uint16_t tpm_priv_len;           /* bytes of TPM2B_PRIVATE in the blob block */
    uint16_t _tpm_pad2;
    uint64_t tpm_blob_block;         /* block holding pub||priv (0 if none) */
} fs_superblock_t;
_Static_assert(sizeof(fs_superblock_t) <= BLOCK_SIZE,
               "fs_superblock must fit in one block");

typedef struct on_disk_inode {
    uint64_t size;
    uint32_t type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t atime, mtime, ctime;
    uint64_t direct[12];
    uint64_t indirect;
    uint64_t double_indirect;
    uint8_t  key_material[32];
    uint8_t  file_key[16];
    uint8_t  file_iv[16];
    uint32_t links;
    uint32_t generation;
    uint32_t checksum;
} on_disk_inode_t;
_Static_assert(sizeof(struct on_disk_inode) * INODES_PER_BLOCK <= BLOCK_SIZE,
               "on_disk_inode too large: INODES_PER_BLOCK inodes must fit one block");

typedef struct mounted_fs {
    int     mounted;             /* 1 after storage_mount reads a valid superblock */
    int     unlocked;            /* 1 after storage_unlock derives disk_key from password */
    block_device_t *bd;
    fs_superblock_t sb;
    uint8_t volume_key[16];      /* HKDF(disk_key, volume_key_salt, "horus-volume-key-v2") */
    uint8_t *inode_cache;
    uint8_t disk_key[32];        /* plaintext disk_key in RAM after unlock; zeroed on error */
    uint8_t meta_mac_key[32];    /* HKDF(disk_key, volume_key_salt, "horus-meta-mac-v1") */
    uint8_t journal_mac_key[32]; /* HKDF(disk_key, volume_key_salt, "horus-journal-mac-v1") */
} mounted_fs_t;

/* The legacy capfs object type (struct fs_object / fs_objects[]) and its
 * at-rest AEAD were removed with the capfs engine; the encrypted fs_server is
 * now the only filesystem. */
extern uint8_t kernel_pepper[16];

extern int fs_server_task_id;
extern int fs_server_listen_ep_idx;


extern char keyboard_buffer[256];
extern uint32_t kb_head;
extern uint32_t kb_tail;

typedef struct spinlock {
    volatile uint32_t locked;
} spinlock_t;

extern spinlock_t storage_lock;
extern spinlock_t cap_lock;
extern spinlock_t page_lock;



int  get_current_task(void);
void set_current_task(int v);

/* Declare a window in which percpu_current_task[] deliberately names a task other
 * than the one this CPU is running -- IPC reply delivery and the spawn-time image
 * load both do this so copy_to_user resolves through the target's address space.
 * enter() goes BEFORE the set_current_task() that installs the impersonated
 * identity, exit() AFTER the one that restores it. See the long note on
 * percpu_real_task[] in scheduler.c; without the bracket the scheduler's claim
 * auditor reads these windows as violations. No-ops without SMP. */
#ifdef IRQ_POLICY_AUDIT
void irq_policy_report(const char *when);
void irq_milestone(const char *name);
void irq_milestone_report(void);
void irq_policy_selftest(void);
#endif
void sched_impersonate_enter(void);
void sched_impersonate_exit(void);

/* ---- Kernel-fault reporting (scheduler.c) ----------------------------------
 *
 * FOR THE CPL-0 TRAP PATHS IN idt.c ONLY. These write bytes to COM1 directly,
 * bypassing console ownership, because print() is klog-only once console_server
 * owns the console and a kernel fault that cannot be heard reads as a hang.
 * Every other kernel message must still go through print()/the console server
 * (finding #126) -- a second UART writer on a live session splits the shell
 * prompt, and that has already cost this project a fictitious "hang".
 *
 * Bracket a report with kfault_begin(fatal)/kfault_end(fatal): fatal=0 takes a
 * bounded claim and releases it (the kernel survives and must be able to report
 * again), fatal=1 claims for good and kfault_end never returns. */
void kfault_begin(int fatal);
void kfault_end(int fatal);
void kfault_str(const char *s);
void kfault_hex(uint64_t v);
void kfault_dec(int v);
void kfault_task(int t);                 /* "N 'name'", name bounded */
void kfault_pf_err(uint64_t err);        /* #PF error bits, spelled out */
void kfault_frame(const struct interrupt_frame64 *f);   /* rip/cs/rflags/rsp/rbp/cpu */
void kfault_claims(int task);            /* who else claims this task (SMP only) */

#ifdef RESUME_RSP_INJECT_PRECLAIM
/* Test-only: leave the UART in the state another CPU's FATAL exception leaves
 * it -- panic claim taken, never released. `make smoke-resume-guard-preclaim`
 * uses it to assert a survivable report still gets out from behind one. */
void kfault_claim_permanently_for_test(void);
#endif

/* Which CPU is executing this code. Derived from the TSS selector in TR (`str`)
 * rather than an uncached LAPIC MMIO read -- see the long note on this_cpu() in
 * scheduler.c for why, and why not %gs. this_cpu_lapic() is the original MMIO
 * derivation, kept as the bootstrap answer (an AP has no TSS until setup_ap_tss)
 * and as the independent oracle percpu_id_verify_self() falsifies against. */
int  this_cpu(void);
/* Nested spinlocks held by THIS CPU right now. Lets a window that must run with
 * interrupts enabled check the one precondition that makes enabling them safe
 * (roadmap 1.1); see smp_maybe_shootdown. */
int  irq_locks_held_here(void);
int  this_cpu_lapic(void);
#ifdef SMP
/* Run once per CPU, on that CPU, as its TSS is loaded: panics if the two
 * derivations disagree, and records the core in percpu_id_verified. */
void percpu_id_verify_self(void);
#endif
/* Request a voluntary yield from a syscall handler; interrupt_handler64 performs
 * the full-context switch via sched_yield_switch. Not a cooperative mid-kernel switch. */
void yield(void);
/* Set by yield() to the yielding task id; consumed by interrupt_handler64. -1 = none. */
extern volatile int g_want_yield;
/* Idle this CPU (sti; hlt loop). The only inter-task path is full-context. */
void __attribute__((noreturn)) kernel_idle(void);
/* Enter a task that already has a fabricated/saved trap frame (do_spawn /
 * sched_prepare_user_context). Noreturn: pop+iretq into ring 3. */
void __attribute__((noreturn)) sched_enter_user(int tid);
/* Voluntary yield with a live trap frame; returns the kernel %rsp for the ISR epilogue. */
uint64_t sched_yield_switch(int cur, uint64_t frame_rsp);
/* Terminate task `id`: record why it died, wake any SYS_WAIT waiter (handing it
 * the cause), drop its signal handler, mark it dead (state 0) and release its SMP
 * running-CPU guard. Does NOT switch away from the caller — the SYS_EXIT/SYS_KILL
 * paths handle that.
 *
 * `cause` is mandatory and describes the death: it is the only record of why a
 * task disappeared, so a NULL here would recreate the silence that made G-8
 * signature A unreadable. A NULL is tolerated (reported as TASK_EXIT_NONE)
 * rather than dereferenced, since teardown runs from the fault handler. */
void task_teardown(int id, const struct task_exit_cause *cause);
/* Resume the next runnable task after `dead` terminated (returns its saved kernel
 * %rsp for the ISR epilogue), or 0 if nothing else is runnable. See scheduler.c. */
uint64_t task_exit_switch(int dead);
/* Re-enter task `t` via the fresh context SYS_EXEC_NAMED fabricated for it (same
 * task, replaced image). Returns its saved kernel %rsp for the ISR epilogue. */
uint64_t exec_reenter_switch(int t);
/* Per-CPU exec re-entry hand-off (kspawn.c). Armed by the exec tail on the CPU
 * performing the exec, taken by that same CPU on its syscall exit. It was a
 * single shared `int` until [G-9]; see the note at its definition. */
void exec_reenter_arm(int t);
int  exec_reenter_take(void);
char console_getc(void);
/* Set by the Makefile from DEFECT_ACTIVE: the space-separated list of
 * defect-reproducing flags this kernel was built with, or "none". Printed at
 * boot so a serial transcript is self-describing -- see main.c. The fallback
 * exists so a hand-rolled compile still builds, and says "unknown" rather than
 * lying about being clean. */
#ifndef DEFECT_FLAGS_STR
#define DEFECT_FLAGS_STR "unknown"
#endif

void println(const char *s);
void print(const char *s);
/* The ring-3 console write path (SYS_WRITE fd 1). `may_klog` is the caller's
 * PROVED CAP_KERNEL_LOG(WRITE) authority to append to the kernel message ring;
 * 0 means console only. Finding [H-2] -- see the comment on the definition. */
void print_from_user(const char *s, int may_klog);
/* Linux-style timestamped boot/kernel-log helpers (terminal.c). */
void kmsg_clock_init(void);         /* calibrate the TSC boot clock; call once, early */
#ifdef CLOCK_TSC_RESOLUTION
uint64_t kmsg_uptime_us(void);      /* control arm only -- see terminal.c */
#endif
void kmsg_begin(void);              /* emit just the "[    S.uuuuuu] " prefix */
void kmsg(const char *s);           /* emit a whole "[    S.mmm] s" line */
uint32_t klog_copy(char *dst, uint32_t offset, uint32_t max); /* snapshot the kernel log ring from `offset`; backs SYS_DMESG */
void print_char(char c);
#ifdef DEBUG_SHELL
/* Defined in syscall.c under DEBUG_SHELL; declared here so the in-kernel debug
 * shell (main.c) and the SYS_EXEC_CMD path (syscall.c) can call it without an
 * implicit declaration (a hard error under modern GCC). */
int process_user_command(const char *cmd);
#endif
void print_hex(uint64_t v);
void print_decimal(uint64_t v);
void print_hrule(uint8_t color);
void set_text_colour(uint8_t color);
uint64_t read_tsc(void);
uint32_t get_system_ticks(void);   /* low 32 bits; for small-delta callers  */
uint64_t get_system_ticks64(void); /* full count; the clock's source (2.2)  */
void outb(uint16_t port, uint8_t val);
uint8_t inb(uint16_t port);
void secure_zero(void *p, size_t n);
void spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);
void dump_kernel_log(void);
/* Console hardware ownership handoff: a ring-3 driver that takes native port I/O
 * over the console becomes the sole writer (console_set_owner), and the kernel's
 * print() stops touching serial+VGA until that task dies (console_clear_owner),
 * so the two writers never interleave on the shared UART under SMP. */
void console_set_owner(int tid);
void console_clear_owner(int tid);
int  console_hw_owned(void);
void syscall_handler(struct interrupt_frame64 *r);
void resume_shell_after_fault(void);
void print_hex64(uint64_t v);
void timer_handler(void);
void pit_init(void);
void smp_maybe_shootdown(uint64_t v);
int smp_get_online_count(void);
/* ACPI MADT CPU enumeration (acpi.c): fills apic_ids[] up to max_ids and returns
 * the enabled-CPU count (>=1), or -1 if the firmware tables can't be parsed. */
/* ---- VT-d DMA remapping (src/kernel/iommu.c) ------------------------------
 *
 * What a device is allowed to reach. Every device starts with an EMPTY address
 * space -- not an identity map -- so a device whose driver has mapped nothing
 * reaches nothing and every address it emits faults. That default is what makes
 * S43/S44's capability meaningful against hardware rather than only against the
 * CPU: a driver's DMA reach is exactly the frames it holds a CAP_FRAME for and
 * has asked to map. See SECURITY.md S45.
 *
 * iommu_active() is 0 on a machine with no DMAR, and every caller degrades
 * honestly rather than pretending the property holds. */
void iommu_init(void);
int  iommu_active(void);
int  iommu_map(uint64_t devindex, uint16_t bdf, uint64_t phys, uint32_t pages,
               int writable);
int  iommu_unmap(uint64_t devindex, uint64_t phys, uint32_t pages);
void iommu_reset_device(uint64_t devindex);
void ensure_iommu_regs_mapped(uint64_t *root_pml4, uint64_t regs_phys);
void ensure_iommu_mapped_current(uint64_t *root_pml4);
uint32_t alloc_user_physical_page(void);

int acpi_detect_cpus(uint8_t *apic_ids, int max_ids);
/* One validated ACPI table by signature (acpi.c). Length-bounded, extent-confined
 * to the PHYS_KVA window, checksum-verified: a caller may read `length` bytes and
 * no more. NULL if absent or if anything about it fails to validate -- firmware
 * tables are semi-trusted input and a partial parse fails closed. */
struct acpi_sdt_header;
const struct acpi_sdt_header *acpi_find_table(const char *sig);
uint32_t acpi_table_length(const struct acpi_sdt_header *h);

/* Preemptive scheduling (scheduler.c). preempt_on_tick is called from the timer
 * ISR with the current trap-frame pointer and the interrupted CS; it returns the
 * kernel %rsp to resume on (unchanged for no-switch, or the next task's saved
 * frame). sched_prepare_user_context fabricates an initial resumable frame for a
 * freshly spawned user task. sched_enable_preemption arms the timer switch once
 * boot is past its delicate single-threaded init. */
uint64_t interrupt_handler64(struct interrupt_frame64 *frame);
uint64_t preempt_on_tick(uint64_t frame_rsp, uint64_t interrupted_cs);
void sched_prepare_user_context(int id, uint64_t entry, uint64_t user_rsp);
/* Called from interrupt_handler64 when the caller has pending_block set (or is
 * already in a BLOCKED_* state). Saves the trap frame first, then publishes the
 * waiter under the IPC lock so a cross-CPU wake always patches a valid frame.
 * Returns the kernel %rsp for the ISR epilogue (next task, or same if already
 * satisfied). */
uint64_t ipc_block_switch(int blocked_task, uint64_t frame_rsp);
/* Publish pending_block after saved_ksp is valid. Returns 1 if the task is now
 * blocked (switch away), 0 if the wait completed immediately (resume same). */
int ipc_publish_pending_block(int cur);
/* Undo a published block (no other runnable task to switch to). */
void ipc_unpublish_block(int cur);
void sched_enable_preemption(void);

/* ---- Leaving a kernel stack (scheduler.c, finding G-8) ---------------------
 *
 * A switch path hands the outgoing task to another CPU, but the CPU making the
 * switch is still executing ISR C frames on that task's kernel stack until
 * isr_common_stub64 reaches `movq %rax,%rsp`. So the hand-over is completed
 * there, not in the switch path: the stub calls sched_release_deferred() on the
 * first instruction at which this CPU is provably reading a different stack.
 *
 * g_kstack_inflight has bit t set for the duration of that window on task t's
 * stack. interrupt_handler64 tests it on entry: a CPU arriving in an ISR for a
 * task another CPU has not finished leaving means two CPUs on one kernel stack,
 * which is memory corruption in progress and halts. One load and a bit test on
 * the common path; MAX_TASKS is 64, so one word covers every task exactly.
 * sched_kstack_holder() names the other CPU and is for the report only. */
extern volatile uint64_t g_kstack_inflight;
void sched_release_deferred(void);
int  sched_kstack_holder(int t);

/* Record that this CPU is about to park at ring 0 on `rsp` (the fault/exit
 * fallbacks in idt.c, which resume at resume_shell_after_fault when nothing else
 * is runnable). Fails closed if another CPU is already parked on the same stack:
 * that is two CPUs taking interrupts on one kernel stack, i.e. S20 in the one
 * place g_kstack_inflight cannot see it, because that mask is keyed on task ids
 * and task 0 is legitimately current on several CPUs at once. */
void sched_note_park(uint64_t rsp);

/* Signal delivery (idt.c): on a ring-3 fault, redirect the trap frame into the
 * task's registered handler instead of killing it. Returns 1 if a signal was
 * delivered (caller returns into the handler), 0 to fall through to the kill
 * path. See the fault sites in interrupt_handler64 / page_fault_handler. */
int try_deliver_fault_signal(struct interrupt_frame64 *frame, int cur,
                             uint32_t signum, uint64_t fault_addr);
/* Signatures MUST match rust/src/memory.rs exactly (return types and the u32
 * n_pages width — they previously drifted to `int`). */
int32_t  rust_page_ref_dec(uint32_t phys, uint16_t *refcounts, uint32_t n_pages);
uint16_t rust_page_ref_inc(uint32_t phys, uint16_t *refcounts, uint32_t n_pages);
bool     rust_page_is_valid_user_phys(uint32_t phys, uint32_t n_pages);
bool     rust_page_refcounts_register(const uint16_t *refcounts, uint32_t n_pages);
bool     rust_cow_copy_required(bool is_cow, bool is_write, uint16_t ref_count);
/* Validate a would-be ring-3 signal-handler entry: it must lie in the user code
 * window so the kernel never iretq's ring 3 to the stack, the kernel image, or
 * an unmapped address. Pure value predicate (no pointer deref); fails closed. */
bool     rust_signal_handler_addr_ok(uint64_t vaddr, uint64_t image_base, uint64_t image_end);

/* Centralized capability serial allocation (wrap logic lives in Rust). */
uint32_t rust_cap_alloc_serial(uint32_t *next_serial);

void terminal_init(void);
void clear_screen(void);
/* x87/SSE context (scheduler.c). The kernel is built -mno-sse and owns no FPU
 * state; these exist purely to keep each ring-3 task's register file private to
 * it across switches. */
void fpu_init_template(void);
void fpu_task_init(int id);
void fpu_save(int id);
void fpu_restore(int id);

void print_blanks(int n);
void print_boot_timestamp(void);
void print_section(const char *title, uint8_t color);
void idt_init64(void);
void pic_init(void);
void set_tss_kernel_stack(uint64_t kstack_top);
/* ---- The I/O-device table (src/kernel/pci.c) -----------------------------
 *
 * What a CAP_IO_DEVICE names. The capability's `object` field is an index into
 * this table, and the three hardware syscalls check the resource a caller asks
 * for against the resources that ONE entry declares. Before this existed the
 * type alone was the authority and the resources were constants compiled into
 * syscall_hw.c, so every device capability meant "the console" — see the header
 * comment of pci.c for why that is the [C-1] shape one layer down.
 *
 * Built once at boot by iodev_init(), read-only afterwards, and never reachable
 * from a syscall: ring 3 names a capability, never a bus address. */
#define IODEV_MAX          16    /* table entries; a bounded, boot-time array   */
#define IODEV_MAX_MMIO      8    /* physical ranges one device may declare      */
#define IODEV_MAX_PORT      8    /* I/O port ranges one device may declare      */
#define IODEV_NONE          0    /* "no device": index 0 is permanently absent  */
#define IODEV_PLATFORM      1    /* entry 1: the legacy console/platform device */
#define IODEV_BDF_NONE      0xFFFFu                /* not a PCI function        */
#define IODEV_CLASS_NETWORK 0x02                   /* PCI class: network        */

/* WHY INDEX 0 IS RESERVED AND NOT THE FIRST DEVICE.
 *
 * Two things default to zero and must not thereby name a device: a task slot's
 * io_device (tasks[] is .bss and do_spawn re-inits only selected fields), and a
 * capability's `object` (cap_install_from_root's 4th argument OVERRIDES it, so a
 * caller that forgets to restate the object passes 0). With a 0-based table both
 * would silently resolve to the platform device — the console — which is the
 * whole authority this change exists to stop handing out by default. Reserving 0
 * makes every one of those paths fail CLOSED without needing to be found. */

struct io_device {
    uint32_t    present;
    const char *name;
    uint16_t    bdf;        /* (bus<<8)|(dev<<3)|fn, or IODEV_BDF_NONE */
    uint16_t    vendor;
    uint16_t    device;
    uint32_t    classcode;  /* class:subclass:prog-if */
    uint32_t    irq_mask;   /* legacy IRQ lines this device may route */
    struct { uint64_t base, len; } mmio[IODEV_MAX_MMIO];
    struct { uint16_t base, len; } port[IODEV_MAX_PORT];
    uint32_t    n_mmio, n_port;
};

/* MUST stay byte-identical to struct dev_info in include/syscall.h. */
struct dev_info {
    uint16_t vendor;
    uint16_t device;
    uint16_t bdf;
    uint16_t n_mmio;
    uint32_t classcode;
    uint32_t irq_mask;
    uint32_t n_port;
    uint32_t reserved;
    struct { uint64_t base, len; } mmio[IODEV_MAX_MMIO];
    struct { uint32_t base, len; } port[IODEV_MAX_PORT];
};
/* The ABI header cannot include this one, so it writes the bounds as literals. */
_Static_assert(IODEV_MAX_MMIO == 8 && IODEV_MAX_PORT == 8,
               "struct dev_info's array bounds are literal 8s in include/syscall.h");

void iodev_init(void);
const struct io_device *iodev_get(uint64_t index);
uint32_t iodev_total(void);
uint64_t iodev_first_of_class(uint8_t class_hi);
int iodev_allows_mmio(const struct io_device *d, uint64_t paddr, uint64_t len);
int iodev_allows_port(const struct io_device *d, uint16_t port);
int iodev_allows_irq(const struct io_device *d, int irq);
/* The one write to PCI configuration space reachable from ring 3, and only the
 * three decode bits of the device the caller's capability names. Bus mastering
 * is among them: on a machine with no IOMMU that is authority over ALL of
 * physical memory, bounded by who may turn it on and for what, never by where
 * the device then goes (docs/LIMITATIONS.md §2.12, SECURITY.md S44). */
#define IODEV_DECODE_IO         0x1u
#define IODEV_DECODE_MEM        0x2u
#define IODEV_DECODE_BUSMASTER  0x4u
int iodev_set_decode(const struct io_device *d, uint32_t flags);

/* TSS I/O-permission bitmap (gdt.c): tss_io_bitmap_init clears the bitmap at
 * boot; tss_set_io_device loads the running CPU's bitmap from ONE device's
 * declared port ranges and flips iomap_base, so a granted task's ring-3 in/out
 * reaches that device's ports and nothing else — every other port, and every
 * other task's in/out, #GPs. Passing IODEV_NONE deactivates the bitmap entirely.
 * See docs/design/console-server.md and src/kernel/pci.c. */
void tss_io_bitmap_init(void);
void tss_set_io_device(uint64_t devindex);
/* IRQ -> userspace notification bridge (idt.c): register/clear routing a hardware
 * IRQ to an async notification for a ring-3 driver. See docs/design/console-server.md. */
/* Every legacy line, not just the two the console needs. IRQ_NOTIFY_MAX is 16
 * because a PCI device's INTERRUPT_LINE is anywhere in 0..15, and the table is
 * indexed by line number. */
#define IRQ_NOTIFY_MAX 16
int  irq_notify_register(int irq, int task, uint32_t slot, uint32_t badge);
void irq_notify_clear_task(int task);
int  irq_notify_ack(int irq, int task);
void cpu_detect_features(void);
void init_syscall_instruction_path(void);
void ramfs_init(void);
int ata_init(void);   /* probe primary master; 1 = ATA disk present, 0 = absent */
int  ata_read(uint32_t lba, void *buf, uint32_t sectors);
int  ata_write(uint32_t lba, const void *buf, uint32_t sectors);
int  ata_flush(void);  /* FLUSH CACHE; 0 = on stable media, -1 = NOT durable */
void scheduler_init(void);
void smp_bringup(void);
void aslr_init_seed(void);
void spawn_initial_userspace_shell(void);
/* Launch the ring-3 init process (PID-1) — the first userspace task, which then
 * spawns and supervises the shell. Replaces spawn_initial_userspace_shell at boot. */
void spawn_initial_userspace_init(void);
int cpu_has_aesni(void);
void cpu_enable_protections(void);
/* Flush-on-switch: evict microarch state (IBPB / L1D flush / MDS VERW) between
 * distrusting ring-3 tasks. Gated on detected CPU support. */
void cpu_flush_microarch_state(void);
extern uint64_t g_domain_flushes;                 /* count of flushes issued (observability) */
int  sched_domain_switch_would_flush(int prev_user_task, int next_task);
#ifdef FLUSH_SELFTEST
void flush_selftest(void);
#endif
void paging_init(void);

void cap_init(void);
capability_t *cap_lookup(uint32_t slot, uint32_t required_rights);
bool cap_mint(uint32_t dest_slot, uint32_t src_slot, uint32_t new_rights);
bool cap_install_endpoint(uint32_t dest_slot, uint32_t object, uint32_t rights, uint32_t badge);
/* Install a freshly-minted capability of `type` naming `object` into the CURRENT
 * task's own cspace, under cap_lock and with the same authority guard,
 * reserved-slot rule and MAX_CAPS_PER_TASK accounting as cap_mint. The general
 * form of cap_install_endpoint, used by SYS_RETYPE to name a newly created
 * kernel object. */
bool cap_install_object(uint32_t dest_slot, uint32_t type, uint64_t object,
                        uint32_t rights, uint32_t badge);

/* Drop a capability the current task holds and return its budget. The
 * counterpart to cap_install_object: caps_in_use is incremented on NULL ->
 * occupied and is decremented ONLY here, so a per-operation mint without a
 * matching consume leaks toward MAX_CAPS_PER_TASK. NOT a revoke — it forgets one
 * slot in the caller's own cspace and touches no derived capability. */
bool cap_consume_slot(uint32_t dest_slot);
/* Mint the one-shot CAP_REPLY naming `sender` into TASK `pid`'s CAPSLOT_REPLY.
 *
 * The blocking-receive counterpart of the cap_install_object call at the end of
 * SYS_IPC_RECV (roadmap 1.3). It exists because a blocked receiver is completed
 * by the SENDER's syscall, on the sender's CPU, so the mint cannot go through
 * cap_install_object -- that installs into get_current_task()'s cspace, which is
 * the sender's.
 *
 * Deliberately NOT a general "install into another task" primitive: the type
 * (CAP_REPLY), the rights (WRITE), and the destination slot (CAPSLOT_REPLY) are
 * all fixed here rather than passed in, so it cannot be reused to place arbitrary
 * authority into an arbitrary cspace. The authority argument is the receiver's,
 * established when it proved READ on the endpoint to block on it; this only
 * completes the receive it was already entitled to. */
bool cap_install_reply_for(int pid, int sender);
/* Read-only view of the kernel root cnode, so the object-reachability sweep in
 * untyped.c can see kernel-held capabilities too. root_cnode is otherwise
 * file-private to capability.c and must stay that way: handing out a mutable
 * pointer would be an unaudited path around every locked cap-write. */
const capability_t *cap_root_cnode_ref(void);
bool cap_transfer(uint32_t dest_slot, uint32_t src_slot);
bool cap_move(uint32_t dest_slot, uint32_t src_slot);
/* Delegate the caller's src_slot into a supervised target's dest_slot through the
 * locked, accounted, rights-reducing cap-write path (SYS_CAP_GRANT). Authority
 * (CAP_TCB on target / admin) is checked by the caller. */
bool cap_grant_into(int target_pid, uint32_t dest_slot, uint32_t src_slot, uint32_t new_rights);

/* Duplicate `parent`'s cspace into `child` as DERIVED capabilities (SYS_FORK,
 * roadmap 2.3). Returns the number of slots copied, or negative. Every copy is a
 * child of the parent's capability in the derivation tree, so the child's
 * authority is a subtree of the parent's and every revocation that sweeps the
 * parent's sweeps the child's. What is deliberately NOT copied -- the identity
 * slots and CAP_REPLY -- and why, is at the definition. */
int cap_clone_cspace(int parent, int child);
bool cap_revoke(uint32_t slot);
bool cap_create_revocation_set(uint32_t target_slot, uint32_t rev_slot);
bool has_encrypted_storage_cap(void);


uint32_t cap_alloc_fresh_serial(void);

/* Lookup/use TOCTOU defense: snapshot a capability's identity, then
 * revalidate the slot still holds that exact identity (with the required
 * rights) at the point of use. Returns NULL on revoke/re-mint/generation bump. */
cap_snapshot_t cap_snapshot(const capability_t *c);
capability_t *cap_revalidate(uint32_t slot, uint32_t required_rights,
                             const cap_snapshot_t *snap);


capability_t *rust_cap_lookup(capability_t *cspace, uint32_t sz, uint32_t slot, uint32_t rights);
bool rust_cap_mint(capability_t *dest_array, uint32_t sz, uint32_t dest_slot,
                   uint32_t src_slot, uint32_t new_rights, uint32_t *next_serial, uint32_t caps_in_use);
bool rust_cap_transfer(capability_t *dest_array, uint32_t sz, uint32_t dest_slot,
                       uint32_t src_slot, uint32_t *next_serial);
/* Cross-cspace mint: delegate a cap derived from *src into dest_cspace[dest_slot]
 * with rights reduced to (new_rights & src->rights) and badge = src->serial.
 * No reserved-slot floor (grant endows a dominated child). Called under cap_lock. */
bool rust_cap_grant_into(const capability_t *src, capability_t *dest_cspace,
                         uint32_t dest_cspace_size, uint32_t dest_slot,
                         uint32_t new_rights, uint32_t *next_serial);
bool rust_cap_revoke(capability_t *cspace, uint32_t sz, uint32_t slot, uint32_t *next_serial);
bool rust_cap_revoke_by_values(capability_t *cspace, uint32_t sz, uint32_t target_serial, uint32_t target_badge, uint64_t target_obj);

/* One capability space, for the system-wide revocation sweep. Layout MUST match
 * `struct CSpaceDesc` in rust/src/capability.rs. */
typedef struct cspace_desc {
    capability_t *caps;
    uint32_t      size;
    uint32_t     *caps_in_use; /* owning task's counter; NULL to skip accounting */
} cspace_desc_t;

/* Authoritative, system-wide revocation: revokes target_slot in target_cspace
 * and sweeps every cspace in `spaces` for derived copies of the same lineage.
 * Must be called under cap_lock so the snapshot is stable. */
bool rust_cap_revoke_global(capability_t *target_cspace, uint32_t target_cspace_size,
                            uint32_t target_slot, uint32_t *target_caps_in_use,
                            const cspace_desc_t *spaces, uint32_t space_count,
                            uint32_t *next_serial);

/* Is fault address `a` a legitimate part of the faulting task's user address
 * space? Region-aware: the caller passes the task's image and heap bounds; the
 * fixed low-stack window is checked internally. `e` is the fault error code
 * (unused today). See rust/src/lib.rs. */
bool rust_validate_page_fault(uint64_t a, uint32_t e,
                              uint64_t image_base, uint64_t image_end,
                              uint64_t heap_start, uint64_t heap_end);
int  rust_handle_command(const uint8_t *cmd, size_t len);

/* Validated ELF header fields returned by rust_elf_validate_header (J10.1).
 * Layout mirrors `struct ElfHeaderInfo` in rust/src/lib.rs (same field order,
 * repr(C)); the offset asserts in loader.c pin the contract. Rust writes it, the
 * loader reads it only after rust_elf_validate_header returns 0. */
struct elf_header_info {
    uint64_t e_entry;    /* entry vaddr, zero-extended from the 32-/64-bit field */
    uint32_t e_phoff;    /* program-header table offset (loader plumbing is 32-bit) */
    uint16_t e_type;     /* 2 = ET_EXEC, 3 = ET_DYN */
    uint16_t e_machine;  /* 3 = EM_386, 62 = EM_X86_64 */
    uint16_t e_phnum;    /* number of program headers, validated to 1..8 */
    uint8_t  ei_class;   /* 1 = ELFCLASS32, 2 = ELFCLASS64 */
};

/* Parse+validate the staged ELF image header entirely in safe Rust: a malformed
 * header can never cause an out-of-bounds read in the parser. `buf`/`buf_len` is
 * the loader staging buffer (buf_len == MAX_PROGRAM_SIZE). Returns 0 and fills
 * `*out` on success, else the loader's negative error code (-2,-3,-4,-5,-6,-7,
 * -8,-17). See rust/src/lib.rs. */
int  rust_elf_validate_header(const uint8_t *buf, size_t buf_len, struct elf_header_info *out);

/* One validated PT_LOAD segment of the load plan (J10.2). Mirrors `struct
 * ElfLoadSegment` in rust/src/lib.rs; the offset asserts in loader.c pin it. */
struct elf_load_segment {
    uint64_t dest_va;   /* map target, validated in [USER_AREA_BASE, USER_MAX_VADDR) */
    uint32_t file_off;  /* offset of the file bytes in the staging buffer */
    uint32_t file_sz;   /* bytes to copy from the file (file_off+file_sz <= buf_len) */
    uint32_t mem_sz;    /* total mapped size; the [file_sz, mem_sz) tail is zero-filled */
    uint32_t flags;     /* ELF p_flags: PF_X=1, PF_W=2, PF_R=4 */
};

/* The validated load plan: up to 8 PT_LOAD segments (e_phnum is capped at 8 by
 * the header check) plus the load slide and image end. Mirrors `struct
 * ElfLoadPlan` in rust/src/lib.rs. */
struct elf_load_plan {
    uint64_t slide;               /* load bias applied to every p_vaddr */
    uint64_t max_va_end;          /* highest dest_va + mem_sz (the image end) */
    struct elf_load_segment segs[8];
    uint32_t nseg;                /* number of PT_LOAD segments, 1..8 */
};

/* Parse+validate the PT_LOAD program headers of the staged image in safe Rust
 * and return the load plan the C loader executes: a malformed program header can
 * never cause an out-of-bounds read (or a u32 length overflow) in the parser.
 * Returns 0 and fills `*out`, else the loader's negative code (-9,-10,-11,-12,
 * -13,-17). Requires the header already validated (ei_class/e_phoff/e_phnum from
 * rust_elf_validate_header). See rust/src/lib.rs. */
int  rust_elf_build_load_plan(const uint8_t *buf, size_t buf_len, uint8_t ei_class,
                              uint32_t e_phoff, uint16_t e_phnum, uint64_t load_base,
                              uint64_t user_area_base, uint64_t user_max_vaddr,
                              struct elf_load_plan *out);

/* The located i386 dynamic REL table (J10.3a). Mirrors `struct ElfI386RelocTable`
 * in rust/src/lib.rs; the offset asserts in loader.c pin it. nrel == 0 means the
 * image has no dynamic relocations. */
struct elf_i386_reloc_table {
    uint32_t rel_file_off;  /* file offset of the REL table in the staging buffer */
    uint32_t nrel;          /* number of 8-byte Elf32_Rel entries (<= 8192) */
};

/* Parse+validate the i386 dynamic REL table of the staged image in safe Rust: a
 * malformed dynamic section or REL table can never cause an out-of-bounds read in
 * the parser. Returns 0 and fills `*out` (out->nrel == 0 = no relocations), else
 * -16. The privileged read-modify-write apply stays in the C loader. */
int  rust_elf_i386_reloc_locate(const uint8_t *buf, size_t buf_len, uint32_t e_phoff,
                                uint16_t e_phnum, struct elf_i386_reloc_table *out);

/* Validate REL entry `k` and return its patch target (r_offset + slide) via
 * `*out_target`. Returns 0 (apply the RMW), 1 (skip — R_386_NONE), or -16
 * (reject). `seg_va`/`seg_memsz` are the load plan's PT_LOAD segments. */
int  rust_elf_i386_reloc_target(const uint8_t *buf, size_t buf_len, uint32_t rel_file_off,
                                uint32_t k, uint64_t slide, const uint64_t *seg_va,
                                const uint64_t *seg_memsz, uint32_t nseg, uint64_t *out_target);

/* The located x86-64 RELA + dynamic symbol tables (J10.3b). Mirrors `struct
 * ElfX8664RelocTable` in rust/src/lib.rs; the offset asserts in loader.c pin it.
 * nrela == 0 = no dynamic relocations; sym_file_off == 0 = no symbol table. */
struct elf_x86_64_reloc_table {
    uint64_t rela_file_off; /* file offset of the RELA table in the staging buffer */
    uint64_t sym_file_off;  /* file offset of the dynamic symbol table (0 = none) */
    uint64_t nrela;         /* number of 24-byte Elf64_Rela entries (<= 8192) */
};

/* Parse+validate the x86-64 RELA + symbol tables of the staged image in safe
 * Rust: no untrusted-offset read (including the GLOB_DAT symbol lookup) can walk
 * off the staging buffer. Returns 0 and fills `*out` (out->nrela == 0 = none),
 * else -16. The privileged copy_to_user apply stays in the C loader. */
int  rust_elf_x86_64_reloc_locate(const uint8_t *buf, size_t buf_len, uint32_t e_phoff,
                                  uint16_t e_phnum, struct elf_x86_64_reloc_table *out);

/* Validate RELA entry `k` and compute the (target, value) to write. Returns 0
 * (write *out_value at *out_target), 1 (skip — R_X86_64_NONE), or -16 (reject).
 * Because x86-64 relocations are a pure write, Rust computes the value (RELATIVE:
 * slide+addend; GLOB_DAT: the resolved symbol address); the loader only writes. */
int  rust_elf_x86_64_reloc_resolve(const uint8_t *buf, size_t buf_len, uint64_t rela_file_off,
                                   uint64_t sym_file_off, uint64_t k, uint64_t slide,
                                   uint64_t user_max_vaddr, const uint64_t *seg_va,
                                   const uint64_t *seg_memsz, uint32_t nseg,
                                   uint64_t *out_target, uint64_t *out_value);


int  do_useradd(uint32_t uid, uint32_t gid, const char *name, const char *pass);
int  do_userdel(uint32_t uid);
int  do_passwd(uint32_t target, const char *newpass);
int derive_and_store_user_file_key(uint32_t uid, const char *material, size_t material_len);


int  storage_mount(block_device_t *bd);
/* Unlock storage at login time: on first boot formats+seals; on subsequent boots
 * derives KEK from password, unwraps disk_key, derives volume/MAC keys, and
 * verifies the metadata HMAC.  Must be called after verify_password succeeds. */
int  storage_unlock(const char *password, size_t plen);
/* Re-wrap disk_key with a new password-derived KEK.  Call after a successful
 * password change so the on-disk wrapped key stays in sync with the login hash.
 * Requires storage to already be unlocked (disk_key in RAM).  Generates fresh
 * kek_salt + nonce for forward security, then writes the updated superblock. */
int  storage_rekey(const char *new_password, size_t plen);
int  storage_read_file_block(mounted_fs_t *mfs, uint64_t ino, uint64_t block, void *buf);
int  storage_write_file_block(mounted_fs_t *mfs, uint64_t ino, uint64_t block, const void *buf);
mounted_fs_t *storage_get_mounted_fs(void);
block_device_t *storage_get_default_device(void);
void storage_set_default_device(block_device_t *bd);
int storage_init(void);
int64_t storage_alloc_block(block_device_t *bd, fs_superblock_t *sb);
void storage_free_block(block_device_t *bd, fs_superblock_t *sb, uint64_t block);
int64_t storage_alloc_inode(block_device_t *bd, fs_superblock_t *sb);
void storage_free_inode(block_device_t *bd, fs_superblock_t *sb, uint64_t ino);
int  storage_read_inode(block_device_t *bd, fs_superblock_t *sb, uint64_t ino, on_disk_inode_t *inode_out);
int  storage_write_inode(block_device_t *bd, fs_superblock_t *sb, uint64_t ino, const on_disk_inode_t *inode);
/* Free all data blocks (direct + single-indirect) and the inode itself. Used by
 * the FS server's delete path via SYS_FS_INODE_FREE. */
int  storage_free_inode_blocks(mounted_fs_t *mfs, uint64_t ino);
/* Derives 64 bytes of per-block subkeys (enc_key32 ‖ mac_key32) from the volume
 * key via HKDF-SHA256, binding (ino, block) into the info string so every block
 * gets independent keys. */
int  storage_derive_block_keys(uint64_t ino, uint64_t block,
                               const uint8_t *vol_key, size_t vol_key_len,
                               uint8_t *enc_key32, uint8_t *mac_key32);
int  storage_block_read(uint64_t block, void *buf);
int  storage_block_write(uint64_t block, const void *buf);
int  do_rotate_keys(void);


int  ramfs_open(const char *path, int flags);
int  ramfs_create(const char *path, int mode);
int  ramfs_write(int fd, const void *buf, size_t len);
int  ramfs_read(int fd, void *buf, size_t len);
char serial2_read_char(void);
void serial_write_char(char c);


/* The legacy capfs syscalls (sys_fs_mint_file / lookup / create / delete /
 * readdir / get_root / read / write) were removed; those syscall numbers now
 * fail closed. */


int  copy_from_user(void *kdst, const void *usrc, size_t len);
int  copy_to_user(void *udst, const void *ksrc, size_t len);
int  user_protect_page(uint64_t vaddr, int writable, int executable);
/* 1 if the kernel's own mapping of `vaddr` is present. Used by the resume-%rsp
 * guards: guard pages live inside .bss and are armed by being made ABSENT, so
 * only a page-table question can tell a real stack from the guard beside it. */
int kern_addr_present(uint64_t vaddr);
uint64_t user_lookup_pte(uint64_t cr3, uint64_t vaddr);
#ifdef ELF_SELFTEST
void elf_loader_selftest(void);
#endif
#ifdef CPU_SELFTEST
void cpu_protections_selftest(void);
#endif
#ifdef PERCPU_SELFTEST
void percpu_selftest(void);   /* STR-derived CPU id vs the LAPIC, on every core */
#endif
#ifdef WX_SELFTEST
void wx_selftest(void);
#endif
#ifdef NZCOW_SELFTEST
void nzcow_selftest(void);   /* generic (non-zero) copy-on-write break test */
#endif
#ifdef SPAWN_OWNER_SELFTEST
/* Staged-image ownership ([G-11]): refuse a foreign arm, accept your own. */
void spawn_owner_selftest(void);
#endif
#ifdef ASPACE_SELFTEST
void aspace_selftest(void);
void free_user_aspace_for_test(uint64_t pml4_phys);
int  user_map_fresh_page_for_test(uint64_t pml4_phys, uint64_t vaddr, uint64_t flags);
void create_user_pagedir(uint32_t task_id);
#endif

/* Build task `child`'s address space as a copy-on-write duplicate of the tree at
 * `parent_cr3` (roadmap 2.3, SYS_FORK). Returns 0, or negative with the child's
 * cr3 left 0. The full argument -- what is shared, what is refused, and why a
 * mapped kernel object refuses the whole clone -- is at the definition. */
int clone_user_aspace(uint32_t child, uint64_t parent_cr3);
/* Map one 4 KiB physical device frame `phys` at `vaddr` in task `task_id`'s own
 * address space, user-accessible with `flags` (paging.c). The caller (the
 * SYS_MAP_PHYS handler) has already validated `phys` against the device
 * allowlist and `writable`; this only builds the PTE bits (always present + user
 * + non-executable, +writable), does the page-table plumbing, and flushes the TLB.
 * Returns 0 on success, negative on failure (bad task / no address space /
 * refused VA). */
int user_map_device_page(uint32_t task_id, uint64_t vaddr, uint64_t phys, uint64_t writable);

/* ---- Frame mapping (roadmap 2.1) ------------------------------------------
 * Map / unmap one untyped-carved KOBJ_FRAME in task `task_id`'s own address
 * space. `eff_rights` is the EFFECTIVE rights word -- the SYS_MAP_FRAME handler
 * has already intersected the capability's rights with what the caller asked
 * for, so the authority decision is made once, where the capability is, and is
 * never re-derived here. Turning it into PTE bits is paging.c's half, because
 * paging.c is the only file that defines them. Return 0 on success, -2 if
 * something is already mapped at `vaddr`, negative otherwise. */
int user_map_frame_page(uint32_t task_id, uint64_t vaddr, uint64_t phys, uint32_t eff_rights);
int user_unmap_frame_page(uint32_t task_id, uint64_t vaddr, uint64_t expect_phys);

/* The untyped region's own permanent reference over an arena page, so that a
 * dying task's page-table walk can never return frame bytes to the free page
 * stack. See the KOBJ_FRAME arm of kobj_alloc (untyped.c) for the full why. */
void     frame_pin_refcount(uint64_t phys_addr);
void     frame_unpin_refcount(uint64_t phys_addr);
uint32_t frame_map_refcount(uint64_t phys_addr);   /* 1 + mappings; >1 == mapped */

uint32_t get_free_user_pages(void);   /* paging.c — free frames in the user pool */
/* Set the runtime physical-pool size (frames), clamped to
 * [PHYS_POOL_MIN_PAGES, USER_PHYS_PAGES]. Must be called before paging_init,
 * which builds the free list. Driven by the E820 memory map at boot. */
void phys_set_pool_pages(uint32_t pages);
/* Boot registers saved by _start (multiboot.S): the multiboot2 magic and a
 * pointer to the boot-information structure. */
extern volatile uint32_t saved_mb_magic;
extern volatile uint32_t saved_mb_info;
#ifdef E820_SELFTEST
void e820_selftest(void);
#endif
#ifdef PREEMPT_SELFTEST
void preempt_selftest(void);
#endif
#ifdef SIGNAL_SELFTEST
void signal_selftest(void);
#endif
#ifdef TSD_SELFTEST
void tsd_selftest(void);
#endif
#ifdef FS_SELFTEST
void fs_selftest(void);
#endif
#if defined(FS_SELFTEST) || defined(NEWLIB_SELFTEST)
/* Shared by both FS harnesses: the newlib self-test also spawns + provisions
 * the fs_server so its client can exercise the real libc file paths. */
int  cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
#endif
#ifdef NEWLIB_SELFTEST
void newlib_selftest(void);
#endif
#ifdef BIGFILE_SELFTEST
void bigfile_selftest(void);
#endif
#ifdef SMP_SELFTEST
void smp_selftest(void);
#endif
#ifdef PROC_SELFTEST
void proc_selftest(void);
#endif
#ifdef NOTIFY_SELFTEST
void notify_selftest(void);
#endif
#ifdef KLOG_FORGE_SELFTEST
/* [H-2] witness: a ring-3 probe holding CAP_KERNEL_LOG(READ) proves it can
 * neither forge into nor evict from the kernel message ring via SYS_WRITE. */
void klog_forge_selftest(void);
#endif
#if defined(MAPPHYS_SELFTEST) || defined(IOPORT_SELFTEST) || defined(IRQ_SELFTEST) || defined(CONSOLE_SELFTEST) || defined(CONSOLE_ISOLATION_TEST) || defined(KLOG_FORGE_SELFTEST) || defined(DEVCAP_SELFTEST) || defined(NET_SELFTEST)
void mapphys_selftest(void);
void devcap_selftest(void);
void net_selftest(void);
void ioport_selftest(void);
void irq_selftest(void);
void console_selftest(void);
void console_isolation_selftest(void);
/* The map-phys harness endows its ring-3 probe with a CAP_IO_DEVICE cap by
 * copying it out of the root cnode, exactly as the FS/newlib harnesses do for
 * their server caps. The [H-2] harness uses it the same way for CAP_KERNEL_LOG,
 * and gets READ only -- root_cnode[15] mints no other right, which is what makes
 * that endowment a test of the gate rather than a way around it. */
int  cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
#endif


/* Capability-addressed IPC object resolution (audit finding C-1). Resolve a
 * CSPACE SLOT to the endpoint / notification index the capability there names,
 * enforcing type, the required right, and the lineage-generation check in one
 * place. Return 0 and write *out on success, negative on any failure. Defined in
 * syscall_ipc.c; the sole path from a userspace-supplied slot to a kernel IPC
 * object. */
int  ipc_ep_from_slot(uint32_t slot, uint32_t need_rights, uint32_t *out_ep);
int  ipc_notif_from_slot(uint32_t slot, uint32_t need_rights, uint32_t *out_slot);

int  sys_ipc_send(uint32_t ep_slot, const void *msg, size_t len);
int  sys_ipc_recv(uint32_t ep_slot, void *msg, size_t max_len);


bool     capability_validate_generation(const capability_t *cap);
/* Lineage generations are keyed by a capability's unique `serial` (finding 3.3),
 * not by `object`: each capability has its own generation cell, so an active,
 * precise use-after-revoke backstop no longer needs the old gen-0 immunity that
 * left every capability's snapshot un-invalidatable. Every C capability-creation
 * site stamps `cap.generation = rust_lineage_current(cap.serial)`. */
uint32_t rust_lineage_bump(uint32_t serial);
bool     rust_lineage_check(uint32_t serial, uint32_t gen);
uint32_t rust_lineage_current(uint32_t serial);

/* ---- Cryptography & entropy (audited primitives implemented in Rust) ---- */
/* SHA-256 suite */
int  rust_password_hash(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t *out, size_t out_len);
/* Argon2id password hash (rust/src/argon2.rs). memory-hard; `p_cost` lanes;
 * `mem` is a caller-owned scratch buffer of `mem_words` u64 (>= 128 * blocks,
 * blocks a multiple of 4*p_cost). Returns 0/-1. */
int  rust_argon2id_hash(const uint8_t *pwd, size_t pwd_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t t_cost, uint32_t m_cost, uint32_t p_cost,
                        uint64_t *mem, size_t mem_words,
                        uint8_t *out, size_t out_len);
int  rust_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len, uint8_t *out32);
/* Plain SHA-256 digest (boot-module manifest verification). */
int  rust_sha256(const uint8_t *data, size_t data_len, uint8_t *out32);
/* Tamper-evident audit log (rust/src/audit.rs). */
int  rust_audit_chain_init(const uint8_t *key, size_t key_len, uint8_t *out_head32);
int  rust_audit_chain_record(const uint8_t *key, size_t key_len, uint64_t seq,
                             const uint8_t *event, size_t event_len,
                             uint8_t *head32, uint8_t *out_mac32);
int  rust_audit_entry_mac(const uint8_t *key, size_t key_len, uint64_t seq,
                          const uint8_t *event, size_t event_len, uint8_t *out_mac32);
int  rust_audit_mac_eq(const uint8_t *a32, const uint8_t *b32);
/* Forward-secure (forward-integrity) audit log: the per-entry key is ratcheted
 * one-way and erased in place, so a kernel compromised at time t cannot forge or
 * alter any entry committed before t. `rust_audit_pub_*` maintain an unkeyed
 * running hash for a key-free self-check of the retained window. */
int  rust_audit_fs_genesis(const uint8_t *pepper, size_t pepper_len,
                           uint8_t *out_key32, uint8_t *out_head32);
int  rust_audit_fs_record(uint8_t *key32, uint64_t seq,
                          const uint8_t *event, size_t event_len,
                          uint8_t *head32, uint8_t *out_mac32);
int  rust_audit_pub_init(uint8_t *out32);
int  rust_audit_pub_extend(const uint8_t *prev32, uint64_t seq,
                           const uint8_t *mac32, uint8_t *out32);
int  rust_ct_eq(const uint8_t *a, const uint8_t *b, size_t len);
int  rust_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *salt, size_t salt_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out, size_t out_len);
/* ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (12-byte nonce, 16-byte tag).
 * seal encrypts buf[0..len] in place and writes a 16-byte tag; open verifies
 * the tag in constant time and decrypts in place only if authentic (returning
 * 0), else zeroes buf and returns -1. */
#define AEAD_NONCE_LEN 12
#define AEAD_TAG_LEN   16

/* Crypto metadata region: one 32-byte slot per physical block (nonce+tag+present+3pad).
 * 16 slots fit in one 512-byte sector → 64 sectors cover all BLOCKS_PER_DISK=1024 slots.
 * These constants drive both the on-disk layout (storage_format) and the in-memory
 * flush granularity (storage_encrypt_block). */
#define META_ENTRY_SIZE        32   /* must equal sizeof(struct block_crypto_meta) — asserted in storage.c */
#define META_ENTRIES_PER_BLOCK (BLOCK_SIZE / META_ENTRY_SIZE)
#define META_BLOCKS_COUNT      (BLOCKS_PER_DISK / META_ENTRIES_PER_BLOCK)
int  rust_aead_seal(const uint8_t *enc_key, const uint8_t *mac_key, const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    uint8_t *buf, size_t len, uint8_t *tag_out);
int  rust_aead_open(const uint8_t *enc_key, const uint8_t *mac_key, const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_len,
                    uint8_t *buf, size_t len, const uint8_t *tag);
/* ps presentation (rust/src/ps.rs): NUL-terminated static state label. */
const char *rust_task_state_name(uint32_t state);
/* Authentication / sudo throttling + privilege policy (rust/src/auth.rs) */
uint32_t rust_sudo_frame_rights(void);
bool     rust_auth_is_locked(uint64_t lockout_until, uint64_t now);
void     rust_auth_on_failure(uint32_t fail_count, uint64_t now,
                              uint32_t *out_count, uint64_t *out_lockout_until);
bool     rust_auth_global_locked(uint64_t now);
void     rust_auth_global_on_failure(uint64_t now);
void     rust_auth_global_on_success(void);
/* ChaCha20 CSPRNG */
void     rust_rng_add_entropy(const uint8_t *data, size_t len);
/* Both return false rather than serving output from an unseeded pool; every
 * caller must check. Use the secure_random_* wrappers below, which halt on a
 * refusal instead of leaving that decision to each call site. */
bool     rust_rng_fill(uint8_t *out, size_t len);
bool     rust_rng_u64_checked(uint64_t *out);
bool     rust_rng_is_seeded(void);
bool     rust_rdrand_u64(uint64_t *out);

/* C-side entropy helpers (crypto.c) */
int  cpu_has_rdrand(void);
void entropy_init(void);            /* gather hardware/timing entropy, seed CSPRNG */
void entropy_add_sample(uint64_t s);/* mix an opportunistic entropy sample */
void secure_random_bytes(void *out, size_t n);
uint64_t secure_random_u64(void);   /* one CSPRNG draw; halts if unseeded */
#ifdef RNG_UNSEEDED_PROBE
void rng_unseeded_probe(void);      /* [defect arm] see make smoke-rng-seed */
#endif
/* The compile-time stack-guard value, before stack_protector_init() swaps it for
 * a CSPRNG draw. Single source of truth: crypto.c initialises __stack_chk_guard
 * to this, and the STACKGUARD_SELFTEST asserts the live guard is NO LONGER this
 * (nor 0), i.e. the boot-time re-seed actually happened. The build is
 * reproducible, so this constant is published — a guard still equal to it is
 * effectively no protection at all. */
#define STACK_GUARD_COMPILE_DEFAULT 0x9c2f5a1e7b40d3e6ULL
void stack_protector_init(void);   /* crypto.c — call once, after entropy_init */
void stackguard_selftest(void);    /* selftest.c — asserts the guard was re-seeded */

/* Password KDF cost (PBKDF2-HMAC-SHA256 iterations). */
#define PASSWORD_KDF_ITERATIONS 120000U   /* legacy PBKDF2 cost (no longer used) */

/* Argon2id password-hashing cost (memory-hard, unlike the former PBKDF2):
 * m_cost KiB of scratch (== 1 KiB blocks) filled t_cost times over p_cost lanes.
 * 4 MiB / 3 passes / 1 lane is a strong, boot-feasible profile. The scratch
 * buffer is sized for the worst case at build time; password hashing runs
 * non-preemptibly under a syscall, so one shared static buffer is safe.
 * Adjust these three to retune cost; the scratch buffer resizes automatically.
 * (m_cost must be a multiple of 4*p_cost; the Rust side rounds down if not.) */
#define ARGON2_M_COST_KIB   4096U
#define ARGON2_T_COST       3U
#define ARGON2_P_COST       1U

/* Maximum heap size per task.  The demand pager allocates physical pages lazily
 * so this is a virtual address ceiling, not a pre-committed reservation.
 * 64 MiB fits comfortably in the 32-bit low-memory window without colliding
 * with typical stack placements (stacks grow down from below 0x80000000). */
#define USER_HEAP_MAX_SIZE  (64U * 1024U * 1024U)
/* Shared Argon2id wrapper using the kernel's single pre-allocated scratch buffer.
 * Safe only for sequential (non-concurrent) calls — all kernel Argon2id users
 * (login hash + KEK derivation) run sequentially inside a single syscall. */
int kernel_argon2id(const uint8_t *pwd, size_t plen,
                    const uint8_t *salt, size_t salt_len,
                    uint8_t *out, size_t out_len);


#define CAP_DIR                 12
#define CAP_FILE                13

#define CAP_RIGHT_FS_LOOKUP     (1u << 10)
#define CAP_RIGHT_FS_CREATE     (1u << 11)
#define CAP_RIGHT_FS_DELETE     (1u << 12)
#define CAP_RIGHT_FS_READ       (1u << 13)
#define CAP_RIGHT_FS_WRITE      (1u << 14)

#define FS_OBJ_DIR              2
#define FS_OBJ_FILE             1
#define FS_DATA_SIZE            4096
#define FS_MAX_CHILDREN         32


/* The capfs_* engine (legacy capability filesystem) was removed. */


int  ramfs_list(char *buf, size_t buflen);


void create_task(int id, uint64_t entry, uint64_t stack_top, uint64_t image_base,
                 uint32_t premap_pages);
void create_user_pagedir(uint32_t id);
/* Pages the currently-armed staged image will occupy once loaded (its PT_LOAD
 * span), so the image-window premap can be sized to the whole image. 0 callers
 * with no armed image pass 0 to create_task for the default. */
uint32_t staged_image_span_pages(void);
void switch_cr3(uint64_t cr3);
void drop_to_ring3(uint64_t entry, uint64_t stack);
void aslr_mix_entropy(uint64_t val);
addr_t   aslr_random_offset(uint64_t max_pages);
addr_t aslr_random_stack_top(addr_t top);

#endif
