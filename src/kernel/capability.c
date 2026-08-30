#include "kernel.h"

/*
 * FFI layout contract — mirror of the compile-time assertions in
 * rust/src/capability.rs. capability_t and the Rust `Capability` struct are the
 * same memory passed across the FFI; if a field is reordered/retyped in either
 * language, one of these assertions fails to compile. Offsets are identical on
 * 32- and 64-bit; only trailing padding differs, so we assert offsets.
 */
_Static_assert(__builtin_offsetof(capability_t, type)       == 0,  "cap.type offset");
_Static_assert(__builtin_offsetof(capability_t, rights)     == 4,  "cap.rights offset");
_Static_assert(__builtin_offsetof(capability_t, object)     == 8,  "cap.object offset");
_Static_assert(__builtin_offsetof(capability_t, badge)      == 16, "cap.badge offset");
_Static_assert(__builtin_offsetof(capability_t, serial)     == 20, "cap.serial offset");
_Static_assert(__builtin_offsetof(capability_t, generation) == 24, "cap.generation offset");
_Static_assert(CAP_NULL == 0, "CAP_NULL must be 0 (matches Rust)");

extern tcb_t tasks[MAX_TASKS];

#define CNODE_SIZE 256
#define KERNEL_RESERVED_CAPS 4

static struct capability root_cnode[CNODE_SIZE];

static uint32_t cap_next_serial = 0x00010000U;

#define MAX_REV_SETS 8


uint32_t cap_alloc_fresh_serial(void) {
    /* Wrap logic lives once, in Rust (assign_fresh_serial); we only own the lock
     * and the counter here. Keeps C and Rust serial generation from drifting. */
    spin_lock(&cap_lock);
    uint32_t s = rust_cap_alloc_serial(&cap_next_serial);
    spin_unlock(&cap_lock);
    return s;
}

/*
 * Lineage / generation tracking is owned entirely by the safe-Rust authority
 * (rust/src/capability.rs, LINEAGE_GEN). The kernel previously kept a second,
 * independently-hashed `lineages[]` table here; the two could desync, letting a
 * stale derived capability pass one generation check while the other lineage had
 * already been bumped (use-after-revoke). The C table has been removed: every
 * bump goes through rust_lineage_bump (inside rust_cap_revoke / *_by_values) and
 * every check goes through rust_lineage_check via the thin wrapper below.
 */
bool capability_validate_generation(const capability_t *cap){
    if(!cap||cap->type==CAP_NULL) return false;
    /* Serial-keyed generation check (finding 3.3): strict equality against the
     * capability's own serial cell, so a revoked capability (or a detached
     * snapshot of one) fails even when it carries the old always-valid gen 0. */
    return rust_lineage_check(cap->serial, cap->generation);
}

static struct {
    uint32_t target_slot;
    uint32_t badge;
    int      valid;
} rev_sets[MAX_REV_SETS];

void cap_init(void) {
    for (int i = 0; i < CNODE_SIZE; i++) {
        root_cnode[i].type = CAP_NULL;
        root_cnode[i].rights = 0;
        root_cnode[i].object = 0;
        root_cnode[i].badge = 0;
        root_cnode[i].serial = 0;
    }
    root_cnode[0].type = CAP_TCB;
    root_cnode[0].rights = CAP_RIGHT_ALL;
    root_cnode[0].object = 0;
    root_cnode[0].badge = 0;
    root_cnode[0].serial = 0xC0DE0001U;
    root_cnode[0].generation = 0;

    root_cnode[1].type = CAP_NOTIFICATION;
    root_cnode[1].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    root_cnode[1].object = 0;
    root_cnode[1].badge = 0;
    root_cnode[1].serial = 0xC0DE0002U;
    root_cnode[1].generation = 0;

    root_cnode[2].type = CAP_ENDPOINT;
    root_cnode[2].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_GRANT;
    root_cnode[2].object = 0;
    root_cnode[2].badge = 0;
    root_cnode[2].serial = 0xC0DE0003U;
    root_cnode[2].generation = 0;

    root_cnode[3].type = CAP_FRAME;
    root_cnode[3].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC;
    root_cnode[3].object = USER_VIRT_BASE;
    root_cnode[3].badge = 0;
    root_cnode[3].serial = 0xC0DE0004U;
    root_cnode[3].generation = 0;

    root_cnode[6].type   = CAP_USER;
    root_cnode[6].rights = CAP_RIGHT_ALL;
    root_cnode[6].object = 0;
    root_cnode[6].badge  = 0;
    root_cnode[6].serial = 0xC0DE0006U;
    root_cnode[6].generation = 0;

    root_cnode[7].type   = CAP_AUDIT;
    root_cnode[7].rights = CAP_RIGHT_READ | CAP_RIGHT_AUDIT_WRITE;
    root_cnode[7].object = 0;
    root_cnode[7].badge  = 0;
    root_cnode[7].serial = 0xC0DE0007U;
    root_cnode[7].generation = 0;

    
    root_cnode[8].type   = CAP_CONSOLE;
    root_cnode[8].rights = CAP_RIGHT_ALL;
    root_cnode[8].object = 0;
    root_cnode[8].badge  = 0;
    root_cnode[8].serial = 0xC0DE0008U;
    root_cnode[8].generation = 0;

    
    root_cnode[9].type   = CAP_ENCRYPTED_STORAGE;
    root_cnode[9].rights = CAP_RIGHT_ALL;
    root_cnode[9].object = 0;
    root_cnode[9].badge  = 0;
    root_cnode[9].serial = 0xC0DE0009U;
    root_cnode[9].generation = 0;

    /* Hardware device authority (CAP_IO_DEVICE): the primordial cap the console
     * server is endowed with (via cap_install_from_root) to reach the
     * device-hardware syscalls -- SYS_MAP_PHYS, SYS_IOPORT_GRANT, SYS_IRQ_REGISTER.
     *
     * `object` names ONE device now: IODEV_PLATFORM, the legacy console hardware
     * (VGA, the UARTs, the PS/2 controller, the PIT). It used to be 0 and to mean
     * nothing at all — the syscalls resolved the console from compiled-in
     * constants — so this capability conferred the console on anyone holding the
     * type, and there was no way to express a driver for anything else. See
     * src/kernel/pci.c. Nothing but console_server is given a copy. */
    root_cnode[10].type   = CAP_IO_DEVICE;
    root_cnode[10].rights = CAP_RIGHT_ALL;
    root_cnode[10].object = IODEV_PLATFORM;
    root_cnode[10].badge  = 0;
    root_cnode[10].serial = 0xC0DE000AU;
    root_cnode[10].generation = 0;

    /* ---- Service endpoint roots (audit finding C-1) -----------------------
     *
     * With IPC capability-addressed, a task can only reach a service through a
     * capability naming that service's endpoint. These are the primordial
     * originals; init is endowed with copies (cap_install_from_root) and
     * delegates them onward to exactly the servers and clients that need them.
     *
     * The listen/client split is what enforces the direction of trust. A LISTEN
     * capability carries READ (the receive right), so its holder may dequeue
     * requests and answer them with SYS_IPC_REPLY_TO — that is the server. A
     * CLIENT capability carries WRITE only, so its holder may send and nothing
     * else. Without the split, any client holding the same capability as the
     * server could intercept its peers' requests and forge its replies, which was
     * exactly the C-1 attack. */

    /* Console service listen (console_server): receive + reply. */
    root_cnode[11].type   = CAP_ENDPOINT;
    root_cnode[11].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    root_cnode[11].object = CON_EP_REQ;
    root_cnode[11].badge  = 0;
    root_cnode[11].serial = 0xC0DE000BU;
    root_cnode[11].generation = 0;

    /* Console service client (shell and its descendants): send only. */
    root_cnode[12].type   = CAP_ENDPOINT;
    root_cnode[12].rights = CAP_RIGHT_WRITE;
    root_cnode[12].object = CON_EP_REQ;
    root_cnode[12].badge  = 0;
    root_cnode[12].serial = 0xC0DE000CU;
    root_cnode[12].generation = 0;

    /* Filesystem service listen (fs_server): receive + reply. Clients do NOT get
     * a copy of this — they acquire a WRITE-only capability at runtime through
     * SYS_CONNECT_FS_SERVER. */
    root_cnode[13].type   = CAP_ENDPOINT;
    root_cnode[13].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    root_cnode[13].object = FS_EP_REQ;
    root_cnode[13].badge  = 0;
    root_cnode[13].serial = 0xC0DE000DU;
    root_cnode[13].generation = 0;

    /* Authority formerly carried by ambient `uid == 0` (finding I-1). Minted
     * here so it can be delegated explicitly and, crucially, REVOKED — an
     * ambient uid check can never be withdrawn from one task without changing
     * its identity, which is why root was such a blunt instrument. */
    root_cnode[15].type   = CAP_KERNEL_LOG;
    root_cnode[15].rights = CAP_RIGHT_READ;
    root_cnode[15].object = 0;
    root_cnode[15].badge  = 0;
    root_cnode[15].serial = 0xC0DE000FU;
    root_cnode[15].generation = 0;

    root_cnode[16].type   = CAP_BOOT_MODULE;
    root_cnode[16].rights = CAP_RIGHT_READ;
    root_cnode[16].object = 0;
    root_cnode[16].badge  = 0;
    root_cnode[16].serial = 0xC0DE0010U;
    root_cnode[16].generation = 0;

    /* The init <-> fs_server "provisioning finished" rendezvous notification.
     * Notifications are capability-addressed too (finding C-2): without this,
     * any task could forge the ready badge, or forge IRQ delivery to a ring-3
     * driver, since SYS_IRQ_REGISTER routes hardware interrupts to these slots. */
    root_cnode[14].type   = CAP_NOTIFICATION;
    root_cnode[14].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    root_cnode[14].object = NOTIF_FS_READY;
    root_cnode[14].badge  = 0;
    root_cnode[14].serial = 0xC0DE000EU;
    root_cnode[14].generation = 0;

    /* Untyped memory (roadmap 0.3, finding I-7): authority to CREATE kernel
     * objects, which until now was not authority anyone held — object storage
     * was a `.bss` array and creation was ambient. This names UNTYPED_ROOT, the
     * user-facing half of the arena; init is endowed with a copy and delegates
     * bounded regions onward.
     *
     * UNTYPED_KERNEL deliberately has NO primordial capability. The kernel's own
     * cspace reserve must not be nameable from ring 3 at all — not narrowed, not
     * gated, not present — so that no userspace allocation pattern can starve
     * task creation. untyped_from_slot refuses it a second time in case one ever
     * appears by other means. */
    root_cnode[17].type   = CAP_UNTYPED;
    root_cnode[17].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_GRANT |
                            CAP_RIGHT_MINT | CAP_RIGHT_REVOKE;
    root_cnode[17].object = UNTYPED_ROOT;
    root_cnode[17].badge  = 0;
    root_cnode[17].serial = 0xC0DE0011U;
    root_cnode[17].generation = 0;

    /* CAP_DEBUG (roadmap 3.6): observation, and nothing else. READ-only at the
     * root, so no delegation can widen it -- rights only ever narrow, so a
     * primordial that never held WRITE cannot produce a descendant that does.
     * init delegates it to the shell, which is what lets `ps` and `capview`
     * work without the CAP_AUDIT that also rotates the audit chain's keys. */
    root_cnode[18].type   = CAP_DEBUG;
    root_cnode[18].rights = CAP_RIGHT_READ;
    root_cnode[18].object = 0;
    root_cnode[18].badge  = 0;
    root_cnode[18].serial = 0xC0DE0012U;
    root_cnode[18].generation = 0;

    /* The network device, if this machine has one (root[19]).
     *
     * Unlike every other root above, this one is CONDITIONAL: iodev_init has
     * already run, and if no PCI network controller was enumerated the slot stays
     * CAP_NULL. That is the fail-closed direction — a machine with no NIC has no
     * capability naming one, so nothing can be delegated and a driver started
     * anyway is refused at its first syscall rather than handed a capability that
     * resolves to whatever happens to sit at that index.
     *
     * init delegates this to a network server exactly as it delegates root[10] to
     * console_server. The two are the demonstration that hardware authority is now
     * divisible: neither capability reaches the other's device. */
    uint64_t nic = iodev_first_of_class(IODEV_CLASS_NETWORK);
    if (nic != IODEV_NONE) {
        root_cnode[19].type   = CAP_IO_DEVICE;
        root_cnode[19].rights = CAP_RIGHT_ALL;
        root_cnode[19].object = nic;
        root_cnode[19].badge  = 0;
        root_cnode[19].serial = 0xC0DE0013U;
        root_cnode[19].generation = 0;
    }

    /* Shared library text (root[20]), roadmap 2.5 / S49.
     *
     * READ | EXEC and deliberately NOT WRITE. Every capability a task receives
     * over the shared library's pages descends from this one, and rights only
     * ever narrow on delegation -- so a primordial that never held WRITE cannot
     * produce a descendant that does, and there is no path by which any task
     * obtains a writable mapping of code another task is executing. That is the
     * whole enforcement; the loader's read-only intent would be advice without
     * it.
     *
     * The object is overridden per install (cap_install_from_root's 4th
     * argument), so this one primordial names every frame of the library in
     * turn. */
    root_cnode[20].type   = CAP_FRAME;
#ifdef SHLIB_TEXT_WRITABLE
    /* Control arm: the primordial carries WRITE, so a task can obtain a writable
     * mapping of shared library text and patch code another task executes. The
     * whole of S49 is this one bit. See make smoke-shlib-writable-control. */
    root_cnode[20].rights = CAP_RIGHT_READ | CAP_RIGHT_EXEC | CAP_RIGHT_WRITE;
#else
    root_cnode[20].rights = CAP_RIGHT_READ | CAP_RIGHT_EXEC;
#endif
    root_cnode[20].object = 0;
    root_cnode[20].badge  = 0;
    root_cnode[20].serial = 0xC0DE0014U;
    root_cnode[20].generation = 0;

    /* Shared library DATA (root[21]), roadmap 2.5 / S50.
     *
     * READ | WRITE and deliberately NOT EXEC -- the mirror image of root[20]
     * above, and the two are separate primordials rather than one because they
     * carry opposite rights for opposite reasons. Text must never be writable
     * (S49: one task patching code another executes). Data must never be
     * executable (W^X: a task can write this page, so it must not be able to
     * jump into what it wrote).
     *
     * A page endowed from this primordial is a PRIVATE frame that
     * shlib_instantiate_data carved and initialised for one task; the object is
     * overridden per install, as it is for root[20]. Nothing endowed from here
     * is ever shared, which is the whole of S50 -- and note the property is not
     * enforced by these rights, which say nothing about sharing. It is enforced
     * by the frame the object names being a fresh one per task. */
    root_cnode[21].type   = CAP_FRAME;
    root_cnode[21].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    root_cnode[21].object = 0;
    root_cnode[21].badge  = 0;
    root_cnode[21].serial = 0xC0DE0015U;
    root_cnode[21].generation = 0;

    cap_next_serial = 0x00010000U;

    for (int i = 0; i < MAX_REV_SETS; i++) rev_sets[i].valid = 0;
    /* Lineage generations live in the Rust authority (LINEAGE_GEN); nothing to
     * initialize here — it is zeroed in the static and bumped lazily. */
}

/* Install a copy of a primordial root capability into a task's cspace slot with
 * a fresh serial (so cap_lookup accepts it). Used to bootstrap the ring-3 init
 * process with the capabilities it delegates onward (spawn_initial_userspace_init)
 * and by the FS/process-control self-test harnesses; root_cnode is otherwise
 * file-private. */
int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object) {
    extern tcb_t tasks[MAX_TASKS];
    if (pid < 0 || pid >= MAX_TASKS || slot >= CNODE_SIZE || root_slot >= CNODE_SIZE) return -1;
    if (!tasks[pid].cspace) return -1;
    uint32_t serial = cap_alloc_fresh_serial();
    spin_lock(&cap_lock);
    tasks[pid].cspace[slot]            = root_cnode[root_slot];
    tasks[pid].cspace[slot].object     = object;
    tasks[pid].cspace[slot].serial     = serial;
    /* Stamp the fresh serial's current generation so the serial-keyed backstop
     * is active for this copied-from-root capability (finding 3.3), and it is
     * born valid even if the serial's hash cell was bumped by a prior revoke. */
    tasks[pid].cspace[slot].generation = rust_lineage_current(serial);
    spin_unlock(&cap_lock);
    return 0;
}

static bool caller_has_authority(void); /* defined below; the no-ambient guard */

/* Install a fresh endpoint capability into the CURRENT task's own cspace under
 * cap_lock, with the same authority guard, reserved-slot rule, and caps_in_use
 * accounting as cap_mint(). Used by SYS_CONNECT_FS_SERVER: any task may connect
 * to the fs_server (the server is a reference monitor that authorizes every
 * request by kernel-attested identity, so connecting grants no file access on
 * its own), but the cap write must go through the same locked discipline as
 * every other cap write rather than a raw, unsynchronised cspace store that
 * races a concurrent rust_cap_revoke_global sweep under SMP and never counts
 * against MAX_CAPS_PER_TASK. Returns false on authority failure, a reserved or
 * out-of-range slot, or when the task is at its capability ceiling. */
bool cap_install_object(uint32_t dest_slot, uint32_t type, uint64_t object,
                        uint32_t rights, uint32_t badge) {
    /* Allocate the serial before taking cap_lock: cap_alloc_fresh_serial()
     * takes the same (non-recursive) lock, so ordering it inside would deadlock
     * (mirrors cap_create_revocation_set). */
    uint32_t serial = cap_alloc_fresh_serial();
    spin_lock(&cap_lock);
    if (!caller_has_authority()) { spin_unlock(&cap_lock); return false; }
    int cur = get_current_task();
    struct capability *cspace = tasks[cur].cspace;
    uint32_t cspace_sz = tasks[cur].cspace_size ? tasks[cur].cspace_size : CNODE_SIZE;
    if (!cspace || dest_slot < KERNEL_RESERVED_CAPS || dest_slot >= cspace_sz) {
        spin_unlock(&cap_lock);
        return false;
    }
    bool was_null = (cspace[dest_slot].type == CAP_NULL);
    if (was_null && tasks[cur].caps_in_use >= MAX_CAPS_PER_TASK) {
        spin_unlock(&cap_lock);
        return false;
    }
    cspace[dest_slot].type       = type;
    cspace[dest_slot].rights     = rights;
    cspace[dest_slot].object     = object;
    cspace[dest_slot].badge      = badge;
    cspace[dest_slot].serial     = serial;
    cspace[dest_slot].generation = rust_lineage_current(serial); /* finding 3.3 */
    if (was_null) tasks[cur].caps_in_use++;
    spin_unlock(&cap_lock);
    return true;
}

bool cap_install_endpoint(uint32_t dest_slot, uint32_t object,
                          uint32_t rights, uint32_t badge) {
    return cap_install_object(dest_slot, CAP_ENDPOINT, (uint64_t)object, rights, badge);
}

/* Mint the one-shot reply right into ANOTHER task's cspace — the blocking
 * receiver's. See the header for why this is not, and must not become, a general
 * cross-cspace install: type, rights and slot are all fixed here.
 *
 * No caller_has_authority() check, and that is the deliberate part. The guard
 * asks whether the CURRENT task may mint, but the current task here is the
 * sender, which is not the one acquiring the right — the receiver is, and it
 * proved its authority by holding READ on the endpoint when it blocked. Applying
 * the caller's guard would make a receive succeed or fail according to the
 * authority of whichever client happened to wake it, which is exactly the kind of
 * ambient-authority coupling roadmap 0.2 removed. The accounting (caps_in_use on
 * a NULL -> occupied transition, the ceiling) is the receiver's and is kept. */
bool cap_install_reply_for(int pid, int sender) {
    if (pid <= 0 || pid >= MAX_TASKS) return false;
    if (sender <= 0 || sender >= MAX_TASKS) return false;
    uint32_t serial = cap_alloc_fresh_serial();   /* takes cap_lock: before it */
    spin_lock(&cap_lock);
    struct capability *cspace = tasks[pid].cspace;
    uint32_t cspace_sz = tasks[pid].cspace_size ? tasks[pid].cspace_size : CNODE_SIZE;
    if (!cspace || CAPSLOT_REPLY >= cspace_sz) { spin_unlock(&cap_lock); return false; }
    bool was_null = (cspace[CAPSLOT_REPLY].type == CAP_NULL);
    if (was_null && tasks[pid].caps_in_use >= MAX_CAPS_PER_TASK) {
        spin_unlock(&cap_lock);
        return false;
    }
    cspace[CAPSLOT_REPLY].type       = CAP_REPLY;
    cspace[CAPSLOT_REPLY].rights     = CAP_RIGHT_WRITE;
    cspace[CAPSLOT_REPLY].object     = (uint64_t)sender;
    cspace[CAPSLOT_REPLY].badge      = 0;
    cspace[CAPSLOT_REPLY].serial     = serial;
    cspace[CAPSLOT_REPLY].generation = rust_lineage_current(serial);
    if (was_null) tasks[pid].caps_in_use++;
    spin_unlock(&cap_lock);
    return true;
}

/* Drop a capability the CURRENT task holds, returning its slot AND its budget.
 *
 * This is the counterpart cap_install_object never had, and its absence is a
 * trap: `caps_in_use` is incremented whenever a slot goes NULL -> occupied and
 * was decremented NOWHERE in the tree. Overwriting a slot with a CAP_NULL via
 * cap_install_object therefore does not free the count — so a per-operation mint
 * (CAP_REPLY, minted on every SYS_IPC_RECV) would leak one count per receive and
 * wedge every long-running server at MAX_CAPS_PER_TASK: after 128 requests the
 * mint fails, the server can no longer answer anyone, and the failure arrives as
 * a hang thousands of messages after the mistake. Short tests would never see it.
 *
 * NOT a revoke. Revocation tears down a derivation subtree across every cspace
 * (rust_cap_revoke_global); this only forgets one slot in the caller's own. That
 * is the correct primitive for consuming a one-shot right, and the wrong one for
 * withdrawing authority you handed to somebody else — do not reach for it there.
 *
 * No authority check: a task may always reduce its own authority, and requiring
 * one would let an unrelated failure strand a consumed capability in place. */
bool cap_consume_slot(uint32_t dest_slot) {
    spin_lock(&cap_lock);
    int cur = get_current_task();
    struct capability *cspace = tasks[cur].cspace;
    uint32_t cspace_sz = tasks[cur].cspace_size ? tasks[cur].cspace_size : CNODE_SIZE;
    if (!cspace || dest_slot < KERNEL_RESERVED_CAPS || dest_slot >= cspace_sz) {
        spin_unlock(&cap_lock);
        return false;
    }
    if (cspace[dest_slot].type != CAP_NULL) {
        cspace[dest_slot].type       = CAP_NULL;
        cspace[dest_slot].rights     = 0;
        cspace[dest_slot].object     = 0;
        cspace[dest_slot].badge      = 0;
        /* serial 0 is what cap_lookup reads as "empty"; leaving a live serial on
         * a CAP_NULL slot would make the slot look occupied to the lineage check
         * while carrying no type. */
        cspace[dest_slot].serial     = 0;
        cspace[dest_slot].generation = 0;
        if (tasks[cur].caps_in_use > 0) tasks[cur].caps_in_use--;
    }
    spin_unlock(&cap_lock);
    return true;
}

/* Release the capabilities a dead task held. Called from task_teardown.
 *
 * ---- WHAT "RECLAIM" MEANS HERE, AND WHAT IT MUST NOT MEAN -----------------
 *
 * `docs/LIMITATIONS.md`, `ROADMAP.md` and `ARCHITECTURE.md` all carried a line
 * about "reclaiming a dead task's cspace", blocked on `cap_lookup`'s root-cnode
 * fallback (removed 2026-08-30, S55). Read as "give the bytes back", that is not
 * merely unimplemented -- it is the one thing this allocator exists to forbid,
 * and doing it would break the system in two independent ways:
 *
 *  1. The arena is a MONOTONIC BUMP allocator, and `untyped.c`'s header says why
 *     in as many words: "This is seL4's rule and it is a safety property, not a
 *     simplification. With a free list, an object's bytes can be handed straight
 *     back out and retyped as a DIFFERENT class while a stale capability still
 *     names the old address -- the classic type-confusion-through-reuse."
 *     Returning a cspace's bytes reintroduces exactly that.
 *
 *  2. `UNTYPED_KERNEL_BYTES` is sized at EXACTLY `MAX_TASKS` cspaces. The
 *     watermark never rewinds, so a free-then-reallocate would consume a second
 *     cspace's worth for the same slot and the reserve would be exhausted after
 *     `MAX_TASKS` task deaths -- at which point `create_task` halts the machine,
 *     because a task with no cspace must not run.
 *
 * The codebase already had the right word for what IS reclaimable, in
 * `destroy_dyn_endpoint`: "The bytes stay consumed in the untyped region (bump
 * discipline); only the name is reclaimed." A cspace's bytes belong to its task
 * SLOT for the life of the boot, exactly as `cspace_pool[id]` did. What is
 * reclaimed is its CONTENTS.
 *
 * ---- WHY THIS IS NOT ALREADY DONE BY create_task ---------------------------
 *
 * It is, eventually: `create_task` zeroes the whole cspace before installing the
 * new task's capabilities, precisely so a dead task's `CAP_USER`/`CAP_CONSOLE`
 * cannot survive into the next occupant. So the authority does end -- WHEN THE
 * SLOT IS NEXT USED, which may be never.
 *
 * Between death and reuse the dead task's capabilities sit in memory, and three
 * separate readers each avoid them by testing `state == 0`: `mark_reachable`
 * (untyped.c) skips dead cspaces when deciding which retyped objects are still
 * named, `h_cap_enumerate` refuses to report them, and `create_task` overwrites
 * them. The property "a task's authority ends when the task does" is therefore
 * held by three readers agreeing about a flag, rather than by the data. Add a
 * fourth reader that forgets the check and it is an escalation; that is the same
 * shape as the `cap_lookup` fallback this unblocks, and as S38's arena guard,
 * whose protections were "circumstances rather than properties".
 *
 * Clearing here makes the cspace of a dead task EMPTY, so a reader that forgets
 * the flag finds nothing rather than everything. `create_task`'s zeroing stays:
 * it now defends against a slot that was never torn down (task 0, and the first
 * use of any slot) rather than against a dead task's leftovers, and belt and
 * braces on the authority of the next occupant is not where to economise.
 *
 * ---- ORDERING ------------------------------------------------------------
 *
 * task_teardown calls this BEFORE kobj_gc(). The sweep then sees an empty
 * cspace rather than relying on `state == 0` to skip a full one, so the two
 * agree by construction instead of by coincidence. Objects this task was the
 * last namer of are collected on that same pass, as they already were.
 *
 * No authority check, and none is possible: the caller is the kernel tearing a
 * task down, not a task acting. It is idempotent, so the double-teardown paths
 * (SYS_EXIT racing a fault) cost a second pass and nothing else.
 *
 * Taking cap_lock here is safe from every teardown path, checked rather than
 * assumed: h_exit, h_kill and h_signal hold no lock when they call
 * task_teardown, and on the fault paths (idt.c) task_teardown is, as the note
 * there says, "the first thing on that path to take a lock at all". It nests
 * inside nothing -- sched_raw_lock is released before this runs and kobj_gc's
 * ut_lock is taken after it.
 *
 * `SECURITY.md` **S56**. */
void cap_release_cspace(int id)
{
    if (id <= 0 || id >= MAX_TASKS) return;

    spin_lock(&cap_lock);
    struct capability *cs = tasks[id].cspace;
    if (cs) {
        uint32_t sz = tasks[id].cspace_size ? tasks[id].cspace_size : CNODE_SIZE;
        if (sz > CNODE_SIZE) sz = CNODE_SIZE;
        for (uint32_t s = 0; s < sz; s++) {
            cs[s].type       = CAP_NULL;
            cs[s].rights     = 0;
            cs[s].object     = 0;
            cs[s].badge      = 0;
            /* serial 0 is what cap_lookup reads as "empty"; a live serial on a
             * CAP_NULL slot would look occupied to the lineage check while
             * carrying no type. Same reason cap_consume_slot clears it. */
            cs[s].serial     = 0;
            cs[s].generation = 0;
        }
    }
    /* The count follows the contents. Left alone it would describe a cspace that
     * no longer holds anything, and `ps` reports it. */
    tasks[id].caps_in_use = 0;
    spin_unlock(&cap_lock);
}

const capability_t *cap_root_cnode_ref(void) { return root_cnode; }

/* THE RESOLVER FAILS CLOSED. It did not until 2026-08-30, and the `else` it used
 * to have was reached two different ways -- only one of which anybody had
 * written down.
 *
 *     if (cspace && slot < cspace_sz) { ...the caller's own cspace... }
 *     else                            { ...root_cnode...              }
 *
 * (1) A task with NO CSPACE resolved every slot against the primordial root
 *     cnode: CAP_TCB over task 0, the console, the kernel log, the user
 *     database, the object store. `scheduler.c` names this and calls it what it
 *     is -- "a freed-and-nulled cspace on a slot anything still consults would
 *     be an authority ESCALATION, not a crash" -- and it is the stated reason a
 *     dead task's cspace cannot be reclaimed, which keeps [I-7] open.
 *
 * (2) A task asking for a slot PAST ITS OWN CSPACE got `root_cnode[slot]`. That
 *     one was not documented anywhere. It is the same escalation reached by
 *     arithmetic rather than by a null pointer, and it needs no missing cspace
 *     at all -- only a cspace shorter than CNODE_SIZE.
 *
 * BOTH WERE UNREACHABLE, AND BOTH BY CIRCUMSTANCE RATHER THAN BY PROPERTY, which
 * is the distinction this repository keeps paying to learn. (1) needs
 * `create_task` to keep halting rather than run a task whose cspace allocation
 * failed. (2) needs `create_task` to keep setting `cspace_size = CNODE_SIZE` for
 * every task -- a single assignment, in another file, whose being a constant is
 * the whole of the argument. Neither is a statement about `cap_lookup`, and
 * `cap_lookup` is the function every capability gate in the kernel resolves
 * through.
 *
 * TASK 0 IS THE ONE LEGITIMATE CALLER OF THE ROOT CNODE, and the rule is not new
 * here: `caller_has_authority()` below already encodes exactly it (`cur == 0 ||
 * tasks[cur].cspace != NULL`) for the mutating operations, so that the
 * "cspace == root_cnode" rights exemption in `cap_mint`/`cap_transfer` provably
 * means "kernel only". The reader had it and the resolver did not; now both do.
 *
 * The generation check stays where it was: a capability that resolves but whose
 * generation is stale is refused, so a revoked slot cannot be used through a
 * pointer obtained before the revoke.
 *
 * `SECURITY.md` **S55**. */
struct capability *cap_lookup(uint32_t slot, uint32_t required_rights) {
    if (slot >= CNODE_SIZE) return NULL;

    int cur = get_current_task();
    struct capability *cspace = tasks[cur].cspace;
    uint32_t cspace_sz = tasks[cur].cspace_size ? tasks[cur].cspace_size : CNODE_SIZE;

    if (!cspace) {
#ifdef CAP_LOOKUP_ROOT_FALLBACK
        /* CONTROL ARM -- never ship. The pre-2026-08-30 fallback: a task with no
         * cspace resolves against the primordial root cnode and holds every
         * capability the kernel minted at boot. See make
         * smoke-captest-cspaceless-control. */
        cspace = root_cnode;
        cspace_sz = CNODE_SIZE;
#else
        /* Task 0 is the kernel boot/idle/reaper task and has no cspace of its
         * own by design; every other task without one is refused rather than
         * handed the root cnode. */
        if (cur != 0) return NULL;
        cspace = root_cnode;
        cspace_sz = CNODE_SIZE;
#endif
    }

    /* Past the end of the caller's OWN cspace is out of range, not a reason to
     * consult somebody else's. `rust_cap_lookup` bounds-checks against the size
     * it is given, so refusing here is belt and braces -- and it is the belt that
     * used to be the escalation, because the size it was given in that branch was
     * the ROOT cnode's. */
#ifdef CAP_LOOKUP_RANGE_FALLBACK
    /* CONTROL ARM -- never ship. The OUT-OF-RANGE half of the old `else`, on its
     * own: the caller keeps its cspace, and only a slot past the end of it
     * resolves against the root cnode.
     *
     * A second arm because the selftest stops at its FIRST failure, so under
     * CAP_LOOKUP_ROOT_FALLBACK -- which restores both halves -- the cspace-less
     * probe fails first and the range check is never reached. With only that arm,
     * nothing establishes that the range check can fire at all; the ordering of
     * the arms is what shows the two rules fail independently. See
     * make smoke-cap-lookup-range-control. */
    if (slot >= cspace_sz) { cspace = root_cnode; cspace_sz = CNODE_SIZE; }
#else
    if (slot >= cspace_sz) return NULL;
#endif

    struct capability *p = rust_cap_lookup(cspace, cspace_sz, slot, required_rights);
    if (p && !capability_validate_generation(p)) return NULL;
    return p;
}

/* WHY THIS IS NO LONGER A HALTING ASSERT.
 *
 * Until 2026-08-29 this file exported two helpers:
 *
 *     void kassert_cap(struct capability *c){if(!c){for(;;){}}}
 *     struct capability *kcap_lookup(uint32_t s,uint32_t r){...kassert_cap(c);...}
 *
 * and cap_mint()/cap_transfer() resolved their SOURCE slot through the second,
 * while holding cap_lock, with interrupts masked by spin_lock's own `cli`.
 * cap_lookup() returns NULL for an out-of-range slot, an empty slot, or a slot
 * whose rights do not include the one asked for. A ring-3 caller picks all three
 * freely: h_cap_mint passes rbx/rcx/rdx straight through, and SYS_CAP_MINT,
 * SYS_CAP_TRANSFER and SYS_CAP_MOVE are SC_NONE entries whose comment says the
 * authority lives "inside the cap_* primitives". So syscall(SYS_CAP_MINT, 200,
 * 200, 0) from any unprivileged task spun that CPU forever inside the critical
 * section, and the next CPU to want cap_lock -- a spawn, a sudo, a revoke, an IPC
 * reply mint -- joined it there. One syscall, no capability required, and the
 * machine stops.
 *
 * The `if (!src || dest_slot >= CNODE_SIZE) { unlock; return false; }` a few
 * lines below was already the intended behaviour. It was simply unreachable,
 * because the helper it guarded could not return NULL. The repair is to let it
 * run, which is why the call sites are unchanged.
 *
 * A halting assert is the wrong primitive for a fail-closed kernel: it turns
 * "refuse this" into "stop everything", at precisely the point a caller-supplied
 * index is resolved. It survives only as the control arm below, so the defect
 * stays reproducible on demand. See SECURITY.md S52.
 */
#ifdef CAP_LOOKUP_ASSERT_HANG
void kassert_cap(struct capability *c){if(!c){for(;;){}}}
struct capability *kcap_lookup(uint32_t slot,uint32_t r){struct capability *c=cap_lookup(slot,r);kassert_cap(c);return c;}
#else
struct capability *kcap_lookup(uint32_t slot,uint32_t r){return cap_lookup(slot,r);}
#endif

/*
 * Capability snapshot + revalidation (defense-in-depth against lookup/use
 * TOCTOU). A looked-up `struct capability *` can become stale if any operation
 * between lookup and use yields, drops cap_lock, or (under future preemption)
 * is interrupted by another task that revokes or re-mints the slot. The pattern
 * is: snapshot at lookup, then `cap_revalidate(slot, rights, &snap)` at the
 * point of use — it re-looks-up the slot and confirms it STILL holds the same
 * capability identity (serial, generation, object) with the required rights.
 * A mismatch (revoked, replaced, or generation-bumped) returns NULL.
 *
 * "Validate at use" beats "look up once": the returned pointer is only trusted
 * for the instant it is reconfirmed under the same invariants cap_lookup
 * enforces (rights mask + Rust lineage/generation check).
 */
cap_snapshot_t cap_snapshot(const struct capability *c) {
    cap_snapshot_t s;
    if (c) {
        s.serial = c->serial;
        s.generation = c->generation;
        s.object = c->object;
        s.valid = (c->type != CAP_NULL);
    } else {
        s.serial = 0; s.generation = 0; s.object = 0; s.valid = 0;
    }
    return s;
}

struct capability *cap_revalidate(uint32_t slot, uint32_t required_rights,
                                  const cap_snapshot_t *snap) {
    if (!snap || !snap->valid) return NULL;
    struct capability *p = cap_lookup(slot, required_rights);
    if (!p) return NULL;
    /* Identity must be unchanged: a revoke nulls these, a re-mint changes the
     * serial, and a lineage revocation bumps the generation. */
    if (p->serial != snap->serial ||
        p->generation != snap->generation ||
        p->object != snap->object) {
        return NULL;
    }
    return p;
}

/*
 * No ambient authority. Every non-kernel task must act within its OWN cspace.
 * Only the kernel boot task (id 0) legitimately operates on root_cnode — user
 * task ids are always >= 1 (allocated from 1 in do_spawn) and are given a real
 * cspace at create_task time. Any other task that reaches the root_cnode
 * fallback is missing its cspace, so refuse it rather than grant it kernel
 * trust. This makes the "cspace == root_cnode" rights-check exemption in the
 * mutating ops below provably mean "kernel only", closing the escalation path
 * where a cspace-less task could mint/transfer/revoke without holding the right.
 */
static bool caller_has_authority(void) {
    int cur = get_current_task();
    return cur == 0 || tasks[cur].cspace != NULL;
}

bool cap_mint(uint32_t dest_slot, uint32_t src_slot, uint32_t new_rights) {
    spin_lock(&cap_lock);
    if (!caller_has_authority()) { spin_unlock(&cap_lock); return false; }
    struct capability *src = kcap_lookup(src_slot, CAP_RIGHT_MINT);
    if (!src || dest_slot >= CNODE_SIZE) {
        spin_unlock(&cap_lock);
        return false;
    }

    if (dest_slot < KERNEL_RESERVED_CAPS) {
        spin_unlock(&cap_lock);
        return false;
    }

    struct capability *dest_array = tasks[get_current_task()].cspace
        ? tasks[get_current_task()].cspace
        : root_cnode;
    uint32_t cspace_sz = tasks[get_current_task()].cspace_size
        ? tasks[get_current_task()].cspace_size
        : CNODE_SIZE;

    
    bool was_null = (dest_array[dest_slot].type == CAP_NULL);
    if (was_null) {
        if (tasks[get_current_task()].caps_in_use >= MAX_CAPS_PER_TASK) {
            spin_unlock(&cap_lock);
            return false;
        }
    }

    
    bool ok = rust_cap_mint(dest_array, cspace_sz, dest_slot, src_slot, new_rights,
                            &cap_next_serial,
                            tasks[get_current_task()].caps_in_use);
    if (ok && was_null) {
        tasks[get_current_task()].caps_in_use++;
    }

    /* No separate C lineage registration: rust_cap_mint already records the
     * minted capability's generation as the floor in the Rust LINEAGE_GEN
     * authority, so the C side has nothing to track. */

    spin_unlock(&cap_lock);
    return ok;
}

bool cap_transfer(uint32_t dest_slot, uint32_t src_slot) {
    spin_lock(&cap_lock);
    if (!caller_has_authority()) { spin_unlock(&cap_lock); return false; }
    struct capability *src = kcap_lookup(src_slot, CAP_RIGHT_MINT);
    if (!src || dest_slot >= CNODE_SIZE) {
        spin_unlock(&cap_lock);
        return false;
    }
    if (dest_slot < KERNEL_RESERVED_CAPS) {
        spin_unlock(&cap_lock);
        return false;
    }

    struct capability *dest_array = tasks[get_current_task()].cspace
        ? tasks[get_current_task()].cspace
        : root_cnode;
    uint32_t cspace_sz = tasks[get_current_task()].cspace_size
        ? tasks[get_current_task()].cspace_size
        : CNODE_SIZE;

    bool was_null = (dest_array[dest_slot].type == CAP_NULL);
    if (was_null && tasks[get_current_task()].caps_in_use >= MAX_CAPS_PER_TASK) {
        spin_unlock(&cap_lock);
        return false;
    }

    bool ok = rust_cap_transfer(dest_array, cspace_sz, dest_slot, src_slot, &cap_next_serial);
    if (ok && was_null) {
        tasks[get_current_task()].caps_in_use++;
    }
    spin_unlock(&cap_lock);
    return ok;
}

bool cap_move(uint32_t dest_slot, uint32_t src_slot) {
    if (cap_transfer(dest_slot, src_slot)) {
        return cap_revoke(src_slot);
    }
    return false;
}

/* Grant (delegate) the caller's capability at `src_slot` into a supervised
 * target task's cspace at `dest_slot`, through the same locked, accounted,
 * lineage-correct discipline every other cap write uses.
 *
 * The authority to grant (a CAP_TCB on the target, or admin) is enforced by the
 * caller (h_cap_grant), exactly as for SYS_KILL. This routine owns the cspace
 * read-modify-write: it holds `cap_lock` across the source lookup and the
 * destination store, so it cannot race a concurrent `rust_cap_revoke_global`
 * sweep under SMP (the bug the old raw `tasks[target].cspace[dest] = *src` store
 * had); it counts a newly-occupied slot against the TARGET's MAX_CAPS_PER_TASK
 * ceiling (the old store never did, so granted caps were invisible to the
 * ceiling and desynced the revoke-time decrement); and it reduces rights to
 * `new_rights & src.rights` while recording the grantor's cap as the grantee's
 * parent (`badge = src.serial`), so the derivation tree stays well-formed and a
 * later revoke of the grantor sweeps the grantee too.
 *
 * NB: unlike cap_mint/cap_transfer there is deliberately NO
 * `dest_slot < KERNEL_RESERVED_CAPS` floor — grant writes into a *child* the
 * caller already dominates (it holds the child's CAP_TCB), and endowing a
 * child's low slots (e.g. its IPC gate at slot 3) is exactly what grant is for.
 * The reserved-slot floor protects a task's own primordial slots against its own
 * mint/transfer; it does not apply to a supervisor endowing a subordinate.
 *
 * Returns false on a missing/invalid source, an out-of-range slot, a missing
 * cspace, or when the target is at its capability ceiling. */
bool cap_grant_into(int target_pid, uint32_t dest_slot, uint32_t src_slot, uint32_t new_rights) {
    if (target_pid <= 0 || target_pid >= MAX_TASKS) return false;
    if (src_slot >= CNODE_SIZE || dest_slot >= CNODE_SIZE) return false;

    spin_lock(&cap_lock);
    if (!caller_has_authority()) { spin_unlock(&cap_lock); return false; }

    int cur = get_current_task();
    struct capability *src_cspace = tasks[cur].cspace;
    uint32_t src_sz = tasks[cur].cspace_size ? tasks[cur].cspace_size : CNODE_SIZE;
    struct capability *dst_cspace = tasks[target_pid].cspace;
    uint32_t dst_sz = tasks[target_pid].cspace_size ? tasks[target_pid].cspace_size : CNODE_SIZE;
    if (!src_cspace || !dst_cspace) { spin_unlock(&cap_lock); return false; }

    /* Authoritative source lookup under the lock: rights(0) => possession is
     * enough, but the type/serial/lineage-generation validity is enforced (the
     * same checks cap_lookup applies), so a revoked or stale source is refused. */
    struct capability *src = rust_cap_lookup(src_cspace, src_sz, src_slot, 0);
    if (src && !rust_lineage_check(src->serial, src->generation)) src = NULL;
    if (!src) { spin_unlock(&cap_lock); return false; }

    bool was_null = (dest_slot < dst_sz) && (dst_cspace[dest_slot].type == CAP_NULL);
    if (was_null && tasks[target_pid].caps_in_use >= MAX_CAPS_PER_TASK) {
        spin_unlock(&cap_lock);
        return false;
    }

    bool ok = rust_cap_grant_into(src, dst_cspace, dst_sz, dest_slot, new_rights,
                                  &cap_next_serial);
    if (ok && was_null) tasks[target_pid].caps_in_use++;
    spin_unlock(&cap_lock);
    return ok;
}

/* ---- FORK: DUPLICATE A CSPACE AS DERIVED CAPABILITIES (roadmap 2.3) -------
 *
 * Give `child` a copy of every capability `parent` holds, each one a DERIVED
 * capability of the parent's: its own fresh serial, and `badge` naming the
 * parent capability's serial, which is what makes it a child in the derivation
 * tree `revoke_subtree` walks. Returns the number of slots copied, or negative.
 *
 * ---- WHY NOT A memcpy, WHICH IS WHAT THIS LOOKS LIKE -----------------------
 *
 * A cspace is an array of `capability_t`. Copying it is one call, and it is
 * wrong in two different directions at once -- which is why both are control
 * arms rather than a paragraph.
 *
 *   IDENTICAL SERIALS (FORK_CSPACE_FLAT_COPY=1). `rust_cap_revoke_global`'s
 *   sweep nulls every capability whose `serial` equals the revoked root's,
 *   across EVERY cspace, because a serial is supposed to identify exactly one
 *   capability. Duplicate one and that stops being true: the child revoking its
 *   OWN slot nulls the parent's too. A task that holds nothing but a copy of its
 *   parent's authority can then destroy that authority in the parent's cspace --
 *   a cross-task revocation primitive, reachable by any task that can fork,
 *   which is every task. Revocation is supposed to flow DOWN the derivation
 *   tree; this makes it flow sideways.
 *
 *   NO PARENT LINK (FORK_CSPACE_ORPHAN_COPY=1). Give the copy a fresh serial but
 *   leave `badge` alone and it is not derived from anything -- a second root of
 *   the capability graph, holding the parent's authority. `mark_children_of`
 *   never marks it, its serial matches no revocation root, and so revoking the
 *   parent's capability leaves the child's working. That is a REVOCATION HOLE
 *   reachable from ring 3 by any task that can fork, and it is the one this
 *   function exists to avoid: it is finding 3.3's shape -- a capability keyed to
 *   a serial no sweep reaches -- applied to a whole cspace at once.
 *
 * Both are avoided the same way: by not writing the copy here at all.
 * `rust_cap_grant_into` is the reviewed derivation, it is what SYS_CAP_GRANT
 * uses, and calling it per slot means a forked capability and a delegated one
 * are the same object by construction rather than by two implementations
 * agreeing. [H-3] is what happens when they stop agreeing.
 *
 * ---- WHAT IS NOT COPIED, AND WHY EACH ONE WOULD BE IMPERSONATION -----------
 *
 * Slots 0..3 (`KERNEL_RESERVED_CAPS`) and slot 4 are the child's OWN identity,
 * installed by `create_task`, and copying the parent's over them is not
 * delegation:
 *
 *   slot 0  CAP_TCB on self. The parent's names the PARENT, so the child would
 *           hold a TCB capability over its own parent -- SYS_KILL and SYS_SIGNAL
 *           on it. That is a widening: the parent never held authority over
 *           itself in a form it could hand away, and fork must not mint one.
 *   slot 3  the legacy image CAP_FRAME. Identical in every task; the child's own
 *           is already right, and the parent's names the parent's window.
 *   slot 4  the PRIVATE reply endpoint SYS_IPC_CALL parks on. Copying it gives
 *           the child the parent's rendezvous, so the child could receive the
 *           parent's replies or wake it spuriously -- exactly the interception
 *           the per-task reply endpoint was introduced to make impossible
 *           (finding C-1). It is the one slot whose whole value is that nobody
 *           else has it.
 *
 * CAP_REPLY is skipped BY TYPE rather than by slot, because it is one-shot and
 * may sit anywhere: it names a specific in-flight sender, and two tasks holding
 * it is a reply-forgery primitive with no revocation involved. The same
 * reasoning already excludes the parent's blocked-IPC state from the fork.
 *
 * A source that is revoked or lookup-invalid (serial 0, or a stale generation)
 * is skipped rather than copied. Copying it would resurrect nothing -- the copy
 * would fail `lineage_check` too -- but it would occupy a slot and count against
 * the child's ceiling, and a cspace full of dead capabilities is a worse report
 * of what a task holds than an empty slot.
 *
 * ---- RIGHTS ARE NOT NARROWED, AND THAT IS DELIBERATE ----------------------
 *
 * `CAP_RIGHT_ALL` is asked for, and `rust_cap_grant_into` intersects it with the
 * source's, so the copy carries exactly the parent's rights and never more.
 * SYS_SPAWN masks the console capability down to WRITE on the way to a child,
 * and fork deliberately does not do the same, because the two are handing
 * authority to different things. Spawn's child is a DIFFERENT PROGRAM and the
 * parent is choosing what to give a stranger. Fork's child is the same program
 * at the same instruction, and the contract is that it can do what the caller
 * could; a fork that silently dropped rights would break `if (fork() == 0)
 * serve();` in a way nothing reports, and the program would work around it by
 * having the parent grant them back -- achieving nothing except making the same
 * authority harder to see in the graph.
 *
 * The authority graph is no looser for it. Every capability the child holds is a
 * DERIVED CHILD of one the parent holds, so the child's authority is a subtree
 * of the parent's, and every revocation that would have swept the parent's now
 * sweeps the child's with it. Fork adds no new ROOT to the graph -- which is the
 * property, and what S41 states.
 *
 * Caller holds no lock; cap_lock is taken here, ONCE for the whole cspace rather
 * than per slot as a loop over cap_grant_into would. A fork must see one
 * consistent snapshot of what the parent holds: released between slots, a
 * concurrent grant or revoke into the parent's cspace would be half-copied, and
 * the child would hold an assortment of capabilities that never existed together
 * in the parent.
 */
int cap_clone_cspace(int parent, int child) {
    if (parent <= 0 || parent >= MAX_TASKS) return -1;
    if (child  <= 0 || child  >= MAX_TASKS) return -1;
    if (parent == child) return -1;

    spin_lock(&cap_lock);

    capability_t *pc = tasks[parent].cspace;
    capability_t *cc = tasks[child].cspace;
    if (!pc || !cc) { spin_unlock(&cap_lock); return -1; }

    uint32_t psz = tasks[parent].cspace_size ? tasks[parent].cspace_size : CNODE_SIZE;
    uint32_t csz = tasks[child ].cspace_size ? tasks[child ].cspace_size : CNODE_SIZE;
    uint32_t lim = psz < csz ? psz : csz;
    if (lim > CNODE_SIZE) lim = CNODE_SIZE;

    int copied = 0;
    for (uint32_t s = KERNEL_RESERVED_CAPS; s < lim; s++) {
        if (s == CAPSLOT_REPLY_EP) continue;      /* the child's own rendezvous */

        capability_t *src = &pc[s];
        if (src->type == CAP_NULL)  continue;
        if (src->type == CAP_REPLY) continue;     /* one-shot; see above */
        if (src->serial == 0)       continue;     /* lookup-invalid */
        if (!rust_lineage_check(src->serial, src->generation)) continue;   /* revoked */

        /* The child's ceiling is the same MAX_CAPS_PER_TASK every other task
         * answers to. Reaching it is not a partial success to be reported as one:
         * a task running with an arbitrary prefix of its parent's authority is a
         * configuration nothing asked for and nothing can reason about, and the
         * prefix depends on slot order. Fail the whole fork instead -- the same
         * all-or-nothing argument S35 makes about a partly-installed mapping. */
        if (tasks[child].caps_in_use >= MAX_CAPS_PER_TASK) {
            spin_unlock(&cap_lock);
            return -2;
        }

#if defined(FORK_CSPACE_FLAT_COPY) || defined(FORK_CSPACE_ORPHAN_COPY)
        /* Control arms: write the copy here instead of deriving it. Both keep
         * type/rights/object, so the child holds the same authority either way
         * and only its POSITION IN THE DERIVATION TREE is wrong -- which is the
         * whole point. A reader diffing the arms against the real path should see
         * two fields, not a different algorithm. */
        {
            bool was_null = (cc[s].type == CAP_NULL);
            cc[s].type   = src->type;
            cc[s].rights = src->rights;
            cc[s].object = src->object;
#ifdef FORK_CSPACE_FLAT_COPY
            /* The parent's own identity, duplicated: one serial, two capabilities. */
            cc[s].badge      = src->badge;
            cc[s].serial     = src->serial;
            cc[s].generation = src->generation;
#else
            /* Fresh identity, but no edge back to the parent's capability. */
            cc[s].badge      = src->badge;
            cc[s].serial     = rust_cap_alloc_serial(&cap_next_serial);
            cc[s].generation = rust_lineage_current(cc[s].serial);
#endif
            if (was_null) tasks[child].caps_in_use++;
            copied++;
        }
#else
        bool was_null = (cc[s].type == CAP_NULL);
        if (rust_cap_grant_into(src, cc, csz, s, CAP_RIGHT_ALL, &cap_next_serial)) {
            if (was_null) tasks[child].caps_in_use++;
            copied++;
        }
#endif
    }

    spin_unlock(&cap_lock);
    return copied;
}

#if defined(EXEC_RESET_CSPACE) || defined(EXEC_ROOT_CSPACE)
/* ---- CONTROL ARMS FOR S42. Not a code path the ship kernel has -------------
 *
 * The real exec does NOTHING to the cspace. That is the property, and it is the
 * hardest kind of property to test: an implementation that omits a step passes
 * every check aimed at what the step would have done. So the arms here ADD the
 * two steps a "give the new image a clean slate" instinct would add, and
 * `forkexectest` measures the difference.
 *
 * Both operate on slots at or above KERNEL_RESERVED_CAPS, which is where
 * `cap_clone_cspace` starts copying and where a task's own identity ends. Slots
 * 0, 3 and 4 -- the CAP_TCB on self, the image capability and the private reply
 * endpoint -- are what `create_task` installs for every task, so leaving them
 * alone is what makes each arm a statement about DELEGATED authority rather than
 * a task with no cspace at all.
 *
 * EXEC_RESET_CSPACE discards. The execed image keeps only its birth endowment,
 * so everything the task was given -- by delegation, by connect, or by the fork
 * that produced it -- is gone. This is the arm that fails "the exec kept it".
 *
 * EXEC_ROOT_CSPACE keeps every capability but re-mints it as a ROOT: a fresh
 * serial and no badge. The task's authority is unchanged and every check that
 * asks "can it still do the thing" passes -- which is the point. What it loses is
 * its POSITION in the derivation graph, so a revocation aimed at the capability
 * it was derived from no longer reaches it. That is finding 3.3's shape reached
 * by execing instead of by forking, and it is the arm the whole property exists
 * for: an exec that launders inherited authority into a new root is a revocation
 * hole with no visible symptom until somebody tries to revoke.
 *
 * Deliberately in ONE function with the two arms as branches, for the reason the
 * FORK_CSPACE arms give: a reader diffing them against the real path should see
 * two policies over one walk, not two different algorithms. */
void cap_exec_mutate_cspace(int t) {
    if (t <= 0 || t >= MAX_TASKS) return;

    spin_lock(&cap_lock);
    capability_t *cs = tasks[t].cspace;
    if (!cs) { spin_unlock(&cap_lock); return; }
    uint32_t sz = tasks[t].cspace_size ? tasks[t].cspace_size : CNODE_SIZE;
    if (sz > CNODE_SIZE) sz = CNODE_SIZE;

    for (uint32_t s = KERNEL_RESERVED_CAPS; s < sz; s++) {
        if (cs[s].type == CAP_NULL) continue;
#ifdef EXEC_RESET_CSPACE
        cs[s].type       = CAP_NULL;
        cs[s].rights     = 0;
        cs[s].object     = 0;
        cs[s].badge      = 0;
        cs[s].serial     = 0;
        cs[s].generation = 0;
        if (tasks[t].caps_in_use > 0) tasks[t].caps_in_use--;
#else
        /* Same type, same rights, same object: the authority is untouched and
         * only its lineage is destroyed. */
        cs[s].badge      = 0;
        cs[s].serial     = rust_cap_alloc_serial(&cap_next_serial);
        cs[s].generation = rust_lineage_current(cs[s].serial);
#endif
    }

    spin_unlock(&cap_lock);
}
#endif /* EXEC_RESET_CSPACE || EXEC_ROOT_CSPACE */

bool cap_revoke(uint32_t slot) {
    spin_lock(&cap_lock);
    if (slot >= CNODE_SIZE) {
        spin_unlock(&cap_lock);
        return false;
    }
    if (!caller_has_authority()) {
        spin_unlock(&cap_lock);
        return false;
    }
    struct capability *cspace = tasks[get_current_task()].cspace ? tasks[get_current_task()].cspace : root_cnode;
    uint32_t cspace_sz = tasks[get_current_task()].cspace_size ? tasks[get_current_task()].cspace_size : CNODE_SIZE;
    if (slot < KERNEL_RESERVED_CAPS && cspace == root_cnode) {
        spin_unlock(&cap_lock);
        return false;
    }
    if ((cspace[slot].rights & CAP_RIGHT_REVOKE) == 0 && cspace != root_cnode) {
        spin_unlock(&cap_lock);
        return false;
    }
    uint32_t orig_type = cspace[slot].type;

    /* Revocation-set indirection: a CAP_REVOCATION capability names a target
     * slot in `object`. Revoke the helper slot itself (single cspace), then
     * redirect to the real target before the system-wide sweep. */
    if (orig_type == CAP_REVOCATION && cspace[slot].object < CNODE_SIZE) {
        uint32_t real_target = (uint32_t)cspace[slot].object;
        rust_cap_revoke(cspace, cspace_sz, slot, &cap_next_serial);
        slot = real_target;
        if (slot >= CNODE_SIZE) {
            spin_unlock(&cap_lock);
            return true;
        }
    }

    /* Snapshot serial/badge for the rev_sets cleanup below, before the slot is
     * nulled by the revocation. */
    uint32_t target_serial = cspace[slot].serial;
    uint32_t target_badge = cspace[slot].badge;

    /*
     * INVARIANT (ARCHITECTURE.md): revocation is system-wide. We hand the Rust
     * authority every live task's cspace plus the kernel root cnode, and it
     * nulls the target plus every derived copy of the same lineage in ANY of
     * them, bumping the lineage generation exactly once. This closes the
     * use-after-revoke / privilege-retention hole where a derived capability in
     * another task's CNode could outlive its parent. The whole sweep runs under
     * cap_lock so the snapshot of tasks[] is stable.
     */
    cspace_desc_t spaces[MAX_TASKS + 1];
    uint32_t nspaces = 0;
    for (int t = 0; t < MAX_TASKS; t++) {
        if (tasks[t].state == 0 || !tasks[t].cspace) continue;
        spaces[nspaces].caps = tasks[t].cspace;
        spaces[nspaces].size = tasks[t].cspace_size ? tasks[t].cspace_size : CNODE_SIZE;
        spaces[nspaces].caps_in_use = &tasks[t].caps_in_use;
        nspaces++;
    }
    /* The kernel root cnode is not any task's cspace; include it so kernel-held
     * derived copies are swept too. (No task uses root_cnode as its cspace, so
     * this cannot double-count.) */
    spaces[nspaces].caps = root_cnode;
    spaces[nspaces].size = CNODE_SIZE;
    spaces[nspaces].caps_in_use = NULL;
    nspaces++;

    /* The target's own caps_in_use counter (NULL when revoking in root_cnode). */
    uint32_t *target_ciu = (cspace == root_cnode) ? NULL : &tasks[get_current_task()].caps_in_use;

    bool ok = rust_cap_revoke_global(cspace, cspace_sz, slot, target_ciu,
                                     spaces, nspaces, &cap_next_serial);

    for (int r = 0; r < MAX_REV_SETS; r++) {
        if (rev_sets[r].valid &&
            (rev_sets[r].badge == target_badge || rev_sets[r].badge == slot ||
             (target_serial != 0 && rev_sets[r].badge == target_serial))) {
            rev_sets[r].valid = 0;
        }
    }
    /* A revoke can have removed the last capability naming a retyped kernel
     * object, and an object no capability names is unreachable — so this is the
     * point at which object lifetimes become capability-governed rather than
     * index-governed (roadmap 0.3, audit I-7).
     *
     * Deliberately INSIDE cap_lock. The sweep decides an object's fate by
     * reading every cspace, and cap-writes are field-by-field, so running it
     * unlocked would let it observe a slot mid-install — type already written,
     * `object` still stale — and conclude a live object is unreachable. Holding
     * cap_lock makes every cspace it reads quiescent. Lock order is cap_lock ->
     * untyped_lock and is the same everywhere (untyped_retype releases the
     * untyped lock before taking cap_lock), so this cannot deadlock. */
    kobj_gc();

    spin_unlock(&cap_lock);
    return ok;
}

bool cap_create_revocation_set(uint32_t target_slot, uint32_t rev_slot) {
    /* Mutates the caller's cspace, so it must observe the same discipline as
     * cap_mint/cap_transfer/cap_revoke: hold cap_lock for the read-modify-write
     * and require authority (so the root_cnode fallback is provably kernel-only
     * for any cspace-less task). Currently has no callers, but is exported in
     * kernel.h -- harden it now so wiring it to a syscall later is not a hole. */
    /* Allocate the serial before taking cap_lock: cap_alloc_fresh_serial()
     * grabs cap_lock itself and the lock is not recursive (same ordering
     * do_spawn uses). A serial burned on a later validation failure is
     * harmless -- the counter is monotonic. */
    uint32_t fresh_serial = cap_alloc_fresh_serial();

    spin_lock(&cap_lock);
    if (!caller_has_authority()) { spin_unlock(&cap_lock); return false; }

    struct capability *cspace = tasks[get_current_task()].cspace ? tasks[get_current_task()].cspace : root_cnode;

    if (target_slot >= CNODE_SIZE || rev_slot >= CNODE_SIZE || target_slot < 4) {
        spin_unlock(&cap_lock);
        return false;
    }

    struct capability *target = &cspace[target_slot];
    if (target->type == CAP_NULL) {
        spin_unlock(&cap_lock);
        return false;
    }

    cspace[rev_slot].type   = CAP_REVOCATION;
    cspace[rev_slot].rights = CAP_RIGHT_REVOKE;
    cspace[rev_slot].object = target_slot;
    cspace[rev_slot].badge  = 0xDEAD0000U;
    cspace[rev_slot].serial = fresh_serial;
    cspace[rev_slot].generation = rust_lineage_current(fresh_serial); /* finding 3.3 */

    spin_unlock(&cap_lock);
    return true;
}

bool has_encrypted_storage_cap(void) {
    struct capability *c = cap_lookup(9, 0);
    return (c && c->type == CAP_ENCRYPTED_STORAGE);
}
