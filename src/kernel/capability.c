#include "kernel.h"

extern tcb_t tasks[MAX_TASKS];

#define CNODE_SIZE 256
#define KERNEL_RESERVED_CAPS 4

static struct capability root_cnode[CNODE_SIZE];

static uint32_t cap_next_serial = 0x00010000U;

#define MAX_REV_SETS 8


uint32_t cap_alloc_fresh_serial(void) {
    spin_lock(&cap_lock);
    uint32_t cur = cap_next_serial;
    if (cur < 0x00010000U) cur = 0x00010000U;
    uint32_t s = cur + 1;
    if (s < 0x00010000U || s == 0) s = 0x00010000U;
    cap_next_serial = s;
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
    return rust_lineage_check(cap->object, cap->generation);
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

    cap_next_serial = 0x00010000U;

    for (int i = 0; i < MAX_REV_SETS; i++) rev_sets[i].valid = 0;
    /* Lineage generations live in the Rust authority (LINEAGE_GEN); nothing to
     * initialize here — it is zeroed in the static and bumped lazily. */
}

struct capability *cap_lookup(uint32_t slot, uint32_t required_rights) {
    if (slot >= CNODE_SIZE) return NULL;
    struct capability *cspace = tasks[get_current_task()].cspace;
    uint32_t cspace_sz = tasks[get_current_task()].cspace_size ? tasks[get_current_task()].cspace_size : CNODE_SIZE;
    struct capability *p = NULL;
    if (cspace && slot < cspace_sz) {
        p = rust_cap_lookup(cspace, cspace_sz, slot, required_rights);
    } else {
        p = rust_cap_lookup(root_cnode, CNODE_SIZE, slot, required_rights);
    }
    if (p && !capability_validate_generation(p)) return NULL;
    return p;
}

void kassert_cap(struct capability *c){if(!c){for(;;){}}}
struct capability *kcap_lookup(uint32_t slot,uint32_t r){struct capability *c=cap_lookup(slot,r);kassert_cap(c);return c;}

bool cap_mint(uint32_t dest_slot, uint32_t src_slot, uint32_t new_rights) {
    spin_lock(&cap_lock);
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

bool cap_revoke(uint32_t slot) {
    spin_lock(&cap_lock);
    if (slot >= CNODE_SIZE) {
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
    uint32_t target_serial = cspace[slot].serial;
    uint32_t target_badge = cspace[slot].badge;
    uint32_t target_obj = cspace[slot].object;
    uint32_t orig_type = cspace[slot].type;
    /* Generation bump is performed exactly once, inside rust_cap_revoke (and
     * rust_cap_revoke_by_values for cross-task slots), against the Rust authority.
     * The previous duplicate C-side lineage_revoke() has been removed to keep a
     * single, consistent source of truth. */
    if (orig_type == CAP_REVOCATION && target_obj < CNODE_SIZE) {
        uint32_t real_target = target_obj;
        rust_cap_revoke(cspace, cspace_sz, slot, &cap_next_serial);
        slot = real_target;
        if (slot >= CNODE_SIZE) {
            spin_unlock(&cap_lock);
            return true;
        }
        target_serial = cspace[slot].serial;
        target_badge = cspace[slot].badge;
        target_obj = cspace[slot].object;
    }
    if (cspace[slot].type != CAP_NULL) {
        if (tasks[get_current_task()].caps_in_use > 0) {
            tasks[get_current_task()].caps_in_use--;
        }
    }
    (void)rust_cap_revoke(cspace, cspace_sz, slot, &cap_next_serial);
    for (int t = 0; t < MAX_TASKS; t++) {
        if (tasks[t].state == 0 || !tasks[t].cspace) continue;
        struct capability *tcspace = tasks[t].cspace;
        (void)rust_cap_revoke_by_values(tcspace, CNODE_SIZE, target_serial, target_badge, target_obj);
    }
    for (int r = 0; r < MAX_REV_SETS; r++) {
        if (rev_sets[r].valid &&
            (rev_sets[r].badge == target_badge || rev_sets[r].badge == slot ||
             (target_serial != 0 && rev_sets[r].badge == target_serial))) {
            rev_sets[r].valid = 0;
        }
    }
    spin_unlock(&cap_lock);
    return true;
}

bool cap_create_revocation_set(uint32_t target_slot, uint32_t rev_slot) {
    
    struct capability *cspace = tasks[get_current_task()].cspace ? tasks[get_current_task()].cspace : root_cnode;

    if (target_slot >= CNODE_SIZE || rev_slot >= CNODE_SIZE || target_slot < 4) return false;

    struct capability *target = &cspace[target_slot];
    if (target->type == CAP_NULL) return false;

    cspace[rev_slot].type   = CAP_REVOCATION;
    cspace[rev_slot].rights = CAP_RIGHT_REVOKE;
    cspace[rev_slot].object = target_slot;
    cspace[rev_slot].badge  = 0xDEAD0000U;
    cspace[rev_slot].serial = cap_alloc_fresh_serial();
    cspace[rev_slot].generation = 0;

    return true;
}

bool has_encrypted_storage_cap(void) {
    struct capability *c = cap_lookup(9, 0);
    return (c && c->type == CAP_ENCRYPTED_STORAGE);
}
