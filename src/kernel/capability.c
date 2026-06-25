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

lineage_entry_t lineages[MAX_LINEAGES];
uint32_t next_lineage_id = 1; 


static uint32_t lineage_hash(uint64_t obj){
    uint64_t x = obj;
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return (uint32_t)(x & (MAX_LINEAGES - 1));
}


static int lineage_find(uint64_t obj){
    uint32_t h = lineage_hash(obj);
    for(uint32_t i=0;i<MAX_LINEAGES;i++){
        uint32_t s=(h+i)&(MAX_LINEAGES-1);
        if(!lineages[s].valid) return -1;
        if(lineages[s].object_id==obj) return (int)s;
    }
    return -1;
}


uint32_t lineage_register(uint64_t object_id){
    if(object_id==0) return MAX_LINEAGES;
    uint32_t h=lineage_hash(object_id);
    for(uint32_t i=0;i<MAX_LINEAGES;i++){
        uint32_t s=(h+i)&(MAX_LINEAGES-1);
        if(lineages[s].valid && lineages[s].object_id==object_id) return s;
        if(!lineages[s].valid){
            lineages[s].object_id=object_id;
            lineages[s].generation=0;
            lineages[s].refcount=1;
            lineages[s].valid=1;
            return s;
        }
    }
    return MAX_LINEAGES; 
}

void lineage_revoke(uint32_t lineage_id){
    if(lineage_id<MAX_LINEAGES && lineages[lineage_id].valid){
        lineages[lineage_id].generation++;
        lineages[lineage_id].refcount=0;
    }
}

bool capability_validate_generation(const capability_t *cap){
    if(!cap||cap->type==CAP_NULL) return false;
    uint64_t oid=cap->object;
    if(oid==0) return true;            
    int s=lineage_find(oid);
    if(s<0) return true;               

    return cap->generation == lineages[s].generation;
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
    for(int i=0;i<MAX_LINEAGES;i++){lineages[i].valid=0;lineages[i].generation=0;lineages[i].refcount=0;lineages[i].object_id=0;}
    next_lineage_id=1;
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

    if (ok && dest_array[dest_slot].object != 0) {
        (void)lineage_register(dest_array[dest_slot].object);
    }

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
    lineage_revoke(lineage_register(target_obj ? (uint64_t)target_obj : (uint64_t)target_serial));
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
