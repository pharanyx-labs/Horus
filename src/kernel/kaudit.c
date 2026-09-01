/* kaudit.c -- tamper-evident audit log: append (audit_log), canonical
 * serialization, per-entry + chained MACs, verification, and the read/digest
 * syscall handlers. Owns the audit ring buffer. Split out of syscall.c. */
#include "syscall_internal.h"

static struct audit_event audit_log_buffer[AUDIT_LOG_SIZE];
static uint32_t audit_head = 0;
static uint32_t audit_count = 0;

/* Forward-secure tamper-proofing (rust/src/audit.rs). For each ring slot we keep
 * the entry's absolute sequence number and its per-entry MAC; `audit_chain_head`
 * is a running keyed commitment over every event ever appended (kept even after
 * the ring overwrites the slot).
 *
 * The MAC/head are keyed by an EVOLVING key `audit_fs_key` (derived once from the
 * per-boot pepper, then ratcheted one-way and ERASED after each entry), not by
 * the persistent pepper. So a kernel compromised at time t holds only the current
 * key and cannot forge or alter any entry committed before t: history prior to a
 * compromise is unforgeable, verified by an external monitor that records the
 * head. `audit_pub_head`/`audit_pub_start` are an UNKEYED running hash that lets
 * the kernel still self-check the retained window for accidental corruption after
 * the keys are gone (a corruption detector, not an anti-forgery mechanism). */
#define AUDIT_MAC_LEN 32
static uint8_t  audit_mac[AUDIT_LOG_SIZE][AUDIT_MAC_LEN];
static uint64_t audit_entry_seq[AUDIT_LOG_SIZE];
static uint8_t  audit_chain_head[AUDIT_MAC_LEN];
static uint8_t  audit_fs_key[AUDIT_MAC_LEN];   /* K_i: ratcheted + erased per entry */
static uint8_t  audit_pub_head[AUDIT_MAC_LEN]; /* unkeyed running hash over (seq,mac) */
static uint8_t  audit_pub_start[AUDIT_MAC_LEN];/* unkeyed hash up to the oldest RETAINED entry */
static uint64_t audit_seq = 0;
static int      audit_chain_ready = 0;

/* Canonical, fixed-layout serialization of an audit event's authenticated
 * fields (everything an attacker must not be able to alter undetected). The
 * exact byte order only has to be self-consistent between record and verify. */
static size_t audit_serialize(const struct audit_event *e, uint8_t *buf) {
    size_t n = 0;
    uint64_t fields[] = {
        (uint64_t)e->type, (uint64_t)e->kind, (uint64_t)e->uid,
        (uint64_t)e->subject_uid, (uint64_t)(uint32_t)e->subject_task,
        e->object, (uint64_t)(uint32_t)e->result, e->timestamp,
        e->arg0, e->arg1,
    };
    for (size_t f = 0; f < sizeof(fields) / sizeof(fields[0]); f++) {
        for (int b = 0; b < 8; b++) buf[n++] = (uint8_t)(fields[f] >> (b * 8));
    }
    for (size_t i = 0; i < sizeof(e->path); i++)    buf[n++] = (uint8_t)e->path[i];
    for (size_t i = 0; i < sizeof(e->message); i++) buf[n++] = (uint8_t)e->message[i];
    return n;
}

/* Initialize the forward-secure audit chain once the per-boot pepper is seeded
 * (called from users_init right after secure_random_bytes(kernel_pepper)).
 * Derives the dedicated genesis key K_0 into audit_fs_key (the pepper itself is
 * left intact for the password hash / user-DB tag) and seeds both the keyed head
 * and the unkeyed public chain. */
void audit_chain_start(void) {
    if (rust_audit_fs_genesis(kernel_pepper, sizeof(kernel_pepper),
                              audit_fs_key, audit_chain_head) == 0 &&
        rust_audit_pub_init(audit_pub_head) == 0) {
        for (int i = 0; i < AUDIT_MAC_LEN; i++) audit_pub_start[i] = audit_pub_head[i];
        audit_seq = 0;
        audit_chain_ready = 1;
    }
}

/* Self-check the RETAINED window for accidental corruption WITHOUT any key (the
 * per-entry keys are erased, by design, so the keyed MACs can no longer be
 * recomputed here — they are verified externally by a monitor holding the head).
 * Fold the unkeyed public chain from `audit_pub_start` (the commitment up to the
 * oldest retained entry) over every retained (seq, mac); the result must equal
 * `audit_pub_head`. Returns 0 if intact, (index+1) of the first divergence, or
 * -1 if the chain is uninitialized. This catches a stray write flipping a stored
 * (seq, mac); it is NOT proof against an attacker who can forge the keyed MACs. */
static int audit_verify(void) {
    if (!audit_chain_ready) return -1;
    uint8_t acc[AUDIT_MAC_LEN];
    for (int i = 0; i < AUDIT_MAC_LEN; i++) acc[i] = audit_pub_start[i];
    uint32_t start = (audit_head + AUDIT_LOG_SIZE - audit_count) % AUDIT_LOG_SIZE;
    for (uint32_t i = 0; i < audit_count; i++) {
        uint32_t idx = (start + i) % AUDIT_LOG_SIZE;
        if (rust_audit_pub_extend(acc, audit_entry_seq[idx], audit_mac[idx], acc) != 0)
            return (int)(i + 1);
    }
    return rust_audit_mac_eq(acc, audit_pub_head) ? 0 : (int)(audit_count ? audit_count : 1);
}

void audit_log(uint32_t type, uint32_t object, int32_t result, const char *msg) {
    struct audit_event *e = &audit_log_buffer[audit_head];

    e->timestamp    = get_system_ticks();
    e->type         = type;
    e->subject_uid  = tasks[get_current_task()].uid;
    e->subject_task = get_current_task();
    e->object       = object;
    e->result       = result;

    if (msg) {
        size_t i;
        for (i = 0; i < sizeof(e->message) - 1 && msg[i]; i++) {
            e->message[i] = msg[i];
        }
        e->message[i] = 0;
    } else {
        e->message[0] = 0;
    }

    /* Forward-secure tamper-proofing: MAC this entry (binding its sequence
     * number) and extend the running head under the CURRENT key, then ratchet the
     * key forward and erase it -- so this entry can never again be forged, even by
     * a later full compromise. The keyed-hash logic lives in rust/src/audit.rs. */
    if (audit_chain_ready) {
        /* Evicting the oldest retained entry? Fold its (seq, mac) into the
         * unkeyed window-start commitment BEFORE its slot is overwritten, so the
         * key-free self-check window slides forward with the ring. */
        if (audit_count == AUDIT_LOG_SIZE) {
            rust_audit_pub_extend(audit_pub_start, audit_entry_seq[audit_head],
                                  audit_mac[audit_head], audit_pub_start);
        }
        uint8_t buf[8 * 10 + 64 + 128];
        size_t len = audit_serialize(e, buf);
        /* rust_audit_fs_record ratchets audit_fs_key (K_i -> K_{i+1}) and erases
         * K_i in place after computing this entry's MAC and the new head. */
        rust_audit_fs_record(audit_fs_key, audit_seq, buf, len,
                             audit_chain_head, audit_mac[audit_head]);
        audit_entry_seq[audit_head] = audit_seq;
        /* Extend the unkeyed public chain over the new (seq, mac) for the
         * key-free retained-window self-check. */
        rust_audit_pub_extend(audit_pub_head, audit_seq, audit_mac[audit_head],
                              audit_pub_head);
        audit_seq++;
    }

    audit_head = (audit_head + 1) % AUDIT_LOG_SIZE;
    if (audit_count < AUDIT_LOG_SIZE) audit_count++;
}


/* Project one internal event onto the exported record.
 *
 * The whole record is zeroed first and every byte of it is then a named field or
 * a zero the message did not fill. `rec` is a KERNEL STACK object, so anything
 * left unwritten is kernel stack handed to ring 3 -- the disclosure
 * copy_to_user's own comment describes for a short copy reported as a complete
 * one, arriving here by a different road. There is no padding in the record by
 * construction (see include/audit_abi.h), so the memset is belt-and-braces
 * against a future field rather than a fix for a hole today; it stays because
 * "there is no padding" is a property of a layout somebody may edit. */
static void audit_export(struct audit_record *rec, const struct audit_event *e) {
    uint8_t *p = (uint8_t *)rec;
    for (size_t i = 0; i < sizeof(*rec); i++) p[i] = 0;

    rec->timestamp    = e->timestamp;
    rec->object       = e->object;
    rec->type         = e->type;
    rec->result       = (int32_t)e->result;
    rec->subject_uid  = e->subject_uid;
    rec->subject_task = (int32_t)e->subject_task;

    for (size_t i = 0; i < sizeof(rec->message) - 1 && e->message[i]; i++)
        rec->message[i] = e->message[i];
}

/* SYS_READ_AUDIT: copy retained audit records into the caller's array, oldest
 * first, and return how many were written. Needs CAP_AUDIT (READ) at slot 7,
 * enforced centrally by the dispatch table.
 *
 * THE STRIDE IS THE EXPORTED RECORD'S, NOT THE INTERNAL EVENT'S, and that
 * sentence is the fix. This loop used to write `sizeof(struct audit_event)` --
 * the kernel's 256 bytes -- at the kernel's stride into `user_events[out]`,
 * where `user_events` was a pointer to a struct of the same NAME and a different
 * shape. For `max` records it wrote `max * 256` bytes into `max * 72` bytes of
 * caller memory. See include/audit_abi.h.
 *
 * Under AUDIT_ABI_LEGACY=1 that is exactly what it does again. SECURITY.md S71. */
void h_read_audit(struct interrupt_frame64 *r) {
    uint64_t user_base = r->rbx;
    uint32_t max = r->rcx;
    if (max > AUDIT_LOG_SIZE) max = AUDIT_LOG_SIZE;

    uint32_t out = 0;
    uint32_t start = (audit_head + AUDIT_LOG_SIZE - audit_count) % AUDIT_LOG_SIZE;

    for (uint32_t i = 0; i < audit_count && out < max; i++) {
        uint32_t idx = (start + i) % AUDIT_LOG_SIZE;
#ifdef AUDIT_ABI_LEGACY
        struct audit_event *user_events = (struct audit_event *)(addr_t)user_base;
        if (copy_to_user(&user_events[out], &audit_log_buffer[idx],
                         sizeof(struct audit_event)) == 0)
            out++;
#else
        struct audit_record rec;
        audit_export(&rec, &audit_log_buffer[idx]);
        void *dst = (void *)(addr_t)(user_base + (uint64_t)out * sizeof(rec));
        if (copy_to_user(dst, &rec, sizeof(rec)) == 0)
            out++;
#endif
    }
    r->rax = out;
}

/* SYS_AUDIT_DIGEST: return the audit-log integrity digest (total event count +
 * running chain-head MAC) and the verify status of the retained window. The
 * slot-7 CAP_AUDIT capability is enforced centrally by the dispatch table. */
void h_audit_digest(struct interrupt_frame64 *r) {
    void *out = (void *)(addr_t)r->rbx;
    int vstatus = audit_verify();

    uint8_t blob[8 + AUDIT_MAC_LEN];
    for (int b = 0; b < 8; b++) blob[b] = (uint8_t)(audit_seq >> (b * 8));
    for (int i = 0; i < AUDIT_MAC_LEN; i++) blob[8 + i] = audit_chain_head[i];

    if (copy_to_user(out, blob, sizeof(blob)) != 0) { r->rax = (uint32_t)SYS_ERR_FAULT; return; }
    r->rax = vstatus;
}

/* NOTE: h_block_read lives in syscall_fs.c, not here. This comment described it
 * from a file it had already left, and described a uid==0 gate its body does not
 * contain. Both were true once; neither was true by 2026-08-29. The authority is
 * CAP_ENCRYPTED_STORAGE at CAPSLOT_AUDIT, from the dispatch table. */

