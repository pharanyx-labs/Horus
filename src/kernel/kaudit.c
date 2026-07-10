/* kaudit.c -- tamper-evident audit log: append (audit_log), canonical
 * serialization, per-entry + chained MACs, verification, and the read/digest
 * syscall handlers. Owns the audit ring buffer. Split out of syscall.c. */
#include "syscall_internal.h"

static struct audit_event audit_log_buffer[AUDIT_LOG_SIZE];
static uint32_t audit_head = 0;
static uint32_t audit_count = 0;

/* Tamper-evidence (rust/src/audit.rs). For each ring slot we keep the entry's
 * absolute sequence number and its per-entry MAC; `audit_chain_head` is a
 * running commitment over every event ever appended (kept even after the ring
 * overwrites the slot). All keyed by the per-boot kernel_pepper. */
#define AUDIT_MAC_LEN 32
static uint8_t  audit_mac[AUDIT_LOG_SIZE][AUDIT_MAC_LEN];
static uint64_t audit_entry_seq[AUDIT_LOG_SIZE];
static uint8_t  audit_chain_head[AUDIT_MAC_LEN];
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

/* Initialize the audit chain once the per-boot pepper is seeded (called from
 * users_init right after secure_random_bytes(kernel_pepper)). */
void audit_chain_start(void) {
    if (rust_audit_chain_init(kernel_pepper, sizeof(kernel_pepper), audit_chain_head) == 0) {
        audit_seq = 0;
        audit_chain_ready = 1;
    }
}

/* Re-derive each retained entry's MAC and compare to what was stored, using a
 * constant-time compare. Returns 0 if the whole retained window is intact, or
 * (index + 1) of the first tampered slot, or -1 if the chain is uninitialized. */
static int audit_verify(void) {
    if (!audit_chain_ready) return -1;
    uint8_t buf[8 * 10 + 64 + 128];
    uint8_t computed[AUDIT_MAC_LEN];
    uint32_t start = (audit_head + AUDIT_LOG_SIZE - audit_count) % AUDIT_LOG_SIZE;
    for (uint32_t i = 0; i < audit_count; i++) {
        uint32_t idx = (start + i) % AUDIT_LOG_SIZE;
        size_t len = audit_serialize(&audit_log_buffer[idx], buf);
        if (rust_audit_entry_mac(kernel_pepper, sizeof(kernel_pepper),
                                 audit_entry_seq[idx], buf, len, computed) != 0)
            return (int)(i + 1);
        if (!rust_audit_mac_eq(computed, audit_mac[idx]))
            return (int)(i + 1);
    }
    return 0;
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

    /* Tamper-evidence: MAC this entry (binding its sequence number) and extend
     * the running chain head. The keyed-hash logic lives in rust/src/audit.rs. */
    if (audit_chain_ready) {
        uint8_t buf[8 * 10 + 64 + 128];
        size_t len = audit_serialize(e, buf);
        rust_audit_chain_record(kernel_pepper, sizeof(kernel_pepper), audit_seq,
                                buf, len, audit_chain_head, audit_mac[audit_head]);
        audit_entry_seq[audit_head] = audit_seq;
        audit_seq++;
    }

    audit_head = (audit_head + 1) % AUDIT_LOG_SIZE;
    if (audit_count < AUDIT_LOG_SIZE) audit_count++;
}


void h_read_audit(struct regs *r) {
    struct audit_event *user_events = (struct audit_event *)(addr_t)r->ebx;
    uint32_t max = r->ecx;
    if (max > AUDIT_LOG_SIZE) max = AUDIT_LOG_SIZE;

    uint32_t out = 0;
    uint32_t start = (audit_head + AUDIT_LOG_SIZE - audit_count) % AUDIT_LOG_SIZE;

    for (uint32_t i = 0; i < audit_count && out < max; i++) {
        uint32_t idx = (start + i) % AUDIT_LOG_SIZE;
        if (copy_to_user(&user_events[out], &audit_log_buffer[idx], sizeof(struct audit_event)) == 0) {
            out++;
        }
    }
    r->eax = out;
}

/* SYS_AUDIT_DIGEST: return the audit-log integrity digest (total event count +
 * running chain-head MAC) and the verify status of the retained window. The
 * slot-7 CAP_AUDIT capability is enforced centrally by the dispatch table. */
void h_audit_digest(struct regs *r) {
    void *out = (void *)(addr_t)r->ebx;
    int vstatus = audit_verify();

    uint8_t blob[8 + AUDIT_MAC_LEN];
    for (int b = 0; b < 8; b++) blob[b] = (uint8_t)(audit_seq >> (b * 8));
    for (int i = 0; i < AUDIT_MAC_LEN; i++) blob[8 + i] = audit_chain_head[i];

    if (copy_to_user(out, blob, sizeof(blob)) != 0) { r->eax = (uint32_t)SYS_ERR_FAULT; return; }
    r->eax = vstatus;
}

/* SYS_BLOCK_READ: raw block read. The slot-7 CAP_BLOCK_DEV capability is
 * enforced centrally by the dispatch table; the uid==0 gate stays here (its
 * distinct -2 return is part of the ABI). */

