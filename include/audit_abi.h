/* audit_abi.h -- the audit record the kernel hands to ring 3, defined ONCE.
 *
 * SECURITY.md S71: a record the kernel copies into ring 3 has one definition, and
 * both rings compile it.
 *
 * WHY THIS FILE EXISTS.
 *
 * Until 2026-09-01 there were two structs named `struct audit_event`: the
 * kernel's internal record (`src/include/kernel.h`, 256 bytes, twelve fields)
 * and a different one in `include/syscall.h` (72 bytes, seven fields) that ring 3
 * declared its receiving array with. They shared a name, a syscall and nothing
 * else. `h_read_audit` copied `sizeof(struct audit_event)` -- the KERNEL's 256 --
 * at the KERNEL's stride into an array the caller had sized at 72 per element:
 *
 *   - every field was read from the wrong offset. A caller's `timestamp` was the
 *     kernel's `type`, its `subject_uid` was the kernel's `uid` (a field nothing
 *     ever writes, so: zero), its `subject_task` was the kernel's `subject_uid`,
 *     and its `message` began inside the kernel's `object`. An audit reader got
 *     zeros where it asked who did it, which is worse than an error;
 *   - and the copy ran off the end. For `max` records the kernel wrote
 *     `max * 256` bytes into `max * 72` bytes of caller memory -- 184 bytes past
 *     the array per record. `userspace/grantee.c` asks for 2 into a 144-byte
 *     STACK array, so the kernel wrote up to 512 bytes there, 368 of them past
 *     the end, on every PROC_SELFTEST boot since the caller was written.
 *
 * `user_copy` walks the caller's own CR3 and refuses an address the task has not
 * mapped, so this is corruption confined to the caller rather than a privilege
 * boundary -- the same shape and the same seriousness as issue #176, and the same
 * sentence applies: "the kernel wrote to an address the caller did not name"
 * invalidates every argument of the form "we validated the pointer the caller
 * gave us".
 *
 * IT WAS FOUND BY THE FIRST THING THAT EVER ENTERED THE HANDLER, which is exactly
 * what `docs/LIMITATIONS.md` 1.8 said would happen and why it stopped calling
 * that section a limitation. SYS_READ_AUDIT is gated on a real CAP_AUDIT in the
 * dispatch table, so `captest` -- which holds none -- was refused centrally and
 * its check asserted a refusal the TABLE issued. The body had never run.
 *
 * THE FIX IS THE FILE, NOT THE PATCH. A layout two rings must agree on cannot be
 * written down twice; that is `include/block_size.h`'s lesson one subsystem over,
 * where 512 was not a constant but an assumption repeated in six places. So the
 * exported record lives here, both rings include this header, and the two can no
 * longer drift because there is only one of them. It is deliberately NOT the
 * kernel's internal struct: `kind`, `uid`, `arg0`, `arg1` and `path` are declared
 * there and written by nothing, and exporting a field means promising to keep it.
 *
 * The name is `audit_record`, not `audit_event`. Sharing a name was half of how
 * this survived -- both sides compiled, both sides were self-consistent, and
 * nothing but a running probe could tell them apart. The rename makes any caller
 * that was reaching for the old declaration fail to build rather than fail to
 * agree.
 *
 * Falsified by AUDIT_ABI_LEGACY=1, which restores the divergent declaration in
 * ring 3 AND the raw kernel-sized copy in h_read_audit -- both halves, because
 * the defect is the disagreement rather than either side.
 */
#ifndef HORUS_AUDIT_ABI_H
#define HORUS_AUDIT_ABI_H

#include <stdint.h>

#define AUDIT_MESSAGE_MAX 128

#ifdef AUDIT_ABI_LEGACY
/* The pre-2026-09-01 ring-3 declaration, restored for the control arm. It is
 * what the caller believed it was receiving; the kernel never sent it. */
struct audit_record {
    uint32_t timestamp;
    uint32_t type;
    uint32_t subject_uid;
    uint32_t subject_task;
    uint32_t object;
    uint32_t result;
    char     message[48];
};
#else
/* Field order is by alignment, largest first, so the layout has no padding to
 * describe and no hole to leak: every one of the 160 bytes is a named field the
 * kernel fills. The _Static_assert below is what keeps that true -- it is
 * compiled in BOTH rings, so a change made on one side fails the build on the
 * other rather than silently becoming a second layout. */
struct audit_record {
    uint64_t timestamp;                    /* ticks at the time of the event   */
    uint64_t object;                        /* subject-specific: cap slot, uid  */
    uint32_t type;                          /* AUDIT_* below                    */
    int32_t  result;                        /* 0 on success, negative on refusal*/
    uint32_t subject_uid;                   /* the uid that caused the event    */
    int32_t  subject_task;                  /* the task id that caused it       */
    char     message[AUDIT_MESSAGE_MAX];    /* NUL-terminated, zero-padded      */
};

_Static_assert(sizeof(struct audit_record) == 160,
               "the audit record's on-the-wire size is part of the syscall ABI; "
               "both rings compile this assert, so a change on one side must be "
               "a deliberate change to both");
#endif /* AUDIT_ABI_LEGACY */

#endif /* HORUS_AUDIT_ABI_H */
