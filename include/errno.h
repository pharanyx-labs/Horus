#ifndef HORUS_ERRNO_H
#define HORUS_ERRNO_H

/*
 * Horus syscall error codes — the single, shared, descriptive error vocabulary
 * used by BOTH the kernel (src/) and userspace (userspace/, include/).
 *
 * All errors are negative; success is 0 (or a non-negative result). Values are
 * aligned with the familiar POSIX errno numbers where a close match exists, so
 * they read the same way to anyone who knows errno, plus a few Horus-specific
 * codes for capability/auth concepts errno has no name for. Use these names
 * instead of bare -1/-2/-3 so the same condition returns the same code across
 * every syscall, and use sys_strerror() to render a human-readable reason.
 */

#define SYS_OK               0    /* success */

#define SYS_ERR_PERM       (-1)   /* not permitted: missing capability / not owner */
#define SYS_ERR_NOENT      (-2)   /* no such object: user, file, endpoint, task, slot */
#define SYS_ERR_INTR       (-4)   /* a blocking call was interrupted by a signal (EINTR) */
#define SYS_ERR_IO         (-5)   /* I/O error from a device or the storage layer */
#define SYS_ERR_AGAIN     (-11)   /* temporarily unavailable / would block */
#define SYS_ERR_NOMEM     (-12)   /* out of memory / no free task or object slot */
#define SYS_ERR_AUTH      (-13)   /* authentication failed: wrong password or locked out */
#define SYS_ERR_FAULT     (-14)   /* bad user pointer: copy to/from userspace failed */
#define SYS_ERR_BUSY      (-16)   /* resource busy / already in use */
#define SYS_ERR_EXIST     (-17)   /* object already exists */
#define SYS_ERR_INVAL     (-22)   /* invalid argument (bad value, format, or state) */
#define SYS_ERR_PIPE      (-32)   /* write to a pipe with no reader left (EPIPE) */
#define SYS_ERR_RANGE     (-34)   /* value or length out of the permitted range */
#define SYS_ERR_NOSYS     (-38)   /* unknown, reserved, or unimplemented syscall */

/* Horus-specific (no POSIX equivalent), placed clear of the errno range. */
#define SYS_ERR_REVOKED   (-61)   /* capability was revoked (stale lineage generation) */
#define SYS_ERR_NORIGHT   (-62)   /* capability lacks the required right */

/* Render an error code as a short, descriptive, static string. Safe in both
 * the freestanding kernel and freestanding userspace (returns only literals).
 * Non-negative inputs are reported as success. */
static inline const char *sys_strerror(int code) {
    switch (code) {
        case SYS_ERR_PERM:    return "operation not permitted (missing capability)";
        case SYS_ERR_NOENT:   return "no such object";
        case SYS_ERR_INTR:    return "interrupted by a signal";
        case SYS_ERR_IO:      return "I/O error";
        case SYS_ERR_AGAIN:   return "temporarily unavailable";
        case SYS_ERR_NOMEM:   return "out of memory / no free slot";
        case SYS_ERR_AUTH:    return "authentication failed";
        case SYS_ERR_FAULT:   return "bad user address";
        case SYS_ERR_BUSY:    return "resource busy";
        case SYS_ERR_EXIST:   return "already exists";
        case SYS_ERR_INVAL:   return "invalid argument";
        case SYS_ERR_PIPE:    return "broken pipe (no reader)";
        case SYS_ERR_RANGE:   return "value out of range";
        case SYS_ERR_NOSYS:   return "syscall not implemented";
        case SYS_ERR_REVOKED: return "capability revoked";
        case SYS_ERR_NORIGHT: return "capability lacks required right";
        default:              return code >= 0 ? "success" : "unknown error";
    }
}

#endif /* HORUS_ERRNO_H */
