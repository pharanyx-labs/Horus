#ifndef USERSPACE_SYSCALL_H
#define USERSPACE_SYSCALL_H

#include <stdint.h>
#include <stddef.h>
#include "errno.h"   /* shared, descriptive syscall error codes (SYS_ERR_*) */

/* MUST stay byte-identical to the copy in src/include/kernel.h
 * (SYS_GET_TASK_INFO ABI). */
/* Task states, as reported in struct task_info.state below. Mirrors the
 * TASK_* set in src/include/kernel.h -- state is part of the syscall ABI, so a
 * ring-3 caller needs the names rather than bare numbers. */
#define TASK_DEAD           0
#define TASK_RUNNABLE       1
#define TASK_BLOCKED_IPC    2   /* in SYS_IPC_CALL, waiting for a reply */
#define TASK_BLOCKED_NOTIF  3   /* in SYS_WAIT_NOTIFY, waiting for a badge */
#define TASK_BLOCKED_WAIT   4   /* in SYS_WAIT, until the target task exits */

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

struct program_header {
    uint32_t magic;
    uint32_t entry;
    uint32_t size;
    char     name[32];
};

struct audit_event {
    uint32_t timestamp;
    uint32_t type;
    uint32_t subject_uid;
    uint32_t subject_task;
    uint32_t object;
    uint32_t result;
    char     message[48];
};

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
/* 38-45: the legacy in-memory capfs. Removed — the syscalls fail closed and the
 * numbers are reserved (kept defined, not reused) so no future syscall silently
 * inherits an old capfs caller. The encrypted fs_server is the only filesystem. */
#define SYS_FS_MINT_FILE  38  /* reserved (removed) */
#define SYS_FS_LOOKUP     39  /* reserved (removed) */
#define SYS_FS_CREATE     40  /* reserved (removed) */
#define SYS_FS_DELETE     41  /* reserved (removed) */
#define SYS_FS_READDIR    42  /* reserved (removed) */
#define SYS_FS_GET_ROOT   43  /* reserved (removed) */
#define SYS_FS_READ       44  /* reserved (removed) */
#define SYS_FS_WRITE      45  /* reserved (removed) */
#define SYS_REGISTER_STORAGE_BACKEND 46
#define SYS_BLOCK_READ   47
#define SYS_BLOCK_WRITE  48
#define SYS_REGISTER_FS_SERVER 49
#define SYS_CONNECT_FS_SERVER  50
/* Capability-algebra syscalls. 4/8/9 predate the SYS_* naming and lived in the
 * dispatch table as bare numeric literals until roadmap 2.1 needed to CALL one
 * from ring 3: SYS_CAP_MINT is how a task narrows a capability's rights before
 * delegating it, which is the operation the whole "delegation may only reduce"
 * invariant is stated over, and it was unnameable from userspace. Authority for
 * all four is enforced inside the cap_* primitives, not by a table slot. */
#define SYS_CAP_MINT            4   /* (dest_slot, src_slot, rights) -> 0; copy within the CALLER's own cspace with rights masked to (rights & the source's). Cannot widen. */
#define SYS_CAP_TRANSFER        8   /* (dest_slot, src_slot) -> 0 */
#define SYS_CAP_MOVE            9   /* (dest_slot, src_slot) -> 0 */
#define SYS_CAP_REVOKE         51
#define SYS_AUDIT_DIGEST       52
#define SYS_PREEMPT_TRACE      53   /* PREEMPT_SELFTEST builds only; NOSYS otherwise */
#define SYS_SIGACTION          54
#define SYS_SIGRETURN          55

/* Encrypted object-store API for the userspace filesystem server (Phase 2).
 * These expose the kernel's persistent, encrypted inode/block store to a ring-3
 * FS server WITHOUT handing it key material — the AEAD stays in the kernel. The
 * server addresses storage by (inode, logical block) and builds all filesystem
 * semantics (names, directories, permissions) on top. Gated like the raw block
 * syscalls: CAP_BLOCK_DEV (slot 7) + uid 0. */
#define SYS_FS_INODE_ALLOC     56   /* (type) -> ino */
#define SYS_FS_INODE_FREE      57   /* (ino)  -> 0 */
#define SYS_FBLOCK_READ        58   /* (ino, block, buf) -> BLOCK_SIZE (decrypt+verify) */
#define SYS_FBLOCK_WRITE       59   /* (ino, block, buf, len) -> len (encrypt, fresh nonce) */
#define SYS_FS_STAT            60   /* (ino, struct fs_stat*) -> 0 */
#define SYS_FS_SET_SIZE        61   /* (ino, size) -> 0 (server owns logical file size) */
#define SYS_BRK                62   /* (addr) -> new break; addr=0 queries current break */
#define SYS_KILL               63   /* (tid) -> terminate task tid; needs a CAP_TCB cap to it */
#define SYS_EXEC_NAMED         64   /* (name) -> replace the caller's own image with a named embedded binary; does not return on success */
#define SYS_CAP_GRANT          65   /* (target_tid, src_slot, dest_slot) -> copy caller's cap into a supervised child's cspace slot */
#define SYS_SIGNAL             66   /* (target_tid, signum) -> deliver a signal to a task held via CAP_TCB */
#define SYS_SIGMASK            67   /* (how, mask) -> old mask; block/unblock this task's own signals */
#define SYS_SPAWN_ARG          68   /* () -> the one-word argument this task was spawned with */
#define SYS_GET_ARGV           69   /* (char ***out) -> argc; writes the argv[] base to *out */
#define SYS_SPAWN_IMAGE        70   /* (image, len, arg, argv, argc) -> pid; spawn a child from a caller-supplied program image (execve-from-fd) */
#define SYS_EXEC_IMAGE         71   /* (image, len, 0, argv, argc) -> replace the caller's own image with a caller-supplied one; no return on success */
#define SYS_SIGALTSTACK        72   /* (ss_sp, ss_size) -> 0; register this task's alternate signal stack (ss_size 0 disables) */
#define SYS_IPC_SENDER         73   /* (ep, uint32_t *out_gid) -> uid; kernel-attested identity of an endpoint's last sender */
#define SYS_FS_SET_META        74   /* (ino, mode, uid, gid) -> 0; persist an inode's owner/mode (fs server only) */
#define SYS_IPC_REPLY_TO       75   /* (req_ep, msg, len) -> 0; reply to the last sender on req_ep (multi-client safe routing) */
#define SYS_FS_INODE_LINK      76   /* (ino) -> 0; increment an inode's hard-link count (fs server only) */
#define SYS_BOOT_MODULE_INFO   77   /* (index, struct boot_module_info*) -> total module count; fills *info for a valid index (store owner only) */
#define SYS_BOOT_MODULE_READ   78   /* (index, offset, buf, len) -> bytes copied from a boot module's payload (store owner only) */
#define SYS_MAP_PHYS           79   /* (dev_slot, paddr, vaddr, len, flags) -> 0; map one frame the named device declares into the caller's address space (CAP_IO_DEVICE + WRITE in dev_slot) */
#define SYS_IOPORT_GRANT       80   /* (dev_slot) -> 0; grant native ring-3 in/out on the named device's ports via the TSS I/O bitmap (CAP_IO_DEVICE + WRITE in dev_slot) */
#define SYS_IRQ_REGISTER       81   /* (dev_slot, irq, notif_slot, badge) -> 0; route an IRQ the named device declares to an async notification (CAP_IO_DEVICE + WRITE in dev_slot) */
#define SYS_CONSOLE_OWNED      82   /* () -> 1 if a ring-3 console server owns the console hardware (so fd-1 output must route through it, not the kernel), else 0; read-only status, self-authorizing */
#define SYS_PIPE               83   /* () -> (read_slot<<16)|write_slot; create a bounded pipe, install a read/write CAP_PIPE in the caller's cspace */
#define SYS_PIPE_READ          84   /* (slot, buf, len) -> bytes; 0 = EOF, SYS_ERR_AGAIN = empty-but-writers-open */
#define SYS_PIPE_WRITE         85   /* (slot, buf, len) -> bytes; SYS_ERR_AGAIN = full-but-reader-open, SYS_ERR_PIPE = no reader */
#define SYS_PIPE_CLOSE         86   /* (slot) -> 0; drop a pipe-end cap and unref that end */
#define SYS_STDIO_INFO         87   /* () -> bit0 stdin-is-pipe, bit1 stdout-is-pipe (spawner-wired); read by posix_init */
#define SYS_TASK_RESUME        89   /* (tid) -> 0; make a spawned-but-suspended child schedulable. Needs a CAP_TCB to the target (or admin), exactly like SYS_KILL. Spawn leaves a child suspended so its supervisor can endow it before it runs. */
#define SYS_RETYPE             90   /* (untyped_slot, kobj_type, count, dest_slot) -> objects created; carve kernel objects out of untyped memory. Authority is the CAP_UNTYPED at untyped_slot (WRITE). */
#define SYS_UNTYPED_INFO       91   /* (untyped_slot, struct untyped_info*) -> 0; size/watermark/free of the region named at untyped_slot (READ). */
#define SYS_IRQ_POLICY_INFO    92   /* (struct irq_policy_info*) -> 0; roadmap 1.1 audit counters. IRQ_POLICY_AUDIT builds only; NOSYS otherwise. CAP_KERNEL_LOG (READ). */
#define SYS_DMESG              88   /* (buf, offset, max) -> bytes; copy a chunk of the kernel message ring at `offset` to buf. CAP_KERNEL_LOG (READ) in CAPSLOT_KERNEL_LOG, else SYS_ERR_PERM */
#define SYS_TASK_EXIT_INFO     93   /* (struct task_exit_info*) -> 0; why the last task this caller waited on died. Self-scoped (no capability): waiting already entitled the caller to observe it. */
#define SYS_IPC_RECV_BLOCK     94   /* (ep_slot, buf, max) -> len; like SYS_IPC_RECV but SLEEPS on an empty queue instead of returning IPC_AGAIN. CAP_ENDPOINT + READ, same gate. */
#define SYS_MAP_FRAME          95   /* (frame_slot, vaddr, rights) -> 0; map the KOBJ_FRAME named by a CAP_FRAME into the caller's own address space. PTE bits come from (cap rights & rights); W|X together is refused. */
#define SYS_UNMAP_FRAME        96   /* (frame_slot, vaddr) -> 0; remove that mapping. The PTE at vaddr must name this capability's own frame. */
#define SYS_CAP_ENUMERATE      97   /* (tid, slot, struct cap_info*) -> 0; read one capability slot of task `tid` (roadmap 3.6). CAP_DEBUG (READ) at CAPSLOT_DEBUG. */
#define SYS_CLOCK_GETTIME      98   /* (clock_id, struct horus_timespec*) -> 0; monotonic time since boot (roadmap 2.2). No capability; 10 ms resolution by design. */
/* The largest frame one SYS_RETYPE may carve, in pages. Ring 3 needs it to know
 * what it may ask for; the kernel bounds it again regardless (src/include/kernel.h). */
#define MAX_FRAME_PAGES        64

#define SYS_MAP_REGION         99   /* (first_slot, count, vaddr, rights) -> 0; map `count` CAP_FRAMEs from consecutive cspace slots at consecutive pages from vaddr. ALL OR NOTHING: a failure withdraws every page the call mapped, so an error leaves the address space untouched. Max 64 pages. */
#define SYS_FRAME_PAGES       100   /* (frame_slot) -> pages (>0); how many contiguous pages the CAP_FRAME at `frame_slot` names. Authority is that capability; no rights floor, because the size is not the contents. Discloses nothing SYS_MAP_FRAME does not already disclose to the same holder. */
#define SYS_DEVICE_INFO       102   /* (dev_slot, struct dev_info*) -> 0; what the device named by the CAP_IO_DEVICE at dev_slot declares: ids, MMIO ranges, port ranges, IRQ lines. CAP_IO_DEVICE + READ in dev_slot, and it reports THAT device only. */
#define SYS_FORK              101   /* () -> child tid in the parent, 0 in the child; duplicate this task, its memory copy-on-write. Gated on the same slot-3 capability as SYS_SPAWN: fork is a second way to create a task, so it answers to the capability that gates the first. The child inherits the caller's capabilities as DERIVED copies, so revoking the parent's sweeps the child's -- see sys_fork(). */

/* Reserved cspace slots the spawner wires a child's pipe stdio into (must match
 * src/include/kernel.h). */
#define STDIN_PIPE_SLOT        14
#define STDOUT_PIPE_SLOT       15

/* Signal numbers (1..31). A task registers a handler with sys_signal() (see
 * below); an unhandled signal terminates the target (default action). */
#define SIG_KILL                9   /* uncatchable: always terminates, never masked */
#define SIG_USR1               10
#define SIG_USR2               12
#define SIG_TERM               15
#define SIG_MAX                31   /* signal numbers are 1..31 (mirrors kernel.h) */

/* sys_sigmask() `how`: combine the supplied mask with the current blocked set. */
#define SIG_SETMASK             0   /* replace the blocked set */
#define SIG_BLOCK               1   /* add to the blocked set */
#define SIG_UNBLOCK             2   /* remove from the blocked set */

/* sys_sigaltstack(): smallest alternate signal stack the kernel accepts, and the
 * ss_size value that disables the altstack (run handlers on the interrupted
 * stack). Mirror of SIG_ALTSTACK_MIN in the kernel. */
#define SIGSTKSZ_MIN         2048
#define SS_DISABLE              0

/* Inode metadata returned by SYS_FS_STAT. Kept ABI-stable across kernel/user. */
struct fs_stat {
    uint64_t size;
    uint32_t type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t links;
};

/* Object types used by the FS server / SYS_FS_INODE_ALLOC. */
#define FS_TYPE_FILE 1
#define FS_TYPE_DIR  2

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

/* Arguments are 64-bit: they carry user pointers, and userspace is now 64-bit,
 * so a 32-bit argument would truncate any address above 4 GiB. Nothing reaches
 * that today (USER_MAX_VADDR is 8 MiB), but the whole point of the higher-half
 * move was to stop the address space being boxed in, and a 32-bit argument here
 * would silently re-impose that bound at the ABI.
 *
 * The RETURN is 64-bit too, and not merely for symmetry: SYS_BRK and SYS_SBRK
 * return an ADDRESS, so a 32-bit return would truncate the program break. The
 * negative error codes still work: the kernel stores a (uint32_t)SYS_ERR_* into
 * rax, which zero-extends, and every wrapper hands the result back as `int` --
 * taking exactly the low 32 bits that hold the code. */
/* Pass a user POINTER to the kernel.
 *
 * The argument registers are 64-bit (see syscall() below), so this is only ever
 * a widening cast -- which is exactly why getting it wrong is silent. Two
 * wrappers, sys_dmesg() and sys_audit_digest(), passed their buffer as
 * `(uint32_t)(unsigned long)ptr` and so handed the kernel the low 32 bits of an
 * address the caller never named (issue #176).
 *
 * That was invisible for as long as it was because of WHERE the survivors live:
 * USER_IMAGE_ASLR_BASE is 16 GiB with 4 TiB of randomisation, so every static
 * and global in every PIE image is above 4 GiB *by construction* and always
 * truncated -- while a stack buffer sits around 8 MiB and is unaffected. Every
 * caller in the tree happened to pass a stack buffer, and the two captest checks
 * that name these syscalls both assert a CAPABILITY REFUSAL, which returns
 * before the pointer is ever read.
 *
 * The failure is not fail-closed, and that is the part worth keeping. The
 * kernel walks the truncated address in the caller's own address space: if
 * nothing is mapped there it refuses (what #176 observed), but if something IS
 * -- the stack lives at ~8 MiB and the heap at 16 MiB in a non-high-heap build,
 * both reachable by truncation -- then copy_to_user writes kernel-supplied bytes
 * into a page of the caller's address space that the caller never nominated.
 * Confined to the caller (user_copy walks tasks[cur].cr3, never another task's),
 * so this is corruption and not a privilege boundary -- but "the kernel wrote to
 * an address the caller did not name" invalidates every argument of the form
 * "we validated the pointer the caller gave us".
 *
 * Use this for every pointer argument. `tools/check_syscall_abi.py` fails the
 * build if any wrapper narrows a pointer, and is a required CI job. */
#ifdef SYSCALL_PTR_TRUNC32
/* Control arm for issue #176 -- the pre-2026-08-20 truncating cast, verbatim.
 * Never a shipping configuration; `make smoke-klog-forge` must go red under it. */
#define SYSCALL_UPTR(p) ((uint64_t)(uint32_t)(unsigned long)(p))
#else
#define SYSCALL_UPTR(p) ((uint64_t)(uintptr_t)(p))
#endif

static inline uint64_t syscall(uint32_t num, uint64_t a, uint64_t b, uint64_t c) {
    uint64_t ret;
    asm volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(a), "c"(b), "d"(c)
        : "memory"
    );
    return ret;
}

/* Up to 5 register args (num, a..e); the kernel reads rax,rbx,rcx,rdx,rsi,rdi.
 * Bind the high args directly to rsi/rdi with the "S"/"D" constraints rather
 * than moving them in and clobbering. (This was originally a workaround for the
 * 32-bit PIE register allocator running out of registers -- ebx being the GOT
 * pointer, and esi/edi being both operands and clobbers. Under -m64 that
 * pressure is gone: addressing is RIP-relative and there is no GOT register.
 * The form is kept because binding directly is still the clearer way to say it.)
 * `f` is accepted for source compatibility but not passed (no sixth arg
 * register in this ABI). */
static inline uint64_t syscall6(uint32_t num, uint64_t a, uint64_t b, uint64_t c,
                                 uint64_t d, uint64_t e, uint64_t f) {
    uint64_t ret;
    register uint64_t r8 asm("r8") = f;   /* 6th arg in r8 (saved in the trap frame) */
    asm volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "b"(a), "c"(b), "d"(c), "S"(d), "D"(e), "r"(r8)
        : "memory"
    );
    return ret;
}

static inline void sys_yield(void) {
    syscall(SYS_YIELD, 0, 0, 0);
}

/* Register (handler != 0) or clear (handler == 0) this task's own fault-signal
 * handler. On a ring-3 fault the kernel enters the handler at ring 3 with the
 * signal number in ebx and the faulting address in ecx, instead of killing the
 * task. Returns 0 on success, -1 if the handler is not in the user code window. */
static inline int sys_signal(uintptr_t handler) {
    return syscall(SYS_SIGACTION, (uint64_t)handler, 0, 0);
}

/* Called from a handler to resume the exact pre-signal context. Does not return
 * to the handler on success (execution jumps back to the interrupted point). */
static inline void sys_sigreturn(void) {
    syscall(SYS_SIGRETURN, 0, 0, 0);
}

/* Block/unblock this task's own signals. `how` is SIG_SETMASK / SIG_BLOCK /
 * SIG_UNBLOCK; `mask` is a bitmask (bit N = signal N). A blocked signal that
 * arrives stays pending and is delivered once unblocked. SIG_KILL can never be
 * blocked. Returns the previous blocked mask. */
static inline uint32_t sys_sigmask(uint32_t how, uint32_t mask) {
    return syscall(SYS_SIGMASK, how, mask, 0);
}

static inline int sys_print(const char *s) {
    return syscall(SYS_PRINT, (uint64_t)(uintptr_t)s, 0, 0);
}

static inline void sys_exit(void) {
    syscall(SYS_EXIT, 0, 0, 0);
    for(;;);
}

static inline int sys_get_line(char *buf, size_t max) {
    return syscall(SYS_GET_LINE, (uint64_t)(uintptr_t)buf, max, 0);
}

static inline void *sys_sbrk(intptr_t increment) {
    return (void*)(uintptr_t)syscall(SYS_SBRK, (uint32_t)increment, 0, 0);
}

/* sys_brk(addr): set the program break to addr and return the new break.
 * If addr is NULL/0, returns the current break without changing it.
 * On failure (out of range) returns the unchanged current break — callers
 * should compare the return value to addr to detect failure, matching Linux. */
static inline void *sys_brk(void *addr) {
    return (void*)(uintptr_t)syscall(SYS_BRK, (uint64_t)(uintptr_t)addr, 0, 0);
}

static inline int sys_write(int fd, const void *buf, size_t len) {
    return syscall(SYS_WRITE, (uint32_t)fd, (uint64_t)(uintptr_t)buf, (uint32_t)len);
}

static inline int sys_read(int fd, void *buf, size_t len) {
    return syscall(SYS_READ, (uint32_t)fd, (uint64_t)(uintptr_t)buf, (uint32_t)len);
}

static inline int sys_open(const char* path) {
    return syscall(SYS_OPEN, (uint64_t)(uintptr_t)path, 0, 0);
}

static inline int sys_wait(int task_id) {
    return syscall(SYS_WAIT, (uint32_t)task_id, 0, 0);
}

/* ---- Why a task died (finding G-8) ----------------------------------------
 *
 * sys_wait() returns 0 for every death alike, so a supervisor could report only
 * THAT its child ended, never why. A crashed shell and a hung one then look
 * identical in a serial capture — which is how G-8 signature A was read as a
 * livelock for two days when the shell was in fact being killed mid-write.
 *
 * The kernel cannot simply print the reason: once ring-3 console_server owns the
 * console, kernel print() records to the klog and stops reaching the wire, and
 * writing anyway is finding #126 (a second UART writer splits the prompt). So
 * the cause is fetched in band and printed by the supervisor through
 * console_server like any other output.
 *
 * Mirrors the TASK_EXIT_* constants and struct task_exit_info in
 * src/include/kernel.h — keep the two in step. */
#define TASK_EXIT_NONE      0   /* no death recorded (nothing waited on yet)      */
#define TASK_EXIT_NORMAL    1   /* SYS_EXIT: the task ended itself                */
#define TASK_EXIT_KILLED    2   /* SYS_KILL by another task; detail = killer tid  */
#define TASK_EXIT_SIGNAL    3   /* uncaught signal, default action; detail = signum*/
#define TASK_EXIT_FAULT     4   /* ring-3 trap, no handler; detail = trap vector  */
#define TASK_EXIT_PAGEFAULT 5   /* #PF killed the task; detail = 14, addr = CR2   */

struct task_exit_info {
    int32_t  tid;       /* the task that died                            */
    int32_t  reason;    /* TASK_EXIT_*                                   */
    uint32_t detail;    /* vector / signum / killer tid, per reason      */
    uint32_t err;       /* #PF error code; 0 otherwise                   */
    uint64_t rip;       /* faulting RIP; 0 when not a fault              */
    uint64_t addr;      /* faulting address (#PF only); 0 otherwise      */
    char     name[32];  /* the dead task's name, captured before reuse   */
};

/* Fill *out with the death record of the last task this caller waited on.
 * Returns 0, or a negative SYS_ERR_*. Before any wait has been satisfied,
 * out->reason is TASK_EXIT_NONE rather than a stale answer. Valid until the
 * caller's next completed sys_wait(), so it survives relaunching the child. */
static inline int sys_task_exit_info(struct task_exit_info *out) {
    return (int)syscall(SYS_TASK_EXIT_INFO, (uint64_t)(uintptr_t)out, 0, 0);
}

/* Terminate task `tid`. Authorised by holding a CAP_TCB capability to the target
 * in the caller's cspace (spawners get one for each child), or CAP_USER (admin).
 * Returns 0 on success, negative on permission/argument error. */
static inline int sys_kill(int tid) {
    return syscall(SYS_KILL, (uint32_t)tid, 0, 0);
}

static inline int sys_get_task_info(int id, struct task_info *out) {
    return syscall(SYS_GET_TASK_INFO, (uint32_t)id, (uint64_t)(uintptr_t)out, 0);
}

static inline int sys_exec(uint32_t load_base, uint32_t entry) {
    return syscall(SYS_EXEC, load_base, entry, 0);
}

static inline int sys_getpid(void) {
    return syscall(SYS_GETPID, 0, 0, 0);
}

/* 1 if a ring-3 console server owns the console hardware. When it does, the
 * kernel's fd-1 write path (SYS_WRITE -> print) stays hands-off the hardware to
 * keep the console single-writer, so a client that wants its stdout on screen must
 * route it through the server instead. */
static inline int sys_console_owned(void) {
    return syscall(SYS_CONSOLE_OWNED, 0, 0, 0);
}

/* ---- Capability slot map (mirrors src/include/kernel.h CAPSLOT_*) ----------
 *
 * IPC is capability-ADDRESSED (audit finding C-1): every IPC syscall's first
 * argument is a CSPACE SLOT, and the kernel derives the endpoint/notification
 * from the capability there — checking its type, the required right, and its
 * lineage. Userspace can no longer name a kernel IPC object directly, so a task
 * can only talk to services something delegated to it.
 *
 * A task is born with exactly one endpoint capability: its own private reply
 * endpoint. Everything else arrives by delegation (SYS_CAP_GRANT from a
 * supervisor, propagation at spawn, or SYS_CONNECT_FS_SERVER). */
/* Capability rights, mirroring src/include/kernel.h. These are ABI in the same
 * sense the CAPSLOT_* numbers are: the kernel compares against these exact bits,
 * so the two lists must not drift. Ring 3 needs them because SYS_CAP_MINT and
 * SYS_MAP_FRAME both take a rights word. */
#define CAP_RIGHT_READ          (1u << 0)
#define CAP_RIGHT_WRITE         (1u << 1)
#define CAP_RIGHT_EXEC          (1u << 2)
#define CAP_RIGHT_GRANT         (1u << 3)
#define CAP_RIGHT_MINT          (1u << 4)
#define CAP_RIGHT_REVOKE        (1u << 5)
#define CAP_RIGHT_AUDIT_WRITE   (1u << 6)

#define CAPSLOT_TCB         0    /* CAP_TCB on self                            */
#define CAPSLOT_FRAME       3    /* CAP_FRAME for the task's image window      */
#define CAPSLOT_REPLY_EP    4    /* CAP_ENDPOINT: this task's PRIVATE reply ep */
#define CAPSLOT_CONSOLE_EP  5    /* CAP_ENDPOINT: console service (send-only for clients) */
#define CAPSLOT_USER        6    /* CAP_USER admin                             */
#define CAPSLOT_AUDIT       7    /* CAP_AUDIT / object-store (server-specific) */
#define CAPSLOT_CONSOLE     8    /* CAP_CONSOLE                                */
#define CAPSLOT_STORAGE     9    /* CAP_ENCRYPTED_STORAGE                      */
#define CAPSLOT_IO_DEVICE  10    /* CAP_IO_DEVICE: the task's primary device    */
#define CAPSLOT_IO_DEVICE_ALT 20 /* CAP_IO_DEVICE: a SECOND device, for a task
                                  * that legitimately drives two (devcaptest).
                                  * The slot is a convention, not authority --
                                  * the capability in it is                    */
#define CAPSLOT_NOTIFY     11    /* CAP_NOTIFICATION: fs-ready rendezvous      */
#define CAPSLOT_FS_LISTEN  12    /* CAP_ENDPOINT: fs service listen (server)   */
#define CAPSLOT_KERNEL_LOG 16    /* CAP_KERNEL_LOG:  SYS_DMESG                 */
#define CAPSLOT_BOOT_MODULE 17   /* CAP_BOOT_MODULE: boot-module read surface  */
#define CAPSLOT_DEBUG      19    /* CAP_DEBUG:       observation only          */
#define CAPSLOT_UNTYPED    18    /* CAP_UNTYPED: kernel-object memory (init)   */
#define CAPSLOT_REPLY      21    /* CAP_REPLY: one-shot right to answer the
                                 * request just received (minted by RECV,
                                 * consumed by REPLY_TO). Server-side only. */
#define CAPSLOT_FS_EP      20    /* CAP_ENDPOINT: fs service (sys_connect_fs_server) */

/* ---- Untyped memory (roadmap 0.3, audit finding I-7) ----------------------
 *
 * Creating a kernel object is an exercise of authority, and CAP_UNTYPED is that
 * authority. A task holding one may retype part of the region it names into
 * endpoints and notifications; a task holding none cannot create a kernel object
 * at all. The region is a hard bound on the kernel memory that task can ever
 * consume, so delegating a small one is a confinement primitive.
 *
 * Allocation inside a region is a bump pointer that never moves backwards
 * (seL4's discipline): destroying an object does not return its bytes. That is
 * what makes reuse safe — bytes only become reusable once every capability into
 * the region has been revoked, which is the same event that invalidates any
 * stale reference to an object in it. */
#define KOBJ_CNODE          1    /* a cspace; not retypable from ring 3 yet    */
#define KOBJ_ENDPOINT       2    /* struct endpoint  -> CAP_ENDPOINT           */
#define KOBJ_NOTIFICATION   3    /* struct notification -> CAP_NOTIFICATION    */
#define KOBJ_FRAME          4    /* a run of 4 KiB pages -> CAP_FRAME          */

/* What one device declares (SYS_DEVICE_INFO). MUST stay byte-identical to struct
 * dev_info in src/include/kernel.h — the kernel fills this layout and copies it
 * out across copy_to_user.
 *
 * A driver cannot be written against a device whose resources it cannot discover:
 * a BAR is assigned by firmware and differs per machine, so hardcoding one is
 * how a driver ends up mapping whatever happens to be at that address. This is
 * the capability-scoped answer — it reports the device THIS capability names, and
 * nothing about any other, so enumerating the machine is not a side effect of
 * holding one device.
 *
 * The array bounds must match IODEV_MAX_MMIO / IODEV_MAX_PORT in
 * src/include/kernel.h; the kernel _Static_asserts that they do. */
struct dev_info {
    uint16_t vendor;      /* PCI vendor id, 0 for a platform device */
    uint16_t device;      /* PCI device id, 0 for a platform device */
    uint16_t bdf;         /* (bus<<8)|(dev<<3)|fn, 0xFFFF if not a PCI function */
    uint16_t n_mmio;      /* MMIO ranges declared */
    uint32_t classcode;   /* class:subclass:prog-if */
    uint32_t irq_mask;    /* bit n set: this device may route legacy IRQ n */
    uint32_t n_port;      /* port ranges declared */
    uint32_t reserved;
    struct { uint64_t base, len; } mmio[8];
    struct { uint32_t base, len; } port[8];
};

/* Report what the device named by the CAP_IO_DEVICE (READ right) at `dev_slot`
 * declares. Returns 0 or a negative SYS_ERR_*. */
static inline int sys_device_info(uint32_t dev_slot, struct dev_info *out) {
    return (int)syscall(SYS_DEVICE_INFO, dev_slot, (uint64_t)(uintptr_t)out, 0);
}

/* MUST stay byte-identical to struct untyped_info in src/include/kernel.h — the
 * kernel fills this layout and copies it out across copy_to_user. */
struct untyped_info {
    uint64_t size;        /* total bytes in the region   */
    uint64_t watermark;   /* bytes consumed              */
    uint64_t free;        /* size - watermark            */
    uint32_t objects;     /* live objects carved from it */
    uint32_t reserved;
};

/* Carve `count` objects of `kobj_type` out of the untyped region named by the
 * CAP_UNTYPED in `untyped_slot` (needs WRITE), installing a capability for each
 * into dest_slot..dest_slot+count-1 of the caller's own cspace. Returns the
 * number created (which may be fewer than asked if the region runs out), or a
 * negative SYS_ERR_*. */
static inline int sys_retype(int untyped_slot, int kobj_type, int count, int dest_slot) {
    return (int)syscall6(SYS_RETYPE, (uint32_t)untyped_slot, (uint32_t)kobj_type,
                         (uint32_t)count, (uint32_t)dest_slot, 0, 0);
}

/* Retype `count` frames of `pages` contiguous pages each. A separate wrapper
 * rather than a fifth parameter on sys_retype, so that not one existing call
 * site changes: they pass 0 for the length and get the ordinary one-page frame.
 * `pages` is meaningful for KOBJ_FRAME alone and is REFUSED, not ignored, on any
 * other class. Bounded by MAX_FRAME_PAGES. */
static inline int sys_retype_sized(int untyped_slot, int count, int dest_slot,
                                   unsigned int pages) {
    return (int)syscall6(SYS_RETYPE, (uint32_t)untyped_slot, (uint32_t)KOBJ_FRAME,
                         (uint32_t)count, (uint32_t)dest_slot, (uint32_t)pages, 0);
}

/* How much of the region named at `untyped_slot` (needs READ) is left. A budget
 * a task cannot observe is one it cannot manage. */
static inline int sys_untyped_info(int untyped_slot, struct untyped_info *out) {
    return (int)syscall(SYS_UNTYPED_INFO, (uint32_t)untyped_slot,
                        (uint64_t)(uintptr_t)out, 0);
}

/* ---- Frame capabilities and shared memory (roadmap 2.1) -------------------
 *
 * A frame is retyped out of untyped memory like any other object
 * (sys_retype(untyped_slot, KOBJ_FRAME, 1, dest)), which leaves a CAP_FRAME in
 * `dest`. Mapping it is what turns that capability into memory.
 *
 * Sharing a page with another task is therefore three existing steps and no new
 * concept: narrow a copy of the capability to the rights that task should have
 * (sys_cap_mint), hand it over (sys_cap_grant), and let it map the frame at an
 * address of its own choosing. The rights it maps with can never exceed the
 * rights on the capability it was given. */

/* Copy the capability in `src_slot` to `dest_slot` of the caller's OWN cspace,
 * with rights masked down to (rights & the source's rights). Cannot widen: a
 * request for a right the source lacks yields a capability without it, not an
 * error, exactly as the capability algebra defines delegation. */
static inline int sys_cap_mint(int dest_slot, int src_slot, unsigned int rights) {
    return (int)syscall(SYS_CAP_MINT, (uint32_t)dest_slot, (uint32_t)src_slot,
                        (uint32_t)rights);
}

/* Map the frame named by the CAP_FRAME in `frame_slot` at `vaddr`, which must be
 * page-aligned, non-zero, and in the user half. `rights` is any combination of
 * CAP_RIGHT_READ / WRITE / EXEC; WRITE and EXEC together are refused (W^X).
 * Returns 0, SYS_ERR_EXIST if something is already mapped at `vaddr`, or another
 * negative SYS_ERR_*. */
static inline int sys_map_frame(int frame_slot, unsigned long vaddr,
                                unsigned int rights) {
    return (int)syscall(SYS_MAP_FRAME, (uint32_t)frame_slot,
                        (uint64_t)vaddr, (uint32_t)rights);
}

/* Map `count` frames from consecutive slots at consecutive pages. Returns 0, or
 * a negative SYS_ERR_*. There is no partial success to interpret: on an error
 * nothing this call mapped remains mapped, which is why the return is a status
 * rather than a count of pages. */
static inline int sys_map_region(int first_slot, unsigned int count,
                                 unsigned long vaddr, unsigned int rights) {
    return (int)syscall6(SYS_MAP_REGION, (uint32_t)first_slot, (uint32_t)count,
                         (uint64_t)vaddr, (uint32_t)rights, 0, 0);
}

/* How many contiguous pages the frame at `frame_slot` spans. Returns the count
 * (always >= 1) or a negative SYS_ERR_*.
 *
 * It returns a SCALAR rather than filling a caller-supplied struct, and that is
 * deliberate: no user pointer means no pointer to truncate, and issue #176 was a
 * wrapper that truncated one to 32 bits. A syscall that needs no buffer should
 * not take one. */
static inline int sys_frame_pages(int frame_slot) {
    return (int)syscall(SYS_FRAME_PAGES, (uint32_t)frame_slot, 0, 0);
}

/* Remove the mapping of this capability's frame at `vaddr`. The capability is
 * required as well as the address: it is what confines the unmap to a page the
 * caller was entitled to map, rather than to any address it happens to have. */
static inline int sys_unmap_frame(int frame_slot, unsigned long vaddr) {
    return (int)syscall(SYS_UNMAP_FRAME, (uint32_t)frame_slot,
                        (uint64_t)vaddr, 0);
}

/* ---- roadmap 2.2: a monotonic clock ----------------------------------------
 *
 * Time since boot, and only that. There is no wall clock in this system:
 * nothing reads an RTC and nothing attests one, so every clock id other than
 * HORUS_CLOCK_MONOTONIC is refused rather than approximated.
 *
 * RESOLUTION IS 10 ms ON PURPOSE. CR4.TSD denies ring 3 RDTSC to remove the
 * cycle-accurate timer that cache and covert-channel attacks lean on; a
 * nanosecond clock behind a syscall would hand it back. `nsec` is therefore
 * always a multiple of 10,000,000. That is not a claim of side-channel safety --
 * a counting loop still builds a finer timer -- only a refusal to make it easy.
 *
 * Monotonic by construction: the source is a counter the timer interrupt only
 * increments, 64-bit so it does not wrap (a u32 at 100 Hz wraps in ~497 days,
 * and a clock that goes backwards makes every timeout fire early or never).
 */
#define HORUS_CLOCK_MONOTONIC 1

struct horus_timespec {
    uint64_t sec;
    uint32_t nsec;      /* always a multiple of 10,000,000 */
    uint32_t reserved;
};

/* Monotonic time since boot. Returns 0, or SYS_ERR_INVAL for any other clock
 * id. No capability: a coarse count of time since boot is not authority over
 * an object, and every task can already approximate it by counting yields. */
static inline int sys_clock_gettime(unsigned clock_id, struct horus_timespec *out) {
    return (int)syscall(SYS_CLOCK_GETTIME, (uint32_t)clock_id,
                        SYSCALL_UPTR(out), 0);
}

/* ---- roadmap 3.6: reading the capability graph -----------------------------
 *
 * Mirrors struct cap_info in src/include/kernel.h. One slot of one task's
 * cspace; walk slot 0..CAP_ENUM_MAX_SLOT over each task to see the whole graph.
 *
 * `object` is deliberately absent: `serial` and `badge` are the graph's nodes
 * and edges, so derivation is fully visible without naming what each capability
 * points at. Same reasoning that suppresses `cr3` and another task's `eip`.
 */
struct cap_info {
    uint32_t slot;
    uint32_t occupied;    /* 0 = empty slot, 1 = a live capability */
    uint32_t type;
    uint32_t rights;
    uint32_t serial;      /* this capability's identity */
    uint32_t badge;       /* its parent's serial; 0 at a root */
    uint32_t generation;
    uint32_t reserved;
};

/* The kernel's CNODE_SIZE. A caller walking a cspace needs the bound, and
 * hard-coding 256 in each tool is how the two drift. */
#define CAP_ENUM_MAX_SLOT 256

/* Read task `tid`'s capability slot `slot`. Needs CAP_DEBUG with READ at
 * CAPSLOT_DEBUG; without it the central gate refuses before the handler runs.
 * A dead task reports every slot empty rather than erroring -- see the handler.
 */
static inline int sys_cap_enumerate(int tid, unsigned slot, struct cap_info *out) {
    return (int)syscall(SYS_CAP_ENUMERATE, (uint32_t)tid, (uint32_t)slot,
                        SYSCALL_UPTR(out));
}

/* ---- roadmap 1.1 interrupt-policy audit readout ----------------------------
 *
 * Mirrors struct irq_policy_info in src/include/kernel.h. Present only in
 * IRQ_POLICY_AUDIT builds; the ship kernel has no dispatch entry and answers
 * SYS_ERR_NOSYS.
 *
 * This exists so the counters can be read *in band*. They used to be printed
 * from the timer ISR straight at the UART, i.e. around the single-writer console
 * rather than through it -- which split the shell prompt, hung the harness, and
 * caused a boot-window snapshot to be published as a session total. Asking for
 * them and printing them like any other program removes the second writer
 * entirely. */
#define IRQ_POLICY_SITE_SLOTS  12

struct irq_policy_site_info {
    uint64_t ra;
    uint32_t hits;
    uint32_t _pad;
};

struct irq_policy_info {
    uint32_t accidental;   /* releases that ENABLED IF the caller had masked (legacy lock) */
    uint32_t suppressed;   /* the same releases, SUPPRESSED by the IF-preserving lock */
    uint32_t benign;
    uint32_t sites;
    uint32_t ticks;
    struct irq_policy_site_info site[IRQ_POLICY_SITE_SLOTS];
};

/* Needs CAP_KERNEL_LOG (READ) -- same gate and same class as sys_dmesg. */
static inline int sys_irq_policy_info(struct irq_policy_info *out) {
    return (int)syscall(SYS_IRQ_POLICY_INFO, (uint64_t)(uintptr_t)out, 0, 0);
}

/* Send to the endpoint named by the CAP_ENDPOINT in `ep_slot` (needs WRITE). */
static inline int sys_ipc_send(int ep_slot, const void *msg, size_t len) {
    return syscall(SYS_IPC_SEND, (uint32_t)ep_slot, (uint64_t)(uintptr_t)msg, (uint32_t)len);
}

/* ---- The IPC retry contract ------------------------------------------------
 *
 * The IPC syscalls return exactly ONE retryable code: IPC_AGAIN (-2), meaning
 * "the single mailbox slot is momentarily full" or "no message yet". It is the
 * only negative that says try again. Every other negative is PERMANENT —
 * SYS_ERR_PERM (-1) above all, which means "you hold no capability for this
 * endpoint" and will be just as true on the millionth attempt as on the first.
 *
 * WHY THIS EXISTS. Four separate userspace loops were written as
 *
 *     while (sys_ipc_call(...) < 0) spin_delay();
 *
 * which retries a permanent authorisation failure forever. That is not a
 * theoretical concern: it is finding G-8 signature C. A client that lost the
 * startup race against fs_server's registration got SYS_ERR_PERM from every
 * call, spun on it for the rest of the boot, and the test hung with every task
 * RUNNABLE, nothing blocked, and NOT ONE BYTE of IPC traffic ever recorded on
 * any endpoint. Three watchdog dumps 1200 ticks apart showed byte-identical
 * instruction pointers.
 *
 * It is also a security property, not merely a robustness one. Fail-closed has
 * to mean STOP, loudly, at the point authority was refused. A refusal that is
 * retried forever is indistinguishable from a hang, so the one event the
 * capability system exists to make visible becomes the one event nobody can
 * see. Revoke a capability out from under a spinning task today and it silently
 * wedges instead of reporting that it was denied.
 *
 * So: retry on ipc_transient() only, and bound even that. */
#define IPC_AGAIN (-2)
static inline int ipc_transient(int rc) { return rc == IPC_AGAIN; }

/* Receive on the endpoint named by the CAP_ENDPOINT in `ep_slot` (needs READ —
 * the receive right, which only a service holder has). */
static inline int sys_ipc_recv(int ep_slot, void *msg, size_t max_len) {
    return syscall(SYS_IPC_RECV, (uint32_t)ep_slot, (uint64_t)(uintptr_t)msg, (uint32_t)max_len);
}

/* Blocking receive (roadmap 1.3): identical authority to sys_ipc_recv — the
 * CAP_ENDPOINT in `ep_slot` must carry READ — but an empty queue SLEEPS the
 * caller instead of returning IPC_AGAIN.
 *
 * Prefer this to a poll loop in any server whose only job is to serve one
 * endpoint. A polling server is runnable forever: it burns a scheduling slot it
 * cannot use, and on a single core it takes time away from the very clients it
 * is waiting for. It never returns IPC_AGAIN, so a caller has nothing transient
 * to retry (see ipc_transient above) — a negative return is a permanent refusal
 * and must not be looped on.
 *
 * Still returns SYS_ERR_PERM if the capability is missing, wrong-typed, or lacks
 * READ, and -1 if the endpoint dies underneath the wait. */
static inline int sys_ipc_recv_block(int ep_slot, void *msg, size_t max_len) {
    return syscall(SYS_IPC_RECV_BLOCK, (uint32_t)ep_slot, (uint64_t)(uintptr_t)msg,
                   (uint32_t)max_len);
}

/* Blocking send-then-receive: sends to the endpoint named by the CAP_ENDPOINT in
 * `send_slot` (needs WRITE), blocks until the reply arrives, copies at most
 * IPC_MSG_MAX bytes into rbuf. Returns bytes received, or a negative error.
 *
 * `reply_ep` is VESTIGIAL and ignored by the kernel. The reply always lands on
 * the caller's own private reply endpoint, which the kernel picks and no other
 * task holds a capability for — so a caller can neither park on someone else's
 * reply endpoint nor be woken through one (finding C-1 / I-5). The argument is
 * retained so the 5-register ABI and existing call sites are unchanged; pass 0.
 *
 * Uses EBX=send_slot, ECX=(ignored), EDX=msg, ESI=len, EDI=rbuf (5 data args,
 * no EBP needed so -fno-omit-frame-pointer builds are safe). */
static inline int sys_ipc_call(int send_ep, int reply_ep,
                               const void *msg, uint32_t len,
                               void *rbuf) {
    uint32_t ret;
    asm volatile("int $0x80"
                 : "=a"(ret)
                 : "a"((uint32_t)SYS_IPC_CALL),
                   "b"((uint32_t)send_ep),
                   "c"((uint32_t)reply_ep),
                   "d"((uint64_t)(uintptr_t)msg),
                   "S"(len),
                   "D"((uint64_t)(uintptr_t)rbuf)
                 : "memory");
    return (int)ret;
}

static inline int sys_ipc_reply(int ep_slot, const void *msg, size_t len) {
    return syscall(SYS_IPC_REPLY, (uint32_t)ep_slot, (uint64_t)(uintptr_t)msg, (uint32_t)len);
}

/* Reply to the task that sent the request most recently received on `req_ep`,
 * delivered directly to that client's blocked sys_ipc_call by kernel-recorded
 * identity (not via a shared reply endpoint) — so one server can serve concurrent
 * clients without their replies colliding. Returns 0 on delivery (or if the
 * client has gone). A negative return means "retry" (the client raced and hasn't
 * finished blocking yet); a server loops until it succeeds. */
/* `req_slot` must hold a CAP_ENDPOINT with READ — the RECEIVE right. This is the
 * reply-forgery primitive (it writes straight into the recorded sender's blocked
 * reply buffer), so only the task that legitimately receives requests on the
 * endpoint may answer them. Clients hold WRITE-only capabilities and are
 * refused. */
static inline int sys_ipc_reply_to(int req_slot, const void *msg, size_t len) {
    return syscall(SYS_IPC_REPLY_TO, (uint32_t)req_slot, (uint64_t)(uintptr_t)msg, (uint32_t)len);
}

/* Kernel-attested identity of the task that last sent on endpoint `ep`: returns
 * its uid and (via *out_gid) gid, as fixed by that task's login. A client cannot
 * forge this — it is not read from the request — so a server uses it instead of
 * trusting any identity a client places in the message body. Returns
 * (uint32_t)-1 when there is no valid last sender. */
static inline uint32_t sys_ipc_sender(int ep, uint32_t *out_gid) {
    return syscall(SYS_IPC_SENDER, (uint32_t)ep, (uint64_t)(uintptr_t)out_gid, 0);
}

static inline int sys_notify(int notif_slot, uint32_t badge) {
    return syscall(SYS_NOTIFY, (uint32_t)notif_slot, badge, 0);
}

/* sys_wait_notify: block until a badge arrives on notif_slot (or return
 * immediately if one is already pending).  The kernel returns the accumulated
 * badge bits in EBX (written via frame->rbx in interrupt_handler64) so no
 * cross-address-space pointer copy is needed. */
static inline int sys_wait_notify(int notif_slot, uint32_t *out_badge) {
    uint32_t ret, badge;
    asm volatile("int $0x80"
                 : "=a"(ret), "=b"(badge)
                 : "a"((uint32_t)SYS_WAIT_NOTIFY), "b"((uint32_t)notif_slot)
                 : "ecx", "edx", "memory");
    if (out_badge) *out_badge = badge;
    return (int)ret;
}

static inline int sys_receive_program(struct program_header *hdr_out) {
    return syscall(SYS_RECEIVE_PROGRAM, (uint64_t)(uintptr_t)hdr_out, 0, 0);
}

static inline int sys_spawn(void) {
    return syscall(SYS_SPAWN, 0, 0, 0);
}

/* fork (roadmap 2.3): duplicate this task. Returns the child's tid in the
 * parent, 0 in the child, negative on failure. The child's memory is a
 * copy-on-write clone of the caller's -- it starts out reading the same bytes,
 * and the first write on either side gives that side a private page.
 *
 * The child inherits the caller's capabilities as DERIVED copies, in the same
 * slots and with the same rights: each has its own serial and names the caller's
 * capability as its parent, so the child's authority is a subtree of the
 * caller's and revoking a capability here sweeps the child's copy with it. Four
 * things are NOT inherited, and each would be impersonation rather than
 * delegation: slots 0-3 and slot 4, which are the child's own CAP_TCB, image
 * frame and PRIVATE reply endpoint, and any CAP_REPLY, which is one-shot. The
 * caller is handed a CAP_TCB naming the child, so it can sys_wait / sys_kill it.
 *
 * SYS_ERR_INVAL means this task cannot be cloned as it stands -- the only case
 * today is a mapped CAP_FRAME, which fork refuses rather than share or copy
 * (see clone_user_aspace in src/kernel/paging.c). SYS_ERR_NOMEM means no free
 * task slot or no physical page. */
static inline int sys_fork(void) {
    return syscall(SYS_FORK, 0, 0, 0);
}

/* Spawn a named embedded binary (hello, captest, fs_server, shell).
 * Returns the new task pid on success, negative on error. */
static inline int sys_spawn_named(const char *name) {
    uint32_t len = 0;
    while (len < 31 && name[len]) len++;
    return (int)syscall(SYS_SPAWN, (uint64_t)(uintptr_t)name, len, 0);
}

/* Spawn a named binary, handing the child a one-word argument it can retrieve
 * with sys_spawn_arg(). A minimal parameter-passing channel (full argv is future
 * work); today it carries e.g. a task id for a supervisor/waiter child. */
static inline int sys_spawn_named_arg(const char *name, uint32_t arg) {
    uint32_t len = 0;
    while (len < 31 && name[len]) len++;
    return (int)syscall(SYS_SPAWN, (uint64_t)(uintptr_t)name, len, arg);
}

/* Retrieve the one-word argument this task was spawned with (0 if none). */
static inline uint32_t sys_spawn_arg(void) {
    return syscall(SYS_SPAWN_ARG, 0, 0, 0);
}

/* Spawn a named binary, passing it a full argument vector. The kernel copies the
 * `argc` strings from argv[] onto the child's initial stack; the child reads them
 * back with sys_get_argv(). Up to 16 args / 512 bytes total (excess is refused).
 * Returns the child's task id, or negative on error. */
static inline int sys_spawn_named_argv(const char *name, int argc, char *const argv[]) {
    uint32_t len = 0;
    while (len < 31 && name[len]) len++;
    return (int)syscall6(SYS_SPAWN, (uint64_t)(uintptr_t)name, len, 0,
                         (uint64_t)(uintptr_t)argv, (uint32_t)argc, 0);
}

/* Retrieve this task's argument vector. Writes the argv[] base pointer to
 * *out_argv (NULL-terminated array) and returns argc (0 and NULL if none). */
static inline int sys_get_argv(char ***out_argv) {
    char **argv = 0;
    int argc = (int)syscall(SYS_GET_ARGV, (uint64_t)(uintptr_t)&argv, 0, 0);
    if (out_argv) *out_argv = argv;
    return argc;
}

/* Replace the calling task's image with a named embedded binary (hello, captest,
 * fs_server, shell), keeping the same task id and cspace (capabilities survive
 * the exec, POSIX-style). On success this does not return — control resumes at
 * the new image's entry point. Returns a negative error only on failure (e.g.
 * unknown name), in which case the caller's image is left intact. */
static inline int sys_exec_named(const char *name) {
    uint32_t len = 0;
    while (len < 31 && name[len]) len++;
    return (int)syscall(SYS_EXEC_NAMED, (uint64_t)(uintptr_t)name, len, 0);
}

/* Replace the caller's image with a named binary, passing it a full argument
 * vector (marshalled onto the fresh stack; read back with sys_get_argv). On
 * success does not return; a negative return means the exec failed and the
 * caller's image is intact. */
static inline int sys_exec_named_argv(const char *name, int argc, char *const argv[]) {
    uint32_t len = 0;
    while (len < 31 && name[len]) len++;
    return (int)syscall6(SYS_EXEC_NAMED, (uint64_t)(uintptr_t)name, len, 0,
                         (uint64_t)(uintptr_t)argv, (uint32_t)argc, 0);
}

/* Spawn a child from a program image the caller supplies in its own memory
 * (execve-from-fd): read a file into `image` (len bytes) via the fs_server, then
 * call this. The image is a Horus `.bin` (44-byte header + payload) or a bare
 * ELF; the kernel validates it with the same loader a named binary uses. The
 * child is handed a full argv (marshalled onto its stack; read via
 * sys_get_argv). Returns the child pid, or a negative SYS_ERR_* (the caller is
 * unaffected on failure). Needs slot-3 WRITE|EXEC, like sys_spawn_named. */
static inline int sys_spawn_image(const void *image, uint32_t len, int argc, char *const argv[]) {
    return (int)syscall6(SYS_SPAWN_IMAGE, (uint64_t)(uintptr_t)image, len, 0,
                         (uint64_t)(uintptr_t)argv, (uint32_t)argc, 0);
}

/* As sys_spawn_image but also hands the child a one-word argument (sys_spawn_arg). */
static inline int sys_spawn_image_arg(const void *image, uint32_t len, uint32_t arg,
                                      int argc, char *const argv[]) {
    return (int)syscall6(SYS_SPAWN_IMAGE, (uint64_t)(uintptr_t)image, len, arg,
                         (uint64_t)(uintptr_t)argv, (uint32_t)argc, 0);
}

/* As sys_spawn_image but also wires the child's stdio to pipe ends the caller
 * holds: in_slot = the caller's cspace slot with the pipe READ end that becomes
 * the child's stdin (0 = leave stdin on the console), out_slot = the WRITE end for
 * the child's stdout (0 = console). The kernel copies those ends into the child
 * before it runs (see wire_child_stdio). Used by the shell to build pipelines. */
static inline int sys_spawn_image_stdio(const void *image, uint32_t len,
                                        int argc, char *const argv[],
                                        uint32_t in_slot, uint32_t out_slot) {
    uint32_t spec = (in_slot & 0xFFFFu) | ((out_slot & 0xFFFFu) << 16);
    return (int)syscall6(SYS_SPAWN_IMAGE, (uint64_t)(uintptr_t)image, len, 0,
                         (uint64_t)(uintptr_t)argv, (uint32_t)argc, spec);
}

/* Pipes. sys_pipe returns (read_slot<<16)|write_slot (both cspace slots holding a
 * CAP_PIPE end), or a negative SYS_ERR_*. read/write/close take a slot. read: 0 =
 * EOF, SYS_ERR_AGAIN = would-block (empty, writers open). write: SYS_ERR_AGAIN =
 * would-block (full, reader open), SYS_ERR_PIPE = no reader. Back-pressure is a
 * userspace yield-retry (posix.c), so these never block in the kernel. */
static inline int sys_pipe(void) {
    return (int)syscall(SYS_PIPE, 0, 0, 0);
}
static inline int sys_pipe_read(uint32_t slot, void *buf, uint32_t len) {
    return (int)syscall(SYS_PIPE_READ, slot, (uint64_t)(uintptr_t)buf, len);
}
static inline int sys_pipe_write(uint32_t slot, const void *buf, uint32_t len) {
    return (int)syscall(SYS_PIPE_WRITE, slot, (uint64_t)(uintptr_t)buf, len);
}
static inline int sys_pipe_close(uint32_t slot) {
    return (int)syscall(SYS_PIPE_CLOSE, slot, 0, 0);
}
/* Bitmask: bit0 = stdin is a pipe (STDIN_PIPE_SLOT), bit1 = stdout is a pipe. */
static inline int sys_stdio_info(void) {
    return (int)syscall(SYS_STDIO_INFO, 0, 0, 0);
}

/* Replace the caller's own image with a caller-supplied program image
 * (execve-from-fd, in place), keeping the same task id and cspace (capabilities
 * survive, POSIX-style). On success this does not return — control resumes at the
 * new image's entry. A negative return means the image was rejected and the
 * caller's image is intact. Needs slot-3 WRITE|EXEC. */
static inline int sys_exec_image(const void *image, uint32_t len, int argc, char *const argv[]) {
    return (int)syscall6(SYS_EXEC_IMAGE, (uint64_t)(uintptr_t)image, len, 0,
                         (uint64_t)(uintptr_t)argv, (uint32_t)argc, 0);
}

/* Register this task's alternate signal stack: signals delivered while the task
 * is not already running on it enter the handler on [ss_sp, ss_sp+ss_size)
 * instead of the interrupted stack. Pass ss_size == SS_DISABLE to turn it off.
 * ss_size must be >= SIGSTKSZ_MIN and the range must lie inside the user address
 * space. Returns 0 on success, negative on error (bad range, or called while a
 * handler is running on the altstack). */
static inline int sys_sigaltstack(void *ss_sp, uint32_t ss_size) {
    return syscall(SYS_SIGALTSTACK, (uint64_t)(uintptr_t)ss_sp, ss_size, 0);
}

/* Delegate a capability to a child task: copy the caller's capability at
 * `src_slot` into `target_tid`'s cspace at `dest_slot`, with a fresh serial so
 * the grantee's cap_lookup accepts it. Authorised only if the caller holds a
 * CAP_TCB to `target_tid` (the per-child cap a spawner receives) or CAP_USER
 * admin — a task may only push capabilities down into children it supervises.
 * Returns 0 on success, negative on error (unauthorised, bad slot/target, or no
 * capability at src_slot). */
static inline int sys_cap_grant(int target_tid, uint32_t src_slot, uint32_t dest_slot) {
    return (int)syscall(SYS_CAP_GRANT, (uint32_t)target_tid, src_slot, dest_slot);
}

/* Send signal `signum` (1..31) to task `target_tid`, which the caller must hold a
 * CAP_TCB for (or be admin). If the target registered a handler (sys_signal), it
 * is redirected into it on its next return to ring 3 with `signum` in ebx;
 * otherwise the target is terminated (default action). Returns 0 on success,
 * negative on error (no capability, bad target/signum). */
static inline int sys_send_signal(int target_tid, uint32_t signum) {
    return (int)syscall(SYS_SIGNAL, (uint32_t)target_tid, signum, 0);
}

static inline uint32_t sys_getuid(void) {
    return syscall(SYS_GETUID, 0, 0, 0);
}

static inline int sys_auth(const char *user, const char *pass, uint32_t *out_uid) {
    return syscall(SYS_AUTH, (uint64_t)(uintptr_t)user, (uint64_t)(uintptr_t)pass, (uint64_t)(uintptr_t)out_uid);
}

static inline int sys_sudo(const char *pass) {
    return syscall(SYS_SUDO, (uint64_t)(uintptr_t)pass, 0, 0);
}

static inline int sys_get_pass(char *buf, size_t max) {
    return syscall(SYS_GET_PASS, (uint64_t)(uintptr_t)buf, max, 0);
}

static inline int sys_useradd(uint32_t uid, uint32_t gid, const char *name) {
    return syscall(SYS_USERADD, uid, gid, (uint64_t)(uintptr_t)name);
}

static inline int sys_userdel(uint32_t uid) {
    return syscall(SYS_USERDEL, uid, 0, 0);
}

static inline int sys_passwd(uint32_t target_uid, const char *newpass) {
    return syscall(SYS_PASSWD, target_uid, (uint64_t)(uintptr_t)newpass, 0);
}

static inline int sys_rotate_keys(void) {

    return syscall(SYS_ROTATE_KEYS, 0, 0, 0);
}

static inline int sys_read_audit(struct audit_event *events, uint32_t max_events) {
    return syscall(SYS_READ_AUDIT, (uint64_t)(uintptr_t)events, max_events, 0);
}

/* The legacy in-memory capfs userspace wrappers (sys_fs_mint_file / lookup /
 * create / delete / readdir / get_root / read / write, syscalls 38-45) were
 * removed along with the capfs engine; those syscalls now fail closed and the
 * encrypted fs_server is the only filesystem. The SYS_FS_* numbers stay defined
 * but reserved so they are not reused. */

/* sys_register_storage_backend() was removed: registering a userspace block
 * backend meant the kernel called ring-3 function pointers from ring 0 (an SMEP
 * violation and TCB escape). Syscall 46 now fails closed (SYS_ERR_NOSYS). The
 * #define is kept so the ABI slot stays reserved. */

static inline int sys_block_read(uint64_t block, void *buf, uint32_t len) {
    return (int)syscall6(SYS_BLOCK_READ, (uint32_t)(block >> 32), (uint32_t)block, (uint64_t)(uintptr_t)buf, len, 0, 0);
}

static inline int sys_block_write(uint64_t block, const void *buf, uint32_t len) {
    return (int)syscall6(SYS_BLOCK_WRITE, (uint32_t)(block >> 32), (uint32_t)block, (uint64_t)(uintptr_t)buf, len, 0, 0);
}

static inline int sys_register_fs_server(uint32_t ep_slot) {
    return syscall(SYS_REGISTER_FS_SERVER, ep_slot, 0, 0);
}

static inline int sys_connect_fs_server(uint32_t dest_slot, uint32_t rights) {
    return syscall(SYS_CONNECT_FS_SERVER, dest_slot, rights, 0);
}


static inline int sys_cap_revoke(uint32_t slot) {
    return syscall(SYS_CAP_REVOKE, slot, 0, 0);
}

/* --- Encrypted object-store API (used by the userspace FS server) ---------- */

/* Allocate a fresh inode of the given type (FS_TYPE_FILE / FS_TYPE_DIR).
 * Returns the inode number, or a negative SYS_ERR_*. */
static inline int sys_fs_inode_alloc(uint32_t type) {
    return syscall(SYS_FS_INODE_ALLOC, type, 0, 0);
}

/* Drop one hard-link reference to an inode. The kernel decrements the on-disk
 * link count and frees the inode and all its data blocks only when the count
 * reaches zero (a directory is always freed outright — no hard links to dirs).
 * Returns 0 or a negative SYS_ERR_*. */
static inline int sys_fs_inode_free(uint32_t ino) {
    return syscall(SYS_FS_INODE_FREE, ino, 0, 0);
}

/* Add one hard-link reference to an inode (increment its on-disk link count).
 * Refuses a directory. Returns 0 or a negative SYS_ERR_*. */
static inline int sys_fs_inode_link(uint32_t ino) {
    return syscall(SYS_FS_INODE_LINK, ino, 0, 0);
}

/* Description of one boot module (a program image GRUB loaded into RAM and the
 * kernel recorded from the multiboot2 tags). Filled by sys_boot_module_info. */
#define BOOT_MODULE_INFO_NAME_MAX 32
struct boot_module_info {
    uint32_t size;                              /* payload byte count */
    char     name[BOOT_MODULE_INFO_NAME_MAX];   /* the module2 cmdline (utility name) */
};

/* Return the number of boot modules the kernel recorded. If `index` is valid and
 * `info` is non-NULL, also fill *info with that module's size and name. Gated on
 * the object-store capability — only the trusted filesystem server may read boot
 * modules, which are TCB-supplied images at the same trust tier as the store. */
static inline int sys_boot_module_info(uint32_t index, struct boot_module_info *info) {
    return syscall(SYS_BOOT_MODULE_INFO, index, (uint64_t)(uintptr_t)info, 0);
}

/* Copy up to `len` bytes from boot module `index`, starting at byte `offset`,
 * into `buf`. Returns the number of bytes copied (0 at/after end of module) or a
 * negative SYS_ERR_*. Same gate as sys_boot_module_info. */
static inline int sys_boot_module_read(uint32_t index, uint32_t offset, void *buf, uint32_t len) {
    return (int)syscall6(SYS_BOOT_MODULE_READ, index, offset, (uint64_t)(uintptr_t)buf, len, 0, 0);
}

/* Read logical `block` of `ino` (decrypt-and-verify in the kernel) into `buf`
 * (must hold BLOCK_SIZE=512 bytes). Returns bytes read (512) or a negative. */
static inline int sys_fblock_read(uint32_t ino, uint32_t block, void *buf) {
    return syscall(SYS_FBLOCK_READ, ino, block, (uint64_t)(uintptr_t)buf);
}

/* Write `len` (<=512) bytes to logical `block` of `ino` (kernel encrypts with a
 * fresh nonce); short writes are zero-padded to a full block. Returns len. */
static inline int sys_fblock_write(uint32_t ino, uint32_t block, const void *buf, uint32_t len) {
    return (int)syscall6(SYS_FBLOCK_WRITE, ino, block, (uint64_t)(uintptr_t)buf, len, 0, 0);
}

/* Fill *out with the inode's metadata. Returns 0 or a negative SYS_ERR_*. */
static inline int sys_fs_stat(uint32_t ino, struct fs_stat *out) {
    return syscall(SYS_FS_STAT, ino, (uint64_t)(uintptr_t)out, 0);
}

/* Set an inode's logical size (the FS server owns file size; the kernel only
 * stores fixed-size encrypted blocks). Returns 0 or a negative SYS_ERR_*. */
static inline int sys_fs_set_size(uint32_t ino, uint32_t size) {
    return syscall(SYS_FS_SET_SIZE, ino, size, 0);
}

/* Persist an inode's permission bits (low 12 of `mode`) and owner (uid/gid).
 * Object-store server only (uid 0 + CAP_BLOCK_DEV); the file-type bits are
 * preserved. Returns 0 or a negative SYS_ERR_*. */
static inline int sys_fs_set_meta(uint32_t ino, uint32_t mode, uint32_t uid, uint32_t gid) {
    return (int)syscall6(SYS_FS_SET_META, ino, mode, uid, gid, 0, 0);
}

/* SYS_MAP_PHYS access flags (the `flags` word). READ is implied; WRITE adds the
 * writable bit. Device MMIO is always mapped non-executable (W^X) by the kernel. */
#define MAP_PHYS_READ   0x1u
#define MAP_PHYS_WRITE  0x2u

/* Map one 4 KiB physical device frame `paddr` at user address `vaddr` in the
 * caller's own address space (both must be page-aligned; `len` must be <= 4096).
 *
 * `dev_slot` names a CAP_IO_DEVICE (WRITE right) in the caller's cspace, and the
 * frame must be one the device THAT capability names declares. A physical address
 * is not authority: holding some other device's capability refuses this frame.
 * Returns 0 on success or a negative SYS_ERR_*. */
static inline int sys_map_phys(uint32_t dev_slot, uint64_t paddr, uint64_t vaddr,
                               uint32_t len, uint32_t flags) {
    return (int)syscall6(SYS_MAP_PHYS, dev_slot, paddr, vaddr, len, flags, 0);
}

/* Grant the calling task native ring-3 in/out on the ports declared by the device
 * named by the CAP_IO_DEVICE (WRITE right) in `dev_slot`, via the TSS
 * I/O-permission bitmap. One device at a time: a second grant replaces the first
 * rather than adding to it. Takes effect immediately for the caller. Returns 0 or
 * a negative SYS_ERR_*. */
static inline int sys_ioport_grant(uint32_t dev_slot) {
    return syscall(SYS_IOPORT_GRANT, dev_slot, 0, 0);
}

/* Route hardware IRQ `irq` to notification slot `notif_slot`, delivering `badge`
 * each time it fires — so a ring-3 driver blocked in sys_wait_notify(notif_slot)
 * wakes to service the device. `dev_slot` names a CAP_IO_DEVICE (WRITE) and the
 * IRQ must be one that device declares, so a driver cannot subscribe to another
 * device's interrupt. Returns 0 or a negative SYS_ERR_*. */
static inline int sys_irq_register(uint32_t dev_slot, uint32_t irq,
                                   uint32_t notif_slot, uint32_t badge) {
    return (int)syscall6(SYS_IRQ_REGISTER, dev_slot, irq, notif_slot, badge, 0, 0);
}

/* Audit-log integrity digest. Writes 40 bytes to `out` (8-byte little-endian
 * total event count, then the 32-byte chain head MAC) and returns the verify
 * status: 0 = retained window intact, >0 = (first tampered index + 1),
 * -1 = chain uninitialized, -3 = copy failed. Requires a CAP_AUDIT read cap. */
static inline int sys_audit_digest(void *out) {
    return syscall(SYS_AUDIT_DIGEST, SYSCALL_UPTR(out), 0, 0);
}

/* Copy up to `max` bytes of the kernel message ring (boot + kernel log) into
 * `buf`, starting `offset` bytes from the oldest retained byte. Returns the
 * number of bytes copied (0 at/after the end), or SYS_ERR_PERM for a non-root
 * caller. Read in a loop advancing `offset` by the return value. Backs `dmesg`. */
/* Make a spawned-but-suspended child schedulable.
 *
 * sys_spawn_* return a child that is NOT yet running, so its supervisor can
 * endow it (sys_cap_grant) before it executes. Call this once the child's
 * capabilities are in place. Requires a CAP_TCB to the target, which the spawn
 * granted you.
 *
 * Forgetting it is a deterministic hang (the child never runs) rather than an
 * intermittent race — which is the point: the safe ordering is the only one the
 * API can express. */
static inline int sys_task_resume(int tid) {
    return syscall(SYS_TASK_RESUME, (uint32_t)tid, 0, 0);
}

static inline int sys_dmesg(void *buf, uint32_t offset, uint32_t max) {
    return syscall(SYS_DMESG, SYSCALL_UPTR(buf), offset, max);
}

#endif
