# Horus syscall reference

Every system call, what it does, and the capability it requires. The numbers and wrappers are in
[`include/syscall.h`](../include/syscall.h); the authoritative gate for each call is its entry in
the dispatch table in `src/kernel/syscall.c`.

## Calling convention

The syscall number goes in `rax` and the arguments in `rbx`, `rcx`, `rdx`, `rsi` and `rdi`, with a
sixth in `r8`. Arguments and the return value are 64-bit. Entry is `int 0x80`, through
`interrupt_handler64` to `syscall_handler`.

**Pointers are passed at full width.** Every wrapper hands its pointers through `SYSCALL_UPTR()`,
and `tools/check_syscall_abi.py` (required job `syscall-abi`) fails the build if one narrows a
pointer, because the low half of a valid address is usually a valid-looking address (S24). The
kernel then refuses any user address the caller has not mapped with the needed permissions (S7).

## Dispatch and authorisation

Every syscall has one entry in a descriptor table:

```c
typedef struct {
    void   (*fn)(struct interrupt_frame64 *r);
    uint16_t slot;     /* authorising cspace slot, or SC_NONE */
    uint32_t rights;   /* rights required at `slot` */
    int      ctype;    /* required capability type, or SC_ANYTYPE */
} syscall_desc_t;
```

Where a call's authority is one fixed capability, `syscall_handler` checks it **before the handler
runs**. `SC_NONE` means the authority depends on the arguments (a `CAP_TCB` for the target, a
capability the caller names by slot) and the handler resolves it through `cap_lookup`, which looks
only in the caller's own cspace and refuses a capability of the wrong type (S55, S60).

- A number with no entry, or a `NULL` handler, returns `SYS_ERR_NOSYS` (S6).
- Retired numbers stay reserved and are never reused, so no new call inherits an old caller:
  1, 5, 6, 13 to 16, 19, 27, and 38 to 45 (the removed in-memory capfs).
- No shipped entry is gated on cspace slot 3, whose `CAP_FRAME` every task is born holding; a
  gate everyone passes is no gate (S28, S79, checked by `tools/check_dispatch_gates.py`).
- A compile-time assertion ties the table's size to the highest number, so a syscall cannot be
  added without its entry.
- Two paths need no capability, by decision: writing to the console (fd 1) and reading a console
  line (fd 0), which refuses once `console_server` owns the hardware (`docs/LIMITATIONS.md` 1.6).

**IPC names objects by cspace slot.** `ipc_ep_from_slot` and `ipc_notif_from_slot` check the
capability's type, the right for the direction (`READ` to receive, `WRITE` to send) and its
lineage before trusting it. Clients hold send-only endpoint capabilities, and replies go to each
task's private reply endpoint, which no other task can name (S13a, S13b, S95).

## Return values

Errors are negative `SYS_ERR_*` codes (`include/errno.h`); success is `0`, a length or an
identifier, depending on the call.

| Code | Meaning |
|---|---|
| `SYS_OK` | Success |
| `SYS_ERR_PERM` | Authorisation failed |
| `SYS_ERR_INVAL` | Invalid argument |
| `SYS_ERR_NOENT` | No such object |
| `SYS_ERR_FAULT` | A user pointer could not be resolved |
| `SYS_ERR_NOSYS` | Unknown, reserved or unimplemented |
| `SYS_ERR_AGAIN` | Would block; retry (pipes). The IPC calls return `IPC_AGAIN` instead |
| `SYS_ERR_INTR` | Interrupted by a signal |
| `SYS_ERR_IO` | Storage failure |
| `SYS_ERR_PIPE` | No reader on the pipe |

`SYS_SBRK` returns an address, so its failure value is `(uint64_t)-1`, the value newlib's
`_sbrk` compares against. The non-blocking IPC calls return `IPC_AGAIN` for a full or empty queue,
and `ipc_call_retry` in `libhorus` retries only that, and boundedly.

## Semantics worth knowing

**Exec keeps authority.** `SYS_EXEC_NAMED` and `SYS_EXEC_IMAGE` replace the caller's image and do
not touch its cspace, so the task keeps the same capabilities with the same lineage, and cannot
launder delegated authority into a root of its own (S42). A forked child's capabilities are
derived from its parent's (S41). A task that has bound the shared libc cannot fork.

**Creating costs a budget.** `SYS_SPAWN`, `SYS_SPAWN_IMAGE` and `SYS_FORK` carve the child's cspace
from the caller's `CAP_UNTYPED` (S57); `SYS_RETYPE` carves endpoints, notifications and frames the
same way, and `SYS_UNTYPED_SPLIT` gives a delegate part of a budget rather than a share of all of
it (S58). A spawned child is suspended until `SYS_TASK_RESUME`, so its supervisor can endow it
first.

**Frames.** A `CAP_FRAME` names a frame object, never a physical address (S26). `SYS_MAP_FRAME`
builds the mapping from the capability's rights (S27), `SYS_MAP_REGION` maps several frames all or
nothing (S35), and `SYS_FRAME_PAGES` reports a frame's size to a holder of its capability (S37).

**Endpoint tokens.** An endpoint capability can carry a token the kernel never interprets.
`SYS_CAP_MINT_TOKEN` sets one; `SYS_IPC_INVOKER` tells a server the token and rights of the
capability a message came through; `SYS_IPC_REPLY_CAP` hands the caller a new capability that can
only narrow the one it invoked; `SYS_IPC_CALL_CAP` makes the call that receives it (S105). These
are the kernel half of the capability filesystem (`docs/design/filesystem.md`).

**Devices.** The device calls take a `CAP_IO_DEVICE` slot and check each frame, port range and
interrupt line against what that device declares (S43). `SYS_DEVICE_ENABLE` sets only the three
PCI decode bits (S44); `SYS_DMA_ADDR` maps a frame for the device through the IOMMU (S45); a
registered legacy line stays masked until `SYS_IRQ_ACK` (S46); `SYS_MSI_REGISTER` takes no vector
(S47). There is no call to list devices.

**Installing.** `SYS_STORAGE_INFO` and `SYS_STORAGE_DEVICE` survey the disks, and
`SYS_STORAGE_FORMAT` erases the disk it names (S83). All three need `CAP_STORAGE_FORMAT`, which
only the installer holds (S72). A volume that has been unlocked cannot be reformatted (S90), and
on a live boot the kernel refuses to open or format a persistent disk at all (S110).

## Every syscall

A call that exists only in a test or diagnostic build says so in brackets; everything else is in the
shipped kernel.

| # | Name | Arguments | What it does | Authority |
|---|---|---|---|---|
| 0 | `SYS_YIELD` |  | Give up the CPU | none (self) |
| 2 | `SYS_EXIT` |  | End the calling task | none (self) |
| 3 | `SYS_GET_LINE` | `buf` | Read a line from the console | `CAP_CONSOLE` at `CAPSLOT_CONSOLE` + READ, type-tested in the handler; no fallback |
| 4 | `SYS_CAP_MINT` | `(dest_slot, src_slot, rights)` | Copy within the CALLER's own cspace with rights masked to (rights & the source's) | holding the source; `cap_mint` masks to `rights & src->rights` |
| 5 | `SYS_CLEAR` |  | Retired: cleared the kernel's VGA text buffer (only with `LEGACY_SYSCALLS_PRESENT`) | absent from the shipped kernel |
| 6 | `SYS_SYSINFO` |  | Retired: returned a version string (only with `LEGACY_SYSCALLS_PRESENT`) | absent from the shipped kernel |
| 7 | `SYS_DEBUG_EXEC` | `cmd` | Run a command in the in-kernel debug shell (only with `DEBUG_SHELL` or `LEGACY_SYSCALLS_PRESENT`) | none; `DEBUG_SHELL` builds only |
| 8 | `SYS_CAP_TRANSFER` | `(dest_slot, src_slot)` | Copy a capability within the caller's own cspace, keeping its rights | holding the source capability |
| 9 | `SYS_CAP_MOVE` | `(dest_slot, src_slot)` | Move a capability to another slot of the caller's own cspace | holding the source capability |
| 10 | `SYS_SBRK` | `increment` | Grow or shrink the caller's heap by an increment | none (own heap, bounds-checked) |
| 11 | `SYS_WRITE` | `fd`, `buf`, `len` | Write to the console (fd 1) | console: none (fd 1 = ambient). `klog`: `CAP_KERNEL_LOG` + WRITE |
| 12 | `SYS_READ` | `fd`, `buf`, `len` | Read a console line (fd 0) | none for fd 0, which refuses once `console_server` owns the console |
| 13 | `SYS_OPEN` | `name`, `flags` | Retired: opened an in-kernel ramfs file (only with `RAMFS_SLOT3_GATE`) | absent from the shipped kernel |
| 14 | `SYS_EXEC_LEGACY` |  | Retired: created a task from a program image (only with `LEGACY_SYSCALLS_PRESENT`) | absent from the shipped kernel |
| 15 | `SYS_RAMFS_CREATE` |  | Retired: created an in-kernel ramfs file (only with `RAMFS_SLOT3_GATE`) | absent from the shipped kernel |
| 16 | `SYS_RAMFS_LIST` |  | Retired: listed the in-kernel ramfs (only with `RAMFS_SLOT3_GATE`) | absent from the shipped kernel |
| 17 | `SYS_WAIT` | `tid` | Wait for a task to die | `CAP_TCB` naming `tid`: READ (S99). No `CAP_USER` fallback |
| 18 | `SYS_GET_TASK_INFO` | `tid`, `struct task_info *` | Read a task's state | self; or `CAP_DEBUG` at `CAPSLOT_DEBUG`: READ (S32) |
| 19 | `SYS_EXEC` | `load_base`, `entry` | Retired: jumped to a caller-chosen address in ring 3 (only with `LEGACY_SYSCALLS_PRESENT`) | absent from the shipped kernel |
| 20 | `SYS_GETPID` |  | The caller's task id | none (self-authorising) |
| 21 | `SYS_IPC_SEND` | `ep_slot`, `msg`, `len` | Send a message, without blocking | `CAP_ENDPOINT` at `ep_slot`: WRITE |
| 22 | `SYS_IPC_RECV` | `ep_slot`, `buf`, `max` | Receive a message, without blocking | `CAP_ENDPOINT` at `ep_slot`: READ |
| 23 | `SYS_IPC_CALL` | `send_slot`, *(ignored)*, `msg`, `len`, `reply_buf` | Send a message and wait for the reply | `CAP_ENDPOINT` at `send_slot`: WRITE |
| 24 | `SYS_IPC_REPLY` | `ep_slot`, `msg`, `len` | Reply on an endpoint | `CAP_ENDPOINT` at `ep_slot`: WRITE |
| 25 | `SYS_NOTIFY` | `notif_slot`, `badge` | OR a badge into a notification and wake its waiter | `CAP_NOTIFICATION` at `notif_slot`: WRITE |
| 26 | `SYS_WAIT_NOTIFY` | `notif_slot` | Wait for a notification | `CAP_NOTIFICATION` at `notif_slot`: READ |
| 27 | `SYS_RECEIVE_PROGRAM` | `struct program_header *` | Retired: armed a program image read from a serial port (only with `LEGACY_SYSCALLS_PRESENT`) | absent from the shipped kernel |
| 28 | `SYS_SPAWN` |  | Spawn a named program as a suspended child | `CAP_UNTYPED` at `CAPSLOT_UNTYPED`: WRITE (S57) |
| 29 | `SYS_GETUID` |  | The caller's uid | none (self) |
| 30 | `SYS_AUTH` | `user`, `pass` | Log in | none (self-authorising) |
| 31 | `SYS_SUDO` | `pass` | Re-authenticate and spawn the armed image as uid 0 | re-authentication in handler and the armed image must be one this task armed (S21) |
| 32 | `SYS_GET_PASS` | `buf` | Read a password from the console (kernel path, before the console server) | none |
| 33 | `SYS_USERADD` | `user`, `pass` | Create an account | `CAP_USER` at `CAPSLOT_USER` |
| 34 | `SYS_USERDEL` | `user` | Delete an account | `CAP_USER` at `CAPSLOT_USER` |
| 35 | `SYS_PASSWD` | `user`, `pass` | Set an account's password | `CAP_USER`, or the target is the caller's own uid |
| 36 | `SYS_ROTATE_KEYS` |  | Rotate the audit chain's keys | slot 8: `CAP_CONSOLE` READ |
| 37 | `SYS_READ_AUDIT` | `buf`, `max` | Read audit records | slot 7: `CAP_AUDIT` READ |
| 46 | `SYS_REGISTER_STORAGE_BACKEND` |  | A stub: always returns `SYS_ERR_NOSYS` | none |
| 47 | `SYS_BLOCK_READ` |  | Read a raw block beneath the filesystem | slot `CAPSLOT_AUDIT` `CAP_ENCRYPTED_STORAGE`, READ \| WRITE |
| 48 | `SYS_BLOCK_WRITE` |  | Write a raw block beneath the filesystem | slot `CAPSLOT_AUDIT` `CAP_ENCRYPTED_STORAGE`, READ \| WRITE |
| 49 | `SYS_REGISTER_FS_SERVER` | `ep_slot` | Register as the filesystem server | slot 6: `CAP_USER` (ALL) |
| 50 | `SYS_CONNECT_FS_SERVER` | `dest_slot`, `rights` | Get a send-only capability to the filesystem server | none, any task may connect |
| 51 | `SYS_CAP_REVOKE` | `slot` | Revoke a capability and everything derived from it | `CAP_RIGHT_REVOKE` on target |
| 52 | `SYS_AUDIT_DIGEST` | `buf` | Read the audit chain's digest | slot 7: `CAP_AUDIT` READ |
| 53 | `SYS_PREEMPT_TRACE` |  | Read preemption trace records (test build only) (only with `PREEMPT_SELFTEST`) | none |
| 54 | `SYS_SIGACTION` | `handler` | Register a signal handler | self only |
| 55 | `SYS_SIGRETURN` |  | Return from a signal handler | inside a handler only |
| 56 | `SYS_FS_INODE_ALLOC` | `(type)` | Allocate an inode | slot `CAPSLOT_AUDIT` `CAP_ENCRYPTED_STORAGE`, READ \| WRITE |
| 57 | `SYS_FS_INODE_FREE` | `(ino)` | Free an inode | slot `CAPSLOT_AUDIT` `CAP_ENCRYPTED_STORAGE`, READ \| WRITE |
| 58 | `SYS_FBLOCK_READ` | `(ino, block, buf)` | Read and verify one block of a file | slot `CAPSLOT_AUDIT` `CAP_ENCRYPTED_STORAGE`, READ \| WRITE |
| 59 | `SYS_FBLOCK_WRITE` | `(ino, block, buf, len)` | Encrypt and write one block of a file | slot `CAPSLOT_AUDIT` `CAP_ENCRYPTED_STORAGE`, READ \| WRITE |
| 60 | `SYS_FS_STAT` | `(ino, struct fs_stat*)` | Read an inode's metadata | slot `CAPSLOT_AUDIT` `CAP_ENCRYPTED_STORAGE`, READ \| WRITE |
| 61 | `SYS_FS_SET_SIZE` | `(ino, size)` | Set a file's size | slot `CAPSLOT_AUDIT` `CAP_ENCRYPTED_STORAGE`, READ \| WRITE |
| 62 | `SYS_BRK` | `(addr)` | Addr=0 queries current break | none (own heap) |
| 63 | `SYS_KILL` | `(tid)` | Needs a CAP_TCB cap to it | `CAP_TCB` for target, or `CAP_USER` |
| 64 | `SYS_EXEC_NAMED` | `(name)` | Does not return on success | none (self): replaces the caller's own image, creates no task |
| 65 | `SYS_CAP_GRANT` | `(target_tid, src_slot, dest_slot)` |  | `CAP_TCB` for target, or `CAP_USER` |
| 66 | `SYS_SIGNAL` | `(target_tid, signum)` |  | `CAP_TCB` for target, or `CAP_USER` |
| 67 | `SYS_SIGMASK` | `(how, mask)` | Block/unblock this task's own signals | self only |
| 68 | `SYS_SPAWN_ARG` | `()` |  | none (self) |
| 69 | `SYS_GET_ARGV` | `(char *out)` | Writes the argv[] base to *out | none (self) |
| 70 | `SYS_SPAWN_IMAGE` | `(image, len, arg, argv, argc)` | Spawn a child from a caller-supplied program image (execve-from-fd) | `CAP_UNTYPED` at `CAPSLOT_UNTYPED`: WRITE (S57) |
| 71 | `SYS_EXEC_IMAGE` | `(image, len, 0, argv, argc)` | No return on success | none (self), as `SYS_EXEC_NAMED` |
| 72 | `SYS_SIGALTSTACK` | `(ss_sp, ss_size)` | Register this task's alternate signal stack (ss_size 0 disables) | self only |
| 73 | `SYS_IPC_SENDER` | `(ep, uint32_t *out_gid)` | Kernel-attested identity of an endpoint's last sender | `CAP_ENDPOINT` at `ep_slot`: READ |
| 74 | `SYS_FS_SET_META` | `(ino, mode, uid, gid)` | Persist an inode's owner/mode (fs server only) | slot `CAPSLOT_AUDIT` `CAP_ENCRYPTED_STORAGE`, READ \| WRITE |
| 75 | `SYS_IPC_REPLY_TO` | `(req_ep, msg, len)` | Reply to the last sender on req_ep (multi-client safe routing) | `CAP_ENDPOINT` at `req_slot`: READ, *plus* the one-shot `CAP_REPLY` at `CAPSLOT_REPLY` (21), which it consumes |
| 76 | `SYS_FS_INODE_LINK` | `(ino)` | Increment an inode's hard-link count (fs server only) | slot `CAPSLOT_AUDIT` `CAP_ENCRYPTED_STORAGE`, READ \| WRITE |
| 77 | `SYS_BOOT_MODULE_INFO` | `(index, struct boot_module_info*)` | Fills *info for a valid index (store owner only) | slot `CAPSLOT_BOOT_MODULE` `CAP_BOOT_MODULE`, READ |
| 78 | `SYS_BOOT_MODULE_READ` | `(index, offset, buf, len)` |  | slot `CAPSLOT_BOOT_MODULE` `CAP_BOOT_MODULE`, READ |
| 79 | `SYS_MAP_PHYS` | `(dev_slot, paddr, vaddr, len, flags)` | Map one frame the named device declares into the caller's address space (CAP_IO_DEVICE + WRITE in dev_slot) | `CAP_IO_DEVICE` at `dev_slot`; the frame must be one the device declares |
| 80 | `SYS_IOPORT_GRANT` | `(dev_slot)` | Grant native ring-3 in/out on the named device's ports via the TSS I/O bitmap (CAP_IO_DEVICE + WRITE in dev_slot) | `CAP_IO_DEVICE` at `dev_slot` |
| 81 | `SYS_IRQ_REGISTER` | `(dev_slot, irq, notif_slot, badge)` | Route an IRQ the named device declares to an async notification (CAP_IO_DEVICE + WRITE in dev_slot) | `CAP_IO_DEVICE` at `dev_slot` declaring the line, and a `CAP_NOTIFICATION` at `notif_slot` |
| 82 | `SYS_CONSOLE_OWNED` | `()` | Whether a ring-3 console server owns the console hardware | none (read-only status) |
| 83 | `SYS_PIPE` | `()` | Create a bounded pipe, install a read/write CAP_PIPE in the caller's cspace | none (own cspace), but the two ends count against `MAX_CAPS_PER_TASK` and the call is refused with `SYS_ERR_NOMEM` at the ceiling (S94) |
| 84 | `SYS_PIPE_READ` | `(slot, buf, len)` | 0 = EOF, SYS_ERR_AGAIN = empty-but-writers-open | `CAP_PIPE` READ at `slot` |
| 85 | `SYS_PIPE_WRITE` | `(slot, buf, len)` | SYS_ERR_AGAIN = full-but-reader-open, SYS_ERR_PIPE = no reader | `CAP_PIPE` WRITE at `slot` |
| 86 | `SYS_PIPE_CLOSE` | `(slot)` | Drop a pipe-end cap and unref that end | `CAP_PIPE` at `slot` |
| 87 | `SYS_STDIO_INFO` | `()` | Read by posix_init | none (own tcb) |
| 88 | `SYS_DMESG` | `(buf, offset, max)` | Copy a chunk of the kernel message ring at `offset` to buf | `CAP_KERNEL_LOG` at `CAPSLOT_KERNEL_LOG` |
| 89 | `SYS_TASK_RESUME` | `(tid)` | Make a spawned-but-suspended child schedulable | `CAP_TCB` for the target |
| 90 | `SYS_RETYPE` | `(untyped_slot, kobj_type, count, dest_slot)` | Carve kernel objects out of untyped memory | `CAP_UNTYPED` at `untyped_slot`: WRITE |
| 91 | `SYS_UNTYPED_INFO` | `(untyped_slot, struct untyped_info*)` | Size/watermark/free of the region named at untyped_slot (READ) | `CAP_UNTYPED` at `untyped_slot`: READ |
| 92 | `SYS_IRQ_POLICY_INFO` | `(struct irq_policy_info*)` | Roadmap 1.1 audit counters (only with `IRQ_POLICY_AUDIT`) | slot `CAPSLOT_KERNEL_LOG` `CAP_KERNEL_LOG`, READ |
| 93 | `SYS_TASK_EXIT_INFO` | `(struct task_exit_info*)` | Why the last task this caller waited on died | none (the caller's own record) |
| 94 | `SYS_IPC_RECV_BLOCK` | `(ep_slot, buf, max)` | Like SYS_IPC_RECV but SLEEPS on an empty queue instead of returning IPC_AGAIN | `CAP_ENDPOINT` at `ep_slot`: READ |
| 95 | `SYS_MAP_FRAME` | `(frame_slot, vaddr, rights)` | Map the KOBJ_FRAME named by a CAP_FRAME into the caller's own address space | `CAP_FRAME` at `frame_slot`, holding at least `rights`; maps the whole run the frame names |
| 96 | `SYS_UNMAP_FRAME` | `(frame_slot, vaddr)` | Remove that mapping | `CAP_FRAME` at `frame_slot`, any rights; withdraws the whole run |
| 97 | `SYS_CAP_ENUMERATE` | `(tid, slot, struct cap_info*)` | Read one capability slot of task `tid` (roadmap 3.6) | `CAP_DEBUG` at `CAPSLOT_DEBUG` (19), READ |
| 98 | `SYS_CLOCK_GETTIME` | `(clock_id, struct horus_timespec*)` | Monotonic time since boot (roadmap 2.2) | none (ambient) |
| 99 | `SYS_MAP_REGION` | `(first_slot, count, vaddr, rights)` | Map `count` CAP_FRAMEs from consecutive cspace slots at consecutive pages from vaddr | a `CAP_FRAME` at each of `first_slot .. first_slot+count-1`, each holding at least `rights` |
| 100 | `SYS_FRAME_PAGES` | `(frame_slot)` | How many contiguous pages the CAP_FRAME at `frame_slot` names | `CAP_FRAME` at `frame_slot`, any rights |
| 101 | `SYS_FORK` | `()` | Duplicate this task, its memory copy-on-write | `CAP_UNTYPED` at `CAPSLOT_UNTYPED` (`CAP_RIGHT_WRITE`), the same authority `SYS_SPAWN` requires, because both create a task and a task's cspace is carved from it (S57) |
| 102 | `SYS_DEVICE_INFO` | `(dev_slot, struct dev_info*)` | What the device named by the CAP_IO_DEVICE at dev_slot declares: ids, MMIO ranges, port ranges, IRQ lines | `CAP_IO_DEVICE` at `dev_slot` |
| 103 | `SYS_DEVICE_ENABLE` | `(dev_slot, flags)` | Set the named device's PCI decode bits (DEV_ENABLE_*) | `CAP_IO_DEVICE` at `dev_slot` |
| 104 | `SYS_DMA_ADDR` | `(dev_slot, frame_slot, uint64_t*)` | The bus address at which that device reaches that frame | `CAP_IO_DEVICE` at `dev_slot` and `CAP_FRAME` at `frame_slot` |
| 105 | `SYS_IRQ_ACK` | `(dev_slot, irq)` | Unmask the line after servicing the device | `CAP_IO_DEVICE` at `dev_slot` declaring the line |
| 106 | `SYS_POLL_NOTIFY` | `(notif_slot, uint32_t*)` | Read a notification without blocking | `CAP_NOTIFICATION` at `notif_slot`: READ |
| 107 | `SYS_MSI_REGISTER` | `(dev_slot, notif_slot, badge)` | Route the named device's MSI to a notification | `CAP_IO_DEVICE` at `dev_slot` and a `CAP_NOTIFICATION` |
| 108 | `SYS_SHLIB_INFO` | `(frame_slot, struct shlib_info*)` | Where the shared library is loaded | `CAP_FRAME` over the library's text |
| 109 | `SYS_UNTYPED_SPLIT` | `(src_slot, dest_slot, bytes)` | Carve `bytes` off the CAP_UNTYPED at `src_slot` and mint a CAP_UNTYPED naming the sub-region into `dest_slot` (roadmap 0.3) | `CAP_UNTYPED` + WRITE at `src_slot`. Carves `bytes` off that region and mints a derived `CAP_UNTYPED` over the sub-region into `dest_slot` |
| 110 | `SYS_STORAGE_INFO` | `(struct storage_info*)` | What volume this machine has (CAP_STORAGE_FORMAT + READ) | `CAP_STORAGE_FORMAT` at `CAPSLOT_STORAGE_FORMAT`: READ |
| 111 | `SYS_STORAGE_FORMAT` | `(const char *password, plen, device, volume_blocks)` | Volume_blocks 0 = the whole device; DESTROY the attached volume and lay a new sealed one down (CAP_STORAGE_FORMAT + WRITE) | `CAP_STORAGE_FORMAT` at `CAPSLOT_STORAGE_FORMAT`: WRITE |
| 112 | `SYS_USERLIST` | `(index, struct user_entry*)` |  | `CAP_USER` at `CAPSLOT_USER` |
| 113 | `SYS_STORAGE_DEVICE` | `(index, struct storage_info*)` | The survey for ONE enumerated persistent device (CAP_STORAGE_FORMAT + READ) | `CAP_STORAGE_FORMAT` at `CAPSLOT_STORAGE_FORMAT`: READ |
| 114 | `SYS_CONSOLE_RELEASE` | `(dev_slot)` | Give the console hardware back to the kernel | `CAP_IO_DEVICE` naming the console hardware |
| 115 | `SYS_FB_INFO` | `(dev_slot, struct fb_geometry*)` | The SHAPE of the linear framebuffer (width/height/pitch/bpp), or SYS_ERR_NOENT if this display is not one | `CAP_IO_DEVICE` naming the framebuffer's device |
| 116 | `SYS_BOOT_FLAGS` | `(void)` | Which entry the operator chose at the boot menu | none |
| 117 | `SYS_CAP_MINT_TOKEN` | `(dest_slot, src_slot, rights, token)` | A TOKENED endpoint capability, from an UNTOKENED one the caller holds with MINT | an untokened `CAP_ENDPOINT` at `src_slot` with `CAP_RIGHT_MINT`; `token` non-zero |
| 118 | `SYS_IPC_CALL_CAP` | `(ep_slot, recv_slot, msg, len, reply_buf, carry_slot)` | SYS_IPC_CALL, naming an EMPTY slot for a reply-minted capability and optionally presenting one more capability to the same ... | `CAP_ENDPOINT` at `send_slot`: WRITE; `carry_slot`, if not `IPC_NO_CAP`, a live `CAP_ENDPOINT` to the same endpoint |
| 119 | `SYS_IPC_INVOKER` | `(ep_slot, struct ipc_invoker *)` | The token and rights of the capability the last received message came through, and of a carried one | `CAP_ENDPOINT` at `ep_slot`: READ |
| 120 | `SYS_IPC_REPLY_CAP` | `(req_slot, msg, len, rights, token)` | SYS_IPC_REPLY_TO that also mints ONE capability into the caller's named slot, derived from the capability its request came through, rights intersected with ... | as `SYS_IPC_REPLY_TO`, and the caller must have named an empty `recv_slot` |
| 121 | `SYS_MEM_SEAL` | `(addr, len)` | Make pages of the caller's own image read-only for good (RELRO) | none: the caller's own image, and it only removes rights |

Numbers 38 to 45 (`SYS_FS_MINT_FILE` to `SYS_FS_WRITE`) are the removed in-memory capfs, reserved
and never to be reused; 1 (`SYS_PRINT`) was never dispatched.

## Adding a syscall

1. Define the number in `include/syscall.h` and add its wrapper there, passing pointers through
   `SYSCALL_UPTR()`.
2. Write `h_yourcall(struct interrupt_frame64 *r)` in the right `syscall*.c`.
3. Add the dispatch entry with its authorising slot, rights and type, or `SC_NONE` with a comment
   saying where the handler checks authority. Never gate on slot 3.
4. Raise the table size; the `_Static_assert` names it if you forget.
5. Add a refusal test to `userspace/captest.c` that asserts the **exact** error code, since a bare
   `< 0` cannot tell a refusal from an empty queue.
6. Classify the call in `.github/syscall-coverage.yml` (covered, or uncovered with a reason), and
   add it to the table above.
