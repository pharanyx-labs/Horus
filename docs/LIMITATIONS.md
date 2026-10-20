# Horus: known limitations

This is the authoritative list of what Horus does not do, does not enforce, or does badly. It is
written to stop anyone concluding that the system is more ready than it is. Where this document
and the code disagree, the code is right and this document has a defect: please open an issue.

**How to read it.** Sections 1 to 5 hold the entries that are **open** today. Each keeps the
number it was filed under, because code comments and other documents cite those numbers. When an
entry closes it moves to [Closed entries](#closed-entries) as one line: what it was, when it
closed, and the pull request that closed it. The full account of any closed entry is in that pull
request and in the git history of this file.

**Finding IDs.** **[C-n]**, **[I-n]**, **[M-n]** and **[F-n]** come from the 2026-07 audit,
[`history/AUDIT-2026-07.md`](history/AUDIT-2026-07.md). **[G-n]** are architectural gaps
([`ARCHITECTURE.md`](ARCHITECTURE.md) §14). **[H-n]** came from an external audit on
2026-08-15 that is not in the tree. **[HORUS-YYYYMMDD-nn]** are findings filed since, by date,
and "audit F*n*" refers to the 2026-09-19 audit, [`AUDIT.md`](AUDIT.md). A finding has one
status, and it is the one given here.

---

## 1. Security

### 1.12 Rollback protection is anchored only on a machine with a TPM

The Merkle tree catches partial rollback, and since 2026-09-01 a TPM NV monotonic counter bound
into the tree's root catches the whole volume being replaced with an older copy (`SECURITY.md`
S70, `make smoke-rollback`). What remains:

- **Only volumes formatted on a machine with a TPM are anchored.** An unanchored volume has the
  tree and nothing more. No policy flag refuses to mount an unanchored volume.
- **The granularity is one boot.** The counter advances once per unlock, so a rollback to a state
  from a previous boot is refused and a rollback within the current boot is not. Closing that
  would cost a TPM NV write per transaction.
- **Anyone who can talk to the TPM can deny service**, by advancing the counter or undefining the
  index. Neither lets them roll the volume back.
- **An anchored volume is bound to its machine.** Moved to another machine it is refused, and
  there is no export path.

### 1.23 A program's execute right is advisory against a task that can read it

What runs from `/bin`, `/sbin`, `/lib` and `/usr` is held by what those trees contain: `fs_server`
rebuilds them from the verified boot modules at every boot and refuses every change to them, root
included (S116). The loader does not check a manifest itself, because it is handed a program's
bytes, not its path: `SYS_SPAWN_IMAGE` runs whatever image its caller supplies, so a task that can
read a file can run it whether or not its mode or its capability carries `EXEC`. That is the rule
filesystem decision 8 accepts for a user's own programs under `/home`, and with TCC on the install
media it now applies on an installed machine. Exec by file capability (filesystem phase 1b) is what
closes it.

### 1.24 Below a session's root, the policy is enforced by `fs_server`, not the kernel

A session is one root capability whose token names its grant set (filesystem decision 13,
`SECURITY.md` S128). The root must carry the union of the session's rights, or a writable home
below a read-only root could not be reached at all, so the kernel bounds the session only by that
union. Within it, `fs_server` keeps the root and every directory on the way to a grant to what the
policy gives there; a bug in that code, the reference monitor for every file's contents already,
would let a session use the union where the policy gives less. Below a granted path with nothing
deeper the kernel's intersection takes over again, as before (S120).

A grant names a path, not an object: whoever may create or remove a name decides what object a
grant of that name reaches. A policy that grants one account a path inside a directory another
account may write (`@all /srv all` beside `alice /srv/alice all`) lets the second account choose
what `alice` is given. The default policy and the one the installer will write grant nothing of
the kind; v12's back-references (phase 3) are what would let the server tell the objects apart.

Sessions' private `/tmp`s (S129) live in `/.session-tmp`, which every session finds absent. A
capability with no grant set reaches it as it reaches any directory; only `init` holds one, and it
lends none to a login.

### 1.26 Mode bits leave out the administrator, and a capability with no grant set can move a file under a grant

A stat through a session's capability (S130) reports as other bits every grant of every other
principal at or above the object, except the administrator's (filesystem decision 16): mode bits
have never bounded the administrator, and counting `@admin / all` would show every ordinary
account's files as `rwx` to everyone. So `0700` means that no account but the administrator may
reach the file. An account the policy grants `/` by name is counted like any other.

The bound holds because a rename through a session's capability may not move an object onto or
off a name the policy names. A capability with no grant set (held by system tasks, never by a
session) renames without that rule, so a file moved that way under another principal's grant can
show a bound that is low through a capability minted before the move, until it is opened again.

### 1.33 A revocation cannot reach through a task that has died **[HORUS-20261013-01]**

A derived capability names its parent by serial, and a revocation finds a capability's descendants
by following those names down from the one revoked (S3). When a task dies, its cspace is emptied
(`cap_release_cspace`), and with it every capability other tasks' copies name as their parent. A
copy whose parent was in the dead task is then out of reach of any revocation above it: nothing
revokes it but its own holder, or that holder's death.

Found while closing 2.9b, where it is concrete: if the shell dies while a program it lent the
keyboard to is still running, `init` takes back the shell's copy, and the program's copy, derived
through the dead shell, is not taken back with it. The program can read what is typed at the next
shell's prompt until it ends. The same holds for a filesystem capability a dead spawner lent
(decision 10) and for any delegation chain with a dead link.

Closing it means a task's death passing its capabilities' children to their grandparents, so a
revocation above still reaches them; that is a change to the derivation tree's rules (S3, S4) and
is not made here.

## 2. Correctness

### 2.3 Only retyped kernel objects have a lifecycle

A retyped endpoint, notification or frame (one carved from untyped memory) is destroyed when no
capability names it, found by a mark-and-sweep over the capability graph in
`src/kernel/untyped.c`. The sweep errs towards leaking: a capability whose lineage generation was
bumped still marks its object, because the opposite error is a use-after-free reachable from
ring 3. A frame is also kept while any page table maps it, since a mapping is a second path to the
same bytes.

The **static objects** below `DYN_EP_BASE` and `DYN_NOTIF_BASE` (the well-known service endpoints
and the per-task reply endpoints) are named by the boot protocol rather than by one capability, so
nothing can decide they are dead. They live for the whole boot. Destruction never returns bytes
either: see 2.5.

### 2.5 A destroyed frame's memory is not reused

Kernel objects are bump-allocated from untyped regions, so destroying one frees its **name** and
not its memory. The bytes would come back only if the untyped capability were revoked and the
region's watermark reset, and that reset is not written. A frame's page is therefore consumed for
the life of the boot. This is the seL4 trade taken on purpose: a free list would let a page be
retyped as a different kind of object while a stale capability still names it. The cost is that a
long-running workload that creates and destroys many frames exhausts its region;
`SYS_UNTYPED_INFO` shows it coming.

Two ceilings sit alongside it; how many frames the kernel can name at once is not one, because
`MAX_DYN_FRAMES` is the arena's page count and every frame takes at least a page. A frame spans at most `MAX_FRAME_PAGES` (64) pages, 256 KiB, because the user half of
the untyped arena is only 3.5 MiB and a frame that could span it would starve every other object
class. `SYS_MAP_REGION` maps at most 64 frames in one call.

### 2.6b A volume has eight key slots, and only an administrator-set password gets one

Either installed account's password opens the disk (`SECURITY.md` S76). A key slot is granted when
an administrator sets a password; `useradd` alone leaves an account locked and slotless, and a
user changing their own password re-seals the slot they already hold. A volume has
`HORUS_KEYSLOTS` (8) slots, so a machine with more than eight password-holding accounts cannot
give each one. At the ninth, `do_passwd` fails closed and changes nothing, and the shell and the
installer both say the volume has no free key slot.

### 2.6d Only the boot is timestamped, from two clocks

Boot-console lines carry a `[    S.uuuuuu] ` stamp until `init` hands the console to the shell.
After that the console is a terminal and must not be stamped. The kernel stamps from the
calibrated TSC; `console_server` has only the 10 ms monotonic clock (S34), so the two halves
agree only to within a tick and `tools/check_console_timestamps.py` tolerates a small backwards
step. Kernel fault reports bypass the console writer and are unstamped, so a boot with a fault in
it fails that check, which is the intended direction.

### 2.7 A mount point is a name, not a boundary

`userspace/hvfs.c` is a per-task mount table: a path prefix maps to a slot holding a filesystem
server's endpoint capability. A task holding no capability for a mount cannot reach that subtree
(`SECURITY.md` S29). A task that *does* hold a server's capability reaches **all** of that server,
wherever it is mounted: mounting `dev_server` at `/dev` does not confine it to `/dev`.
Confinement is each server's job. The table is per-task, so a child inherits no mounts, and it
holds at most `HVFS_MAX_MOUNTS` (4).

### 2.9 Measured boot is off unless the build asks for it

On a machine with no TPM (and under QEMU without swtpm) boot proceeds: nothing is measured and the
volume key is not sealed, so `SECURITY.md` S11 and S12 do not apply. The boot log says so. A build
with `MEASURED_BOOT_REQUIRED=1` halts when measured boot is unavailable and refuses a persistent
volume that was never sealed (S85, `make smoke-measured-persist`). The default build does not set
it. CI requires swtpm for every TPM gate (`SWTPM_REQUIRED=1`), so those gates cannot pass by
measuring nothing.

### 2.9a Pinning the kernel into the boot image has two costs

The seal binds `PCR[4]`, the firmware's measurement of a boot image that pins the kernel's
SHA-256 (`SECURITY.md` S92). So:

- **A kernel update means resealing.** A new kernel changes the pin, the image and `PCR[4]`, and a
  volume sealed under the old image will not open. A signature scheme would avoid that and was not
  used, because it would make `PCR[4]` the same for every signed kernel.
- **A volume sealed under one firmware does not open under the other.** OVMF and SeaBIOS measure
  different bytes, so a machine that changes firmware mode after an install must reseal.

GRUB's own `tpm` module would let the bootloader measure the kernel instead; it exists only for
`x86_64-efi`, not for the `i386-pc` GRUB the BIOS path uses.

### 2.12 What a device capability does not cover

A `CAP_IO_DEVICE` names one entry in the kernel's device table and reaches only that device's
frames, ports and interrupt lines (`SECURITY.md` S43). It deliberately does not cover:

- **DMA on a machine without an IOMMU.** With VT-d, a device's address space starts empty and holds
  only what its driver mapped (S45). Where there is no DMAR table, `iommu_active()` is 0, the boot
  says so, and a bus-mastering device reaches all of memory.
- **Learning a bus address without a device capability.** `SYS_DMA_ADDR` needs both the frame
  capability and a device capability, on purpose.
- **Discovery.** `SYS_DEVICE_INFO` reports only the device the caller's capability names; there is
  no call to list devices. A driver cannot find a second device it might want: `init` delegates it
  or nothing does.

### 2.14 `netd` receives on one network device model only

`netd` drives an Intel NIC from ring 3. Against QEMU's 82574L (`e1000e`) it exchanges ARP with the
gateway eighteen times, wrapping its receive ring twice, and `make smoke-net` gates on that.
Against the 82540EM (`e1000`) CI's QEMU was recorded delivering the reply almost never, with the
address filter, ring addresses, descriptor layout, device reset, bus mastering and the IOMMU
ruled out. On 2026-10-13 a defect was found in the receive ring itself (256 descriptors behind 8
buffers, so from the ninth frame the device was given descriptors with no buffer) and fixed, but
it does not explain this one: on QEMU 11 the 82540EM delivered the reply in every boot with the
old ring and the new. Whether CI's QEMU still drops it is not yet measured, so the model is not
gated on reception. `make smoke-net-intx` keeps the 82540EM exercised for its interrupt handling.

### 2.15 What message-signalled interrupts do not cover

The kernel, not the driver, chooses an MSI vector (`SECURITY.md` S47).

- **MSI-X is protected but not enabled.** Its table lives in device memory a driver could map, so
  that page is refused to the driver (S48). Enabling MSI-X needs per-device work that could not be
  verified here, so a device offering only MSI-X falls back to its legacy interrupt line.
- **A vector is never reclaimed.** A dead driver's route stops delivering, but the vector stays
  allocated. There are sixteen, and the seventeenth request is refused rather than sharing one.
- **Interrupt remapping is off.** What stops a device forging an MSI today is S45: its DMA cannot
  reach the local APIC's message window.

### 2.16 What the shared libc does not do

Shipped programs link against the shared libc by name: the kernel hands its text only to programs
that ask (S106), and crt0's linker resolves each reference, refuses a library it was not built
for, and seals the table read-only (S107, S108). What remains:

- **A task that has bound the library cannot fork.** The library's text is mapped from frames in
  the untyped arena, and `clone_user_aspace` refuses to clone such a mapping. `SYS_FORK` returns an
  error and nothing is shared. None of the shipped programs forks, and the shell is not a libc
  program. This is decision D3 in [`design/shared-libc.md`](design/shared-libc.md).
- **No thread-local storage.** `R_X86_64_TPOFF*` relocations are refused.
- **No wall clock**, so `time()` returns -1 and `gettimeofday` refuses with `ENOSYS`. `tcc`'s
  `__DATE__` and `__TIME__` are the epoch's.
- **The library's address is randomised per boot, not per task.** Shared text must sit at one
  address in every task. The address is drawn at boot from the CSPRNG (S51), but one leak reveals
  it for every task.
- **`hello_shared`, the oldest self-test, still uses the index-based stub archive**, which cannot
  reach library data such as `optarg`. Every shipped program uses the linker instead.

### 2.20 The reply endpoint table is a fixed array

`MAX_ENDPOINTS` is `REPLY_EP_BASE + MAX_TASKS`, so the table always covers every task's reply
endpoint (`SECURITY.md` S95). It is about 336 KiB of `.bss` whether or not a task ever makes a
call. The consistent design is a reply endpoint retyped from the untyped memory that pays for the
task, the way its cspace already is. That touches endpoint resolution, the reachability sweep and
teardown, and the present cost is affordable.

### 2.21 An unencrypted volume is unprotected at rest

The installer can lay down a volume without encryption when the operator chooses it (`SECURITY.md`
S104). Encryption is the default. On an unsealed volume:

- **there is no confidentiality**: `disk_key` is stored in the clear, so anyone with the disk reads
  everything;
- **there is no tamper evidence against someone with the disk**: the tags and the Merkle tree still
  catch accidental corruption, but their keys derive from the same clear key;
- **rollback protection is nominal**, for the same reason;
- **the account passwords still hold**: the shell is behind a login, and a
  `MEASURED_BOOT_REQUIRED` build refuses an unsealed volume.

It does not make installing faster; the metadata region is laid down the same way.

### 2.22 A file cannot be moved to another directory

`rename` and `link` across directories are refused with `EXDEV` (`SECURITY.md` S121), because in
the capability-addressed filesystem a file's rights come from its path, and a move would change
who may reach it. The rule that would allow a safe move (`docs/design/filesystem.md` §5.5) needs
each object's back-references, which arrive with the v12 format in phase 3. Until then a mover
copies the file and removes the original, and a directory cannot be moved at all.

---

## 3. Scale and performance

### 3.1 Compile-time ceilings

| Resource | Limit | Where |
|---|---|---|
| Tasks | 256, provisioned at boot from the kernel's untyped reserve | `MAX_TASKS` sizes the reserve; `g_max_tasks` is what the boot provisioned |
| Capabilities per task | 128 in use, 256 slots | `MAX_CAPS_PER_TASK`, `CNODE_SIZE` |
| CPUs | 8; fewer boot and run on what is present | `MAX_CPUS` (`src/include/cpu_limits.h`) |
| Static endpoints | 320: 64 well-known plus one reply endpoint per task | `MAX_ENDPOINTS` |
| Retyped endpoints, notifications | 256 each | `MAX_DYN_ENDPOINTS`, `MAX_DYN_NOTIFICATIONS` |
| Static notifications | 64 | `MAX_NOTIFICATIONS` |
| Retyped frames | as many as the arena has pages (1,664), each at most 64 pages | `MAX_DYN_FRAMES`, `MAX_FRAME_PAGES` |
| Untyped arena, user half | 3.5 MiB | `UNTYPED_USER_BYTES` |
| Untyped arena, kernel reserve | 3 MiB: per task, a 10 KiB cspace and 2 KiB of TCB | `UNTYPED_KERNEL_BYTES` |
| Untyped regions nameable at once | 64 | `MAX_UNTYPED` |
| IPC message | 256 bytes | `IPC_MSG_MAX` |
| Boot modules | 48 | `MAX_BOOT_MODULES` |
| Volume | 16 GiB ceiling; the real size comes from the disk | `BLOCKS_PER_DISK` × 4 KiB |
| File | 512 GiB, so in practice the volume is the bound | direct, single, double and triple indirect blocks |
| Inodes | one per 32 blocks | `storage_format_sealed` |
| ATA disk | 128 GiB (LBA28) | `_Static_assert` in `storage.c` |
| Program image | 8 MiB | `LOADER_STAGING_BYTES` |
| Physical memory | 4 GiB of address, not of RAM: firmware moves the RAM behind the device hole below 4 GiB to above it, and none of that is used (the IdeaPad's pool holds 1,842 MiB of its 4 GB; the boot's pool line now says how much RAM lies above 4 GiB). Above 1 GiB a region's ragged edges (under 2 MiB each) are not used either | `PHYS_POOL_CEIL`, a 32-bit frame address |
| Memory map regions | 32; RAM in any past them is not used, and the boot says so | `RAM_REGIONS_MAX` |
| Device table | 64 entries | `IODEV_MAX` |

**The kernel image is itself a ceiling.** It must end below `USER_PHYS_BASE` (16 MiB), which the
`linker64.ld` ASSERT enforces. That 16 MiB is the window in which the kernel maps itself with
4 KiB pages, the only place a guard page can exist. GRUB stages boot modules in the same room.
`.bss` is budgeted at **6,816 KiB** (`.github/image-budget.yml`), held exactly by
`tools/check_image_budget.py`, and `argon2_scratch` is 4,096 KiB of it: the Argon2 memory cost,
which must not be cut to buy room. Raising `MAX_CPUS`, `BLOCKS_PER_DISK` or the Argon2 cost spends
that budget; raising `MAX_TASKS` spends pool memory instead.

### 3.3 SMP scheduling is simple

Each CPU has a run list, and a CPU with nothing of its own takes another's waiting task (#584);
an idle AP stops its timer until another CPU's tick wakes it (#585). CPU time is a capability
(#592, S152, S153), but `init` binds no task to a budget yet, so every task still runs on the BSP's
whole root and a task that never blocks takes its share of every CPU. A budget ends when it runs
out (#595) and a refill is noticed when it is due (#596), but the shortest period is still a
10 ms tick; in the `SMP=0` build, which is not shipped, there is no deadline timer, so a budget
ends at the next tick and a task out of budget keeps its CPU when nothing else can run. The
TSC-deadline timer and the TSC clock (#596) are used only where the TSC is invariant; elsewhere
the timers are LAPIC counts calibrated against the PIT over 10 ms, and the clock counts PIT
interrupts, so it falls behind whenever the BSP holds interrupts off for longer than a tick.
Priorities exist (#594, S154, S155), but every shipped task is at 255, so none outranks another. A
lower priority runs only when nothing above it can, so a task that polls with `SYS_YIELD` keeps
everything below it from its CPU unless a budget bounds it, and a task that becomes runnable at a
higher priority waits for its CPU's next tick, since a wake does not preempt. There is no affinity
and no real-time guarantee yet. Under TCG emulation more cores are slower than one; the benefit needs KVM or
hardware. Each supported CPU costs about 104 KiB of `.bss` whether present or not, so beyond about
16 the per-CPU blocks would have to be allocated at boot. The scheduler, capability, IPC, spawn,
page and storage locks are each global, and a storage call holds the storage layer for the whole
call (S146), so beyond eight to sixteen cores extra CPUs mostly wait. Every revoke and every task
exit holds `cap_lock` for a whole sweep of the capability graph (S151): 29 µs at the median of 40
sweeps in a session and 236 µs at the most, under KVM (2026-10-17).
The SMP race gates run at four CPUs; `smoke-smp-topology` covers bring-up at eight. The design that
replaces this is [`design/scheduler.md`](design/scheduler.md) (ROADMAP 1.8).

### 3.4 One clock, and no timers

`SYS_CLOCK_GETTIME` gives monotonic time since boot at 10 ms resolution, deliberately (S34). There
is no wall clock, no per-task timer, no timeout on IPC, and no libc `clock_gettime`. A blocked task
waits until it is woken or killed. The PIT runs at a fixed 100 Hz on the BSP, and a busy AP's
one-shot timer at the same 10 ms.

### 3.6 `fs_server` polls while the volume is sealed

Until a volume unlocks (the whole of an install, and an installed machine's login prompt until the
first login), `fs_server` cannot block for requests: it would not notice the unlock until the next
request arrived. It polls instead, yielding the CPU on every pass, so it gives way at once to any
task that has work but stays runnable itself and keeps an otherwise idle CPU busy. Until 2026-10-12
it waited by spinning, which held each time slice to its end and, on one CPU at a true 100 Hz
tick, made the installer drop keystrokes. Waking it on the unlock instead of polling would end
this.

---

## 4. What does not exist yet

- **A disk that boots itself, on real firmware.** The installer lays out a GPT disk with an EFI
  system partition (S114, S115), and `make smoke-install-boot-disk` installs under QEMU's OVMF and
  starts the machine from the disk alone; the IdeaPad 1 14IGL05 does the same from its eMMC. Two
  limits are by construction: the firmware finds GRUB at the removable-media path because Horus
  cannot write UEFI boot entries, and every partition lies inside the 16 GiB the kernel
  addresses, so a larger disk's remainder is unused. What swap does not yet do is below.
- **Parts of the installed layout.** The install media puts GNU coreutils, TCC, their man pages,
  licences and source offer in the system trees (S116), but `/lib` stays empty (programs link the
  shared libc the kernel loads, not a file), and the
  shell's file commands
  (`rm`, `touch`, `mv`, `cp`, `mkdir`, `chmod`, `stat`) take a name in the current directory, not
  a path. The servers `init` starts are compiled into the kernel image, by design
  ([`design/installed-system.md`](design/installed-system.md) section 3).
- **Networking above Ethernet.** No IP, TCP, sockets or ARP table. `netd` completes one ARP
  exchange (2.14).
- **Storage beyond ATA and SD/eMMC.** Legacy IDE and SD/eMMC are readable, writable and
  installable. AHCI identifies a SATA drive and stops: no reads or writes, so a SATA SSD cannot be
  installed onto. An NVMe controller is driven from ring 3: `nvmed` identifies it and reads and
  writes it, polling, under one device capability and the IOMMU, in the `NVME_SELFTEST` build
  only (`make smoke-nvme`). The kernel's storage reads blocks only from ring-0 drivers, so an NVMe
  disk cannot yet be installed onto or booted from (ROADMAP 2.7). The SD/eMMC and IDE drivers
  also run in ring 3, as `sdhcid` in the `SDHCID_SELFTEST` build (`make smoke-sdhcid`) and `atad`
  in the `ATAD_SELFTEST` build (`make smoke-atad`, the primary channel's master only), but
  `sdhci.c` and `ata.c` still serve the kernel. All three serve the block-driver protocol to
  clients in a test build (`make smoke-blkproto`), `nvmed` only for a namespace with 512-byte
  blocks. The kernel never waits on a ring-3 task mid-call, so they become disks the system stores
  to when the kernel stops doing disk I/O (filesystem phase 2, [`design/ring3-storage.md`](design/ring3-storage.md)).
- **USB.** A machine with no PS/2 controller emulation has no keyboard. On eMMC, write durability
  across a power cut rests on the driver's flush and the laptop's register reading; no emulated
  gate can witness it.
- **Graphics.** A text grid only. The framebuffer console draws an 8x16 font; after the console
  handover, `console_server` draws no cursor on a framebuffer (the kernel's console does). The
  8x8 font used for 80x50 VGA text mode has an ASCII half of unrecorded provenance
  (`THIRD_PARTY.md`).
- **Processes beyond fork and exec.** No process groups, job control, `SIGCHLD` or `/proc`. A child
  of `fork` carries everything its parent held into an `exec`, with no way for the parent to narrow
  it first. One thread per address space.
- **More than one filesystem.** One volume and one `fs_server`, plus `dev_server` in self-test
  builds. The capability filesystem of [`design/filesystem.md`](design/filesystem.md) has its
  kernel half (phase 1a, IPC tokens, S105), and `fs_server` answers through capabilities (S120),
  refuses moves across directories (S121) and opens sessions from the policy (S128), and the POSIX
  layer and the shell walk with capabilities when they hold a root (S126, S127), and every login
  asks for its session (S141). A new installed volume is given a policy that gives every account
  one (S148). Nothing reaches a file any other way (S14), so a login the policy gives nothing is
  ended.
- **Swap has no way to keep a secret out of it.** On an installed boot idle pages go to the
  sealed partition under pressure, an idle task's included, and come back on touch (S118, S119,
  S123). A page goes out sealed under a key that dies with the boot, but a task cannot yet ask for
  its secrets never to be written at all ([`design/swap.md`](design/swap.md) step 3, a question
  for the maintainer). Fork sharing a swapped page is built but no gate exercises it, since every
  program in `/bin` seals pages and a fork refuses a sealed task. The handshake that keeps an IPC
  delivery from writing into a page the pager is taking on another CPU (S123) has no witness that
  can fail: the swap gate boots one CPU, and the race needs two.
- **Kernel ASLR.** User programs get 30 bits of address randomisation; the kernel loads at a fixed
  address.
- **Other architectures.** x86-64 only, booted by GRUB under BIOS or UEFI.

---

## 5. Process and assurance

### 5.1 No independent review **[C-5]**

Claude writes most of the code and merges its own pull requests once the gates are green; the
maintainer sets direction and decides the questions `CLAUDE.md` reserves for them. The ruleset
requires a pull request and no approving review, so **no human reads a change before it lands.**
The automated verification is extensive; human review is absent. **[C-1]** showed what that
produces: a defect that passed every gate because the suite tested the property the author had in
mind rather than the one the documentation claimed. The honest claim is "thoroughly automatically
verified", not "independently reviewed".

### 5.2i The format trusts its checked writes instead of reading the metadata back

A format used to read its whole metadata region back and hash what it found. It now hashes the one
all-zero block every metadata block was written from, which is sound because every write in the
format is checked. The trade, which was the maintainer's decision on 2026-09-24: a device that
acknowledges a write and does not store it leaves a leaf whose hash disagrees with the disk. That
metadata block is then refused on first use, so the 128 data blocks it describes are unusable
until a reformat. Nothing wrong is ever accepted. `smoke-installer-emmc` fell from about 90 s to
51.5 s; on a real card the saving is projected, not timed.

### 5.3 No release provenance **[I-9]**

There are four releases, `v0.2.0-alpha` (2026-09-14), `v0.3.0-alpha` (2026-10-09), `v0.4.0-alpha`
and `v0.4.1-alpha` (both 2026-10-12), each an install ISO and its SHA-256 on GitHub, from an
unsigned lightweight tag. There are no signed artifacts and no SLSA provenance, so nobody can check
that an ISO they were given came from this repository's CI. From `v0.4.1-alpha` the ISO rebuilds to
the same bytes from a checkout of its tag (S17), so anyone can confirm it by rebuilding it with
`make install.iso`, given the same versions of the compiler, Rust, GRUB, `xorriso` and `mtools`,
which each release lists beside the ISO. A different compiler gives a different kernel, so the
check is as strong as the reader's ability to match those versions; no script or container does
that for them yet (ROADMAP 4.11). The one network input to the
build, the newlib tarball, is pinned by SHA-256 and checked before unpacking (`make
smoke-newlib-tamper`), so inbound verification is in place; outbound is not.

### 5.3b The `RUST_ENABLED=0` build cannot link

`src/kernel/rust_shims.c` reads as a C fallback for the Rust core. It provides a handful of symbols
and the kernel calls forty-nine, so 43 stay unresolved, among them the capability engine, the page
refcounts and the hashes. CI never builds this configuration. Whether a no-Rust build is a goal at
all is undecided; `SECURITY.md` S86's checker refuses a new shim with no subject.

### 5.4 Cryptography is unaudited and not verified constant-time **[HORUS-20260920-03]**

ChaCha20, SHA-256, BLAKE2b, Argon2id and the AEAD are from-scratch `no_std` Rust with no external
dependency. None has been independently audited and none is verified constant-time. They protect
the measured-boot chain and the sealed volume key (SHA-256), every block of the encrypted store and
the `disk_key` unwrap (the AEAD), every password at rest (Argon2id), and the CSPRNG (ChaCha20). The
tests witness how the primitives are used, not the primitives. The two places a timing leak would
matter most are the password path behind the login prompt and the AEAD over attacker-chosen block
contents. Closing this means an independent audit, or replacing them with an audited `no_std`
implementation, vendored and hash-pinned; both are the maintainer's decision, because the crate's
zero-dependency property is itself part of the supply-chain argument. Writing new primitives is not
the fix.

### 5.5 Formal verification is narrow

Kani proves properties of capability derivation, lookup (the typed resolver every gate goes
through, and IPC authority) and revocation, the ELF validator, the user-address validators,
the random pool's seed gate, the login throttle and the page-pool refcount
arithmetic: **43** harnesses, every one of them gating in the required `kani-bounded` job. That is
the whole of the formal methods here. The kernel as a whole is not verified, no refinement proof
links a specification to the code, and no TLA+ specification exists (two unsound ones were removed on
2026-09-10).

---

## 6. Completeness estimate

Against "a complete, self-hosting operating system":

| Area | Estimate |
|---|---|
| Boot and low-level x86-64 | 85% |
| Memory management | 70% |
| Capability model, design | 80% |
| Capability model, enforcement | 85% (no ambient authority left in the ship kernel; 1.33) |
| Scheduling | 55% |
| SMP | 50% |
| IPC | 55% |
| Filesystem | 65% |
| Userspace and libc | 65% |
| Drivers | 25% (IDE, SD/eMMC, one NIC, PS/2, NVMe in a self-test; no AHCI I/O or USB) |
| Networking | 10% (a driver and one ARP exchange; nothing above Ethernet) |
| Formal verification | 10% |
| Build and supply chain | 80% |
| Governance and review | 35% |

**Overall: an early research kernel with unusually thorough instrumentation.** The machinery
around it (measured boot, adversarial CI with control arms, bounded proofs) is more mature than
the operating system it checks. The largest remaining risk is not technical: no second person
reviews the capability paths (5.1).

---

## Closed entries

One line each. The number is kept so that citations resolve; the pull request has the account.

| § | Finding | What it was | Closed |
|---|---|---|---|
| 1.1 | [C-1], [C-2] | IPC was addressed by a global integer, not a capability | 2026-07-27, #108 |
| 1.2 | [I-1], [H-1] | `uid == 0` was a kernel authority beside the capabilities | 2026-07-27, #109; last gate 2026-08-15, #155 |
| 1.3 | [I-4] | `SYS_GET_TASK_INFO` disclosed another task's instruction pointer | 2026-07-27, #109 |
| 1.4 | [C-4] | User copies truncated silently and reported success | 2026-08-13, #141 |
| 1.5 | [I-3] | An unprivileged task could force a broad revocation | 2026-08-16, #160 |
| 1.6 | | Three kernel console paths needed no capability: `SYS_WRITE` to fd 1, `SYS_READ` from fd 0 and `SYS_GET_PASS`, so any task could read or draw on the console whenever no console server owned it (S135) | 2026-10-13, #559 |
| 1.6a | [H-3] | Four ramfs paths were gated on the slot-3 decoy capability | 2026-08-22, #194 |
| 1.6b | | Task-creating syscalls were gated on the slot-3 decoy | 2026-08-30, #256 |
| 1.6c | | Two ship-build syscalls were gated on the slot-3 decoy (S79) | 2026-09-03, #307 |
| 1.7 | | Two syscall wrappers truncated a buffer pointer to 32 bits | 2026-08-20, #177 |
| 1.8 | | Syscall handlers no tracked workload entered; every implemented syscall's body is entered now, the last three (`SYS_STORAGE_DEVICE`, `SYS_STORAGE_FORMAT`, `SYS_CONSOLE_RELEASE`) by refusals inside the body from `formatprobe` and `captest` (S25) | 2026-10-14, #574 |
| 1.9 | | S16 had no witness | 2026-08-28, #222 |
| 1.10 | | A gate was classified as a control arm by its name | 2026-08-30, #251 |
| 1.11 | | The property table's `enforced by` column was parsed and discarded | 2026-08-30, #251 |
| 1.13 | [HORUS-20260911-03b] | `create_task` building a cspace unlocked: withdrawn, not a defect | 2026-09-12, #390 |
| 1.14 | [HORUS-20260911-04] | A spawned child's stdio pipe end was a derivation root, so revoking the spawner's end missed it; pipe ends could not be revoked at all (S3, S134) | 2026-10-13, #558 |
| 1.15 | [HORUS-20260919-02] | A verified boot module could change after its hash was taken (S96) | 2026-09-19, #402 |
| 1.16 | [HORUS-20260920-01] | A kernel fault wrote a kernel text address into a ring-3 exit record (S97) | 2026-09-21, #412 |
| 1.17 | [HORUS-20260920-02] | A reused task slot kept its predecessor's wait record (S98) | 2026-09-21, #413 |
| 1.18 | [HORUS-20260921-01] | Any task could wait on any task (S99) | 2026-09-21, #414 |
| 1.19 | [HORUS-20260921-02] | A capability for a dead task named whatever reused its slot (S100) | 2026-09-21, #417 |
| 1.20 | [HORUS-20260921-03] | A spawn could reuse a slot whose kernel stack a CPU was still on (S20) | 2026-09-21, #421 |
| 1.21 | [HORUS-20260921-04] | A task killed while running on another CPU kept running (S56) | 2026-09-22, #423 |
| 1.22 | [HORUS-20261008-01] | Any user could free any inode, `/bin` included, through a directory entry forged in a file they own (S113) | 2026-10-08, #502 |
| 1.25 | [HORUS-20261009-01] | A wait could return while its child still read alive, and a waiter could miss its child's death (S125) | 2026-10-09, #528 |
| 1.27 | [HORUS-20261012-01] | Changing your own password re-sealed the key slot of the boot's first login (S75) | 2026-10-12, #552 |
| 1.28 | [HORUS-20261012-02] | A crafted program header offset wrapped the spawn path's premap bound (S84) | 2026-10-12, #551 |
| 1.29 | [HORUS-20261012-03] | A forked or granted pipe end was not counted, so the pipe could be freed under its holder (S41, S133) | 2026-10-12, #553, #555 |
| 1.30 | [HORUS-20261012-04] | The inode table and allocation bitmaps were not authenticated at rest, so an owner, mode, size, link count or bitmap could be changed on the disk undetected (S143) | 2026-10-14, #575 |
| 1.31 | [HORUS-20261012-05] | The uid path reached a file by inode number and checked only that inode's mode bits, so a file inside another account's private directory answered to anyone who named its number; the uid path is gone, and every filesystem request is decided by the capability it came through (S14) | 2026-10-16, #583 |
| 1.32 | [HORUS-20261012-06] | A reply, and the sender identity a server authorises on, named a task slot, so a dead client's successor could receive both (S13, S13b) | 2026-10-12, #554 |
| 1.34 | [HORUS-20261013-02] | A register BAR smaller than a page handed its driver the whole page, so a neighbour's registers in that page were reachable (S43) | 2026-10-13, #562 |
| 1.35 | [HORUS-20261014-01] | Once authenticated, the inode table and allocation bitmaps were still in the clear, so every file's size, owner, mode and link count could be read off the disk; every block of them the kernel writes is now sealed (S143) | 2026-10-14, #575 |
| 1.36 | [HORUS-20261014-02] | Indirect pointer blocks were stored in the clear with no MAC, and a freed block keeps its nonce and tag, so a pointer edited on the disk could serve a file its own earlier contents (S143) | 2026-10-14, #575 |
| 1.37 | [HORUS-20261014-03] | The Merkle root bound the rollback generation and no other superblock field, so moving the inode table made an inode read another inode's genuine slot, and clearing `rollback_anchored` on a restored image skipped the TPM counter check (S143, S70) | 2026-10-14, #575 |
| 1.38 | [HORUS-20261015-03] | The shell lent the keyboard from the slot holding its session capability, so the first program a login ran destroyed it; logout ended nothing and the next login on that console walked by the previous one's root, a standard user by root's (S147) | 2026-10-15, #579 |
| 1.39 | [HORUS-20261015-04] | The shell held `CAP_USER`, the kernel log, `CAP_DEBUG` and the object store's capability for the whole boot, so in every login; only its own uid check kept a standard account from them. `SYS_SUDO` took the caller's own password to a uid-0 spawn, which no armed image could reach. Administration is now lent to the administrator's session and taken back at logout, and `SYS_SUDO` is withdrawn (S149) | 2026-10-15, #582 |
| 1.40 | [HORUS-20261016-01] | A spawned child could run before its supervisor resumed it: the spawn path published the child's frame and retracted it a line later, and a CPU choosing in between ran it with a half-populated cspace. `smoke-installer-sd-smp` failed 3 boots in 50 on `main` because the shell's watcher ran, found nothing granted and exited, so `init` waited on the shell directly and no login got a filesystem session (S150) | 2026-10-16, #586 |
| 1.41 | [HORUS-20261017-01] | A retyped object could be collected before the capability naming it was installed: `SYS_RETYPE` carved it, released the untyped lock and waited for `cap_lock`, while a revoke on another CPU ran the collector under that lock, found the object unnamed and freed its index; the capability then named a freed index that the next retype, by any task, reused, so a task could come to map another task's frame. Found by review on 2026-10-17; the control arm reproduces it on the first round. Teardown also ran the collector without `cap_lock`, so it could read a capability mid-write (S151) | 2026-10-17, #591 |
| 2.0 | [C-3] | Spinlock interrupt state was global | 2026-08-13, #135 |
| 2.1 | [I-2] | Heap syscalls truncated 64-bit arithmetic | 2026-08-13, #145 |
| 2.2 | [I-5] | Endpoints were single-slot mailboxes | 2026-08-10, #120 |
| 2.25 | [I-10] | The write-ahead journal was not durable on real hardware | 2026-08-16, #158 |
| 2.4 | | Copy-on-write had one producer; `fork` is now the second (S39, S40) | 2026-08-28, #225 |
| 2.5a | [HORUS-20260919-01] | The physical free path was safe by its callers, not by construction (S102) | 2026-09-22, #425 |
| 2.6 | | User accounts did not survive a reboot (S62) | 2026-08-31, #267 |
| 2.6a | | Self-test markers written in pieces could be split; now refused by `tools/check_split_markers.py` (kernel markers are 2.6c) | 2026-09-01, #268, #284 |
| 2.6c | | Gates read kernel markers off the console that ring 3 also writes, so one could arrive split; the kernel keeps a whole copy of what it prints on COM4, which no capability names, every gate that waits for a kernel marker reads it there or is listed with its reason in `.github/kernel-markers.yml`, and `tools/check_kernel_markers.py` keeps it so (S144) | 2026-10-14, #576 |
| 2.30 | [HORUS-20261014-05] | The console changed hands without waiting for a kernel line already being written on another CPU, so that line and `console_server`'s first lines interleaved on COM1; the owner now changes under the console lock (S145) | 2026-10-14, #576 |
| 2.31 | [HORUS-20261015-01] | Two CPUs could be inside the storage layer at once, through its one journal and one set of metadata and Merkle caches, and two password hashes could share the Argon2 scratch buffer, so an install on two CPUs could write a volume that failed its own checks on the next boot; every storage call and every hash is now one operation at a time (S146) | 2026-10-15, #577 |
| 2.32 | [HORUS-20261015-02] | A killed task could run on, writing memory it shared with live tasks, until its CPU took the kill IPI, which `SYS_KILL` did not wait for; a hypervisor relaying the IPI made that milliseconds, and CI's killed-task check failed 2 times in 31. Teardown now returns only once no other CPU is running the task (S56) | 2026-10-15, #580 |
| 2.8 | | The CSPRNG was safe by boot ordering, not by construction (S30) | 2026-08-23, #200 |
| 2.9b | | Console input had an owner for passwords only, named by task id, so any program a person ran could read the command lines they typed; input is now a capability lent to the foreground program (S93) | 2026-10-13, #559 |
| 2.10 | | Four live syscalls had no caller | 2026-08-23, #204 |
| 2.10a | | Two more uncalled syscalls, retired with 1.6c (S79) | 2026-09-03, #307 |
| 2.11 | | A forked child did not inherit its parent's cspace (S41) | 2026-08-28, #221 |
| 2.13 | | A PCI interrupt line could not be delivered to ring 3 (S46) | 2026-08-28, #232 |
| 2.17 | | `hello_newlib` is 1.2 MB of real code: withdrawn, not a defect. Measured 2026-10-13: its code is 98 KB and 1.06 MiB is `big_rodata`, which it carries on purpose to prove an image over 1 MiB loads; `--gc-sections` saves 368 bytes, since `libc.a` members are linked only when referenced | 2026-10-13, #565 |
| 2.18 | | The `.bin` container was declared four times and parsed in eleven places (S80) | 2026-09-03, #308 |
| 2.19 | | The end of a directory and its absence were the same answer | 2026-09-06, #318 |
| 2.23 | [A3] | Revoking one capability could make an unrelated live one unusable: revocations were also recorded in a 4096-cell hashed table (S5) | 2026-10-11, #540 |
| 2.24 | | Capability serials repeated: the 32-bit counter wrapped after about 4.3 billion mints, passing through the primordial range, and a reused task slot reissued its birth serials (S5) | 2026-10-11, #540 |
| 2.26 | | `rotate_keys` changed no key: it re-sealed a few blocks of the caller's files under the same key. Withdrawn (decision D14): the shell command is gone and `SYS_ROTATE_KEYS` answers `SYS_ERR_NOSYS` to every caller; real rotation of the volume key comes with filesystem phase 2 | 2026-10-14, #572 |
| 2.27 | | The monotonic clock ran at twice wall-clock speed under QEMU's TCG, so `failure_delay` waited half as long: the timer tick, in mode 3, was delivered twice per period | 2026-10-12, #549 |
| 2.28 | | The wait for secondary CPUs was a loop count, a few milliseconds on a fast host under KVM, so a CPU the host scheduled late went uncounted and then ran anyway, and could take a TLB shootdown it was not counted for; the wait is now 2 s of the calibrated clock and bring-up then closes, so a later CPU is parked and never used (S138) | 2026-10-13, #565 |
| 2.29 | [HORUS-20261014-04] | A delete freed each pointer tree in one journal transaction, so a file across more bitmap blocks than the journal holds failed to delete and finished at the next unlock's fsck; the free is committed in batches bounded by what the journal holds | 2026-10-14, #575 |
| 3.2 | [I-6] | `this_cpu()` read LAPIC MMIO on every call | 2026-07-31, #116 |
| 3.5 | | The block allocator rescanned the bitmap from the start | 2026-09-01, #277 |
| 5.2 | [C-6] | Which checks gate a merge was reconciled by hand | 2026-09-21, #415 |
| 5.2b | [I-11] | A required check was nondeterministic by construction | 2026-08-16, #161 |
| 5.2c | [G-8] | The SMP session soak: a task was claimable while its old CPU was still on its stack | 2026-08-17, #162 |
| 5.2d | [G-9] | Claims leaked and kernel stacks collided on the spawn and reap path | 2026-08-21, #188 |
| 5.2e | [G-10] | The spawn and exec path was unserialised process-wide state | 2026-08-18, #168, #170 |
| 5.2f | [G-11] | The armed image was ambient state that `sudo` would elevate | 2026-08-18, #170 |
| 5.2g | [G-12] | Two CPUs current on one task through the user-entry path | 2026-09-03, #305 |
| 5.2h | [G-13] | The installer gate's format bound was a total, not a stall | 2026-09-03, #306 |
| 5.3a | | `horus.iso` was not byte-reproducible: newlib carried its build path, the EFI boot image a clock-made serial, the ISO's directory records the build's time, and a kernel could keep the previous build's module manifest (S17) | 2026-10-12, #557 |
| 5.3c | | Horus could not be reinstalled over an existing Horus volume (S90) | 2026-09-11, #381 |
| 5.3d | | Six checkers examined nothing and passed when their parser went silent | 2026-09-10, #368, #369, #375 |
| 5.3e | | A stale scheduler claim under the switch-commit injection, once in 200 boots: not seen again in 199 boots that finished the whole workload, 2,344 refused switches between them, pinned and unpinned | 2026-10-09, #522, #526 |
| 5.6 | [M-3] | Governance files were in the wrong place | 2026-07-27, #107 |
| 5.7 | | GitHub can inject workflows no commit contains, and one ran from 2026-09-19 to 2026-09-20; the scheduled `ruleset-audit` now fails on any workflow GitHub runs that is neither in the tree nor recorded in `.github/injected-workflows.yml`, and on a recorded-as-stopped one running again | 2026-10-13, #567 |
| 5.8 | | Two Kani proofs ran only in a manual job that could not fail and had never run | 2026-10-06, #485 |
