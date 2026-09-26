# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/pharanyx-labs/Horus/security/advisories/new)
on this repository. If that is unavailable to you, email **horus@pharanyx.co.uk**.

Include the affected component and commit, the security property that is violated (by its S-number
below, if one fits), reproduction steps or a proof of concept, and your assessment of the impact.

**What to expect.** Acknowledgement within 7 days, an initial assessment within 14, and a fix or a
documented decision within 90 days for a confirmed issue. Horus is a research project with one
maintainer; these are honest targets, not a commercial service level. Reporters are credited in the
advisory and in `CHANGES.md` unless they prefer otherwise. There is no bug bounty.

---

## Where Horus stands

Horus is a **research microkernel**. It is not production-ready, it has had no independent audit,
and it has known open defects, every one of which is listed in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md), the single authoritative status of every finding.

- **Nobody reviews a change before it merges** (**[C-5]**). Claude writes most of the code and
  merges its own pull requests once every required check passes; the maintainer sets direction and
  decides changes to the security model. The claim this project can make is "thoroughly
  automatically verified", not "independently reviewed".
- **The capability model is enforced end to end.** Every system call in the shipped kernel is
  authorised by a capability the caller holds, apart from writing to the console and reading a
  console line, which are ambient by decision (`docs/LIMITATIONS.md` 1.6).
- **Open security limitations worth knowing first**: an inherited pipe end escapes revocation
  (1.14); most gates still read kernel reports off a console ring 3 also writes (2.6c); measured
  boot is opt-in on a machine without a TPM (2.9); any program a person runs can read the command
  lines they type (2.9b); and the cryptography is unaudited (5.4).

Its appropriate uses are research, teaching, and developing the capability model itself.

---

## Threat model

### Assets

| Asset | Protected by |
|---|---|
| Kernel integrity | Ring separation, SMEP and SMAP, W^X, `CR0.WP`, guard pages and stack canaries |
| Capability unforgeability | Per-task capability tables named by slot; userspace never sees a capability |
| Isolation between tasks | Per-task page tables, checked user copies, a flush on switch, the IOMMU for devices |
| Data at rest | Per-block AEAD keys derived inside the kernel, which never releases them |
| Boot chain | The kernel's hash pinned in the firmware-measured boot image; a module manifest inside the kernel; TPM PCRs 4, 8 and 9 |
| Volume key | Sealed to those PCRs, so a tampered boot cannot unseal it |
| User identity | Established only by `SYS_AUTH`; a server reads it from the kernel (`SYS_IPC_SENDER`), never from the client |

### Adversaries considered

**A1: an unprivileged ring-3 program** running arbitrary code with an ordinary capability table,
after kernel compromise, another task's memory, another user's files or more authority. *Defended*
for memory isolation, syscall authorisation and IPC: a task reaches a service only through a
capability naming that service, and a client's capability can send but never receive. *Not
defended* against denial of service: there are no CPU or memory quotas.

**A1b: a task with a privileged identity and no capabilities**, such as uid 0 with an empty
capability table. *Defended*: identity confers no kernel authority (S18).

**A1c: a task that can stage a program image, against a task that can authenticate.** *Defended*:
an armed image belongs to the task that armed it, so `sudo` cannot be made to elevate someone
else's program (S21).

**A2: a compromised userspace server.** Confined to its own address space and the capabilities it
was given. A compromised `fs_server` controls all filesystem policy and a compromised
`console_server` sees all terminal traffic: both are trusted by construction.

**A3: an offline attacker with the disk.** *Defended* on an encrypted volume: AEAD with a key
sealed to the TPM or wrapped under the account passwords, a Merkle tree against rolled-back
blocks, and a TPM counter against a whole volume replaced by an older copy. An unencrypted volume,
which the installer offers only as a deliberate choice, has none of this (`docs/LIMITATIONS.md`
2.21).

**A4: a boot-chain tamperer** who modifies the kernel or a module, or boots media of their own.
*Defended*: modules are checked against a manifest inside the kernel; the kernel's hash is pinned
in the boot image the firmware measures, so GRUB refuses a substituted kernel and a rebuilt boot
image cannot unseal the volume (S92). Anyone who can boot their own media can still erase the
disk.

**A4b: a concurrent task exploiting kernel locking under SMP.** *Defended*: interrupt nesting
state and the caller's interrupt flag are per CPU, and a lock release restores the caller's flag
rather than imposing one; the SMP race gates run in CI at four and eight CPUs.

**A5: a local side-channel attacker** timing another task. *Partly defended*: a microarchitectural
flush on each switch between tasks, SMT siblings parked, `RDTSC` denied to ring 3, and a clock
coarse enough not to replace it (S34). Not defended against shared L2 and L3 channels.

**A6: a malicious contributor or build tamperer.** *Partly defended*: signed commits, a protected
branch with no bypass actors, actions pinned by commit, least-privilege workflow tokens, a
reproducible kernel, secret scanning with push protection. *Not defended*: no human reviews a
change before it merges, and a pull request from outside the project waits for the maintainer.

### Explicitly out of scope

- **Physical attacks**: cold boot, bus probing, and DMA on a machine without an IOMMU. With VT-d
  a device reaches only the memory its driver mapped (S45, S53); without a DMAR table the kernel
  says so at boot and devices reach all memory.
- **Firmware and any hypervisor**, which are trusted.
- **Speculative execution** beyond the flush on switch and SMT parking.
- **Denial of service by a local task**: a task can spin or exhaust the memory it was given.
- **The cryptographic primitives themselves**, which are unaudited and not verified constant-time
  (**[HORUS-20260920-03]**, `docs/LIMITATIONS.md` 5.4).

---

## Security properties

Each property is a claim, the mechanism that enforces it, and the test or proof that would fail
if it broke. An arm is a build that puts the defect back on purpose; the witness must go red
under it.

**The table is checked by CI.** `tools/check_invariants.py` (required job `invariants`) parses
it and fails the build if a property has no witness that resolves to a real `make` target or CI
job, if a named target does not exist or nothing runs it, if an arm's flag is missing from
`DEFECT_FLAGS` (so a boot under it would not say so), or if the mechanism names code that no
longer exists. The table is the registry; `.github/invariants.yml` holds exemptions only, and
has none.

| # | Claim | Mechanism | Witness |
|---|---|---|---|
| S1 | A task cannot exercise authority it holds no capability for | The dispatch table states the capability each syscall needs and checks it centrally; where the caller names the capability, one shared resolver (`ipc_ep_from_slot`, `ipc_notif_from_slot`, `iodev_from_slot`) does the `cap_lookup` | `make smoke-captest` (198 checks) |
| S2 | Delegation cannot widen authority | Mint, grant and transfer compute `requested & src->rights` | CI job `rust`; `cargo test --manifest-path rust/Cargo.toml --release` |
| S3 | Revoking a capability revokes its entire derivation subtree, system-wide | `rust_cap_revoke_global` walks every live cspace and removes the whole derivation subtree | CI job `rust`; CI job `kani-bounded` |
| S4 | Revoking a capability does *not* revoke ancestors, siblings, or independent peers | The revocation closure follows descendants only | CI job `rust`; CI job `kani-bounded` |
| S5 | A revoked capability cannot be used, even from a stale snapshot | Revocation nulls the slots structurally and bumps a generation keyed by serial, so a stale copy fails `lineage_check` | `make smoke-captest` |
| S6 | An unknown or reserved syscall number cannot reach a handler | Table dispatch with a compile-time size assertion; an absent entry returns `SYS_ERR_NOSYS` | `make smoke-captest` |
| S7 | A user pointer cannot address kernel memory | User copies walk the page tables in software and require `PAGE_USER`; SMAP backs this in hardware | `make smoke-captest`, `make smoke-cpu` |
| S8 | No kernel page is simultaneously writable and executable | Per-section PTE permissions and `CR0.WP`, swept at boot | `make smoke-wx` |
| S9 | A kernel stack overflow cannot reach adjacent memory | An unmapped guard page below every kernel stack: per-task, boot, IST and per-CPU idle stacks | `make smoke-wx`, `make smoke-wx-smp` |
| S10 | A boot module that fails its hash check cannot be executed | The module manifest is verified at boot; the read path refuses an unverified module, and verified modules are re-hashed before userspace starts (S96) | `make smoke-modules-tamper` |
| S11 | Tampering with the boot chain is detectable | TPM measurement: the firmware measures the boot image, which pins the kernel's hash, into `PCR[4]`; the kernel measures its command line and manifest into `PCR[8]` and each module into `PCR[9]` | `make smoke-tpm`, `make smoke-tpm-tamper`, `make smoke-boot-pin`, `make smoke-tpm-bootimg` |
| S12 | A tampered boot cannot unlock the volume | The volume key-encryption key is sealed to PCRs 4, 8 and 9 | `make smoke-tpm-seal` |
| S13 | A server can determine a client's true identity | `SYS_IPC_SENDER` returns the uid the kernel recorded at login, gated on the receive right | `make smoke-fs-perms`, `make smoke-captest` |
| S13a | A task can operate on an IPC object only via a capability naming it | IPC resolves the endpoint or notification from the caller's slot (`ipc_ep_from_slot`, `ipc_notif_from_slot`) | `make smoke-captest` |
| S13b | A client cannot intercept or forge a server's replies | Clients are minted send-only capabilities; receive and reply need READ | `make smoke-captest` |
| S18 | Being uid 0 confers no kernel authority by itself | Every former `uid == 0` gate is a typed capability | `make smoke-captest` |
| S14 | File permissions are enforced against that identity | `fs_server` checks every operation against the kernel-attested uid | `make smoke-fs-perms` |
| S15 | An address-space slot rebuilt after task death leaks nothing | A reused slot's cspace is zeroed and its address space returned to the pool | `make smoke-aspace` |
| S16 | A task cannot read another's XMM register file | `fpu_save` and `fpu_restore` save and restore the whole FXSAVE image on every ring transition | `make smoke-fpu`; arms: `smoke-fpu-leak-control` (`FPU_NO_RESTORE=1`), `smoke-fpu-save-control` (`FPU_NO_SAVE=1`) |
| S22 | A number stated in the documentation matches the tree it describes | `.github/doc-claims.yml` declares each derivable count and where it is stated; `tools/check_doc_claims.py` derives and compares them, and refuses retired phrasings | CI job `doc-claims` |
| S17 | The shipped **kernel image** corresponds to the published source | `kernel.elf` builds byte-for-byte identically from the same source; the ISO does not yet (`docs/LIMITATIONS.md` 5.3a) | `make smoke-repro-sha`; CI job `reproducible`; `make reproducible-build`; arms: `smoke-repro-sha-control` (`REPRO_SHA_UNCHECKED=1`) |
| S19 | Audit-log history committed before a kernel compromise cannot be forged or rewritten | A forward-secure hash chain in `src/kernel/kaudit.c`: the MAC key is ratcheted one way and erased after every entry | CI job `rust` |
| S20 | A task's kernel stack is executed by at most one CPU at a time | The scheduler holds its claim on a task until the CPU has left that task's stack (`sched_release_deferred`); a CPU whose last task dies parks on its own stack; a spawn never reuses a slot a CPU is still on; `g_kstack_inflight` halts the kernel on a collision | `make smoke-kstack-race`, `make smoke-kstack-park`, `make smoke-enter-user-claim`, `make smoke-sched-invariants`, `make smoke-task-ceiling`, `make smoke-kstack-imp`, `make smoke-kstack-reuse`; arms: `smoke-enter-user-claim-control` (`ENTER_USER_PUBLISH_EARLY=1`, `ENTER_USER_STEAL_WIDEN=1`), `smoke-enter-user-collide-control` (`ENTER_USER_CLAIM_UNCHECKED=1`, `ENTER_USER_PUBLISH_EARLY=1`, `ENTER_USER_STEAL_WIDEN=1`), `smoke-kstack-imp-control` (`KSTACK_COLLIDE_IMPERSONATED=1`), `smoke-kstack-reuse-control` (`SLOT_REUSE_UNCHECKED=1`); falsified by `KSTACK_INFLIGHT_LEGACY_WORD=1`, `KSTACK_SLOT_INDEX_TRUNC=1` |
| S25 | Which syscalls a test actually exercises is measured, not assumed | `SYSCALL_COVERAGE=1` records the first entry into each handler; `.github/syscall-coverage.yml` classifies all 102 implemented syscalls as covered or uncovered with a reason. Currently **91 of 102**: the property is that the number is decided and checked, not that it is complete | `make smoke-syscall-coverage`; CI job `syscall-coverage`; arms: `smoke-syscall-coverage-control` (`SYSCOV_PROBES_ABSENT=1`) |
| S24 | The kernel never reads or writes a user address the caller did not name | Every pointer-taking wrapper in `include/syscall.h` passes its pointer at full width (`SYSCALL_UPTR`), checked by `tools/check_syscall_abi.py`; `user_copy` then refuses an address the task has not mapped | `make smoke-klog-forge`, `make smoke-auditprobe`; CI job `syscall-abi`; arms: `smoke-klog-forge-abi-control` (`SYSCALL_PTR_TRUNC32=1`), `smoke-auditprobe-control` (`SYSCALL_PTR_TRUNC32=1`) |
| S23 | A ring-3 task cannot forge entries into the kernel message ring, nor evict what is already there | `h_write` appends to the kernel log only for a holder of `CAP_KERNEL_LOG` with WRITE, and the root mints that capability READ-only | `make smoke-klog-forge`; arms: `smoke-klog-forge-control` (`KLOG_WRITE_UNGATED=1`) |
| S29 | Reaching a mounted subtree requires the capability for that mount, not the path | The VFS is a per-task library (`userspace/hvfs.c`), not a server; a mount is a slot holding the server's capability, and an empty or wrong slot fails the kernel's IPC gate | `make smoke-vfs`, `make smoke-newlib`, `make smoke-session`; arms: `smoke-newlib-walk-control` (`POSIX_LEGACY_WALK=1`), `smoke-newlib-dotdot-control` (`HVFS_DOTDOT_SERVER=1`), `smoke-vfs-mount-control` (`VFS_MOUNT_UNGATED=1`), `smoke-vfs-prefix-control` (`VFS_FIRST_MATCH=1`) |
| S28 | A gate satisfied by a capability every task already holds is not a gate | The ramfs paths that were gated on the slot-3 capability every task holds are retired and answer `SYS_ERR_NOSYS` | `make smoke-passwd-probe`; arms: `smoke-captest-getline-control` (`GETLINE_SLOT3_FALLBACK=1`), `smoke-passwd-probe-legacy-control` (`LEGACY_SYSCALLS_PRESENT=1`), `smoke-passwd-probe-control` (`RAMFS_SLOT3_GATE=1`) |
| S26 | Memory can only be mapped through a capability naming a kernel-managed frame object | `CAP_FRAME.object` is an index into the frame table `SYS_RETYPE` fills, bounds-checked, never a physical address, so the slot-3 decoy every task holds maps nothing | `make smoke-frame` (58 parent checks + 9 peer checks); arms: `smoke-frame-index-control` (`FRAME_INDEX_UNCHECKED=1`) |
| S27 | A memory mapping conveys no authority the capability does not carry | `SYS_MAP_FRAME` resolves the named slot with the requested rights and builds the PTE from `cap->rights & requested` | `make smoke-frame`; arms: `smoke-frame-rights-control` (`FRAME_RIGHTS_UNCHECKED=1`) |
| S21 | A program image can only be spawned by the task that armed it, and a child inherits its stdio from that same task | `loader_arm_commit` records the arming task; `do_spawn` and `h_sudo` refuse a foreign or unowned image | `make smoke-spawn-owner`; arms: `smoke-spawn-owner-control` (`SPAWN_OWNER_UNCHECKED=1`) |
| S30 | The CSPRNG never emits output before it is seeded from real entropy | `RngState::fill` refuses and zeroes the buffer while unseeded; the C wrappers halt on a refusal | `make smoke-rng-seed`; `cargo test --features rng_unseeded_legacy`; arms: `smoke-rng-seed-control` (`RNG_UNSEEDED_LEGACY=1`) |
| S31 | The capability algebra's authority invariants, and the page-pool refcount arithmetic, are proved over the whole input space, and the proofs run | **23** `#[kani::proof]` harnesses; `.github/kani-harnesses.yml` classifies each as gating or excused, and `tools/check_kani_harnesses.py` fails the build on one in neither. **2** excused harnesses, the serial-keyed lineage pair, run in the manual `kani` job | CI job `kani-bounded`; CI job `kani`; `cargo kani` |
| S32 | The capability graph is observable, under an authority that observes and nothing else | `CAP_DEBUG`, minted READ-only at the root, gates cross-task introspection and `SYS_CAP_ENUMERATE`, which reports a slot's type, rights, serial, badge and generation but not its object | `make smoke-session`, `make smoke-captest`; arms: `smoke-captest-capenum-control` (`CAP_ENUMERATE_UNGATED=1`), `smoke-proc-taskinfo-control` (`TASKINFO_WIDE_AUTHORITY=1`) |
| S33 | The security core's `unsafe` FFI code is free of the undefined behaviour an interpreter can see | `cargo miri test` over the Rust core, every tested module except the crypto ones excused in `.github/miri-scope.yml` | CI job `miri` |
| S34 | A clock is available to ring 3 without restoring the timer `CR4.TSD` denies | `SYS_CLOCK_GETTIME` reports monotonic time from the PIT tick counter at 10 ms resolution, never the TSC | `make smoke-captest`; arms: `smoke-captest-clock-control` (`CLOCK_TSC_RESOLUTION=1`) |
| S35 | A mapping call that reports failure installs no mapping | `SYS_MAP_REGION` is all-or-nothing: a page that cannot be mapped withdraws every page the call already mapped | `make smoke-frame`; arms: `smoke-frame-region-control` (`FRAME_REGION_NO_ROLLBACK=1`), `smoke-frame-region-wide-control` (`FRAME_REGION_ROLLBACK_WIDE=1`) |
| S36 | A frame capability names a run of pages, and every page of it is real | A `KOBJ_FRAME` carries its length and is mapped and withdrawn whole; every page of the run is distinct and real | `make smoke-frame`; arms: `smoke-frame-pages-control` (`FRAME_PAGES_SAME_PHYS=1`) |
| S37 | A frame's size is readable by a holder of its capability, and by nobody else | `SYS_FRAME_PAGES` resolves the caller's capability, type-tested, never a frame index | `make smoke-frame`; arms: `smoke-frame-info-control` (`FRAME_INFO_BY_INDEX=1`) |
| S38 | A page belonging to a kernel object is never copied out from under it | `cow_break_pte` refuses any page inside the untyped arena | `make smoke-nzcow`; CI job `fork`; arms: `smoke-nzcow-arena-control` (`COW_ARENA_UNGUARDED=1`) |
| S39 | A forked child's memory is a copy of its parent's, not a share | `clone_user_aspace` marks both the parent's and the child's leaves copy-on-write | `make smoke-fork`, `make smoke-forkexec`; arms: `smoke-fork-share-control` (`FORK_SHARE_WRITABLE=1`) |
| S40 | A fork never shares a kernel object's page | `clone_user_aspace` refuses a task with a frame from the untyped arena mapped, before the child exists | `make smoke-fork`; arms: `smoke-fork-arena-control` (`FORK_ARENA_UNCHECKED=1`) |
| S41 | A forked child's capabilities are derived from its parent's, never duplicates of them | `cap_clone_cspace` derives each child capability through `rust_cap_grant_into`, with its own serial and the parent's as its badge | `make smoke-fork`; arms: `smoke-fork-cspace-flat-control` (`FORK_CSPACE_FLAT_COPY=1`), `smoke-fork-cspace-orphan-control` (`FORK_CSPACE_ORPHAN_COPY=1`) |
| S42 | An exec replaces the image, not the authority | The exec paths rebuild the address space and do not touch the cspace, so lineage survives an exec | `make smoke-forkexec`, `make smoke-execprobe`; arms: `smoke-forkexec-reset-control` (`EXEC_RESET_CSPACE=1`), `smoke-forkexec-root-control` (`EXEC_ROOT_CSPACE=1`), `smoke-execprobe-reset-control` (`EXEC_RESET_CSPACE=1`), `smoke-execprobe-root-control` (`EXEC_ROOT_CSPACE=1`) |
| S43 | Hardware authority names a device, and reaches only that device | A `CAP_IO_DEVICE` names an entry in the boot-time device table, and the device syscalls check each frame, port range and interrupt against what that entry declares | `make smoke-devcap`, `make smoke-devcap-fb`; arms: `smoke-devcap-object-control` (`IO_DEVICE_OBJECT_UNCHECKED=1`), `smoke-devcap-ports-control` (`IO_DEVICE_PORTS_GLOBAL=1`), `smoke-devcap-irq-control` (`IO_DEVICE_IRQ_UNCHECKED=1`); falsified by `FB_INFO_ANY_DEVICE=1` |
| S44 | Turning a device into a bus master is authority, held by a capability, and it is the one authority this machine cannot bound | `SYS_DEVICE_ENABLE` sets only the three PCI decode bits of the named device; `SYS_DMA_ADDR` needs both the frame and a device capability | `make smoke-net`; arms: `smoke-net-decode-control` (`NET_NO_DECODE=1`), `smoke-frame-dma-control` (`DMA_ADDR_FRAME_ONLY=1`), `smoke-net-busmaster-control` (`NET_NO_BUSMASTER=1`) |
| S45 | A device reaches only the memory its driver mapped for it | VT-d gives every device its own address space, starting empty; `SYS_DMA_ADDR` maps only frames the driver holds | `make smoke-net`; arms: `smoke-net-iommu-control` (`NET_IOMMU_NO_MAP=1`) |
| S46 | An unserviced device interrupt cannot livelock the machine, and re-enabling one is authority | A level-triggered line is masked before it is acknowledged and stays masked until the driver calls `SYS_IRQ_ACK`, which needs the device capability | `make smoke-net`, `make smoke-captest`; arms: `smoke-net-mask-control` (`IRQ_NO_MASK_ON_FIRE=1`), `smoke-net-irq-storm-control` (`IRQ_FORCE_PIC=1`, `IRQ_NO_MASK_ON_FIRE=1`), `smoke-captest-irq-ack-control` (`IRQ_ACK_UNGATED=1`) |
| S47 | A device's interrupt vector is chosen by the kernel, never by its driver | `SYS_MSI_REGISTER` programs the device's MSI capability with a vector the kernel allocates; the ABI has no field for a vector | `make smoke-net`; arms: `smoke-net-msi-vector-control` (`MSI_VECTOR_FROM_USER=1`) |
| S48 | A driver cannot map its own device's MSI-X vector table | `SYS_MAP_PHYS` refuses the page holding a device's MSI-X table | `make smoke-net`; arms: `smoke-net-msix-table-control` (`MSIX_TABLE_MAPPABLE=1`) |
| S49 | Shared library text is executed by many tasks and writable by none | The library is loaded once, and every task maps its text through a `CAP_FRAME` with READ and EXEC and never WRITE | `make smoke-shlib`; arms: `smoke-shlib-writable-control` (`SHLIB_TEXT_WRITABLE=1`) |
| S50 | A shared library's writable data is private to each task | A shared object's writable pages are kept as a template no task maps, and each task gets its own copy | `make smoke-shlib`; arms: `smoke-shlib-data-shared-control` (`SHLIB_DATA_SHARED=1`), `smoke-shlib-data-init-control` (`SHLIB_DATA_UNINITIALISED=1`) |
| S51 | The shared library's load address is drawn per boot, and is not ambient information | `shlib_init` draws the base from the CSPRNG-seeded `aslr_random_offset` at boot; `SYS_SHLIB_INFO` reports it only to a holder of the library's text capability | `make smoke-shlib-aslr`, `make smoke-shlib`; arms: `smoke-shlib-aslr-control` (`SHLIB_BASE_FIXED=1`); falsified by `SHLIB_INFO_UNGATED=1`, `SHLIB_INFO_TYPE_ONLY=1` |
| S52 | An unauthorised capability operation is refused by returning, never by halting the CPU | `cap_mint` and `cap_transfer` resolve through `cap_lookup`, which returns NULL rather than spinning on an assertion | `make smoke-captest`; arms: `smoke-captest-mint-hang-control` (`CAP_LOOKUP_ASSERT_HANG=1`) |
| S53 | A device's translation of a page does not outlive the capability that authorised it | `destroy_dyn_frame` unmaps a frame from every device domain before scrubbing it, and `task_teardown` resets a dying driver's domain | `make smoke-iommu-teardown`; arms: `smoke-iommu-teardown-control` (`IOMMU_NO_FRAME_TEARDOWN=1`), `smoke-iommu-teardown-task-control` (`IOMMU_NO_TASK_TEARDOWN=1`) |
| S54 | Every `unsafe` in the security core states what its caller must uphold | `tools/check_unsafe_safety.py` requires a `# Safety` section on every `unsafe` in the Rust core | CI job `unsafe-safety`; CI job `miri`; CI job `kani-bounded` |
| S55 | A capability lookup resolves against the CALLER'S OWN cspace, or refuses | `cap_lookup` resolves only within the caller's own cspace; a task with no cspace (other than task 0) or a slot past its end is refused | `make smoke-cap-lookup`; arms: `smoke-cap-lookup-control` (`CAP_LOOKUP_ROOT_FALLBACK=1`), `smoke-cap-lookup-range-control` (`CAP_LOOKUP_RANGE_FALLBACK=1`) |
| S56 | A task's authority ends when the task does | `task_teardown` empties the cspace before `kobj_gc`; a torn-down task is never resumed or dispatched again, and other CPUs running it are sent the kill IPI | `make smoke-cspace-release`, `make smoke-killed-task`; arms: `smoke-cspace-release-control` (`CSPACE_KEEP_ON_TEARDOWN=1`), `smoke-proc-killed-task-control` (`DEAD_TASK_RUNS=1`) |
| S57 | Creating a task exercises authority the capability graph describes | Spawn and fork carve the child's cspace from the caller's own `CAP_UNTYPED`; a task with no untyped cannot create one | `make smoke-proc`; arms: `smoke-proc-spawn-decoy-control` (`SPAWN_SLOT3_DECOY_GATE=1`) |
| S58 | A budget can be subdivided, not only shared | `SYS_UNTYPED_SPLIT` carves bytes off the parent's region and mints a derived capability over them; the parent pays | `make smoke-captest`; arms: `smoke-captest-split-control` (`UNTYPED_SPLIT_FREE_BYTES=1`) |
| S59 | A supervisor can provision a server on an endpoint it created | `launch_dev_server` retypes an endpoint from `init`'s own untyped and delegates it | `make smoke-init-provision`; arms: `smoke-init-provision-control` (`INIT_PROVISION_NO_UNTYPED=1`) |
| S60 | A capability lookup refuses a type-mismatched capability | `cap_lookup` takes the expected type and refuses any other | `make smoke-captest`; arms: `smoke-captest-lookup-type-control` (`CAP_LOOKUP_TYPE_UNCHECKED=1`) |
| S61 | Several passwords open one volume, and revoking one revokes exactly that one | Up to eight key slots each wrap the volume key under a KEK derived with Argon2id from one password; removing a slot removes exactly that wrap | `make smoke-keyslots`; arms: `smoke-keyslots-control` (`KEYSLOT_REMOVE_NOOP=1`) |
| S62 | User accounts survive a reboot, and an unauthentic account table refuses logins | The account table is sealed under a key derived from the volume key and written through the journal; a table that fails authentication loads nothing | `make smoke-users-persist`, `make smoke-users-tamper`; arms: `smoke-users-persist-control` (`USERS_PEPPER_PER_BOOT=1`) |
| S63 | A login is not consent to format a disk | A login never formats; only `storage_authorize_format`, reached through `CAP_STORAGE_FORMAT`, does | `make smoke-storage-noformat`; arms: `smoke-storage-noformat-control` (`STORAGE_AUTOFORMAT=1`) |
| S64 | A block device accepts only blocks it has memory for | The RAM disk refuses a block past the memory reserved for it | `make smoke-vdisk-bound`; arms: `smoke-vdisk-bound-control` (`VDISK_TOTAL_UNBOUNDED=1`) |
| S65 | A metadata update in a committed journal transaction is durable, whether or not its cache line was evicted first | Per-block metadata lives in a bounded write-back cache whose dirty lines are written inside the committing journal transaction | `make smoke-meta-crash`; arms: `smoke-meta-crash-control` (`META_CACHE_NO_WRITEBACK=1`), `smoke-meta-crash-txn-control` (`META_CACHE_WB_OUTSIDE_TXN=1`), `smoke-meta-crash-vacuity-control` |
| S66 | A metadata block is served only when it verifies against the path to the **current** rollback root, an earlier state of this volume is not a valid state | A Merkle tree over the metadata region; each block is verified against the current root before use | `make smoke-merkle-replay`; arms: `smoke-merkle-replay-control` (`MERKLE_NODE_TRUST_CACHED=1`), `smoke-merkle-parent-bind-control` (`MERKLE_SKIP_PARENT_BIND=1`) |
| S67 | `fsck` does not free the blocks of a live file | `storage_fsck_pass` builds its reference set from every level of each live inode's block tree | `make smoke-fsck-refs`; arms: `smoke-fsck-refs-control` (`FSCK_SHALLOW_REFS=1`) |
| S68 | A volume is laid out against the disk it is on, and never larger | A volume is sized from the disk's IDENTIFY, and a superblock larger than the disk is refused | `make smoke-fs-16g`, `make smoke-fs-shrink`; arms: `smoke-fs-shrink-control` (`STORAGE_MOUNT_ANY_SIZE=1`) |
| S69 | A sector transfer happens only when the drive says it is ready; a read that did not happen is never reported as one that did | `ata_wait_busy` returns a result the sector paths check, and `ata_transfer_ready` allows a transfer only with DRQ set and BSY, ERR and DF clear | `make smoke-ata-ready`; arms: `smoke-ata-ready-control` (`ATA_READY_ERR_ONLY=1`) |
| S70 | A volume older than the machine it is presented to is refused, **whole-volume rollback** | `sb.rollback_gen` is bound into the Merkle root and checked against a TPM NV monotonic counter at unlock | `make smoke-rollback`, `make smoke-nvcounter`; arms: `smoke-rollback-control` (`ROLLBACK_ANCHOR_IGNORE=1`) |
| S71 | A record the kernel copies into ring 3 has **one** definition, and both rings compile it | `include/audit_abi.h` is the one declaration of the audit record, compiled by both rings with a size assertion | `make smoke-auditprobe`; arms: `smoke-auditprobe-abi-control` (`AUDIT_ABI_LEGACY=1`) |
| S72 | Destroying a volume answers to a capability nothing else in the system holds | `CAP_STORAGE_FORMAT` is a capability type of its own, granted by `init` to the installer alone | `make smoke-captest`, `make smoke-storage-survey`; arms: `smoke-captest-storage-format-control` (`STORAGE_FORMAT_UNGATED=1`) |
| S73 | A disk is erased only after an act that means erasing the disk and nothing else | The installer formats only after the operator types the confirmation word, as the last step after every answer is shown back | `make smoke-installer-refuse`, `make smoke-installer`; arms: `smoke-installer-refuse-control` (`INSTALLER_NO_CONFIRM=1`) |
| S74 | The object store answers only an **unlocked** volume, not merely a mounted one | The object-store handlers require an unlocked volume, not only a mounted one | `make smoke-installer-provision`; arms: `smoke-installer-provision-control` (`STORE_LOCKED_UNCHECKED=1`) |
| S75 | A password command changes the account it names, and says which one it changed | The shell's `passwd <uid>` passes that uid, and `SYS_PASSWD` reports which account it changed | `make smoke-passwd-target`; arms: `smoke-passwd-target-control` (`PASSWD_TARGET_IGNORED=1`) |
| S76 | An account an administrator creates can be the **first** login after a power cycle | When an administrator sets a password, `do_passwd` grants that account a key slot | `make smoke-installer-accounts`; arms: `smoke-installer-accounts-control` (`PASSWD_NO_KEYSLOT=1`) |
| S77 | A file's **mode** is set by its owner or root; its **owner** is set by root alone | `fs_server` lets an owner or root change a mode, and only root change an owner | `make smoke-session`; arms: `smoke-session-chown-control` (`FS_CHOWN_ANY_UID=1`), `smoke-session-chmod-control` (`FS_CHMOD_ANY_OWNER=1`) |
| S78 | Every account has a home directory that the **account** owns, and the account table is read only with `CAP_USER` | `useradd` creates a home owned by the account; `SYS_USERLIST` needs `CAP_USER` | `make smoke-session`, `make smoke-captest`; arms: `smoke-session-home-control` (`HOME_DIR_ROOT_OWNED=1`), `smoke-captest-userlist-control` (`USERLIST_UNGATED=1`) |
| S79 | **No syscall in the ship build is authorised by a capability the kernel hands every task** | `tools/check_dispatch_gates.py` refuses any ship dispatch row gated on slot 3, whose capability every task holds | `make smoke-passwd-probe`; arms: `smoke-passwd-probe-recv27-control` (`LEGACY_SYSCALLS_PRESENT=1`), `smoke-passwd-probe-exec19-control` (`LEGACY_SYSCALLS_PRESENT=1`, `SYSCALL_COVERAGE=1`) |
| S80 | **The `.bin` program-image container has exactly one declaration, and the kernel reads what the build tool wrote** | `include/program_abi.h` is the one declaration of the `.bin` container, used by the kernel, userspace and the host build tool | `make smoke-image-abi`, `make smoke-preempt`, `make smoke-smp`, `make smoke-proc`, `make smoke-signal`, `make smoke-tsd`, `make smoke-fs`, `make smoke-captest`; arms: `smoke-image-abi-control` (`IMAGE_HDR_WRITER_SKEW=1`) |
| S81 | **A kernel diagnostic cannot be cut in half by a ring-3 task's output** | Kernel reports go first to COM3, which no device declares, so no capability or port grant can reach it | `make smoke-kdiag`, `make smoke-kdiag-ioport`; arms: `smoke-kdiag-split-control` (`KDIAG_NOISE=1`, `KDIAG_PROBE=1`, `KDIAG_SPLIT_WIDEN=1`), `smoke-kdiag-legacy-control` (`KDIAG_LEGACY_COM1=1`), `smoke-kdiag-grant-control` (`KDIAG_PORTS_GRANTABLE=1`) |
| S82 | **A machine with more than one disk says so, and a survey answers only about the device it was asked about** | Every disk is a block device of its own, and a survey answers only for the index it was asked about | `make smoke-storage-survey`; arms: `smoke-storage-survey-single-control` (`STORAGE_SINGLE_DEVICE=1`), `smoke-storage-device-clamp-control` (`STORAGE_DEVICE_INDEX_CLAMP=1`) |
| S83 | **The call that erases a disk names the disk it erases** | `SYS_STORAGE_FORMAT` takes the target disk as an argument and refuses a mounted or unknown one | `make smoke-installer-target`; arms: `smoke-installer-target-control` (`STORAGE_FORMAT_TARGET_IGNORED=1`) |
| S84 | **A program image cannot read past its own bytes into the shared staging buffer** | Every ELF parse is bounded by the bytes actually staged (`staged_bytes`), and a rejected ELF fails closed before the old address space is torn down | `make smoke-proc`, `make smoke-execprobe`; arms: `smoke-proc-overreach-control` (`ELF_LOAD_BOUND_STAGING=1`), `smoke-proc-truncated-image-control` (`IMAGE_LEN_UNCHECKED=1`) |
| S85 | **A disk that was never sealed cannot satisfy a machine that requires measured boot** | `MEASURED_BOOT_REQUIRED=1` refuses to unlock a persistent volume that was never sealed to the TPM | `make smoke-measured-persist`, `make smoke-measured-persist-sealed`; arms: `smoke-measured-boot-required-control` (`MEASURED_BOOT_REQUIRED=1`), `smoke-measured-persist-control` (`MEASURED_VOLUME_UNCHECKED=1`) |
| S86 | **Every symbol the security core exports across the FFI has a live caller** | `tools/check_ffi_deadsurface.py` requires every exported Rust FFI symbol to have a caller | CI job `ffi-deadsurface` |
| S87 | **Every object linked into `kernel.elf` is classified, and the verified core has a stated size** | `.github/ring0-classification.yml` assigns every linked object to `core` (10,843 code lines, 18 files), `driver`, `service` or `selftest`, and `tools/check_ring0_budget.py` holds `core` to its budget. 10,843 code lines is a lot; the value is that the number is stated and cannot move silently | CI job `ring0-budget` |
| S88 | **The kernel's lock order is declared, and no path closes a cycle** | `.github/lock-order.yml` declares the lock nestings, and `tools/check_lock_order.py` fails on any other nesting or a reversal | CI job `lock-order` |
| S89 | **The console's input and its output change hands at the same moment** | Keyboard input and screen output pass to `console_server` at the same moment (`console_hw_owned`) | `make smoke-keyboard`, `make smoke-keyboard-installer`, `make smoke-keyboard-install`; arms: `smoke-keyboard-control` (`CONSOLE_NO_KBD=1`); falsified by `CONSOLE_KBD_SPLIT_ESC=1` |
| S90 | **A volume that has been unlocked cannot be reformatted; one that has only been recognised can be, by a capability holder** | `storage_authorize_format` refuses a volume that has been unlocked; a locked, recognised one can be replaced by the `CAP_STORAGE_FORMAT` holder, once | `make smoke-replace-live`, `make smoke-installer-replace`, `make smoke-replace-oneshot`; arms: `smoke-replace-live-control` (`STORAGE_REPLACE_UNLOCKED=1`); falsified by `STORAGE_FORMAT_AUTH_STICKY=1` |
| S91 | **The kernel command line is part of the measured boot** | The command line is measured into `PCR[8]` with the manifest; the boot mode is read from whole words, and anything unclear means live boot | `make smoke-tpm-cmdline`, `make smoke-boot-menu`; arms: `smoke-tpm-cmdline-control` (`BOOT_CMDLINE_UNMEASURED=1`) |
| S92 | **The kernel that runs is the kernel the boot image was built to boot, and the boot image is measured** | GRUB checks the kernel against a SHA-256 pinned inside the boot image, and the firmware measures that image into `PCR[4]` | `make smoke-boot-pin`, `make smoke-tpm-bootimg`; arms: `smoke-boot-pin-control`, `smoke-tpm-bootimg-control` (`BOOT_IMAGE_UNBOUND=1`, `BOOT_PIN_UNCHECKED=1`) |
| S93 | **A console client is not entitled to read a password** | `console_server` serves `CON_OP_GETPASS` only to the registered input owner | `make smoke-console-pass`, `make smoke-session`; arms: `smoke-console-pass-control` (`CONSOLE_PASS_UNGATED=1`), `smoke-captest-getline-control` (`GETLINE_SLOT3_FALLBACK=1`) |
| S94 | **Every write to a capability slot goes through the locked, accounted cap-write path** | `tools/check_cap_writes.py` requires every write to a capability slot to go through the locked cap-write path or a declared exemption | `make smoke-captest`; CI job `cap-writes`; arms: `smoke-cap-accounting-control` (`PIPE_CAP_UNACCOUNTED=1`) |
| S95 | **Every task's private reply endpoint is an object no other task can hold a capability for** | `MAX_ENDPOINTS` covers every task's reply endpoint, and a reply endpoint cannot be named by another task's capability | `make smoke-reply-ep`, `make smoke-captest`; arms: `smoke-reply-ep-control` (`REPLY_EP_SPACE_OVERLAP=1`) |
| S96 | **A boot module the kernel verified is the one it serves** | The kernel keeps its own writes off every module and re-hashes verified modules before userspace starts | `make smoke-boot-module-reserve`; arms: `smoke-boot-module-reserve-control` (`POOL_RESERVE_FIXED_BASE=1`), `smoke-boot-module-reverify-control` (`BOOT_MODULE_RESERVE_UNCHECKED=1`, `POOL_RESERVE_FIXED_BASE=1`), `smoke-boot-module-image-control` (`BOOT_MODULE_IMAGE_PROBE=1`, `BOOT_MODULE_RESERVE_UNCHECKED=1`) |
| S97 | **A task's exit record carries no kernel address** | A supervisor-mode fault records no kernel address in the exit record | `make smoke-kfault-record`; arms: `smoke-kfault-record-control` (`EXIT_RECORD_KERNEL_RIP=1`) |
| S98 | **A task starts with no death record, whichever slot it lands in** | `create_task` clears the exit record of the slot it reuses | `make smoke-proc`; arms: `smoke-proc-exit-record-control` (`EXIT_RECORD_STALE_ON_REUSE=1`) |
| S99 | **Waiting on a task needs a capability naming that task** | `SYS_WAIT` needs a `CAP_TCB` naming the task | `make smoke-proc`; arms: `smoke-proc-wait-control` (`WAIT_TCB_UNCHECKED=1`) |
| S100 | **A `CAP_TCB` names one task, never the slot it lived in** | A `CAP_TCB` records the task's generation (`task_tcb_held`), so a capability for a dead task refuses rather than naming the slot's next occupant | `make smoke-proc`; arms: `smoke-proc-tcb-reuse-control` (`TCB_GENERATION_UNCHECKED=1`) |
| S101 | **No task runs on a secondary SMT thread** | `ap_entry64` parks every secondary SMT thread before its scheduler timer starts, deciding sibling-ness from the CPU's own topology | `make smoke-smp-topology`, `make smoke-smt`; arms: `smoke-smp-topology-sibling-control` (`SMT_SIBLING_BY_INDEX=1`) |
| S102 | **A physical frame is never on the free list twice** | `free_user_physical_page` accepts only a frame recorded as on loan in `page_on_loan` | `make smoke-pagefree`; arms: `smoke-pagefree-control` (`PAGE_FREE_UNGUARDED=1`) |
| S103 | **The compiled-in accounts exist only on a live boot** | `users_apply_boot_policy` removes the compiled-in accounts on any boot that is not live and has a persistent disk | `make smoke-installer`; arms: `smoke-installer-defaults-control` (`DEFAULT_ACCOUNTS_ON_DISK=1`) |
| S104 | **A volume is unencrypted only when its operator chose that, and every boot says which kind it found** | An unsealed volume is written only when the installer's operator chooses it, and every boot reports which kind it found | `make smoke-installer-unsealed`, `make smoke-installer`; arms: `smoke-installer-unsealed-control` (`STORAGE_UNSEALED_IGNORED=1`), `smoke-installer-sealed-control` (`STORAGE_UNSEALED_ALWAYS=1`) |
| S105 | **A server can only narrow the authority a client invoked it with, and tells clients apart by the capability, never by who they are** | An endpoint capability carries a token; the receiver sees the invoking capability's token and rights, and a reply-mint can only narrow them | `make smoke-captoken`, `make smoke-captoken-smp`; CI job `kani-bounded`; arms: `smoke-captoken-unmasked-control` (`TOKEN_REPLY_MINT_UNMASKED=1`) |
| S106 | **A task holds the shared libc only if its own image asked for it and its spawner held all of it, and the library's data it runs with is its own memory** | The kernel hands the library's text capabilities only to a program whose image asks for it and whose spawner holds them, with fresh private data at every spawn and exec | `make smoke-shlib-inherit`; arms: `smoke-shlib-inherit-image-control` (`SHLIB_INHERIT_ANY_IMAGE=1`); falsified by `SHLIB_DATA_TEMPLATE_SHARED=1`, `SHLIB_EXEC_NO_DATA=1`, `SHLIB_TEMPLATE_UNPINNED=1` |
| S107 | **A page a program seals is read-only for good, and a program can seal nothing but its own image** | `SYS_MEM_SEAL` clears write permission on pages of the caller's own image for good, all or nothing | `make smoke-mem-seal`; arms: `smoke-mem-seal-write-control` (`MEM_SEAL_KEEPS_WRITE=1`); falsified by `MEM_SEAL_ANY_ADDRESS=1` |
| S108 | **A program linked against the shared libc runs only against the library it was built for, with every name it imports resolved or refused, and its resolved table sealed before main** | crt0's linker resolves every import by name against the library's export table, refuses a mismatched ABI hash or an unknown name, then seals the table | `make smoke-shlib-link`; falsified by `DYNLINK_ABI_UNCHECKED=1`, `DYNLINK_UNKNOWN_ZERO=1`, `DYNLINK_NO_SEAL=1` |
| S109 | **No password printed in the source is ever written to a disk** | `users_persist` refuses to write a table that still holds a compiled-in password | `make smoke-live-no-seed`; arms: `smoke-live-no-seed-control` (`USERS_PERSIST_COMPILED_IN=1`); falsified by `LIVE_OPENS_VOLUME=1` |
| S110 | **There is no way to live-boot an installed system** | A live boot mounts no persistent disk, and `storage_unlock` refuses one on a live boot | `make smoke-live-locked`; arms: `smoke-live-locked-control` (`LIVE_OPENS_VOLUME=1`) |

---

## Cryptography

| Purpose | Primitive |
|---|---|
| Random numbers | ChaCha20 with fast key erasure, seeded from RDRAND (health-checked), the TSC and interrupt jitter; refuses output until seeded (S30) |
| Data at rest | An AEAD with a per-block subkey and a fresh nonce for every write |
| Passwords and the key-encryption keys | Argon2id |
| Key derivation | HKDF-SHA256 for the per-block subkeys, the metadata and journal MAC keys, and the account-table key |
| Measurement | SHA-256 for the kernel pin, the module manifest and the TPM PCRs; BLAKE2b inside Argon2 |
| Integrity | A Merkle tree over the block metadata, anchored by a TPM monotonic counter |

All of them are implemented in `no_std` Rust in `rust/src/`, with no external dependency. None is
independently audited or verified constant-time (**[HORUS-20260920-03]**).

---

## Process security

The build and CI are part of the trusted computing base.

**In place:** signed commits and linear history required on `main`; no bypass actors;
force-pushes and deletion blocked; every third-party action pinned to a full commit SHA;
least-privilege tokens per workflow; every CI job classified as gating or exempt with a written
reason in `.github/ci-gating.yml`, and a ruleset that requires the `gates` aggregator (which needs
every gating job) and CodeQL, with branches kept up to date before merging; a daily audit of the
live ruleset by a read-only GitHub App; a reproducible `kernel.elf`; CodeQL, Semgrep, Trivy,
gitleaks and cargo-audit, the last two failing the build on a finding; a CycloneDX SBOM per run;
Dependabot on actions and Cargo; secret scanning with push protection; fuzzing at the FFI
boundary; bounded Kani proofs and Miri on every pull request.

**Known gaps:**

- **No review before merge** (**[C-5]**): the ruleset requires no approving review, and merges are
  made by Claude once the gates are green. A pull request from outside the project is not merged
  that way; it waits for the maintainer.
- **No build provenance or signed artifacts** (**[I-9]**), and the ISO is not byte-reproducible
  (`docs/LIMITATIONS.md` 5.3, 5.3a).
- **Workflows GitHub injects are invisible to the tree's checks** (`docs/LIMITATIONS.md` 5.7).

---

## Supported versions

There is one release, `v0.2.0-alpha` (2026-09-14), an install ISO for developers. Security fixes
land on `main` only; there are no backports. Anyone using Horus for research should track `main`
and rebuild.

---

## Hardening the build

- Ship the default flags. `DEBUG_SHELL=1` adds an in-kernel debug shell and extra syscall surface,
  and the `*_SELFTEST` builds add test-only syscalls; none of them is a shipping configuration.
  Every boot prints `DEFECT FLAGS:`, which must read `none` for a build you trust.
- `MEASURED_BOOT_REQUIRED=1` makes measured boot mandatory: the kernel halts without it and
  refuses a disk that was never sealed (`docs/LIMITATIONS.md` 2.9).
- Check reproducibility before trusting a kernel: run `make reproducible-build` twice and compare
  the `kernel.elf` line of `.build.sha`. The `horus.iso` line differs between runs, as expected.
- For measured boot, compute the expected PCR values with `tools/tpm_expected_pcr.py` and compare
  them with the running system.
