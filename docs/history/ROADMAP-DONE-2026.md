# Roadmap items delivered in 2026

Every roadmap item, or part of one, that was finished, one line each with the pull requests that
delivered it. [`../ROADMAP.md`](../ROADMAP.md) holds only open work since 2026-10-12; an item's
number is never reused, so a citation of a finished item in the code resolves here. A number that
appears both here and in the roadmap is an item whose own goal was met with a remainder still
open. The account of each is in its pull requests.

## Track 0: make the object model true

| Item | Delivered |
|---|---|
| 0.1 Capability-addressed IPC [C-1], [C-2] | Every IPC syscall takes a cspace slot and the kernel derives the endpoint from the capability there. 2026-07-27, #108 |
| 0.2 Retire ambient `uid == 0` authority [I-1] | Every uid gate replaced by a held capability. 2026-07-27, #109; the last gate 2026-08-15, #155 |
| 0.3 Kernel objects from untyped memory [I-7] | `CAP_UNTYPED` and `SYS_RETYPE` carve cspaces, endpoints, notifications, frames and task control blocks; creating a task is paid for (S57) and the budget can be split (S58). 2026-07-27, #111; completed 2026-08-30, #253, #257 |

## Track 1: correctness and performance foundations

| Item | Delivered |
|---|---|
| 1.1 Explicit boot interrupt policy, then a per-CPU spinlock [C-3] | 2026-08-10 to 2026-08-13, #124 to #127, #135 |
| 1.2 `%gs`-based per-CPU data [I-6], the performance goal | `this_cpu()` reads the TSS selector instead of the LAPIC. 2026-07-31, #116. The `%gs` block itself is still open |
| 1.3 Endpoint queues, reply capabilities, a blocking receive [I-5] | 2026-08-10 to 2026-08-11, #120, #121, #133 |
| 1.4 Fail-closed user copies [C-4] | 2026-08-13, #141 |
| 1.5 64-bit-clean heap arithmetic [I-2] | 2026-08-13, #145 |
| 1.55 A durable write-ahead journal [I-10], [I-11] | 2026-08-16, #158, #161 |
| 1.6 Unbounded revocation closure [I-3] | 2026-08-16, #160 |
| 1.7 Serialise the spawn and exec path [G-10], [G-9] | 2026-08-17 to 2026-08-21, #164, #168, #170, #188 |
| 1.8 Per-CPU scheduling, steps 0, 1, 1b and 2a | LIMITATIONS 5.3e settled (#526), the shootdown wait fails closed (#523), SMT siblings refuse work (#525), one selection rule for every switch path (#524). 2026-10-09 |

## Track 2: toward a complete operating system

| Item | Delivered |
|---|---|
| 2.1 Frames, shared memory and sized regions [F-2.1] | Frame capabilities, all-or-nothing region maps, sized frames, and copy-on-write refused over a frame (S26, S27, S35 to S38). 2026-08-22 to 2026-08-27 |
| 2.2 Time and timers [F-2.6], the monotonic clock | A monotonic clock at 10 ms, deliberately coarse (S34). 2026-08-24, #208 |
| 2.3 Process and session model [F-2.4], `fork` | `fork` with copy-on-write (S39, S40), derived capabilities for the child (S41), and `fork` then `exec` keeping lineage (S42). 2026-08-28 |
| 2.4 A VFS layer [F-2.2], the walker | A per-task mount table and one path walker in a library, not a server (S29); `init` provisions a server's endpoint from its own budget (S59). 2026-08-22 to 2026-08-30 |
| 2.5 Dynamic linking and a shared libc [F-2.5] | `libhorus` for the servers (#184); a shared libc handed out by capability, linked by name and sealed, and the shipped programs moved onto it (S106 to S108). 2026-08-21 to 2026-09-26, #465, #467, #468, #470 |
| 2.6 A network stack in ring 3 [F-2.3], the driver | `netd`, an Intel NIC driver holding one device capability and one untyped region, confined by the IOMMU (S44, S45). 2026-08-28, #227, #228 |
| 2.7 Device drivers in ring 3, the model | A device capability names one device and reaches only its frames, ports and interrupt lines (S43); interrupts and MSI reach ring 3 with the kernel choosing the vector (S46 to S48). 2026-08-28 to 2026-08-29, #226, #232 |
| 2.8 A volume large enough to install onto | 4 KiB blocks, no in-RAM metadata mirror, a Merkle rollback tree, a 16 GiB ceiling sized from the disk (S65, S66, S68), and a TPM anchor for whole-volume rollback (S70). 2026-08-31 to 2026-09-01, #270, #273, #274, #276, #279 |
| 2.9 An installer | A format capability only the installer holds (S72), consent by a typed word after every answer is shown back (S73), a choice of target disk (S82, S83), replacing an existing volume from install media (S90), two accounts that each open the disk (S76), and an optional unencrypted volume (S104). 2026-09-01 to 2026-09-24 |
| 2.10 A capability-addressed filesystem, phase 1a and phase 1b steps 1, 2, 3(a), 3(b), 4 and 5 | Endpoint tokens and reply-mint in the kernel (S105, #455); `fs_server` answers through tokened capabilities (S120, #515); cross-directory `rename` and `link` refused `EXDEV` (S121, #516); clients walk with capabilities and hand children narrowed copies (S126, S127, #529 to #532); sessions compiled from the policy (S128, #534) and a private `/tmp` (#536); the truthful `stat`, `chmod`, `chown` and same-directory `link` (S130 to S132, #538, #543, #544); each login's session asked for by `init` as the attested account, with a watcher reaping the shell (S140, S141, #573). 2026-09-25 to 2026-10-14 |
| 2.11 An installed system, steps 1 and 2 | A live boot never opens an installed disk (S110, #472); the disk boots itself under UEFI, the laptop's eMMC included (S114, S115, #503, #505); its programs are on it, in system trees rebuilt from the verified modules at every boot and read-only to everyone (S116, #506). 2026-09-26 to 2026-10-08 |
| 2.12 Encrypted swap | A sealed slot store under a per-boot key with the tags in RAM (S118, #510), paging out under pressure (S119, #512), and idle tasks giving memory back under the pager's hold (S123, #518). Compressed memory deferred on 2026-10-08. 2026-10-08 to 2026-10-09 |

## Track 3: assurance and observability

| Item | Delivered |
|---|---|
| 3.1 Reproducible builds | `kernel.elf` byte-reproducible and gated; then the ISOs, `horus.iso` and the release's `install.iso`, built in two directories at two times and compared on every pull request (S17, `smoke-repro-iso`). 2026-10-12, #557 |
| 3.2 Measured boot and a sealed volume key | TPM PCR measurement, a key sealed to the measurements (S11, S12), the kernel pinned in the boot image (S92), and a policy build that refuses to run unmeasured (S85) |
| 3.3 Boot-module integrity manifest | A module that fails its hash check cannot be read or run (S10) |
| 3.4 Kani proofs on revocation | Revocation reaches exactly the target's derivation subtree |
| 3.5 Proofs over the capability algebra [F-3.1], lookup and grant | Lookup and grant proved, and the bounded proofs gate a merge (`kani-bounded`). 2026-08-23, #205 |
| 3.6 A debug capability [F-3.2] | `CAP_DEBUG`, read-only, gates cross-task introspection and `SYS_CAP_ENUMERATE`; the shell's `capview` draws the capability graph (S32). 2026-08-23 to 2026-08-24, #206, #209 |
| 3.8 KASLR, CFI and sanitisers [F-3.5], Miri | Miri over the Rust core on every pull request (S33). 2026-08-24, #207 |

## Track 4: repository, governance and secure development

| Item | Delivered |
|---|---|
| 4.2 Gate the security tests [C-6] | Every job is classified as gating or exempt with a written reason in `.github/ci-gating.yml`; the ruleset requires the `gates` aggregator and CodeQL, and `gates` needs every gating job. 2026-08-16 to 2026-09-21, #159, #165, #415 |
| 4.3 `gitleaks` and `cargo-audit` fail the build | 2026-08-30 |
| 4.5 Tagged releases, the first four | `v0.2.0-alpha` (2026-09-14), `v0.3.0-alpha` (2026-10-09), `v0.4.0-alpha` and `v0.4.1-alpha` (2026-10-12), each an install ISO and its SHA-256; from `v0.4.1-alpha` the ISO rebuilds to the same bytes from its tag |
| 4.6 `horus.py` under `tools/` [M-2] | 2026-09-09 |
| 4.7 Governance files [M-3] | 2026-07-27, #107 |
| 4.9 One author identity [M-9] | 2026-08-29, #241 |
| 4.10 Third-party material declared | `THIRD_PARTY.md`, 2026-09-08 |
| 4.12 A security-invariant registry [F-4.1] | `tools/check_invariants.py` binds every `SECURITY.md` property to a witness that runs. 2026-08-28 |
| 4.14 Nightly fuzzing and full Kani | Every Kani proof gates every pull request (#485); each proof's recorded mutation is replayed nightly to show it still fails (#493); every fuzz target runs nightly for ten minutes and a crash fails the run (#492). 2026-10-06 |

## Track 5: closing the known limitations

| Item | Delivered |
|---|---|
| 5.3 Kernel reports off the shared console (LIMITATIONS 2.6c, 2.30) | The kernel keeps a whole copy of everything it prints on COM4, a port no capability names (S144), and every gate that waits for a kernel marker reads it there, or COM3 for a diagnostic report, or is listed with its reason in `.github/kernel-markers.yml`, which `tools/check_kernel_markers.py` enforces; the console changes hands under the console lock, so only between lines (S145). 2026-10-14, #576 |
| 5.2 Authenticated metadata on the current format (LIMITATIONS 1.30, D2) | The inode bitmap, block bitmap and inode table are leaves of the Merkle tree, checked in the block layer on every read and carried to the root on every write, and sealed with the block AEAD; indirect pointer blocks are sealed too; the root binds the superblock's layout and flags. Format v14: an older volume is refused with a message. Three findings of the same kind closed with it (LIMITATIONS 1.35, 1.36, 1.37), and the delete that overflowed the journal (2.29) (S143). 2026-10-14, #575 |
| 5.1 Revocable pipe ends (LIMITATIONS 1.14) | A spawned child's stdio end is derived from the spawner's, `SYS_PIPE`'s ends carry `REVOKE`, and a revoke releases the ends it removed from the pipe table under `cap_lock` (S134). 2026-10-13, #558 |
| 2.26 `rotate_keys` withdrawn (LIMITATIONS 2.26, D14) | It changed no key; the shell command is gone and `SYS_ROTATE_KEYS` answers `SYS_ERR_NOSYS` to everyone. Real rotation of the volume key comes with filesystem phase 2. 2026-10-14, #572 |
| 5.13 A pipe end that cannot outlive its pipe | A pipe end's object carries its pipe slot's generation beside the index, and every pipe operation (I/O, count, release, the revocation tally's release) compares it under `pipe_lock`, so an end left over from a freed pipe reaches nothing, not the next pipe to take the slot (S139). 2026-10-14, #571 |
| 5.12 Secondary CPUs waited for by the clock (LIMITATIONS 2.28) | `smp_start_aps` waits 2 s of the calibrated TSC instead of 200 `pause` loops, the INIT and SIPI settle times are the specification's in wall time, and bring-up then closes, so a CPU that checks in later is parked with interrupts off, never counted and never run (S138). 2026-10-13, #565 |
| 5.5 Console input as a capability (LIMITATIONS 2.9b, and 1.6) | Keyboard input is the console endpoint tokened `CON_TOKEN_INPUT`, minted by `init` alone and lent by the shell to the foreground program until it has been waited for (S93); the kernel's `SYS_WRITE` fd 1, `SYS_READ` fd 0 and `SYS_GET_PASS` ask for the console's capabilities (S135). Decision D6 was answered with both halves, writes included. 2026-10-13, #559 |
