# Changelog

Notable changes to Horus, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project intends to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it has a public ABI to break.

Each entry says what changed in one sentence and names the pull request that made the change;
the reasoning, the measurements and what was tried first are in that pull request. The longer
record is [`docs/history/DEVLOG-2026.md`](docs/history/DEVLOG-2026.md): 142 entries recording what was
tried, what failed, and how each measurement was taken. Every entry written up to 2026-10-07 is
kept in full in [`docs/history/CHANGES-2026.md`](docs/history/CHANGES-2026.md). The current
status of any finding an entry names is in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md), never
here.

## [Unreleased]

### Security

- No task runs in ring 3 on page tables other than its own (S156). Every return to ring 3 now checks that the loaded CR3 is the returning task's; on a mismatch, which is a kernel defect, the task's own tables are loaded and COM3 records it, and a `SCHED_INVARIANTS` build halts. The fork refusal fixed in #596 had returned a task on the kernel's tables, where it only died; the same slip with another task's tables would have run one task's code in another's memory. `make smoke-cr3-return` puts that slip back and shows it repaired. (#598)
- A task could come to map another task's frame (LIMITATIONS 1.41, HORUS-20261017-01, S151). `SYS_RETYPE` made an object, released the untyped lock and only then installed the capability naming it, while a revoke on another CPU ran the object collector in between; the collector freed the unnamed object's index, and the capability then named whatever the next retype, by any task, put there. Objects are now born pinned and collectable only once named, and the collector always holds `cap_lock`, which task teardown did not take. `make smoke-retype-race` holds every retype's window open while another CPU revokes; its arm, with objects born unpinned, loses the first frame it retypes (#591).
- Priorities are capped by authority (ROADMAP 1.8 step 4b, S154, S155, `docs/design/scheduler.md` §3.2). Among the budgeted work a CPU may run, the higher priority runs, 0 to 255, round robin within a level, and the task a CPU is running keeps it over anything it outranks and over slack work, so budgeted work no longer gives way to slack work waiting on its CPU. `SYS_SCHED_SET_PRIORITY` needs a `CAP_TCB` with the new `CAP_RIGHT_PRIORITY` and refuses a priority or maximum above the caller's own maximum; `SYS_SCHED_GET_PRIORITY` reads both. A child starts at its creator's priority and maximum and every shipped task is at 255, so nothing is scheduled differently yet. `make smoke-captest` checks the refusals and `make smoke-sched-budget` that a task at 100 does not run beside one at 255 that yields; each has an arm that puts the defect back (#594).
- CPU time is a capability (ROADMAP 1.8 step 4a, S152, S153, `docs/design/scheduler.md` §3.1). A task runs only on the time a scheduling context it is bound to grants: `SYS_SCHED_SPLIT` carves a budget every period out of a context its caller holds, its memory from the caller's untyped region, and never makes time (a Kani proof); `SYS_SCHED_BIND` binds a task its caller holds a `CAP_TCB` to; revoking a context gives its time back and stops the tasks bound to it. Time is measured with the TSC and charged by the context's own CPU, including time in system calls, so a task cannot run for nothing by yielding before each tick; a task out of budget is switched away and its CPU idles. `init` holds the per-CPU roots and every task runs on the BSP's root, so nothing in the shipped system has a smaller budget yet. `make smoke-sched-budget` binds a spinner to a fifth of an AP and it sees 30% of the ticks (it counts the distinct 10 ms ticks it ran in, and a 20 ms burst touches three); its arm, with budgets never enforced, sees all of them (#592).
- A spawned child could run before its supervisor had given it anything (LIMITATIONS 1.40, S150). Spawn built the child's first frame with the routine that also publishes it, and took it back a line later; a CPU choosing in that moment ran the child with an empty cspace. On two CPUs `smoke-installer-sd-smp` failed 3 boots in 50 this way: the shell's watcher ran, found nothing granted and exited, so no login got a filesystem session. The frame is now built without being published. `make smoke-spawn-window` holds every spawn open for three ticks and checks that no CPU chooses a child still being built; its arm restores the old order (#586).
- The filesystem no longer decides anything by who is asking (phase 1b step 6, LIMITATIONS 1.31 closed, S14, S77). `fs_server` checked any request that came without a file capability against the sender's user id and a file's stored mode, with uid 0 passing everything, and any task could get such a channel by asking (`SYS_CONNECT_FS_SERVER`); a file inside another account's private directory answered to anyone who named its inode number. Now every request is decided by the capability it came through, the connect, register and set-owner-and-mode calls answer nobody, nothing stores a mode or owner, a stat names the session's account, and a login the policy gives nothing is ended with the reason instead of being let in with no files. `make smoke-fs-perms` and five new arms, in place of the four the uid path took with it (#583).
- A standard account gets the bare minimum, and administration belongs to the administrator's session. The shell held `CAP_USER`, the kernel log, `CAP_DEBUG` and the object store's capability for the whole boot, and only its own uid check kept a standard account from them; now `init` lends the first three to the shell when root logs in and takes them back at logout, and the kernel's capability test is what refuses `dmesg`, `capview`, `ps` of other tasks, `useradd`, `userdel` and `passwd <uid>` to anyone else. `sudo` and `SYS_SUDO` are withdrawn: administration is a login as the administrator. The demonstration commands (`spawn`, `fss*`, `ipc_send`, `ipc_recv`, `notify`, `wait_notify`, `mem`, `yield`) are built only into a `DEBUG_SHELL=1` shell (S149, LIMITATIONS 1.39). `make smoke-session-admin-caps` and two arms (#582).
- A login could hold the previous login's filesystem. The shell lent the keyboard to a program from the same slot as its capability for asking `init` for sessions, so the first program a login ran destroyed that capability: logging out ended nothing, and the next login on that console got no session of its own and walked by the previous one's root, so a standard user after root could read and write as root (LIMITATIONS 1.38, S147; on `main` since #573). The slot is moved, two fixed slots sharing a number no longer compile, and the shell drops its root and working directory at logout and uses them only while a session is open. `make smoke-session-handover` and two arms (#579).
- A new installed system gives every account a filesystem session from its first login (phase 1b step 3(c), S148). Until now an installed volume had no `/etc/fs.policy`, so only the administrator got one and everyone else reached files by user id and mode. `fs_server` now writes the policy when it first provisions a volume that has no `/etc`: the live default, and read on `/etc/shell.conf` and `/etc/login.conf` for every account. It never writes it again, so a policy the administrator deletes leaves the administrator alone rather than coming back. Two defects found on the way are fixed: a grant on a file alone (`@all /etc/shell.conf read`) could not be reached, because the directory above it carried only `read` and so could not be walked through; and the shell's `cat` showed only the first 176 bytes of a file. `make smoke-installer-policy` and three arms (#581).
- The capability type test every gate depends on moved from C into the Rust resolver, `rust_cap_lookup_typed`, with a Kani proof that it returns only a live capability of the requested type and rights; IPC authority is resolved in Rust and proved to come from a held capability naming exactly the object used; and the four capability exports that had no proof (`rust_cap_alloc_serial`, `rust_cap_transfer`, `rust_cap_grant_from_user`, `rust_cap_revoke`) have one (ROADMAP 3.5, S60, S13a). Six proofs, six arms, and `tools/check_kani_ffi.py`, which refuses a capability export no proof calls (#578).
- A killed task has stopped by the time the kill returns. Killing a task running on another CPU sent it an interrupt and returned at once, and until that CPU took the interrupt the dead task went on running, writing any memory it shared with live tasks. On bare metal that is microseconds; under a hypervisor that relays the interrupt it was milliseconds, enough to fail CI's killed-task check 2 times in 31. Teardown now waits until no other CPU is running the task (S56, LIMITATIONS 2.32). `make smoke-killed-task-late` withholds the interrupt altogether and still passes; without the wait it fails. (#580)
- On two CPUs, an install could write a volume that failed its own checks on the next boot: the correct password was refused, or the shell found its directory gone. The installer's last writes and `fs_server` provisioning `/bin` ran through the storage layer at the same time, and its journal and caches have one copy each. Every storage call is now one operation at a time, and the block reads and writes refuse to run outside one; two password hashes no longer share the Argon2 scratch buffer at once either (S146, LIMITATIONS 2.31). `make smoke-storage-smp` runs two CPUs through both at once; without the lock nearly every write and read-back in that test fails, and hundreds of metadata spans are refused. (#577)
- The kernel keeps a whole copy of everything it prints on COM4, a port no capability names, and every gate that waits for a kernel marker now reads it there (or on COM3, for a diagnostic report) instead of off the console ring 3 also writes, where it could arrive split (LIMITATIONS 2.6c closed, ROADMAP 5.3, S144). 131 gate invocations moved; `tools/check_kernel_markers.py` fails a gate that reads a kernel marker off the console without a listed reason. The console now changes hands under the console lock, so a kernel line being written when `console_server` takes it over finishes first (2.30 closed, S145). `make smoke-kcon`, `make smoke-kcon-ioport`, `make smoke-console-handover-lines` and three arms (#576).
- The inode table, the allocation bitmaps and every indirect pointer block are now sealed and authenticated at rest, and the superblock's layout is authenticated (LIMITATIONS 1.30 and 1.35 closed, ROADMAP 5.2, decision D2, S143). An owner, mode, size, bitmap bit or pointer edited on the disk was served as the volume's own, and every file's size, owner and mode could be read off it; each edit is now refused at first use and none of it is readable, and moving the inode table or clearing `rollback_anchored` on a restored image (which skipped the TPM counter check) fails at unlock. Two findings of the same kind are closed with it (1.36, 1.37). **Format v14: an installed volume of an older format is refused with a message and must be reinstalled.** `make smoke-meta-span`, `make smoke-rollback-anchor-flag` and five arms (#575).
- Deleting a file whose blocks lie in more bitmap blocks than one journal transaction holds (several GiB) failed with an I/O error and finished at the next unlock's fsck; the free is now committed in batches (LIMITATIONS 2.29). `make smoke-fs-free-batch` and its arm (#575).
- Every implemented syscall's handler is now entered by a tracked workload (LIMITATIONS 1.8 closed, S25). `formatprobe`, a probe task holding one `CAP_STORAGE_FORMAT`, enters the survey and format handlers, and every call it makes is refused inside the handler before anything is written; `captest` enters `SYS_CONSOLE_RELEASE` through three slots that hold no device authority. A format password longer than a login can type back is refused rather than shortened, now witnessed by `make smoke-formatprobe` with a control arm (S142). (#574)
- Each login now works in its own filesystem session (phase 1b step 3(b)). After a login the shell asks `init` for it; `init` names the account by the uid the kernel attests, never by the request, and grants the shell the root and working directory `fs_server` opens for that account's policy, so a standard user sees only what the policy grants (on a live boot `/bin`, `/lib`, `/usr`, a home and a private `/tmp`) and starts in the home, and `pwd` says so. At logout, or when the shell dies, `init` revokes the session and ends it. A shell holding a session never falls back to the uid path (S141). Through a session `chmod` and `chown` say that what they asked already holds and that nothing changed, or are refused (S131). The uid path's metadata rules and home ownership (S77, S78) are now witnessed by `make smoke-fs-perms` and three arms until that path goes. (#573)
- `init` no longer blocks waiting on the shell: a watcher task holding a copy of `init`'s capability to the shell narrowed to READ waits for it and reports its death to `init`. A spawner's `CAP_TCB` now carries MINT (decision D1) so it can hand on less than it holds; a mint only narrows (S2). `make smoke-shellwatch` ends the shell twice and checks the watcher can wait and do nothing else (S140), with a control arm. (#573)
- `rotate_keys` is withdrawn (decision D14, LIMITATIONS 2.26): it re-sealed a few blocks of the caller's files under the same key and changed no key, whatever its name said. The shell command and its man page are gone, and `SYS_ROTATE_KEYS` stays reserved, answering `SYS_ERR_NOSYS` to every caller, which `captest` checks. Real rotation of the volume key comes with filesystem phase 2. (#572)
- A pipe end named its pipe by slot index alone, so an end left over from a freed pipe, if S134's counts were ever wrong, would reach the next pipe to take the slot. A pipe end now names one use of its slot (the index and the slot's generation), and every pipe operation, the revocation tally's release included, compares the generation under `pipe_lock`; a leftover end reaches nothing (S139, ROADMAP 5.13). `make smoke-pipe` frees a pipe under a live end on purpose and checks the end misses the next pipe four ways, with a control arm. (#571)
- A workflow GitHub injects into the repository, with no file in the tree, went unnoticed by every check: one ran from 2026-09-19 to 2026-09-20 (LIMITATIONS 5.7). The scheduled `ruleset-audit` now fails on any workflow GitHub runs that is neither in `.github/workflows/` nor recorded with its reason in `.github/injected-workflows.yml`, and on a workflow recorded as stopped running again (`tools/check_injected_workflows.py`, with a falsification harness of ten arms). (#567)
- A driver whose device has a register BAR smaller than a page was handed the whole page, so a neighbour's registers that firmware put in the same page were within its reach (LIMITATIONS 1.34). `SYS_MAP_PHYS` now checks the page it maps: one that another device declares any part of, or that lies in the chipset window, is refused. `make smoke-devpage` witnesses it against a table with the neighbours QEMU never makes, with a control arm. (#562)
- The pipe end a spawned child is given for its stdin or stdout was a root of the capability graph, so revoking the spawner's end did not reach it, and no pipe end could be revoked at all. `SYS_PIPE`'s two ends now carry `REVOKE`, the child's end is derived from the spawner's (with `READ` or `WRITE` alone), and a revoke takes the ends it removed out of the pipe's counts before it returns, so the peer sees EOF or EPIPE at once. A pipe read or write now finds its end and moves the bytes under one lock, so a revoke cannot free the pipe between the two (S3, S134; LIMITATIONS 1.14). (#558)
- Any program a person ran could read the command lines they typed afterwards, and the console's password owner was a task id. Keyboard input is now a capability: `init` mints it, the shell lends a copy to the program it runs in the foreground and takes it back when that program ends, and `console_server` serves input through nothing else (S93; LIMITATIONS 2.9b). The kernel's own console paths, `SYS_WRITE` to fd 1, `SYS_READ` from fd 0 and `SYS_GET_PASS`, asked for no capability, so any task could draw on or read the console whenever no console server owned it; they now ask for the console's capabilities (S135; LIMITATIONS 1.6). (#559)
- A new limitation is recorded: a revocation cannot reach a copy derived through a task that has died, so a program still running when its shell dies keeps the keyboard it was lent (LIMITATIONS 1.33). (#559)
- A new limitation is recorded: a device whose register BAR is smaller than a page hands its driver the whole page, so firmware that put another device's registers in it would let the driver reach them (LIMITATIONS 1.34). It is closed before the ring-3 SD/eMMC driver serves a real disk. (#561)

### Added

- A budget ends when it runs out, not at the next 10 ms tick (ROADMAP 1.8 step 3b, S153, `docs/design/scheduler.md` §3.4): at every choice a CPU arms its LAPIC timer for the moment the chosen task's budget is spent, so a task given 1 ms every 100 ms runs a millisecond in every period instead of ten in one period of ten. (#595)
- The TSC-deadline timer, the TSC clock and refills (ROADMAP 1.8 step 3c, S153, S34, `docs/design/scheduler.md` §3.4). Where the CPU offers the TSC-deadline mode and an invariant TSC, every CPU's timer is armed with the TSC value it is to fire at, and the clock is derived from the TSC, so it no longer falls behind while the BSP holds interrupts off; elsewhere the LAPIC count and the PIT stay. A CPU also arms its timer for a refill that lets a more urgent task run, so a task given 9 ms every 10 on an otherwise idle CPU runs nine tenths of the time instead of half, and on a machine with one CPU a budget now ends when it runs out. Two charging faults found on the way are fixed: a run across its period's end was charged wholly to the period it began in, so a task could take up to twice its budget in the next, and a CPU judged the task it was running before charging it, so a task whose budget had just ended kept its CPU over lower priorities until the next interrupt. The KVM CI job now gives its guests both CPU features. (#596)
- The IDE driver runs in ring 3 as `atad`, holding one device capability: it moves data by PIO with I/O decode and no bus mastering, identifies the primary master, reads, and writes only a disk carrying the test signature, and serves the block-driver protocol. The controller's legacy ports are declared for ring 3 only in its self-test build, which also turns the ring-0 probe off, so no task can be granted them while `ata.c` drives the controller (S137). `make smoke-atad` checks the write and the capacity on the host and has three control arms; `make smoke-devcap` checks the controller's capability declares no ATA port, with an arm that declares them; `make smoke-blkproto` now runs through all three drivers. (#564)
- The ring-3 storage drivers serve a block-driver protocol (`include/blkproto.h`), its server half written once and linked into `sdhcid` and `nvmed`. A supervisor binds each client's token to an extent of the disk and a frame of its own; a client's sectors are relative to its extent and cannot leave it, a token nobody bound reaches nothing, and only the supervisor binds (S136). `make smoke-blkproto` runs it through both drivers, checks where the write landed on the host, and has four control arms. Nothing consumes it yet; filesystem phase 2 will. (#563)
- The SD/eMMC driver runs in ring 3 as `sdhcid`, the first step of taking the storage drivers out of the kernel (`docs/design/ring3-storage.md`). Its whole authority is one device capability: it moves data by PIO, so it holds no memory to give its controller and never enables bus mastering. It brings up an SD card or eMMC device, reads, and writes only a card whose block 0 carries the test signature, in the `SDHCID_SELFTEST` build; the kernel's storage still uses `sdhci.c`. `make smoke-sdhcid` checks two cards in the guest, on the image and against the image's size, with three control arms. The route is decided: the kernel keeps the keys and stops doing disk I/O, so the drivers leave ring 0 with filesystem phase 2. (#561)
- An NVMe driver, `nvmed`, runs in ring 3 holding one device capability and one untyped region, confined by the IOMMU: it identifies the controller and its namespace, reads, writes and flushes, polling, and never writes a disk whose block 0 lacks the test signature. It runs in the `NVME_SELFTEST` build; the kernel's storage cannot read through it yet, so nothing installs onto NVMe (ROADMAP 2.7). `make smoke-nvme` checks the write on the host as well as in the guest, with two control arms. (#560)
- `make smoke-console-pass` now witnesses both halves: input refused to a client's stdout capability, an input capability lent to a child and gone once taken back, and the kernel's console reads and writes refused without a capability, with four control arms. `captest` asks `SYS_READ` fd 0 and `SYS_GET_PASS` without a capability, so `SYS_GET_PASS` is covered for the first time. (#559)
- `make smoke-pipe-revoke-child` spawns stages wired to pipe ends, revokes the ends and checks the stages lost theirs, a forked child's revoke spared the original, and no pipe was left allocated; two control arms (the child's end as a root, the removed ends left counted) run beside it in the `smoke-pipe` CI job. A Kani proof shows a revoke counts exactly the pipe ends it removes, with four arms. (#558)

### Changed

- Seven of the roadmap's open decisions are answered, each as the roadmap recommended (D3, D4, D5, D7, D10, D13 and D15), so measured boot by default, rollback anchoring, kernel updates without a lockout, exec only from a file capability, signed releases with provenance, secrets kept out of swap and CI throughput (new item 4.15) no longer wait on anything. (#589)
- A frame is refused only when its untyped region runs out (roadmap 2.1). The kernel could name 256 frames at once, a quarter of what the user half of the arena holds, so a program carving small frames was refused with most of its budget unspent by a limit no capability stated. The table is now as large as the arena has pages (1,664). `make smoke-frame-budget` carves frames until each half of the arena refuses and checks the table never did; its arm puts the 256 back (#588).
- An idle CPU no longer takes a hundred timer interrupts a second (ROADMAP 1.8 step 3a, `docs/design/scheduler.md` §3.4). Each AP's timer is one-shot and re-armed only while the AP has a task; an idle AP takes its last tick and stops, and every tick on any CPU ends by waking as many stopped APs as there are tasks waiting, so a task still gets a CPU within a tick. One AP keeps ticking, so a waiting task never depends on the boot CPU, which can spend seconds in the kernel with interrupts masked. At the login prompt on eight CPUs the APs took about 3400 ticks in five seconds and now take 488, the watcher's alone. `make smoke-tickless` and two arms (#585).
- Each CPU now keeps its own list of the tasks homed on it and chooses from that first, instead of every CPU scanning one shared table of every task (ROADMAP 1.8 step 2, `docs/design/scheduler.md` §3.5). A task is homed on the CPU that created it and moves when another CPU, with nothing of its own to run, takes it; the tasks waiting on a CPU stuck in a long kernel operation go to the others after two ticks. What may run is decided exactly as before, and a wake touches no list, so no wake can leave a task where no CPU looks. `SCHED_INVARIANTS=1` checks that every live task is on exactly one list; `smoke-runq-unhomed-control` and `smoke-smp-nosteal-control` are its arms (#584).

### Fixed

- Every build that carries more than the shipped kernel now says so at boot. `DEFECT FLAGS:` named only the flags in the defect-flag table, so 97 other build switches (every `*_SELFTEST`, `SCHED_INVARIANTS`, `HANG_WATCHDOG`, `DEBUG_SHELL` among them) built kernels that announced `none`; it now names every switch the build was asked for except those a shipped image uses, and `make smoke-defect-flags-instrument` checks it. A control arm's expected fault is now read from the kernel's own channel (COM3 or COM4) wherever the kernel writes it, so it can be neither split nor printed by another task, and `tools/check_kernel_markers.py` requires that of every arm. `make smoke-killed-task` and its relatives now fail on any write after `SYS_KILL` returns, as S56 states, rather than on one after a grace, which also made their control arm miss under load. The shortest budget period stays 10 ms, on purpose: a refill interrupt is charged to no budget. (#597)
- A fork refused because the caller's untyped region was spent returned to ring 3 with the kernel's page tables still loaded, so the caller was killed by its next instruction fetch ("the pager could not resolve an approved fault (code -2)"); the refusal now puts the caller's own page tables back, as every other refusal on that path did. Found by CI's KVM job, which `make smoke-captest` now witnesses deterministically. A page fault the pager cannot resolve is now reported in full on the kernel's diagnostic port, COM3, and a failed gate prints COM3. (#596)
- Two control arms went red on changes they do not measure. `smoke-defer-exemption-control` held its race window open with a spin count, which on a newer CI runner image no longer spanned two claim audits, and went 0 of 46; it now holds the window until audits have run, and hit on 20 boots of 20. `smoke-console-handover-lines` and its arm gave up after 3 inconclusive boots, about one CI run in 80 at CI's measured rate; they now allow 8. (#593)

- The boot harness could score a previous boot's lines as the current one's: QEMU truncates its log only when it opens it, after the harness has begun polling, so a log kept at a fixed path still held the last boot's output for that moment, and a planted `PANIC:` line made a clean boot fail. `tools/smoke_test.sh` now empties its three logs before QEMU starts (#591).
- A tree that had run `smoke-repro-iso-path-control` built every later image with that arm's libc, which carries its build directory, so `smoke-repro-iso` went red there on a library it never asked for. The newlib build is now asked on every `make` whether its stamp still matches the settings, and rebuilds when it does not; when it does, it leaves `libc.a` untouched, so nothing relinks (#587).
- `smoke-installer-provision-control`, the S74 arm, reproduced its defect in 1 run of 6 and turned main red on a run where the defect had fired: boot 1's copy of the base system often finishes before the power-off, leaving boot 2 nothing to break. The arm now requires the defect's own mark, the startup copy against the locked store writing 0 inodes, and only reports the `/bin` listing. Measured: 8 runs in 8. (#570)
- The shell's `passwd` said only `passwd failed` for any of eight failures, the ninth account's full key slots among them (LIMITATIONS 2.6b). It now names the step, in the same words as the installer, from one table in `libhorus` (`passwd_reason`). (#569)
- `netd`'s receive ring had 256 descriptors and 8 buffers, and recycling advanced its tail one descriptor per frame, so from the ninth frame of the boot the device was handed descriptors whose buffer address was 0: the frame went to bus address 0 (refused by the IOMMU where there is one) and the driver never read it. The ring is now exactly as long as its buffers and is read in order from a cursor. `make smoke-net` now makes eighteen ARP exchanges, wrapping the ring twice, with a control arm that puts the old ring back and loses every reply after the eighth. It does not settle LIMITATIONS 2.14, which stays open. (#568)
- The boot waited for the secondary CPUs for a count of `pause` instructions, a few milliseconds on a fast host under KVM, so a CPU the host scheduled late went uncounted and then ran tasks anyway, and could acknowledge a TLB shootdown it was not counted for (LIMITATIONS 2.28). The wait is now 2 s of the calibrated clock, the INIT and SIPI settle times are the specification's in wall time, and bring-up then closes: a CPU that checks in later is parked, never counted and never run (S138). `make smoke-smp-ap-late` (under KVM) and `make smoke-smp-ap-closed` witness each half, each with a control arm. (#565)
- A tree that had built newlib once never re-ran its build script, so a changed script never reached the libc: a release build in an older worktree kept the build path #557 maps away. The script is now a prerequisite of the library. (#558)

## [0.4.1-alpha]: 2026-10-12

**The install ISO rebuilds to the same bytes from its tag.** A release can now be checked by
building it again: `make install.iso` from a checkout of the tag, with the tool versions the
release lists, gives the ISO published beside the checksum, byte for byte, whatever directory it
is built in and whenever. Install media for
x86-64, built for a UK/ISO keyboard, published as an alpha for developers.

### Security

- A kernel built after an install build in the same tree kept the install build's boot-module manifest, so it pinned, and would accept, the coreutils it did not ship: the manifest was regenerated when a module changed but not when the list of modules did, and `make clean` left it. It is now regenerated on every build and removed by `clean`. Every hash it held was of a binary this project built. (#557)

### Added

- `make smoke-repro-iso` builds `kernel.elf`, the gates' `horus.iso` and the release's `install.iso` in the tree and again in a git worktree at another path, later and in parallel, and requires the same bytes; a difference names the files inside the ISO and keeps both copies. Two control arms, one per leak, run in a new CI job beside it. (#557)

### Fixed

- The install ISO differed with the directory and the time it was built in: newlib carried its build path into the shared libc (and so into the kernel that pins it), the EFI boot image took its FAT serial from the clock, the ISO's directory records took the build's time, and both FAT images ended in a sector of the build host's uninitialised stack, which mtools 4.0.43 writes when it creates an image file (the images are now made zero-filled and formatted in place). All four are fixed, and LIMITATIONS 5.3a, which blamed `grub-mkrescue` (no longer used), is closed. (#557)

## [0.4.0-alpha]: 2026-10-12

**Capabilities that revoke precisely, a filesystem that walks by them, and every finding of a
source review closed or planned**, and the work since v0.3.0-alpha behind it: 64-bit capability
serials with the lossy revocation table gone, programs and the shell walking the filesystem by
capability with a private `/tmp` per session and a truthful `stat`, `chmod`, `chown` and `link`,
manual pages and a few `/etc` settings that can only tighten, the first steps of the per-CPU
scheduler, and fixes for a password change that could lock root out, a crafted program header, a
reply delivered to the wrong task and pipe ends freed under their holders. The roadmap now holds
only open work, as a route. Install media for x86-64, built for a UK/ISO keyboard, published as
an alpha for developers.

### Security

- A task could hand a child it supervises one of its pipe ends with `SYS_CAP_GRANT`, and the copy was not counted, so closing its own end freed the pipe under the child and the next pipe to take its index was reachable through the child's copy. Ring 3 may no longer copy a pipe end at all: `SYS_CAP_GRANT`, `SYS_CAP_MINT`, `SYS_CAP_TRANSFER` and `SYS_CAP_MOVE` refuse one, and the kernel's own copies (a fork's, the stdio wiring at spawn) count every end they make. No program in the tree passed a pipe end that way (LIMITATIONS 1.29, S133). (#555)
- A client killed with a call in flight left its task slot to a successor, and the reply right and `SYS_IPC_SENDER` named the slot, not the task: the server's answer could complete the successor's own call, and the server could be told the successor (with its uid) had sent the dead client's request. Each queued message now records its sender's slot generation, and both check it (S13, S13b; LIMITATIONS 1.32). (#554)
- A forked child's copies of its parent's pipe ends were not counted, so when the parent closed its ends the pipe was freed under the child and its index could be reused by an unrelated pipe the child could then reach. Fork now counts every pipe end the child holds (S41; LIMITATIONS 1.29). A pipe end copied by `SYS_CAP_GRANT`, `SYS_CAP_MINT` or `SYS_CAP_TRANSFER` is still uncounted, and 1.29 now says so. (#553)
- An account changing its own password re-sealed the key slot of whoever had logged in first that boot, under that account's uid: after root logged in and out, another account's `passwd` locked root's password out of the volume at the next boot and opened root's slot with its own. It now re-seals the caller's own slot (the boot's unlock if that was the caller's, otherwise the slot recorded on the account), sealed to the caller's uid, and refuses when neither is known (S75; LIMITATIONS 1.27). Volumes where this already happened keep the damage. (#552)
- A program image whose ELF header put the program headers just short of 4 GiB into the file made the kernel take a supervisor page fault on the spawn path, killing the caller inside the spawn lock. The premap span was sized by a C parse of the headers that ran before any validator, with a 32-bit bound the offset wrapped; it now comes from the same Rust validators the loader uses, so no C code parses the headers (S84; LIMITATIONS 1.28). (#551)
- Six defects a source review found are recorded as open, each confirmed by reading the current code: a `passwd` re-seals the key slot of the boot's first login rather than the caller's, a crafted program header offset wraps the spawn path's premap bound, `fork` copies a pipe end without counting it, the inode table and bitmaps are not authenticated at rest, the uid path reaches a file by inode number whatever its directories allow, and a reply or a sender's identity names a task slot rather than a task (LIMITATIONS 1.27 to 1.32). `SECURITY.md` A3 is now *partly defended*. (#550)
- `rotate_keys` was described as re-encrypting the volume under a fresh key, and `SYS_ROTATE_KEYS` as rotating the audit chain's keys; it does neither. It rewrites at most 64 of the caller's blocks under the same keys with fresh nonces. The help, the manual and `docs/SYSCALLS.md` now say so, and LIMITATIONS 2.26 records it. (#542)
- Revoking a capability no longer makes unrelated live capabilities unusable. Revocations were also recorded in a 4096-cell table indexed by a hash of the serial, so a revoke made every live capability in the same cell read as revoked; in CI it cost the shell its root directory. The table is gone: serials are 64-bit and never reissued (they used to wrap after about 4.3 billion mints, and a reused task slot reissued its birth serials), a slot only ever gets a fresh serial, and a revoke empties every slot it reaches, so a capability in its slot is live (S5; LIMITATIONS 2.23, 2.24). `SYS_CAP_ENUMERATE` reports 64-bit serials. (#540)
- A `SYS_WAIT` could return while its child still read alive, because the waiter was woken before the child was marked dead; seen once in 200 boots. Every teardown now runs under the lock a waiter publishes itself under and wakes the waiter last, which also closes a window, found by reading the code and never observed, in which a waiter could miss its child's death (S125). (#528)
- The scheduler refuses to run a task on an SMT sibling whatever interrupts it; a parked sibling keeps interrupts on, and the rule used to rest on no interrupt ever reaching one (S101). (#525)
- A TLB shootdown whose bounded wait runs out with a CPU still unacknowledged halts the kernel instead of returning as though the flush had happened; only the SMP selftest calls it today, so this is in place before the first real caller (S124). (#523)

### Added

- `docs/design/configuration.md`: the rule for what a configuration file may change (only tighten security, or change presentation, read by ring-3 programs and never the kernel), and the plan for the manual pages. (#541)
- The roadmap holds only open work now, as a route in four waves with the fifteen decisions it waits on listed first, including a plan for every open limitation (new items 5.1 to 5.11); finished items moved to `docs/history/ROADMAP-DONE-2026.md`, so their citations still resolve. LIMITATIONS 2.6c's count of gates reading kernel reports off the shared console is re-derived (55 by a string search, not about twenty), and the scheduler and filesystem designs and the README no longer describe finished steps as to come. LIMITATIONS 2.28 records that the boot's wait for secondary CPUs is bounded by a count of `pause` instructions rather than by time, which counted a late CPU out under KVM in CI. (#556)
- Two configuration files, `/etc/shell.conf` (the prompt's hostname, the message of the day) and `/etc/login.conf` (a pause after a wrong password), fully commented, written once where none exists and never overwritten. A setting can only tighten security or change presentation; a bad line is ignored with a message naming it, and nothing in either file reaches the kernel (`shell.conf(5)`, `login.conf(5)`). (#546)
- `ln` and `link()` work through a session's capability within one directory: the file travels as a carried capability, never an inode, and the new name may give no more than the caller already holds on the file, refusing a read-only file a writable name (S132). (#544)
- A manual page for every shell command, the administrator's commands, `fs.policy(5)` and three overviews, `horus(7)`, `capabilities(7)` and `sh(1)`; `hier(7)` rewritten for the layout as it is. The manual ships as one archive module that `fs_server` unpacks into `/usr/share/man`, refusing the whole archive if any member is not a plain file with a plain name (S116). (#545)
- `fs_server` walks a whole path below a directory capability in one request and answers with one capability, derived from the one invoked, so a client will hold one capability per open path rather than one per component (filesystem decision 12). Every name is checked before any is looked up, and one that is `.`, `..` or holds `/` in any position refuses the walk (S120). (#529)
- The POSIX layer walks by capability in a program that holds a root directory capability: every open file, directory stream and working directory holds one capability, minted by one walk from the root or the working directory, and close gives it back. The path is chosen once at start, and such a program never touches the uid path, so a refusal cannot fall back to it. Nothing grants a root until phase 1b step 3, so programs still reach files by the uid path today (S126). (#530)
- A spawner can hand a child its filesystem as narrowed copies of its own root and working directory (`hvfs_grant_fs`), which the child keeps only while the spawner does; nothing calls it in a shipped boot until the shell walks by capability (S127). (#531)
- The shell walks by capability when it holds a root directory capability, and hands each program it runs its root and working directory, taking them back when the program ends. Every filesystem request it makes names the object it is about. Nothing gives the shell a root before phase 1b step 3, so sessions still use the uid path (S126, S127). (#532)
- `fs_server` opens a login's session from the filesystem policy: it compiles the account's grants into a grant set named in one root capability's token, keeps every directory on the way to a grant to lookup and a listing of the names that lead there, answers a withheld name as absent, and gives a granted path exactly its granted rights. A live boot's RAM store uses the compiled-in default, a persistent volume its `/etc/fs.policy`, and without one, or with one that does not parse, the administrator alone. Only init's untokened capability can open a session, and nothing asks for one at login until step 3(b) (S128). New syscall `SYS_FS_STORE_KIND` (122) tells `fs_server` which kind of store it serves; it answers only the holder of the store capability. (#534)
- Each session gets a private `/tmp`: a directory `fs_server` makes for that session alone, seen by it as `/tmp`, hidden from every other session, the administrator's included, and removed with everything in it when the session ends. The default policy gives it without exec. A crash's leftovers are cleared by the next boot's first session. Nothing asks for a session at login until step 3(b) (S129). (#536)
- A stat through a session's capability tells the truth: owner bits are the capability's rights and other bits a bound on every other account's grants that can overstate and never understate, each capability's token naming the node of the policy that bounds it; the administrator's grants are not counted (`docs/LIMITATIONS.md` 1.26). A rename onto or off a name the policy names is refused `EXDEV`. A token's generation is now 19 bits (S130). (#538)
- A chmod or chown through a session's capability succeeds only when it asks for what is already true and stores nothing: `chmod 600` on a file another account also reaches fails and so says the file is shared, a looser mode or a group bit is refused, and `chown` succeeds only to the caller itself (S131). (#543)

### Changed

- LIMITATIONS 2.23 recorded that revoking one capability could make an unrelated live one unusable, before the fix in this release removed the cause. (#539)
- The filesystem design says how a session's several grants meet the one root a client holds (decision 13), and how `stat`, `chmod` and `chown` through a capability treat the administrator, files below a grant and a home's `EXEC` bit (decisions 16 to 19). (#533, #537)
- The scheduler chooses the next task by one rule, `sched_selectable`, where every switch path wrote the rule out for itself: six copies, kept in step by hand. Behaviour is unchanged. (#524)
- LIMITATIONS 5.3e, a stale scheduler claim seen once in 200 boots under the switch-commit injection, is closed: none in 199 boots that finished the whole workload, 2,344 refused switches between them, pinned and unpinned. (#526)
- `smoke-switch-commit` watches every switch the process workload refuses, about twelve, where it stopped at the first; it now also fails a boot in which no switch was refused, and says how many it saw. (#522)
- `smoke-switch-commit` failed under KVM on 3 of its first 7 runs, main among them, when the process workload, which the injection slows by parking a CPU at every exit, stopped short of its last line. Such a boot is now retried up to ten times and never counted as a pass; a stale claim, a panic or any other self-test failure is still red at once. (#527)
- The scheduling and SMP design records the decisions taken for it: CPU time as a capability accounted per CPU, slack time behind a right, priorities capped by authority, passive servers, per-CPU run queues and one-shot timers, affinity that only narrows, more than eight CPUs; roadmap item 1.8. (#521)
- LIMITATIONS numbered two entries 1.23: the open one on a program's execute right (#506) and a closed one on the wait race (#528), so one citation had two statuses. The closed one is 1.25, and `doc-claims` now fails when a LIMITATIONS number names more than one entry. (#535)

### Fixed

- `smoke-kstack-reuse` deleted the serial log of a boot that went red, so a failure left nothing to read; it keeps the log now. The `SYS_CAP_ENUMERATE` comment no longer says it reports a generation, which capabilities no longer have. (#547, #548)
- Under QEMU's TCG emulator the monotonic clock ran at twice wall-clock speed, so `login.conf`'s `failure_delay` waited half as long as it said: the timer tick, programmed as a square wave, was delivered twice per period. It is now programmed as a rate generator, one interrupt per period on every machine, and `smoke-etc-config` holds the delay to the host's clock. At the true rate, `fs_server`'s wait for a sealed volume, which spun each time slice away, starved the keyboard during an install until the password lost characters; it now yields the CPU (LIMITATIONS 3.6). (#549)

## [0.3.0-alpha]: 2026-10-09

**An installed disk that starts on its own, with its programs on it**, and the work since
v0.2.0-alpha behind it: GPT and an EFI system partition, system trees rebuilt from the verified
modules at every boot, all RAM up to 4 GiB, encrypted swap that an idle task gives memory back to,
the first half of the capability filesystem in `fs_server`, a shared libc, and the laptop's eMMC
working end to end. Install media for x86-64, built for a UK/ISO keyboard, published as an alpha
for developers.

### Security

- A rename or link that would give a file a name in a second directory is refused with `EXDEV`, so a move can never change who may reach a file; a rename within one directory works, and through a capability needs `CREATE` and `DELETE` there (S121, phase 1b step 5). (#516)
- `fs_server` answers requests through tokened capabilities: the object comes from the token, the rights from the capability, and children come back narrowed and revoked with it (S120, phase 1b step 1); the uid path stays beside it until step 6. (#515)
- The system trees (`/bin`, `/sbin`, `/lib`, `/usr`) are rebuilt from the verified boot modules at every boot, and `fs_server` refuses every change to them, root included (S116). (#506)
- A user could free any inode, `/bin` included, by forging a directory entry in a file they own; `fs_server` now refuses any file as a directory operand (`[HORUS-20261008-01]`, S113). (#502)
- The tools that build and check Horus are pinned. (#490)
- A task record with kernel-half bounds would have made a kernel address the task's own. (#487)
- An ELF offset from the image or from the C side could wrap instead of being refused. (#486)
- A live boot no longer opens an installed system. (#472)
- A live boot no longer writes the built-in accounts to an installed disk. (#469)
- An installed machine accepted the compiled-in `root` password until its volume was unlocked. (#437)

### Added

- A large idle task gives memory back: under pressure the pager takes idle pages from tasks no CPU is running, holding each off every CPU while its page tables change, before the short task's own (S123). `init` was never actually pinned against swap, because its task was named `prog1`; it is now pinned by identity and named `init`. (#518)
- Swap pages out: a task short of memory sends its own idle pages to the encrypted swap partition and gets them back on touch; 48 MiB runs on a 64 MiB pool (S119). (#512)
- The swap partition is opened at an installed boot's unlock as a sealed store: every page under a key made at that boot, its tag kept in RAM, nothing on the partition in plaintext (S118). Nothing is paged out to it yet. (#510)
- The page pool uses all of a machine's RAM up to 4 GiB, every region the memory map names, instead of the one region holding 16 MiB capped at 1 GiB; a 3 GiB guest's pool went from 495 MiB to 3054 MiB (S117). (#508)
- An installed machine has its programs on it: the install media carries GNU coreutils, TCC and their man pages, with the licence texts and a written source offer in `/usr/share/doc`. (#506)
- An installed disk starts on its own under UEFI: the installer lays out GPT, an EFI system partition, swap and the volume, with the swap and volume sizes asked for (S115). (#505)
- The kernel mounts a volume from a GPT partition, and refuses a partition table that does not verify (S114). (#503)
- Every Kani proof's control arm runs nightly. (#493)
- The coreutils and `tcc` share one libc instead of carrying their own. (#470)
- A program can be linked against the shared libc like any other library. (#468)
- A program can make part of itself read-only for good. (#467)
- A program can be given the shared libc by the system itself, and only if it asks. (#465)
- The website is eight pages instead of one, and it says Horus can be installed. (#458)
- The website's mark is the Eye of Horus. (#457)
- A server can tell its clients apart by the capability they call it through. (#455)
- Shift+PgUp and Shift+PgDn scroll the console back. (#445)
- A kernel log on Alt+F2, for diagnostic builds. (#443)
- The installer waits for a key when it has finished, then clears the screen for the login prompt. (#438)
- The installer can format without encryption, for an operator who chooses it. (#435)
- The installer can lay down a volume smaller than the disk. (#434)
- The SMP race gates also run under KVM, as a second detector. (#422)
- Up to eight CPUs, and eight by default. (#420)
- The docs and the website keep the writing rules by check, not by request. (#411)
- The page pool's refcount arithmetic is proved, not reviewed. (#409)
- Two CI facts that live outside the tree are now written down. (#407)
- The full `kani` job cannot fail and has never been run. (#407)
- The first external review of this tree is reconciled, not filed away. (#406)
- Cryptography has a finding ID (`[HORUS-20260920-03]`, `LIMITATIONS.md` 5.4). (#406)
- The design for `[HORUS-20260911-04]` is written out. (#406)
- The kernel's `.bss` has a budget, and CI holds it exactly (audit F2). (#403)

### Changed

- The installer reads better: a bright, closed frame; the step shown as a row of dots; sizes on one line ("512 MiB (131,072 blocks)", or GiB); the review reduced to install, change an answer or cancel, so it no longer runs into the footer; the word to type set apart; and on a disk that starts on its own, advice to remove the install media. (#514)
- The boot's memory line says how much RAM lies above 4 GiB, out of Horus's reach, and a diagnostic build lists the firmware's whole memory map: the IdeaPad showed 1,842 MiB of its 4 GB with nothing saying where the rest was. (#511)
- The installed-system design records that a user's own programs may run from `/home`, outside the manifest. (#500)
- The filesystem design sets out phase 1b in six steps and records the four decisions taken for it. (#499)
- The README is rewritten to match the tree as it is. (#496)
- `CHANGES.md` is one line per entry; the full entries are in `docs/history/CHANGES-2026.md`. (#495)
- The website is plain HTML in `site/`, edited directly. (#494)
- Fuzzing runs nightly, for ten minutes per target, and a crash fails it. (#492)
- The SMP race gates under KVM now gate every merge. (#491)
- Three more Kani proofs gate every pull request. (#488)
- Every Kani proof runs on every pull request. (#485)
- `THIRD_PARTY.md` lists the vendored GNU coreutils (GPLv3) and TinyCC (LGPL 2.1). (#483)
- `docs/SYSCALLS.md` lists every syscall. (#482)
- `docs/ARCHITECTURE.md` describes the system as built. (#481)
- `docs/BUILDING.md` describes the build and the machines Horus runs on today. (#480)
- `SECURITY.md` states each property in one row a person can read. (#479)
- `TESTS.md` is a catalogue again: one row per gate. (#478)
- The contributor and reference documents describe the project as it is. (#477)
- The README is rewritten from scratch. (#476)
- `docs/ROADMAP.md` says what is done and what is next, in order. (#475)
- `docs/LIMITATIONS.md` lists only what is open. (#474)
- The boot log and the console are left-aligned again; only the installer is centred. (#449)
- A live boot's root password is `toor`; `rootpass` is gone. (#442)
- Formatting no longer reads the whole metadata region back. (#432)
- Every CI build used one of the runner's four cores. (#418)
- A CI run took nearly an hour, set by two jobs. (#416)

### Fixed

- An install gate on two CPUs failed in three of five CI runs: while `console_server` was starting, `init` wrote through the kernel and the server wrote straight to the serial port, so `init`'s line came out split. `init` now waits for the server to own the console and writes through it. (#519)
- A pipeline typed as the first command after logging in on an installed system hung: a pipe end went into the slot the filesystem endpoint is installed into, and was overwritten by it. Capabilities the kernel allocates now start above every well-known slot (S122). `init` also put the filesystem's endpoint and the console's notification in the same slot; that is now a build error. (#517)
- After an install on a framebuffer wider than 80 columns, the installer's right border stayed on the screen beside the login banner: the console's clear repainted cells, not the screen. (#513)
- On a framebuffer, the installer's progress panel lost six of its eight rows to a black box while the password was hashed; it is now drawn inside the installer's frame. (#504)
- A login that unlocked the disk left "Turning your password into a key" on the screen for good; the panel is now the installer's alone, and a login says it is checking the password instead. (#504)
- A disk started by UEFI GRUB came up with an empty `/bin`: the kernel dropped every boot module below 1 MiB, where that GRUB puts small ones, and the install entry got no modules at all because the media build read the module list only once. (#506)
- A stalled Ubuntu package mirror held every CI job until its timeout, because a retry runs only after a command exits; each apt attempt is now bounded. (#501)
- `smoke-kdiag-ioport` could report a refusal missing because ring-3 output cut the kernel's kill report in half. (#498)
- The roadmap called nightly fuzzing and full Kani not started after both had landed. (#497)
- The `unsafe` check never read most of `lib.rs`. (#489)
- `smoke-kdiag-split-control` went red about one CI run in 24 on changes that do not touch the console. (#473)
- A merge-conflict marker sat in `docs/LIMITATIONS.md` §5.6 for a day, with every job green. (#471)
- A failed install showed nothing on the screen, or only the start of the reason. (#463)
- A BIOS boot drew the installer with no frame, and the format progress bar empty. (#462)
- The website failed WCAG 2.1 AA contrast for its faintest text, and a screen reader heard the home page's two tokens as identical. (#460)
- The website's footer was a ragged run of links. (#459)
- An idle console prompt kept a core busy. (#453)
- A flush on an SD card or eMMC could return while the card was still writing. (#452)
- Every disk read on a laptop's eMMC took about 83 ms, so commands and keys lagged by seconds. (#450)
- Stray characters appeared before `init: the installer finished`. (#448)
- A command typed without its operand said "Unknown command". (#447)
- An install onto a laptop's eMMC failed at the password step, on two cores and never on one. (#444)
- An install that failed at the password step said only "could not set the password". (#436)
- The installer sat in the top-left corner of a laptop's screen. (#433)
- An install on a laptop's eMMC took twenty minutes and showed nothing while it did. (#431)
- The SD stride control arm cleared the key slots it had just written, and the install gate reported a refused format as a wedge. (#431)
- The installer drew its screens into a serial port that was not there, so on a laptop it ran correctly and invisibly. (#429)
- A laptop's eMMC answered every command and the bus then wedged, so the installer still found no disk. (#428)
- A laptop's eMMC controller was found and then read as zeros, so it could not be installed onto. (#427)
- A laptop with more than fourteen PCI functions lost the rest, eMMC controller included. (#426)
- The page free path now refuses a frame it did not lend. (#425)
- The kernel-stack park control arm went red about one run in ten with the defect present. (#424)
- A task killed while it ran on another CPU kept running. (#423)
- A new task could be written onto a kernel stack another CPU was still using. (#421)
- A capability for a dead task controlled whatever task reused its slot. (#417)
- A new CI gate did not block merges until someone synced the ruleset by hand. (#415)
- Any task could wait on any other task and read why it died. (#414)
- A task could read the previous occupant's death record from its reused slot. (#413)
- A kernel fault handed ring 3 the kernel's own address. (#412)
- Five documents stated the Kani harness count and no two agreed. (#409)
- `rust/KANI.md` carried two claims that had gone false. (#409)
- A number that advertised its own freshness had been stale for five weeks. (#407)
- [G-9] was open and closed in the same tree, and an outside reader believed the wrong one. (#406)
- Boot modules are no longer limited to the room below 16 MiB. (#404)
- A verified boot module could change after its hash was taken (HORUS-20260919-02). (#402)
- The kernel did not build on Void Linux: a 270-byte trampoline came out as 128 MiB. (#400)

## [0.2.0-alpha]: 2026-09-14

**The first release of Horus that anyone can boot without a toolchain**, and the first that
exists as a tag at all: see the note under 0.1.0. Install media for x86-64, built for a UK/ISO
keyboard, published as an alpha for developers.

The full entries are in [`docs/history/CHANGES-2026.md`](docs/history/CHANGES-2026.md).

## [0.1.0]: 2026-08-21

> **Never tagged and never published.** This section recorded a milestone in the changelog and
> nothing else: no `v0.1.0` tag was ever pushed and no release was ever made, so the link that
> used to sit here pointed at a page that has never existed. It is left in place because the
> entries archived for it are a true account of what changed, but the first actual release of
> Horus is **v0.2.0-alpha**, above.

The full entries are in [`docs/history/CHANGES-2026.md`](docs/history/CHANGES-2026.md).
