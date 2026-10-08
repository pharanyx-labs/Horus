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

- A user could free any inode, `/bin` included, by forging a directory entry in a file they own; `fs_server` now refuses any file as a directory operand (`[HORUS-20261008-01]`, S113). (#502)
- The tools that build and check Horus are pinned. (#490)
- A task record with kernel-half bounds would have made a kernel address the task's own. (#487)
- An ELF offset from the image or from the C side could wrap instead of being refused. (#486)
- A live boot no longer opens an installed system. (#472)
- A live boot no longer writes the built-in accounts to an installed disk. (#469)
- An installed machine accepted the compiled-in `root` password until its volume was unlocked. (#437)

### Added

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
