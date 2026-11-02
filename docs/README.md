# Horus documentation

Start with the [project README](../README.md). Where a document and the code disagree, the code
is right; please open an issue so the document is fixed.

## Where a later session starts

The open work, and the order to take it, is [`ROADMAP.md`](ROADMAP.md). The items recorded so
the long-term security and CI work is not re-derived each session are 4.17, 4.19, 4.20, 4.22,
4.23, 5.14 and 5.15. The same queue is on the status page of the site. Do not start a later item in a lane
while an earlier one is open, and do not implement one of them inside a documentation change.

## The living documents

These describe the system as it is today, and each change updates them in the same pull request.

| Document | What it is for |
|---|---|
| [`LIMITATIONS.md`](LIMITATIONS.md) | What does not work or is not enforced. **The single authoritative status of every finding.** Read it before drawing conclusions |
| [`ROADMAP.md`](ROADMAP.md) | The open work only, the decisions it waits on, and the route through it in waves |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How each subsystem is built and why: boot, the C and Rust split, capabilities, paging, scheduling, SMP, IPC, syscalls, the servers, storage, trusted boot, side channels, and the known architectural gaps |
| [`SYSCALLS.md`](SYSCALLS.md) | Every system call, the capability it requires, and how to add one |
| [`../SECURITY.md`](../SECURITY.md) | The threat model, every security property with the test that witnesses it, and how to report a vulnerability |
| [`BUILDING.md`](BUILDING.md) | Toolchain, targets, running under QEMU and on hardware, installing, reproducible builds, and every build flag. Its defect-flag table is the index of the control arms, and CI holds it complete |
| [`../TESTS.md`](../TESTS.md) | Every test target and what it proves |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | The workflow, code style, and the invariant rule |
| [`../rust/KANI.md`](../rust/KANI.md) | What the Kani proofs establish, and how every one of them gates a merge |
| [`../THIRD_PARTY.md`](../THIRD_PARTY.md) | Everything not written for Horus, and its provenance |
| [`../CHANGES.md`](../CHANGES.md) | What changed, by pull request |

## Designs

Specifications written before the code. Each says at its top what of it is built.

| Design | Status |
|---|---|
| [`design/filesystem.md`](design/filesystem.md) | The capability-addressed filesystem. Phases 1a (endpoint tokens, S105) and 1b are built; phases 2 to 4 remain (ROADMAP 2.10) |
| [`design/installed-system.md`](design/installed-system.md) | Programs on the disk under a pinned manifest, a disk that boots itself, accounts as files. The first two are built; accounts as files are not (ROADMAP 2.11) |
| [`design/scheduler.md`](design/scheduler.md) | Scheduling and SMP: CPU time as a capability accounted per CPU, priorities capped by authority, passive servers, per-CPU run queues, one-shot timers, affinity that only narrows, more than eight CPUs. Steps 0, 1, 1b, 2a, 2, 3a, 3b, 3c, 4a and 4b are built. Next is step 5, passive servers, then affinity, more than eight CPUs and targeted shootdown (ROADMAP 1.8) |
| [`design/swap.md`](design/swap.md) | Encrypted swap: a per-boot key, every page authenticated with its tag kept in RAM, only private pages, an in-kernel pager. Steps 1, 2 and 2a are built: the sealed slot store, eviction and fault-in, and the pager hold (S118, S119, S123) |
| [`design/ring3-storage.md`](design/ring3-storage.md) | Storage drivers out of ring 0: the kernel keeps the keys and stops doing disk I/O, and ring-3 drivers holding one device capability move the ciphertext. `sdhcid`, `atad` and `nvmed` run in self-test builds and share the block-driver protocol. The installed system still uses the kernel's IDE and eMMC drivers (ROADMAP 2.7, 2.10) |
| [`design/shared-libc.md`](design/shared-libc.md) | How programs receive, bind and seal the shared libc. Built (S106 to S108) |
| [`design/meta-cache-merkle.md`](design/meta-cache-merkle.md) | The bounded metadata cache and the Merkle rollback tree. Built (S65, S66) |
| [`design/console-server.md`](design/console-server.md) | Moving the console driver to ring 3. Built |
| [`design/configuration.md`](design/configuration.md) | Configuration files in `/etc` that can only tighten security or change cosmetics, read by ring-3 programs and never the kernel; manual pages shipped as one verified archive. Built: the manual (#545) and the files (#546) |

## Audits and investigations

| Record | What it holds |
|---|---|
| [`AUDIT.md`](AUDIT.md) | The latest self-audit, 2026-09-19: three findings (F1 to F3), all closed |
| [`history/AUDIT-EXTERNAL-2026-09-20.md`](history/AUDIT-EXTERNAL-2026-09-20.md) | The first outside review of the tree, reconciled against the checkout. It sets no statuses |
| [`history/AUDIT-2026-08-30.md`](history/AUDIT-2026-08-30.md) | The 2026-08-30 whole-tree audit |
| [`history/AUDIT-2026-07.md`](history/AUDIT-2026-07.md) | The 2026-07 audit that defined the [C-n], [I-n], [M-n] and [F-n] findings, with its predecessor as an appendix |
| [`investigations/`](investigations/) | How the hardest findings were narrowed and measured, including the hypotheses that were wrong: [G-8], [G-9], [G-10], [G-11] and [G-12] (all closed), and the kernel-pointer disclosure survey behind roadmap 3.8 |
| [`history/CHANGES-2026.md`](history/CHANGES-2026.md) | The changelog in full to 2026-10-07, every entry with its reasoning and measurements, before `CHANGES.md` became one line per entry |
| [`history/ROADMAP-DONE-2026.md`](history/ROADMAP-DONE-2026.md) | Every roadmap item finished in 2026, one line each with its pull requests; a citation of a finished item resolves here |
| [`history/DEVLOG-2026.md`](history/DEVLOG-2026.md) | The development log to early September 2026: why each change was made, what was tried first, and how each rate was measured |

The records under `history/` and `investigations/` are kept as written, because the reasoning in
them is the evidence. They describe the tree as it was; the current status of anything they name
is in [`LIMITATIONS.md`](LIMITATIONS.md).

## Checked, not promised

Several kinds of claim in these documents are checked by CI rather than trusted:
`tools/check_doc_claims.py` derives every declared count and refuses phrasings that were retired
because they became false; `tools/check_invariants.py` requires every `SECURITY.md` property to
name a test that exists and runs; `tools/check_defect_flags.py` holds `BUILDING.md`'s control-arm
table complete; `tools/check_named_targets.py` refuses a `make` target that does not exist; and
`tools/check_prose_style.py` enforces British English and bans em dashes.
