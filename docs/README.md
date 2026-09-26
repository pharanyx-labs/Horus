# Horus documentation

Start with the [project README](../README.md). Where a document and the code disagree, the code
is right; please open an issue so the document is fixed.

## The living documents

These describe the system as it is today, and each change updates them in the same pull request.

| Document | What it is for |
|---|---|
| [`LIMITATIONS.md`](LIMITATIONS.md) | What does not work or is not enforced. **The single authoritative status of every finding.** Read it before drawing conclusions |
| [`ROADMAP.md`](ROADMAP.md) | What is done, and what comes next in what order |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How each subsystem is built and why: boot, the C and Rust split, capabilities, paging, scheduling, SMP, IPC, syscalls, the servers, storage, trusted boot, side channels, and the known architectural gaps |
| [`SYSCALLS.md`](SYSCALLS.md) | Every system call, the capability it requires, and how to add one |
| [`../SECURITY.md`](../SECURITY.md) | The threat model, every security property with the test that witnesses it, and how to report a vulnerability |
| [`BUILDING.md`](BUILDING.md) | Toolchain, targets, running under QEMU and on hardware, installing, reproducible builds, and every build flag. Its defect-flag table is the index of the control arms, and CI holds it complete |
| [`../TESTS.md`](../TESTS.md) | Every test target and what it proves |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | The workflow, code style, and the invariant rule |
| [`../rust/KANI.md`](../rust/KANI.md) | What the Kani proofs establish, and which of them gate a merge |
| [`../THIRD_PARTY.md`](../THIRD_PARTY.md) | Everything not written for Horus, and its provenance |
| [`../CHANGES.md`](../CHANGES.md) | What changed, by pull request |

## Designs

Specifications written before the code. Each says at its top what of it is built.

| Design | Status |
|---|---|
| [`design/filesystem.md`](design/filesystem.md) | The capability-addressed filesystem. Phase 1a (endpoint tokens, S105) is built; phase 1b is next (ROADMAP 2.10) |
| [`design/installed-system.md`](design/installed-system.md) | Programs on the disk under a pinned manifest, a disk that boots itself, accounts as files. Decided, not yet built (ROADMAP 2.11) |
| [`design/shared-libc.md`](design/shared-libc.md) | How programs receive, bind and seal the shared libc. Built (S106 to S108) |
| [`design/meta-cache-merkle.md`](design/meta-cache-merkle.md) | The bounded metadata cache and the Merkle rollback tree. Built (S65, S66) |
| [`design/console-server.md`](design/console-server.md) | Moving the console driver to ring 3. Built |

## Audits and investigations

| Record | What it holds |
|---|---|
| [`AUDIT.md`](AUDIT.md) | The latest self-audit, 2026-09-19: three findings (F1 to F3), all closed |
| [`history/AUDIT-EXTERNAL-2026-09-20.md`](history/AUDIT-EXTERNAL-2026-09-20.md) | The first outside review of the tree, reconciled against the checkout. It sets no statuses |
| [`history/AUDIT-2026-08-30.md`](history/AUDIT-2026-08-30.md) | The 2026-08-30 whole-tree audit |
| [`history/AUDIT-2026-07.md`](history/AUDIT-2026-07.md) | The 2026-07 audit that defined the [C-n], [I-n], [M-n] and [F-n] findings, with its predecessor as an appendix |
| [`investigations/`](investigations/) | How the hardest findings were narrowed and measured, including the hypotheses that were wrong: [G-8], [G-9], [G-10], [G-11] and [G-12] (all closed), and the kernel-pointer disclosure survey behind roadmap 3.8 |
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
