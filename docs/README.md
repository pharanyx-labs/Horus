# Horus documentation

Technical documentation for the Horus microkernel. Start with the
[project README](../README.md) for an overview.

---

## Read in this order

**Understanding the system**

1. **[ARCHITECTURE.md](ARCHITECTURE.md)** — How Horus is built and why. Boot and memory
   layout, the C/Rust split, capabilities, paging, scheduling, SMP, IPC, the syscall layer,
   userspace servers, storage, trusted boot, side-channel posture, and the known
   architectural gaps.

2. **[SYSCALLS.md](SYSCALLS.md)** — The complete syscall ABI: calling convention, the
   capability-checked dispatch table, every syscall with its authorisation requirement, and
   how to add one.

3. **[../SECURITY.md](../SECURITY.md)** — The threat model, the adversaries considered and
   excluded, the security properties Horus claims with the witness for each, and the
   vulnerability reporting process.

**Evaluating the system**

4. **[LIMITATIONS.md](LIMITATIONS.md)** — What does not work, what is not enforced, and where
   the documentation used to overstate the case. This is the authoritative status of every
   finding. Read it before drawing any conclusion about Horus's readiness.

5. **[AUDIT.md](AUDIT.md)** — The full security and engineering audit, with the July 2026
   predecessor audit as Appendix A.

**Working on the system**

6. **[BUILDING.md](BUILDING.md)** — Toolchain, build targets, configuration flags, running
   under QEMU and on hardware, reproducible builds, boot modules, troubleshooting. Its
   defect-flag table is the index of the control arms, and CI checks that it is complete.

7. **[../TESTS.md](../TESTS.md)** — The test catalogue and what each test proves.

8. **[../CONTRIBUTING.md](../CONTRIBUTING.md)** — Workflow, code style, and the
   invariant-preservation rule for security-critical paths.

9. **[ROADMAP.md](ROADMAP.md)** — The prioritised plan toward a complete operating system,
   ordered by assurance value.

---

## Investigations

The forensic record of the harder findings — how each was narrowed, which hypotheses were
wrong, and how the rate was measured. Kept in full because in a security project the
reasoning is the evidence. Their **current status** is in [LIMITATIONS.md](LIMITATIONS.md),
not here.

| Investigation | Status |
|---|---|
| [`G-08-two-cpus-one-kernel-stack.md`](investigations/G-08-two-cpus-one-kernel-stack.md) | Closed 2026-08-17 |
| [`G-09-scheduler-claim-leak.md`](investigations/G-09-scheduler-claim-leak.md) | **Open** |
| [`G-10-spawn-path-uaf.md`](investigations/G-10-spawn-path-uaf.md) | Closed 2026-08-18 |
| [`G-11-armed-image-ownership.md`](investigations/G-11-armed-image-ownership.md) | Closed 2026-08-18 |

---

## Reference material

| File | Contents |
|---|---|
| [`cap_algebra.tla`](cap_algebra.tla) | TLA+ specification of the capability algebra |
| [`paging_isolation.tla`](paging_isolation.tla) | TLA+ specification of address-space isolation |
| [`design/console-server.md`](design/console-server.md) | The design behind the ring-3 console driver, as built |
| [`history/DEVLOG-2026.md`](history/DEVLOG-2026.md) | The development log: 117 narrative entries, newest first |
| [`../CHANGES.md`](../CHANGES.md) | The changelog |

The TLA+ specifications are **not yet model-checked in CI** — see roadmap item 3.5.

---

## A note on accuracy

These documents are rewritten rather than patched when they drift from the code. The previous
set claimed IPC was "capability-gated" when the kernel did not in fact bind endpoints to
capabilities — precisely the kind of overstatement that makes documentation dangerous in a
security project.

Three classes of claim are now checked rather than promised, because each had already gone
stale silently: `tools/check_doc_claims.py` derives every documented count and the phrasings
that must not reappear, `tools/check_gate_pairs.py` refuses an orphan control arm, and
`tools/check_defect_flags.py` holds BUILDING.md's defect-flag table to being the complete list
it claims to be. Each is a required CI job.

**Where a document and the code disagree, the code is authoritative.** Please open an issue
so the document gets fixed rather than the reader misled.
