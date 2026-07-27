# Horus Documentation

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
   the documentation used to overstate the case. Read this before drawing any conclusion
   about Horus's readiness.

5. **[AUDIT-2026-07-27.md](AUDIT-2026-07-27.md)** — The current full security and engineering
   audit: kernel findings, process findings, and the enhancement roadmap. Supersedes
   [AUDIT-2026-07.md](AUDIT-2026-07.md).

**Working on the system**

6. **[BUILDING.md](BUILDING.md)** — Toolchain, build targets, configuration flags, running
   under QEMU and on hardware, reproducible builds, boot modules, troubleshooting.

7. **[../TESTS.md](../TESTS.md)** — The test catalogue and what each test proves.

8. **[../CONTRIBUTING.md](../CONTRIBUTING.md)** — Workflow, code style, and the
   invariant-preservation rule for security-critical paths.

9. **[ROADMAP.md](ROADMAP.md)** — The prioritised plan toward a complete operating system,
   ordered by assurance value.

---

## Reference material

| File | Contents |
|---|---|
| [`cap_algebra.tla`](cap_algebra.tla) | TLA+ specification of the capability algebra |
| [`paging_isolation.tla`](paging_isolation.tla) | TLA+ specification of address-space isolation |
| [`proposals/console-server.md`](proposals/console-server.md) | The RFC behind the ring-3 console driver |
| [`AUDIT-2026-07.md`](AUDIT-2026-07.md) | The previous audit (findings A1–A4, P1–P5), retained as a record |
| [`../CHANGES.md`](../CHANGES.md) | Historical development log |

The TLA+ specifications are **not yet model-checked in CI** — see roadmap item 3.5.

---

## A note on accuracy

These documents are rewritten rather than patched when they drift from the code. The previous
set claimed IPC was "capability-gated" when the kernel did not in fact bind endpoints to
capabilities — precisely the kind of overstatement that makes documentation dangerous in a
security project.

**Where a document and the code disagree, the code is authoritative.** Please open an issue
so the document gets fixed rather than the reader misled.
