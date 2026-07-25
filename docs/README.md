# Horus Documentation

Technical documentation for the Horus microkernel.

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Design philosophy, subsystem internals, capability model, task/process model, scheduling, signals, IPC/pipes, SMP, memory layout, measured boot, Rust integration |
| [SYSCALLS.md](SYSCALLS.md) | Per-syscall reference (0–88): numbers, capability requirements, notes |
| [BUILDING.md](BUILDING.md) | Toolchain requirements, build targets, build flags, QEMU setup, troubleshooting |
| [LIMITATIONS.md](LIMITATIONS.md) | Honest account of what works, what is partial, and known security gaps |
| [AUDIT-2026-07.md](AUDIT-2026-07.md) | July 2026 security & engineering audit findings (A1–A4, P1–P5) and status |
| [ROADMAP.md](ROADMAP.md) | Audit-driven remediation tracks and open contribution areas |

Formal specifications:

| File | Contents |
|---|---|
| [cap_algebra.tla](cap_algebra.tla) | TLA+ specification of the capability algebra (mint, transfer, revoke) |
| [paging_isolation.tla](paging_isolation.tla) | TLA+ specification of paging isolation properties |

Templates & proposals:

| File | Contents |
|---|---|
| [pull_request_template.md](pull_request_template.md) | PR description + security-impact checklist |
| [security_report.md](security_report.md) | Security-issue report template |
| [proposals/console-server.md](proposals/console-server.md) | Design record for the ring-3 console driver (implemented) |

Project-level documents (at the repository root):

| Document | Contents |
|---|---|
| [README.md](../README.md) | Quick start, status-at-a-glance table, project overview |
| [SECURITY.md](../SECURITY.md) | Security policy, current posture, hardening in place, reporting |
| [TESTS.md](../TESTS.md) | Test coverage today (91 Rust unit tests, 52 CI jobs) and what is needed |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to set up and submit work |
| [CHANGES.md](../CHANGES.md) | Changelog (`main` branch state) |
