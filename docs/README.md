# Horus Documentation

This folder contains technical documentation for the Horus microkernel.

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Design philosophy, subsystem internals, capability model, memory layout, Rust integration |
| [BUILDING.md](BUILDING.md) | Toolchain requirements, build targets, QEMU setup, troubleshooting |
| [LIMITATIONS.md](LIMITATIONS.md) | Honest account of what works, what is stubbed, and known security gaps |
| [ROADMAP.md](ROADMAP.md) | Planned milestones and open contribution areas |

Formal specifications:

| File | Contents |
|---|---|
| [cap_algebra.tla](cap_algebra.tla) | TLA+ specification of the capability algebra (mint, transfer, revoke) |
| [paging_isolation.tla](paging_isolation.tla) | TLA+ specification of paging isolation properties |

Project-level documents (at the repository root):

| Document | Contents |
|---|---|
| [README.md](../README.md) | Build quick start, status-at-a-glance table, project overview |
| [SECURITY.md](../SECURITY.md) | Security policy, current posture, hardening in place, reporting |
| [TESTS.md](../TESTS.md) | Test coverage today and what is still needed |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to set up and submit work |
| [CHANGES.md](../CHANGES.md) | Changelog (`main` branch state) |
