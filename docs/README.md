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

For project-level information — build quick start, status table, contributing — see the [top-level README](../README.md).
