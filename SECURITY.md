# Security Policy

## Project security posture

Horus is a **research microkernel** in early development. It is not suitable for use in production environments or for handling sensitive workloads. The security properties described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) reflect the design intent; several of them are not yet fully implemented. [docs/LIMITATIONS.md](docs/LIMITATIONS.md) describes the current gaps honestly.

Known weaknesses include:

- The password hashing scheme is custom and has not been reviewed by a cryptographer
- Cryptographic primitives in `rust/src/crypto.rs` are placeholder stubs
- ASLR is not enforced on every task spawn
- The audit log has no integrity protection
- SMP and preemptive scheduling are not yet implemented

These are not undisclosed vulnerabilities — they are documented, known limitations of an incomplete system.

---

## Reporting a vulnerability

If you discover a security issue in Horus that is not already documented in [docs/LIMITATIONS.md](docs/LIMITATIONS.md), please report it responsibly rather than disclosing it publicly right away.

**How to report:**

Open a GitHub Security Advisory in this repository (Settings → Security → Advisories → New draft advisory). This creates a private thread visible only to repository maintainers.

Include:

- A description of the issue and the component it affects
- Steps to reproduce or a proof-of-concept if applicable
- Your assessment of the impact
- Whether you want to be credited in the fix

We will acknowledge the report within a few days and aim to respond substantively within two weeks.

---

## Scope

Given the project's status, the following are in scope for responsible disclosure:

- Bugs in the capability system that allow a task to bypass access control
- Memory safety issues in the C kernel or Rust FFI boundary
- Authentication bypass in the user authentication path
- Privilege escalation from Ring 3 to Ring 0

The following are out of scope for now, because they are known and documented:

- Weak password hashing
- Missing ASLR enforcement
- Absence of covert-channel mitigations
- Missing preemption or SMP support
- Stub implementations that return errors

---

## Supported versions

There are no stable releases yet. Security fixes are applied to the `main` branch only.
