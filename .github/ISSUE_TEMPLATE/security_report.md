---
name: Security report
about: Report a suspected security issue in Horus
title: "[SECURITY] "
labels: security
assignees: pharanyx-labs
---

> ## ⚠️ Stop, is this sensitive?
>
> **For an exploitable vulnerability, do not open a public issue.** Use
> [private vulnerability reporting](https://github.com/pharanyx-labs/Horus/security/advisories/new)
> instead, or email horus@pharanyx.co.uk. See [SECURITY.md](../../SECURITY.md).
>
> This public template is for hardening suggestions, questions about the security model, and
> issues you have already confirmed are non-sensitive.

> ## Already known?
>
> Please check [docs/LIMITATIONS.md](../../docs/LIMITATIONS.md) first, which carries the
> authoritative status of every finding, and then
> [docs/AUDIT.md](../../docs/AUDIT.md) for the current audit. Several weaknesses are documented
> and tracked; reports of anything already listed there are duplicates.
>
> The open ones worth knowing about are **process** rather than defects: **[C-5]**, no
> security-critical change has been reviewed by a second person, and **[C-6]**, ruleset
> reconciliation lags a merge. **[I-7]**, the fixed `tasks[]` table, is the open technical one.
>
> *This block named **[C-1]** as an open weakness until 2026-08-30. It was fixed on 2026-07-27,
> which is to say the issue template invited duplicate reports of a defect that had not existed
> for a month.*

## Summary

<!-- One sentence. -->

## Which security property is violated?

<!-- Ideally by ID from the claims table in SECURITY.md, e.g. "S1: a task cannot exercise
authority it holds no capability for". If it does not map to a listed claim, say what you
expected the system to guarantee. -->

## Component

- [ ] Capability system, lookup, mint, grant, revocation, lineage
- [ ] Syscall dispatch and authorisation
- [ ] Memory management, paging, COW, user copies, W^X
- [ ] IPC, notifications, or pipes
- [ ] Scheduler, SMP, or locking
- [ ] Process control, spawn, exec, kill, signal, wait
- [ ] Filesystem server or the encrypted object store
- [ ] Console server or device delegation
- [ ] Cryptography, RNG, or key derivation
- [ ] Authentication or audit logging
- [ ] Boot integrity, measured boot, or TPM sealing
- [ ] Build, CI, or supply chain
- [ ] Other:

## Details

<!-- What happens, what should happen, and the code path or syscalls involved. -->

## Impact

- Confidentiality / integrity / availability:
- Can an unprivileged ring-3 task escalate privilege or bypass a capability check?
- Can a task affect another task it holds no `CAP_TCB` for?
- Is this a regression? If so, from which commit?
- Known workaround:

## Reproduction

<!-- Steps, or a minimal program. Write "available privately" if you would rather not post it,
and in that case please use private disclosure instead. -->

## Environment

- Commit:
- Build configuration: <!-- default / SMP=0 / DEBUG_SHELL=1 / MINIMAL_SECURE=1 / a *_SELFTEST -->
- Host and QEMU version, or hardware:
- Relevant CPU features: <!-- SMEP, SMAP, RDRAND, TPM present -->

## Suggested fix

<!-- Optional. -->

## Credit

- [ ] Credit me if a fix is published
- [ ] Keep my name private
