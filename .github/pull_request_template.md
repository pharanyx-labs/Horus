## Description

<!-- What does this change do? Link the related issue if there is one. -->

## Motivation

<!-- Why is this needed? What problem does it solve? -->

---

## Security invariant statement

**Required for any change touching:** `src/kernel/capability.c`, `rust/src/capability.rs`,
`src/kernel/syscall*.c`, `src/kernel/paging.c`, `src/kernel/scheduler.c`,
`src/kernel/loader.c`, `rust/src/lib.rs`, `src/kernel/storage.c`, `src/kernel/crypto.c`,
`src/kernel/tpm.c`, `.github/workflows/`, `Makefile`, or `linker64.ld`.

Delete this section only if none of those are touched.

**Which invariant does this change preserve?**
<!-- Name it, ideally by its ID from the table in SECURITY.md — e.g. "S3: revoking a
     capability revokes its entire derivation subtree, system-wide". -->

**What is the witness?**
<!-- The test or proof that would fail if the invariant broke. If none exists, adding it is
     part of this PR — see CONTRIBUTING.md. "No test exists" is not an exemption. -->

**Does this change weaken any invariant, deliberately or otherwise?**
<!-- An honest, documented weakening is acceptable; a silent one is not. If yes, update
     docs/LIMITATIONS.md in this PR. -->

**New attack surface or trust assumption introduced?**
<!-- New syscalls, capabilities, rights, kernel objects, or anything newly reachable from
     ring 3. -->

---

## Testing performed

Tick what you actually ran, and paste the relevant output if a test is central to the change.

- [ ] `make` — builds cleanly, no new warnings
- [ ] `cargo test --manifest-path rust/Cargo.toml --release`
- [ ] `cargo clippy --manifest-path rust/Cargo.toml --release --all-targets -- -D warnings`
- [ ] `make smoke` — boots to the ring-3 login prompt
- [ ] `make smoke-captest` — capability conformance (**run this for any authorisation change**)
- [ ] `make reproducible-build` — still byte-for-byte identical
- [ ] Subsystem self-tests, list which: <!-- smoke-wx / smoke-smp / smoke-fs / smoke-cow / smoke-tpm / ... -->
- [ ] New or updated tests added for the logic this PR changes

> **Note.** The security-specific `smoke-*` jobs are **not** merge-gating in CI (finding
> **[C-6]**, roadmap 4.2). Run them locally — CI will not stop you.

---

## Documentation

- [ ] `docs/SYSCALLS.md` updated (new or changed syscall)
- [ ] `docs/ARCHITECTURE.md` updated (design or invariant changed)
- [ ] `docs/LIMITATIONS.md` updated (limitation added, removed, or changed)
- [ ] `TESTS.md` updated (new test target)
- [ ] Code comments explain *why*, not just *what*

## Checklist

- [ ] One concern per PR — security-model changes are not bundled with feature work
- [ ] Commits are signed and use a conventional prefix
- [ ] No unrelated reformatting
- [ ] No new external dependencies without justification
- [ ] No new `unsafe` in the logic (as opposed to the FFI boundary) of
      `rust/src/capability.rs`, `memory.rs`, or `lib.rs`

## Related issues

<!-- Closes #, Depends on # -->
