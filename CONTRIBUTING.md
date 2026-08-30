# Contributing to Horus

Horus is a research microkernel with meaningful work at every level — from userspace
utilities to the capability algebra. Contributions of all sizes are welcome.

This document explains how to contribute, and the one rule that is stricter here than in most
projects: **on security-critical paths, a change must state the invariant it preserves and
ship the test that witnesses it.**

---

## Before you start

Read, in this order:

1. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how the system is built and why.
2. [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) — what does not work. Many good ideas are
   already known gaps.
3. [`docs/ROADMAP.md`](docs/ROADMAP.md) — what is planned, and in what order.
4. [`docs/AUDIT.md`](docs/AUDIT.md) — the current audit. For the *status* of a finding, read
   [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md), which is authoritative.

If you want high-impact work, the roadmap's **Track 0** items are the ones that matter most,
and **Track 0.1** (capability-addressed IPC) is the single most valuable change available.

---

## Setting up

```bash
git clone https://github.com/pharanyx-labs/Horus.git
cd Horus
rustup target add x86_64-unknown-none
sudo apt-get install -y build-essential binutils make \
    xorriso grub-pc-bin grub-common mtools qemu-system-x86

make          # build
make smoke    # headless boot; asserts the ring-3 shell comes up
make test     # the full local self-test sweep
```

[`docs/BUILDING.md`](docs/BUILDING.md) has the complete build reference.

---

## The workflow

1. **Open an issue first** for anything non-trivial, so the design can be discussed before
   you write code. Small fixes can go straight to a PR.
2. **Branch from `main`** using a conventional prefix: `feat/`, `fix/`, `docs/`, `ci/`,
   `refactor/`, `harden/`, `verify/`, `test/`, `chore/`.
3. **Keep the change focused.** One concern per PR. Security-model changes in particular must
   not be bundled with feature work — they need to be reviewable in isolation.
4. **Run the relevant tests locally** before pushing. At minimum `make smoke` and
   `make smoke-captest`; run whichever `smoke-*` targets cover the subsystem you touched.
5. **Open a PR** against `main` and fill in the template.

`main` is protected: linear history, signed commits, no force pushes, and required status
checks. Your commits **must be signed** — see
[GitHub's signing guide](https://docs.github.com/en/authentication/managing-commit-signature-verification).

---

## Commit messages

Conventional-commit prefix, imperative subject, and a body that explains **why**.

```
fix(capability): serial-key the lineage generation backstop

The generation table was keyed by `object`, so two independent capabilities
to the same object shared a cell. The only way to keep them independent was
to treat generation 0 as always-valid — and every capability in the running
kernel was created with generation 0, so the backstop was dormant: a stale
snapshot passed the check unconditionally.

Key by `serial` instead and check strict equality, so each capability gets
its own cell and gen 0 is no longer an escape hatch.

Invariant preserved: a revoked capability, or any detached snapshot of one,
fails validation (SECURITY.md S5).
Witness: rust/src/capability.rs test_revoke_by_values_invalidates_snapshot,
         make smoke-captest.
```

The existing history is a good model. Commit messages here routinely record what was tried,
what failed, and why the final approach is correct — that is deliberate and worth matching.

---

## The invariant rule

Horus's security argument is a list of claims, each with a mechanism and a witness (see the
table in [`SECURITY.md`](SECURITY.md)). A change to a security-critical path must keep that
list true.

**If your change touches any of these, your PR must state the invariant it preserves and
point at the test or proof that witnesses it:**

- `src/kernel/capability.c`, `rust/src/capability.rs` — the capability algebra
- `src/kernel/syscall*.c` — syscall dispatch and authorisation
- `src/kernel/paging.c` — address-space isolation, user copies, W^X
- `src/kernel/scheduler.c` — context switching, locking, flush-on-switch
- `src/kernel/loader.c`, `rust/src/lib.rs` — ELF loading
- `src/kernel/storage.c`, `src/kernel/crypto.c`, `src/kernel/tpm.c` — data at rest, measured boot
- `.github/workflows/`, `Makefile`, `linker64.ld` — the build is part of the TCB

**"No test exists for that" is not an exemption — it is the work.** The project's most
serious open defect (**[C-1]**) is precisely a documented property with no test binding it to
the code.

If your change *weakens* an invariant deliberately (e.g. for performance), say so explicitly
in the PR and in `docs/LIMITATIONS.md`. An honest, documented weakening is fine; a silent one
is not.

---

## Code style

**C (kernel).**
- C99 (`-std=gnu99`), freestanding. No libc, no floating point (the kernel is built
  `-mno-sse -mno-mmx -mno-80387`).
- Builds clean under `-Wall -Wextra -Wformat-security -Werror=vla`. Warnings are not
  acceptable.
- 4-space indent, no tabs. Braces on the same line.
- **Comment the why, not the what.** Explain the invariant a block maintains, the hazard it
  avoids, or the bug it fixes. The existing code does this well; match it.
- Fail closed. A path that cannot establish authority returns an error; it does not proceed
  hopefully.

**Rust (security core).**
- `no_std`. Builds clean under `cargo clippy --all-targets -- -D warnings`.
- `unsafe` only at the FFI boundary, with a `# Safety` doc comment stating the caller's
  obligations.
- Every FFI function validates its own inputs. Never assume the C side checked.
- Unit tests alongside the code. Add a Kani proof where the property is algebraic.

**Assembly.** Comment every non-obvious instruction. Note which registers are clobbered and
what state the CPU is in.

---

## Testing

Three layers — see [`TESTS.md`](TESTS.md) for the full catalogue.

1. **Rust unit tests and Kani proofs** — `cargo test --manifest-path rust/Cargo.toml`.
2. **QEMU integration self-tests** — `make smoke-<name>`. Each boots a purpose-built kernel
   configuration and asserts a marker on the serial console.
3. **Scripted shell sessions** — Python drivers under `tools/` that type into the real ring-3
   shell and assert on the output.

**Adding a self-test.** Most follow the same shape: a `*_SELFTEST` compile flag guards a
routine in `src/kernel/selftest.c` (or a ring-3 program in `userspace/`) that prints
`NAME: PASS`, and a `make smoke-name` target boots it and greps for that marker. Copy an
existing target.

**Prefer adversarial tests.** `smoke-modules-tamper` corrupts a boot module and asserts it is
refused; `smoke-tpm-tamper` asserts the PCRs diverge. Testing that a control *fires* is more
valuable than testing that the happy path works, and this project takes that seriously.

---

## What makes a PR easy to merge

- One concern, clearly described.
- The invariant statement and its witness, where applicable.
- Tests added, and the `make smoke-*` targets you ran listed in the PR body.
- No unrelated reformatting.
- No new warnings.
- Documentation updated in the same PR when behaviour changes — especially
  `docs/LIMITATIONS.md` if a limitation is added or removed.

---

## Reporting bugs and vulnerabilities

**Security vulnerabilities: do not open a public issue.** Follow the private disclosure
process in [`SECURITY.md`](SECURITY.md).

**Ordinary bugs:** open an issue with the commit hash, your build configuration
(`make`, `make SMP=0`, etc.), the exact command, and the serial output. `dmesg` output from
inside the running system is often the most useful thing you can attach.

---

## A note on review

Horus is currently maintained by one person, and the branch ruleset does not require reviewer
approval — a limitation documented honestly in [`SECURITY.md`](SECURITY.md) and tracked as
roadmap item 4.1.

**If you have kernel, capability-system, or formal-methods background and would be willing to
review security-critical changes, that is the single most valuable contribution available to
this project.** Open an issue and say so.

---

## Licence

Contributions are accepted under the [MIT Licence](LICENSE). By submitting a pull request you
agree that your contribution is licensed under it.
