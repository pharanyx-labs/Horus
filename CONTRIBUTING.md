# Contributing to Horus

Contributions are welcome at every level, from a user command to the capability algebra. One
rule here is stricter than in most projects: **a change to a security-critical path states the
property it keeps and ships the test that would fail if it broke.**

## Before you start

1. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): how the system is built and why.
2. [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md): what does not work. Many good ideas are known
   gaps with a design already written down.
3. [`docs/ROADMAP.md`](docs/ROADMAP.md): what comes next, in order. "What happens next" at the
   top is where effort counts most.

## Setting up

```bash
git clone https://github.com/pharanyx-labs/Horus.git
cd Horus
rustup target add x86_64-unknown-none
sudo apt-get install -y build-essential binutils make \
    xorriso grub-pc-bin grub-common mtools qemu-system-x86

make                # build kernel.elf
make smoke          # boot headless and wait for the ring-3 login prompt
make smoke-captest  # the capability conformance suite
```

`make test` runs the Rust unit tests and a clean rebuild; it does not boot anything. The
`smoke-*` targets are the integration tests. [`docs/BUILDING.md`](docs/BUILDING.md) is the full
build reference.

## The workflow

1. **Open an issue first** for anything non-trivial, so the design is discussed before the code.
2. **Branch from `main`** with a conventional prefix: `feat/`, `fix/`, `docs/`, `ci/`,
   `refactor/`, `harden/`, `verify/`, `test/` or `chore/`.
3. **One concern per pull request.** A security-model change is never bundled with feature work.
4. **Run the tests the change touches** before pushing: at least `make smoke` and
   `make smoke-captest`, plus the `smoke-*` targets for the subsystem, plus the
   `tools/check_*.py` checkers.
5. **Open the pull request** and fill in the template honestly: tick only what you ran.

`main` requires signed commits, linear history and every required check. The CI gate is one
aggregated check that needs every job `.github/ci-gating.yml` marks as gating; a new CI job
fails the `ci-gating` check until it is classified there.

## Commit messages

A conventional prefix, and a subject that says in plain words what was wrong or what is now
true. The body explains **why**: what was tried, what failed, and why the final approach is
right. On a security-critical path, end with the property kept and its witness:

```
fix(capability): a stale snapshot of a revoked capability still validated

The generation table was keyed by object, so two independent capabilities to
one object shared a cell, and generation 0 had to be treated as always valid.
Every capability in the kernel had generation 0, so the backstop never fired.

Key it by serial and check strict equality, so each capability has its own
cell and 0 is no longer an escape hatch.

Invariant preserved: a revoked capability, or any detached snapshot of one,
fails validation (SECURITY.md S5).
Witness: rust/src/capability.rs test_revoke_invalidates_pre_revoke_snapshot,
         make smoke-captest.
```

## The invariant rule

The security argument is the property table in [`SECURITY.md`](SECURITY.md): each row is a
claim, the code that enforces it, and the test that witnesses it. If your change touches any of
the following, the pull request names the property it keeps and the test or proof that shows it:

- `src/kernel/capability.c`, `rust/src/capability.rs`: the capability algebra
- `src/kernel/syscall*.c`: dispatch and authorisation
- `src/kernel/paging.c`: address-space isolation, user copies, W^X
- `src/kernel/scheduler.c`: switching, locking, flush-on-switch
- `src/kernel/loader.c`, `rust/src/lib.rs`: ELF loading
- `src/kernel/storage.c`, `src/kernel/crypto.c`, `src/kernel/tpm.c`: data at rest and measured boot
- `.github/workflows/`, `Makefile`, `linker64.ld`: the build is part of the trusted base

**"No test exists for that" is not an exemption; writing it is the work.** And a test that
cannot fail is not a test: a new gate gets a **control arm**, a build flag that puts the defect
back, registered in `.github/gate-pairs.yml` and in the defect-flag table of
[`docs/BUILDING.md`](docs/BUILDING.md), under which the gate must go red.

A deliberate weakening (for performance, say) is stated in the pull request and in
`docs/LIMITATIONS.md`. An honest, recorded weakening can be accepted; a silent one cannot.

## Code style

**C.** `-std=gnu99`, freestanding: no libc and no floating point. Clean under `-Wall -Wextra`.
Four-space indent, braces on the same line. Comment the why: the invariant a block keeps, the
hazard it avoids, the bug it fixed. Name symbols in comments, never line numbers. Fail closed: a
path that cannot establish authority returns an error.

**Rust.** `no_std`, clean under `cargo clippy --all-targets -- -D warnings`. `unsafe` only at the
FFI boundary, and every `unsafe` function carries a `# Safety` section stating what the caller
must uphold. Every FFI function checks its own inputs; never assume the C side did. Unit tests
beside the code, and a Kani proof where the property is algebraic ([`rust/KANI.md`](rust/KANI.md)).

**Assembly.** Comment every non-obvious instruction, the registers it clobbers and the CPU state
it assumes.

**Documentation.** British English, and no em dashes in any form; `tools/check_prose_style.py`
enforces both. A count that can be derived is declared in `.github/doc-claims.yml` rather than
typed and trusted.

## Tests

[`TESTS.md`](TESTS.md) is the catalogue. Most integration tests follow one shape: a `*_SELFTEST`
flag builds a self-test into the kernel or a ring-3 program that prints `NAME: PASS`, and a
`make smoke-<name>` target boots it and waits for the marker. Copy an existing target. Prefer
tests that try the forbidden thing and require the refusal over tests of the happy path.

## Reporting bugs and vulnerabilities

**Vulnerabilities: never in a public issue.** Follow [`SECURITY.md`](SECURITY.md).

**Other bugs:** open an issue with the commit, the build configuration, the exact command and
the serial output. `dmesg` from inside the running system is often the most useful attachment.

## Review

Most of Horus is written by Claude, which merges its own pull requests once every required check
passes; the maintainer sets direction and decides changes to the security model. A pull request
from outside the project is not merged that way: it waits for the maintainer. Otherwise no human
reviews a change before it lands (`docs/LIMITATIONS.md` 5.1). **If you know kernels, capability
systems or formal methods and would review the capability paths, that is the most valuable
contribution available.** Open an issue and say so.

## Licence

Contributions are accepted under the [MIT Licence](LICENSE). By opening a pull request you agree
that your contribution is licensed under it.
