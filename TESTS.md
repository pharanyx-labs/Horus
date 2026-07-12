# Testing Horus

## Current state

The Rust security core has **54 unit tests**, and a CI pipeline gates every push and pull request (`.github/workflows/ci.yml`). Six **headless QEMU boot tests** run in CI: `make smoke` boots to the ring-3 login prompt with no fault, `make smoke-elf` boots a real multi-segment static-PIE ELF at a randomised base and asserts the loader enforced W^X **and** applied its `R_386_RELATIVE` relocation, `make smoke-preempt` asserts the timer time-slices two non-yielding ring-3 tasks, `make smoke-signal` faults a task on purpose and asserts its handler runs, `make smoke-proc` drives ring-3 process control (exit/kill/spawn/exec/grant/signal/wait/fault-wait), and `make smoke-smp` asserts the application processors come online and run tasks concurrently. A further set of self-tests exists as local targets (not yet gated in CI): the filesystem server (`make smoke-fs`, plus `smoke-fs-persist`, `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-wal`, `smoke-fs-large` for persistence, per-file permissions, multi-client concurrency, the write-ahead journal, and large/double-indirect files), the delegated boot-through-`init` filesystem path (`smoke-init-fs`), and the newlib libc port (`smoke-newlib`). There is still no deeper booted-kernel integration test (driving the shell through scripted sessions) or fuzz harness; those are the highest-value remaining contributions.

---

## Running the tests

### Rust unit tests

```bash
cargo test --manifest-path rust/Cargo.toml --release
```

This runs the unit tests across the security core:

- `capability.rs` — mint with a subset of rights (no escalation), system-wide / cross-task revocation, stale-generation rejection, lineage low-bit collision safety, fresh-serial allocation across the u32 wrap boundary
- `memory.rs` — the refcount-table trust boundary (a wrong pointer or length is refused, not dereferenced), saturation, decrement-at-zero, valid-user-phys bounds, and the page alloc/free LIFO + exhaustion guards
- `lib.rs` — page-fault validation, capability-rights subset checks, demand-paging (COW / demand-zero) policy, FS-operation right enforcement, command dispatch, the W^X page policy (`rust_user_page_is_noexec`), and the signal-handler-address window (`rust_signal_handler_addr_ok`)
- `rng.rs` — ChaCha20 against the RFC 8439 vector, reseed behaviour
- `sha256.rs` — SHA-256 / HMAC / HKDF / PBKDF2 against published known-answer vectors
- `blake2b.rs` — BLAKE2b-512 against the RFC 7693 known-answer vector, plus multi-block/empty inputs
- `argon2.rs` — Argon2id against `argon2-cffi` reference tags, single-lane and multi-lane (`p=2`/`p=4`), incl. the kernel's exact 4 MiB / 3-pass / 1-lane config
- `aead.rs` — the ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD: seal/open round-trip, tampered-ciphertext and tampered-tag rejection (fail-closed), wrong-AAD rejection, and nonce separation
- `audit.rs` — the tamper-evident audit MACs: per-entry MAC determinism, sequence/content/key binding, domain-separated chain IV, order-sensitivity of the chain head, a full record-then-verify cycle with tamper detection, the constant-time MAC compare, and FFI null rejection
- `auth.rs` — auth/sudo lockout arithmetic, the anti-spray throttle, and least-privilege sudo frame rights
- `ps.rs` — task state-name labels

### Headless self-tests

```bash
make smoke          # SMOKE_TIMEOUT=<seconds> to override the default 40
```

Each self-test target clean-builds with the relevant flag, boots under QEMU with no display (`tools/smoke_test.sh`, software TCG so it needs no host KVM), captures the serial port, and asserts on a marker (and fails on any `PAGE FAULT` / CPU exception / `PANIC` / triple-fault). Reaching the login prompt proves the whole boot path end to end: kernel init, the loader, per-task paging including the W^X stack, dropping to ring 3, the syscall dispatch table servicing `SYS_WRITE`, and console output.

| Target | Marker |
|---|---|
| `make smoke` | reaches the ring-3 shell banner + login prompt |
| `make smoke-elf` | `ELF_SELFTEST: PASS` |
| `make smoke-preempt` | `PREEMPT_SELFTEST: PASS` |
| `make smoke-signal` | `SIGNAL_SELFTEST: PASS` |
| `make smoke-proc` | `PROC_SELFTEST: PASS exit+kill+spawn+exec+grant+signal` (+ `wait OK` / `fault-wait OK`) |
| `make smoke-smp` | `SMP_SELFTEST: PASS` |
| `make smoke-fs` | `FS_SELFTEST: PASS` (local; `STORAGE=ata` for a real disk) |
| `make smoke-fs-persist` | file written on boot 1 is present on boot 2 against the same disk image (local) |
| `make smoke-fs-perms` | per-file POSIX ownership/permissions enforced against kernel-attested uid (local) |
| `make smoke-fs-conc` | three concurrent clients each receive only their own replies (local) |
| `make smoke-fs-wal` | a write committed then crashed pre-apply is replayed from the journal on the next mount (local) |
| `make smoke-fs-large` | reads/writes across direct + single- + double-indirect blocks (local) |
| `make smoke-newlib` | `NEWLIB_SELFTEST: PASS` (local) |

### Full build test

```bash
make test          # cargo tests, then a clean full build
```

### Manual testing under QEMU

The most useful end-to-end check is still booting and exercising Horus interactively:

```bash
make run            # then connect: nc localhost 4445
```

```
login: user
password: password
whoami
ls
help
```

---

## Continuous integration

`.github/workflows/ci.yml` runs **eleven jobs**, all hard gates:

1. **rust** — `cargo test --release` and `cargo clippy --all-targets -- -D warnings`
2. **kernel** — builds `kernel.elf` and a bootable ISO (x86-64) and uploads them as artifacts
3. **altconfigs** — a build matrix over `DEBUG_SHELL=1` and `MINIMAL_SECURE=1`
4. **smoke** — `make smoke` (headless boot to the shell/login prompt, no fault)
5. **smoke-elf** — `make smoke-elf` (ELF loader + W^X + relocation self-test)
6. **smoke-preempt** — `make smoke-preempt` (two-task timer preemption)
7. **smoke-signal** — `make smoke-signal` (fault delivered to a registered handler)
8. **smoke-smp** — `make smoke-smp` (application processors run tasks concurrently)
9. **smoke-proc** — `make smoke-proc` (ring-3 exit/kill/spawn/exec/grant/signal/wait)
10. **reproducible** — builds `kernel.elf` twice and fails if they are not byte-for-byte identical
11. **security** — Semgrep, Trivy, gitleaks, cppcheck, flawfinder, `cargo-audit`, and a CycloneDX SBOM (advisory)

All but the security job use only first-party / pinned actions.

---

## What still needs tests

The gaps that remain:

### Deeper booted-kernel integration tests

`make smoke` covers "boot completes and userspace runs with no fault." The remaining gap is a harness that *drives* the serial port through scripted sessions and asserts on responses (a Python `pexpect` script is a natural fit): a successful/failed login, a capability denial, an ELF running under W^X. Gating `smoke-fs` and `smoke-newlib` in CI is low-hanging fruit here.

### TLA+ specs

`docs/cap_algebra.tla` and `docs/paging_isolation.tla` model the capability and paging invariants but are not model-checked in CI. Wiring TLC/Apalache into the pipeline would close the loop.

### A real C-side test harness

`tests/test_capability.c` is a standalone illustration that reimplements a simplified `cap_lookup`; it is **not** linked against the kernel's `capability.c` and is not built by the Makefile. A host harness linking the real `capability.c` with mocked `tasks[]` / `get_current_task()` would give the C guards genuine regression coverage.

### Fuzzing

The syscall interface and the Rust FFI boundary are the obvious targets. A `cargo-fuzz` target over the pointer-taking FFI entry points is cheap to stand up; `syzkaller` driving a privileged task under QEMU/KVM is the larger effort.

Contributions to any of the above are very welcome.
