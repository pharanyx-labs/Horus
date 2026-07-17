# Testing Horus

## Current state

The Rust security core has **57 unit tests**, and a CI pipeline gates every push and pull request (`.github/workflows/ci.yml`) with **24 jobs**. The **headless QEMU boot tests** run in CI: `make smoke` boots to the ring-3 login prompt with no fault, `make smoke-elf` boots a real multi-segment static-PIE ELF at a randomised base and asserts the loader enforced W^X **and** applied its `R_386_RELATIVE` relocation, `make smoke-elf64` does the same for a real **64-bit** static-PIE and asserts the loader applied its `R_X86_64_RELATIVE` relocation (loaded and inspected, never executed, so the gate is independent of the ring-3 ABI), `make smoke-aslr` spawns eight PIE images and asserts the load base actually varies (image-base ASLR was once silently disabled entirely, and nothing noticed) and that every base keeps the premap inside a single page table, `make smoke-preempt` asserts the timer time-slices two non-yielding ring-3 tasks, `make smoke-signal` faults a task on purpose and asserts its handler runs, `make smoke-proc` drives ring-3 process control (exit/kill/spawn/exec/grant/signal/wait/fault-wait), `make smoke-cow` asserts fresh heap pages read as zero from one shared read-only frame and that writing one breaks it to a private page without disturbing its sibling, `make smoke-notify` asserts an async `SYS_NOTIFY` badge reaches a task blocked in `SYS_WAIT_NOTIFY`, `make smoke-smp` asserts the application processors come online and run tasks concurrently, and the filesystem/libc suite (`make smoke-fs`, plus `smoke-fs-persist`, `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-wal`, `smoke-fs-large`, `smoke-newlib` for persistence, per-file permissions, multi-client concurrency, the write-ahead journal, large/double-indirect files, and the newlib libc port) is now gated too. Beyond the marker self-tests, `make smoke-session` drives the **real** ring-3 shell over serial through a scripted login/command session and asserts on the responses (`tools/session_test.py`). The delegated boot-through-`init` filesystem path (`make smoke-init-fs`, which boots the `fs_server` the way the real system does — spawned and endowed by ring-3 `init` rather than by the kernel) is gated too. A coverage-guided fuzz harness is still the highest-value remaining contribution.

---

## Running the tests

### Rust unit tests

```bash
cargo test --manifest-path rust/Cargo.toml --release
```

This runs the unit tests across the security core:

- `capability.rs` — mint with a subset of rights (no escalation), transfer (full-rights copy sharing the parent lineage), system-wide / cross-task revocation, primordial-root revocation refusal, stale-generation rejection, lineage-generation wraparound (skips the reserved 0, invalidates pre-wrap caps), revoke-by-values invalidating a pre-revoke snapshot (the IPC TOCTOU guard), lineage low-bit collision safety, fresh-serial allocation across the u32 wrap boundary
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
| `make smoke-elf64` | `ELF64_SELFTEST: PASS` (x86-64 `R_X86_64_RELATIVE` applied to a real 64-bit static-PIE, + W^X) |
| `make smoke-aslr` | `ASLR_SELFTEST: PASS` (image base varies across 8 spawns; premap stays inside one page table) |
| `make smoke-preempt` | `PREEMPT_SELFTEST: PASS` |
| `make smoke-signal` | `SIGNAL_SELFTEST: PASS` |
| `make smoke-proc` | `PROC_SELFTEST: PASS exit+kill+spawn+exec+grant+signal` (+ `wait OK` / `fault-wait OK`) |
| `make smoke-notify` | `NOTIFY_SELFTEST: PASS` (async `SYS_NOTIFY` badge delivered to a blocked `SYS_WAIT_NOTIFY`) |
| `make smoke-smp` | `SMP_SELFTEST: PASS` |
| `make smoke-fs` | `FS_SELFTEST: PASS` (`STORAGE=ata` for a real disk) |
| `make smoke-fs-persist` | file written on boot 1 is present on boot 2 against the same disk image |
| `make smoke-fs-perms` | per-file POSIX ownership/permissions enforced against kernel-attested uid |
| `make smoke-fs-conc` | three concurrent clients each receive only their own replies — and, since the 64-bit flip, the regression test for per-task x87/SSE context (it was the only witness that a task's `xmm` was not preserved across a syscall) |
| `make smoke-fs-wal` | a write committed then crashed pre-apply is replayed from the journal on the next mount |
| `make smoke-fs-large` | reads/writes across direct + single- + double-indirect blocks |
| `make smoke-newlib` | `NEWLIB_SELFTEST: PASS` |
| `make smoke-session` | `SESSION_TEST: PASS` — drives the real ring-3 shell over serial (auth + least-privilege) |

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

`.github/workflows/ci.yml` runs **twenty-four jobs**. Twenty-three are hard gates; the
`security` SAST/SBOM scan is advisory (every step is `continue-on-error`, so it
reports but never blocks a merge). Note `altconfigs` is one job id that fans out
into three matrix runs (`DEBUG_SHELL=1`, `MINIMAL_SECURE=1`, `SMP=1`), so the
checks list shows twenty-six.

1. **rust** — `cargo test --release` and `cargo clippy --all-targets -- -D warnings`
2. **kernel** — builds `kernel.elf` and a bootable ISO (x86-64) and uploads them as artifacts
3. **altconfigs** — a build matrix over `DEBUG_SHELL=1`, `MINIMAL_SECURE=1` and `SMP=1` (the shipping SMP config: `smoke-smp` compiles `-DSMP` too, but only together with its selftest harness)
4. **smoke** — `make smoke` (headless boot to the shell/login prompt, no fault)
5. **smoke-elf** — `make smoke-elf` (ELF loader + W^X + relocation self-test)
6. **smoke-elf64** — `make smoke-elf64` (the loader's x86-64 RELA path: loads a real 64-bit static-PIE and asserts `R_X86_64_RELATIVE` was applied, plus W^X on an ELF64 image. The image is loaded and inspected, never executed, so this gate stays independent of the ring-3 ABI — it was written while userspace was still 32-bit, and keeping it that way means the loader's RELA path is gated on its own terms rather than implicitly via the shipped binaries)
7. **smoke-aslr** — `make smoke-aslr` (spawns 8 PIE images; asserts the load base actually varies, and that every base keeps the premap inside one page table — the invariant that bounds the entropy)
8. **smoke-preempt** — `make smoke-preempt` (two-task timer preemption)
9. **smoke-signal** — `make smoke-signal` (fault delivered to a registered handler)
10. **smoke-proc** — `make smoke-proc` (ring-3 exit/kill/spawn/exec/grant/signal/wait)
11. **smoke-cow** — `make smoke-cow` (demand-zero pages share one read-only zero frame; a write breaks it to a private page without disturbing its sibling)
12. **smoke-notify** — `make smoke-notify` (async `SYS_NOTIFY` badge to a blocked `SYS_WAIT_NOTIFY`)
13. **smoke-smp** — `make smoke-smp` (application processors run tasks concurrently)
14. **smoke-fs** / **smoke-fs-perms** / **smoke-fs-conc** / **smoke-fs-persist** / **smoke-fs-wal** / **smoke-fs-large** — the encrypted filesystem suite (server round-trip, permissions, concurrency, reboot persistence, journal crash-recovery, large files). `-conc` doubles as the x87/SSE context regression: it caught a task's `xmm0` surviving into another task and being written to disk as file data, with every checksum agreeing
15. **smoke-init-fs** — `make smoke-init-fs` (the same `fs_server` round-trip, but with the server spawned and endowed by ring-3 `init` as the real system boots it, rather than by the kernel)
16. **smoke-newlib** — `make smoke-newlib` (newlib libc over the POSIX fd layer)
17. **smoke-session** — `make smoke-session` (drives the real ring-3 shell over serial: auth + least-privilege enforcement)
18. **reproducible** — builds `kernel.elf` twice and fails if they are not byte-for-byte identical
19. **security** — Semgrep, Trivy, gitleaks, cppcheck, flawfinder, `cargo-audit`, and a CycloneDX SBOM (advisory)

All but the security job use only first-party / pinned actions.

---

## What still needs tests

The gaps that remain:

### Deeper booted-kernel integration tests

`make smoke-session` (`tools/session_test.py`) seeds this: it drives the serial port through a scripted login/shell session and asserts on the responses — a failed then successful login, the kernel-attested identity via `whoami`, and a capability-gated admin op allowed for root but denied for a standard user. The remaining work is to broaden the scenarios (an ELF running under W^X, an IPC/FS round-trip, a capability revocation) and grow the assertion vocabulary. A coverage-guided fuzz harness over the syscall/FFI boundary is still absent.

### TLA+ specs

`docs/cap_algebra.tla` and `docs/paging_isolation.tla` model the capability and paging invariants but are not model-checked in CI. Wiring TLC/Apalache into the pipeline would close the loop.

### A real C-side test harness

`tests/test_capability.c` is a standalone illustration that reimplements a simplified `cap_lookup`; it is **not** linked against the kernel's `capability.c` and is not built by the Makefile. A host harness linking the real `capability.c` with mocked `tasks[]` / `get_current_task()` would give the C guards genuine regression coverage.

### Fuzzing

The syscall interface and the Rust FFI boundary are the obvious targets. A `cargo-fuzz` target over the pointer-taking FFI entry points is cheap to stand up; `syzkaller` driving a privileged task under QEMU/KVM is the larger effort.

Contributions to any of the above are very welcome.
