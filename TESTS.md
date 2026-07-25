# Testing Horus

## Current state

The Rust security core has **91 unit tests**, and `.github/workflows/ci.yml` gates every push and PR with **52 jobs** — three advisory (`security` SAST/SBOM, `fuzz`, `kani`; their steps are `continue-on-error`, so they report but never block a merge) and the rest gating. Of those, only four are **required status checks** in branch protection (Rust+clippy, kernel+ISO build, QEMU smoke-boot, reproducible build); the others run and must be green but are not yet promoted to required (see [ROADMAP.md](docs/ROADMAP.md) Track 0.3).

Beyond the unit tests, ~45 **headless QEMU self-tests** boot the real kernel under software TCG (no host KVM needed), capture the serial port, and assert on a marker — failing on any `PAGE FAULT` / CPU exception / `PANIC` / triple-fault. Reaching the login prompt alone proves the whole boot path: kernel init, the loader, per-task paging with W^X stacks, dropping to ring 3, the syscall dispatch table servicing `SYS_WRITE`, and console output. A coverage-guided syscall/FFI fuzz harness under QEMU is still the highest-value remaining contribution.

---

## Running the tests

### Rust unit tests

```bash
cargo test --manifest-path rust/Cargo.toml --release
```

Coverage across the security core:

- `capability.rs` — mint with a rights subset (no escalation), transfer, system-wide / cross-task revocation, **descendant-only** revocation (a child's revoke leaves parent/siblings/same-object peers intact; overflow falls back to a complete object sweep), primordial-root revocation refusal, the serial-keyed lineage backstop (finding 3.3: a gen-0 snapshot is invalidated after revoke; a distinct lineage cell is untouched), stale-generation rejection, revoke-by-values invalidating a pre-revoke snapshot (the IPC TOCTOU guard), fresh-serial allocation across the u32 wrap.
- `memory.rs` — the refcount-table trust boundary (a wrong pointer/length is refused, not dereferenced), saturation, decrement-at-zero, valid-user-phys bounds, page alloc/free LIFO + exhaustion.
- `lib.rs` — page-fault validation, rights-subset checks, demand-paging (COW / demand-zero) policy, FS-op right enforcement, command dispatch, the W^X page policy (`rust_user_page_is_noexec`), the signal-handler-address window (`rust_signal_handler_addr_ok`), and the ELF-parse validators.
- `rng.rs` — ChaCha20 vs the RFC 8439 vector, reseed behaviour.
- `sha256.rs` — SHA-256 / HMAC / HKDF / PBKDF2 vs published vectors.
- `blake2b.rs` — BLAKE2b-512 vs the RFC 7693 vector, multi-block/empty inputs.
- `argon2.rs` — Argon2id vs `argon2-cffi` tags, single- and multi-lane (`p=2`/`p=4`), incl. the kernel's exact 4 MiB / 3-pass / 1-lane config.
- `aead.rs` — the ChaCha20 + HMAC-SHA256 AEAD: round-trip, tampered-ciphertext/tag rejection (fail-closed), wrong-AAD rejection, nonce separation.
- `audit.rs` — the forward-secure audit log: per-entry MAC determinism and sequence/content/key binding, the domain-separated chain, order-sensitivity of the head, the one-way key ratchet + erase, a full record-then-verify cycle with tamper detection, the constant-time compare, FFI null rejection.
- `auth.rs` — auth/sudo lockout arithmetic, the anti-spray throttle, least-privilege sudo frame rights.
- `ps.rs` — task state-name labels.

Machine-checked **Kani** proofs (advisory `kani` job) cover, over the entire `u32` input space, that mint never escalates rights, serials are never reserved/zero, revocation hits exactly the target's subtree, and the lineage backstop invalidates a recorded generation without touching a distinct cell.

### Headless self-tests

```bash
make smoke          # SMOKE_TIMEOUT=<seconds> to override the default
```

Selected markers (there are ~45 `smoke-*` targets; see [BUILDING.md](docs/BUILDING.md) for the full list):

| Target | Marker / asserts |
|---|---|
| `make smoke` | reaches the ring-3 shell banner + login prompt |
| `make smoke-cpu` | `CPU_SELFTEST: PASS` — SMEP+SMAP+UMIP detected *and* set in CR4 |
| `make smoke-tsd` | ring-3 `RDTSC` raises `#GP` under `CR4.TSD` and is delivered as a fault signal |
| `make smoke-wx` / `-wx-smp` | kernel-image r-x/r--/rw-, `CR0.WP`/`EFER.NXE` engaged, stack guards present, and **no leaf anywhere is both writable and executable** (single- and multi-core) |
| `make smoke-stackguard` | kernel/IST stack guard pages fault on overflow |
| `make smoke-elf` / `-elf64` | loader + W^X + relocation for ELFCLASS32 (`R_386_RELATIVE`) and ELFCLASS64 (`R_X86_64_RELATIVE`) |
| `make smoke-aslr` | image base varies across 8 spawns, spanning > 1 GiB |
| `make smoke-preempt` / `-signal` / `-proc` | timer time-slicing; a fault runs the handler; full ring-3 process control |
| `make smoke-cow` / `-nzcow` | the demand-zero/COW user contract; the generic non-zero COW break |
| `make smoke-notify` / `-pipe` | async badge notifications; bounded pipes with back-pressure |
| `make smoke-flush` / `-smt` | flush-on-switch detection + policy; SMT siblings parked |
| `make smoke-smp` / `-aspace` / `-e820` | APs run tasks concurrently; address-space reclaim; E820 pool sizing |
| `make smoke-fs` (+ `-perms`/`-conc`/`-persist`/`-wal`/`-large`) | server round-trip, permissions, concurrency (also the x87/SSE regression), reboot persistence, journal crash-recovery, large files |
| `make smoke-init-fs` / `-newlib` | the `init`-endowed `fs_server`; the newlib libc port |
| `make smoke-captest` | `CAPTEST: PASS <n> checks` — conformance asserting mostly on refusals |
| `make smoke-session` / `-session-smp` / `-console-smp` | drives the real ring-3 shell over serial (auth + least privilege), incl. under `-smp 4` (regression guards for the SMP console-output-doubling and fabricated-reply races) |
| `make smoke-console` / `-console-isolation` | the ring-3 console server; a console-driver fault is contained |
| `make smoke-mapphys` / `-ioport` / `-irq` | the three `CAP_IO_DEVICE` device-delegation mechanisms |
| `make smoke-modules` / `-coreutils-shell` / `-modules-tamper` | coreutils as GRUB modules provisioned into `/bin` and run; a tampered module is refused (SHA-256 manifest) |
| `make smoke-tpm` / `-tpm-tamper` / `-tpm-seal` / `-tpm-seal-roundtrip` | measured boot (PCR 8/9 vs host-recomputed) + TPM-sealed vdisk KEK (needs `swtpm`) |

### Full build test

```bash
make test          # cargo tests, then a clean full build
```

### Manual testing under QEMU

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

## What still needs tests

- **Deeper booted-kernel integration.** `tools/session_test.py` seeds this (scripted login/shell with response assertions); broaden the scenarios (ELF under W^X, IPC/FS round-trips, a capability revocation observed end-to-end) and grow the assertion vocabulary.
- **TLA+ specs.** `docs/cap_algebra.tla` and `docs/paging_isolation.tla` model the capability and paging invariants but are not model-checked in CI. Wiring TLC/Apalache into the pipeline (and extending `cap_algebra.tla` to the derivation-tree revocation) would close the loop.
- **A real C-side test harness.** `tests/test_capability.c` is a standalone illustration reimplementing a simplified `cap_lookup`; it is not linked against the kernel's `capability.c`. A host harness linking the real file with mocked `tasks[]` / `get_current_task()` would give the C guards genuine coverage.
- **Fuzzing.** A `cargo-fuzz` target over the pointer-taking FFI entry points is cheap to stand up (host `fuzz` job seeds it); a `syzkaller`-style syscall fuzzer under QEMU is the larger effort.

Contributions to any of the above are very welcome.
