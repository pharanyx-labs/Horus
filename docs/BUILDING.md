# Building Horus

Toolchain requirements, build targets, build flags, and how to run Horus under QEMU. Horus is **x86-64 only** — the kernel runs in 64-bit long mode and there is no 32-bit kernel build.

---

## Toolchain requirements

### Required (all builds)

| Tool | Purpose | Minimum |
|---|---|---|
| GCC | C compiler and assembler driver | 9.x |
| GNU Binutils (`ld`, `objcopy`) | Linker and binary tools | 2.34 |
| GNU Make | Build system | 4.x |
| Rust + Cargo | Rust security core | stable (2021 edition) |

### Required for ISO and QEMU

| Tool | Purpose |
|---|---|
| `xorriso` | ISO image creation |
| `grub-pc-bin` / `grub-common` | GRUB2 Multiboot2 modules + `grub-mkrescue` |
| `mtools` | `mformat`, required by `grub-mkrescue` |
| `qemu-system-x86_64` | Emulation / boot tests |

### Optional

| Tool | Purpose |
|---|---|
| `swtpm` | Software TPM 2.0, required only by the `smoke-tpm*` targets (measured boot / sealing) |

### Installing on Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install \
    build-essential gcc binutils make \
    xorriso grub-pc-bin grub-common mtools \
    qemu-system-x86 swtpm

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup target add x86_64-unknown-none
```

---

## Build targets

### `make` / `make all`

Builds `kernel.elf` (x86-64): compiles the Rust crate to `libhorus_shell.a`, all C/assembly and the core userspace binaries, and links with `linker64.ld`.

### `make run`

Builds `boot.iso` and launches QEMU: 512 MB RAM, `qemu64` CPU with AES/RDRAND/SMEP/SMAP, `-machine accel=kvm:tcg` (KVM when available), no display, console + monitor multiplexed onto stdio (`-serial mon:stdio`; Ctrl-A X quits, Ctrl-A C reaches the monitor). It also ships the ported GNU coreutils and their man pages as boot modules by default (`RUN_MODULES=1`), so `/bin` comes up populated and `man <name>` reads `/usr/share/man`; set `RUN_MODULES=0` for a module-free boot. Default login: `user` / `password` (or `root` / `rootpass`).

### `make boot.iso` / `make clean`

`boot.iso` builds the bootable ISO without launching QEMU. `clean` removes compiled objects, the Rust build cache, and `tools/mkheadered` (it keeps the untracked `boot.iso` and the gitignored `newlib/install`).

### `make test`

Runs the **91** Rust unit tests across the security core (see [TESTS.md](../TESTS.md)), then a clean full build to verify compilation.

### `make reproducible-build`

Clean-builds twice with a fixed `SOURCE_DATE_EPOCH` (2021-01-01 UTC) and fails if the two `kernel.elf`/`boot.iso` are not byte-for-byte identical; checksums recorded to `.build.sha`.

### `make security`

Runs the security scanners (Semgrep, Trivy, gitleaks, cppcheck, flawfinder, `cargo-audit`) and emits a CycloneDX SBOM. Advisory (non-blocking in CI).

### Headless self-tests

Each does a clean build with the relevant flag, boots headless under QEMU (`tools/smoke_test.sh`, software TCG — no host KVM needed), and asserts on a serial marker. `SMOKE_TIMEOUT=<seconds>` overrides the default. There are ~45 `smoke-*` targets, all CI-gated; the main ones:

| Target | Asserts |
|---|---|
| `make smoke` | Boots to the ring-3 login prompt with no fault/panic — the end-to-end boot check |
| `make smoke-cpu` | SMEP/SMAP/UMIP are detected *and* present in CR4 |
| `make smoke-tsd` | Ring-3 `RDTSC` raises `#GP` (CR4.TSD) and is delivered as a fault signal |
| `make smoke-wx` / `-wx-smp` | Whole-address-space W^X leaf sweep + stack guard pages (single- and multi-core) |
| `make smoke-stackguard` | Kernel/IST stack guard pages fault on overflow |
| `make smoke-elf` / `-elf64` | Loader + W^X + relocation for ELFCLASS32 (`R_386_RELATIVE`) and ELFCLASS64 (`R_X86_64_RELATIVE`) static-PIE images |
| `make smoke-aslr` | The loader randomises the image base across spawns (8 distinct high bases, > 1 GiB span) |
| `make smoke-preempt` | The timer time-slices two non-yielding ring-3 tasks |
| `make smoke-signal` | A deliberate fault runs the registered handler instead of killing the task |
| `make smoke-proc` | Ring-3 process control: exit + kill + spawn + exec + grant + signal + wait |
| `make smoke-cow` / `-nzcow` | The demand-zero/COW user contract, and the generic non-zero COW break |
| `make smoke-notify` | Async badge-carrying notifications incl. the blocking wait |
| `make smoke-pipe` | Bounded in-kernel pipes with EAGAIN + yield back-pressure |
| `make smoke-flush` | Flush-on-switch detection + policy (IBPB / L1D / MDS) |
| `make smoke-smp` / `-smt` | APs come online and run tasks; SMT siblings are parked |
| `make smoke-captest` | Capability/syscall conformance, asserting mostly on refusals |
| `make smoke-session` / `-session-smp` | Scripted integration: drives the real ring-3 shell over serial (auth + least privilege) |
| `make smoke-fs` (`STORAGE=ata`) | The ring-3 `fs_server` + a client drive the full path over IPC |
| `make smoke-fs-persist` / `-perms` / `-conc` / `-wal` / `-large` | Persistence across reboot, POSIX permissions, multi-client concurrency, journal replay, large/double-indirect files (`-conc` also regresses per-task x87/SSE context) |
| `make smoke-init-fs` | The `init`-delegated `fs_server` driven end-to-end |
| `make smoke-newlib` | The newlib libc port over the POSIX fd layer (first run fetches + builds newlib) |
| `make smoke-console` / `-console-isolation` / `-console-smp` | The ring-3 console server; a console-driver fault is contained |
| `make smoke-mapphys` / `-ioport` / `-irq` | The three device-delegation mechanisms (`CAP_IO_DEVICE`) |
| `make smoke-modules` / `-coreutils-shell` / `-modules-tamper` | Coreutils shipped as GRUB modules, provisioned into `/bin` and run; and refusal of a tampered module (SHA-256 manifest) |
| `make smoke-tpm` / `-tpm-tamper` / `-tpm-seal` / `-tpm-seal-roundtrip` | Measured boot (PCR 8/9 vs host-recomputed) + TPM-sealed vdisk KEK (needs `swtpm`) |
| `make smoke-e820` / `-aspace` | E820 pool sizing; address-space reclaim on task-slot reuse |

### The newlib dependency

`newlib/` is an upstream dependency (gitignored, absent from a fresh clone). The first target that needs the libc port runs `tools/build_newlib.sh`, which fetches newlib 4.5.0 from sourceware (verifying a pinned SHA-256), builds it against `newlib/tools/x86_64-elf-*` (thin wrappers aiming the host gcc at a 64-bit freestanding target, flags kept in sync with `USERSPACE_CFLAGS`), and installs under `newlib/install`. Under a minute; no-ops once built; `make clean` keeps it; CI caches it on the script's hash.

---

## Build flags

Pass as `make FLAG=VALUE`.

| Flag | Default | Effect |
|---|---|---|
| `RUST_ENABLED` | `1` | If `0`, links C stub shims instead of the Rust library |
| `DEBUG_SHELL` | `0` | Enables the in-kernel debug shell |
| `MINIMAL_SECURE` | `0` | Strips optional kernel features for a smaller attack surface |
| `SMP` | `1` | **Default-on.** Brings up the application processors; `SMP_CPUS` sets the guest core count. `SMP=0` compiles the subsystem out and boots single-core |
| `STORAGE_ATA` | `0` | FS smoke/self-test targets prefer the ATA path; at runtime the kernel always probes for a disk and falls back to the RAM vdisk. `BLOCKS_PER_DISK` sizes the volume |
| `COREUTILS_MODULES` | `0` | Ships the ported GNU coreutils **and man pages** as GRUB modules (not baked into the kernel); the `fs_server` provisions binaries into `/bin` and man pages into `/usr/share/man` at boot. `COREUTILS_MODULE_SET` selects utilities (default: all; the 16 MiB volume holds every one). `make run` enables it by default (`RUN_MODULES=1`) |
| `*_SELFTEST` | `0` | Boot-time self-tests: `ELF_`, `ELF64_`, `ASLR_`, `PREEMPT_`, `SIGNAL_`, `PROC_`, `COW_`, `NOTIFY_`, `FS_`, `INIT_FS_`, `PERSIST_`, `PERM_`, `CONC_`, `BIGFILE_`, `NEWLIB_`, `SMP_`, `WX_`, `TSD_`, `PIPE_`, and the TPM ones — each embeds and runs the matching in-kernel test at boot |

> The `DEBUG_SHELL=1`, `MINIMAL_SECURE=1`, and `SMP=1` configurations are covered by a CI build matrix (the `altconfigs` job).

---

## Userspace programs

Core userspace (`init`, `shell`, `fs_server`, `console_server`, `hello`, `captest`, plus self-test drivers) are compiled as **static-PIE** 64-bit ELF binaries (`EM_X86_64`, `ET_DYN`, linked with `userspace/pie.ld`) running under the GDT's 64-bit user code segment. `do_spawn` picks a random page-aligned load base and the loader applies `R_X86_64_RELATIVE` relocations there; `tools/mkheadered` prepends the custom program header the loader consumes. A flat-binary fallback remains for non-ELF images. Larger programs link against the newlib libc port over a per-process POSIX fd layer (`malloc`/`sbrk`/`brk`).

The loader still supports ELFCLASS32 (`R_386_RELATIVE`); `userspace/elftest.o` is deliberately built 32-bit (`USERSPACE_CFLAGS_32`) so `make smoke-elf` keeps gating that path.

```bash
make userspace       # build all userspace binaries
```

The kernel image bundles only the core binaries above, so rebuilding after changing one requires re-running `make` from the top. The **ported GNU coreutils are not bundled** — they ship as GRUB modules (`COREUTILS_MODULES=1`) loaded into RAM outside the kernel image, provisioned into `/bin` at boot. See `userspace/ports/coreutils/README.md`.

---

## Rust crate details

The crate at `rust/` builds as a `staticlib` with `panic = "abort"`, `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `strip = true`; the resulting `libhorus_shell.a` is linked `--whole-archive`. A missing Cargo or `x86_64-unknown-none` target fails the build with an explicit error.

---

## Troubleshooting

- **`grub-mkrescue failed`** — install `grub-pc-bin grub-common xorriso mtools`.
- **`cargo not found`** — install Rust via `rustup`.
- **`rust target x86_64-unknown-none missing`** — `rustup target add x86_64-unknown-none`.
- **Linker errors about missing `rust_*` symbols** — ensure `RUST_ENABLED=1` (default) or the crate built; pass `RUST_ENABLED=0` to use the C stubs.
- **`smoke-tpm*` fails to start** — install `swtpm`; those targets need a software TPM 2.0.
- **QEMU shows nothing / serial only** — the boot configures GRUB's terminal to serial; connect via `nc localhost 4445`.
