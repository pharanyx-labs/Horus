# Building Horus

This document covers toolchain requirements, build targets, build flags, and how to run Horus under QEMU.

---

## Toolchain requirements

### Required (all builds)

| Tool | Purpose | Minimum version |
|---|---|---|
| GCC | C compiler and assembler driver | 9.x |
| GNU Binutils (`ld`, `objcopy`) | Linker and binary tools | 2.34 |
| GNU Make | Build system | 4.x |
| Rust + Cargo | Rust security core | stable (2021 edition) |

### Required for ISO and QEMU

| Tool | Purpose |
|---|---|
| `xorriso` | ISO image creation |
| `grub-pc-bin` | GRUB2 Multiboot2 bootloader modules |
| `grub-mkrescue` | ISO assembly |
| `qemu-system-x86_64` | Emulation / boot tests |

### Installing on Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install \
    build-essential gcc binutils make \
    xorriso grub-pc-bin \
    qemu-system-x86
```

### Installing Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Then add the required target:

```bash
rustup target add x86_64-unknown-none
```

---

## Build targets

### `make` / `make all`

Builds `kernel.elf` (x86-64). This is the main build target. It will:

1. Compile the Rust crate to `rust/target/x86_64-unknown-none/release/libhorus_shell.a`
2. Compile all C and assembly source files
3. Link everything into `kernel.elf` using the linker script `linker64.ld`

```bash
make
```

### `make run`

Builds `boot.iso` and launches QEMU with the following configuration:

- 512 MB RAM
- CPU model `qemu64` with AES-NI enabled
- SDL display (VGA text mode, 80×50)
- Two serial ports: localhost:4445 (debug socket) and localhost:4444 (serial)
- No network (isolated)

```bash
make run
```

Connect to the debug serial port from another terminal:

```bash
nc localhost 4445
```

### `make boot.iso`

Builds the bootable ISO without launching QEMU. Requires `xorriso` and `grub-mkrescue`.

```bash
make boot.iso
```

### `make clean`

Removes all compiled objects, the Rust build cache, and the `tools/mkheadered` binary. Does not remove `boot.iso` (which is in `.gitignore` and not tracked).

```bash
make clean
```

### `make test`

Runs the Rust unit tests (54 across the security core — see [TESTS.md](../TESTS.md)), then does a clean full build to verify compilation.

```bash
make test
```

### `make smoke-elf`

Builds the kernel with `ELF_SELFTEST=1` (which embeds a real multi-segment ELF), boots it headless, and requires the in-kernel self-test to report `ELF_SELFTEST: PASS` on serial — a runtime check that the ELF loader maps each `PT_LOAD` with the correct W^X permissions. Does not affect the default (ship) kernel.

```bash
make smoke-elf
```

### `make smoke`

Boots the kernel headless under QEMU and asserts it reaches the ring-3 shell banner with no fault/panic — the runtime boot check. Builds `boot.iso` first; needs `qemu-system-x86_64`. `SMOKE_TIMEOUT=<seconds>` overrides the default 40 s wait.

```bash
make smoke
```

### `make reproducible-build`

Performs a clean build with a fixed `SOURCE_DATE_EPOCH` (2021-01-01 UTC) and records the SHA-256 checksums to `.build.sha`. Used to verify that the build is byte-for-byte deterministic.

```bash
make reproducible-build
```

---

## Build flags

Pass flags as `make FLAG=VALUE`.

| Flag | Default | Values | Effect |
|---|---|---|---|
| `DEBUG_SHELL` | `0` | `0`, `1` | Enables in-kernel debug shell (`#ifdef DEBUG_SHELL` code) |
| `MINIMAL_SECURE` | `0` | `0`, `1` | Strips optional kernel features for a smaller attack surface |
| `RUST_ENABLED` | `1` | `0`, `1` | If `0`, links C stub shims instead of the Rust library |
| `ELF_SELFTEST` | `0` | `0`, `1` | Embeds a real ELF and runs an in-kernel loader + W^X self-test at boot |

Examples:

```bash
make DEBUG_SHELL=1
make MINIMAL_SECURE=1
```

> **Architecture:** Horus is x86-64 only. The kernel runs in 64-bit long mode; there is no 32-bit kernel build. (The `DEBUG_SHELL=1` and `MINIMAL_SECURE=1` configurations are covered by a CI build matrix.)

---

## Userspace programs

Userspace programs (`shell`, `hello`, `fs_server`, `captest`) are compiled as flat 32-bit ELF binaries (EM_386) loaded at virtual address `0x400000` and run in a compatibility-mode segment beneath the 64-bit kernel. The `mkheadered` tool adds a custom program header that the kernel's loader uses to map them into a task's address space.

Build all userspace programs:

```bash
make userspace
```

The kernel image (`boot.iso`) bundles the compiled userspace binaries. Rebuilding the kernel after changing userspace requires re-running `make` from the top level.

---

## Rust crate details

The Rust crate is at `rust/`. It builds as a `staticlib` (`crate-type = ["staticlib"]`) with:

- `panic = "abort"` (no unwinding)
- `opt-level = "z"` (size-optimised)
- `lto = true` (link-time optimisation)
- `codegen-units = 1` (deterministic output)
- `strip = true`

The resulting archive is `rust/target/<target>/release/libhorus_shell.a`. The linker links it with `--whole-archive` to pull in all symbol definitions.

If Cargo is not installed or the Rust target is missing, the build will fail with an explicit error message indicating what is needed.

---

## Troubleshooting

**`grub-mkrescue failed`**
Install `grub-pc-bin` and `xorriso`. On some distros: `sudo apt-get install grub-pc-bin xorriso`.

**`cargo not found`**
Install Rust via `rustup`: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

**`rust target x86_64-unknown-none missing`**
Run: `rustup target add x86_64-unknown-none`

**`ERROR: rust/target/.../libhorus_shell.a missing`**
Run `cargo build --release --manifest-path rust/Cargo.toml --target x86_64-unknown-none` manually and check for errors.

**Linker errors about missing `rust_*` symbols**
Ensure `RUST_ENABLED=1` (the default) or that the Rust crate built successfully. If you need to build without Rust, pass `RUST_ENABLED=0` to use the C stub shims instead.

**QEMU displays nothing / serial output only**
The 64-bit build configures GRUB's terminal to serial. If you are not connected to localhost:4445, you will see nothing on the SDL window until the kernel switches to VGA mode. Connect via `nc localhost 4445` or remove the `terminal_input/output serial` lines from `grub.cfg`.
