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
| `qemu-system-x86_64` | 64-bit emulation |
| `qemu-system-i386` | 32-bit emulation |

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
# 64-bit (default)
rustup target add x86_64-unknown-none

# 32-bit (if building with BITS=32)
rustup target add i686-unknown-linux-gnu
```

---

## Build targets

### `make` / `make all`

Builds `kernel.elf` (64-bit by default). This is the main build target. It will:

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

Runs the Rust unit tests (41 across the security core — see [TESTS.md](../TESTS.md)), then does a clean full build to verify compilation.

```bash
make test
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
| `BITS` | `64` | `32`, `64` | Target architecture |
| `DEBUG_SHELL` | `0` | `0`, `1` | Enables in-kernel debug shell (`#ifdef DEBUG_SHELL` code) |
| `MINIMAL_SECURE` | `0` | `0`, `1` | Strips optional kernel features for a smaller attack surface |
| `RUST_ENABLED` | `1` | `0`, `1` | If `0`, links C stub shims instead of the Rust library |

Examples:

```bash
make BITS=32
make DEBUG_SHELL=1
make BITS=64 MINIMAL_SECURE=1
```

---

## 32-bit build

The 32-bit build uses `linker.ld`, the `i686` Rust target, and 32-bit GCC flags. The Rust target is `i686-unknown-linux-gnu` (a hosted target used for the 32-bit cross-compilation; the `-unknown-none` bare-metal target is used for 64-bit).

```bash
rustup target add i686-unknown-linux-gnu
make BITS=32
```

QEMU run for 32-bit uses `-kernel kernel.elf` directly (no ISO needed):

```bash
qemu-system-i386 -kernel kernel.elf -m 512M -cpu qemu64,+aes -nographic \
    -serial stdio -no-reboot -net none
```

---

## Userspace programs

Userspace programs (`shell`, `hello`, `fs_server`, `captest`) are compiled as flat 32-bit ELF binaries loaded at virtual address `0x400000`. The `mkheadered` tool adds a custom program header that the kernel's loader uses to map them into a task's address space.

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
