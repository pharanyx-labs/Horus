# Building Horus

Toolchain, build targets, configuration flags, and how to run Horus under QEMU or on
hardware.

Horus is **x86-64 only**. The kernel runs in 64-bit long mode; there is no 32-bit kernel
build. Boot is Multiboot2 via GRUB (BIOS); UEFI is not supported.

---

## Requirements

A Linux host with an x86-64 native toolchain. No cross-compiler is needed — the kernel is
built freestanding with your system `gcc`.

```bash
sudo apt-get install -y --no-install-recommends \
    build-essential binutils make \
    xorriso grub-pc-bin grub-common mtools \
    qemu-system-x86

rustup target add x86_64-unknown-none
```

| Tool | Purpose |
|---|---|
| `gcc`, `binutils`, `make` | Compile and link the kernel and userspace |
| `rustup` + `x86_64-unknown-none` | The `no_std` security core |
| `xorriso`, `grub-pc-bin`, `grub-common`, `mtools` | Build the bootable ISO |
| `qemu-system-x86` | Run and test |
| `swtpm`, `swtpm-tools` *(optional)* | Measured-boot and sealed-key testing |
| `python3` *(optional)* | Scripted shell sessions and PCR recomputation |

---

## Building

```bash
make            # kernel.elf
make iso        # boot.iso (implies kernel.elf)
make clean      # remove build products
make clean-rust # also clear the Cargo target directory
```

The build links the Rust staticlib with `--whole-archive` (so `#[no_mangle]` FFI symbols
survive), then the C kernel objects, under `linker64.ld`.

**Kernel compile flags of note:**

```
-ffreestanding -fno-pic -fno-pie -mcmodel=kernel
-mno-sse -mno-mmx -mno-80387        # the kernel never touches FP/SIMD registers
-fstack-protector-strong -mstack-protector-guard=global
-Wall -Wextra -Wformat-security -Werror=vla
-frandom-seed=horus -fdebug-prefix-map=...   # reproducibility
```

The kernel is built without SSE deliberately: ring-3 owns the FPU/SIMD register file, and the
kernel's only job is to save and restore it. `fxsave`/`fxrstor` are therefore inline
assembly, since the compiler is forbidden from emitting SSE.

---

## Running

```bash
make run        # boot boot.iso under QEMU with a serial console
make run-tpm    # same, under an emulated TPM (requires swtpm)
```

Log in as **`root`** / **`horus`**.

Useful once you are in:

```
ls /bin              # the provisioned coreutils and test programs
dmesg                # the kernel message ring (root only)
ps                   # tasks, including the userspace servers
cat /etc/motd | wc -l
tcc -v
help
```

`Ctrl-A X` exits QEMU.

### On real hardware

`boot.iso` is a standard El Torito BIOS-boot ISO. Write it to a USB stick with `dd` and boot a
machine in legacy/CSM mode. Horus expects a serial port for its console; without one you get
VGA text output only. This is genuinely exercised, but expect rough edges — driver coverage
is minimal (ATA PIO and PS/2 only).

---

## Configuration flags

Pass as `make VAR=value`. Each toggles `#ifdef` regions, so a flag change forces a rebuild of
the affected objects.

| Flag | Default | Effect |
|---|---|---|
| `SMP` | `1` | Multi-core: ACPI MADT enumeration, AP bringup, per-CPU LAPIC timers, TLB shootdown, SMT parking. `SMP=0` compiles it all out. |
| `DEBUG_SHELL` | off | In-kernel debug shell and command-execution syscall. **Development only** — it widens the syscall surface. |
| `MINIMAL_SECURE` | off | Reduced-surface build for security experiments. |

CI builds `SMP=1`, `SMP=0` (via the default job), `DEBUG_SHELL=1`, and `MINIMAL_SECURE=1`, so
all four keep compiling.

### Self-test builds

Each security self-test is a separate kernel configuration whose test-only code is **absent**
from the default build (and whose test-only syscalls therefore fail closed). You rarely
invoke these directly — the `make smoke-*` targets build and run them for you.

`WX_SELFTEST`, `ELF_SELFTEST`, `ELF64_SELFTEST`, `PREEMPT_SELFTEST`, `SIGNAL_SELFTEST`,
`TSD_SELFTEST`, `E820_SELFTEST`, `SMP_SELFTEST`, `FLUSH_SELFTEST`, `CAPTEST_SELFTEST`,
`PERM_SELFTEST`, and others.

### Defect-reproducing builds (control arms)

A handful of flags exist to rebuild a defect on purpose, so that the gate for its fix has a
failing arm. A gate that has only ever been run against the fixed kernel is not evidence.

| Flag | Reproduces | Gate |
|---|---|---|
| `KFAULT_INJECT` | Takes a deliberate supervisor page fault (a read of `0x94`, G-8's address) on a timer tick **after** `console_server` owns the console. `KFAULT_INJECT_TICKS` (default 400) sets how long after. | `make smoke-kfault` |
| `KFAULT_LEGACY_PRINTLN` | Reports a CPL-0 page fault through `println()` as the kernel used to — i.e. into the klog, where nothing on the wire can hear it. | `make smoke-kfault-legacy`, which requires the report to be **absent** |
| `EP_QUEUE_SLOTS=1` | A single-slot endpoint queue, for the roadmap 1.3 blocking-receive gates. | `make smoke-recvblock` |

None of these is a shipping configuration.

---

## Testing

```bash
make smoke      # headless boot; asserts the ring-3 shell banner and login prompt
make test       # the full local sweep
```

Individual self-tests are `make smoke-<name>`. A few of the important ones:

| Target | Asserts |
|---|---|
| `smoke-captest` | Unheld capabilities, post-revoke use, and bad input are all refused (29 checks) |
| `smoke-wx` | No kernel page is both writable and executable (sweeps every leaf PTE) |
| `smoke-cpu` | SMEP and SMAP are actually set in CR4 |
| `smoke-smp` | APs run scheduled tasks; TLB shootdown completes |
| `smoke-aspace` | A rebuilt task slot leaks no physical pages |
| `smoke-cow` | Copy-on-write breaks correctly |
| `smoke-modules-tamper` | A corrupted boot module is refused |
| `smoke-tpm-tamper` | A corrupted module additionally diverges the measured PCRs |
| `smoke-tpm-seal` | A changed PCR leaves the volume locked |
| `smoke-fs-perms` | POSIX rwx is enforced against the kernel-attested uid |
| `smoke-fs-wal` | The journal recovers a crash-interrupted write |

The full catalogue is in [`../TESTS.md`](../TESTS.md).

Tests that need a TPM (`smoke-tpm*`) require `swtpm`; they drive it through
`tools/run_with_swtpm.sh`. Note that QEMU's `tpmdev` wants `swtpm --ctrl` on a socket, not
`--server`.

**Timeouts.** Some targets need a larger budget than the 40 s default — for example
`make smoke-tcc SMOKE_TIMEOUT=320`, because the ~1 MiB `tcc` image loads block-by-block over
the FS server. Under TCG emulation everything is slow, and four cores are measurably *slower*
than one.

---

## Reproducible builds

```bash
make reproducible-build   # build twice from clean and diff kernel.elf
make verify-build         # alias
```

This is a required CI check. Reproducibility comes from `-frandom-seed`,
`-fdebug-prefix-map`, `--build-id=none`, and avoiding any timestamp or path leakage into the
image.

**A reproducible build is a supply-chain control, not a nicety:** it is what lets a third
party confirm that a binary corresponds to the source beside it. Note that the repository
currently also *commits* a prebuilt `kernel.elf`, which undercuts that — see
`docs/LIMITATIONS.md` §5.6. Always rebuild rather than trusting the committed artifact.

---

## Boot modules

Program images reach the system as GRUB `module2` entries rather than being compiled into
`kernel.elf`, so they cost nothing against the `__bss_end <= USER_PHYS_BASE` (16 MiB) linker
assertion.

At build time, `tools/gen_module_manifest.sh` hashes each module and generates
`src/kernel/boot_module_manifest.h`, which is compiled **into the kernel image**. At boot the
kernel re-hashes each module and compares. A module that does not match is reported as an
empty slot and its payload cannot be read — so it can never be provisioned into `/bin` as an
executable.

`init` reads verified modules over `SYS_BOOT_MODULE_READ` and writes them into the encrypted
store. Destinations are constrained to `/bin` and `/usr/share/man`. Nothing ever executes a
module in place.

To add one: build a PIE binary into `userspace/`, add a `module2` line to `grub.cfg`, and
rebuild. The manifest regenerates automatically.

---

## Rust core

```bash
cargo test   --manifest-path rust/Cargo.toml --release
cargo clippy --manifest-path rust/Cargo.toml --release --all-targets -- -D warnings
```

Both are CI hard gates — clippy warnings fail the build.

Fuzzing (nightly toolchain):

```bash
cargo +nightly fuzz run <target>    # targets in rust/fuzz/
```

Kani proofs over the capability algebra run under `cargo kani`.

The crate has **no external runtime dependencies**. That is deliberate: it keeps the
supply-chain graph empty. Dependabot is configured for Cargo anyway, so it lights up the
moment one is added.

---

## Troubleshooting

**`error: linker ... cannot find -lhorus_shell`** — the Rust staticlib did not build. Run
`cargo build --manifest-path rust/Cargo.toml --release --target x86_64-unknown-none` and read
the error.

**`can't find target x86_64-unknown-none`** — `rustup target add x86_64-unknown-none`.

**`xorriso: command not found` on `make iso`** — install `xorriso grub-pc-bin grub-common
mtools`.

**QEMU boots to a blank screen** — Horus's console is on serial. Use `make run`, which wires
`-serial mon:stdio`, rather than invoking QEMU by hand.

**A smoke test times out** — raise the budget (`make smoke-x SMOKE_TIMEOUT=180`). CI runners
and TCG are slow; this is usually not a real failure.

**Linker assertion `__bss_end <= USER_PHYS_BASE`** — you added a large static array. Move it
into a physical-pool reservation instead (see how `loader_staging` and `g_vdisk_backing` are
handled in `src/include/kernel.h`).
