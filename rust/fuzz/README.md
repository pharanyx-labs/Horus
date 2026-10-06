# Fuzzing the Horus security-core FFI boundary

Coverage-guided ([cargo-fuzz] / libFuzzer) fuzzing of the pure, pointer- and scalar-taking FFI
predicates exported by the `horus_shell` crate; the functions the C kernel calls to make
security decisions. These are the cheapest, highest- value fuzz surface: no global state,
deterministic, and a panic or UB on any input is a real bug.

## Targets

| Target | Function under test | Invariants asserted |
|---|---|---|
| `ct_eq` | `rust_ct_eq` | symmetric; agrees with a plain compare; reflexive; never panics |
| `validate_page_fault` | `rust_validate_page_fault` | never panics on any scalar input |
| `signal_handler_addr` | `rust_signal_handler_addr_ok` | a positive result implies the address is inside the recorded image window; never panics |

## Running

Requires the pinned nightly and `cargo-fuzz` (the versions `.github/workflows/fuzz.yml` uses):

```sh
rustup toolchain install nightly-2026-08-21 --profile minimal --component rust-src
cargo install cargo-fuzz --version 0.13.2 --locked
# from the rust/ directory:
cargo +nightly-2026-08-21 fuzz run ct_eq
cargo +nightly-2026-08-21 fuzz run validate_page_fault -- -max_total_time=60
```

`Cargo.lock` here is committed, so `libfuzzer-sys` is pinned too.

## How it links

`horus_shell` is normally a `#![no_std]` `staticlib` with its own `#[panic_handler]`. Building
it into a std libFuzzer harness would collide on the panic handler, so the crate exposes a
`fuzzing` feature that (a) is built as an `rlib` and (b) gates the panic handler off (std
provides it). This crate is its own Cargo workspace so it never enters the parent build graph;
the gating `rust` CI job and the kernel build stay on stable and are unaffected.

CI fuzzes every target for ten minutes each night (`.github/workflows/fuzz.yml`), carrying each
target's corpus over from the night before. A crash fails the run and uploads the crashing input
as an artifact; reproduce it with `cargo +nightly-2026-08-21 fuzz run <target> <file>`. It never
runs on a pull request, so it does not gate a merge.

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz
