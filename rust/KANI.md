# Formal verification of the capability engine (Kani)

An application of [Kani](https://github.com/model-checking/kani) — a bounded model checker for Rust — to the security core's capability algebra and the ELF-load validators. Where the `#[cfg(test)] mod tests` in `capability.rs` *samples* inputs, Kani proves a property over the **entire** input space by symbolic execution, so it covers boundaries the samples miss.

## What is proved

The harnesses live under `#[cfg(kani)]` in `capability.rs` and `lib.rs` and are compiled **only** by `cargo kani` — invisible to the kernel build, `cargo test`, clippy, and the fuzz crate.

| Harness | Property proved (∀ inputs) |
|---|---|
| `serial_never_reserved_or_zero` | For every serial-counter value, `assign_fresh_serial` returns a serial `>= MIN_DERIVED_SERIAL` and `!= 0` and advances the counter to exactly that value — a derived serial can never collide with a primordial (`0xC0DE…`) or empty (serial-0) slot. |
| `mint_never_escalates_rights` | For every (source rights, requested rights) pair, the minted rights are exactly `requested & source` — mint can only ever *reduce* authority. |
| `revoke_descendant_never_nulls_ancestors` | **Audit A1.** Over a parent → child → grandchild chain, for every distinct serial triple, revoking the grandchild's subtree leaves parent and child intact and nulls exactly the grandchild — the property the old equivalence-set matcher violated. |
| `revoke_root_nulls_every_descendant` | The completeness half: revoking the root nulls both the child and the grandchild, for every distinct serial triple. Together the two pin revocation to exactly the target's subtree — no ancestors, all descendants. |
| `revoke_invalidates_recorded_generation` | **Finding 3.3.** For every serial, a capability that recorded the current lineage generation fails `lineage_check` after that serial is revoked (its generation bumped) — the use-after-revoke backstop actually rejects a stale snapshot. |
| `revoke_does_not_touch_a_distinct_lineage_cell` | The precision half: bumping one serial's generation leaves a *distinct* (non-colliding) serial's recorded generation still valid, so revocation does not spuriously invalidate an unrelated lineage. |
| *(two ELF validators in `lib.rs`)* | The ELF header / load-plan validators reject malformed inputs without out-of-bounds access, over the whole input space. |

Kani also discharges the implicit memory-safety checks on these paths (no overflow, no invalid/null/out-of-bounds dereference) and the loop-unwinding assertions for the revocation closure — several hundred checks, all passing.

Scope note: the revocation proofs use a 3-deep chain in one cspace — enough for the ancestor/descendant distinction and transitivity. A multi-cspace + overflow-fallback model (the overflow path is covered by a unit test today) is the natural next step.

## Running it

Kani is a separate toolchain (its own pinned nightly + the CBMC solver bundle), so it is not part of the default build.

```sh
cargo install --locked kani-verifier
cargo kani setup                 # one-time: downloads the CBMC/Kani bundle
cd rust && cargo kani            # runs every #[kani::proof] harness
cargo kani --harness mint_never_escalates_rights   # or a single one
```

Expected tail:

```
VERIFICATION:- SUCCESSFUL
Manual Harness Summary:
Complete - 8 successfully verified harnesses, 0 failures, 8 total.
```

(Eight harnesses: the six capability proofs above plus the two ELF header/load-plan validators in `lib.rs`.)

CI runs this as a **non-gating advisory** job (`kani` in `.github/workflows/ci.yml`), like the `fuzz` and `security` jobs: a regression or a flaky toolchain install surfaces without reddening the pipeline. The four required-status hard gates stay `rust`, `kernel`, `smoke`, `reproducible`.
