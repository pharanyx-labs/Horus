# Formal verification of the capability engine (Kani)

A first, deliberately small application of [Kani](https://github.com/model-checking/kani)
— a bounded model checker for Rust — to the security core's capability algebra.
Where the `#[cfg(test)] mod tests` in `capability.rs` *samples* inputs, Kani
proves a property over the **entire** input space by symbolic execution, so it
covers boundaries the samples miss.

## What is proved

The harnesses live in `capability.rs` under `#[cfg(kani)] mod kani_proofs` and are
compiled **only** by `cargo kani` — invisible to the kernel build, `cargo test`,
clippy, and the fuzz crate.

| Harness | Property proved (∀ inputs) |
|---|---|
| `serial_never_reserved_or_zero` | For every value of the serial counter, `assign_fresh_serial` returns a serial `>= MIN_DERIVED_SERIAL` and `!= 0`, and advances the counter to exactly that value. A derived serial can never collide with a primordial (`0xC0DE…`) serial or an empty (serial-0) slot. |
| `mint_never_escalates_rights` | For every (source rights, requested rights) pair, the minted capability's rights are a subset of the source's, and exactly `requested & source`. Mint can only ever *reduce* authority — no privilege escalation. |
| `revoke_descendant_never_nulls_ancestors` | **Audit A1.** Over a parent → child → grandchild derivation chain, for *every* distinct serial triple, revoking the grandchild's subtree leaves the parent and the child intact (`typ` and `serial` unchanged) and nulls exactly the grandchild. This is the property the old equivalence-set matcher violated — it matched the target's `badge` against other caps' `serial`, so revoking a child also nulled its parent. |
| `revoke_root_nulls_every_descendant` | The completeness half: revoking the root of the same chain nulls the child **and** the grandchild, for every distinct serial triple — no derived authority outlives its ancestor. Together the two proofs pin revocation to exactly the target's subtree: no more (no ancestors), no less (all descendants). |

Kani also discharges the implicit memory-safety checks on these paths (no
overflow, no invalid/null/out-of-bounds dereference) and the loop-unwinding
assertions for the revocation closure, so the bounded worklist is proved to be
fully explored at the proof's size — several hundred checks across the harnesses,
all passing.

Scope note: the harnesses keep `object == 0` so the shared `LINEAGE_GEN` static
(global mutable state, which needs a heavier model) is not exercised; the rights,
serial and derivation-subtree logic under proof is identical either way. The
revocation proofs use a 3-deep chain in one cspace — enough to cover the
ancestor/descendant distinction and transitivity; a multi-cspace and
overflow-fallback model is the natural next step (the overflow path is covered by
a unit test today).

## Running it

Kani is a separate toolchain (its own pinned nightly + the CBMC solver bundle,
~140 MB), so it is not part of the default build.

```sh
cargo install --locked kani-verifier
cargo kani setup                 # one-time: downloads the CBMC/Kani bundle
cd rust && cargo kani            # runs every #[kani::proof] harness
# or a single one:
cargo kani --harness mint_never_escalates_rights
```

Expected tail:

```
VERIFICATION:- SUCCESSFUL
Manual Harness Summary:
Complete - 6 successfully verified harnesses, 0 failures, 6 total.
```

(Six harnesses in total: the four capability proofs above plus the ELF
header/load-plan validators in `lib.rs`.)

CI runs this as a **non-gating advisory** job (`kani` in `.github/workflows/ci.yml`),
like the fuzz and security jobs: a regression or a flaky toolchain install
surfaces without reddening the pipeline. The four hard gates stay `rust`,
`kernel`, `smoke`, `reproducible`.
