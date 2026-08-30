# Formal verification of the capability engine (Kani)

An application of [Kani](https://github.com/model-checking/kani) (a bounded model checker for
Rust) to the security core's capability algebra and the ELF-load validators. Where the
`#[cfg(test)] mod tests` in `capability.rs` *samples* inputs, Kani proves a property over the
**entire** input space by symbolic execution, so it covers boundaries the samples miss.

## What is proved

The harnesses live under `#[cfg(kani)]` in `capability.rs` and `lib.rs` and are compiled
**only** by `cargo kani`, invisible to the kernel build, `cargo test`, clippy, and the fuzz
crate.

| Harness | Property proved (∀ inputs) |
|---|---|
| `serial_never_reserved_or_zero` | For every serial-counter value, `assign_fresh_serial` returns a serial `>= MIN_DERIVED_SERIAL` and `!= 0` and advances the counter to exactly that value, a derived serial can never collide with a primordial (`0xC0DE…`) or empty (serial-0) slot. |
| `mint_never_escalates_rights` | For every (source rights, requested rights) pair, the minted rights are exactly `requested & source`, mint can only ever *reduce* authority. |
| `revoke_descendant_never_nulls_ancestors` | **Audit A1.** Over a parent → child → grandchild chain, for every distinct serial triple, revoking the grandchild's subtree leaves parent and child intact and nulls exactly the grandchild; the property the old equivalence-set matcher violated. |
| `revoke_root_nulls_every_descendant` | The completeness half: revoking the root nulls both the child and the grandchild, for every distinct serial triple. Together the two pin revocation to exactly the target's subtree: no ancestors, all descendants. |
| `revoke_invalidates_recorded_generation` | **Finding 3.3.** For every serial, a capability that recorded the current lineage generation fails `lineage_check` after that serial is revoked (its generation bumped); the use-after-revoke backstop actually rejects a stale snapshot. |
| `revoke_does_not_touch_a_distinct_lineage_cell` | The precision half: bumping one serial's generation leaves a *distinct* (non-colliding) serial's recorded generation still valid, so revocation does not spuriously invalidate an unrelated lineage. |
| `lookup_grants_exactly_the_rights_held` | **Roadmap 3.5.** For every (held, requested) rights pair, `rust_cap_lookup` succeeds **exactly when** the capability holds every requested right. Stated as an equivalence, not an implication, so a lookup that refused too much fails it too, "never grants what it should not" is satisfied by a predicate that always returns null. |
| `lookup_never_returns_an_empty_slot` | For every rights value, including the degenerate `required_rights == 0` that a "does it hold these" check answers vacuously, an empty slot never satisfies a lookup. |
| `lookup_refuses_every_out_of_range_slot` | For every slot index past the cspace, lookup refuses rather than reading whatever follows the cspace in memory. |
| `grant_never_escalates_rights` | For every (source, requested) pair, `rust_cap_grant_into` yields exactly `requested & source`; the same algebra as mint, on the operation that hands authority to a **different task**. |
| `grant_records_its_parent_and_takes_a_fresh_serial` | For every source serial, the grantee records the grantor as parent (`badge = src.serial`) and takes a fresh derived serial of its own, what makes a later revoke of the grantor sweep the grantee, and what keeps the derivation graph a tree. |
| `grant_from_an_invalid_source_refuses_and_writes_nothing` | Authority cannot be fabricated: granting from an empty source, or one with the lookup-invalid serial 0, refuses **and leaves the destination untouched**. |
| `grant_refuses_every_out_of_range_slot` | For every slot index, grant is bounded by the destination cspace. |
| *(two ELF validators in `lib.rs`)* | The ELF header / load-plan validators reject malformed inputs without out-of-bounds access, over the whole input space. |

Kani also discharges the implicit memory-safety checks on these paths (no overflow, no
invalid/null/out-of-bounds dereference) and the loop-unwinding assertions for the revocation
closure, several hundred checks, all passing.

Scope note: the revocation proofs use a 3-deep chain in one cspace, enough for the
ancestor/descendant distinction and transitivity. A multi-cspace + overflow-fallback model (the
overflow path is covered by a unit test today) is the natural next step.

## Running it

Kani is a separate toolchain (its own pinned nightly + the CBMC solver bundle), so it is not part of the default build.

```sh
cargo install --locked kani-verifier
cargo kani setup                 # one-time: downloads the CBMC/Kani bundle
cd rust && cargo kani            # runs every #[kani::proof] harness
cargo kani --harness mint_never_escalates_rights   # or a single one
```

**Which of these gate a merge is written down in `.github/kani-harnesses.yml`**, and
`tools/check_kani_harnesses.py` (the required `kani-bounded` job) fails the build if a proof
is in neither list. Eleven gate; four are excused with a reason, and run only in the manual
`kani` job.

That split exists because **none of them used to run at all**. The `kani` job is
`workflow_dispatch`-only *and* carries `continue-on-error: true` on both steps, so for as long
as it has existed no capability-algebra proof could have reddened a build; the same shape as
`smoke-kstack-park`, which was required and unfailable at once. A full `cargo kani` really is
too slow to gate (it exceeded GitHub's 6-hour ceiling), so the answer is to run the subset that
finishes and say out loud which ones do not.

Measured 2026-08-23, Kani 0.67.0, and measured **twice** because the first figure was
misleading: **319 s** for eleven harnesses against a cold target directory, **196 s** for
thirteen against a warm one. More proofs in less time, what dominates is the rebuild each `cargo
kani --harness` invocation may need, not the solving. Per-harness solver time sums to about
three minutes, nearly all of it the two revocation proofs.

Two harnesses were excused from gating on 2026-08-23 with a plausible reason; the ELF
validators, "corroboration, not the only witness", one of them "the more expensive of the two",
and then measured the same day at **2 seconds each**. Both gate now. The excuse was not a lie;
it was unmeasured, which is worth exactly what an unenforced note is worth.

**Falsify a proof before trusting it.** Every proof added on 2026-08-23 was checked by mutating
the property it claims: weakening lookup's rights test to "any overlap", dropping grant's `&
src.rights`, removing a bound, zeroing the recorded parent, and confirming the harness reports
`VERIFICATION:- FAILED`. One mutation appeared not to be caught and the *mutation* was wrong: a
first-occurrence string replace hit `rust_cap_mint`, 77 lines above the intended
`rust_cap_grant_into`. Aimed correctly, the proof failed as it should.

Expected tail:

```
VERIFICATION:- SUCCESSFUL
Manual Harness Summary:
Complete - 8 successfully verified harnesses, 0 failures, 8 total.
```

(Eight harnesses: the six capability proofs above plus the two ELF header/load-plan validators in `lib.rs`.)

CI runs this as a **non-gating advisory** job (`kani` in `.github/workflows/ci.yml`), like the `fuzz` and `security` jobs: a regression or a flaky toolchain install surfaces without reddening the pipeline. The four required-status hard gates stay `rust`, `kernel`, `smoke`, `reproducible`.
