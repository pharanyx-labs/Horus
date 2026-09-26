# Formal verification with Kani

[Kani](https://github.com/model-checking/kani) is a bounded model checker for Rust. Where the
unit tests in `rust/src/` sample inputs, a Kani harness proves its property for **every** input
by symbolic execution. Horus uses it on the capability algebra, the ELF validators and the
reference-count arithmetic that guards the physical page pool.

The harnesses live under `#[cfg(kani)]` in `capability.rs`, `lib.rs` and `memory.rs`. Only
`cargo kani` compiles them; the kernel build, `cargo test`, clippy and the fuzz crate never see
them.

## What is proved

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
| `reply_mint_never_escalates_and_never_receives` | **Endpoint tokens (S105).** For every (invoker rights, requested rights, token), a reply-minted capability is a subset of the one the request came through, never carries receive, names the same endpoint, and records it as parent. A server needs no mint authority of its own: it can only narrow what the caller had. |
| `mint_token_only_from_an_untokened_minter` | A token is minted only from an untokened endpoint capability that holds MINT, for every source. Otherwise a client could re-point its capability at another object. |
| `mint_keeps_the_token` | A minted copy always carries its source's token, so narrowing never loses the identity a server tells clients apart by. |
| `elf_header_validation_is_sound` | The ELF header validator in `lib.rs` rejects every malformed header without an out-of-bounds read, over the whole input space. |
| `elf_load_plan_is_sound` | The load-plan validator does the same for program headers: every accepted segment lies inside the image it came from. |
| `refc_index_is_always_inside_the_table` | **The bound between a `u32` C chose and a raw write.** For every address and every pool size up to the table's capacity, an accepted index is inside both the caller's table and the fixed-size one `refc_table_ok` insists on. This is what `rust_page_ref_inc` and `rust_page_ref_dec` rely on before `refcounts.add(idx)`. |
| `refc_index_names_the_page_that_contains_the_address` | The index is not merely in range: it names the page that actually contains the address. Stated as containment rather than by recomputing the division, so the proof characterises the result instead of restating the implementation. A harness that recomputed it would pass against a wrong derivation copied into both call sites. |
| `every_page_in_the_pool_has_an_index` | The completeness half: every page the table can track is reachable, so the derivation has no gap that would silently stop refcounting a page. Without it, a derivation that refused everything would satisfy the two above. |
| `an_increment_never_wraps_a_refcount` | For every `u16`, an increment saturates and never wraps to 0. A count that wrapped to 0 would let a page somebody still holds reach the free stack, the shortest path to one frame in two address spaces. |
| `a_decrement_never_underflows_a_refcount` | For every `u16`, a decrement is refused **exactly** when the count is already 0, and otherwise strictly decreases. Stated as an equivalence so a refusal that is too eager cannot satisfy it vacuously. A wrap to 65535 would pin the page for the rest of the boot. |

Kani also discharges the implicit checks on these paths (no overflow, no invalid or
out-of-bounds dereference) and the loop-unwinding assertions of the revocation closure.

**Scope.** The revocation proofs use a three-deep chain in one cspace, which is enough for the
ancestor and descendant distinction and for transitivity. A model across several cspaces is the
natural next step. None of this verifies the kernel as a whole (`docs/LIMITATIONS.md` 5.5).

## Which proofs gate a merge

`.github/kani-harnesses.yml` puts every harness in one of two lists, and
`tools/check_kani_harnesses.py`, run by the required `kani-bounded` job, fails the build if a
proof is in neither list. **21** gate; **2** are excused with a
reason: the two lineage-generation proofs, measured on 2026-08-23 not to finish in 1500 s each.
Those two run only in the manual `kani` job, which cannot fail as written
(`docs/LIMITATIONS.md` 5.8). The counts are declared in `.github/doc-claims.yml` and re-derived
on every run.

## Running it

Kani is a separate toolchain (its own pinned nightly and the CBMC solver), so it is not part of
the default build.

```sh
cargo install --locked kani-verifier
cargo kani setup                                     # one time: downloads CBMC and Kani
cd rust && cargo kani                                # every harness, including the slow pair
cargo kani --harness mint_never_escalates_rights     # one harness
```

A successful run ends with `VERIFICATION:- SUCCESSFUL` and a summary line counting the
harnesses verified.

## Adding a proof

Falsify it before trusting it: mutate the property it claims (weaken a rights test, drop a
bound, zero a recorded parent) and confirm the harness reports `VERIFICATION:- FAILED`. State
properties as equivalences where you can, so a function that refuses everything cannot satisfy
them vacuously. Then add the harness to `.github/kani-harnesses.yml`, gating unless it has a
measured reason not to.
