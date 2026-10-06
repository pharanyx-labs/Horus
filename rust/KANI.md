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
| `revoke_reaches_every_cspace_and_spares_a_peer` | **S3, S4 across cspaces.** A root in one cspace, its child granted into a second and a grandchild granted back: revoking the root nulls all three, and an independent capability on the same object in the second cspace survives, for every distinct serial quadruple. |
| `revoke_invalidates_recorded_generation` | **Finding 3.3.** For every serial, a capability that recorded the current lineage generation fails `lineage_check` after that serial is revoked (its generation bumped); the use-after-revoke backstop actually rejects a stale snapshot. |
| `revoke_does_not_touch_a_distinct_lineage_cell` | The precision half: bumping one serial's generation leaves a *distinct* (non-colliding) serial's recorded generation still valid, so revocation does not spuriously invalidate an unrelated lineage. |
| `lineage_idx_is_always_inside_the_table` | For every serial, the real serial-to-cell hash names a cell inside the generation table. The two proofs above stub that hash (see below), and this is the one property of it they rely on. |
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
| `elf_readers_never_wrap_an_offset` | **S111.** An ELF field read succeeds exactly when the whole field lies inside the image, for every offset up to `usize::MAX`, and a read at `base + delta` is a read at the checked sum. Before 2026-10-06 the sum was unchecked and the release kernel wrapped it. |
| `x86_64_reloc_target_is_inside_a_segment` | **S111.** For every 48-byte image, table offset, entry index and slide, an accepted x86-64 relocation writes all 8 bytes inside one loaded segment, and deciding to defer an entry never overflows. |
| `i386_reloc_target_is_inside_a_segment` | **S111.** The same for i386, whose relocations write 4 bytes. |
| `page_fault_never_accepts_a_kernel_half_address` | **S112.** For every fault address and every image and heap bounds C could pass, the page-fault validator accepts exactly the user-half addresses inside the image, the heap or the low stack. A kernel address is never the task's own, however wrong the bounds. |
| `signal_handler_is_never_a_kernel_half_address` | **S112.** The same for a signal handler: accepted exactly inside the task's image and below the user ceiling. |
| `refc_index_is_always_inside_the_table` | **The bound between a `u32` C chose and a raw write.** For every address and every pool size up to the table's capacity, an accepted index is inside both the caller's table and the fixed-size one `refc_table_ok` insists on. This is what `rust_page_ref_inc` and `rust_page_ref_dec` rely on before `refcounts.add(idx)`. |
| `refc_index_names_the_page_that_contains_the_address` | The index is not merely in range: it names the page that actually contains the address. Stated as containment rather than by recomputing the division, so the proof characterises the result instead of restating the implementation. A harness that recomputed it would pass against a wrong derivation copied into both call sites. |
| `every_page_in_the_pool_has_an_index` | The completeness half: every page the table can track is reachable, so the derivation has no gap that would silently stop refcounting a page. Without it, a derivation that refused everything would satisfy the two above. |
| `an_increment_never_wraps_a_refcount` | For every `u16`, an increment saturates and never wraps to 0. A count that wrapped to 0 would let a page somebody still holds reach the free stack, the shortest path to one frame in two address spaces. |
| `an_unseeded_pool_emits_nothing` | **S30.** An unseeded random pool refuses every request and zeroes the caller's buffer, whatever it held, for every length up to 16. The existing `rng_unseeded_legacy` control arm turns it red. |
| `the_throttle_locks_within_the_limit` | From any stored failure count, at most `MAX_AUTH_FAILS` consecutive failed logins pass before the account locks, and the lockout lasts the full period from the tick it is set. |
| `a_decrement_never_underflows_a_refcount` | For every `u16`, a decrement is refused **exactly** when the count is already 0, and otherwise strictly decreases. Stated as an equivalence so a refusal that is too eager cannot satisfy it vacuously. A wrap to 65535 would pin the page for the rest of the boot. |

Kani also discharges the implicit checks on these paths (no overflow, no invalid or
out-of-bounds dereference) and the loop-unwinding assertions of the revocation closure.

**Scope.** The revocation proofs use a three-deep chain in one cspace, which is enough for the
ancestor and descendant distinction and for transitivity, and a fourth proof spreads the chain
across two cspaces with an independent peer on the same object. None of this verifies the kernel
as a whole (`docs/LIMITATIONS.md` 5.5).

**Some proofs stub the hash.** With the real `lineage_idx`, whose two 64-bit multiplications
the solver must expand bit by bit, neither proof finished in 1500 s. They replace it with
`lineage_idx_model` (`#[kani::stub]`, enabled for the crate in `rust/Cargo.toml`) and finish in
about four minutes each. Neither property depends on which cell a serial maps to: the first needs
the same cell every time, which any pure function gives, and the second assumes two serials in
different cells. What the real hash must still get right is staying inside the table, and
`lineage_idx_is_always_inside_the_table` proves that for every serial. How evenly the hash spreads
serials (how often two collide) is not proved; it is the fail-safe A3 residual. The root
revocation proof and the two-cspace proof stub the hash for the same reason: revoking bumps the
generation of every serial it removes, and what they assert (which slots are nulled) does not
depend on which cell each bump lands in.

## Which proofs gate a merge

All of them. `.github/kani-harnesses.yml` lists every harness, the required `kani-bounded` job
runs each one on every pull request, and `tools/check_kani_harnesses.py` fails the build if a
proof is missing from the list. All **32** gate. There is no way to excuse a proof from running:
the checker refuses any list but `gating`. The count is declared in `.github/doc-claims.yml` and
re-derived on every run.

## Running it

Kani is a separate toolchain (its own pinned nightly and the CBMC solver), so it is not part of
the default build.

```sh
cargo install --locked kani-verifier
cargo kani setup                                     # one time: downloads CBMC and Kani
cd rust && cargo kani                                # every harness
cargo kani --harness mint_never_escalates_rights     # one harness
```

A successful run ends with `VERIFICATION:- SUCCESSFUL` and a summary line counting the
harnesses verified.

## Control arms

Every proof has at least one **control arm** in `.github/kani-arms.yml`: the defect the proof
forbids, written as an exact text substitution in `rust/src`. `tools/kani_arms.py` applies each
arm to a scratch copy of `rust/` (never the tree), runs the proof and requires
`VERIFICATION:- FAILED`; the nightly `kani-arms.yml` workflow runs all of them and keeps every
arm's output. On every pull request, `tools/check_kani_arms.py` (in `kani-bounded`) checks
without a solver that each arm's anchor text still occurs exactly once and that every gating
proof has an arm. Run one arm locally with `tools/kani_arms.py --only <id>`.

## Adding a proof

Falsify it before trusting it: mutate the property it claims (weaken a rights test, drop a
bound, zero a recorded parent) and confirm the harness reports `VERIFICATION:- FAILED`. State
properties as equivalences where you can, so a function that refuses everything cannot satisfy
them vacuously. Then add the harness to the `gating` list in `.github/kani-harnesses.yml` and
its arm to `.github/kani-arms.yml`. A proof too slow for every pull request has to be made to
finish (bound it, or stub what it does not depend on, as the lineage pair does) before it lands,
because no other job runs it.
