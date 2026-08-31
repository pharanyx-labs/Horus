# RFC: a bounded metadata cache and a Merkle rollback tree

*Design written 2026-08-31, before any code. Stages 2 and 3 of the work that lets
a volume be large enough to install onto; stage 1 (4 KiB blocks) landed in #270.*

The two falsifying arms are designed **first**, deliberately. These stages rewrite
the rollback-protection chain — the mechanism standing between a physical
attacker and silently reverting a disk to an earlier state — and stage 1 produced
seven defects from what looked like a constant change. An arm designed after the
code tends to test what the code does; an arm designed before it tests what the
code is *for*.

---

## 1. What changes, and what that breaks

### Today

`g_block_meta[BLOCKS_PER_DISK]` is a **complete in-RAM mirror** of the on-disk
nonce/tag region, 32 bytes per block. Integrity is two-level: a MAC per meta
block, then `sb.meta_hmac` over all of those. Both scale with the volume — the
top MAC's input is `META_BLOCKS_COUNT * 32`, so at 16 GiB it would hash 1 MiB on
every metadata write, and the mirror alone would want 128 MiB of RAM.

### Stage 2 — bounded write-back cache

The mirror becomes a fixed-size cache (`META_CACHE_ENTRIES`, resident regardless
of volume size) over the on-disk region, with dirty write-back.

**New failure modes, none of which exist today:**

| # | failure | why it is possible only now |
|---|---|---|
| E1 | a dirty entry is evicted without write-back | today nothing is ever evicted |
| E2 | write-back happens *outside* the journal transaction that owns it | today the meta write is staged with its data write |
| E3 | a miss reads the on-disk copy while a dirty entry for the same block is resident elsewhere (aliasing) | today there is one copy |
| E4 | the cache is lost on crash with the journal believing it durable | today the mirror is reconstructed wholesale at unlock |

E1 and E4 are the same event seen from two sides, and are what **Arm A** exists
for. E2 is what makes E1 fatal rather than merely lossy: the journal's guarantee
is that a committed transaction is durable, and a meta write that escapes the
transaction is a write the journal never promised.

### Stage 3 — Merkle tree

The two-level MAC becomes a tree of fanout `BLOCK_SIZE/32` = 128, depth 3 for a
16 GiB volume (4.19M blocks → 32,768 leaves → 256 → 2 → root), with a bounded
node cache. Per-write cost becomes ~4 hashes instead of 1 MiB.

**New failure mode:**

| # | failure | why it is possible only now |
|---|---|---|
| R1 | a cached interior node is trusted without being verified against the path to the current root | today there are no interior nodes and no node cache |

R1 is **Arm B**.

---

## 2. Arm A — eviction under crash

### The property

> A metadata update belonging to a committed journal transaction is durable,
> whether or not its cache entry was evicted before the crash.

### The defect to inject

`META_CACHE_EVICT_NOWB=1` — eviction drops a dirty entry instead of writing it
back. This is E1 directly, and it is the shape a real implementation gets wrong
by forgetting the dirty bit or by writing back lazily.

### The witness

Two boots on one image, reusing the `WAL_CRASHTEST` pattern (`g_wal_crash_armed`
+ halt at a chosen point, `storage_fresh_format` to tell the boots apart):

- **Boot 1** writes `META_CACHE_ENTRIES + N` *distinct* blocks, so the working
  set provably exceeds the cache and eviction must occur, then crashes at the
  armed point.
- **Boot 2** mounts, replays the journal, and reads every one of those blocks
  back, requiring each to decrypt and verify.

Marker `METACACHE: PASS all <n> blocks verified after crash`.

### The vacuity trap, and how this arm avoids it

**A test whose working set fits in the cache never evicts, so it cannot fail.**
This is exactly the shape that let a control arm pass earlier today: the pepper
arm could not reproduce because the selftest ran before `users_init`, so the
condition its defect depended on had not been created yet.

So the arm asserts on eviction *having happened*, not merely on the reads
succeeding:

```
if (meta_cache_evictions() == 0)
    → "METACACHE: FAIL no eviction occurred — this run tested nothing"
```

That counter is the difference between "the blocks verified" and "the blocks
verified *despite* eviction". Without it, growing the cache later would silently
turn this gate into a no-op, and nothing would say so.

### What building the arm first actually found

The arm was built against the current tree, before any cache existed, and its
first version **could not reproduce**. That non-result is the most useful thing
in this document.

The injection skipped one `flush_meta_block` call. It changed nothing: at 4 KiB
there are 128 metadata entries per meta block, so the entire 64-block working set
lives in ONE of them, and `flush_meta_block` rewrites the whole block from the
in-RAM mirror. Skipping flush 32 was simply undone by flush 33, entry included.

**A complete mirror is self-healing against a lost metadata write**, because it
holds every entry and can always regenerate any of them. That is a real property
of today's design, it is nowhere written down, and **stage 2 removes it**: once a
bounded cache evicts a dirty entry without writing back, the only copy is gone
and no later flush can reconstruct it.

So this is a cost of stage 2, not merely an implementation note. The arm now
clears the in-RAM entry as well as skipping the write, which is what eviction
without write-back actually leaves behind — and it reproduces:
`METACACHE: FAIL block 31 lost after eviction`.

Note what the ordering bought. Had stage 2 been written first, "skip the flush"
WOULD have reproduced — against the cache — and the difference between *skipping
a write* and *losing an entry* would never have surfaced. The arm would have
passed for a reason nobody had understood, which is how a gate ends up testing
something other than what its name says.

### Failing for the right reason

Under the defect the marker must be a **read failure of a specific block**, not a
mount failure. If `storage_unlock` refuses outright, that is E4 destroying the
whole region and the arm proves something weaker than intended — so the arm
distinguishes the two:

- `METACACHE: FAIL block <n> lost after eviction` — the intended reproduction.
- `METACACHE: FAIL volume did not mount` — reported separately, and treated as
  *inconclusive for this property* rather than as a pass, in the same way
  `smoke-kstack-park-control` scores a died boot as INCONCLUSIVE rather than a
  miss.

---

## 3. Arm B — stale-node replay

### The property

> An interior node is trusted only when it verifies against the path to the
> *current* root. A node that was valid at an earlier time is not valid now.

### The attack this models

A physical attacker with the disk rewinds part of the metadata region to an
earlier state that was, at the time, perfectly well-formed. Every byte they write
was genuinely produced by this volume; nothing is forged. The question is whether
the tree notices that it is *old*.

### The defect to inject

`MERKLE_NODE_TRUST_CACHED=1` — a node found in the node cache is returned without
re-verifying it against its parent. That is the natural performance shortcut, and
it is precisely what makes a replay succeed.

### The witness, and the subtlety that decides it

**The replayed node must be independently valid.** If Arm B replays garbage, or a
node whose own MAC fails, then the arm passes because the MAC check fired — and
it has tested nothing about the tree structure. A node MAC'd on its own is a set
of independent MACs, not a Merkle tree; the whole point of the tree is that a
node is bound to its *position and generation* through its parent.

So the sequence is:

1. Boot 1: write block set A. Snapshot the on-disk bytes of one interior node —
   valid, current, correctly MAC'd at this instant.
2. Boot 1 continues: write block set B, which changes that subtree, so the node
   and every ancestor up to the root are rewritten.
3. Overwrite that node's on-disk bytes with the **step-1 snapshot** — a genuine
   past state of this volume, not a forgery.
4. Boot 2: read a block covered by that subtree.

Requirement: **refusal**, with marker
`MERKLE: PASS stale node refused (subtree <k>)`.

Under `MERKLE_NODE_TRUST_CACHED=1` the read succeeds and returns the earlier
contents:
`MERKLE: FAIL stale node accepted — subtree <k> served a rolled-back block`.

### A second arm, because one is not enough

Arm B as stated exercises the *cache* path. A separate, smaller arm —
`MERKLE_SKIP_PARENT_BIND=1` — removes the parent binding itself (a node is
verified by its own MAC only). Both arms must produce the same refusal, from
different causes, or the tree is being verified in only one of the two places it
matters. This is the lesson from `smoke-cap-lookup-range-control`: a witness that
returns at its first failure needs a second arm to show the second rule fires
independently.

---

## 4. What these arms do NOT cover

Stated plainly, because a gate's scope is part of its claim:

- **Whole-volume rollback.** An attacker who replaces the superblock, the
  metadata region and the tree *together* with a consistent earlier snapshot
  defeats both arms, because every internal relationship holds. The Merkle root
  lives in the superblock it is meant to protect. Defending this needs a
  freshness anchor outside the volume — a TPM NV counter is the usual answer —
  and is **not** in scope for stages 2 or 3. The tree improves per-write cost and
  catches *partial* rollback; it does not make the volume monotonic.
- **A crash during write-back itself.** Arm A crashes at the journal's armed
  point. Tearing *inside* a single meta block write is the disk's atomicity
  domain, not the cache's, and is already covered by the journal.
- **Cache aliasing (E3).** Not an arm: it is a data-structure invariant, better
  served by an assertion in the lookup path than by a boot test. It is listed so
  that its absence is deliberate rather than forgotten.

---

## 5. Order of work

1. **Arm A's harness first, against the current code.** It must PASS on today's
   full mirror — which evicts nothing — and that run is what proves the harness
   itself works before there is any cache to blame. The eviction-count assertion
   will fail here, which is correct and is the signal to gate it only once the
   cache exists.
2. Stage 2, then Arm A with `META_CACHE_EVICT_NOWB=1`.
3. Stage 3, then Arm B and its parent-binding sibling.
4. Only then raise `BLOCKS_PER_DISK`.

Each stage lands separately and green. Stage 1 produced seven defects from one
constant; these two rewrite the integrity chain, and there is no version of
"land them together" that is easier to debug.
