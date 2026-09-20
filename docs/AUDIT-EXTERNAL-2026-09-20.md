# External review, 2026-09-20: reconciliation

**What this is.** An unsolicited third-party review of the public tree, received 2026-09-20 and
reconciled against the checkout the same day. It is not an in-tree audit and does not replace
[`AUDIT.md`](AUDIT.md), the 2026-09-19 self-audit: that one was run against the source with the
tools that derive its numbers, this one was run against the published repository, the GitHub API
and a sampled read of the sources.

**Why it is recorded rather than filed away.** It is the first review of this project by somebody
who did not write it. That makes its *errors* as informative as its findings, because an error an
outside reader makes against a tree that documents itself this heavily is usually the tree's
fault. One of them was.

**Baseline.** The review pinned `91a388b` (PR #403). The tree was at `248676b` (PR #405) when it
arrived, one commit ahead, which is why it does not mention `[HORUS-20260920-01]` or
`[HORUS-20260920-02]`.

**Status rule, unchanged.** [`LIMITATIONS.md`](LIMITATIONS.md) is the authoritative status of
every finding. Nothing in this file sets a status. Where the review named an ID, the ID keeps the
meaning and the status `LIMITATIONS.md` gives it, and where the review contradicted that status
the contradiction is recorded below rather than imported.

**The review is not quoted in full, deliberately.** Pasting it verbatim would have put
*"[G-9], open"* into the tree, which is the two-statuses defect CLAUDE.md section 3 exists to
catch, and would have done it in the same commit that fixes an instance of that defect.

---

## 1. The finding that is ours, not theirs

The review's highest-rated kernel finding, **C-K2**, is filed against **[G-9]** as an open
finding. [G-9] closed on 2026-08-21. Its successor [G-12] closed on 2026-09-03. The item the
review is describing is [`LIMITATIONS.md`](LIMITATIONS.md) section 5.3e, which is deliberately
**not** a G-numbered finding, for reasons recorded on 2026-09-11 so they would not be
re-litigated: the only rate it has is conditioned on a widener (four guest CPUs pinned onto two
host cores, plus `KSP_GUARD_INJECT`, which injects a bogus kernel stack pointer and is not a
passive instrument), and 5.3e says in terms that neither 1/200 nor 31/200 is the gate's flake
rate and that neither should be quoted as one.

**Where the reviewer got "open" from.** `docs/README.md`'s investigations table listed
`G-09-scheduler-claim-leak.md` with status **Open**. Every other statement of that status in the
tree said closed: the investigation file's own header, `LIMITATIONS.md` 5.2d, `ARCHITECTURE.md`,
`TESTS.md`, `CHANGES.md`, `README.md`, `.github/ci-gating.yml` and the public site. The index
disagreed with all of them, and the index is what an outside reader reaches first.

This is the second time [G-9] has held two statuses at once. The first was `TESTS.md` carrying a
section headed *"Open finding G-9 ... Status: open"* against *"[G-9] closed"* later in the same
file, corrected 2026-08-21. That sweep read the prose and missed the index.

**Corrected 2026-09-20**, and ratcheted: the stale row is now a `forbidden:` pattern in
[`.github/doc-claims.yml`](../.github/doc-claims.yml), so restoring it fails the `doc-claims`
job. The rule was falsified before it was committed, by restoring the row and confirming the
base checker goes red on it.

**Why this is worth a section of its own.** Section 3 of the maintainer's rules asserts that a
finding ID with two statuses in one tree is a defect. Until now the argument for that was
hygiene. It is now measured: a stale status line in an index propagated into an external
reviewer's highest-rated kernel finding, and would have propagated back into the tree had the
review been reconciled by accepting it. The cost of the defect is not that a document looks
untidy. It is that the project's own record was the source of somebody else's wrong conclusion.

**The substance of C-K2 stands.** There is an open item about claim staleness under injection,
it is 5.3e, and the review's recommendations for it (a construction-level claim published only
after the stack switch, a debug profile that halts rather than logs on a
`g_kstack_inflight` mismatch, and a soak in the gate's own unpinned configuration rather than
the widened one) are the right shape and are what 5.3e already says would change its
classification.

---

## 2. Reconciliation

Verified against the checkout at `248676b`. "Already recorded" means the review reached a
conclusion the tree had already reached and published; it is accurate, and it is not new
information.

| Review ID | Claim | Verdict |
|---|---|---|
| C-K1 / C-5 | No independent review; `required_approving_review_count: 0`, `require_code_owner_review: false` | **Confirmed.** Ruleset 21815299 returns both. Already recorded as [C-5], `LIMITATIONS.md` 5.1 |
| C-K2 | Stale scheduler claims under SMP, filed against [G-9] | **ID incorrect**, substance confirmed. See section 1 |
| C-K3 | Inherited pipe end is a derivation root, breaking S3 closure | **Confirmed.** `capability.c` `cap_install_child_pipe_end` sets `badge = 0`. Already recorded as [HORUS-20260911-04], section 1.14 |
| C-K4 | `free_user_physical_page` is safe only by caller discipline | **Confirmed.** It guards the shared zero page and clamps the refcount index, then pushes the address onto `free_page_stack` with no range test and no double-free test. Already recorded as [HORUS-20260919-01] / audit F3, section 2.5a |
| C-K5 | Boot-module TOCTOU closed, but the pattern is the lesson | **Confirmed and accepted.** Closed as [HORUS-20260919-02] (S96, PRs #402/#404). The generalisation is new; see section 3 |
| C-K6 | Malicious-contributor residual: no SLSA, ISO unreproducible | **Confirmed.** ISO already recorded at 5.3a; provenance is roadmap 4.4/4.5 |
| C-K7 | Crypto in the TCB is unaudited and not constant-time | **Confirmed, and the process point is accepted.** Already stated at 5.4 and in `SECURITY.md`, but it had no finding ID and therefore no status anything could reconcile. Promoted to **[HORUS-20260920-03]** |
| I-1 | Ruleset reconciliation lag | **Confirmed.** Already recorded as [C-6], 5.2 |
| I-2 | Ring-0 service eviction is not blocking work | **Confirmed.** Already recorded as G-14; roadmap 2.7a |
| I-3 | `GETPASS` is owner-gated, `GETLINE` and `READ_RAW` are not | **Confirmed, already recorded.** `SECURITY.md` S93 states this residue itself, including why: `cat` with no arguments reads stdin through `READ_RAW` |
| I-4 | Roughly 20 gates still scrape the shared console | **Confirmed.** Already recorded at 2.6c |
| I-5 | Formal methods cover the algebra, not the kernel | **Confirmed, already recorded** at 5.5 |
| I-6 | CodeQL runs `c-cpp` only, so the Rust security core is invisible to it | **Confirmed and new.** `codeql.yml`'s matrix is `[ 'c-cpp' ]`. Not previously recorded |
| I-7 | `horus.iso` is not byte-reproducible | **Confirmed, already recorded** at 5.3a |
| I-8 | No CPU or memory quotas | **Confirmed, already recorded.** `SECURITY.md` excludes availability explicitly |
| I-9 | History rewrite and a single synthetic identity | **Confirmed** as fact. The recommendation (stop rewriting, use `.mailmap`) is accepted |
| I-10 | `font_8x8` has no licence | **Confirmed, already recorded.** `include/console_font.h` carries a PROVENANCE paragraph saying it has none, and `THIRD_PARTY.md` records it |
| I-11 | Drivers and the block layer are in ring 0 | **Confirmed, already recorded.** Classified `driver` in `.github/ring0-classification.yml` |

### Claims that are wrong

| Claim | Tree |
|---|---|
| *"in one architecture note, `EP_QUEUE_SLOTS = 1`"* | `EP_QUEUE_SLOTS` is **4**. `=1` is a control arm that restores the pre-queue single-slot design, described as such in `ROADMAP.md`. The review read an arm as the shipped value |
| *"Selftests in the kernel image ... enlarge the privileged attack surface"*, and the recommendation to compile them out of the production profile or measure them into a separate PCR | `selftest.c` is 238 kB of **source**, and its header states that every block is compiled only under its own `-D*_SELFTEST` switch, so the default build yields an almost-empty object. It is also its own category in `.github/ring0-classification.yml`, outside the `core` budget. The recommendation addresses a condition that does not hold |
| *"core ≈ 9.7 kLOC"* | `core_budget_loc` is **10081**. The figure was current on 2026-09-11 and is quoted without its date |
| Ratings that assume `91a388b` is the tip | One commit stale. Sections 1.16 and 1.17 of `LIMITATIONS.md`, both open, postdate the baseline |

---

## 3. What the review added

Most of its findings are faithful re-reads of `LIMITATIONS.md` and `SECURITY.md`. That is worth
knowing in itself, because it means the self-disclosure is legible to an outside reader and that
a hostile reading of it did not turn up a security property the tree claims and does not have.
It also means the independent-discovery rate is low, and the review says so: it did not line-read
`storage.c`, `scheduler.c` or the ring-3 servers, which is where an independent reviewer would
add the most.

Four things in it are genuinely new, and all four are accepted:

1. **The verify-then-use pattern, generalised.** [HORUS-20260919-02] was "hash it, write over the
   bytes, then serve the verified flag". The review's point is that the closure fixed one
   instance and the pattern is the finding: any future surface that is measured and then used
   (initrd, sealed snapshots, shared-library text) needs a post-condition re-hash or an
   immutability argument, not a second discovery. Recorded against S96.

2. **Crypto needed an ID, not a paragraph.** Section 5.4 and `SECURITY.md` both disclosed that
   the primitives are unaudited and not constant-time, in prose, with no finding ID. Every other
   gap in this project has an ID whose status is reconciled across files, and this one could not
   be tracked, cited in a PR, or closed. Now **[HORUS-20260920-03]**.

3. **CodeQL does not see the Rust.** The security core is the part of the tree that exists to
   hold the untrusted-bytes and algebraic-security code, and the only SAST job that runs on a
   schedule cannot read it.

4. **The review-hole framing.** The review's argument is that the engineering environment is
   correctly treated as part of the TCB, and that this TCB is currently one human, one model,
   one namespace, one ruleset app key and one runner image. It is right that no amount of gate
   writing addresses this, because the gates are written by the same pair. [C-5] stays open and
   this file is not evidence against it: an unsolicited review that was not commissioned, not
   scoped and not answerable is not the independent review 4.1 calls for.

---

## 4. Accepted and not yet done

Recorded here so the next session does not have to re-derive them from the review. None of these
is a status; each is either an open finding with an ID or a roadmap item.

- **[HORUS-20260911-04]**, the pipe-end badge. The review proposed the one-field change plus
  refcount accounting plus a smoke-pipe-revoke-child gate (a target that does not exist yet, so
  it is named here without backticks) with a `PIPE_CHILD_BADGE_ZERO=1` control arm. That is the right shape and the design is now written out in section 1.14. It is
  not in this change: it is a change to authorisation spanning `capability.c`, the Rust
  revocation sweep and `pipe.c`, and it wants its own pull request.
- **[HORUS-20260920-03]**, crypto. Filed; the fix (vendor an audited `no_std` implementation, or
  extract a verified subset) is a dependency decision and needs the maintainer.
- **CodeQL Rust coverage**, from I-6.
- **`.mailmap` instead of history rewriting**, from I-9.
- **Splitting `ci.yml`** and restating `permissions` at job level, from the minor issues. The
  file is 255 kB and a `permissions:` slip in it would not be caught by reading.
