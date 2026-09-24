# A capability-addressed filesystem for Horus

**Status: design, not built. Nothing here is implemented.** It exists to be argued with before
any code is written, because the subject is storage at rest, the authority model and the
cryptography all at once, which is three §4 asks in one change. The three load-bearing questions
were put to the maintainer and answered on 2026-09-23; §6 records them as decisions.

Opened 2026-09-23 at the maintainer's request: "a much more robust filesystem, a hybrid of the
major unix ones out there but definitely unique and most importantly, secure".

---

## 1. What already exists, stated honestly

It would be easy to write this document as though Horus had no filesystem. It has a good deal,
and the parts worth keeping are the parts most systems get wrong.

| Property | Today |
|---|---|
| Confidentiality at rest | Per-block AEAD. `disk_key` is wrapped by a KEK derived with Argon2id from the passphrase, LUKS style, and never stored in plaintext |
| Integrity | A Merkle tree over the metadata region, rooted in `meta_root` in the superblock and verified at unlock |
| Crash atomicity | A write-ahead redo log: stage, commit with an HMAC-authenticated header, then apply |
| Privilege separation | `fs_server` runs in ring 3 and **never sees key material**; the kernel does the crypto behind `SYS_FBLOCK_READ`/`WRITE` |
| Layout | Superblock, inode bitmap, block bitmap, data bitmap, inode table, data region |
| Directories | An array of `fs_dirent` records in ordinary inode data; root is inode 0 |
| Authority | Kernel-attested uid/gid and Unix mode bits |

The first four rows are better than most filesystems in use. A redesign that lost any of them
would be a regression however modern the rest looked.

## 2. The defect worth redesigning around

**The filesystem authorises by identity, in a system whose entire thesis is that nothing
authorises by identity.**

`FS_OP_CHMOD` is "owner or root". `FS_OP_CHOWN` is "root only". `FS_OP_STAT` returns `uid` and
`gid`, and the access checks compare them against the caller's. The uid is not forgeable, because
it comes from `SYS_IPC_SENDER` and never from anything the client asserts, so this is not a hole
an attacker walks through today. It is something worse in the long run: it is **`uid == 0`
ambient authority**, the exact thing roadmap 0.2 retired from the kernel on 2026-07-27, still
running in ring 3 because the filesystem was written before that change and never revisited.

CLAUDE.md §1 says it plainly. Nothing is granted for who you are. A filesystem that asks "are you
root?" has an answer for that question, and the answer is a standing grant that no capability
mediates, cannot be attenuated, cannot be delegated for one file, and cannot be revoked short of
changing the uid.

So the unique property this design is organised around is not a tree structure or a checksum
algorithm. It is this: **a file handle is a capability, and there is no other way to reach a
file.**

## 3. What to borrow, and from where

"A hybrid of the major Unix ones" is the right instinct, provided each borrowing is taken for a
reason rather than for a resemblance.

| Borrowed | From | Why |
|---|---|---|
| Extents instead of block pointers | ext4, XFS | A 1 GiB file today costs a quarter of a million block pointers. Extents make a contiguous file's metadata O(1) rather than O(size), which also shrinks the encrypted metadata region and therefore the Merkle tree over it |
| B-tree directories | XFS, ext4 htree | Directories are a linear array, so every lookup is O(n) and every create rescans for collisions. A directory of ten thousand files is already unpleasant |
| Copy on write | btrfs, ZFS | Discussed in §5; it is the one borrowing with a real argument against it |
| Per-block authenticated encryption | **already Horus** | Keep it. It gives confidentiality and integrity in one construction, per block, and it is better than ZFS's separate checksum |
| Merkle-rooted metadata | **already Horus** | Keep it, and extend it to cover data extents, not only the metadata region |

What is deliberately **not** borrowed: multi-device and RAID (no second disk exists to test on),
online resize (nothing needs it), extended attributes as a general key-value store (an
unbounded, unaudited surface attached to every file), and POSIX ACLs, which are a second identity
based authority model layered on the first.

## 4. The shape proposed

**Files are named by capability, not by path.** Opening a path is a *derivation*: a directory
capability plus a name yields a file capability whose rights are at most the directory
capability's rights. This is the same algebra the kernel's cspace already implements, so the
rules are the ones already proved in `rust/src/capability.rs` rather than a second, parallel set
invented for storage.

- Rights are the familiar set (read, write, append, truncate, unlink, and a `grant` right that
  controls whether the holder may pass it on) and they only ever **shrink** on derivation. §1.
- There is no `chown`, because there is no owner. There is no `chmod`, because there are no mode
  bits. The question "may this task write this file?" is answered by "does it hold a capability
  with write on it?", which is a lookup and not a policy.
- `root` is not a principal. A task that holds the root directory capability with full rights can
  do what root did; the difference is that this is a thing it **holds**, which can be attenuated
  before handing to a child, and revoked by the existing revocation machinery (S3, and the Kani
  proofs on revocation already cover the subtree property).
- A compromised `fs_server` cannot escalate, because it still never holds key material and now
  also never holds an authority it was not handed.

**On disk**, the layout changes only where it must:

- The superblock keeps its wrapped key, its salts and `meta_root`. A format change is a format
  change, but the cryptographic core does not need reinventing and should not be.
- Inodes lose `uid`, `gid` and `mode`, and gain nothing in their place: authority is not on the
  disk at all. It lives in cspaces, which are kernel objects, which are not attacker-writable in
  the way a disk is. **This is a security improvement on its own**, independent of capabilities:
  today an attacker who can write raw blocks can change a file's owner to 0. After this there is
  no such field to write.
- That raised the one genuinely hard question, what a capability *persists* as across a reboot
  given that cspaces do not survive one. §6 answers it: it does not persist. Nothing on the
  medium is authority.

## 5. The copy-on-write argument, both sides

**For.** Crash atomicity becomes structural rather than procedural: nothing is overwritten, so
there is no window in which a block is half old and half new, and the write-ahead log can retire.
Snapshots become nearly free, which is the feature that makes rollback after a bad update
possible. It composes well with per-block AEAD, because a rewritten block is a *new* block and
therefore gets a fresh nonce by construction, which removes a whole class of nonce-reuse mistakes
that in-place encryption has to avoid by remembering.

**Against.** Copy on write turns every write into an allocation, which on a nearly-full volume
turns into a search, and the allocator is the component that recently needed a rotating start
hint to stop rescanning (5.3, fixed 2026-09-01). It fragments, and the only storage this system
can actually drive is PIO, where fragmentation costs round trips that §7 shows are already the
dominant cost. And it needs a free-space accounting story that a journalled in-place filesystem
does not: "how much space is left" stops being "count the zero bits".

**My recommendation is copy on write anyway**, on the strength of the nonce argument alone. A
design where nonce reuse cannot happen is worth more than one where it is merely avoided
carefully, and that is §1's "by construction beats by remembering" applied to cryptography.

## 6. The decisions, as taken

Answered by the maintainer on 2026-09-23. Recorded here as decisions, not options, because the
work below depends on them and a design document that still asks a settled question is stale.

**Decision 1: a file capability is derived fresh each boot from policy. The disk holds no
authority at all.** At unlock `init` holds the root directory capability and everything else is
derived from it. There is no owner field, no mode bits and no rights table on the medium, so an
attacker who can write raw blocks gains nothing by writing them: there is nothing there to forge.
This is the strongest form of the §1 argument and it is what makes the design worth building.
What it costs is that "these files belong to this user" must be expressed in the boot-time policy
rather than in the inode, and **the policy therefore becomes the protected object**: it must live
inside the AEAD and the Merkle tree, and a rollback of it is a privilege change. That is a
smaller and far more auditable surface than per-inode ownership, because it is one object rather
than one per file.

**Decision 2: the authority change lands first, on the existing v11 format.** Capabilities
replace uid, gid and mode against the layout that exists today, as its own reviewable change with
its own control arms. Extents, B-tree directories and copy on write follow as a second change
against a new format. The security argument is then reviewable on its own rather than buried in a
rewrite, and if the layout work stalls the ambient authority is gone regardless.

**Decision 3: copy on write, in that second change.** Taken chiefly for the cryptographic
argument in §5: a rewritten block is a new block and therefore gets a fresh nonce by
construction, so nonce reuse becomes impossible rather than carefully avoided. The allocator work
and the fragmentation cost are accepted with it.

**Still open, and deliberately not forced:**

1. **Clean break, or migration from v11?** Recommendation stands: refuse to mount v11 rather than
   ship a converter that must stay correct forever, given that the only volume in existence is a
   test bed that is wiped freely. This only has to be answered when the second change begins.
2. **Does the Merkle root get anchored to the TPM?** `meta_root` is verified at unlock against the
   superblock, which detects tampering but not **rollback**: an attacker with the disk can restore
   a whole earlier volume, consistent root and all. Under decision 1 this now matters more than it
   did, because the boot-time policy is on that disk and rolling it back is a privilege change.
   Sealing a counter or the root to a PCR closes it, and it is a boot-chain change.

## 6a. The decisions as they were originally put

1. **Does a file capability persist across a reboot, and if so how?** A cspace is a kernel object
   and does not survive one. The options are a sealed on-disk table mapping a durable identifier
   to a rights set (which reintroduces something disk-writable and must therefore be inside the
   Merkle tree and the AEAD), or an unlock-time bootstrap in which `init` holds the root
   capability and everything else is derived fresh each boot from a policy. The second is cleaner
   and means the disk holds no authority whatever; it also means "this user owns these files" has
   to be expressed somewhere else. **This is the load-bearing decision and it should be taken
   first**, because both the on-disk format and the security argument follow from it.
2. **Clean break, or migration from v11?** A migration path is a second implementation of the
   old format that must stay correct forever, and the only volume in existence is a test bed that
   is wiped freely. I recommend a clean break with a refusal to mount v11, not a converter.
3. **Does the Merkle root get anchored to the TPM?** Today `meta_root` is verified at unlock
   against the superblock, which detects tampering but not **rollback**: an attacker with the disk
   can restore a whole earlier volume, consistent root and all. Sealing a counter or the root to a
   PCR closes that, and it is a boot-chain change.
4. **Is copy on write accepted, with the allocator work it implies?** §5.
5. **How much of this is one change?** My recommendation is that it is not. The authority model
   (§4) is separable from the layout (§3) and should land first, against the *existing* on-disk
   format, so that the security change is reviewable on its own and not buried in a rewrite.

## 7. Performance, and the one design choice that costs the most

The brief is parity with the major Unix filesystems or better. That is a harder bar than it
sounds, because the present design has a cost that none of them carry, and it was found by
debugging a laptop rather than by reading the code.

**FORMATTING IS O(VOLUME SIZE), AND IT DOES NOT HAVE TO BE.** Every block has a 32-byte entry in
a side table holding its nonce and its authentication tag, so the table is exactly 1/128th of the
volume. A 16 GiB volume therefore has a 128 MiB table, and formatting **writes all of it**: 32,768
block writes before a single byte belongs to the operator. It used to read all of it back as
well, so the Merkle build hashed what was on the medium; the writes are now checked and the tree
is built from the block they wrote (`docs/LIMITATIONS.md` 5.2i), which halved the pass count but
not the order. On an eMMC laptop the format was twenty minutes and was twice reported as a hang.
ext4 formats a 16 GiB volume in about a second, and the difference is not implementation
quality, it is this table.

**THE NONCE DOES NOT NEED STORING.** It can be derived: `nonce = f(disk_key, block, generation)`.
Under copy on write a rewritten block is a new block with a new generation, so derived nonces are
unique by construction, which is the same argument §5 makes for copy on write and is the reason
the two decisions belong together. That removes 12 of the 32 bytes and, more importantly, removes
the reason the table has to exist at format time at all.

**THE TAG BELONGS IN THE PARENT, NOT IN A SIDE TABLE.** This is what ZFS does and it is better
than what Horus does now. A block's authentication tag is stored in the structure that points at
it, which is itself authenticated by *its* parent, up to a root in the superblock. Then:

- there is no side table, so a format writes a superblock, a root node and an empty allocator, and
  costs **O(1) rather than O(volume)**;
- the Merkle tree stops being a separate structure built over the whole table, because the
  pointer tree *is* the Merkle tree;
- a block cannot be verified without walking the path that reaches it, which is the property that
  makes a substituted block detectable rather than merely unlikely;
- integrity and confidentiality stay in one AEAD construction per block, which is the part of the
  current design worth keeping.

**The rest is ordinary, and ordinary is the point:**

| | why it is needed for parity |
|---|---|
| Extents | Sequential reads become one descriptor and one long transport run instead of a pointer per block. The transport can now carry runs (2026-09-23); nothing above it asks for them |
| B-tree directories | The current directory is a linear array, so lookup is O(n) and every create rescans. This is the single biggest gap against ext4 and XFS on a real workload |
| Delayed allocation | Batches writes into contiguous extents instead of allocating per block, which is what makes the extent above actually contiguous |
| Read-ahead | Free once extents exist, because the next block's location is known rather than looked up |
| Lazy metadata | Whatever per-block state survives, initialised on first use. `storage_alloc_inode` already does exactly this for the inode table, and the reason given there is the reason here |

**WHAT PARITY WILL AND WILL NOT MEAN.** PIO is the transport, and no filesystem design recovers
what DMA gives. Parity is to be claimed per operation, against a measurement, and never as a
general statement: "lookup in a directory of N is O(log N)", "a format is constant time",
"a sequential read of an extent issues one command per run". A claim that Horus is as fast as
ext4 without naming the operation and the machine is the kind of claim
`docs/LIMITATIONS.md` now warns about for storage generally.

## 8. What is not a filesystem problem, and was fixed first

Volume creation is slow for two reasons, and only one of them is the layout in §7. The other was
transport, and it was fixed on 2026-09-23 rather than designed around.

The format writes about **2.3 MB** and costs about **4,700 synchronous operations**, measured as
`format ≈ 5.2s + 4700/IOPS` (`docs/LIMITATIONS.md` 5.2h). The reason is that both storage
backends move **one 512-byte sector per command** while a filesystem block is 4096 bytes:
`ata.c` sets `ATA_SECCOUNT` to 1, and `sdcard_write` issues eight single-block `CMD24` writes per
block. 576 blocks times 8 is 4,608, which is the measured figure.

That was fixed on 2026-09-23: ATA issues one `READ`/`WRITE SECTORS` per run, the SD path uses
`CMD18`/`CMD25`, and regions are cleared in runs fed from a single sector. **Identical bytes,
identical cryptography, a fraction of the round trips.** It was done first so the new design is
measured against a transport that is not wasting seven eighths of its commands, and so that any
remaining slowness is attributable to the layout rather than to the wire.

**It is also the reason §7 exists.** Fixing the transport moved the bottleneck onto the Merkle
build, which read the entire side table back. That read-back is gone now, and what remains is
still not a transport problem: it is the consequence of storing per-block crypto metadata in a
table proportional to the volume, which a format must write whole. The wire was the cheap half.

---

## Falsification

Nothing here is a claim about the tree yet. When it becomes one, each property below needs a
witness in `SECURITY.md` and a control arm that reddens the base gate, per §2:

- A task holding a read-only file capability cannot write, and the arm removes the rights check.
- A derived capability cannot exceed its parent's rights, which the existing revocation and
  derivation proofs should extend to cover rather than duplicate.
- Revoking a directory capability revokes every file capability derived through it.
- No operation succeeds on the strength of the caller's uid, and the arm restores the uid check
  so the gate can be shown to catch it.
- A volume whose `meta_root` is rolled back to a consistent earlier state is refused (only if
  decision 3 is taken).
