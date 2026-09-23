# A capability-addressed filesystem for Horus

**Status: design, not built. Nothing here is implemented.** It exists to be argued with before
any code is written, because the subject is storage at rest, the authority model and the
cryptography all at once, which is three §4 asks in one change.

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
- That raises the one genuinely hard question, which §6 asks rather than answers: what a
  capability *persists* as across a reboot, given that cspaces do not survive one.

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

## 6. The decisions that need the maintainer, before any code

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

## 7. What is not a filesystem problem, and should be fixed first

Volume creation is slow, and it is tempting to design around it. It should not be, because the
cause is transport and not layout.

The format writes about **2.3 MB** and costs about **4,700 synchronous operations**, measured as
`format ≈ 5.2s + 4700/IOPS` (`docs/LIMITATIONS.md` 5.2h). The reason is that both storage
backends move **one 512-byte sector per command** while a filesystem block is 4096 bytes:
`ata.c` sets `ATA_SECCOUNT` to 1, and `sdcard_write` issues eight single-block `CMD24` writes per
block. 576 blocks times 8 is 4,608, which is the measured figure.

One command per block (`ATA_SECCOUNT = 8`, and `CMD25 WRITE_MULTIPLE_BLOCK` on eMMC) writes
**identical bytes with identical cryptography** and should cost about an eighth as many
operations. That is a separate, small, security-neutral change and it should be made before any
filesystem work, so that the new design is measured against a transport that is not wasting
seven eighths of its round trips.

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
