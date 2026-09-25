# A capability-addressed filesystem for Horus

**Status: specification, not built. Nothing here is implemented.** Every load-bearing question
has been answered by the maintainer: three on 2026-09-23 and four more on 2026-09-25. §13
records them all as decisions. What remains open is listed there too, and none of it blocks the
first phase.

The brief, in the maintainer's words: "a much more robust filesystem, a hybrid of the major unix
ones out there but definitely unique and most importantly, secure" (2026-09-22), and "least
privilege from the ground up while being as featureful as the major unix filesystems"
(2026-09-25).

The design has two halves, and they must not be confused:

- **Least privilege from the ground up** is about *who holds what*: the kernel, the filesystem
  server, a client, the policy. §3 to §7.
- **As featureful as the major Unix filesystems** is about *what the format can do*: extents,
  B-tree directories, copy on write, snapshots, reflinks, extended attributes, symlinks,
  timestamps. §8 and §9.

The first half is where Horus is unique. The second is where it has to be ordinary, and ordinary
is the goal.

---

## 1. What exists today, stated honestly

It would be easy to write this document as though Horus had no filesystem. It has a good deal,
and the parts worth keeping are the parts most systems get wrong.

| Property | Today |
|---|---|
| Confidentiality at rest | Per-block AEAD (ChaCha20 with HMAC-SHA256, encrypt then MAC). `disk_key` is wrapped by a KEK derived with Argon2id from the passphrase, LUKS style, and never stored in plaintext. A volume can be formatted unsealed when the operator chooses that (S104) |
| Nonces | A **fresh random** 96-bit nonce per block write, stored in a side table with the tag |
| Integrity | A Merkle tree over the metadata region, rooted in `meta_root` in the superblock and verified at unlock (S66) |
| Rollback of the whole volume | Refused on a TPM machine: `sb.rollback_gen` is bound into the root and checked against a TPM NV monotonic counter at unlock (S70, `docs/LIMITATIONS.md` 1.12) |
| Crash atomicity | A write-ahead redo log: stage, commit with an HMAC-authenticated header, then apply |
| Privilege separation | `fs_server` runs in ring 3 and **never sees key material**; the kernel does the crypto behind `SYS_FBLOCK_READ`/`WRITE` |
| Layout | Superblock, inode bitmap, block bitmap, data bitmap, inode table, data region |
| Directories | An array of `fs_dirent` records in ordinary inode data; root is inode 0 |
| Authority | Kernel-attested uid/gid (`SYS_IPC_SENDER`) and Unix mode bits |

The first six rows are better than most filesystems in use. A redesign that lost any of them
would be a regression however modern the rest looked.

**Two things the table hides.** First, the layout does not live where the table implies.
`fs_server` enforces who may do what, but the superblock, the inode table, the write-ahead log,
the Merkle tree and fsck are all in `src/kernel/storage.c`, 4,998 lines of ring 0, and the kernel
knows what an inode is (`SYS_FBLOCK_READ` takes an inode number). Roadmap 2.7a names that file as
the largest piece of evictable policy in the kernel. Second, the feature set is thin:

| A Unix program expects | Today |
|---|---|
| Symbolic links | None |
| Timestamps | None; the kernel has only a monotonic clock since boot (`SYS_CLOCK_GETTIME`) |
| Moving a directory to another parent | Refused (`FS_OP_RENAME` allows a directory to be renamed only within its own parent) |
| Large directories | A linear array: lookup is O(n) and every create rescans |
| Sparse files, `fallocate`, `O_TMPFILE`, locks | None |
| Snapshots, reflinks, extended attributes | None |

## 2. The defect worth redesigning around

**The filesystem authorises by identity, in a system whose entire thesis is that nothing
authorises by identity.**

`FS_OP_CHMOD` is "owner or root". `FS_OP_CHOWN` is "root only". `FS_OP_STAT` returns `uid` and
`gid`, and `perm_ok` in `userspace/fs_server.c` compares them against the caller's. The uid is
not forgeable, because it comes from `SYS_IPC_SENDER` and never from anything the client asserts,
so this is not a hole an attacker walks through today. It is something worse in the long run: it
is **`uid == 0` ambient authority**, the exact thing roadmap 0.2 retired from the kernel on
2026-07-27, still running in ring 3 because the filesystem was written before that change and
never revisited. And any client may connect: `SYS_CONNECT_FS_SERVER` mints a send capability for
whoever asks, so reaching the filesystem at all is ambient.

CLAUDE.md §1 says it plainly. Nothing is granted for who you are. A filesystem that asks "are you
root?" has an answer for that question, and the answer is a standing grant that no capability
mediates, cannot be attenuated, cannot be delegated for one file, and cannot be revoked short of
changing the uid.

So the unique property this design is organised around is not a tree structure or a checksum
algorithm. It is this: **a file handle is a capability, and there is no other way to reach a
file.**

## 3. The threat model

Each party below is assumed hostile in the way stated. The right-hand column is what the design
guarantees against it; anything not in that column is not claimed.

| Adversary | Can | Cannot, by construction |
|---|---|---|
| **The disk in someone else's hands** (offline) | Read ciphertext; see which blocks are in use and roughly how large the volume's contents are; write any block; restore an old image | Read plaintext without the passphrase; forge or move a block undetected (the tag is in the authenticated parent, and the AAD names the block's address); present an earlier volume as current on a TPM machine (S70). Change anyone's authority, **because no authority is on the disk** (decision 1) |
| **A compromised `fs_server`** | Read and write every file on the volume it serves (it is the filesystem); lie to its clients | Learn `disk_key` or any key derived from it; make the kernel reuse a nonce; hand a client a capability with rights beyond the capability that client invoked; reach any object outside the filesystem |
| **A hostile ring-3 client** | Send any request on a capability it holds, with any bytes in it | Reach an object no capability it holds leads to; widen a right; climb above a directory capability with `..` or a symbolic link; make the server interpret a path; gain rights by moving or linking a file (§5.5) |
| **Hostile names and contents** | Choose file names designed to collide in a hash; create deep trees and huge directories | Degrade lookup to linear time (the name hash is keyed with a per-volume secret); exhaust space reserved for deletion (§8.9) |
| **A device** (DMA) | Write memory it is mapped to | Everything the IOMMU gates already refuse; this design adds nothing and removes nothing |

**The kernel is trusted**, and the design's purpose is to make it trusted for less: the key, the
nonce, the seal, and the root anchor, and nothing that knows what a file is.

## 4. The layering: who holds what

The decision of 2026-09-25 is that **the kernel seals blocks and nothing more**. Every structure
that means something to a filesystem moves to ring 3.

| Component | Ring | Holds | Does |
|---|---|---|---|
| Kernel sealed-block service | 0 | `disk_key` and the keys derived from it; the nonce counter; the TPM anchor | Seals a block to a physical address and returns its nonce and tag; opens a block given its address, nonce and tag; commits a new root with a transaction number that only goes up; verifies the root at unlock |
| `fs_server` | 3 | A volume capability (seal, open, commit) and the receive end of its endpoint | The whole format: the tree, directories, extents, the allocator, copy on write, snapshots, xattrs. Answers single-component requests on capabilities the kernel attests |
| `fs_scrub` | 3 | A **read-only** volume capability | Walks the tree and opens every block, so latent corruption is found before it is needed. Cannot write |
| `init` | 3 | The root directory capability, minted at unlock | Evaluates the policy (§6) and hands every other task only the subtrees the policy names |
| A client (libc, `hvfs`) | 3 | Directory and file capabilities | Walks paths, resolves `..` and symbolic links **itself**, against capabilities it already holds |

This closes most of the `storage.c` row of roadmap 2.7a: the superblock parser, the inode table,
the write-ahead log, the Merkle builder and fsck leave ring 0, and what stays is the part that
must, because it holds the key.

### 4.1 The kernel interface

Three calls replace `SYS_FS_INODE_ALLOC`, `SYS_FS_INODE_FREE`, `SYS_FBLOCK_READ`,
`SYS_FBLOCK_WRITE`, `SYS_FS_STAT`, `SYS_FS_SET_SIZE`, `SYS_FS_SET_META` and `SYS_FS_INODE_LINK`,
each gated by a `CAP_VOLUME` capability whose rights say which calls it permits:

- **Seal** `(vol, phys, buf, kind) -> (nonce, tag)`: the kernel chooses the nonce (§4.2), seals
  `buf` with AAD `(volume id, phys, kind)`, writes the ciphertext to `phys`, and returns the nonce
  and tag. The caller stores them in whatever points at the block. WRITE right.
- **Open** `(vol, phys, nonce, tag, kind, buf)`: reads `phys`, verifies against the tag the
  caller supplies, and decrypts into `buf`, or fails without writing a byte of `buf`. READ right.
- **Commit** `(vol, root pointer, txg)`: writes the next superblock slot with the new root, and
  refuses a `txg` that is not greater than the last committed one. The TPM anchor (S70) is bound
  into what the superblock authenticates, exactly as `rollback_gen` is today. WRITE right.

Unlock gives `fs_server` the committed root pointer and nothing else. The kernel never parses
anything below the root, so a malformed tree is a ring-3 fault in one server, not a kernel
parser bug.

`kind` separates block types (tree node, data, superblock) inside the AAD, so a data block can
never be presented where a tree node is expected even by a server that confuses them.

### 4.2 The nonce is the kernel's, always

The 2026-09-23 version of this document proposed deriving each nonce as
`f(disk_key, block, generation)` so it would not need storing. **That was wrong for this
layering.** The generation would be chosen by `fs_server`, and a compromised `fs_server` could
repeat one and make the kernel encrypt two different blocks under the same ChaCha20 keystream.
Nonce uniqueness must not depend on ring 3.

The construction: **`nonce = epoch (32 bits) || counter (64 bits)`**, chosen by the kernel on
every seal.

- `counter` increases by one per seal and is never reset. The kernel reserves ranges ahead of
  use by committing a high-water mark in the superblock, so after a crash it resumes above
  anything it could have issued. Within a volume's life, in normal operation, **no nonce repeats,
  by construction**, with no birthday bound (a random 96-bit nonce is safe only to about 2^32
  writes per key, which a long-lived disk can reach).
- `epoch` is drawn at random at every unlock. It exists for the case the counter cannot
  cover: someone restores an old image, rewinding the high-water mark, and the volume is then
  written again. On a TPM machine S70 refuses that image. On a machine without one, a repeat
  now needs the same random epoch as well as an overlapping counter.

The nonce is stored in the parent pointer beside the tag (§8.2), so 12 bytes per pointer are
the price. Storing it is not what made formatting slow; the side table was (§10).

### 4.3 Unsealed volumes

An unsealed volume (S104) keeps the same construction with its key in the clear, as today. The
tags then detect corruption, not tampering, and every boot keeps saying which kind of volume it
found.

## 5. Capabilities for files

### 5.1 The kernel primitive this needs

The kernel's IPC has no way today for a server to know *which* of its capabilities a message
arrived through, and no way to hand a capability back in a reply. Both are needed, and nothing
more:

1. **A token on an endpoint capability.** A send capability to an endpoint may carry a 64-bit
   token. On receive, the kernel delivers the token **and the rights** of the capability the
   message was sent through. The server trusts both because the kernel attests them; the client
   cannot choose either.
2. **Reply-mint.** When a server replies, it may ask the kernel to mint one new capability into a
   slot the caller named in its call. The kernel derives it **from the capability the request was
   sent through**: same endpoint, a token the server chooses, and rights that are the server's
   request **intersected with the invoking capability's rights**. So the new capability is a
   child of the invoking one in the derivation tree, and revoking a directory capability revokes
   everything opened through it with the machinery that already exists (S3).
3. **Carry one capability.** A call may carry one further capability, and only one to the same
   endpoint. The server receives its token and rights, not the capability. This is what `rename`
   and `link` need, since they name two directories.

`fs_server` therefore holds no mint authority of its own. It cannot fabricate a capability; it
can only narrow the one a client invoked. `SYS_CONNECT_FS_SERVER` and the uid/gid half of
`SYS_IPC_SENDER` retire from the filesystem path. The first capability, the root directory, is
minted by `init`, which creates the endpoint and so holds its mint right (§6.1).

### 5.2 The token

The token is `fs_server`'s own business, but it must meet two requirements:

- **It never names a different object than the one it was minted for.** In the new format object
  ids are never reused (§8.3), so the id alone suffices. In phase 1 on the v11 format inode
  numbers are reused, and the token carries a per-inode generation kept in memory, since
  capabilities do not outlive a boot. An inode whose generation would wrap is retired until the
  next boot rather than reused.
- **It carries the policy grant it descends from** (§6), which the truthful view (§7) and the
  rename rule (§5.5) need.

A stale token (the object was deleted) is refused with `NOENT`. It never falls through to
whatever now occupies the slot.

### 5.3 Rights

| Right | On a file | On a directory |
|---|---|---|
| `READ` | Read data, `stat`, read xattrs | List entries, `stat` |
| `WRITE` | Overwrite, truncate, `fallocate` | (not meaningful) |
| `APPEND` | Write only at the end: a log a task may add to and never rewrite | (not meaningful) |
| `EXEC` | Execute (see §7.3 for where this is and is not enforced) | (not meaningful) |
| `LOOKUP` | (not meaningful) | Derive a capability to a named child |
| `CREATE` | (not meaningful) | Add an entry: create, `mkdir`, `symlink`, link in, rename in |
| `DELETE` | (not meaningful) | Remove an entry: unlink, `rmdir`, rename out |
| `SETATTR` | Set timestamps, set and remove `user.*` xattrs | The same, on the directory itself |
| `SNAPSHOT` | (not meaningful) | On the root only: create, list and roll back snapshots (§8.7) |
| `GRANT` | May be passed to another task (the kernel's existing right) | The same |

**A directory's rights are inherited, and only shrink.** A child capability derived through a
directory capability carries at most that directory's rights, masked to what makes sense for the
child's type. A read-only view of `/usr` yields read-only files and read-only subdirectories all
the way down. The kernel enforces the "at most" (§5.1); `fs_server` only chooses how far below it
to go.

### 5.4 Paths belong to the client

**The server answers single-component requests only.** `LOOKUP(dir, "name")` is the whole of
path resolution on the server side. It never sees a `/`, never interprets `..`, and never follows
a symbolic link. A name containing `/` or equal to `.` or `..` is refused.

The walk is the client's, in `hvfs` (roadmap 2.4), against capabilities the client already
holds:

- **`..` pops the walker's own descent stack**, as `hvfs` has done since 2026-08-23. It can never
  climb above the capability the walk started from, because there is no request that would.
- **A symbolic link is a string the client resolves**, relative to the directory holding it, or
  for an absolute target relative to the task's own root capability (which is not the volume
  root unless the policy gave it that). The loop limit is 40, as on Linux. A symbolic link can
  never widen authority, because following one uses only authority the client already holds.

This is `openat2(RESOLVE_BENEATH | RESOLVE_IN_ROOT)` as the only mode there is, rather than an
option a careful program remembers to ask for.

### 5.5 Rename and link never widen anyone's reach

Because rights come from the path, moving an object changes who can do what to it. Unix does not
have this problem, since its permissions sit on the inode; this design has it and must close it.
The attack it prevents: a task holding `DELETE` on `/etc` and write access to its own home moves
`/etc/passwd` into its home and writes to it.

**The rule.** Within one directory, `rename` needs `CREATE` and `DELETE` on that directory. Across
directories, `rename(A/x, B/y)` and `link(x, B/y)` also need both of these to hold:

1. the caller's rights over `x` (through the capability it presented) include every right its
   capability to `B` would confer on `x`, `GRANT` included; and
2. **no policy grant reaches `x` with more rights through `B` than it already has**, computed from
   the compiled policy (§6) and each object's back-references (§8.3).

Condition 1 covers the capabilities the caller has handed out at run time, since those are
bounded by the caller's own. Condition 2 covers everyone else, since every other capability is
bounded by some policy grant. A move that fails either returns `EXDEV`, and `mv` falls back to
copying, which is always honest: the copy is a new object the caller made with rights it already
held, and the original stays where its other holders expect it.

Hard links to directories are refused, as on every Unix.

### 5.6 What the server keeps per client

Nothing. Rights and token arrive with every message, attested by the kernel, so a request is
authorised from what is in it. The one exception is state that must outlive a request (a lock, an
unlinked file still open, an `O_TMPFILE`), which needs to know when the last capability carrying
a token is gone. That is a fourth kernel primitive, a **no-senders notification** (as in Mach),
and it lands with those features in phase 4, not before.

## 6. Policy and principals

Decision 1: capabilities are derived fresh each boot from a policy, and the disk holds no
authority. So the policy is the protected object.

### 6.1 Where authority starts

At unlock `init` creates the filesystem endpoint, spawns `fs_server` with its receive end and a
volume capability, and mints the **root directory capability** for itself. Everything else
descends from that capability. No task gets filesystem access by asking.

### 6.2 The policy file

`/etc/fs.policy` is an ordinary file, so it is inside the AEAD and the tree like everything else,
and a whole-volume rollback of it is refused on a TPM machine (S70). Each line grants one
principal one subtree with a set of rights:

```
# principal   path            rights
@all          /bin            read,lookup,exec
@all          /lib            read,lookup
@all          /usr            read,lookup,exec
@all          /etc/passwd     read
alice         /home/alice     read,write,lookup,create,delete,setattr,exec,grant
@admin        /               all
```

- A principal is an account name from `/etc/passwd` or a group (`@name`). `@all` is every
  authenticated session.
- Rights are the §5.3 names. `all` is every right.
- **Nothing is granted that is not written down.** A path absent from the policy is reachable only
  through a capability to an ancestor that is in it.
- Writing the policy is a privilege change, so it takes a write capability to `/etc/fs.policy`,
  which the example gives only to `@admin`.

**Evaluation.** `auth_server` (from `docs/design/installed-system.md` §7) authenticates a login
and asks `init` for the session. `init` walks each granted path from the root capability, derives
a capability with exactly the granted rights, and grants those capabilities, and nothing else, to
the session's first task. The compiled policy is also handed to `fs_server` read-only, because
§5.5 and §7 need it.

### 6.3 What this removes, and is glad to

- **No setuid or setgid.** There is no identity to switch to. A program that needs more
  authority is started by something that holds it and grants it.
- **No sticky bit, and no shared `/tmp`.** Each session gets a private `/tmp`, a directory created
  for it at login and removed at logout, and nobody else holds a capability to it. The problem the
  sticky bit exists to solve never arises.
- **No device nodes.** A device is a capability (`CAP_IO_DEVICE`, S43), never a file, so creating
  a file can never create access to hardware. `mknod` is refused.
- **No named pipes or Unix sockets in the filesystem**, for now: each would be a rendezvous that a
  directory capability grants implicitly. They can come later as objects that hand out a pipe or
  endpoint capability on open, and until then they are refused, not faked.

## 7. The POSIX view: truthful, never reassuring

GNU coreutils will ship (installed-system decision 2), and `ls -l`, `chmod`, `cp -p`, `tar`,
`install`, `ssh` and git all expect owners and mode bits. The decision of 2026-09-25 is a
**truthful synthesised view**: nothing ever reports a file as protected when it is not.

### 7.1 `stat`

- **Owner bits** are the rights of the capability the caller used: `r` for `READ`, `w` for
  `WRITE`, `x` for `EXEC` on a file or `LOOKUP` on a directory.
- **Group bits** are always zero. Groups are a policy notion, not a file one.
- **Other bits** are the union of the rights every *other* policy grant has over the object,
  through any path that reaches it. That is a sound upper bound, because a capability anyone
  holds at run time descends from some grant and cannot exceed it. It can overstate who may read
  a file; it can never understate it.
- **`st_uid`** is the caller's own uid, and **`st_gid`** its primary group. They say "you", which
  is the only identity a capability tells the server anything about.
- Timestamps, size, link count and inode number (the object id, truncated to 64 bits) are real.

### 7.2 `chmod` and `chown`

**They succeed only when they ask for what is already true, and otherwise fail with `EPERM`.**
`chmod 600` on a file in a private home, where no other grant reaches it, is true and succeeds.
The same command on a file in a shared directory is false, fails loudly, and the user learns that
the file is shared: which is what `chmod` was being asked to prevent. `chown` to the caller's own
uid succeeds; to anyone else it fails. Changing who can reach a file is done by changing the
policy or by where the file lives, never by a bit that looks like protection.

### 7.3 `EXEC`, honestly

The `EXEC` right is enforced where a program is started from a file capability. It is **not**
enforced against a task that can read a file's bytes and hand them to `SYS_SPAWN_IMAGE`, because
that call takes an image from memory. For `/bin`, `/sbin` and `/lib` the manifest pinned in the
boot image decides what runs regardless (installed-system decision 1). For a user's own programs,
`EXEC` is advisory against anything that can read the file until the loader starts programs only
from file capabilities, and that goes in `docs/LIMITATIONS.md` when phase 1 lands, not later.

## 8. The on-disk format (v12)

A clean break: v12 refuses to mount v11 (open question 1, recommendation stands). Every structure
below is written only through seal, read only through open, and reachable only from the
committed root.

### 8.1 Superblocks

A ring of superblock slots at both ends of the volume (as ZFS keeps uberblocks). Each commit
writes the next slot. At unlock the kernel takes the slot with the highest transaction number
that verifies, so a torn write of the newest slot falls back to the one before it. Each slot
holds the wrapped keys and salts (as today), the root pointer, the transaction number, the nonce
high-water mark, and `rollback_gen` for S70.

### 8.2 The block pointer

Every reference to a block is the same 48-byte structure, and it is also the Merkle edge:

| Field | Bytes | Why |
|---|---|---|
| `phys` | 8 | Where the ciphertext is |
| `nonce` | 12 | Chosen by the kernel at seal (§4.2) |
| `tag` | 16 | The AEAD tag. **In the parent, not a side table** |
| `birth` | 8 | The transaction that wrote it; drives snapshots and freeing (§8.7) |
| `len`, `kind`, `flags` | 4 | Length in blocks for an extent, block type, and whether a second copy exists |

A metadata pointer carries a **second copy** (another `phys`, `nonce`, `tag`), written to a
different region, so a sector of flash that goes bad under a tree node is repaired from its twin
instead of losing the subtree below it (ZFS's ditto blocks). Data is single-copy.

Because every block is verified by the pointer that reaches it, **the pointer tree is the Merkle
tree.** There is no separate tree to build, no side table, and a format writes a superblock, one
root node and an empty allocator: **O(1), not O(volume)**.

### 8.3 One tree for the filesystem

All filesystem metadata lives in one copy-on-write B+tree (as btrfs keeps its filesystem tree),
keyed `(object id, item type, offset)`:

| Item | Key offset | Holds |
|---|---|---|
| `OBJECT` | 0 | Type, size, link count, the three timestamps (§8.6), flags |
| `BACKREF` | parent id | The name this object has in that parent. One per link, so any object's paths are known, which §5.5 and §7.1 need and fsck uses |
| `DIRENT` | keyed hash of the name | Child id and type. The hash is SipHash under a per-volume key, so names chosen to collide cannot make a directory linear |
| `DIRINDEX` | insertion sequence | The same entry, for a `readdir` cookie that stays stable while the directory changes |
| `EXTENT` | file offset | A block pointer to a run of data blocks. A missing range is a hole: sparse files are free |
| `SYMLINK` | 0 | The target string, up to 4,095 bytes |
| `XATTR` | keyed hash of the name | One `user.*` attribute (§8.8) |

**Object ids are 64 bits and never reused.** The next id is in the tree's root, and a deleted
id stays retired. So a token (§5.2) can never alias a newer object.

Names are bytes, up to 255, without `/` or NUL, as on every Unix. Open question 2 asks whether to
refuse control characters as well.

### 8.4 Space

Free space is a second B+tree of free extents keyed by start, with an in-memory index by size
(as XFS keeps two). Allocation looks for a run that fits the whole write, which is what makes an
extent contiguous. Writes are gathered per transaction and allocated at commit (delayed
allocation), so a file written in small pieces still lands in long runs.

### 8.5 Transactions and `fsync`

A transaction gathers every change for a short interval, writes every new block, and ends with
one commit (§4.1). Nothing is overwritten in place, so there is no instant at which the volume is
half old and half new, and **the write-ahead log retires**. `fsync` and `fdatasync` force the
current transaction to commit. A faster intent log for `fsync`-heavy workloads is a later
optimisation, not part of the format's correctness.

### 8.6 Timestamps

`mtime`, `ctime` and `btime` (creation) are stored with nanosecond fields and 10 ms resolution in
practice. **`atime` is not stored**: on copy on write each read would become a write, and it
tells anyone who can `stat` a file when someone last read it. `stat` reports `atime` as `mtime`,
which is what `noatime` does on Linux.

Wall-clock time comes from the RTC, read by a ring-3 time service with a `CAP_IO_DEVICE` for the
RTC's ports. **A timestamp is information, never authority**: nothing authorises on one, because
the clock is untrusted input like any other.

### 8.7 Snapshots and reflinks

- **A snapshot** is a read-only, named, whole-filesystem root kept alive past its transaction.
  Every block pointer records its birth transaction, and each snapshot keeps a list of the blocks
  that died after it (ZFS's dead lists), so deleting a snapshot frees exactly the blocks no one
  else still references, without walking the whole tree.
- **Taking and rolling back a snapshot needs `SNAPSHOT` on the root capability.** Rolling back
  restores the policy file with everything else, which is a privilege change, so it is gated by
  the capability that could already rewrite the policy. A rollback is a new, forward transaction
  whose root reuses the old tree, so the S70 counter keeps advancing and a legitimate rollback is
  never confused with an attacker's.
- **Reading a snapshot** is a read-only capability derived from the root capability at the
  snapshot, so its contents are reachable only by whoever the policy lets reach the root.
- **A reflink** (`FICLONE`, `copy_file_range`) shares extents between two files and counts the
  references in a small table (as ZFS's block reference table), so a clone costs no data writes.
  It needs `READ` on the source and `CREATE` on the destination directory, which is exactly what a
  copy needs, so it grants nothing a copy would not.

### 8.8 Extended attributes

**`user.*` only.** Every other namespace (`security.*`, `trusted.*`, `system.*`, and with it POSIX
ACLs) is refused, because each is an identity-based authority hook on Linux and this filesystem
has no identity to hook. Names up to 255 bytes, values up to 4 KiB, at most 64 KiB per object.
Reading needs `READ`; setting or removing needs `SETATTR`. They are ordinary tree items, so they
are sealed and verified like everything else.

### 8.9 Running out of space

Copy on write needs free space to delete anything, since the delete itself writes new tree
nodes. A reserve (a small fraction of the volume, as ZFS keeps its slop space) is withheld from
ordinary allocation and is usable only by deletions and commits, so a full volume can always be
emptied. **Per-subtree quotas** extend the policy (`alice /home/alice ... quota=4G`), so one
principal filling the disk cannot deny space to another; the quota is charged to the grant
through which the space was allocated.

### 8.10 Deliberately left out

| Left out | Why |
|---|---|
| Deduplication | Whether a write deduplicates tells the writer that someone else has the same block: an information leak between principals |
| Transparent compression | Compressing before encrypting leaks information through length when attacker-chosen data sits beside a secret (the CRIME class). Declined 2026-09-25 |
| Change notification | A cross-task channel that reveals metadata. Declined 2026-09-25 |
| `atime` | §8.6 |
| TRIM by default | Discarding a block tells the device, and anyone who images it, which blocks are free. Available as an explicit operator action, off by default, as dm-crypt does |
| Multiple devices, RAID, online resize | There is no second disk to test on, and nothing needs them |
| POSIX ACLs | A second identity-based authority model layered on the first |

## 9. Parity, feature by feature

| Feature | ext4 | XFS | btrfs | ZFS | Horus v12 |
|---|---|---|---|---|---|
| Extents | yes | yes | yes | yes | yes (§8.3) |
| B-tree directories | htree | yes | yes | ZAP | yes, with a keyed hash |
| Copy on write | no | no | yes | yes | yes |
| Crash atomicity | journal | journal | CoW | CoW | CoW (§8.5) |
| Checksums on data | no | no | yes | yes | yes, a MAC, which also stops forgery |
| Checksums on metadata | yes | yes | yes | yes | yes, a MAC, and two copies |
| Encryption | per directory | no | no | per dataset | the whole volume, names and metadata included |
| Snapshots | no | no | yes | yes | yes (§8.7) |
| Reflinks | no | yes | yes | yes | yes (§8.7) |
| Symbolic and hard links | yes | yes | yes | yes | yes (§5.4, §5.5) |
| Sparse files, `fallocate` | yes | yes | yes | yes | yes |
| Extended attributes | yes | yes | yes | yes | `user.*` only (§8.8) |
| Quotas | user, group, project | user, group, project | per subvolume | per dataset | per policy grant (§8.9) |
| Scrub | no | no | yes | yes | yes, by a read-only task |
| Format cost | about a second | about a second | about a second | about a second | constant (today: O(volume)) |
| Whole-volume rollback refused | no | no | no | no | yes, with a TPM (S70) |
| Authority | uid, gid, mode, ACLs | same | same | same | capabilities only; nothing on the disk |

**Parity is claimed per operation, against a measurement, and never as a general statement.**
PIO is the transport, and no format recovers what DMA gives. Claims take the form "lookup in a
directory of N is O(log N)", "a format is constant time", "a sequential read of an extent issues
one command per run".

## 10. Performance: the choice that costs the most

**Formatting is O(volume size) today, and does not have to be.** Every block has a 32-byte entry
in a side table holding its nonce and tag, so the table is exactly 1/128th of the volume: a
16 GiB volume has a 128 MiB table, and formatting writes all of it before a single byte belongs to
the operator. On an eMMC laptop the format took twenty minutes and was twice reported as a hang
(`docs/LIMITATIONS.md` 5.2h and 5.2i). ext4 formats the same volume in about a second, and the
difference is not implementation quality, it is this table.

§8.2 removes it: the tag and nonce live in the parent, so there is nothing proportional to the
volume to write. The transport work of 2026-09-23 (one command per run instead of per sector, on
both ATA and SD) was done first, so that what remains is attributable to the layout rather than
the wire.

The rest is ordinary, and ordinary is the point: extents make a sequential read one descriptor
and one long transport run; delayed allocation makes those extents contiguous; read-ahead is free
once the next block's location is known rather than looked up.

## 11. Order of work

Each phase is its own set of PRs with its own gates and control arms. Phase 1 lands against the
**existing v11 format** (decision 2), so the authority change is reviewable on its own and the
ambient authority is gone even if the format work stalls.

| Phase | What lands | Removes |
|---|---|---|
| **1a** | Kernel: tokens on endpoint capabilities, reply-mint, carry-one (§5.1), with Kani proofs that a reply-minted capability never exceeds its invoking parent | Nothing yet |
| **1b** | `fs_server` authorises by capability; `hvfs` walks with capabilities; `init` mints the root and evaluates `/etc/fs.policy`; the truthful `stat`/`chmod`/`chown` (§7); the rename rule (§5.5) | `perm_ok`, `FS_OP_CHOWN`'s root check, `SYS_FS_SET_META`, the uid path of `SYS_IPC_SENDER` in the filesystem, `SYS_CONNECT_FS_SERVER` |
| **2** | Kernel sealed-block service (§4.1, §4.2); the v12 tree, extents, space, transactions and snapshots-ready birth times in `fs_server` | The inode table, WAL, Merkle builder and fsck from `storage.c`; the side table; `SYS_FBLOCK_*` and `SYS_FS_INODE_*` |
| **3** | Symbolic links, timestamps and the RTC time service, cross-directory rename, sparse files, `fallocate`, `fs_scrub` | The v11 directory array |
| **4** | Snapshots, reflinks, `user.*` xattrs, quotas; the no-senders notification, and with it locks, open-unlinked files and `O_TMPFILE` | |

Phase 1b and the accounts work of `installed-system.md` §9 step 3 meet at `/etc/passwd`: the
policy names principals from it. Whichever lands second adapts to the first; neither blocks the
other, because phase 1b can name the compiled-in accounts until `auth_server` exists.

## 12. What this design does not claim

- **A compromised `fs_server` is not contained within the filesystem.** It can read and write
  every file on its volume. What it cannot do is reach the key, cause nonce reuse, or leave the
  filesystem. Hiding file contents from the filesystem server itself (the kernel decrypting data
  straight into the client) is possible with this layering but is not in any phase.
- **Rollback within one boot session is not refused**, as S70 already states: the counter
  advances once per unlock.
- **Timestamps are not evidence.** The clock is untrusted.
- **`EXEC` is advisory against a task that can read the file**, until programs start only from
  file capabilities (§7.3).

## 13. The decisions, as taken

Recorded as decisions, not options, because the work depends on them and a design document that
still asks a settled question is stale.

**2026-09-23:**

1. **A file capability is derived fresh each boot from policy. The disk holds no authority at
   all.** There is no owner field, no mode bits and no rights table on the medium, so an attacker
   who can write raw blocks gains nothing by writing them. The cost is that "these files belong to
   this user" lives in the policy (§6), which therefore becomes the protected object.
2. **The authority change lands first, on the existing v11 format** (§11 phase 1).
3. **Copy on write**, taken chiefly for the cryptographic argument: a rewritten block is a new
   block, so an old nonce is never reused for new contents. §4.2 now makes the nonce the kernel's
   as well, which is what makes that argument hold against a compromised server.

**2026-09-25:**

4. **The kernel seals blocks and nothing more** (§4). It holds the key, chooses every nonce, and
   anchors the root. Inodes, directories, extents, the allocator, copy on write and fsck move to
   ring-3 `fs_server`.
5. **The POSIX view is truthful and synthesised** (§7): `stat` reports the caller's real rights and
   a sound bound on everyone else's; `chmod` and `chown` succeed only when they ask for what is
   already true.
6. **Snapshots, reflinks and `user.*` extended attributes are in.** Compression and change
   notification are out (§8.10). Symbolic links, timestamps, sparse files, `fallocate`,
   `O_TMPFILE`, cross-directory rename, locks and B-tree directories were never in question.
7. **The TPM anchor (S70) carries into v12**, bound into every superblock slot.

**Still open, none of them blocking phase 1:**

1. **Clean break from v11?** Recommendation: yes, refuse to mount v11 rather than ship a converter
   that must stay correct forever; the only volumes in existence are test beds. Needed before
   phase 2.
2. **Refuse control characters in names?** A name holding a newline or an escape sequence breaks
   shell scripts and can rewrite a terminal (`ls` of a hostile directory). Refusing bytes `0x01`
   to `0x1f` and `0x7f` closes that at the cost of strict POSIX conformance. Recommendation: refuse
   them. Needed before phase 2.
3. **Should a looser `chmod` succeed?** A `chmod 644` in a private home asks for *more* exposure
   than is true; granting that request would claim nothing false about protection, but it would
   still report a state that is not real. Decision 5 as given refuses it. Recommendation: keep the
   strict rule and revisit only if a real tool breaks on it.

---

## Falsification

Nothing here is a claim about the tree yet. When it becomes one, each property below needs a
witness in `SECURITY.md` and a control arm that reddens the base gate, per §2:

- A task holding a read-only file capability cannot write, and the arm removes the rights check.
- A reply-minted capability never exceeds the capability it was invoked through; the Kani proof
  covers the algebra and an arm lets the server's requested rights through unmasked.
- Revoking a directory capability revokes every file capability derived through it.
- No filesystem operation succeeds on the strength of the caller's uid, and the arm restores
  `perm_ok` so the gate can be shown to catch it.
- `LOOKUP` of `..`, of `.` and of a name containing `/` is refused, and a symbolic link to
  `../../etc` from a capability rooted at a home directory does not escape it.
- A cross-directory rename that would widen a grant's reach is refused, and the arm drops
  condition 2 of §5.5.
- `chmod 600` on a file another grant can read fails, and the arm makes it report success.
- The kernel never issues the same nonce twice for one volume, including across a crash; the arm
  lets `fs_server` supply the nonce.
- A block moved to another address, or presented as another kind, is refused at open.
- A volume whose root is rolled back to a consistent earlier state is refused on a TPM machine
  (S70, carried into v12).
- A full volume can still delete a file.
