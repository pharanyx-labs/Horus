# An installed system: what lives on the disk, and how it is trusted

**Decided (§8); two of three steps built.** The disk boots itself (#503, #505) and its programs are on it (#506); accounts as files (§9 step 3) are not started. A live boot writes nothing (S110, #472). The maintainer asked on 2026-09-24 for an install that works the
way other major operating systems do: every file the system needs copied onto the volume,
binaries in `/bin` and `/sbin` placed sensibly, `/tmp` and `/var` created, man pages copied, and
a machine that boots from its own disk. This document says what that changes, and puts the
decisions that touch the trusted computing base (CLAUDE.md §4) with a recommendation for each.

It builds on [`filesystem.md`](filesystem.md) and does not reopen its decisions: the disk holds no
authority (decision 1), and the capability change lands before any format change (decision 2).

## 1. What exists today, stated honestly

| Question | Today |
|---|---|
| What is on an installed volume | An encrypted, Merkle-verified filesystem holding the system trees (`/bin`, `/sbin`, `/lib`, `/usr`), `/etc`, `/home` and `/var`, and the sealed account table |
| Where programs come from | `init`, `shell`, `fs_server`, `console_server`, `dev_server`, `installer` and `netd` are **compiled into the kernel image** and spawned by name (section 3). User commands that are programs (GNU coreutils, TCC) run from `/bin` on the volume |
| What `/bin` is | A system tree `fs_server` rebuilds at every boot from the boot modules the kernel verified: a file whose bytes match its module is kept, any other is rewritten, anything no module names is removed, and every change to it is refused, root included (**S116**, decision 7). The install media carries GNU coreutils and TCC as modules, and so does `make run`; the plain `horus.iso` carries none |
| How a program is trusted | The kernel image and every boot module are checked against SHA-256 pins inside the measured boot image (**S92**), measured into `PCR[4]`/`PCR[8]` |
| How the machine boots | From its own disk under UEFI, when installed from `install.iso`: the installer lays out the GPT and EFI system partition of section 6 (S114, S115). Verified under QEMU's OVMF and on the IdeaPad 1 14IGL05's own firmware. The install media's menu offers live boot and install only, and since #472 a live boot opens no disk, so it cannot start an installed system |
| Man pages | Boot modules under `/usr/share/man`, a system tree like `/bin`. The licence texts and the source offer are in `/usr/share/doc` |

## 2. The layout proposed

A Filesystem Hierarchy Standard shape, trimmed to what exists:

| Path | Holds | Notes |
|---|---|---|
| `/bin` | Programs a user runs: the shell, and every user command that is a program rather than a builtin | Read-only at run time (§4) |
| `/sbin` | Programs that administer the machine or are run by `init`: `installer`, and account tools as they become programs | Read-only at run time. See §3 for why the boot-critical servers are not here |
| `/lib` | Shared libraries (`libhorus`, and newlib's where a program links it) | Read-only at run time |
| `/etc` | Configuration, as today | |
| `/home` | Users' files, as today | |
| `/tmp` | Scratch, **emptied at every boot** | Recommendation in §5 |
| `/var` | State that survives a reboot: `/var/log` for the audit chain's persisted copy, `/var/tmp` for scratch that must survive | |
| `/usr/share/man` | Man pages, one directory as today | Copied by the installer |

**The `/bin` and `/sbin` split follows one rule**: a program belongs in `/sbin` when running it is
an administrative act (it changes the machine, not the user's files) or when only `init` starts
it; everything else is `/bin`. With what exists today that puts the shell and the user commands
in `/bin`, and the `installer` in `/sbin`.

## 3. The boot-critical servers cannot be loaded from the disk

`init`, `fs_server` and `console_server` run **before the volume is unlocked**: `fs_server` is how
the volume is read at all, and the console is how the password that unlocks it is typed. They
cannot come from `/sbin`, because nothing can read `/sbin` until they are running. This is the
same reason every Unix has an initramfs.

**Recommendation: they stay inside the measured boot image, and they do not appear in `/sbin`.**
A copy in `/sbin` that is not what runs is worse than no copy: an administrator reading
`/sbin/fs_server` would be reading a file that has no bearing on the machine, and replacing it
would appear to work and change nothing. The alternative, loading them from the EFI system
partition as boot modules measured by the loader, is a later refinement that changes nothing
about this rule.

## 4. How a program on the disk is trusted (the decision that matters most)

Today nothing the volume holds can run, so the question never arose. Once `/bin` is on the disk,
the loader has to decide whether a file there may execute.

- **(A) A signed manifest. Recommended.** The build signs a manifest listing the SHA-256 of every
  system file it installs. The public key is pinned inside the measured boot image, beside the
  kernel's own hash (S92). The loader refuses to execute a file under `/bin`, `/sbin` or `/lib`
  whose hash is not in a manifest that verifies. A write to the disk, by an attacker with the raw
  blocks or by a compromised `fs_server`, then cannot make code run: **by construction, not by
  remembering** (§1). It also answers what an update is: a new manifest, signed by the same key.
- **(B) Trust the sealed volume.** Anything on the encrypted, Merkle-verified volume runs. This is
  simpler and protects against someone with the disk and not the key, but not against anything
  that can write a file through the filesystem, which under filesystem decision 1 is whoever holds
  a write capability to `/bin`. It makes the policy the only guard on what executes.
- **(C) Both**, (A) for system paths and (B) for a user's own programs under `/home`. This is where
  (A) leads anyway once users compile their own programs with TCC, and it can be added later
  without changing (A).

Independently of the choice, `/bin`, `/sbin` and `/lib` are **read-only at run time** (decision 7):
`fs_server` refuses every change to them, for every client, so an update is new install media, not
an ordinary file write.

## 5. The smaller decisions

**`/tmp`: emptied at every boot.** Recommendation: a directory on the volume that `init` empties
at boot, rather than a RAM-backed filesystem, because the volume is already encrypted (nothing in
`/tmp` reaches the disk in plaintext) and a RAM filesystem would be a second implementation to
secure. `/var/tmp` is the place for scratch that must survive.

**What goes in `/bin` at all.** The only user programs that are files are GNU coreutils (GPLv3)
and TCC (LGPL). As separate programs beside the MIT system this is aggregation, not a combined
work, and it carries the obligations decision 2 meets: `/usr/share/doc` holds the licence texts
(`horus/LICENSE`, `coreutils/COPYING`, `tcc/COPYING`) and `SOURCE`, a written offer naming the
commit whose `userspace/ports` tree is the exact source of every binary shipped.

**Man pages** come from the same source the `make run` build uses, `userspace/man`, and land in
`/usr/share/man`.

## 6. The bootloader, so the disk boots on its own

The installer writes a **GPT partition table** with three partitions, each sized by the operator
within what the disk holds:

1. An **EFI system partition** (FAT32, 64 MiB) holding GRUB as `\EFI\BOOT\BOOTX64.EFI`, the
   kernel, and the same memdisk that carries the pinned kernel hash on the install media today.
   The build makes the whole partition as an image (mtools), and the installer writes it as raw
   blocks, so Horus carries no FAT writer. The fallback path is used because Horus cannot write
   the firmware's boot entries (it has no UEFI runtime services). UEFI firmware measures what it
   loads into `PCR[4]`, as SeaBIOS does for the ISO, so the measured-boot argument (S11, S92)
   carries over unchanged.
2. A **swap partition**, of Horus's own type (not Linux's, which a Linux system booted on the
   machine would activate and write to unencrypted). Reserved and unused until encrypted swap is
   built.
3. The **Horus volume**, of Horus's own type. The volume-size option (#434) becomes the partition
   size, which is what it always approximated. The kernel finds it by reading the GPT
   (`rust/src/gpt.rs`, S114): both CRCs must verify, exactly one entry may carry the volume type,
   and the partition must be block-aligned and inside the device. A table that is refused is
   never read as a whole-device volume.

A disk with no partition table is still mounted as a whole-device volume, which is what every
volume was before, and what the persistence gates' raw images are.

**How the ESP image is trusted (S115).** The installer's kernel writes the ESP from an image
the install media carries as a boot module. Every other module is pinned by a hash compiled into
the kernel (S96), but this one cannot be: it contains the kernel, so the kernel would have to
hold a hash of itself. It is pinned one level up instead. The install entry's GRUB config, in
the measured memdisk beside the kernel's own pin (S92), passes the image's SHA-256 on the
command line as `horus.esp=`, and the kernel hashes the module where it lies at the moment it
writes it, and compares. Media whose image does not match is refused by the installer before it
asks anything. The image is never readable from ring 3, and `fs_server` never copies it.

Secure Boot is not proposed here: the laptop's firmware would need Horus's own key enrolled, and
measured boot already gives the property that matters for the sealed key, that a modified boot
chain cannot unseal it.

## 7. Accounts: `/etc/passwd` and `/etc/shadow`

The account table today is sealed in a region the kernel reads directly (`storage_users_save`),
and `h_auth` checks passwords in ring 0. The request is for `/etc/shadow` holding just what is
needed.

**Recommendation:**

- `/etc/passwd`, readable by anyone: name, uid, home and shell. No secret.
- `/etc/shadow`: the Argon2id hash, its salt and the lockout state. Nothing else.
- Both are **files on the volume**, so they are inside the AEAD and the Merkle tree like
  everything else, and they are read and written by a ring-3 `auth_server` that holds a capability
  to those two files and nothing else, rather than by the kernel. That moves password handling out
  of ring 0 (§1, shrink ring 0), which is the "much more robust" part: a parser bug in account
  handling becomes a ring-3 fault in one server.
- The **unlock** stays in the kernel: a password still opens a key slot before anything on the
  volume can be read, so the order "unlock, then identify" is unchanged.

**The live boot keeps its promise already.** A live-boot login once unlocked an installed volume
and, when it carried no account table yet, wrote the compiled-in one onto it. Two properties
close that ahead of this design: a table holding a compiled-in password is never written
(`SECURITY.md` S109), and a live boot opens no disk at all (S110).

## 8. The decisions, as taken

Answered by the maintainer on 2026-09-24. Recorded as decisions, not options, because the work
depends on them.

1. **A manifest decides what runs from the disk, and its hash is pinned in the measured boot
   image.** A file under `/bin`, `/sbin` or `/lib` executes only if its SHA-256 is in the
   manifest, and the manifest is accepted only if its own SHA-256 matches the pin beside the
   kernel's (S92). There is no signing key: the trust anchor is the one the kernel already has,
   and updating the system means updating the boot image, as updating the kernel does now. This
   is §4's option A with a hash in place of a signature; it needs no new cryptographic primitive
   and no key to guard.
2. **GNU coreutils and TCC ship in the install image.** The image carries their licence texts and
   an offer of the exact source for every binary shipped, and `/usr/share/man` their pages. This
   is the first GPL code in a Horus release, as separate programs beside the MIT system.
3. **Accounts move to `/etc/passwd` and `/etc/shadow`**, files on the volume read and written by a
   ring-3 `auth_server`; the kernel keeps only the unlock (§7).
4. **The bootloader is GPT with an EFI system partition** carrying GRUB, the kernel and the pinned
   hash, measured as today, with the Horus volume as the second partition. No Secure Boot (§6).

The signing-key question this design first left open was answered the same day by removing the
key: a hash pinned in the measured image needs none (decision 1).

**2026-10-07:**

5. **A user's own programs may run from `/home`: §4's option C.** The manifest still decides
   everything under `/bin`, `/sbin` and `/lib`. Outside them, a program a user built (with TCC, for
   instance) runs on the `EXEC` right of its file capability, which the filesystem policy grants
   (`docs/design/filesystem.md` decision 8). Until the loader starts programs only from file
   capabilities, that right is advisory against any task that can read the file and hand its bytes
   to `SYS_SPAWN_IMAGE`; `docs/LIMITATIONS.md` records it when programs first run from the disk.

**2026-10-08:**

6. **The disk boots itself before the manifest work**, with the layout of section 6: an EFI
   system partition, a swap partition reserved for encrypted swap, and the volume, each sized by
   the operator. Separate system and home volumes wait for filesystem phase 2, since the kernel
   mounts one volume today and phase 2 rebuilds the store anyway.
7. **The system trees are rebuilt at every boot from the verified modules, and nobody can change
   them, root included.** `/bin`, `/sbin`, `/lib`, `/usr`, `/usr/share`, `/usr/share/man` and
   `/usr/share/doc` hold exactly the boot modules that passed the kernel's manifest (S96), whose
   own hash is pinned in the measured image (S92), so decision 1's rule holds by what the trees
   contain rather than by a check in the loader, which is handed bytes, not paths. An update is
   new install media. A task can still spawn bytes it read from anywhere (`docs/LIMITATIONS.md`
   1.23) until programs start from file capabilities. **S116**.

## 9. Order of work

1. The bootloader and partition table (decision 6). Done (#503, #505).
2. The layout and the programs on the disk, held to the manifest by decision 7. Done (#506).
3. `/etc/passwd` and `/etc/shadow` with the ring-3 `auth_server`.

Each is its own PR with its own gates and control arms. The copy on write and extents work from
[`filesystem.md`](filesystem.md) is independent of all three.

## Falsification

Each step names the gate that would go red if it were false before it is built:

- **Nothing but a verified module is in the system trees.** Built: `make smoke-system-trees`
  installs from one media, boots newer media, and requires the new programs, a stray file gone,
  and every change root attempts in `/bin` refused (S116); three arms make each half writable,
  unpruned or trusting of size alone.
- **The disk boots on its own.** Built: `make smoke-install-boot-disk` installs onto a blank disk
  image under OVMF, then boots that image alone with no install media attached, logs in and runs
  `seq` from `/bin` (S114, S115, S116).
- **A live boot writes nothing.** Built: `make smoke-live-locked` hashes the whole disk image
  before and after a live boot that logs in, and requires them to be equal (S110).
