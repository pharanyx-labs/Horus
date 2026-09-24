# An installed system: what lives on the disk, and how it is trusted

**Design only, nothing built.** The maintainer asked on 2026-09-24 for an install that works the
way other major operating systems do: every file the system needs copied onto the volume,
binaries in `/bin` and `/sbin` placed sensibly, `/tmp` and `/var` created, man pages copied, and
a machine that boots from its own disk. This document says what that changes, and puts the
decisions that touch the trusted computing base (CLAUDE.md §4) with a recommendation for each.

It builds on [`filesystem.md`](filesystem.md) and does not reopen its decisions: the disk holds no
authority (decision 1), and the capability change lands before any format change (decision 2).

## 1. What exists today, stated honestly

| Question | Today |
|---|---|
| What is on an installed volume | An encrypted, Merkle-verified filesystem holding `/etc`, `/home`, `/lib` and `/usr`, and the sealed account table. **No program is on it** |
| Where programs come from | `init`, `shell`, `fs_server`, `console_server`, `dev_server`, `installer` and `netd` are **compiled into the kernel image** and spawned by name. Nothing is loaded from the volume |
| What `/bin` is | On a `make run` build, a view of GRUB boot modules (GNU coreutils, TCC). **The shipping `horus.iso` and `install.iso` carry none**, deliberately: the Makefile keeps them "module-free (GPLv3-clean)", and Horus is MIT |
| How a program is trusted | The kernel image and every boot module are checked against SHA-256 pins inside the measured boot image (**S92**), measured into `PCR[4]`/`PCR[8]` |
| How the machine boots | Only from the install media. The installer writes the volume over the whole disk, with no partition table and no bootloader, so a laptop's own disk does not boot |
| Man pages | Boot modules under `/usr/share/man`, again only on `make run` builds |

So "copy the binaries onto the disk" is not a copy of something that is there. The shipping
system's programs live inside the kernel, and its user commands are shell builtins.

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

Independently of the choice, `/bin`, `/sbin` and `/lib` should be **read-only at run time**: the
boot policy derives only read capabilities for them, so an update is an explicit act with its own
authority, not an ordinary file write.

## 5. The smaller decisions

**`/tmp`: emptied at every boot.** Recommendation: a directory on the volume that `init` empties
at boot, rather than a RAM-backed filesystem, because the volume is already encrypted (nothing in
`/tmp` reaches the disk in plaintext) and a RAM filesystem would be a second implementation to
secure. `/var/tmp` is the place for scratch that must survive.

**What goes in `/bin` at all.** The only user programs that are files today are GNU coreutils
(GPLv3) and TCC (LGPL). Shipping them in the install image puts GPL code in an MIT project's
release for the first time. As separate programs this is aggregation, not a combined work, but it
carries obligations: the licence texts and an offer of the exact source for every binary shipped.
**This is a licensing decision for the maintainer, not a technical one.** The alternatives are
MIT-licensed replacements (the shell's builtins already cover `ls`, `cat` and others) or shipping
`/bin` with only the shell until those exist.

**Man pages** are copied from the same source the `make run` build uses, `userspace/man`, into
`/usr/share/man`. The same licence question applies to the pages for GNU programs.

## 6. The bootloader, so the disk boots on its own

The installer writes a **GPT partition table** with two partitions:

1. An **EFI system partition** (FAT32, a few tens of MiB) holding GRUB, the kernel, and the same
   memdisk that carries the pinned kernel hash on the install media today. UEFI firmware measures
   what it loads into `PCR[4]`, as SeaBIOS does for the ISO, so the measured-boot argument (S11,
   S92) carries over unchanged.
2. The **Horus volume**, taking the rest of the disk, or the size the operator chose. The
   volume-size option (#434) becomes the partition size, which is what it always approximated.

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

**A defect this closes.** A live-boot login that unlocks an installed volume carrying no account
table yet writes the compiled-in table onto it (`users_unlock_and_restore` calling
`users_persist`), which breaks the live entry's promise that it changes nothing on the disk.
Under this design a live boot mounts nothing read-write.

## 8. Order of work

1. The layout and the installer copying files, with **(A)**'s manifest check in the loader, as
   one change: executing from the disk must never exist without the check.
2. The bootloader and partition table.
3. `/etc/passwd` and `/etc/shadow` with the ring-3 `auth_server`.

Each is its own PR with its own gates and control arms. The copy on write and extents work from
[`filesystem.md`](filesystem.md) is independent of all three.

## Falsification

Each step names the gate that would go red if it were false before it is built:

- **A file not in the manifest does not run.** A gate that writes a program to `/bin` through the
  filesystem and requires the loader to refuse it; the arm skips the manifest check and must run it.
- **The disk boots on its own.** A gate that installs onto a blank disk image and boots QEMU with
  OVMF from that image alone, with no install media attached.
- **A live boot writes nothing.** A gate that hashes the whole disk image before and after a live
  boot that logs in, and requires them to be equal.
