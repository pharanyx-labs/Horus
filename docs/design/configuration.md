# Configuration files and manual pages

**Built: the manual (#545) and the files (#546).** The maintainer asked, on the night of 2026-10-11, for
"a few .conf files in /etc so the user can finetune how horus works", with the instruction to be
careful: "ensure you don't make it too easy to make the kernel more insecure. be minimal but still
give a small bit of config across the whole system. comment each conf file thoroughly". The same
request asked for proper manual pages. The rules in §2 are the reading of that instruction this
design takes; each is open to revision, and §6 lists what is deliberately left out.

## 1. What exists

| Piece | State |
|---|---|
| `/etc` | Created by `fs_server` at boot. Holds `fs.policy` on a persistent volume (the installer writes it; design `filesystem.md` §6.2). Not a system tree: it is not rebuilt from boot modules, so what an administrator writes there persists |
| Readers | `fs_server` reads `/etc/fs.policy` from its own store. The shell reads files through its filesystem endpoint (`sh_open`, `sh_read_file`). The kernel reads no file at all |
| Manual pages | Plain text, one file per page under `userspace/man/`, each a verified boot module placed at `/usr/share/man/<name>`. `man` prefers a page on disk and falls back to the shell's built-in table. Shipped today: `hier(7)`, `tcc(1)` and the coreutils pages |
| Boot modules | `MAX_BOOT_MODULES` is 48, and an install image uses about 30 |

## 2. The rules

1. **The kernel reads no configuration.** Nothing in a file can change what the kernel authorises,
   how it measures the boot, what it encrypts or how. A setting that would need the kernel to
   change behaviour is out of scope (§6) and, if ever wanted, is a separate §4 question with its own
   syscall review.
2. **A security setting can only tighten.** Every setting that touches authority, authentication
   or exposure has a compiled default and a compiled bound, and the file can choose a value only on
   the strict side of the default. A value past the default is refused, not clamped, so a file
   cannot be mistaken for having done something it did not.
3. **Everything else is cosmetic, and bounded.** A name in the prompt, whether a message of the day is shown.
   Every value has a type, a length or range, and a character set, checked before use.
4. **A file is hostile input.** It is read by a program that trusts nothing in it: lines are
   bounded, unknown keys and malformed values are ignored with one message naming the line, and the
   program runs on its compiled defaults for anything it could not take. A missing file means
   compiled defaults, silently. A file never makes a program fail to start.
5. **Who may change it is the filesystem's business.** `/etc` is writable only through a capability
   the filesystem policy grants, which by default is the administrator's alone. A configuration
   file is not a new authority path; it is an ordinary file with an ordinary owner.
6. **Every file explains itself.** Each shipped file is fully commented: what every key does, its
   default, its range, what tightening it costs, and which manual page says more. Each has a
   section 5 manual page.
7. **Shipped defaults are seeded, never imposed.** The commented defaults arrive as one verified
   boot module (§4). `fs_server` writes a file into `/etc` only when it does not exist, so a live
   boot shows the defaults and an installed system keeps its administrator's edits across boots and
   updates.

## 3. The files

Three files, three programs, nothing in the kernel.

**When a file can be read.** On an installed system the volume is sealed from power-on until the
first login of the boot unlocks it (S74), so nothing in `/etc` can be read before that login, and
the compiled defaults apply until then. Each file is therefore read at a point where it can be, and
each manual page says plainly when a setting cannot apply. Nothing that must hold before the first
login is offered as a setting.

### `/etc/shell.conf`, read by the shell after each login

| Key | Default | Range | Kind |
|---|---|---|---|
| `hostname` | `horus` | 1 to 32 of `a-z 0-9 -`, not starting with `-` | Cosmetic: the name in the prompt (`root@horus#`) |
| `motd` | `yes` | `yes`, `no` | Cosmetic: print `/etc/motd` after a login, if it exists and is readable |

### `/etc/login.conf`, read by the shell before each login after the first

| Key | Default | Range | Kind |
|---|---|---|---|
| `failure_delay` | `0` | `0` to `30` seconds | Tighten-only: a pause after each failed login, on top of the kernel's account lockout (`rust/src/auth.rs`, proved by `the_throttle_locks_within_the_limit`), which no file can change. Before the boot's first login on an installed system the default applies |

Both files are readable by every account and secret to none. Once logins open sessions through
the filesystem policy (roadmap 2.10, step 3(b)), the default policy gains `@all /etc/shell.conf
read` and `@all /etc/login.conf read`, two read grants on two files that hold no secret, so that
the shell can read them with the login's own capability; that change is made, and stated, with
step 3(b).

### `/etc/fs.policy`, read by `fs_server`

Exists. Its rules are design `filesystem.md` §6; this design only adds its manual page
(`fs.policy(5)`) and ships a commented example beside the defaults (`/usr/share/doc/horus/fs.policy.example`)
rather than an `/etc/fs.policy`, because a policy file's absence has a meaning (the administrator
alone, decision 9) that seeding one would change.

## 4. Manual pages

The request is "proper man pages". Every shell builtin, every program in `/bin`, every
configuration file and the system itself gets a page in the format `hier(7)` already uses: NAME,
SYNOPSIS, DESCRIPTION, OPTIONS where there are any, FILES, SECURITY where the command touches
authority, EXIT STATUS, SEE ALSO.

| Section | Pages |
|---|---|
| 1 | every shell builtin (`ls`, `cd`, `cat`, `capview`, `ps`, `sudo`, `passwd`, ...) |
| 5 | `shell.conf`, `login.conf`, `fs.policy` |
| 7 | `horus` (an overview), `capabilities` (the model a user meets), `hier` (updated) |
| 8 | `useradd`, `userdel`, `rotate_keys` |

Forty or more pages cannot each be a boot module (48 in all). They ship as **one** module, a `ustar`
archive built reproducibly (sorted, zero mtimes and owners), verified by its hash like every other
module (S96), which `fs_server` unpacks into `/usr/share/man` with the system-tree rules: rebuilt
every boot, read-only to every client. The `/etc` defaults are a second archive, unpacked with
rule 7 instead. The unpacker accepts regular files only, names under its one target directory with
no `..`, no absolute path and no link, and refuses the whole archive on the first header that does
not check out.

## 5. Order

1. This design.
2. The manual-page archive and its unpacker, with the section 1, 7 and 8 pages.
3. `/etc/shell.conf` and `/etc/login.conf`: the parser, the seeding, their section 5 pages. The
   tighten-only keys carry a gate that sets a stricter value and observes it, and a control arm that
   lets a looser value through and must be refused.

## 6. Deliberately not configurable

| What | Why not |
|---|---|
| Anything the kernel does: lockout thresholds, swap, scheduling, the boot measurement, crypto parameters | Rule 1. Each would need a kernel interface that reads policy from a file, which makes the file part of the trusted computing base |
| The keyboard layout | Decoded in the kernel today, chosen at build time (`PS2_LAYOUT_DEFAULT`). A runtime choice needs a kernel interface: a §4 question, held |
| Loosening anything | Rule 2 |
| `sudo` behaviour, who is an administrator | Accounts and authority are the kernel's and the policy's, not a preference |
