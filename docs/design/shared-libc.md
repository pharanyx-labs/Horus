# A shared libc: who holds it, how a program binds it, and what seals it

**Design; its decisions are taken, nothing in it is built yet.** Roadmap 2.5 has had a shared
libc object since 2026-08-29 (S49, S50, S51), but only self-test builds load it and only two
test programs bind it. This document says how the shipped system uses it: how the library
reaches a task, how a program links against it by name, and how the table a program resolved is
made unwritable afterwards. The maintainer's decisions are recorded in §2, with the date each
was taken; the rest of the document is how they are built.

## 1. What exists today

| Question | Today |
|---|---|
| The library | `userspace/libc.so`: newlib, its port glue and libhorus, 36 pages (34 text, 2 data), 342 `R_X86_64_RELATIVE` relocations and nothing else. Gated by the `shared-objects` job (`tools/check_shared_object.py`) |
| Who loads it | `shlib_init` (`src/kernel/shlib.c`), called **only** from `shlibc_selftest` in a `SHLIBC_SELFTEST` build. The ship kernel never loads it |
| Where it goes | A base drawn once per boot (S51), 5 TiB plus up to 2^30 pages. Text frames are carved from `UNTYPED_KERNEL` |
| Who holds it | The two self-test tasks, endowed by the kernel from root primordials 20 (text, READ\|EXEC) and 21 (data, READ\|WRITE), at slots `LIBC_SLOT_FIRST` (40) onward |
| How a program binds it | `crt0_shared.c` calls `shlib_bind` (`userspace/shlib_start.c`): `SYS_SHLIB_INFO`, `SYS_MAP_FRAME` per page, then every libc call is a 14-byte thunk through an **index-ordered** export table (`tools/gen_libc_stubs.sh`) |
| Data symbols | `_impure_ptr` works because it is a pointer; `optarg` and `optind` cannot be shared, so a program using `getopt` fails to link |
| Private data | `shlib_instantiate_data` carves a fresh frame from `UNTYPED_KERNEL` per call, never returned |
| Fork | `clone_user_aspace` refuses any task with a frame from the untyped arena mapped (the library's frames are), so a task that has bound the library cannot fork |

## 2. The decisions

| # | Decision | Taken |
|---|---|---|
| D1 | Tasks get the library by **inheritance at spawn**. init gets the text capabilities at boot; a spawner that holds them passes them to a child **only when the child's image asks** for the shared libc. No capabilities, and the bind fails closed | 2026-09-25 |
| D2 | A **ring-3 dynamic linker in crt0**. Programs link against `libc.so` properly; crt0 applies its own `GLOB_DAT`/`JUMP_SLOT` relocations against the library's export table, refuses a library whose ABI hash differs, then seals the table read-only with a **new syscall that can only drop rights** (RELRO). No new relocation parsing in ring 0 | 2026-09-25 |
| D3 | A task that has bound the library **still cannot fork**. The refusal stays, and is recorded in `docs/LIMITATIONS.md` | 2026-09-25 |
| D4 | The shell is freestanding, so its image never asks. **init grants the shell the text capabilities** with an explicit `SYS_CAP_GRANT`, and no data page. Nothing else is granted them | 2026-09-25 |
| D5 | **Exec** into an image that asks revokes the old data capabilities and gives fresh ones from the template; exec into an image that does not ask drops them | 2026-09-25 |
| D6 | Private data pages are **per task slot**, from a kernel reserve, not charged to the spawner's untyped. This replaces the charging half of D1, for the reason in §5 | 2026-09-25 |

## 3. The library at boot

The library is a **boot module named `libc.so`**, loaded by GRUB with the others. Every boot
module is already checked against a SHA-256 pin inside the measured boot image (S92), so the
library is pinned exactly as a program in `/bin` is, with no new mechanism. The kernel calls
`shlib_init` on it once, before init is spawned, exactly as the self-test does today.

A boot with no `libc.so` module loads no library. Nothing is endowed, and every program that
asks for it fails its bind with a fixed message. That is the fail-closed direction: a missing
library stops the programs that need it, and nothing else.

## 4. Who holds the text

The text capabilities are CAP_FRAMEs carrying READ\|EXEC and never WRITE (S49), one per text
page, in slots `LIBC_SLOT_FIRST` onward. Holding them is holding the authority to **map** the
library's code. It is not authority to change it: no descendant of a capability without WRITE
can have WRITE (S27).

- **init** is endowed at boot from root primordial 20, as the self-test tasks are today.
- **The shell** receives derived copies from init by `SYS_CAP_GRANT` (D4). It holds no data page,
  so it cannot map the library writable, and it never binds the library itself.
- **A spawned child** receives derived copies of its spawner's text capabilities, in the same
  slots, **if and only if** its image asks (§6) and the spawner holds **every** text page. A
  spawner holding a partial set passes nothing: a child with half a library would fault inside
  it, at an address that explains nothing.
- **Revocation** is by lineage. Every holder's copy descends from init's, so revoking init's
  sweeps every copy in the system.

**The slot range is reserved.** `grant_child_tcb_cap` installs a spawner's `CAP_TCB` for each
child in the first free slot at or above 16, so a shell that has spawned two dozen children today
would reach slot 40. The range `LIBC_SLOT_FIRST` to `LIBC_SLOT_FIRST + SHLIB_MAX_PAGES - 1` is
therefore skipped by first-free allocation. A range that is only free by convention is a range
the next spawn silently writes into.

## 5. Private data

Every task that binds the library needs its own copy of the library's writable pages (S50).
D1 said those copies are charged to the spawner's untyped memory. **That cannot work as the
allocator stands.** An untyped region is a bump pointer that never gives a frame's bytes back
(`docs/LIMITATIONS.md` 2.5; the seL4 rule, deliberately). Every program run would permanently
spend 8 KiB of the 3.5 MiB region init and the shell share, so the shell would stop being able
to start programs after at most about 440 commands a boot, and fewer in practice.

So the data pages follow the precedent cspaces already set (D6). **Each task slot owns its libc
data frames for the life of the boot**:

- A kernel reserve of `MAX_TASKS × SHLIB_MAX_DATA_PAGES` frames, sized at compile time
  beside the cspace reserve. `SHLIB_MAX_DATA_PAGES` is 4 against libc's 2, and `shlib_init`
  refuses a library with more writable pages than that, rather than overrun the reserve.
- A slot's frames are carved the first time the slot runs a program that binds the library, and
  are reused by every later occupant of that slot. They are the same class of object every
  time, so reuse cannot confuse one type for another, which is the hazard the watermark exists
  to exclude.
- **At every spawn or exec that binds**, the frames are overwritten from the template before the
  task can run. A new occupant sees the library's initialisers, never the previous occupant's
  errno, stdio buffers or heap state.
- **The capabilities are minted READ\|WRITE, without GRANT and without EXEC.** A task cannot hand
  its data page to another task, so no second task can hold a view of the next occupant's
  state. (Whether `SYS_CAP_GRANT` enforces the GRANT right today is checked as part of this work,
  with a witness; if it does not, that is fixed first, since the property rests on it.)
- **At task teardown and at exec**, the data capabilities are revoked, so nothing names the
  frames between one occupant and the next.

The cost is fixed and visible: at two data pages and 256 task slots, 2 MiB of the pool, held
back whether or not the library is used.

## 6. How an image asks

An image asks for the shared libc with **`DT_NEEDED "libc.so"`** in its dynamic section, which
the static linker writes when a program is linked against `libc.so`. No new header field, and
nothing a program can claim without being linked that way.

- `DT_NEEDED` naming exactly `libc.so`: the image asks.
- No `DT_NEEDED`: the image is static, and loads exactly as today.
- Any other `DT_NEEDED`, or more than one: the loader **refuses** the image. There is one shared
  library, and an image asking for another is asking for something that will never be there.

## 7. What the kernel loader does with an image that asks

The loader applies relocations in safe Rust today (`rust_elf_x86_64_reloc_resolve`), and refuses
a relocation against an undefined symbol. For an image that asks, and only for one:

- `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT` and `R_X86_64_64` against an **undefined** symbol are
  skipped. Those are crt0's to resolve (§8), and the slot is left zero, so a program whose crt0
  did not run faults on a null pointer rather than calling somewhere.
- Everything else is exactly as today: `RELATIVE` is applied, a defined-symbol `GLOB_DAT` is
  resolved, `R_X86_64_COPY` and every other type are refused.

That is a narrowing of what the loader does for these images, not new parsing: the loader
already reads each entry's type and symbol, and now declines some of them.

## 8. The linker in crt0

`crt0_shared` becomes a small dynamic linker, and it runs before anything that could use libc:

1. **Map the library**, as `shlib_bind` does today: `SYS_SHLIB_INFO`, then each page with the
   rights its capability carries.
2. **Check the ABI.** The library carries a hash of its export table (every name, in order, and
   the newlib version) and the program carries the hash it was linked against. A mismatch is a
   refusal, with a fixed message: a program built against a different library would resolve
   names that mean different things.
3. **Resolve by name.** The export table becomes a sorted array of `{name, address}`. For each of
   its own `GLOB_DAT`, `JUMP_SLOT` and `R_X86_64_64` relocations against an undefined symbol,
   crt0 looks the name up and writes the address plus addend. **A name the library does not
   export is a refusal**, never a zero. Resolving by name also retires the index-ordered table,
   whose every insertion renumbered the entries after it.
4. **Seal** the program's RELRO range (§9).
5. Then `posix_init` and `main`, as today.

**Data symbols go through the GOT.** Programs are compiled with `-mno-direct-extern-access`, so a
reference to `optind` is a `GLOB_DAT` rather than a copy relocation, and the GOT entry points at
the library's own `optind` in this task's private data page. `getopt` and the program then read
and write the same variable, and `optarg`/`optind` stop blocking the eleven coreutils.

## 9. The seal: a syscall that can only drop rights

**`SYS_MEM_SEAL` (121)**, `(addr, len) -> 0`: clears WRITE on every page of the caller's own
image in the range, and marks each one sealed (a software bit in the page-table entry, bit 10).

- **It only drops.** There is no call that sets a sealed page writable again, and the
  copy-on-write break path refuses a sealed page, so a write to one is a fault the task does not
  survive, as any write to read-only memory is.
- **Own image only.** It refuses any page outside the caller's image window, and any page mapped
  through a capability (a frame's rights are its capability's, and are changed by revoking it).
- **No capability gates it**, and that is argued rather than assumed: it removes authority the
  caller already had over memory only it can reach, so there is nothing to authorise. That is the
  same reasoning under which a task may drop its own capabilities.
- **Fork** would have to keep a sealed page read-only in both tasks rather than marking it
  copy-on-write (whose first write re-grants WRITE). Sealed tasks cannot fork today (D3), so this
  is stated for when they can, and the clone refuses a sealed page until then rather than
  silently marking it copy-on-write.

## 10. What this costs, and what it does not fix

- **A task that binds the library cannot fork** (D3). None of the eleven coreutils forks; `tcc`
  does not; the shell is not a libc program.
- **The library's base is per boot, not per task** (S51, unchanged). One information leak reveals
  it for every task.
- **Up to 64 capability slots per task** for the library's pages, 36 today, of 128.
- **2 MiB of the pool** for the data reserve, held whether or not the library is used.
- **The shipping ISO carries no program that binds it** until the installed-system work ships
  the coreutils ([`installed-system.md`](installed-system.md)). Gates run it on the module builds.

## 11. Order of work

Each step is one pull request with its own gates and control arms, and each leaves the tree
working.

| Step | What | Witness, and the defect its arm puts back |
|---|---|---|
| 1 | The ship kernel loads the `libc.so` module; the per-slot data reserve; init endowed; the slot range reserved; spawn and exec inherit by `DT_NEEDED` (§4 to §6); fork still refused | A gate that spawns a module-built program asking for the library and one that does not, then checks the second holds nothing. Arms: inheritance regardless of the image; a partial set passed on; data not re-copied on reuse (the previous occupant's errno visible); GRANT-able data capability |
| 2 | `SYS_MEM_SEAL` (§9) | A probe seals a page, then tries a write and a copy-on-write break. Arms: seal that leaves WRITE; a break path that re-grants |
| 3 | The loader's narrowing (§7), and the linker in crt0 (§8) with named exports and the ABI hash | `hello_shared` rebuilt against `libc.so` and using `getopt`. Arms: ABI hash ignored; an unknown name resolved to zero; the seal skipped (the table still writable) |
| 4 | The eleven coreutils and `tcc` move onto it; `gen_libc_stubs.sh` retires | The existing coreutils gates, unchanged, on the shared build, plus the measured sizes in `docs/ROADMAP.md` |
