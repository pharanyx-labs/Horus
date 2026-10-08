# Encrypted swap

**Decided; steps 1 and 2 of §5 built (#510, #512).** The maintainer asked on 2026-10-08 for the swap limitation to be sorted
out now, and for the swap partition to be properly encrypted. The four decisions below were taken
the same day, each as recommended. The memory ceiling went first (#508), so swap starts from a
pool that already holds all of the RAM below 4 GiB.

## 1. What exists

| Piece | State |
|---|---|
| The partition | The installer lays one out on a bootable disk, between the EFI system partition and the volume, sized by the operator, with its own type GUID (`rust/src/gpt.rs`). Opened at unlock as the sealed slot store (`src/kernel/swap.c`, S118); nothing is evicted into it yet |
| Finding it | The kernel parses a GPT in Rust and mounts a volume only from a table that verifies (S114); the swap partition is found by the same parse |
| Cryptography | `rust_aead_seal` and `rust_aead_open` (ChaCha20 with HMAC-SHA256, encrypt-then-MAC) and the kernel CSPRNG |
| Running out of memory | A hard failure: an allocation that finds the pool empty fails (`docs/LIMITATIONS.md` section 4) |
| The fault path | `handle_demand_page_fault` runs under `page_lock`, a spinlock taken with interrupts off |
| Disk I/O | Synchronous, through the IDE and SD/eMMC drivers, each under its own lock (`ata_lock`, `sdhci_lock`) |

## 2. The decisions (2026-10-08)

1. **The memory ceiling first, then swap.** Done: #508.
2. **A per-boot key, every page authenticated, tags kept in RAM.** A 256-bit key is drawn from the
   CSPRNG when swap is enabled. It lives only in kernel memory, is never written anywhere, and is
   never itself swappable, so power-off destroys it and the partition becomes noise. Each page is
   sealed with the kernel's AEAD under a fresh nonce. The nonce, the tag and the map of which slot
   holds what are kept in RAM, never on the partition, which therefore carries no plaintext at
   all, not even a header. A page modified on the disk, an older copy of a page written back, or a
   read that fails kills the task that owns the page, with a logged reason. The task is never
   handed bytes other than the ones it gave up.
3. **Only a task's private pages.** Never kernel memory, page tables, shared or copy-on-write-shared
   frames, frames lent through a frame capability, device frames, or any page of `init`,
   `fs_server` and `console_server`. A request by which a task marks pages that hold secrets as
   never to be swapped is a later, separate change: a new syscall operation is a §4 question of its
   own.
4. **The pager is in the kernel and minimal.** Page tables and the fault path are kernel state
   already. Swap I/O goes through the kernel's own block drivers, not `fs_server`, so bringing a
   page back never depends on a ring-3 server that might itself be swapped.

## 3. The design

### 3.1 When swap is on

Only on an installed boot, after the volume has been unlocked, and only on the disk that volume
came from. A live boot opens no disk (S110), so it never swaps; neither does an install boot, which
is about to rewrite the disk. If the GPT names no swap partition, or the partition is smaller than
one page, swap stays off and the boot says so.

### 3.2 A slot

The partition is an array of 4 KiB slots. For each slot the kernel keeps, in RAM:

- a 64-bit **generation**, raised on every write to the slot;
- the 32-byte **tag** of the page last sealed into it;
- whether it is in use.

A page is sealed with a nonce made of the slot index and the generation, and the slot index and
generation are also authenticated data. So a block copied from another slot fails, and so does an
older copy of the same slot: both carry the wrong generation for the tag held in RAM. The table
costs about 40 bytes a slot, 10 MiB for a 1 GiB partition, taken from the pool when swap is
enabled and sized to the partition.

### 3.3 A swapped-out page

A PTE that is not present, with a software bit (`PAGE_SWAPPED`, bit 11) set and the slot index in
the address bits. The MMU never reads a non-present PTE, so the encoding is the kernel's alone.
Every walker that reads non-present PTEs knows it (`src/kernel/paging.c`):

- the fault path brings the page back, before the copy-on-write branch, whose flags it may carry;
- `fork` shares the slot rather than reading the page back: both entries name it, its count goes
  up, both lose `PAGE_WRITE` for `PAGE_COW` as a present page would, and each gets its own frame
  when it next touches the page. This was chosen over the read-back first planned, because fork
  holds `page_lock` and the read is disk I/O. It is not exercised by a gate yet: a fork is refused
  for a task holding sealed pages, which every shared-libc program in `/bin` does;
- task teardown, and mapping over a swapped entry, free the slot;
- the user-copy path and `SYS_MEM_SEAL` bring a swapped page back first (a swapped PTE is memory
  the task already has, unlike the absent page the copy path refuses); a protection change applies
  to the swapped PTE's flags; the frame, device and private-copy map paths treat a swapped entry
  as occupied.

### 3.4 Choosing a page

When a fault finds fewer than `SWAP_LOW_WATER` frames free, the faulting task gives up to
`SWAP_EVICT_BATCH` of **its own** idle pages before it takes another. A clock hand walks its user
page tables from where it last stopped, giving each eligible page one pass with its accessed bit
cleared before taking it.

**Its own, not any task's.** The plan was any task not running on another CPU, but checking that
and changing the PTE cannot be made atomic against the scheduler starting the task elsewhere, which
would leave a stale translation to a freed frame on that CPU. A shootdown would close it, and the
fault path cannot wait for one with interrupts off. The current task's pages have no such window:
this CPU runs it, and any CPU that starts running it reloads CR3 first, the argument
`clone_user_aspace` already makes. Taking an idle task's pages is the next step, with a shootdown.

A page is eligible under §2.3 and, measured the hard way, **only where the fault path approves a
fault** (the image, the heap, the low stack, per `rust_validate_page_fault`): the first version
also took the shared libc's per-task data, and the task died for touching its own memory. A page
whose write fails stays where it is.

### 3.5 I/O and the fault path

Disk I/O never sits under `page_lock`. A page going out is chosen under the lock, written from its
own frame with the lock dropped (the task is in the kernel, so nothing writes the frame meanwhile),
and only then, under the lock again and only if the PTE is unchanged, does the PTE become a swapped
PTE and the frame go back to the pool. A page coming back is read and opened into a fresh frame
with the lock dropped, then installed after re-checking that the PTE still names that slot.
`swap_lock` nests inside `page_lock` (teardown frees slots under it) and never the other way.

### 3.6 Failures

| Event | Result |
|---|---|
| The partition is full | Eviction finds no slot; the allocation fails as it does today, and the fault path now says so in the log (`fault: task killed, the pager could not resolve an approved fault`) |
| A write fails | The page stays in RAM; the slot is not marked used |
| A read fails, or the tag does not match | The owning task is killed with `swap: page failed authentication` or `swap: page could not be read`; the slot is freed |
| A task exits | Its slots are freed; nothing is written |

## 4. Properties and witnesses

- **Nothing on the swap partition is plaintext, and a page read back is the page written, or it
  is refused (S118).** Built for the store as `make smoke-swap-store`: on an installed disk's own
  boot the login turns swap on, a self-test seals 32 marked pages and reads them back, and a
  block changed on the disk and an older copy of a slot written back must both be refused; the
  host then scans the partition in the disk image for the marker and must find none. Arms:
  sealing off (the host finds the marker) and the tag check removed (the changed block is taken).
  A replay needs no arm of its own: the generation is in the nonce, but what refuses an older
  copy is the tag held in RAM, the same check the tag arm removes, and the self-test requires
  both refusals.
- **A page that went to swap comes back exactly as it was (S119).** Built as `make smoke-swap`: on
  the installed disk's boot with the pool capped at 64 MiB, `swaphog` writes 48 MiB, more than the
  pool holds, and reads every byte back; the kernel must report pages out, and the host must find
  none of `swaphog`'s marker on the partition. Arm: a page taken for swap is written as zeros,
  which `swaphog` catches at its first page.
- **Swap is never used on a live boot.** `smoke-live-locked` already hashes the whole disk before
  and after a live boot; it gains a low-memory run so the pager is under pressure when it does.
- **Only eligible pages leave RAM.** Held by `swap_evictable` and the fault-path region check
  (§3.4); a self-test that checks every page the clock takes is not built yet.

## 5. Order of work

1. **The sealed slot store**: finding the partition, the key, the slot table, sealing and opening a
   page, with a boot self-test and the arms above. No page ever leaves a task yet. Done (#510).
2. **Eviction and fault-in**: the swapped PTE, the walker audit, the clock, the I/O with the lock
   dropped, and the memory-pressure gate. Done (#512), taking the faulting task's own pages.
2a. **Taking an idle task's pages**, with a TLB shootdown, so a large idle task gives memory back
   to a small busy one.
3. **A no-swap request for secrets**, asked first as a §4 question.

Each is its own pull request with its own gates.
