# Encrypted swap

**Decided; step 1 of §5 built (#510).** The maintainer asked on 2026-10-08 for the swap limitation to be sorted
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
Every walker that reads non-present PTEs has to know it. The list is part of the implementation PR
and the main review burden:

- the fault path (bring the page back);
- `fork` (bring the parent's swapped pages back before sharing them copy-on-write, so a slot never
  has two owners);
- unmapping, task teardown and region release (free the slot);
- `SYS_MEM_SEAL`, the user-copy paths and the Rust validators (treat a swapped page as present for
  their checks, by bringing it back first).

### 3.4 Choosing a page

When an allocation would find the pool below a low-water mark, a clock hand walks the user page
tables, giving each eligible page one pass with its accessed bit cleared before taking it. A page
is eligible only under §2.3, and only if its task is not running on another CPU at that moment, so
the unmap needs no shootdown: the switch to that task already flushes. A page whose seal or write
fails stays where it is.

### 3.5 I/O and the fault path

Disk I/O cannot sit under `page_lock`. A page going out is sealed into a kernel bounce page under
the lock, its PTE becomes a swapped PTE marked in transit, and the lock is dropped for the write.
Its frame is freed only once the write has completed; a fault on it meanwhile waits. A page coming
back is read and opened with the lock dropped, then installed after re-checking that the PTE still
names that slot. One thread per address space keeps the re-check simple.

### 3.6 Failures

| Event | Result |
|---|---|
| The partition is full | Eviction finds no slot; the allocation fails as it does today |
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
  both refusals. Step 2 adds the end-to-end form: a program that writes a marker across more
  memory than the pool holds and reads it all back, with swap traffic in the kernel's count.
- **Swap is never used on a live boot.** `smoke-live-locked` already hashes the whole disk before
  and after a live boot; it gains a low-memory run so the pager is under pressure when it does.
- **Only eligible pages leave RAM.** A self-test build checks every page the clock takes against
  §2.3 and halts on one that is not.

## 5. Order of work

1. **The sealed slot store**: finding the partition, the key, the slot table, sealing and opening a
   page, with a boot self-test and the arms above. No page ever leaves a task yet. Done (#510).
2. **Eviction and fault-in**: the swapped PTE, the walker audit, the clock, the I/O with the lock
   dropped, and the memory-pressure gate.
3. **A no-swap request for secrets**, asked first as a §4 question.

Each is its own pull request with its own gates.
