# Storage drivers out of ring 0

The kernel's storage drivers (`src/kernel/sdhci.c`, `ata.c` and `ahci.c`, about 2,300 lines)
run in ring 0. Each reads card responses, capacity fields and status bits from a device that
`SECURITY.md` treats as hostile, so a bug in any of them, or a device that never answers, is a
fault in the kernel. This document is the route that takes them out, and the reason it is this
route.

## 1. The constraint that decides the route

The obvious design is a protocol by which the kernel's storage (`storage.c`) reads and writes
blocks through a ring-3 driver. **The kernel cannot do that.** It never switches tasks partway
through a system call: the cooperative switch was retired (the comment on `yield` in
`scheduler.c`), and a ring-0 loop is not preempted (`console_getc` in `terminal.c`). A kernel
path that waited for a ring-3 driver's answer would wait for a task that cannot run: a hang on one
CPU, and a CPU lost on several. Bringing back an in-kernel wait would grow the scheduler at the
core of the kernel and reopen the shared kernel stack hazard (S20) the retirement closed.

Two more facts point the same way. The volume is mounted during boot (`storage_init` in
`main.c`), before any ring-3 task exists. And swap's decision 4 (`swap.md`) puts swap I/O through
the kernel's own drivers so that bringing a page back never depends on a ring-3 server.

So the drivers cannot leave while the kernel does disk I/O. **The kernel stops doing disk I/O.**

## 2. The decision (2026-10-13)

The maintainer asked for the most secure route for a least-privilege kernel. It is this:

- **The keys stay in ring 0; the bytes move in ring 3.** The filesystem design already makes the
  kernel a sealed-block service that holds the key and nothing that knows what a file is
  ([`filesystem.md`](filesystem.md) section 4). Its seal and open calls are amended here to take
  and return **ciphertext** rather than to read and write the disk themselves (section 4). The
  kernel then never waits on a device or a driver: every call it serves is a computation on
  buffers.
- **Each driver is a ring-3 task holding one device capability**, like `nvmed` and `netd`. A
  driver serves blocks; it holds no key and sees ciphertext only. A hostile driver can refuse
  service and can return stale or forged ciphertext, which the tags in the parent pointers (and,
  for swap, the tags kept in RAM) refuse. It cannot read or forge a block.
- **No fallback.** When a driver moves to ring 3 its ring-0 copy is deleted in the same change.
  A ring-0 driver kept "in case" is the risk this route exists to remove.

## 3. The route

| Step | What lands | What it needs |
|---|---|---|
| 1 | **`sdhcid`**, the SD/eMMC driver in ring 3, proved on its own in the `SDHCID_SELFTEST` build (`make smoke-sdhcid`). Nothing else changes | Done |
| 2 | **The block-driver protocol** (section 5), served by `sdhcid` and `nvmed`: done. Then the IDE driver in ring 3, and **filesystem phase 2** with the amendment in section 4: `fs_server` moves ciphertext between the kernel's sealed-block calls and a driver | Roadmap 2.10 phase 2 |
| 3 | **Swap through a ring-3 driver** (section 6). Revises `swap.md` decision 4 | Step 2 |
| 4 | **The cutover.** No kernel path does disk I/O; `sdhci.c`, `ata.c` and `ahci.c` are deleted, each replaced by its ring-3 driver and its gates moved onto it. The installer formats through the same protocol | Steps 2 and 3, and a full install on the IdeaPad (eMMC) and an NVMe machine |

After step 4 the kernel holds no storage driver, and the NVMe disk is installable by the same path
as eMMC, with no NVMe-specific kernel code ever written.

## 4. The amendment to the sealed-block calls

[`filesystem.md`](filesystem.md) section 4.1 has the kernel write the ciphertext in **Seal** and
read it in **Open**. With the I/O in ring 3:

- **Seal** `(vol, phys, buf, kind) -> (ciphertext, nonce, tag)`. The kernel still chooses the
  nonce (section 4.2 there, unchanged: nonce uniqueness never depends on ring 3), and `phys` is
  still bound into the AAD, so a block written anywhere else does not open.
- **Open** `(vol, phys, ciphertext, nonce, tag, kind) -> plaintext`, or a failure that writes
  nothing. The caller supplies the ciphertext it read; the tag it checks against comes from the
  authenticated parent pointer, never from the driver.
- **Commit** seals the next superblock with its transaction number and the TPM anchor, and
  returns it for `fs_server` to write; **unlock** takes the superblock `fs_server` read and
  verifies it. A replayed older superblock is what S70's anchor already refuses.

Nothing about what is authenticated changes: the driver and `fs_server` were already outside the
trust the key gives, and remain so.

## 5. The block-driver protocol

Built (#563): [`include/blkproto.h`](../../include/blkproto.h) and its server half,
`userspace/blkserve.c`, linked into `sdhcid` and `nvmed` alike, so every driver holds a client to
the same rules. A driver answers on one endpoint; each request and reply is one message, and the
sectors move in a frame, never in the message.

| Request | From | Reply |
|---|---|---|
| `BIND (token, start, length, frame)` | the supervisor | done: that token now reaches that extent, through that frame |
| `INFO` | a client | its extent's length in 512-byte sectors, and the transfer limit |
| `READ (sector, count)` | a client | the sectors, into its frame |
| `WRITE (sector, count)` | a client | done, from its frame |
| `FLUSH` | a client | done once everything accepted is on stable media (an SD card's DAT0 released, an NVMe flush completed) |

- **Authority is the capability the request came through** (`SYS_IPC_INVOKER`), never the message.
  The untokened capability is the supervisor's: minting a tokened one needs it, so only the task
  that made the endpoint holds one, and it alone may bind. Every client holds a tokened, send-only
  capability, and a token nobody bound reaches nothing. The supervisor is not a client.
- **A client is given a range, not a disk.** Its sectors are relative to its extent's start, and a
  transfer must lie wholly inside the extent, so it cannot name a sector it was not given. The
  driver also bounds every transfer by the device's own extent (S64). In the installed system
  `fs_server` will hold the volume, the swap path the swap partition, and only the installer the
  whole disk.
- **One frame per client.** The supervisor grants the driver each client's frame and names it in
  that client's binding; a frame already bound is refused, so no two clients' data pass through
  the same memory. `nvmed` copies between a client's frame and its own buffer, so a controller is
  never given a client's memory.
- **The driver's own authority is the endpoint's receive right**, the frames, and its device: it
  cannot send on the endpoint or mint from it.
- **A dead or stalled driver must fail closed at the client.** A client blocks in its call, so the
  storage service that consumes this (filesystem phase 2) must bound its wait and treat no answer
  as an I/O error, with `init` restarting the driver; nothing reads a block from anywhere else.

`make smoke-blkproto` runs `blktest`, which plays the supervisor's part and then the clients',
through both drivers, and the host checks the disk afterwards. `nvmed` serves only a namespace
formatted with 512-byte blocks; a 4 KiB format is refused rather than translated.

## 6. Swap

Swap's design keeps the pager in the kernel, and that stays: the pager chooses pages, seals them
under the per-boot key and keeps every tag in RAM. Step 3 moves only the I/O. A page going out is
sealed into a frame and handed to the swap path; a page coming back blocks the faulting task
through the ordinary full-context path, as a blocking IPC does, and resumes it once the ciphertext
has arrived and opened. The driver and the swap path are added to the tasks whose pages never
leave RAM (`swap.md` decision 3), which keeps decision 4's reason: bringing a page back never
depends on a task that is itself swapped out.

## 7. Step 1, as built

`sdhcid` (`userspace/sdhcid.c`) holds **one capability**: a `CAP_IO_DEVICE` naming the SD host
controller. It holds no untyped memory, because it moves data by PIO through the controller's
buffer data port, and it enables memory decode without bus mastering, so the controller cannot
start a DMA at all. It is less authority than the ring-0 driver had, which was all of it.

The driver is a port of `sdhci.c`'s logic with its waits bounded by the clock rather than by spin
counts. Ring 3 cannot read PCI configuration space, so where the ring-0 driver reads the slot
information register for the register BAR, `sdhcid` maps each of the device's memory regions and
takes the first, in BAR order, whose registers answer as a host controller.

`make smoke-sdhcid` boots it against a 64 MiB card (CSD version 1, byte-addressed) and a 4 GiB
card (CSD version 2, block-addressed) and checks three things: the guest's verdict, the written
sectors on the image read on the host, and the decoded capacity against the image's size. Each
has a control arm (`SDHCID_ADDR_INVERTED`, `SDHCID_WRITE_WRONG_LBA`, `SDHCID_CSD_SPEC_BITS`).
`make smoke-sdhcid-emmc` runs the eMMC branch on a host shaped like the IdeaPad's; it is local
only, because CI's QEMU has no `emmc` device.

## 8. Found on the way

A device whose register BAR is smaller than a page (QEMU's SD host controller has 256 bytes) was
mapped by `SYS_MAP_PHYS` a whole page at a time while the check covered only the length asked for,
so firmware that put another device's registers in the same page would have let the driver reach
them. Closed (LIMITATIONS 1.34, #562): the page is checked whole, refused if another device
declares any part of it or if it lies in the chipset window. QEMU's firmware gives each small BAR
its own page, so `make smoke-devpage` runs the decision against a table built with the neighbours
a real machine may have.
