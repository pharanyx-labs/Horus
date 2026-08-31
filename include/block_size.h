/* block_size.h — the filesystem block size, defined once for both rings.
 *
 * Included by the kernel (via src/include/kernel.h) AND by ring-3 code that
 * talks to the block syscalls. Like kernel_vma.h it must contain nothing but a
 * #define: no types, no declarations.
 *
 * WHY THIS HEADER EXISTS. Until 2026-08-31 the kernel said BLOCK_SIZE 512 in
 * kernel.h and userspace/fs_server.c said `#define BLK 512u` -- two independent
 * definitions of one number, on opposite sides of a syscall ABI. Raising the
 * kernel's to 4 KiB left the server reading whole blocks into a 512-byte buffer
 * and every filesystem gate failed with `FS_SELFTEST: FAIL read-len=-5`. The
 * server had done nothing wrong; it simply believed a constant nobody had told
 * it about.
 *
 * SYS_FBLOCK_READ hands back a whole block, so this size IS part of the ABI. A
 * caller that guesses it wrong either loses data or overruns a buffer, which
 * makes a shared definition the only honest place for it.
 */
#ifndef HORUS_BLOCK_SIZE_H
#define HORUS_BLOCK_SIZE_H

/* 4 KiB. Raised from 512 B with the on-disk format v9: at 512 the indirect
 * fan-out was BLOCK_SIZE/8 = 64 pointers, capping a file at 2.04 MiB, and every
 * per-block table (crypto metadata, bitmaps, MAC input) was eight times larger
 * than it needed to be. At 4 KiB the fan-out is 512 and the same
 * double-indirect structure reaches 1.00 GiB. */
#define HORUS_BLOCK_SIZE 4096

#endif /* HORUS_BLOCK_SIZE_H */
