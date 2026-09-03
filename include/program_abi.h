/* program_abi.h -- the Horus `.bin` program-image container, defined ONCE.
 *
 * SECURITY.md S80: the container the BUILD writes and the KERNEL reads has one
 * definition, and every reader derives its offsets from it.
 *
 * THE FORMAT. A `.bin` is this 44-byte header followed immediately by `size`
 * bytes of payload (a raw binary or an ELF, which try_elf_load then recognises):
 *
 *     offset 0   uint32_t magic    'HORU', little-endian -- 0x55524F48
 *     offset 4   uint32_t entry    entry offset within the payload, 0 = "ask the ELF"
 *     offset 8   uint32_t size     payload length in bytes
 *     offset 12  char     name[32] NUL-padded image name
 *     offset 44  payload
 *
 * WHY THIS FILE EXISTS.
 *
 * Until 2026-09-03 this format was written down FOUR times and no two copies
 * were connected:
 *
 *   - `struct program_header` in src/include/kernel.h: an ELF program header
 *     (type/offset/vaddr/paddr/filesz/memsz/flags/align) with four Horus fields
 *     appended -- 104 bytes, `magic` at offset 96. Nothing read the eight ELF
 *     fields and the `program_header_t` typedef had no uses at all.
 *   - `struct program_header` in include/syscall.h: the staging header alone,
 *     44 bytes. Same name as the above, different layout, no compiler seeing
 *     both. That divergence is docs/LIMITATIONS.md 2.18 and it broke
 *     SYS_RECEIVE_PROGRAM in two independent places.
 *   - A private copy inside tools/mkheadered.c -- the tool that writes every
 *     `.bin` in the tree, and therefore the only one of the four that actually
 *     DEFINED the format.
 *   - And the readers used neither: arm_named_binary() and arm_image_from_user()
 *     in src/kernel/loader.c assembled `magic` from bytes 0..3, `entry` from
 *     4..7, `size` from 8..11 and `name` from 12, with the literal 44 for the
 *     payload offset and 0x55524F48 spelled out at each site.
 *
 * So the two declarations that shared a name were the two nothing used, and the
 * three copies that mattered -- writer, and two hand-rolled parsers -- agreed
 * only because somebody kept them in step by hand. That is include/block_size.h's
 * lesson one subsystem over: 512 was not a constant but an assumption repeated in
 * six places. It is also why S71's repair was a FILE rather than a patch, and this
 * is the same repair applied to the same shape.
 *
 * THE NAME IS `horus_image_header`, NOT `program_header`. Sharing a name was half
 * of how the divergence survived: both sides compiled, both were self-consistent,
 * and nothing but a running probe could tell them apart. A rename makes any caller
 * still reaching for an old declaration fail to BUILD rather than fail to AGREE.
 *
 * THE EIGHT ELF FIELDS ARE DELIBERATELY NOT CARRIED OVER. Exporting a field means
 * promising to keep it, and nothing ever read them -- the same judgement
 * audit_abi.h made about `kind`, `uid`, `arg0`, `arg1` and `path`. An image's ELF
 * program headers are parsed out of the payload by the ELF loader, which is where
 * that information belongs and already lives.
 *
 * THIS HEADER IS DELIBERATELY FREESTANDING: <stdint.h> and nothing else, no
 * kernel types, no libc. tools/mkheadered.c is a HOST program built with the host
 * compiler and it includes this file, so the writer and the readers are the same
 * declaration rather than three that happen to agree. A dependency on kernel.h
 * here would force the tool back to a private copy and reopen the whole finding.
 *
 * Falsified by IMAGE_HDR_WRITER_SKEW=1, which makes mkheadered emit a one-sided
 * layout change -- exactly what the four-copy arrangement could not catch -- and
 * requires the kernel's parse to reject it. tools/check_image_abi.py is the
 * ratchet that refuses a second declaration of this format anywhere in the tree.
 */
#ifndef HORUS_PROGRAM_ABI_H
#define HORUS_PROGRAM_ABI_H

#include <stdint.h>

/* 'H' 'O' 'R' 'U' little-endian. Spelled once; readers compare against this. */
#define HORUS_IMAGE_MAGIC 0x55524F48u

/* The longest name a `.bin` can carry, NUL included. */
#define HORUS_IMAGE_NAME_MAX 32

struct horus_image_header {
    uint32_t magic;                        /* HORUS_IMAGE_MAGIC */
    uint32_t entry;                        /* entry offset in the payload, 0 = ELF decides */
    uint32_t size;                         /* payload bytes following this header */
    char     name[HORUS_IMAGE_NAME_MAX];   /* NUL-padded */
};

/* The payload begins immediately after the header. Derived, never written out as
 * a literal: `44` appeared in two parsers and one writer, and a constant that is
 * spelled rather than computed is the thing this file exists to remove. */
#define HORUS_IMAGE_HDR_BYTES ((uint32_t)sizeof(struct horus_image_header))

/* The layout IS the ABI, so it is asserted rather than assumed. These fire in
 * every translation unit that includes this header -- kernel and host tool alike
 * -- which is what makes "one definition" a property of the build rather than a
 * claim in a comment. A field inserted, reordered or retyped fails the build at
 * the point of the change instead of silently shifting a boot module's name. */
_Static_assert(sizeof(struct horus_image_header) == 44, "horus_image_header is 44 bytes");
_Static_assert(__builtin_offsetof(struct horus_image_header, magic) == 0,  "image hdr .magic at 0");
_Static_assert(__builtin_offsetof(struct horus_image_header, entry) == 4,  "image hdr .entry at 4");
_Static_assert(__builtin_offsetof(struct horus_image_header, size)  == 8,  "image hdr .size at 8");
_Static_assert(__builtin_offsetof(struct horus_image_header, name)  == 12, "image hdr .name at 12");
_Static_assert(HORUS_IMAGE_NAME_MAX == 32, "image hdr name field is 32 bytes");

#endif /* HORUS_PROGRAM_ABI_H */
