/*
 * ELF-loader W^X self-test program.
 *
 * Built as a REAL multi-segment ELF (see userspace/elftest.ld) rather than an
 * objcopy-flattened blob, so the kernel's try_elf_load() path parses it and
 * applies per-segment W^X protection. Embedded into the kernel only in the
 * ELF_SELFTEST build. The kernel self-test (elf_loader_selftest() in
 * syscall.c) loads this image through the real spawn path and then inspects
 * the resulting page-table entries to prove:
 *
 *   .text   (R+X) -> page is executable (NX clear)
 *   .data   (R+W) -> page is writable and non-executable (WRITE set, NX set)
 *   .rodata (R)   -> page is read-only and non-executable (WRITE clear, NX set)
 *
 * The marker bytes below are spot-checked by the kernel after loading to
 * confirm the segment bytes were copied to the right virtual addresses. If the
 * program is ever actually run, _start prints ELF_RUN_OK as an end-to-end
 * proof, but the self-test does not depend on running it.
 *
 * elftest.ld pins the layout: .text at 0x400000, .data at 0x401000,
 * .rodata at 0x402000, each its own page-aligned PT_LOAD segment.
 */

/* -> .data segment (initialized, writable): R+W, must be mapped NX. */
volatile unsigned char elftest_data_marker = 0xD2;

/* -> .rodata segment (const): R only, must be mapped read-only + NX. */
const unsigned char elftest_rodata_marker = 0x5A;

static const char run_msg[] = "ELF_RUN_OK\n";

static inline int sys_write(int fd, const void *buf, unsigned len)
{
    int ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(11 /*SYS_WRITE*/), "b"(fd), "c"((unsigned)(unsigned long)buf), "d"(len)
                     : "memory");
    return ret;
}

void _start(void)
{
    sys_write(1, run_msg, sizeof(run_msg) - 1);
    for (;;) {
        __asm__ volatile("int $0x80" :: "a"(0 /*SYS_YIELD*/) : "memory");
    }
}
