/*
 * ELF-loader W^X + ASLR/relocation self-test program.
 *
 * Built as a real static-PIE (ET_DYN) multi-segment ELF (see userspace/elftest.ld)
 * so the kernel's try_elf_load() parses it, loads it at a RANDOMIZED base, applies
 * R_386_RELATIVE relocations, and enforces per-segment W^X. Embedded into the
 * kernel only in the ELF_SELFTEST build. The kernel self-test
 * (elf_loader_selftest() in syscall.c) loads this image through the real spawn
 * path and inspects the resulting page-table entries + memory to prove:
 *
 *   .text   (R+X) -> executable (NX clear)
 *   .rodata (R)   -> read-only + non-executable (WRITE clear, NX set)
 *   .data   (R+W) -> writable + non-executable (WRITE set, NX set)
 *   selfptr       -> relocated to base + &marker (proves R_386_RELATIVE applied)
 *
 * The markers live in dedicated sections that the linker script pins to the
 * start of each segment, so the kernel finds them at base + segment vaddr
 * regardless of the randomized load base.
 */

/* First byte of the .rodata segment: R only, must map read-only + NX. */
__attribute__((used, section(".rodata.marker")))
const unsigned char elftest_rodata_marker = 0x5A;

/* First word of the .data segment: a pointer to the rodata marker. In a PIE
 * this is an absolute address, so the linker emits an R_386_RELATIVE relocation
 * and the kernel loader must fix it up to (base + &elftest_rodata_marker). */
__attribute__((used, section(".data.selfptr")))
const unsigned char *const elftest_selfptr = &elftest_rodata_marker;

/* Immediately after selfptr in .data: a plain writable marker byte. */
__attribute__((used, section(".data.marker")))
volatile unsigned char elftest_data_marker = 0xD2;

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
