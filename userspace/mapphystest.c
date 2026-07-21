#include "syscall.h"

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/*
 * MAPPHYS_SELFTEST driver. The kernel (mapphys_selftest) spawns this program with
 * a CAP_IO_DEVICE capability in slot 10 (the SYS_MAP_PHYS gate) and, just before
 * entering ring 3, seeds SENTINEL into VGA text cell CELL through its own
 * higher-half alias of 0xB8000.
 *
 * This probe proves the whole map-a-device-frame path from ring 3:
 *   1. a NON-allowlisted physical frame is refused (the allowlist, not just the
 *      capability, gates which frame may be mapped);
 *   2. the allowlisted VGA framebuffer maps successfully;
 *   3. reading CELL back through the mapping yields the kernel's SENTINEL -- so
 *      the user PTE really points at physical 0xB8000, not a fresh zero page;
 *   4. a MAGIC written through the mapping reads back -- so it is writable + user.
 * Any deviation prints a specific FAIL; success prints MAPPHYS_SELFTEST: PASS.
 */
#define VGA_PADDR   0xB8000ULL
#define VGA_VADDR   0xB8000ULL      /* identity-map the frame into the user half */
#define CELL        1000            /* a cell inside the first mapped 4 KiB frame
                                     * (offset 2000 < 4096; the 80x50 buffer spans
                                     * two frames and we map only the first here) */
#define SENTINEL    0x0741          /* 'A', attr 0x07 -- must match the kernel seed */
#define MAGIC       0x0758          /* 'X', attr 0x07 */
#define OFFLIST     0x00200000ULL   /* a frame that is NOT on the device allowlist */

void _start(void) {
    /* (1) A frame off the allowlist must be refused even though we hold the cap. */
    if (sys_map_phys(OFFLIST, OFFLIST, 4096, MAP_PHYS_WRITE) >= 0) {
        report("MAPPHYS_SELFTEST: FAIL allowlist\n"); sys_exit();
    }

    /* (2) The allowlisted VGA framebuffer maps. */
    if (sys_map_phys(VGA_PADDR, VGA_VADDR, 4096, MAP_PHYS_WRITE) != 0) {
        report("MAPPHYS_SELFTEST: FAIL map\n"); sys_exit();
    }

    volatile unsigned short *cell = (volatile unsigned short *)(unsigned long)(VGA_VADDR + CELL * 2);

    /* (3) Read the kernel's sentinel back through the mapping. */
    if (*cell != SENTINEL) { report("MAPPHYS_SELFTEST: FAIL read\n"); sys_exit(); }

    /* (4) Write + read back through the mapping. */
    *cell = MAGIC;
    if (*cell != MAGIC) { report("MAPPHYS_SELFTEST: FAIL write\n"); sys_exit(); }

    report("MAPPHYS_SELFTEST: PASS\n");
    sys_exit();
}
