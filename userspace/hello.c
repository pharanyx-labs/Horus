#include "syscall.h"

void _start(void) {
    sys_print("Hello from a real userspace program!\n");
    sys_print("Using sbrk for heap...\n");

    char* buf = (char*)sys_sbrk(256);
    if (buf) {
        sys_print("Allocated 256 bytes at: ");
        uint32_t addr = (uint32_t)buf;
        char hex[9];
        for (int i = 7; i >= 0; i--) {
            int d = addr & 0xF;
            hex[i] = (d < 10) ? '0'+d : 'A'+d-10;
            addr >>= 4;
        }
        hex[8] = 0;
        sys_print("0x");
        sys_print(hex);
        sys_print("\n");
    }

    sys_print("Done. Exiting.\n");
    sys_exit();
}
