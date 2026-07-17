#include "syscall.h"

void _start(void) {
    sys_print("Hello from a real userspace program!\n");
    sys_print("Using sbrk for heap...\n");

    char* buf = (char*)sys_sbrk(256);
    if (buf) {
        sys_print("Allocated 256 bytes at: ");
        uintptr_t addr = (uintptr_t)buf;
        char hex[17];
        for (int i = 15; i >= 0; i--) {
            int d = addr & 0xF;
            hex[i] = (d < 10) ? '0'+d : 'A'+d-10;
            addr >>= 4;
        }
        hex[16] = 0;
        sys_print("0x");
        sys_print(hex);
        sys_print("\n");
    }

    sys_print("Done. Exiting.\n");
    sys_exit();
}
