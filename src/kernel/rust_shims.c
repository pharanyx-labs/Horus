#include "kernel.h"
#include <stddef.h>
#include <stdint.h>

int rust_handle_command(const uint8_t *cmd, size_t len) {
    if (!cmd || len == 0) return -1;

    char buf[128];
    size_t n = (len >= sizeof(buf)-1) ? sizeof(buf)-1 : len;
    for (size_t i = 0; i < n; i++) buf[i] = (char)cmd[i];
    buf[n] = 0;

    char *s = buf;
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;

    if (s[0] == 'h' && s[1] == 'e' && s[2] == 'l' && s[3] == 'p' && s[4] == 0) return 42;
    if (s[0] == 'v' && s[1] == 'e' && s[2] == 'r' && s[3] == 's' &&
        s[4] == 'i' && s[5] == 'o' && s[6] == 'n' && s[7] == 0) return 43;
    if (s[0] == 'e' && s[1] == 'c' && s[2] == 'h' && s[3] == 'o' && s[4] == ' ') return 44;
    if (s[0] == 'e' && s[1] == 'x' && s[2] == 'i' && s[3] == 't' && s[4] == 0) return 1;
    if (s[0] == 'u' && s[1] == 'p' && s[2] == 't' && s[3] == 'i' &&
        s[4] == 'm' && s[5] == 'e' && s[6] == 0) return 45;
    if ((s[0] == 'p' && s[1] == 's' && s[2] == 0) ||
        (s[0] == 't' && s[1] == 'a' && s[2] == 's' && s[3] == 'k' && s[4] == 's' && s[5] == 0)) return 46;
    if (s[0] == 'c' && s[1] == 'a' && s[2] == 'p' && s[3] == 's' && s[4] == 0) return 47;
    if (s[0] == 'c' && s[1] == 'l' && s[2] == 'e' && s[3] == 'a' && s[4] == 'r' && s[5] == 0) return 48;
    if (s[0] == 'k' && s[1] == 'i' && s[2] == 'l' && s[3] == 'l' && s[4] == ' ') return 49;
    if (s[0] == 'm' && s[1] == 'i' && s[2] == 'n' && s[3] == 't' && s[4] == ' ') return 50;

    return -1;
}

/* No-Rust fallback: mirror rust/src/lib.rs's region-aware check. */
bool rust_validate_page_fault(uint64_t fault_addr, uint32_t error_code,
                              uint64_t image_base, uint64_t image_end,
                              uint64_t heap_start, uint64_t heap_end) {
    (void)error_code;
    if (image_base != 0 && fault_addr >= image_base && fault_addr < image_end) return true;
    if (heap_start != 0 && fault_addr >= heap_start && fault_addr < heap_end) return true;
    if (fault_addr >= 0x7df000 && fault_addr < 0x7ff000) return true;   /* low stack */
    return false;
}

uint32_t rust_get_user_page_protection(uint32_t task_id, uint64_t vaddr) {
    (void)task_id;

    if ((vaddr >= 0x400000 && vaddr < 0x800000) ||
        (vaddr >= 0xA00000 && vaddr < 0xB00000) ||
        (vaddr >= 0x7FC000 && vaddr < 0x800000)) {
        return 0x7;
    }
    return 0;
}

__attribute__((weak))
int rust_validate_fs_operation(uint32_t task_id, uint32_t op, uint32_t rights, const uint8_t *name, size_t nlen) {
    (void)task_id; (void)op; (void)name; (void)nlen;
    return (rights != 0) ? 0 : -1;
}

__attribute__((weak))
int rust_validate_ipc(uint32_t task_id, uint32_t ep_slot, uint32_t rights) {
    (void)task_id; (void)ep_slot;
    return (rights != 0) ? 0 : -1;
}

__attribute__((weak))
bool rust_cow_copy_required(bool is_cow, bool is_write, uint16_t ref_count) {
    (void)is_cow; (void)is_write;
    return (ref_count > 1);
}

__attribute__((weak))
bool rust_should_demand_zero(uint32_t err_code) {
    return ((err_code & 1) == 0) && ((err_code & 4) != 0);
}
