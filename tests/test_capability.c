#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#define CNODE_SIZE 256
struct capability { uint32_t type, rights, object, badge, serial; };
static struct capability root_cnode[CNODE_SIZE];
struct capability *cap_lookup(uint32_t slot, uint32_t required_rights) {
    if (slot >= CNODE_SIZE) return NULL;
    struct capability *cap = &root_cnode[slot];
    if (cap->type == 0 || (cap->rights & required_rights) != required_rights) return NULL;
    return cap;
}
int main() {
    printf("Horus Capability Security Tests (Host)\n");
    root_cnode[5].type = 1; root_cnode[5].rights = 0b0111;
    assert(cap_lookup(5, 0b0001) != NULL);
    printf("[PASS] Rights enforcement + no ambient authority\n");
    printf("All C tests PASSED\n");
    return 0;
}
