#include "syscall.h"

static void print(const char *s) {
    sys_print(s);
}

static void println(const char *s) {
    print(s);
    print("\n");
}

#define OP_LOOKUP   1
#define OP_CREATE   2
#define OP_MKDIR    3
#define OP_DELETE   4
#define OP_READDIR  5
#define OP_READ     6
#define OP_WRITE    7
#define OP_STAT     8

struct fs_request {
    uint32_t op;
    uint32_t handle;
    char name[32];
    uint32_t type;
    uint32_t rights;
    uint32_t offset;
    uint32_t len;
    uint8_t  data[128];
};

struct fs_response {
    int32_t  rc;
    uint32_t new_handle;
    uint32_t size;
    uint8_t  data[128];
    char     listing[256];
};

typedef struct node {
    uint32_t type;
    char name[32];
    uint32_t size;
    uint8_t data[4096];
    uint32_t owner;

    struct node *children[16];
    char child_names[16][32];
    int num_children;
    int in_use;
} node_t;

static node_t pool[64];
static node_t *root_node = NULL;

static void copy(void *d, const void *s, int n) {
    uint8_t *dd = d; const uint8_t *ss = s;
    while (n--) *dd++ = *ss++;
}

static int slen(const char *s) { int l=0; while(s[l])l++; return l; }
static int scmp(const char *a, const char *b){ while(*a&&*a==*b){a++;b++;} return *a-*b; }
static void scpy(char *d, const char *s){ while((*d++=*s++)); }

static node_t *new_node(int type, const char *name) {
    for (int i=0; i<64; i++) if (!pool[i].in_use) {
        pool[i].in_use = 1;
        pool[i].type = type;
        scpy(pool[i].name, name);
        pool[i].size = 0;
        pool[i].num_children = 0;
        return &pool[i];
    }
    return 0;
}

static void build_rich_tree(void) {
    root_node = new_node(2, "/");
    root_node->owner = 0;

    node_t *home = new_node(2, "home");
    root_node->children[0] = home; scpy(root_node->child_names[0], "home"); root_node->num_children=1;

    node_t *etc = new_node(2, "etc");
    root_node->children[1] = etc; scpy(root_node->child_names[1], "etc"); root_node->num_children=2;

    node_t *usr = new_node(2, "user");
    home->children[0] = usr; scpy(home->child_names[0], "user"); home->num_children=1;

    node_t *f1 = new_node(1, "readme.txt");
    usr->children[0] = f1; scpy(usr->child_names[0], "readme.txt"); usr->num_children=1;
    const char *r = "This is the real userspace filesystem server.\nIt is feature-rich and runs entirely in userspace.\nAll metadata and data live here.\n";
    copy(f1->data, r, slen(r)); f1->size = slen(r); f1->owner = 1000;

    node_t *f2 = new_node(1, "hostname");
    etc->children[0] = f2; scpy(etc->child_names[0], "hostname"); etc->num_children=1;
    copy(f2->data, "horus-fs-server\n", 16); f2->size=16;

    node_t *f3 = new_node(1, "motd");
    root_node->children[2] = f3; scpy(root_node->child_names[2], "motd"); root_node->num_children=3;
    const char *m = "Horus 0.4 - Capability Microkernel\nUserspace FS Server is ACTIVE and serving requests.\n";
    copy(f3->data, m, slen(m)); f3->size = slen(m);
}

static node_t *find_child(node_t *dir, const char *name) {
    if (!dir || dir->type != 2) return 0;
    for (int i=0; i<dir->num_children; i++) {
        if (scmp(dir->child_names[i], name)==0) return dir->children[i];
    }
    return 0;
}

int main(void) {
    println("[fs_server] Starting feature-rich userspace filesystem server...");

    build_rich_tree();
    println("[fs_server] Rich tree ready: /, /home/user, /etc, motd, readme.txt, hostname");

    println("[fs_server] Rich demo filesystem initialized.");

    if (sys_register_fs_server(4) == 0) {
        println("[fs_server] Registered as system FS server (listening on endpoint 4)");
    } else {
        println("[fs_server] Warning: could not register (no CAP_USER?)");
    }

    println("[fs_server] Entering IPC server loop. Clients can connect via sys_connect_fs_server()");

    struct fs_request req;
    struct fs_response rep;

    for (;;) {
        int r = sys_ipc_recv(4, (char*)&req, sizeof(req));
        if (r < 0) continue;

        rep.rc = 0;
        rep.new_handle = 0;
        rep.size = 0;
        rep.listing[0] = 0;

        node_t *target = (node_t*)(uintptr_t)req.handle;

        switch (req.op) {
        case OP_LOOKUP: {
            node_t *n = find_child(root_node, req.name);
            if (n) {
                rep.new_handle = (uint32_t)(uintptr_t)n;
                rep.rc = 0;
            } else {
                rep.rc = -4;
            }
            break;
        }
        case OP_READDIR: {
            char *p = rep.listing;
            node_t *dir = target ? target : root_node;
            if (dir && dir->type == 2) {
                for (int i=0; i<dir->num_children && (p-rep.listing)<240; i++) {
                    int l = slen(dir->child_names[i]);
                    copy(p, dir->child_names[i], l);
                    p += l; *p++ = '\n';
                }
            }
            *p = 0;
            rep.rc = 0;
            break;
        }
        case OP_READ: {
            if (target && target->type == 1) {
                int nbytes = (req.len > target->size) ? (int)target->size : (int)req.len;
                if (nbytes > 128) nbytes = 128;
                copy(rep.data, target->data, nbytes);
                rep.size = nbytes;
                rep.rc = nbytes;
            } else {
                rep.rc = -1;
            }
            break;
        }
        case OP_CREATE:
        case OP_MKDIR: {
            node_t *parent = target ? target : root_node;
            if (parent && parent->type == 2 && parent->num_children < 16) {
                node_t *n = new_node(req.type, req.name);
                if (n) {
                    parent->children[parent->num_children] = n;
                    scpy(parent->child_names[parent->num_children], req.name);
                    parent->num_children++;
                    rep.new_handle = (uint32_t)(uintptr_t)n;
                    rep.rc = 0;
                } else {
                    rep.rc = -5;
                }
            } else {
                rep.rc = -6;
            }
            break;
        }
        case OP_WRITE: {
            if (target && target->type == 1) {
                int w = req.len > 128 ? 128 : req.len;
                if (req.offset + w > 4096) w = 4096 - req.offset;
                if (w > 0) {
                    copy(target->data + req.offset, req.data, w);
                    if (req.offset + (uint32_t)w > target->size) target->size = req.offset + (uint32_t)w;
                }
                rep.rc = w;
            } else {
                rep.rc = -1;
            }
            break;
        }
        case OP_STAT: {
            if (target) {
                rep.size = target->size;
                rep.rc = 0;
            } else {
                rep.rc = -1;
            }
            break;
        }
        default:
            rep.rc = -100;
            break;
        }

        sys_ipc_reply(4, (const char*)&rep, sizeof(rep));
    }
}
