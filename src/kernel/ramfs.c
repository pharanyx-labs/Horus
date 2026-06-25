#include "kernel.h"

#define MAX_FILES 8
#define MAX_FILE_SIZE 4096

typedef struct {
    char name[32];
    uint8_t data[MAX_FILE_SIZE];
    uint32_t size;
    int in_use;

    uint32_t owner_uid;
} ramfile_t;

static ramfile_t ramfs_files[MAX_FILES];

struct fs_object *fs_objects[MAX_FS_OBJECTS];

static struct fs_object fs_object_pool[MAX_FS_OBJECTS];

static void fs_object_pool_init(void) {
    for (int i = 0; i < MAX_FS_OBJECTS; i++) {
        fs_object_pool[i].gen = 0;
        fs_object_pool[i].in_use = 0;
        fs_objects[i] = NULL;
    }
}

static inline uintptr_t fs_pack_object(struct fs_object *obj) {
    if (!obj) return 0;
    int idx = (int)(obj - fs_object_pool);
    if (idx < 0 || idx >= MAX_FS_OBJECTS) return (uintptr_t)obj;
    return (uintptr_t)((uint64_t)idx | ((uint64_t)obj->gen << 32));
}

static struct fs_object *fs_resolve_cap(const struct capability *cap) {
    if (!cap) return NULL;
    uint64_t val = cap->object;
    uint32_t idx = (uint32_t)(val & 0xFFFFFFFFULL);
    uint32_t cgen = (uint32_t)(val >> 32);
    if (idx < (uint32_t)MAX_FS_OBJECTS) {
        struct fs_object *obj = &fs_object_pool[idx];
        if (obj->in_use && obj->gen == cgen) return obj;
        return NULL;
    }
    
    struct fs_object *p = (struct fs_object *)(uintptr_t)val;
    if (p && p->in_use) return p;
    return NULL;
}

static int my_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static void my_strcpy(char* dst, const char* src) {
    while ((*dst++ = *src++));
}

static size_t my_strlen(const char* s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static void my_memcpy(void* dst, const void* src, size_t n) {
    uint8_t* d = dst;
    const uint8_t* s = src;
    while (n--) *d++ = *s++;
}

static void efs_apply_keystream(struct fs_object *obj, uint8_t *data, size_t len, int for_write)
{
    if (!obj || !obj->is_encrypted || len == 0) return;

    uint8_t state[32];
    for (int i = 0; i < 32; i++) state[i] = obj->enc_file_key[i];
    for (int i = 0; i < 16; i++) state[i] ^= obj->file_key_iv[i];

    for (size_t pos = 0; pos < len; pos++) {
        
        uint32_t *w = (uint32_t *)state;
        w[0] += w[1] + (uint32_t)pos;
        w[1] = (w[1] << 5) | (w[1] >> 27);
        w[1] ^= w[0];
        uint8_t ks = (uint8_t)(w[pos & 7] >> ((pos & 3) * 8));
        data[pos] ^= ks ^ obj->file_key_iv[pos & 15];

        if ((pos & 15) == 15) {
            uint8_t t = state[0]; for (int j=0; j<31; j++) state[j] = state[j+1]; state[31] = t;
        }
    }

    (void)for_write;
    secure_zero(state, sizeof(state));
}

void ramfs_init(void) {
    fs_object_pool_init();
    storage_init();

    my_strcpy(ramfs_files[0].name, "hello.txt");
    my_strcpy((char*)ramfs_files[0].data, "Hello from Horus ramfs!\n");
    ramfs_files[0].size = my_strlen((char*)ramfs_files[0].data);
    ramfs_files[0].in_use = 1;
    ramfs_files[0].owner_uid = 0;

    my_strcpy(ramfs_files[1].name, "readme.txt");
    my_strcpy((char*)ramfs_files[1].data, "This is a simple in-memory ramfs.\nUse open/read/write syscalls.\n");
    ramfs_files[1].size = my_strlen((char*)ramfs_files[1].data);
    ramfs_files[1].in_use = 1;
    ramfs_files[1].owner_uid = 0;

    capfs_init();
}

int capfs_init(void) {
    return 0;
}

struct fs_object *capfs_alloc_object(int type, const char *name) {
    for (int i = 0; i < MAX_FS_OBJECTS; i++) {
        if (fs_objects[i] == NULL) {
            struct fs_object *obj = &fs_object_pool[i];
            obj->type = type;
            obj->size = 0;
            obj->in_use = 1;
            my_strcpy(obj->name, name ? name : "unnamed");
            obj->num_children = 0;
            obj->owner_uid = 0;
            obj->integrity_tag = 0xF5000000U + (addr_t)i;
            obj->gen = 1;

            extern tcb_t tasks[MAX_TASKS];

            if (get_current_task() >= 0 && tasks[get_current_task()].has_file_key &&
                has_encrypted_storage_cap()) {
                obj->is_encrypted = 1;
                const uint8_t *mk = tasks[get_current_task()].user_file_master_key;
                for (int k = 0; k < 32; k++) {
                    obj->enc_file_key[k] = mk[k] ^ (uint8_t)(i + k);
                }
                for (int k = 0; k < 16; k++) {
                    obj->file_key_iv[k] = mk[k % 32] ^ (uint8_t)(addr_t)obj ^ (uint8_t)k;
                }
            }

            fs_objects[i] = obj;
            return obj;
        }
    }
    return NULL;
}

int find_file(const char* name) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (ramfs_files[i].in_use && my_strcmp(ramfs_files[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

int ramfs_open(const char* path, int flags) { (void)flags;
    int idx = find_file(path);
    if (idx < 0) return -1;
    return 3 + idx;
}

int ramfs_read(int fd, void* buf, size_t len) {
    int idx = fd - 3;
    if (idx < 0 || idx >= MAX_FILES || !ramfs_files[idx].in_use) return -1;

    size_t to_read = len;
    if (to_read > ramfs_files[idx].size) to_read = ramfs_files[idx].size;

    my_memcpy(buf, ramfs_files[idx].data, to_read);

    return (int)to_read;
}

int ramfs_write(int fd, const void* buf, size_t len) {
    int idx = fd - 3;
    if (idx < 0 || idx >= MAX_FILES || !ramfs_files[idx].in_use) return -1;

    if (len > MAX_FILE_SIZE) len = MAX_FILE_SIZE;

    my_memcpy(ramfs_files[idx].data, buf, len);
    ramfs_files[idx].size = len;
    return (int)len;
}

int ramfs_create(const char* name, int mode) { (void)mode;
    if (find_file(name) >= 0) return -1;

    extern tcb_t tasks[MAX_TASKS];

    for (int i = 0; i < MAX_FILES; i++) {
        if (!ramfs_files[i].in_use) {
            my_strcpy(ramfs_files[i].name, name);
            ramfs_files[i].size = 0;
            ramfs_files[i].in_use = 1;
            ramfs_files[i].owner_uid = tasks[get_current_task()].uid;

            return 3 + i;
        }
    }
    return -1;
}

int ramfs_list(char *buf, size_t bufsize) {
    size_t pos = 0;
    for (int i = 0; i < MAX_FILES; i++) {
        if (ramfs_files[i].in_use) {
            size_t namelen = my_strlen(ramfs_files[i].name);
            if (pos + namelen + 1 >= bufsize) break;
            my_memcpy(buf + pos, ramfs_files[i].name, namelen);
            pos += namelen;
            buf[pos++] = '\n';
        }
    }
    buf[pos] = 0;
    return (int)pos;
}

int capfs_lookup(struct capability *dir_cap, const char *name, struct capability *out_cap, uint32_t desired_rights) {
    if (!dir_cap || dir_cap->type != CAP_DIR || !out_cap || !name) return -1;

    struct fs_object *dir = fs_resolve_cap(dir_cap);
    if (!dir || dir->type != FS_OBJ_DIR) return -1;

    if ((dir_cap->rights & CAP_RIGHT_FS_LOOKUP) == 0) return -2;

    if (rust_validate_fs_operation((addr_t)get_current_task(), 0, dir_cap->rights, (const uint8_t*)name, my_strlen(name)) < 0) {
        return -20;
    }

    if (name[0] == 0 || my_strlen(name) > 31 || my_strcmp(name, ".") == 0 || my_strcmp(name, "..") == 0) {
        return -7;
    }

    for (int i = 0; i < dir->num_children; i++) {
        if (my_strcmp(dir->child_names[i], name) == 0) {
            struct fs_object *child = dir->children[i];
            if (!child || !child->in_use) return -3;

            out_cap->type   = (child->type == FS_OBJ_DIR) ? CAP_DIR : CAP_FILE;
            out_cap->object = fs_pack_object(child);
            out_cap->rights = desired_rights & dir_cap->rights;
            out_cap->badge  = dir_cap->badge ? dir_cap->badge : dir_cap->object;

            return 0;
        }
    }
    return -4;
}

int capfs_create(struct capability *dir_cap, const char *name, int type, struct capability *out_cap, uint32_t desired_rights) {
    if (!dir_cap || dir_cap->type != CAP_DIR || !out_cap || !name) return -1;

    struct fs_object *dir = (struct fs_object *)dir_cap->object;
    if (!dir || dir->type != FS_OBJ_DIR) return -1;

    if ((dir_cap->rights & CAP_RIGHT_FS_CREATE) == 0) return -2;
    if (dir->num_children >= FS_MAX_CHILDREN) return -5;

    size_t nlen = my_strlen(name);
    if (nlen == 0 || nlen > 31 || my_strcmp(name, ".") == 0 || my_strcmp(name, "..") == 0) return -7;

    for (int i = 0; i < dir->num_children; i++) {
        if (my_strcmp(dir->child_names[i], name) == 0) return -8;
    }

    struct fs_object *child = capfs_alloc_object(type, name);
    if (!child) return -6;

    extern tcb_t tasks[MAX_TASKS];

    if (rust_validate_fs_operation((addr_t)get_current_task(), 1, dir_cap->rights, (const uint8_t*)name, my_strlen(name)) < 0) {
        return -20;
    }

    child->owner_uid = tasks[get_current_task()].uid;

    
    if (tasks[get_current_task()].has_file_key && has_encrypted_storage_cap()) {
        child->is_encrypted = 1;
        const uint8_t *mk = tasks[get_current_task()].user_file_master_key;
        for (int k = 0; k < 32; k++) {
            child->enc_file_key[k] = mk[k] ^ (uint8_t)(k * 0x5F);
        }
        for (int k = 0; k < 16; k++) {
            child->file_key_iv[k] = mk[(k + 3) % 32] ^ (uint8_t)(addr_t)child ^ (uint8_t)k;
        }
    }

    int slot = dir->num_children++;
    dir->children[slot] = child;
    my_strcpy(dir->child_names[slot], name);

    out_cap->type   = (type == FS_OBJ_DIR) ? CAP_DIR : CAP_FILE;
    out_cap->object = (addr_t)child;
    out_cap->rights = desired_rights & dir_cap->rights;
    out_cap->badge  = dir_cap->badge ? dir_cap->badge : (addr_t)dir;

    return 0;
}

int capfs_delete(struct capability *dir_cap, const char *name) {
    if (!dir_cap || dir_cap->type != CAP_DIR || !name) return -1;

    struct fs_object *dir = (struct fs_object *)dir_cap->object;
    if (!dir || dir->type != FS_OBJ_DIR) return -1;

    if ((dir_cap->rights & CAP_RIGHT_FS_DELETE) == 0) return -2;

    for (int i = 0; i < dir->num_children; i++) {
        if (my_strcmp(dir->child_names[i], name) == 0) {
            struct fs_object *victim = dir->children[i];
            if (victim) {
                victim->in_use = 0;
                victim->num_children = 0;
            }
            for (int j = i; j < dir->num_children - 1; j++) {
                dir->children[j] = dir->children[j+1];
                my_strcpy(dir->child_names[j], dir->child_names[j+1]);
            }
            dir->num_children--;
            return 0;
        }
    }
    return -4;
}

int capfs_readdir(struct capability *dir_cap, char *buf, size_t bufsize) {
    if (!dir_cap || dir_cap->type != CAP_DIR || !buf || bufsize < 2) return -1;
    if ((dir_cap->rights & CAP_RIGHT_FS_LOOKUP) == 0) return -2;

    struct fs_object *dir = (struct fs_object *)dir_cap->object;
    if (!dir || dir->type != FS_OBJ_DIR) return -1;

    size_t pos = 0;
    for (int i = 0; i < dir->num_children && pos + 1 < bufsize; i++) {
        size_t n = my_strlen(dir->child_names[i]);
        if (pos + n + 1 >= bufsize) break;
        my_memcpy(buf + pos, dir->child_names[i], n);
        pos += n;
        buf[pos++] = '\n';
    }
    buf[pos] = 0;
    return (int)pos;
}

int capfs_read(struct capability *file_cap, void *buf, size_t len) {
    if (!file_cap || file_cap->type != CAP_FILE) return -1;
    if ((file_cap->rights & CAP_RIGHT_FS_READ) == 0) return -2;

    if (rust_validate_fs_operation((addr_t)get_current_task(), 3, file_cap->rights, NULL, 0) < 0) return -20;

    struct fs_object *obj = (struct fs_object *)file_cap->object;
    if (!obj || obj->type != FS_OBJ_FILE) return -1;

    size_t to_read = len;
    if (to_read > obj->size) to_read = obj->size;

    my_memcpy(buf, obj->data, to_read);

    if (obj->is_encrypted) {
        
        efs_apply_keystream(obj, (uint8_t *)buf, to_read, 0);
    }

    return (int)to_read;
}

int capfs_write(struct capability *file_cap, const void *buf, size_t len) {
    if (!file_cap || file_cap->type != CAP_FILE) return -1;
    if ((file_cap->rights & CAP_RIGHT_FS_WRITE) == 0) return -2;

    if (rust_validate_fs_operation((addr_t)get_current_task(), 4, file_cap->rights, NULL, 0) < 0) return -20;

    struct fs_object *obj = (struct fs_object *)file_cap->object;
    if (!obj || obj->type != FS_OBJ_FILE) return -1;

    if (len > FS_DATA_SIZE) len = FS_DATA_SIZE;

    const uint8_t *src = (const uint8_t *)buf;

    my_memcpy(obj->data, src, len);
    obj->size = (addr_t)len;

    if (obj->is_encrypted) {
        
        efs_apply_keystream(obj, obj->data, (size_t)obj->size, 1);
    }

    return (int)len;
}
