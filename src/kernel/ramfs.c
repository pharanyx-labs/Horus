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

/* ------------------------------------------------------------------------- *
 * Encryption at rest for is_encrypted files.
 *
 * Files are sealed with the kernel's ChaCha20 + HMAC-SHA256 Encrypt-then-MAC
 * AEAD (rust/src/aead.rs) — the same authenticated construction used by the
 * block-storage layer, and validated against its RFC known-answer vectors.
 * This replaces a previous in-kernel homebrew XOR keystream that had no
 * integrity protection and reused its keystream across rewrites.
 *
 * Per encrypted object we keep two independent HKDF-SHA256 subkeys
 * (confidentiality + integrity) derived from the owning task's file master
 * key, a nonce redrawn from the CSPRNG on every write (so (key,nonce) never
 * repeats), and the authentication tag over the whole ciphertext.
 * ------------------------------------------------------------------------- */

/* Whole-object decrypt scratch: the AEAD tag covers the entire ciphertext, so
 * even a partial read must open the full object before returning a prefix.
 * Guarded by storage_lock along with the rest of the FS (single-core kernel). */
static uint8_t efs_scratch[FS_DATA_SIZE];

/* Additional authenticated data binding a ciphertext to its object identity
 * (stable for the object's lifetime). Stops a valid (nonce,tag,ciphertext)
 * triple from being replayed against a different object. */
static void efs_aad(const struct fs_object *obj, uint8_t out[4]) {
    out[0] = (uint8_t)(obj->integrity_tag);
    out[1] = (uint8_t)(obj->integrity_tag >> 8);
    out[2] = (uint8_t)(obj->integrity_tag >> 16);
    out[3] = (uint8_t)(obj->integrity_tag >> 24);
}

/* Derive the per-file AEAD subkeys from the task's 32-byte file master key via
 * HKDF-SHA256 (fresh random salt -> independent keys per file) into the
 * concatenation enc_key(32) || mac_key(32). Fails closed: if HKDF cannot
 * produce key material the object is left unencrypted rather than sealed under
 * a zero key. */
static void efs_derive_file_keys(struct fs_object *obj, const uint8_t *master_key) {
    static const char info[] = "horus/efs/file-key/v1";
    uint8_t salt[16];
    uint8_t okm[64];
    rust_rng_fill(salt, sizeof(salt));
    if (rust_hkdf_sha256(master_key, 32, salt, sizeof(salt),
                         (const uint8_t *)info, sizeof(info) - 1,
                         okm, sizeof(okm)) != 0) {
        obj->is_encrypted = 0;
        secure_zero(okm, sizeof(okm));
        secure_zero(salt, sizeof(salt));
        return;
    }
    my_memcpy(obj->enc_key, okm, 32);
    my_memcpy(obj->mac_key, okm + 32, 32);
    secure_zero(okm, sizeof(okm));
    secure_zero(salt, sizeof(salt));
}

/* Seal obj->data[0..size] in place with a fresh nonce; stores nonce and tag. */
static void efs_seal(struct fs_object *obj) {
    if (!obj->is_encrypted || !obj->data) return;
    uint8_t aad[4];
    efs_aad(obj, aad);
    rust_rng_fill(obj->file_nonce, sizeof(obj->file_nonce));
    rust_aead_seal(obj->enc_key, obj->mac_key, obj->file_nonce,
                   aad, sizeof(aad),
                   (uint8_t *)obj->data, (size_t)obj->size, obj->file_tag);
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
                efs_derive_file_keys(obj, tasks[get_current_task()].user_file_master_key);
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

    /* Encryption keys (if any) were already derived by capfs_alloc_object from
     * the owning task's file master key — no per-file key setup here. */

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

    if (obj->is_encrypted) {
        size_t clen = (size_t)obj->size;
        if (clen > FS_DATA_SIZE || !obj->data) return -1;

        uint8_t aad[4];
        efs_aad(obj, aad);

        /* The AEAD tag covers the whole ciphertext, so decrypt-and-verify the
         * entire object into scratch, then hand back only the requested prefix.
         * On authentication failure nothing is copied to the caller. */
        my_memcpy(efs_scratch, obj->data, clen);
        if (rust_aead_open(obj->enc_key, obj->mac_key, obj->file_nonce,
                           aad, sizeof(aad), efs_scratch, clen, obj->file_tag) != 0) {
            secure_zero(efs_scratch, clen);
            return -21;   /* AEAD authentication failed: tampered or wrong key */
        }
        my_memcpy(buf, efs_scratch, to_read);
        secure_zero(efs_scratch, clen);
    } else if (obj->data) {
        my_memcpy(buf, obj->data, to_read);
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
    if (!obj->data) return -1;

    my_memcpy(obj->data, buf, len);
    obj->size = (addr_t)len;

    /* Seal in place: obj->data now holds ciphertext, authenticated by file_tag
     * under a freshly drawn nonce. */
    if (obj->is_encrypted) {
        efs_seal(obj);
    }

    return (int)len;
}
