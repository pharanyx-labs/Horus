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

/* A small in-memory file store (the "ramfs") that predates the encrypted
 * fs_server. It survives only to back the sealed user-account database
 * (kusers.c stores "passwd" through ramfs_open/read/write) and a couple of
 * demo files. The former capability filesystem ("capfs": fs_objects[],
 * capfs_lookup/create/delete/readdir/read/write and its at-rest AEAD) was a
 * separate, parallel filesystem reachable via syscalls 38-45; it has been
 * removed in favour of the single encrypted fs_server, and those syscalls now
 * fail closed. */
void ramfs_init(void) {
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
