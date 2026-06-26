#ifndef KERNEL_H
#define KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>


typedef uint64_t addr_t;
typedef uint64_t paddr_t;
typedef uint64_t vaddr_t;


#define BLOCK_SIZE              512
#define BLOCKS_PER_DISK         1024
#define PAGE_SIZE               4096
#define USER_PHYS_BASE          0x01000000
#define USER_PHYS_PAGES         16384
#define CNODE_SIZE              256
#define MAX_TASKS               64
#define MAX_CAPS_PER_TASK       128
#define KERNEL_RESERVED_CAPS    4
#define MAX_REV_SETS            8

/* Number of lineage slots. Mirrors LINEAGE_SLOTS in rust/src/capability.rs,
 * which is the authoritative table; keep these two in sync. */
#define MAX_LINEAGES            4096
#define USER_VIRT_BASE          0x0000000000400000ULL
#define USER_MAX_VADDR          0x0000000000800000ULL
#define USER_AREA_BASE          0x400000ULL
#define KERNEL_TSS_STACK        0xFFFF8000FFFFF000ULL
#define USER_ASPACE_PREMAP_PAGES 32
#define KERNEL_STACK_SIZE 8192
#define MAX_USERS               32
#define USER_HEAP_BASE              0x0000000001000000ULL
#define USER_MEM_MAX_COPY           (64*1024)
#define ASLR_HIGH_STACK_BASE        0x00007ff000000000ULL
#define USER_HIGH_STACK_WINDOW      (16*1024*1024ULL)
#define ASLR_MAX_LOAD_RANDOM_PAGES  16
#define ASLR_MAX_STACK_RANDOM_PAGES 4
#define ASLR_MAX_HEAP_GAP_PAGES     8
#define DEMO_TASK_STACK_TOP         0x00007fffe0000000ULL
#define AUDIT_LOG_SIZE          256
#define PASS_SALT_LEN           16
#define PASS_HASH_LEN           32
#define MAX_FS_OBJECTS          64
#define INODES_PER_BLOCK        (BLOCK_SIZE / 128)
uint32_t rust_get_user_page_protection(uint32_t t,uint32_t v);
int rust_validate_fs_operation(uint32_t task_id, uint32_t op, uint32_t rights, const uint8_t *name, size_t nlen);
#define MAX_ENDPOINTS 64
#define IPC_MSG_MAX   256

struct endpoint {
    int      has_message;     
    int      msg_len;
    int      sender_task;     
    int      last_sender;     
    uint8_t  msg[IPC_MSG_MAX];
};
extern struct endpoint endpoints[MAX_ENDPOINTS];
struct task_info { uint32_t id; uint32_t state; char name[32]; uint32_t caps_in_use; uint32_t uid; uint32_t gid; int in_kernel; uint64_t tsc_base; int blocked_on_notif; int blocked_on; uint64_t heap_start; uint32_t eip; uint32_t esp; uint64_t heap_used; uint32_t cr3; };
struct dir_entry { char name[32]; uint32_t ino; uint32_t type; uint32_t name_len; uint32_t inode; };
typedef struct platform_info {
    int family, model, stepping;
    int has_long_mode;
    char vendor[13];
    int has_smap;
    int has_smep;
    int has_aesni;
    int has_tsc;
    int has_sse;
    int has_sse2;
    int has_sse4_2;
    int has_rdrand;
    int has_invariant_tsc;
    int num_logical_cpus;
    int num_physical_cpus;
    uint64_t total_memory_bytes;
} platform_info_t;
extern platform_info_t platform;
#define MAX_CPUS 4
void users_init(void);


#define SYS_YIELD           0
#define SYS_PRINT           1
#define SYS_EXIT            2
#define SYS_GET_LINE        3
#define SYS_SBRK            10
#define SYS_WRITE           11
#define SYS_READ            12
#define SYS_OPEN            13
#define SYS_WAIT            17
#define SYS_GET_TASK_INFO   18
#define SYS_EXEC            19
#define SYS_GETPID          20

#define SYS_IPC_SEND   21
#define SYS_IPC_RECV   22
#define SYS_IPC_CALL   23
#define SYS_IPC_REPLY  24

#define SYS_NOTIFY          25
#define SYS_WAIT_NOTIFY     26

/* Distinct return code for syscalls whose capability check passed but whose
 * backing operation is not implemented (vs. -1 = denied/bad-arg). */
#define SYS_ERR_NOSYS       (-38)
#define SYS_RECEIVE_PROGRAM 27
#define SYS_SPAWN           28

#define SYS_GETUID   29
#define SYS_AUTH     30
#define SYS_SUDO     31
#define SYS_GET_PASS 32

#define SYS_USERADD   33
#define SYS_USERDEL   34
#define SYS_PASSWD    35
#define SYS_ROTATE_KEYS   36  
#define SYS_READ_AUDIT    37
#define SYS_FS_MINT_FILE  38
#define SYS_FS_LOOKUP     39
#define SYS_FS_CREATE     40
#define SYS_FS_DELETE     41
#define SYS_FS_READDIR    42
#define SYS_FS_GET_ROOT   43
#define SYS_FS_READ       44
#define SYS_FS_WRITE      45
#define SYS_REGISTER_STORAGE_BACKEND 46
#define SYS_BLOCK_READ   47
#define SYS_BLOCK_WRITE  48
#define SYS_REGISTER_FS_SERVER 49
#define SYS_CONNECT_FS_SERVER  50
#define SYS_CAP_REVOKE         51

#define CAP_NULL                0
#define CAP_TCB                 1
#define CAP_NOTIFICATION        2
#define CAP_ENDPOINT            3
#define CAP_FRAME               4
#define CAP_USER                6
#define CAP_AUDIT               7
#define CAP_CONSOLE             8
#define CAP_ENCRYPTED_STORAGE   9
#define CAP_REVOCATION          10
#define CAP_BLOCK_DEV           11

#define CAP_RIGHT_READ          (1u << 0)
#define CAP_RIGHT_WRITE         (1u << 1)
#define CAP_RIGHT_EXEC          (1u << 2)
#define CAP_RIGHT_GRANT         (1u << 3)
#define CAP_RIGHT_MINT          (1u << 4)
#define CAP_RIGHT_REVOKE        (1u << 5)
#define CAP_RIGHT_AUDIT_WRITE   (1u << 6)
#define CAP_RIGHT_ALL           (0xFFFFFFFFu)

#define AUDIT_AUTH          1
#define AUDIT_SUDO          2
#define AUDIT_USER_MGMT     3
#define AUDIT_CAP_OPERATION 4
#define AUDIT_FILE_ACCESS   5
#define AUDIT_IPC           6
#define AUDIT_FS            7

#define AUDIT_CAP_MINT      10
#define AUDIT_CAP_REVOKE    11
#define AUDIT_CAP_TRANSFER  12
#define AUDIT_FS_LOOKUP     20
#define AUDIT_FS_CREATE     21
#define AUDIT_FS_DELETE     22
#define AUDIT_FS_READ       23
#define AUDIT_FS_WRITE      24
#define AUDIT_IPC_GRANT     30
#define AUDIT_TASK_CREATE   40
#define AUDIT_TASK_EXIT     41


typedef struct regs {uint32_t eax;uint32_t ebx;uint32_t ecx;uint32_t edx;uint32_t esi;uint32_t edi;uint32_t ebp;uint32_t esp;uint32_t eip;uint32_t eflags;uint32_t int_no;uint32_t err_code;uint32_t useresp;uint32_t cs;uint32_t ds;uint32_t es;uint32_t fs;uint32_t gs;uint32_t ss;} regs_t;


typedef struct user_account {
    char     name[32];
    uint32_t uid;
    uint32_t gid;
    uint32_t auth_lockout_until;
    uint32_t auth_fail_count;
    uint8_t  salt[16];
    int      valid;
    uint8_t  pass_hash[32];   
    char     home[64];
    char     shell[32];
} user_account_t;


typedef struct audit_event {
    uint32_t type;
    uint32_t kind;
    uint32_t uid;
    uint32_t subject_uid;
    int      subject_task;
    uint64_t object;
    int      result;
    uint64_t timestamp;
    uint64_t arg0;
    uint64_t arg1;
    char     path[64];
    char     message[128];
} audit_event_t;


typedef struct program_header {
    uint32_t type;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint32_t flags;
    uint32_t align;
    char     name[32];      
    uint64_t size;          
    uint32_t magic;         
    uint32_t entry;
} program_header_t;


typedef struct capability {
    uint32_t type;
    uint32_t rights;
    uint64_t object;
    uint32_t badge;
    uint32_t serial;
    uint32_t generation;
} capability_t;

/* Immutable identity snapshot of a capability, taken at lookup time and
 * reconfirmed at use time via cap_revalidate() to defend against lookup/use
 * TOCTOU. `object` is uint64_t to match capability_t.object exactly. */
typedef struct cap_snapshot {
    uint32_t serial;
    uint32_t generation;
    uint64_t object;
    int      valid;
} cap_snapshot_t;


typedef struct tcb {
    uint32_t state;
    uint32_t caps_in_use;
    capability_t *cspace;
    uint32_t cspace_size;
    uint64_t tsc_base;
    uint32_t esp; uint32_t eip; uint32_t cr3; uint32_t priority; uint32_t cap_tcb; int auth_fail_count; int auth_lockout_until; int ipc_role; 
    
    uint32_t uid;
    uint32_t gid;
    char     name[32];
    uint8_t  user_file_master_key[32];
    int      has_file_key;

    
    uint64_t heap_start;
    uint64_t heap_current;
    uint64_t heap_end;

    
    int      in_kernel;
    int      blocked_on;
    int      blocked_on_notif;
    int      waiter;

    
    uint64_t kernel_stack_top;

    
    uint8_t  padding[248];
} tcb_t;

extern tcb_t tasks[MAX_TASKS];


/* Lineage/generation tracking is owned by the safe-Rust authority
 * (rust/src/capability.rs). The legacy C `lineages[]` table and its helpers
 * (lineage_register/lineage_revoke/next_lineage_id) have been removed to avoid a
 * C/Rust desync that allowed use-after-revoke; use rust_lineage_check /
 * rust_lineage_bump instead. */


typedef struct block_device {
    char name[32];
    uint64_t total_blocks;
    int (*read_block)(struct block_device *bd, uint64_t block, void *buf);
    int (*write_block)(struct block_device *bd, uint64_t block, const void *buf);
    void *private;
} block_device_t;

typedef struct virtual_disk {
    uint8_t *data;
    uint64_t size;
    uint64_t block_count;
} virtual_disk_t;

typedef struct fs_superblock {
    uint32_t magic;
    uint32_t version;
    uint64_t inode_bitmap_start;
    uint64_t block_bitmap_start;
    uint64_t data_bitmap_start;
    uint64_t inode_table_start;
    uint64_t data_start;
    uint64_t inode_count;
    uint64_t block_count;
    uint64_t total_blocks;
    uint32_t block_size;
    uint8_t  volume_key_salt[16];
    uint8_t  volume_key[16];
    uint32_t generation;
} fs_superblock_t;

typedef struct on_disk_inode {
    uint64_t size;
    uint32_t type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t atime, mtime, ctime;
    uint64_t direct[12];
    uint64_t indirect;
    uint64_t double_indirect;
    uint8_t  key_material[32];
    uint8_t  file_key[16];
    uint8_t  file_iv[16];
    uint32_t links;
    uint32_t generation;
    uint32_t checksum;
} on_disk_inode_t;

typedef struct mounted_fs {
    int mounted;
    block_device_t *bd;
    fs_superblock_t sb;
    uint8_t volume_key[16];
    uint8_t *inode_cache;
} mounted_fs_t;

typedef struct fs_object {
    int in_use;
    uint32_t owner_uid;
    int is_encrypted;
    uint32_t integrity_tag;
    uint32_t type;
    void *data;
    uint64_t size;
    char child_names[8][32];
    int num_children;
    void *children[8];
    uint8_t enc_file_key[32];
    uint8_t file_key_iv[16];
    char name[32];
    uint32_t gen;
} fs_object_t;

extern fs_object_t *fs_objects[MAX_FS_OBJECTS];
extern uint8_t kernel_pepper[16];

extern int fs_server_task_id;
extern int fs_server_listen_ep_idx;


extern char keyboard_buffer[256];
extern uint32_t kb_head;
extern uint32_t kb_tail;

typedef struct spinlock {
    volatile uint32_t locked;
} spinlock_t;

extern spinlock_t storage_lock;
extern spinlock_t cap_lock;
extern spinlock_t page_lock;



int  get_current_task(void);
void set_current_task(int v);
void schedule(void);
void yield(void);
char console_getc(void);
void console_putc(char c);
void console_puts(const char *s);
void println(const char *s);
void print(const char *s);
void print_hex(uint64_t v);
void print_decimal(uint64_t v);
void print_hrule(uint8_t color);
void set_text_colour(uint8_t color);
uint64_t read_tsc(void);
uint32_t get_system_ticks(void);
void outb(uint16_t port, uint8_t val);
uint8_t inb(uint16_t port);
void secure_zero(void *p, size_t n);
void spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);
void dump_kernel_log(void);
void syscall_handler(struct regs *r);
void resume_shell_after_fault(void);
void print_hex64(uint64_t v);
void timer_handler(void);
void smp_maybe_shootdown(uint64_t v);
int smp_get_online_count(void);
/* Signatures MUST match rust/src/memory.rs exactly (return types and the u32
 * n_pages width — they previously drifted to `int`). */
int32_t  rust_page_ref_dec(uint32_t phys, uint16_t *refcounts, uint32_t n_pages);
uint16_t rust_page_ref_inc(uint32_t phys, uint16_t *refcounts, uint32_t n_pages);
bool     rust_page_is_valid_user_phys(uint32_t phys, uint32_t n_pages);
bool     rust_page_refcounts_register(const uint16_t *refcounts, uint32_t n_pages);
bool     rust_cow_copy_required(bool is_cow, bool is_write, uint16_t ref_count);

/* Centralized capability serial allocation (wrap logic lives in Rust). */
uint32_t rust_cap_alloc_serial(uint32_t *next_serial);

void terminal_init(void);
void clear_screen(void);
void print_blanks(int n);
void print_boot_timestamp(void);
void print_section(const char *title, uint8_t color);
void idt_init64(void);
void pic_init(void);
void set_tss_kernel_stack(uint64_t kstack_top);
void cpu_detect_features(void);
void init_syscall_instruction_path(void);
void ramfs_init(void);
void ata_init(void);
void scheduler_init(void);
void smp_bringup(void);
void aslr_init_seed(void);
void spawn_initial_userspace_shell(void);
int cpu_has_aesni(void);
void cpu_enable_protections(void);
void paging_init(void);

void cap_init(void);
capability_t *cap_lookup(uint32_t slot, uint32_t required_rights);
bool cap_mint(uint32_t dest_slot, uint32_t src_slot, uint32_t new_rights);
bool cap_transfer(uint32_t dest_slot, uint32_t src_slot);
bool cap_move(uint32_t dest_slot, uint32_t src_slot);
bool cap_revoke(uint32_t slot);
bool cap_create_revocation_set(uint32_t target_slot, uint32_t rev_slot);
bool has_encrypted_storage_cap(void);


uint32_t cap_alloc_fresh_serial(void);

/* Lookup/use TOCTOU defense: snapshot a capability's identity, then
 * revalidate the slot still holds that exact identity (with the required
 * rights) at the point of use. Returns NULL on revoke/re-mint/generation bump. */
cap_snapshot_t cap_snapshot(const capability_t *c);
capability_t *cap_revalidate(uint32_t slot, uint32_t required_rights,
                             const cap_snapshot_t *snap);


capability_t *rust_cap_lookup(capability_t *cspace, uint32_t sz, uint32_t slot, uint32_t rights);
bool rust_cap_mint(capability_t *dest_array, uint32_t sz, uint32_t dest_slot,
                   uint32_t src_slot, uint32_t new_rights, uint32_t *next_serial, uint32_t caps_in_use);
bool rust_cap_transfer(capability_t *dest_array, uint32_t sz, uint32_t dest_slot,
                       uint32_t src_slot, uint32_t *next_serial);
bool rust_cap_revoke(capability_t *cspace, uint32_t sz, uint32_t slot, uint32_t *next_serial);
bool rust_cap_revoke_by_values(capability_t *cspace, uint32_t sz, uint32_t target_serial, uint32_t target_badge, uint64_t target_obj);

/* One capability space, for the system-wide revocation sweep. Layout MUST match
 * `struct CSpaceDesc` in rust/src/capability.rs. */
typedef struct cspace_desc {
    capability_t *caps;
    uint32_t      size;
    uint32_t     *caps_in_use; /* owning task's counter; NULL to skip accounting */
} cspace_desc_t;

/* Authoritative, system-wide revocation: revokes target_slot in target_cspace
 * and sweeps every cspace in `spaces` for derived copies of the same lineage.
 * Must be called under cap_lock so the snapshot is stable. */
bool rust_cap_revoke_global(capability_t *target_cspace, uint32_t target_cspace_size,
                            uint32_t target_slot, uint32_t *target_caps_in_use,
                            const cspace_desc_t *spaces, uint32_t space_count,
                            uint32_t *next_serial);

bool rust_validate_page_fault(uint32_t t, uint32_t a, uint32_t e);
int  rust_handle_command(const uint8_t *cmd, size_t len);


int  do_useradd(uint32_t uid, uint32_t gid, const char *name, const char *pass);
int  do_userdel(uint32_t uid);
int  do_passwd(uint32_t target, const char *newpass);
int derive_and_store_user_file_key(uint32_t uid, const char *material, size_t material_len);


int  storage_format(block_device_t *bd);
int  storage_mount(block_device_t *bd);
int  storage_read_file_block(mounted_fs_t *mfs, uint64_t ino, uint64_t block, void *buf);
int  storage_write_file_block(mounted_fs_t *mfs, uint64_t ino, uint64_t block, const void *buf);
mounted_fs_t *storage_get_mounted_fs(void);
block_device_t *storage_get_default_device(void);
void storage_set_default_device(block_device_t *bd);
int capfs_init(void);
int storage_init(void);
int storage_mount(block_device_t *bd);
int64_t storage_alloc_block(block_device_t *bd, fs_superblock_t *sb);
void storage_free_block(block_device_t *bd, fs_superblock_t *sb, uint64_t block);
int64_t storage_alloc_inode(block_device_t *bd, fs_superblock_t *sb);
void storage_free_inode(block_device_t *bd, fs_superblock_t *sb, uint64_t ino);
int  storage_read_inode(block_device_t *bd, fs_superblock_t *sb, uint64_t ino, on_disk_inode_t *inode_out);
int  storage_write_inode(block_device_t *bd, fs_superblock_t *sb, uint64_t ino, const on_disk_inode_t *inode);
int  storage_derive_block_keys(uint64_t ino, uint64_t block, uint32_t gen,
                               const uint8_t *vol_key, uint8_t *enc_key, uint8_t *mac_key);
int  storage_compute_mac(const uint8_t *nonce, const uint8_t *data, size_t data_len,
                         const uint8_t *mac_key, uint8_t *tag_out);
void storage_register_userspace_block_backend(int (*r)(uint64_t, void*), int (*w)(uint64_t, const void*));
void crypto_aes128_ctr_encrypt(void *b, size_t l, const uint8_t *k, const uint8_t *n);
int  storage_block_read(uint64_t block, void *buf);
int  storage_block_write(uint64_t block, const void *buf);
int  do_rotate_keys(void);


int  ramfs_open(const char *path, int flags);
int  ramfs_create(const char *path, int mode);
int  ramfs_write(int fd, const void *buf, size_t len);
int  ramfs_read(int fd, void *buf, size_t len);
char serial2_read_char(void);
void serial_write_char(char c);


int sys_fs_mint_file(uint32_t dir_slot, uint32_t name_slot, uint32_t out_slot);
int sys_fs_lookup(uint32_t dir_slot, const char *name, uint32_t out_slot, uint32_t desired_rights);
int sys_fs_create(uint32_t dir_slot, const char *name, int type, uint32_t out_slot, uint32_t desired_rights);
int sys_fs_delete(uint32_t dir_slot, const char *name);
int sys_fs_readdir(uint32_t dir_slot, char *buf, uint32_t sz);
int sys_fs_get_root(uint32_t out_slot, uint32_t rights);
int sys_fs_read(uint32_t file_slot, char *buf, uint32_t len);
int sys_fs_write(uint32_t file_slot, const char *buf, uint32_t len);


int  copy_from_user(void *kdst, const void *usrc, size_t len);
int  copy_to_user(void *udst, const void *ksrc, size_t len);


int  sys_ipc_send(uint32_t ep_slot, const void *msg, size_t len);
int  sys_ipc_recv(uint32_t ep_slot, void *msg, size_t max_len);


bool     capability_validate_generation(const capability_t *cap);
uint32_t rust_lineage_bump(uint64_t obj);
bool     rust_lineage_check(uint64_t obj, uint32_t gen);

/* ---- Cryptography & entropy (audited primitives implemented in Rust) ---- */
/* SHA-256 suite */
int  rust_password_hash(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t *out, size_t out_len);
int  rust_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len, uint8_t *out32);
int  rust_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *salt, size_t salt_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out, size_t out_len);
/* ChaCha20 CSPRNG */
void     rust_rng_add_entropy(const uint8_t *data, size_t len);
void     rust_rng_fill(uint8_t *out, size_t len);
uint64_t rust_rng_u64(void);
bool     rust_rng_is_seeded(void);
bool     rust_rdrand_u64(uint64_t *out);

/* C-side entropy helpers (crypto.c) */
int  cpu_has_rdrand(void);
void entropy_init(void);            /* gather hardware/timing entropy, seed CSPRNG */
void entropy_add_sample(uint64_t s);/* mix an opportunistic entropy sample */
void secure_random_bytes(void *out, size_t n);

/* Password KDF cost (PBKDF2-HMAC-SHA256 iterations). */
#define PASSWORD_KDF_ITERATIONS 120000U


#define CAP_DIR                 12
#define CAP_FILE                13

#define CAP_RIGHT_FS_LOOKUP     (1u << 10)
#define CAP_RIGHT_FS_CREATE     (1u << 11)
#define CAP_RIGHT_FS_DELETE     (1u << 12)
#define CAP_RIGHT_FS_READ       (1u << 13)
#define CAP_RIGHT_FS_WRITE      (1u << 14)

#define FS_OBJ_DIR              2
#define FS_OBJ_FILE             1
#define FS_DATA_SIZE            4096
#define FS_MAX_CHILDREN         32


int capfs_lookup(capability_t *dir_cap, const char *name, capability_t *out_cap, uint32_t desired_rights);
int capfs_create(capability_t *dir_cap, const char *name, int type, capability_t *out_cap, uint32_t desired_rights);
int capfs_delete(capability_t *dir_cap, const char *name);
int capfs_readdir(struct capability *dir_cap, char *buf, size_t bufsize);
int capfs_read(struct capability *file_cap, void *buf, size_t len);
int capfs_write(struct capability *file_cap, const void *buf, size_t len);


int  ramfs_list(char *buf, size_t buflen);


void create_task(int id, uint64_t entry, uint64_t stack_top);
void create_user_pagedir(uint32_t id);
void switch_cr3(uint64_t cr3);
void drop_to_ring3(uint64_t entry, uint64_t stack);
void aslr_mix_entropy(uint64_t val);
uint32_t aslr_random_offset(uint32_t max);
addr_t aslr_random_stack_top(addr_t top);

#endif
