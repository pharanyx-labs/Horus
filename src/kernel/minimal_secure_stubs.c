#include "kernel.h"
#ifndef MINIMAL_SECURE
#else
void ramfs_init(void){}
int ramfs_open(const char *p, int f){(void)p;(void)f;return -1;}
int ramfs_create(const char *p, int m){(void)p;(void)m;return -1;}
int ramfs_write(int fd, const void *b, size_t l){(void)fd;(void)b;(void)l;return -1;}
int ramfs_read(int fd, void *b, size_t l){(void)fd;(void)b;(void)l;return -1;}
int ramfs_list(char *b, size_t n){(void)b;(void)n;return 0;}
int storage_init(void){return 0;}
int storage_mount(block_device_t *b){(void)b;return 0;}
/* storage_format_sealed is static in storage.c — no stub needed here. */
int storage_unlock(const char *p,size_t l){(void)p;(void)l;return 0;}
int storage_block_read(uint64_t bl, void *buf){(void)bl;(void)buf;return -1;}
int storage_block_write(uint64_t bl, const void *buf){(void)bl;(void)buf;return -1;}
void ata_init(void){}
void ata_read_sector(uint32_t lba, uint8_t *buf){(void)lba;(void)buf;}
void ata_write_sector(uint32_t lba, const uint8_t *buf){(void)lba;(void)buf;}
int crypto_aes_init(void){return 0;}
void crypto_aes128_ctr_encrypt(void *b, size_t l, const uint8_t *k, const uint8_t *n){(void)b;(void)l;(void)k;(void)n;}
int do_rotate_keys(void){return 0;}
int sys_fs_mint_file(uint32_t d,uint32_t n,uint32_t o){(void)d;(void)n;(void)o;return -1;}
int sys_fs_lookup(uint32_t d,const char *nm,uint32_t o,uint32_t r){(void)d;(void)nm;(void)o;(void)r;return -1;}
int sys_fs_create(uint32_t d,const char *nm,int t,uint32_t o,uint32_t r){(void)d;(void)nm;(void)t;(void)o;(void)r;return -1;}
int sys_fs_delete(uint32_t d,const char *nm){(void)d;(void)nm;return -1;}
int sys_fs_readdir(uint32_t d,char *b,uint32_t s){(void)d;(void)b;(void)s;return -1;}
int sys_fs_get_root(uint32_t o,uint32_t r){(void)o;(void)r;return -1;}
int sys_fs_read(uint32_t f,char *b,uint32_t l){(void)f;(void)b;(void)l;return -1;}
int sys_fs_write(uint32_t f,const char *b,uint32_t l){(void)f;(void)b;(void)l;return -1;}
int capfs_lookup(capability_t *d,const char *n,capability_t *o,uint32_t r){(void)d;(void)n;(void)o;(void)r;return -1;}
int capfs_create(capability_t *d,const char *n,int t,capability_t *o,uint32_t r){(void)d;(void)n;(void)t;(void)o;(void)r;return -1;}
int capfs_delete(capability_t *d,const char *n){(void)d;(void)n;return -1;}
int capfs_readdir(struct capability *d,char *b,size_t s){(void)d;(void)b;(void)s;return -1;}
int capfs_read(struct capability *f,void *b,size_t l){(void)f;(void)b;(void)l;return -1;}
int capfs_write(struct capability *f,const void *b,size_t l){(void)f;(void)b;(void)l;return -1;}
#endif
