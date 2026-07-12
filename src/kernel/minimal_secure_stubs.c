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
int storage_rekey(const char *p,size_t l){(void)p;(void)l;return 0;}
int storage_block_read(uint64_t bl, void *buf){(void)bl;(void)buf;return -1;}
int storage_block_write(uint64_t bl, const void *buf){(void)bl;(void)buf;return -1;}
void ata_init(void){}
void ata_read_sector(uint32_t lba, uint8_t *buf){(void)lba;(void)buf;}
void ata_write_sector(uint32_t lba, const uint8_t *buf){(void)lba;(void)buf;}
int crypto_aes_init(void){return 0;}
void crypto_aes128_ctr_encrypt(void *b, size_t l, const uint8_t *k, const uint8_t *n){(void)b;(void)l;(void)k;(void)n;}
int do_rotate_keys(void){return 0;}
/* The legacy capfs (sys_fs_* 38-45 + capfs_*) was removed; no stubs needed. */
#endif
