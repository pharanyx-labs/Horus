




/* mkheadered -- write a Horus `.bin`: the container header, then the payload.
 *
 * THIS TOOL DEFINED THE FORMAT AND DID NOT SHARE ITS DEFINITION. Until
 * 2026-09-03 the struct below was a private copy here, a second (44-byte) copy in
 * include/syscall.h, a third (104-byte, same name, ELF-flavoured) in
 * src/include/kernel.h, and neither of the two readers in src/kernel/loader.c
 * used any of them -- they assembled the fields from literal byte offsets. Four
 * copies, none connected, agreeing only by hand. docs/LIMITATIONS.md 2.18.
 *
 * It now includes the one declaration. That is the whole repair: this is a HOST
 * program built with the host compiler, so program_abi.h is deliberately
 * freestanding (<stdint.h> and nothing else) to keep it includable from here.
 * A change to the layout now fails to build, or moves both sides at once. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "program_abi.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input.elf> <output.bin> [name]\n", argv[0]);
        return 1;
    }

    const char *input = argv[1];
    const char *output = argv[2];
    const char *name = (argc > 3) ? argv[3] : "";

    FILE *fin = fopen(input, "rb"); /* nosemgrep: path-manipulation -- build tool; paths are Makefile-controlled, not user input */
    if (!fin) {
        perror("open input");
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long fsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    /* Must not exceed the kernel's staged-image cap (LOADER_STAGING_BYTES in
     * src/include/kernel.h, 8 MiB): the kernel refuses to arm a larger image, so
     * a .bin bigger than this could never load. Keep the two in step. */
    if (fsize <= 0 || fsize > 8*1024*1024) {
        fprintf(stderr, "Bad input size (max 8 MiB, the kernel LOADER_STAGING_BYTES cap)\n");
        fclose(fin);
        return 1;
    }

    /* Check the allocation. fsize is already bounded to 8 MiB above, so this is
     * unlikely rather than impossible -- and an unlikely NULL handed to fread()
     * is still a null dereference inside libc, which reports as a crash of the
     * BUILD rather than as "mkheadered could not allocate". A build tool that
     * fails should say why: it is the same fail-closed rule the kernel holds
     * itself to, and it costs three lines. */
    uint8_t *data = malloc(fsize);
    if (!data) {
        fprintf(stderr, "out of memory allocating %ld bytes\n", fsize);
        fclose(fin);
        return 1;
    }
    if (fread(data, 1, fsize, fin) != (size_t)fsize) {
        perror("read");
        free(data);
        fclose(fin);
        return 1;
    }
    fclose(fin);

    struct horus_image_header hdr = {0};
    hdr.magic = HORUS_IMAGE_MAGIC;
    hdr.entry = 0;
    hdr.size  = fsize;
    strncpy(hdr.name, name, HORUS_IMAGE_NAME_MAX - 1);
    {

        char elfpath[512];
        size_t ilen = strlen(input);
        if (ilen < sizeof(elfpath) - 4) {
            strcpy(elfpath, input);
            char *d = strrchr(elfpath, '.');
            if (d) strcpy(d, ".elf");
            else strcat(elfpath, ".elf");
            FILE *fe = fopen(elfpath, "rb");
            if (fe) {
                uint8_t eh[52];
                if (fread(eh, 1, 52, fe) == 52 && eh[0]==0x7f && eh[4]==1) {
                    uint32_t e_entry = (uint32_t)eh[24] | ((uint32_t)eh[25]<<8) |
                                       ((uint32_t)eh[26]<<16) | ((uint32_t)eh[27]<<24);
                    if (e_entry >= 0x400000U) {
                        hdr.entry = e_entry - 0x400000U;
                    } else if (e_entry > 0) {
                        hdr.entry = e_entry;
                    }
                }
                fclose(fe);
            }
        }
    }

    FILE *fout = fopen(output, "wb"); /* nosemgrep: path-manipulation -- build tool; paths are Makefile-controlled, not user input */
    if (!fout) {
        perror("open output");
        free(data);
        return 1;
    }

#ifdef IMAGE_HDR_WRITER_SKEW
    /* CONTROL ARM (S80). Emit `name` four bytes further into the SAME 44-byte
     * header, as if a `uint32_t flags` had been inserted before it on the WRITER
     * side only. That is the change four unconnected copies of a layout could not
     * catch, and it is deliberately not a loud one: magic, entry, size and the
     * payload offset are all still exactly right, the kernel arms the image
     * successfully, and only the NAME comes back wrong. An arm that broke the
     * magic would be caught by any reader; this one is caught only by a test that
     * checks the whole header. */
    {
        unsigned char skew[44];
        memset(skew, 0, sizeof(skew));
        memcpy(skew + 0, &hdr.magic, 4);
        memcpy(skew + 4, &hdr.entry, 4);
        memcpy(skew + 8, &hdr.size,  4);
        strncpy((char *)skew + 16, name, 27);
        fwrite(skew, 1, sizeof(skew), fout);
    }
#else
    fwrite(&hdr, 1, sizeof(hdr), fout);
#endif
    fwrite(data, 1, fsize, fout);
    fclose(fout);

    free(data);
    printf("Created %s (size=%ld, name='%s')\n", output, fsize, name);
    return 0;
}
