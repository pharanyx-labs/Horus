/* Compiler libcall for the Clang nightly (roadmap 4.22).
 *
 * Decision. fs_server is in the trusted computing base, and this definition is
 * linked into it. Clang, with -ffreestanding and -fno-builtin, still emits a
 * call to memcpy for a struct assignment that GCC inlines. The call is not a
 * libc the program asked for. It is the compiler's own helper, and a
 * freestanding link has to provide it or the program does not link.
 *
 * Recommendation. Keep the symbol out of libhorus. That archive is on the
 * newlib link line, and a member named memcpy would be taken instead of
 * libc's. Keep it off the GCC link line as well: GCC does not reference it,
 * and the default image must not change. A separate archive, added only when
 * CLANG=1, is extracted only by a program that references the symbol. Of the
 * shipped programs, that is fs_server. shell.c keeps its own static memcpy
 * and does not pull this member.
 *
 * The body is a byte move in registers the compiler cannot turn back into a
 * call to memcpy. It does not use the FPU, and it does not handle overlap:
 * memcpy is not required to. No syscall, no capability, no policy.
 */
#include <stddef.h>
#include <stdint.h>

void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    __asm__ volatile("rep movsb"
                     : "+D"(d), "+S"(s), "+c"(n)
                     :
                     : "memory");
    return dest;
}
