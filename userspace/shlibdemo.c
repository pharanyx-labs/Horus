/* shlibdemo.c -- the shared object, built once and executed by many tasks.
 *
 * A stand-in for libc, deliberately small: the point of this object is the
 * MECHANISM it exercises -- loaded once into frames, mapped read+exec into
 * several address spaces, writable by none of them (S49) -- and a large library
 * would prove nothing extra while making a failure harder to read.
 *
 * Built -shared -fPIC -nostdlib, so it has no undefined symbols and its only
 * relocations are R_X86_64_RELATIVE. shlib_init refuses anything else rather
 * than partially applying it.
 *
 * The export table is first in the object, at offset 0, so a caller can find it
 * without resolving a symbol by name. That IS the limitation this file admits
 * to: name resolution is what makes a dynamic linker, and an index into a fixed
 * table is what this mechanism supports until one exists.
 */

/* Marked used and placed in its own section so the linker keeps it at offset 0
 * of the first PT_LOAD, ahead of any code. A table the loader cannot find is a
 * library nobody can call. */
__attribute__((section(".shlib_exports"), used))
const void *const shlib_exports[4];

int shlib_add(int a, int b);
int shlib_magic(void);
int shlib_checksum(const char *s);

__attribute__((section(".shlib_exports"), used))
const void *const shlib_exports[4] = {
    (const void *)&shlib_add,
    (const void *)&shlib_magic,
    (const void *)&shlib_checksum,
    0
};

int shlib_add(int a, int b) { return a + b; }

/* A value a caller can check it really executed OUR code and not a patched
 * copy. The control arm's whole demonstration is this number coming back
 * different in a task that never wrote it. */
int shlib_magic(void) { return 0x5A5A1234; }

int shlib_checksum(const char *s) {
    int h = 0;
    while (*s) { h = h * 31 + (unsigned char)*s; s++; }
    return h;
}
