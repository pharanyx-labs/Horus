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
 * The export table is in the SHARED read-only segment, and a caller finds it
 * through e_entry rather than by resolving a symbol by name. That IS the
 * limitation this file admits to: name resolution is what makes a dynamic
 * linker, and an index into a fixed table is what this mechanism supports until
 * one exists.
 *
 * IT ALSO HAS WRITABLE DATA NOW, and that is the point of the second half of
 * this file. Measured going into the newlib migration: of the 59 newlib symbols
 * the shipped coreutils actually reference, exactly three are writable --
 * `_impure_ptr` (errno, stdio buffers, atexit, rand state), `optarg` and
 * `optind`. A libc cannot be shared until a shared object can carry data that
 * is PRIVATE to each task, so `shlib_counter` below is the stand-in for those
 * three, and S50 is the property it witnesses.
 *
 * Shared writably, one task would read another's stdio buffers and errno and
 * could corrupt its malloc arena. That is the same argument S49 makes about
 * text, arriving one segment further on, and it is why the split is enforced by
 * the linker script (userspace/shlib.ld) rather than by convention.
 */

/* Marked used and placed in its own section so the linker keeps it at offset 0
 * of the first PT_LOAD, ahead of any code. A table the loader cannot find is a
 * library nobody can call. */
__attribute__((section(".shlib_exports"), used))
const void *const shlib_exports[7];

int shlib_add(int a, int b);
int shlib_magic(void);
int shlib_checksum(const char *s);
int shlib_state_get(void);
void shlib_state_set(int v);
int shlib_state_initial(void);

/* THE PER-TASK STATE. Lives in .data, which shlib.ld puts on its own page in
 * its own PT_LOAD, which the loader instantiates privately for each task.
 *
 * The initialiser is a value no task would write by accident, so "the task got
 * its own copy" and "the copy was initialised from the library's image" are
 * separately observable -- one arm can break either without breaking the other.
 * A zero initialiser would have made those two indistinguishable, because a
 * freshly carved frame is already zero. */
#define SHLIB_STATE_INITIAL 0x1234ABCD
int shlib_counter = SHLIB_STATE_INITIAL;

int shlib_state_get(void) { return shlib_counter; }
void shlib_state_set(int v) { shlib_counter = v; }

/* The initialiser, returned from TEXT rather than read from data.
 *
 * This exists so no caller has to write the constant down. A test comparing
 * shlib_state_get() against a literal 0x1234ABCD of its own would hold a second
 * copy of a fact owned by this file, and the two would drift -- which is the
 * failure the generated shlib_offsets.h exists to prevent one level up. Here the
 * comparison is between the library's DATA (per task, writable) and the
 * library's CODE (shared, immutable), so "was my copy initialised from the
 * image" is answered without any third party knowing the value. */
int shlib_state_initial(void) { return SHLIB_STATE_INITIAL; }

__attribute__((section(".shlib_exports"), used))
const void *const shlib_exports[7] = {
    (const void *)&shlib_add,
    (const void *)&shlib_magic,
    (const void *)&shlib_checksum,
    (const void *)&shlib_state_get,
    (const void *)&shlib_state_set,
    (const void *)&shlib_state_initial,
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
