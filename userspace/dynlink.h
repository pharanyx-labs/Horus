/* dynlink.h -- the ring-3 linker's entry point and its refusals
 * (userspace/dynlink.c, docs/design/shared-libc.md §8). */
#ifndef HORUS_DYNLINK_H
#define HORUS_DYNLINK_H

#define DYNLINK_NO_CAP   (-1)   /* no library capability: the image did not ask, or nothing to pass on */
#define DYNLINK_NO_DATA  (-2)   /* the kernel mapped no private copy of the library's data            */
#define DYNLINK_TEXT     (-3)   /* a page of the library's code would not map                         */
#define DYNLINK_ABI      (-4)   /* the library is not the one this program was built against          */
#define DYNLINK_UNKNOWN  (-5)   /* a name the library does not export (*unknown says which)           */
#define DYNLINK_RELOC    (-6)   /* the program's own dynamic section is malformed                     */
#define DYNLINK_SEAL     (-7)   /* the resolved table could not be sealed                             */

/* Map the library, resolve this program's references to it by name, and seal
 * them. 0 on success; otherwise a reason above, and for DYNLINK_UNKNOWN the name
 * in *unknown. Calls nothing in the library. */
int horus_dynlink(const char **unknown);

#endif
