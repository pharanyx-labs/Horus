/* cpu_limits.h -- the CPU ceiling, in the ONE form both C and assembly can read.
 *
 * Deliberately nothing but #defines: src/boot/ap_trampoline.S and
 * src/boot/multiboot.S include this with -x assembler-with-cpp, and a C
 * declaration here would not assemble. kernel.h includes it too, so MAX_CPUS has
 * exactly one definition. Until 2026-09-21 the trampoline carried its own copy
 * (AP_MAX_CPUS) pinned to the C value by a _Static_assert, and the GDT carried
 * one hand-written TSS slot per AP; raising the ceiling meant finding all three.
 * Now the trampoline bounds against this value and the GDT reserves its slots
 * from it with .rept, so there is nothing to keep in step.
 *
 * Every CPU costs about 104 KiB of .bss whether it is present or not (a 68 KiB
 * idle stack with its guard page, three IST fault stacks and a TSS with its I/O
 * bitmap), all of it below USER_PHYS_BASE, which .github/image-budget.yml bounds.
 * Raising this is therefore a budget change as well as a code one: see
 * docs/LIMITATIONS.md for why the ceiling is 8 and what going further needs. */
#ifndef HORUS_CPU_LIMITS_H
#define HORUS_CPU_LIMITS_H

#define MAX_CPUS 8

/* No valid CPU index: an APIC id with no slot parks in the trampoline. */
#define CPU_INDEX_NONE 0xFF

#endif
