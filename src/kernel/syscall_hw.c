/* syscall_hw.c -- console/driver hardware-delegation syscalls.
 *
 * The security-hardening program's Phase 6 driver-privilege-separation work moves
 * the console (VGA/serial/keyboard) out of ring 0 into a ring-3 server that owns
 * the hardware directly. This file holds the kernel side of "owns the hardware":
 * the narrow, cap-gated syscalls that hand a ring-3 driver controlled access to
 * device memory. The first (J2) is SYS_MAP_PHYS, which maps an ALLOWLISTED device
 * frame into the caller's own address space. Later jobs (a TSS I/O-permission
 * bitmap grant, an IRQ->notification bridge) join it here.
 *
 * Every syscall here is gated on CAP_IO_DEVICE in the dispatch table (syscall.c),
 * so only a task explicitly endowed with that capability -- the console server --
 * can reach any of it. See docs/proposals/console-server.md.
 */
#include "syscall_internal.h"

/* The fixed device-frame allowlist. A physical frame may be mapped into a user
 * address space ONLY if it is on this list -- there is no way to name an
 * arbitrary physical address, so this syscall cannot be turned into a
 * map-anything primitive (which would hand a driver the kernel's own memory).
 * The list is exactly the console's frames:
 *   - [0xB8000, 0xBA000): the VGA text-mode framebuffer. An 80x50 text buffer is
 *     8000 bytes, so it spans two 4 KiB frames (0xB8000 and 0xB9000).
 *   - [0xA0000, 0xB0000): the VGA graphics/font plane, written during mode init
 *     (load_8x8_font blits into the font plane). 16 frames.
 * Both live in low physical memory, well inside the user half, so they can be
 * mapped without touching the kernel's higher-half window. */
static int device_frame_allowed(uint64_t phys) {
    if (phys & (PAGE_SIZE - 1)) return 0;                  /* frame-aligned only */
    if (phys >= 0xB8000ULL && phys < 0xBA000ULL) return 1; /* VGA text framebuffer */
    if (phys >= 0xA0000ULL && phys < 0xB0000ULL) return 1; /* VGA graphics/font plane */
    return 0;
}

/* The user (lower) canonical half: pml4 indices 0..255, i.e. addresses below
 * 2^47. user_pte_slot() independently refuses the kernel half, but rejecting it
 * here gives a clear SYS_ERR_INVAL rather than a generic map failure. */
#define USER_HALF_LIMIT   0x0000800000000000ULL

/* SYS_MAP_PHYS(paddr, vaddr, len, flags): map one allowlisted 4 KiB device frame
 * `paddr` at user address `vaddr` in the caller's own address space. The frame is
 * mapped present + user + non-executable, writable iff MAP_PHYS_WRITE is set.
 *
 * Fail closed on every irregularity: an off-list frame (SYS_ERR_PERM -- it is an
 * authority question, the cap alone is not enough), a misaligned or oversized
 * request, a zero/kernel-half target VA, or a missing access bit (SYS_ERR_INVAL).
 * The cap gate (CAP_IO_DEVICE + WRITE in the authorizing slot) is enforced
 * centrally by syscall_handler before this runs. */
void h_map_phys(struct interrupt_frame64 *r) {
    uint64_t paddr = r->rbx;
    uint64_t vaddr = r->rcx;
    uint64_t len   = r->rdx;
    uint32_t flags = (uint32_t)r->rsi;

    /* One frame at a time: a device mapping is a single named frame, never a
     * range the caller can stretch off the allowlisted page. */
    if (len == 0 || len > PAGE_SIZE) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    /* At least READ must be requested; unknown bits are ignored (only WRITE is
     * otherwise meaningful). */
    if (!(flags & (MAP_PHYS_READ | MAP_PHYS_WRITE))) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }

    if (!device_frame_allowed(paddr)) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    if ((vaddr & (PAGE_SIZE - 1)) || vaddr == 0 || vaddr >= USER_HALF_LIMIT) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }

    int cur = get_current_task();
    uint64_t writable = (flags & MAP_PHYS_WRITE) ? 1 : 0;
    int rc = user_map_device_page((uint32_t)cur, vaddr, paddr, writable);
    r->rax = (rc == 0) ? 0 : (uint32_t)SYS_ERR_FAULT;

    /* Hand the console over to the ring-3 console driver, so the kernel's print()
     * stops touching serial+VGA (klog only) and the two can't interleave on the
     * shared UART once SMP runs them at once. The console driver is the task that
     * owns BOTH the console ports (io_allowed, via SYS_IOPORT_GRANT) AND the VGA
     * framebuffer it just mapped — that pair uniquely identifies console_server.
     * Keying off the port grant alone would wrongly silence ioporttest (grants
     * ports to probe faults, never drives the console); off the VGA map alone would
     * wrongly silence mapphystest (maps the frame to verify it, holds no port
     * grant). Both self-tests report via the kernel console, so neither may lose
     * ownership of it. */
    if (rc == 0 && paddr >= 0xB8000ULL && paddr < 0xBA000ULL &&
        cur > 0 && cur < MAX_TASKS && tasks[cur].io_allowed) {
        console_set_owner(cur);
    }
}

/* SYS_IOPORT_GRANT(): grant the calling task native ring-3 in/out on the console
 * ports (the TSS I/O bitmap's allowlist). Cap-gated on CAP_IO_DEVICE + WRITE by
 * the dispatch table, so only the console/driver server reaches it. Sets the
 * per-task flag and activates the bitmap on the current CPU immediately, so the
 * caller's next in/out succeeds without waiting for a reschedule; the context
 * switch (set_current_task -> tss_set_io_allowed) keeps it correct afterward, and
 * flips it off for every other task. */
void h_ioport_grant(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    tasks[cur].io_allowed = 1;
    tss_set_io_allowed(1);
    /* Console ownership is NOT taken here: the port grant alone does not make a
     * task the console driver (ioporttest grants ports only to probe that a
     * non-allowlisted port still faults, and reports via the kernel console). The
     * handover happens once the same task also maps the VGA framebuffer — the pair
     * that uniquely identifies console_server. See h_map_phys. */
    r->rax = 0;
}

/* SYS_IRQ_REGISTER(irq, notif_slot, badge): route hardware IRQ `irq` (0 timer /
 * 1 keyboard) to an async notification for the calling task, so a ring-3 driver
 * blocked in SYS_WAIT_NOTIFY wakes to service the device. Cap-gated on
 * CAP_IO_DEVICE + WRITE by the dispatch table -- console/driver server only. Only
 * a task may register for itself; the registration is dropped when the task exits
 * (irq_notify_clear_task from task_teardown). Fail closed on an unroutable IRQ. */
void h_irq_register(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    int irq = (int)r->rbx;
    if (irq_notify_register(irq, cur, (uint32_t)r->rcx, (uint32_t)r->rdx) != 0) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }
    r->rax = 0;
}
