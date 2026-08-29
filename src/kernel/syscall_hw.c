/* syscall_hw.c -- the device-delegation syscalls.
 *
 * The security-hardening program's Phase 6 driver-privilege-separation work moved
 * the console (VGA/serial/keyboard) out of ring 0 into a ring-3 server that owns
 * the hardware directly. This file holds the kernel side of "owns the hardware":
 * the narrow, cap-gated syscalls that hand a ring-3 driver controlled access to
 * one device's memory, ports and interrupt.
 *
 * WHAT CHANGED, AND WHY IT IS THE [C-1] FIX AGAIN
 * ----------------------------------------------
 * Each of these syscalls used to be gated by a fixed dispatch-table entry:
 * "CAP_IO_DEVICE with WRITE, in slot 10". The capability's `object` field was
 * never read, and the resources came from constants — a compiled-in VGA
 * allowlist, a compiled-in console port set, and a hardcoded pair of IRQ numbers.
 * Holding the type WAS the authority, and the authority it conferred was the
 * console, all of it, for everyone who held it.
 *
 * That is finding [C-1]'s shape exactly: an object named by an unmediated
 * constant instead of by the capability. So it takes [C-1]'s fix. The first
 * argument of each of these syscalls is now a CSPACE SLOT holding a
 * CAP_IO_DEVICE; the slot is resolved through iodev_from_slot(); and the frame,
 * port range or IRQ the caller asks for is checked against what THAT device
 * declares in the kernel's device table (src/kernel/pci.c). The fixed slot-10
 * dispatch entries are gone — the per-slot lookup IS the gate, and leaving the
 * table entry would have re-admitted the old "any device cap unlocks the console"
 * behaviour underneath the new checks.
 *
 * A driver can now be given the hardware it needs and nothing else, which is the
 * precondition for a second ring-3 driver existing at all (roadmap 2.6, 2.7).
 */
#include "syscall_internal.h"

/* Resolve a device-capability slot to the device it names.
 *
 * Same discipline as ipc_ep_from_slot: type-test the capability, bounds-test the
 * object, and resolve the object to a live kernel-side entry, all at one choke
 * point, so no handler can forget one of the three. A device index that names no
 * present entry fails here rather than in the handler.
 *
 * Note there is no `revoke` interaction to worry about that cap_lookup does not
 * already cover: the table is immutable after boot, so an index that resolves
 * once resolves to the same device forever. What can change is whether the CALLER
 * still holds the capability, and that is exactly what cap_lookup answers. */
static const struct io_device *iodev_from_slot(uint32_t slot, uint32_t need_rights,
                                              uint64_t *out_index) {
#ifdef IO_DEVICE_CAP_UNCHECKED
    /* Control arm: the shape "we removed the dispatch-table entry and the
     * handler does not gate either". The three syscalls lost their fixed slot-10
     * CAP_IO_DEVICE entries when the lookup moved here, so this file IS the gate
     * now; an arm that only ever bypasses the OBJECT check cannot say whether
     * the capability is still required at all. Under this flag every caller
     * resolves to the platform device holding nothing. See
     * `make smoke-captest-devcap-control`. */
    (void)need_rights; (void)slot;
    if (out_index) *out_index = IODEV_PLATFORM;
    return iodev_get(IODEV_PLATFORM);
#else
    struct capability *c = cap_lookup(slot, need_rights);
    if (!c || c->type != CAP_IO_DEVICE) return 0;
    const struct io_device *d = iodev_get(c->object);
    if (!d) return 0;
    if (out_index) *out_index = c->object;
    return d;
#endif
}

/* The user (lower) canonical half: pml4 indices 0..255, i.e. addresses below
 * 2^47. user_pte_slot() independently refuses the kernel half, but rejecting it
 * here gives a clear SYS_ERR_INVAL rather than a generic map failure. */
#define USER_HALF_LIMIT   0x0000800000000000ULL

/* SYS_MAP_PHYS(dev_slot, paddr, vaddr, len, flags): map one 4 KiB frame `paddr`
 * of the device named by `dev_slot` at user address `vaddr` in the caller's own
 * address space. The frame is mapped present + user + non-executable, writable
 * iff MAP_PHYS_WRITE is set.
 *
 * `paddr` is not authority — the capability is. A physical address that the named
 * device does not declare is refused with SYS_ERR_PERM whatever the caller holds,
 * so this cannot be turned into a map-anything primitive (which would hand a
 * driver the kernel's own memory, and the untyped arena with it).
 *
 * Fail closed on every irregularity: a frame the device does not declare
 * (SYS_ERR_PERM -- it is an authority question), a slot that is not a device
 * capability (SYS_ERR_PERM), a misaligned or oversized request, a zero/kernel-half
 * target VA, or a missing access bit (SYS_ERR_INVAL). */
void h_map_phys(struct interrupt_frame64 *r) {
    uint32_t dev_slot = (uint32_t)r->rbx;
    uint64_t paddr    = r->rcx;
    uint64_t vaddr    = r->rdx;
    uint64_t len      = r->rsi;
    uint32_t flags    = (uint32_t)r->rdi;

    const struct io_device *d = iodev_from_slot(dev_slot, CAP_RIGHT_WRITE, 0);
    if (!d) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    /* One frame at a time: a device mapping is a single named frame, never a
     * range the caller can stretch off the declared region. */
    if (len == 0 || len > PAGE_SIZE) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    /* At least READ must be requested; unknown bits are ignored (only WRITE is
     * otherwise meaningful). */
    if (!(flags & (MAP_PHYS_READ | MAP_PHYS_WRITE))) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }

    if (paddr & (PAGE_SIZE - 1)) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
#ifdef IO_DEVICE_OBJECT_UNCHECKED
    /* Control arm: the pre-2026-08-28 behaviour, in which the capability's object
     * was not consulted and every holder of the type reached one compiled-in
     * allowlist. See docs/BUILDING.md and the smoke-devcap-object-control gate. */
    if (!(paddr >= 0xB8000ULL && paddr < 0xBA000ULL) &&
        !(paddr >= 0xA0000ULL && paddr < 0xB0000ULL)) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
#else
    if (!iodev_allows_mmio(d, paddr, len)) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
#endif

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
     * owns BOTH the console ports (a port grant on the platform device, via
     * SYS_IOPORT_GRANT) AND the VGA framebuffer it just mapped — that pair
     * uniquely identifies console_server. Keying off the port grant alone would
     * wrongly silence ioporttest (grants ports to probe faults, never drives the
     * console); off the VGA map alone would wrongly silence mapphystest (maps the
     * frame to verify it, holds no port grant). Both self-tests report via the
     * kernel console, so neither may lose ownership of it. */
    if (rc == 0 && paddr >= 0xB8000ULL && paddr < 0xBA000ULL &&
        cur > 0 && cur < MAX_TASKS && tasks[cur].io_device == IODEV_PLATFORM) {
        console_set_owner(cur);
    }
}

/* SYS_IOPORT_GRANT(dev_slot): grant the calling task native ring-3 in/out on the
 * ports declared by the device named by `dev_slot`, via the TSS I/O bitmap.
 *
 * The grant is to ONE device, recorded per task, and the bitmap is reloaded from
 * that device's ranges on every switch in (set_current_task -> tss_set_io_device),
 * so no task inherits another's ports and no grant spans two devices. Regranting
 * replaces the previous device rather than accumulating: a task holding two device
 * capabilities gets one port set at a time, because the bitmap is per CPU and the
 * union of two devices' ports is an authority neither capability names.
 *
 * The bitmap is also activated on the current CPU immediately, so the caller's
 * next in/out succeeds without waiting for a reschedule. */
void h_ioport_grant(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    uint32_t dev_slot = (uint32_t)r->rbx;
    uint64_t index = IODEV_NONE;
    const struct io_device *d = iodev_from_slot(dev_slot, CAP_RIGHT_WRITE, &index);
    if (!d) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    /* A device that declares no ports is granted nothing, and says so. Returning
     * success would activate an empty bitmap and report a grant that confers
     * nothing, which reads to a driver as "the hardware is yours". */
    if (d->n_port == 0) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

#ifdef IO_DEVICE_PORTS_GLOBAL
    /* Control arm: the pre-2026-08-28 bitmap, which was one boot-time console
     * allowlist shared by every grant regardless of which device was named.
     * See the smoke-devcap-ports-control gate. */
    index = IODEV_PLATFORM;
#endif
    tasks[cur].io_device = index;
    tss_set_io_device(index);
    /* Console ownership is NOT taken here: the port grant alone does not make a
     * task the console driver (ioporttest grants ports only to probe that a
     * non-allowlisted port still faults, and reports via the kernel console). The
     * handover happens once the same task also maps the VGA framebuffer — the pair
     * that uniquely identifies console_server. See h_map_phys. */
    r->rax = 0;
}

/* SYS_IRQ_REGISTER(dev_slot, irq, notif_slot, badge): route hardware IRQ `irq` to
 * an async notification for the calling task, so a ring-3 driver blocked in
 * SYS_WAIT_NOTIFY wakes to service its device.
 *
 * Both ends are capabilities. `dev_slot` must name a device that declares `irq`,
 * so a driver cannot subscribe to another device's interrupt — the line is the
 * device's, not the type's. `notif_slot` must name a notification the caller
 * holds (finding C-2), so the holder cannot aim real interrupts at another task's
 * rendezvous. Only a task may register for itself; the registration is dropped
 * when the task exits (irq_notify_clear_task from task_teardown). */
void h_irq_register(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    uint32_t dev_slot = (uint32_t)r->rbx;
    int irq = (int)r->rcx;

    const struct io_device *d = iodev_from_slot(dev_slot, CAP_RIGHT_WRITE, 0);
    if (!d) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
#ifndef IO_DEVICE_IRQ_UNCHECKED
    /* Control arm IO_DEVICE_IRQ_UNCHECKED: the pre-2026-08-28 handler, which
     * accepted any routable IRQ from any holder of the type. See the
     * smoke-devcap-irq-control gate. */
    if (!iodev_allows_irq(d, irq)) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
#endif

    uint32_t ns;
    if (ipc_notif_from_slot((uint32_t)r->rdx, CAP_RIGHT_WRITE, &ns) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    if (irq_notify_register(irq, cur, ns, (uint32_t)r->rsi) != 0) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }
    r->rax = 0;
}

/* SYS_DEVICE_INFO(dev_slot, struct dev_info *out): report what the device named
 * by the CAP_IO_DEVICE at `dev_slot` declares.
 *
 * READ, not WRITE: learning what your device is is an observation, and a
 * READ-only delegate should be able to discover its resources without being able
 * to map them. The rights split is real here — SYS_MAP_PHYS demands WRITE.
 *
 * Scoped to the named device on purpose. A driver needs its own BARs (firmware
 * assigns them, so a hardcoded address is how a driver ends up mapping whatever
 * happens to sit there), but nothing needs a bus walk, and offering one would
 * make holding any device capability a way to enumerate the whole machine. There
 * is no "list all devices" syscall for the same reason. */
void h_device_info(struct interrupt_frame64 *r) {
    const struct io_device *d = iodev_from_slot((uint32_t)r->rbx, CAP_RIGHT_READ, 0);
    if (!d) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    struct dev_info info;
    for (unsigned i = 0; i < sizeof(info); i++) ((uint8_t *)&info)[i] = 0;
    info.vendor    = d->vendor;
    info.device    = d->device;
    info.bdf       = d->bdf;
    info.classcode = d->classcode;
    info.irq_mask  = d->irq_mask;
    info.n_mmio    = (uint16_t)d->n_mmio;
    info.n_port    = d->n_port;
    /* Whether the device has MSI, never where the capability is: the offset names
     * the register carrying the vector, and that is the kernel's alone (S47). */
    info.msi_capable = d->msi_cap ? 1u : 0u;
    for (uint32_t i = 0; i < d->n_mmio && i < IODEV_MAX_MMIO; i++) {
        info.mmio[i].base = d->mmio[i].base;
        info.mmio[i].len  = d->mmio[i].len;
    }
    for (uint32_t i = 0; i < d->n_port && i < IODEV_MAX_PORT; i++) {
        info.port[i].base = d->port[i].base;
        info.port[i].len  = d->port[i].len;
    }

    if (copy_to_user((void *)(addr_t)r->rcx, &info, sizeof(info)) != 0) {
        r->rax = (uint32_t)SYS_ERR_FAULT; return;
    }
    r->rax = 0;
}

/* SYS_DEVICE_ENABLE(dev_slot, flags): set the three PCI decode bits of the device
 * named by `dev_slot` to exactly `flags` (DEV_ENABLE_IO / _MEM / _BUSMASTER).
 *
 * WRITE, because it changes the device. A driver needs it: firmware leaves a
 * device's decode wherever it liked, and a device that is not a bus master cannot
 * DMA, so without this a ring-3 driver maps a BAR and finds silence.
 *
 * WHAT GRANTING BUS MASTERING MEANS HERE, stated plainly because the capability
 * cannot bound it: this machine has no IOMMU. A bus-mastering device reaches ALL
 * of physical memory, and the descriptors that tell it where to go live in guest
 * memory the driver writes. So the authority this call confers is, in the worst
 * case, the machine — and that is a property of the hardware, not of the
 * capability model. What the capability still does is decide WHO may turn it on
 * and FOR WHICH device, which is the part that is enforceable and the part that
 * an IOMMU would later make complete. SECURITY.md S44; docs/LIMITATIONS.md §2.12.
 *
 * Not a config-space write primitive: the offset is fixed in iodev_set_decode,
 * the value is masked to three bits, and the device is the one the capability
 * named. A driver that could reach the rest of those 256 bytes could move its own
 * BAR onto another device's registers and make every mmio check a lie. */
void h_device_enable(struct interrupt_frame64 *r) {
    const struct io_device *d = iodev_from_slot((uint32_t)r->rbx, CAP_RIGHT_WRITE, 0);
    if (!d) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    uint32_t flags = (uint32_t)r->rcx;
    if (flags & ~(uint32_t)(IODEV_DECODE_IO | IODEV_DECODE_MEM | IODEV_DECODE_BUSMASTER)) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }
    /* A platform device has no configuration space. Refusing is not pedantry:
     * reporting success for a decode that was never set would have a driver wait
     * on hardware that is not listening, and blame its own ring buffers. */
    if (iodev_set_decode(d, flags) != 0) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    r->rax = 0;
}

/* SYS_DMA_ADDR(dev_slot, frame_slot, uint64_t *out): the bus address at which the
 * device named by `dev_slot` reaches the frame named by `frame_slot`.
 *
 * WHY IT TAKES A DEVICE CAPABILITY IT NEVER TOUCHES. The answer is a physical
 * address, and handing physical addresses to ring 3 is a disclosure: it is the
 * kernel's memory layout, and nothing else in this ABI reports one. Gating it on
 * the frame capability alone would hand that layout to every task that ever
 * retyped a page, for no purpose any of them could act on.
 *
 * Requiring the device capability makes the disclosure add NOTHING to what the
 * caller can already do. A holder of a bus-mastering device capability can
 * already read and write all of physical memory through its device, IOMMU-less;
 * telling it where its own frame sits is beneath the authority it holds. That is
 * the whole security argument for this call, and it is why the two capabilities
 * are required together rather than either alone.
 *
 * The name is `dma_addr` and not `paddr` deliberately. What a device needs is the
 * address IT uses, which is the physical address only because there is no IOMMU;
 * with one it becomes an IOVA established by a mapping call, and this signature
 * — device, frame, out — is already the right shape for that day.
 *
 * The kernel cannot police the DIRECTION. READ on the frame is what is required,
 * because a transmit buffer the device only reads is legitimate and demanding
 * WRITE would refuse it; but nothing here can stop the driver writing this
 * address into a receive descriptor. The rights bound who may ask, not what the
 * device does with the answer.
 *
 * LIFETIME, and why it is safe today by construction rather than by care. A frame
 * whose capability is revoked while the device is still writing into it would be
 * a use-after-free performed by hardware, with no software on the path to catch
 * it. It cannot happen in this tree: the untyped allocator is a monotonic bump
 * pointer with no region reset, so a destroyed frame's BYTES are never handed to
 * another object (src/kernel/untyped.c, "ALLOCATION DISCIPLINE"). The day a
 * region reset lands, it must account for outstanding DMA before it rewinds a
 * watermark -- that comment already says so for the refcount pins, and this is a
 * second reason.
 *
 * WHAT IT DOES WHEN THERE IS AN IOMMU, which is the point of the call now. It
 * MAPS the frame into the named device's address space and then reports the
 * address. Before VT-d it only reported, because the device could already reach
 * everything and the answer was the whole of the authority. Now the answer is
 * the SMALLER half: the mapping is what grants the reach, and a device whose
 * driver never called this reaches nothing at all. The IOVA equals the physical
 * address, which is a choice rather than an identity map -- see iommu_map.
 *
 * `writable` comes from the capability's own rights, not from an argument. A
 * driver holding a READ-only CAP_FRAME gets a READ-only device mapping, so a
 * compromised device cannot scribble on a page its driver may only read. That is
 * the rights floor of S27 extended to the device, and it is why this call takes
 * the frame capability rather than a physical address. */
void h_dma_addr(struct interrupt_frame64 *r) {
    /* The device index this call is about. Resolved once, here, and used both to
     * gate the call and to name the address space the mapping goes into -- one
     * lookup, so the gate and the effect cannot disagree about which device. */
    uint64_t devidx = IODEV_NONE;
#ifndef DMA_ADDR_FRAME_ONLY
    /* Control arm DMA_ADDR_FRAME_ONLY: gate on the frame alone, the shape this
     * call would take if the device capability were treated as documentation
     * rather than as a requirement. Under it any task that ever retyped a page
     * learns the kernel's physical layout. See make smoke-frame-dma-control. */
    if (!iodev_from_slot((uint32_t)r->rbx, CAP_RIGHT_WRITE, &devidx)) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
#endif

    struct capability *c = cap_lookup((uint32_t)r->rcx, CAP_RIGHT_READ);
    if (!c || c->type != CAP_FRAME) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    /* The same resolver SYS_MAP_FRAME uses, and for the same reason: a
     * CAP_FRAME's object is an INDEX into the frame table, never an address
     * (finding F-2.1). A dead index answers 0 and is refused here, so a stale
     * capability cannot name a bus address. */
    uint64_t phys  = frame_phys_by_index((uint32_t)c->object);
    uint32_t pages = frame_pages_by_index((uint32_t)c->object);
    if (phys == 0 || pages == 0) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    /* The device mapping carries the capability's own write right and no more. */
    int writable = (c->rights & CAP_RIGHT_WRITE) ? 1 : 0;

    /* DMA_ADDR_NO_MAP reports the address without installing the mapping -- what
     * this call did before VT-d existed. Under an IOMMU that hands a driver an
     * address its device cannot reach, and the fact that everything then BREAKS
     * is the evidence that a device's address space really does start empty.
     * It is the NET_IOMMU_NO_MAP arm's mechanism (make smoke-net-iommu-control).
     *
     * A flag rather than a kernel #ifdef on purpose: an ifdef around the map call
     * would also compile out the capability checks above it, and the arm would
     * then be demonstrating something weaker than the mapping's necessity. */
    uint32_t dma_flags = (uint32_t)r->rsi;
    if (dma_flags & ~(uint32_t)DMA_ADDR_NO_MAP) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }
    if (iommu_active() && !(dma_flags & DMA_ADDR_NO_MAP)) {
        const struct io_device *md = iodev_get(devidx);
        if (!md) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
        if (iommu_map(devidx, md->bdf, phys, pages, writable) != 0) {
            r->rax = (uint32_t)SYS_ERR_FAULT; return;
        }
    }

    if (copy_to_user((void *)(addr_t)r->rdx, &phys, sizeof(phys)) != 0) {
        r->rax = (uint32_t)SYS_ERR_FAULT; return;
    }
    r->rax = 0;
}

/* SYS_IRQ_ACK(dev_slot, irq): the driver has serviced its device; unmask the line.
 *
 * WHY THIS EXISTS AT ALL. A registered line is masked by the kernel the moment it
 * fires (see the dispatcher in idt.c) and stays masked until this call. That is
 * what stops an unserviced level-triggered device from livelocking the machine --
 * without it, the PIC re-delivers forever, ring 3 never runs, and the driver that
 * would clear the line never gets the chance.
 *
 * WHY IT IS CAPABILITY-GATED. Unmasking is authority: it decides that a device
 * may interrupt this machine again. Gated exactly as SYS_IRQ_REGISTER is -- the
 * caller must hold a CAP_IO_DEVICE whose device DECLARES this line -- so a task
 * cannot re-enable an interrupt for hardware it does not hold. An ungated version
 * would let any task unmask any line, which is both a way to resurrect a storm
 * somebody else's dead driver left behind and a way to interfere with a driver
 * that is deliberately keeping its device quiet.
 *
 * AND ONLY THE REGISTRATION'S OWNER. Holding the right device capability is not
 * sufficient: irq_notify_ack refuses unless the line is registered to the CALLING
 * task. Two tasks holding copies of one device capability are otherwise able to
 * acknowledge each other's interrupts, which would let one of them unmask a line
 * the other is mid-service on. */
void h_irq_ack(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    int irq = (int)r->rcx;
#ifndef IRQ_ACK_UNGATED
    /* Control arm IRQ_ACK_UNGATED: drop the authority check, so any task unmasks
     * any line. See make smoke-irq-ack-control. */
    const struct io_device *d = iodev_from_slot((uint32_t)r->rbx, CAP_RIGHT_WRITE, 0);
    if (!d) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
    if (!iodev_allows_irq(d, irq)) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
#endif

    if (irq_notify_ack(irq, cur) != 0) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    r->rax = 0;
}

/* SYS_MSI_REGISTER(dev_slot, notif_slot, badge): route the named device's
 * message-signalled interrupt to a notification the caller holds.
 *
 * NOTE WHAT IS NOT AN ARGUMENT: a vector. That absence IS the property (S47).
 *
 * An MSI is a memory write whose data word carries the interrupt vector, so with
 * MSI the question "which interrupt does this device raise" stops being a fact
 * about the board and becomes a value in a register. A driver that could set it
 * could point its device at the timer's vector, another driver's, or an exception
 * gate -- #GP is vector 13, and a device raising 13 at will could make any task
 * appear to fault anywhere. The kernel therefore allocates the vector from a
 * range it owns and programs the capability itself, and the ABI gives ring 3
 * nowhere to express a preference.
 *
 * This is only enforceable because configuration space is unreachable from ring 3
 * (S43) and SYS_DEVICE_ENABLE reaches exactly three decode bits (S44). MSI is
 * what makes that strictness load-bearing rather than tidy.
 *
 * Both capabilities are required and both are the caller's: a CAP_IO_DEVICE
 * naming the device, and a CAP_NOTIFICATION to be woken on. The second is
 * finding C-2's rule -- routing a real interrupt at a rendezvous the caller does
 * not hold would let one task aim hardware at another's wakeups. There is no
 * `irq` to validate against the device's declared lines, because an MSI is not a
 * line; what replaces that check is the device capability itself, since only a
 * device the caller names can be programmed at all.
 *
 * No masking and no ack, unlike S46's INTx path: an MSI is a message, edge by
 * construction, so there is no asserted line to re-deliver and no livelock to
 * prevent. See src/kernel/msi.c. */
void h_msi_register(struct interrupt_frame64 *r) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    uint64_t devindex = IODEV_NONE;
    const struct io_device *d =
        iodev_from_slot((uint32_t)r->rbx, CAP_RIGHT_WRITE, &devindex);
    if (!d) { r->rax = (uint32_t)SYS_ERR_PERM; return; }

    /* A device with no MSI capability is refused rather than silently falling
     * back to its INTx line: a driver that asked for MSI and got a wire would be
     * waiting on a notification wired differently from the one it programmed for,
     * and would blame its own ring buffers. */
    if (!d->msi_cap) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    uint32_t ns;
    if (ipc_notif_from_slot((uint32_t)r->rcx, CAP_RIGHT_WRITE, &ns) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }

    int vector = msi_register(d, devindex, cur, ns, (uint32_t)r->rdx);
    if (vector == 0) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

#ifdef MSI_VECTOR_FROM_USER
    /* Control arm: honour a vector the CALLER asked for, in rsi -- the shape this
     * syscall takes the moment anyone decides a driver "knows best" which vector
     * it wants. netd then asks for 13 and every task on the machine starts
     * taking general-protection faults it never caused.
     * See make smoke-net-msi-vector-control. */
    if ((uint32_t)r->rsi != 0) {
        iodev_program_msi(d, (uint8_t)r->rsi);
    }
#endif

    /* The vector is NOT reported back. A driver has no use for it -- it waits on
     * the notification -- and telling it would be handing out the kernel's
     * interrupt-space layout for nothing. */
    r->rax = 0;
}
