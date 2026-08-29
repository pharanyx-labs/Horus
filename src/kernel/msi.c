/* msi.c -- message-signalled interrupts, and who gets to choose a vector.
 *
 * THE PROPERTY THIS FILE EXISTS FOR
 * ---------------------------------
 * An MSI is not a wire. It is a memory WRITE the device performs -- to an address
 * the LAPIC decodes, carrying a data word whose low byte is the interrupt VECTOR.
 * So with MSI, "which interrupt does this device raise" stops being a property of
 * the board and becomes a value in a register.
 *
 * That is a much sharper question than INTx ever posed. A device wired to INTx
 * can only assert the line firmware gave it; the worst a malicious driver could
 * do was subscribe to a line its device does not own, which S43 already refuses.
 * A device with MSI raises whatever vector its capability registers say -- the
 * timer's, another driver's, or an exception gate. #GP's vector is 13, and a
 * device that could raise 13 at will could make any task appear to fault
 * anywhere.
 *
 * SO THE KERNEL CHOOSES THE VECTOR, AND THE DRIVER NEVER NAMES ONE. SYS_MSI_REGISTER
 * takes a device capability and a notification capability and nothing else: no
 * vector, no address, no data. The kernel allocates a vector from a range it
 * owns, programs the device's capability registers itself, and records where the
 * resulting interrupt should be delivered. A driver cannot ask for a particular
 * vector because the ABI gives it nowhere to say one.
 *
 * That is only enforceable because configuration space is unreachable from ring 3
 * (S43) and SYS_DEVICE_ENABLE reaches exactly three decode bits and nothing else
 * (S44). MSI is the reason those were worth being strict about: without them a
 * driver could simply write its own message data and this file would be advice.
 *
 * WHY THE RANGE IS 48..63
 * -----------------------
 * Disjoint from the legacy 32..47 block, so an allocated vector can never collide
 * with an I/O APIC pin, and it stops at 63 because vector 64 (0x40) is the LAPIC
 * timer, so it cannot collide with that either. Every
 * vector in it has an IDT gate installed at boot, for the reason LIMITATIONS 2.13
 * records: a vector with no gate raises #GP against whatever was interrupted, so
 * the first message would kill an innocent task at a random instruction.
 *
 * NO MASKING, AND WHY THAT IS NOT S46 BEING ABANDONED
 * ---------------------------------------------------
 * S46 masks a fired line until its driver acknowledges, because a LEVEL-triggered
 * INTx line stays asserted and would re-deliver forever. An MSI is a message: one
 * write, one interrupt, edge by construction. There is no line to stay asserted
 * and so no livelock to prevent -- a device that sends messages faster than they
 * are serviced is a throughput problem, not a wedged machine. The masking
 * machinery is therefore deliberately not applied here, and SYS_IRQ_ACK is not
 * needed for an MSI-registered device.
 */
#include "kernel.h"


struct msi_route {
    uint32_t in_use;
    uint64_t devindex;
    int      task;
    uint32_t notif;      /* resolved notification index, not a cspace slot */
    uint32_t badge;
};

static struct msi_route msi_routes[MSI_VECTOR_COUNT];

extern int sys_notify(uint32_t notif_slot, uint32_t badge);

/* Allocate a vector, or 0 if the range is exhausted.
 *
 * Linear and small on purpose: MSI_VECTOR_COUNT is 16, one per delegatable
 * device, and a machine that runs out has more devices than the io-device table
 * holds. Failing closed here means SYS_MSI_REGISTER refuses rather than reusing a
 * vector two devices would then share -- and a shared vector is two drivers each
 * being told about the other's interrupts, which is S43's confusion arriving one
 * layer further in. */
static int msi_alloc_vector(void) {
    for (uint32_t i = 0; i < MSI_VECTOR_COUNT; i++)
        if (!msi_routes[i].in_use) return (int)(MSI_VECTOR_BASE + i);
    return 0;
}

/* Programming the capability lives in pci.c, with every other configuration-space
 * access. Keeping it there is the architectural point rather than tidiness: this
 * file decides WHICH vector, and exactly one file in the kernel is able to write
 * the register that carries it. Exporting a general config-space write so that
 * this file could do it itself would hand any future caller the ability to
 * reprogram a BAR (S43) or a device's message data (S47). */
extern int iodev_program_msi(const struct io_device *d, uint8_t vector);

/* Route `d`'s MSI to (`task`, `notif`, `badge`). Returns the vector, or 0.
 *
 * The caller (h_msi_register) has already established that the task holds a
 * CAP_IO_DEVICE naming this device and a CAP_NOTIFICATION it may be woken on.
 * Everything about WHICH vector is decided here, where ring 3 cannot reach. */
int msi_register(const struct io_device *d, uint64_t devindex, int task,
                 uint32_t notif, uint32_t badge) {
    if (!d || !d->msi_cap || d->bdf == IODEV_BDF_NONE) return 0;

    /* One route per device. Re-registering replaces it rather than allocating a
     * second vector, so a driver cannot exhaust the range by asking repeatedly. */
    for (uint32_t i = 0; i < MSI_VECTOR_COUNT; i++)
        if (msi_routes[i].in_use && msi_routes[i].devindex == devindex) {
            msi_routes[i].task  = task;
            msi_routes[i].notif = notif;
            msi_routes[i].badge = badge;
            if (iodev_program_msi(d, (uint8_t)(MSI_VECTOR_BASE + i)) != 0) return 0;
            return (int)(MSI_VECTOR_BASE + i);
        }

    int vector = msi_alloc_vector();
    if (!vector) return 0;

    uint32_t idx = (uint32_t)vector - MSI_VECTOR_BASE;
    msi_routes[idx].devindex = devindex;
    msi_routes[idx].task     = task;
    msi_routes[idx].notif    = notif;
    msi_routes[idx].badge    = badge;
    /* in_use last: the dispatcher reads this table from an interrupt, and a
     * half-filled entry marked live is a notification aimed at task 0. */
    __asm__ volatile ("" ::: "memory");
    msi_routes[idx].in_use   = 1;

    if (iodev_program_msi(d, (uint8_t)vector) != 0) { msi_routes[idx].in_use = 0; return 0; }
    return vector;
}

/* Drop any MSI routes owned by `task`, called from task_teardown.
 *
 * The device is left ENABLED and its vector allocated. That looks like a leak and
 * is the safe direction: disabling a capability means writing configuration space
 * of a device that may be mid-transaction, and freeing the vector means the next
 * device to be allocated it inherits any message already in flight from this one.
 * A message arriving for a route that is no longer in use is dropped by the
 * dispatcher, which is the fail-closed outcome; reclaiming properly needs a
 * quiesce step this tree does not have. Recorded in docs/LIMITATIONS.md. */
void msi_clear_task(int task) {
    for (uint32_t i = 0; i < MSI_VECTOR_COUNT; i++)
        if (msi_routes[i].in_use && msi_routes[i].task == task)
            msi_routes[i].task = -1;
}

/* Deliver an MSI. Called from the interrupt dispatcher for vectors in the range.
 * Returns 1 if the vector was ours. */
int msi_dispatch(uint64_t vector) {
    if (vector < MSI_VECTOR_BASE || vector >= MSI_VECTOR_BASE + MSI_VECTOR_COUNT)
        return 0;
    uint32_t idx = (uint32_t)vector - MSI_VECTOR_BASE;
    if (!msi_routes[idx].in_use || msi_routes[idx].task < 0) return 1;  /* ours, dropped */
    sys_notify(msi_routes[idx].notif, msi_routes[idx].badge);
    return 1;
}
