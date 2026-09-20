# Kernel-pointer disclosure: what ring 3 can already learn about the kernel's layout

*Current status of the findings below is authoritative in
[`../LIMITATIONS.md`](../LIMITATIONS.md) §1.16 and §1.17, not here.*

---

**Why this exists.** Roadmap **3.8** keeps KASLR open, and KASLR is worth exactly what the
absence of kernel-pointer disclosure makes it worth: a randomised base that a task can read back
through a syscall is not a mitigation, it is a decoration. So the layout-disclosure surface is a
prerequisite for that work rather than a follow-up to it, and this is the survey of it.

**Scope.** Every path by which a kernel virtual address, a physical address, or the position of
either, reaches a ring-3 task. Not covered: side channels that infer layout by measurement rather
than reading it (cache, TLB and branch-predictor timing), which are the subject of the
side-channel posture in `ARCHITECTURE.md` and are not made worse or better by anything here.

**Method.** Read against the working tree at `57a80e7`. Every `copy_to_user` site under
`src/kernel` was enumerated (79 of them across 13 files) and each structure copied out was checked
field by field for address-valued members. Each syscall's authorisation was read from the dispatch
table in `syscall.c`, never from the handler's comment, because the two are exactly the pair this
survey exists to compare. The two behavioural findings were demonstrated on a boot under QEMU with
a temporary probe, which was removed before this was committed; the probe wrote straight at the
UART through `serial_write_char`, so its output is visible whether or not a ring-3 console owner
holds the console, and it is quoted verbatim below.

---

## 1. Findings

### 1.1 A supervisor-mode fault writes a kernel text address into a ring-3 task's exit record, **[HORUS-20260920-01]**

`page_fault_handler` deliberately does not condition the kill path on `f64->cs & 3`, and says so:
the faulting access can be a supervisor one, the kernel touching a bad user address mid-syscall on
this task's CR3, and blaming only ring-3 faults would leave that case halting the machine. That
decision is right. What rides along with it is that the same path then builds a
`struct task_exit_cause` carrying `f64->rip`, and for a CPL-0 fault that value is **kernel text**.
`task_teardown` copies it into `tasks[id].exit_info` verbatim.

Both readers of that record are ungated. In the dispatch table, `SYS_WAIT` and
`SYS_TASK_EXIT_INFO` are `SC_NONE`, and `h_wait` performs no parentage or capability test: a task
may wait on any tid, and a tid that is already `TASK_DEAD` is answered immediately from the corpse.
So the kernel address reaches ring 3 with no authority at all.

**Measured.** The tree already ships the injector for this exact fault, `KFAULT_INJECT`, which
reproduces the [G-8] signature: a supervisor read of address 0x94 on a timer tick after a ring-3
console server owns the console. Built with the probe and run through `tools/kfault_test.sh`:

```
PAGE FAULT at 0x94 err=0x0(not-present,read,supervisor) task=3 'console_server'
  vec=14 errc=0x0
  rip=0xffffffff80108479 cs=0x8 rflags=0x10046
Rejected by validator - killing task 3
[audit-probe] exit record for tid 3 carries KERNEL rip=0xffffffff80108479 reason=5
```

`0xffffffff80108479` is `interrupt_handler64 + 0x7b9`, resolved with `nm -n kernel.elf` against the
kernel that produced it. Its distance from the kernel's base is fixed at link time, so under KASLR
this single value **is** the slide, handed to an unprivileged reader.

**What it is today, stated honestly.** With the base fixed, the address is already derivable from
`kernel.elf`, so today this discloses nothing an attacker could not look up. It is still the wrong
shape: it is the same class of leak `LIMITATIONS.md` §1.3 closed for `SYS_GET_TASK_INFO`, where
`info.cr3` is zeroed and another task's `eip` is withheld, and it becomes a live slide oracle on
the first day the base moves. It fires precisely when a kernel memory-safety defect is being
exercised, which is the moment KASLR exists to survive.

**The fix, when it lands.** Record `rip` only for a ring-3 frame and 0 otherwise, at the point the
cause is built, matching what `h_task_info` already does for `eip`. The kernel-side RIP is not lost:
it belongs in the `kfault_frame` banner at the UART, which already prints it and is where a
maintainer reads it. The witness is a boot under `KFAULT_INJECT` in which the supervisor fault
still reports at the UART and the exit record reads 0, with the control arm restoring the verbatim
copy.

### 1.2 A reused task slot keeps the previous occupant's wait record, **[HORUS-20260920-02]**

`create_task` resets fifteen fields of a reused slot one by one, and its comment on
`image_premap_pages` states the discipline: set here, not left to slot-reuse staleness. Two fields
are not in that list, `exit_info` and `wait_exit_info`. The task table is carved from untyped
memory, which the allocator zeroes, so a slot is clean on its first use and only its **reuse** is
at issue.

`h_task_exit_info` returns `tasks[cur].wait_exit_info` with no capability and no test that this
task ever waited on anything. The header in `include/syscall.h` promises the opposite: asking
before any wait has completed is documented to yield `TASK_EXIT_NONE` rather than a stale answer.
For a task in a reused slot it yields the previous occupant's record: the tid it supervised, that
task's faulting RIP, the faulting address and its name.

**Measured, and the limit of the measurement.** Under `PROC_SELFTEST` the record is demonstrably
left behind in the freed slot:

```
[audit-probe] dying tid 3 leaves a wait_exit_info in its slot: reason=4 tid=1
              rip=0x000001fea8329000 name=faulter
```

That is `proctest` dying while holding the death record of the `faulter` child it supervised,
including `faulter`'s ASLR'd user RIP. What the measurement does **not** show is a later task
inheriting it. The slot scan in `do_spawn_inner` takes the lowest free slot, so short-lived
programs churn the low slots while the tasks that wait are long-lived: across the whole
`tools/session_test.py` run, which logs in, runs a session and logs out again, `create_task` is
called four times and not one call inherits a non-empty record. Forcing the reuse by reversing the
scan order was tried and rejected as evidence: it perturbs the workload rather than the defect,
and `proctest` fails its own `find-looper` assertion under it.

So this is **latent, not observed**: the missing reset is unconditional and the record provably
survives in the slot, but no measured workload reuses a waiter's slot. Both halves belong in the
record, and the end-to-end read is the witness that should land with the fix, not a claim to make
ahead of it.

**The fix, when it lands.** Clear both fields in `create_task` beside the other fifteen. It also
disposes of a smaller residue in the same structure: `task_teardown` copies the dead task's name
and terminates it, leaving the bytes beyond the terminator as whatever the slot's previous
occupant's record held, and the whole 32-byte field is copied to the waiter.

---

## 2. Posture, which is not a defect but decides what KASLR would be worth

**UMIP is conditional on the CPU, and without it there is no KASLR at all.**
`cpu_enable_protections` sets CR4.UMIP only when `platform.has_umip`, which is correct (the bit
faults on a CPU that does not implement it) and is the right default. The consequence for 3.8 is
structural: on a machine without UMIP, `SIDT` and `SGDT` are legal at CPL 3 and hand any task the
linear addresses of the IDT and GDT, both of which live in the kernel image. No capability, no
defect required, complete defeat. The CPU self-test covers the positive case only, and the harness
boots QEMU with `+umip`, so the tree holds no evidence about the machine that lacks it. KASLR would
force a decision that does not exist today: refuse to boot, boot with the randomisation off and say
so in the banner, or boot with it on and record in `docs/LIMITATIONS.md` that it is cosmetic there.
Fail closed (§1) argues for one of the first two.

Worth recording on the other side: CR4.TSD is set unconditionally, so ring 3 cannot execute
`RDTSC`, which removes the cycle-accurate timer that the prefetch and TLB-timing attacks against
KASLR depend on. That is a real head start, and it is the reason this survey treats reading as the
problem and measuring as out of scope.

**The kernel log is a layout oracle by design.** `h_dmesg`'s own comment says the log discloses
addresses, and it is gated on `CAP_KERNEL_LOG` rather than on uid, which is the right gate for what
it is. Under KASLR every kernel address in that ring becomes the slide, so holding that capability
would become equivalent to knowing it. `SYS_IRQ_POLICY_INFO` is the sharpest case, since it returns
kernel return addresses outright, and it is absent from ship builds. The honest options are to
suppress kernel addresses in the log when the base is randomised, as Linux does with `%pK`, or to
document `CAP_KERNEL_LOG` as slide-equivalent. The second is cheap and true; the first is work that
should not be started without deciding which.

**Physical addresses are a separate question.** `SYS_DMA_ADDR` answers a frame's physical address
and `SYS_DEVICE_INFO` answers MMIO bases and the MSI-X table page. Both are capability-gated, both
are documented as disclosures that add nothing to a caller who already holds a bus-mastering
device, and neither says anything about where the kernel's **virtual** base is. They matter only if
3.8 ever randomises the physical load address as well, and they are the reason that half is a
larger decision than the virtual half.

---

## 3. What was checked and found clean

| Path | Gate | Result |
|---|---|---|
| `SYS_GET_TASK_INFO` | self, or `CAP_USER` / `CAP_AUDIT` | `cr3` forced to 0, another task's `eip` withheld (§1.3, **[I-4]**) |
| `SYS_CAP_ENUMERATE` | `CAP_DEBUG` | `object` deliberately absent from `struct cap_info`; `serial` and `badge` carry the graph |
| Capability `object` values | n/a | table indices since **[F-2.1]**, not pointers; the legacy slot-3 `CAP_FRAME` holds a user address |
| Fault signal delivery | ring 3 only | `try_deliver_fault_signal` refuses a ring-0 frame; passes signum and CR2, nothing else |
| `SYS_BOOT_MODULE_INFO` | `CAP_BOOT_MODULE` | size and name only, no physical extent |
| `SYS_UNTYPED_INFO` | `CAP_UNTYPED` | sizes and counts, no base |
| `SYS_SHLIB_INFO` | `CAP_FRAME` + READ on the library's own text | a user address, randomised per boot (**S51**) |
| `SYS_DMA_ADDR`, `SYS_DEVICE_INFO`, `SYS_FB_INFO` | device capabilities | physical, gated, and reasoned about in place |
| Kernel `print()` under a ring-3 console owner | `CAP_KERNEL_LOG` to read back | goes to the klog, not to the owner; writing the klog needs the capability too (**[H-2]**) |
| Padding and residue in copied structures | n/a | `task_info` and `fb_geometry` are zeroed before filling; the `.rodata` residue in the legacy `SYS_SYSINFO` was fixed |
| `DEBUG_SHELL` and selftest address prints | never shipped (§6) | out of scope by construction |

---

## 4. What this means for roadmap 3.8

1. Fix **[HORUS-20260920-01]** and **[HORUS-20260920-02]**. Both are small, both are the same class
   as a finding already closed, and the first is a slide oracle the day the base moves.
2. Decide the UMIP posture. It is a boot-policy question and it bounds what KASLR can claim, so it
   belongs in `SECURITY.md` before any randomisation lands, not after.
3. Decide what the kernel log says under KASLR, and write the answer down either way.
4. Only then the relocation work itself, where the entropy available under `-mcmodel=kernel` is
   about 9 bits and the cost is a boot-time relocator, a build-time relocation tool and an early
   entropy source, all three inside the TCB.
