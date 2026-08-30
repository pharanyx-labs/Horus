# G-10: the spawn/exec path was process-wide singleton state, unserialised

*Extracted from [`../../TESTS.md`](../../TESTS.md), where it was one section of a test
catalogue. The narrative is kept in full: in this project the reasoning is the evidence, and
the record of which hypotheses were wrong is the part worth reusing.*

*Current status is authoritative in [`../LIMITATIONS.md`](../LIMITATIONS.md); the gates that
witness it are listed in [`../../TESTS.md`](../../TESTS.md).*

---

**Found 2026-08-17 while narrowing [G-9]; closed 2026-08-18.** The section below is kept in the
order it happened (the lead, then the page-table half, then the rest) because how the finding
was narrowed is the part worth reusing.

**Found 2026-08-17 while narrowing [G-9]. No witness yet: this is a lead with a mechanism.**

Everything `SYS_SPAWN` / `SYS_EXEC_NAMED` needs in flight is a file-scope singleton: the one ELF
staging buffer `loader_staging` (`kernel.h:99`), the staged argv (`g_args_*`, `kspawn.c:9-12`),
`g_spawn_stdio_spec` and `g_spawn_caller` (`kspawn.c:21-22`): and nothing serialises two CPUs
through any of it. There is no lock in `loader.c` and none around `do_spawn`.
`g_exec_reenter_task` was one instance of the pattern and is now per-CPU; the rest are not.

The evidence is the [G-9] residue: 6 boots in 30 take a CPL-0 `vec=14 errc=0x2` (a supervisor
*write* to a non-present page) at `lapic_eoi` and `interrupt_handler64`. A CPU taking an
interrupt on a CR3 that does not map the LAPIC is an address space that became reachable before
`create_user_pagedir` populated its kernel half.

The authority half matters more than the correctness half: `g_spawn_caller` is written at
`do_spawn` entry and read much later by `wire_child_stdio`, so a child can have its stdio wired
from **the wrong parent's cspace**. That is capability inheritance from a task that never spawned
it, which is why this is filed rather than left as a TODO.

#### The page-table half, fixed and falsified the same day

The "no test yet" note above lasted about an hour. The probe that settled it was cheap and did
not presuppose a path: record the CR3 each CPU has loaded (`percpu_cr3[]`, written by
`switch_cr3`) and ask, at the moment of reclaim, whether anyone else still holds the tree being
freed. **19 boots in 20.**

```
CR3UAF: freeing the address space of slot 1 while cpu 3 still has it loaded
        (cr3=0x2c1f000, that cpu is running task 0 '')
```

`create_user_pagedir()` reclaims a slot's previous occupant, and justified the free with

> *"the caller is on the kernel CR3, so the tree about to be freed is not the one any CPU is
> walking"*

; which establishes only that *this* core has left it. A CPU parked in `kernel_idle()` never
reloads CR3, and `SYS_KILL` marks a task dead while it is still running in ring 3 on another
core, while the slot allocator asks only for `state == 0`. So the frames went back to the pool
and were handed out as ordinary pages under a live core: a cross-address-space read/write
primitive, surfacing as a supervisor write fault at `0xFEE000B0` (the LAPIC EOI register, which
lives in each task's own `pml4[0]` map).

**Fix:** refuse to free a tree another CPU has loaded, and park it in a small fixed table
(`pending_aspace[]`) for retry on the next rebuild rather than leaking it. Fail closed both
ways; the overflow leaks rather than freeing in use.

| Arm | Boots | `0xFEE000B0` fault | free-in-use |
|---|---|---|---|
| guarded, ship config | 30 | **0** |, |
| ship config, before the fix | 30 | 6 |, |
| `CR3_RECLAIM_UNGUARDED=1` | 20 |, | **20** |

Gates: `make smoke-cr3-reclaim` (fault **absent**) and `make smoke-cr3-reclaim-control`
(free-in-use **present**). Different markers on the two arms, deliberately: the free-in-use
happens every boot while the fault it causes lands on ~20%, so gating the control on the fault
would be flaky for nothing.

**Effect on [G-9]:** the `PROC_SELFTEST` workload went from ~45% of boots failing to **2 in 30**
on the ship config, and `make smoke-kstack-park` passes in its exact form. Still not zero, so
that gate stays advisory.

#### The rest of it, 2026-08-18: one half deleted, one half serialised

**The authority half is gone rather than guarded.** `g_spawn_caller` and `g_spawn_stdio_spec`
are parameters now: `do_spawn_stdio(spec)` → `do_spawn_inner(caller, spec)` →
`wire_child_stdio(child, caller, spec)`. There is no window left in which a second CPU can
redirect the read, so "the child inherited a pipe capability from a task that never spawned it"
is unexpressible rather than unlikely. No control arm is offered for this, deliberately: the
defect was the *existence* of the global, and a flag that put it back would be re-introducing
the state rather than exercising a check. What is checked instead is the stronger property that
replaced it; the parent whose cspace is read is the task that armed the image being loaded,
which is [G-11]'s ownership check, and that has a control arm.

**The staging window is serialised.** `spawn_stage_acquire()` / `spawn_stage_release()` bracket
every arm → consume region: `h_spawn`, `h_spawn_image`, `h_exec_named`, `h_exec_image`, both
`kshell.c` launchers, `h_sudo`'s consume, and all ten self-test sites that stage by hand.

**And the measurement says the race is not reachable in any workload this tree can boot.** That
is stated rather than glossed, because a serialised build with zero incidents proves nothing
unless the window was entered twice at all. `SPAWN_STAGE_TRACE=1` reports every entry to the
staging window and every arrival that finds another CPU inside one; `SPAWN_STAGE_WIDEN=1` holds
each of the first 24 windows open for 12M `pause` iterations (verified in the emitted code, not
assumed from the source) to make an overlap likely if one is possible:

| Arm | Boots | Completed | Windows entered | Contended arrivals | Thefts |
|---|---|---|---|---|---|
| serialised, `SPAWN_STAGE_WIDEN=1 SPAWN_STAGE_TRACE=1` | 8 | 8 | 112 | **0** | 0 |
| `+ SPAWN_STAGE_UNSERIALISED=1` (control) | 8 | 7 | 102 | **0** | 0 |

The trace is what explained it. The 14 windows per boot come from three tasks (the in-kernel
driver as task 0, `init`, and the proctest driver) on three different CPUs, and they never
overlap because **every spawner in the tree today is `init` or one of `init`'s children**:
`init` spawns its servers sequentially, and the driver that spawns everything else is itself one
of those children, so it cannot be running while `init` is mid-spawn.

**So no smoke target claims a rate for this, and none is added.** A probabilistic pair whose
control arm cannot fail is a test that cannot fail. `SPAWN_STAGE_UNSERIALISED=1` stays in the
Makefile so the arm exists the moment a workload with two live spawners does. What is gated is
the deterministic property that makes a residual interleaving safe rather than exploitable:
`make smoke-spawn-owner`, below.

---
