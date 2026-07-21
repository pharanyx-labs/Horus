# RFC: Console driver privilege separation (ring-3 `console_server`)

**Status:** implemented · **Phase:** 6 (Security hardening) → C · **Realises:** the
former roadmap item *"Reduce driver blast radius (privilege separation)"*
(`docs/ROADMAP.md`).

This document began as the design proposal the roadmap asks for before any patch,
and now records the design as built. It describes moving the console (VGA text /
serial) out of the ring-0 kernel into a ring-3 server process that owns the console
hardware directly: the problem, the three new kernel mechanisms the move requires,
the capability model, the server and client design, the boot-ordering and panic
consequences, and how each step is verified. Where this document and the code
disagree, the code is the source of truth — open an issue.

**Implementation status.** The program landed as the commit-per-job plan in §9,
each job behavior-verified with a gated smoke test:

| Job | What landed | Gate |
|-----|-------------|------|
| J2 | `SYS_MAP_PHYS` — map an allowlisted device frame into a task's address space | `smoke-mapphys` |
| J3 | Per-task TSS I/O-permission bitmap — native ring-3 port I/O | `smoke-ioport` |
| J4 | IRQ→notification bridge (`SYS_IRQ_REGISTER`) | `smoke-irq` |
| J5a | `console_server` owns the hardware, serves a client over IPC | `smoke-console` |
| J5b | The real shell's **output** routed through the ring-3 console | `smoke-session`, `smoke-modules` |
| J5c | Console **input** (line editing, echo, password masking) moved to ring 3 | `smoke-session` |
| J6 | Blast-radius proof — a console fault is contained in ring 3 | `smoke-console-isolation` |

Two items in this document remain deliberately unbuilt: keyboard (PS/2) input stays
in the kernel for now (the tests and headless deployment drive serial), and the
in-kernel console is retained as a robustness fallback and for coreutils output,
boot, and panic — see the notes inline.

---

## 1. Problem

`docs/LIMITATIONS.md` states the core weakness plainly: Horus is **one flat trust
domain**. Every driver runs in ring 0, so *"a bug in the terminal driver has the
same blast radius as one in the capability system,"* and a full kernel compromise
also defeats the audit log and the user-DB tag.

The Phase 6 hardening program has, until now, attacked only one axis — the
*likelihood* of a memory-safety bug in the riskiest code (the ELF loader parse
moved to memory-safe Rust, coverage-guided fuzzing over the FFI predicates, Kani
proofs on the capability engine and the ELF validators). None of that reduces the
*consequence* of a bug: a flaw anywhere in ring 0 still has kernel-wide reach.
Privilege separation is the missing axis, and the console is the place to start:

- **It is the most attacker-facing driver.** It parses PS/2 scancodes
  (`ps2_translate`, `src/kernel/idt.c`), edits input lines and echoes them
  (`h_get_line`, `src/kernel/syscall.c`), and handles password entry with masked
  echo (`h_get_pass`, `src/kernel/syscall.c`) — all untrusted-input handling, all
  in ring-0 C.
- **Its current design forces a boot-ordering hack.** `console_getc()`
  (`src/kernel/terminal.c`) is an **unpreemptible ring-0 spin**: it must not
  cooperatively yield, because input arrives by hardware IRQ and a cooperative
  switch would run on the peer's CR3 and `copy_to_user` the byte into the wrong
  address space (reasoning in-comment at `terminal.c`). As a direct consequence,
  `init` must block on a notification until `fs_server` signals provisioning is
  done before it launches the shell (`docs/ARCHITECTURE.md`), because a blocking
  console read starves everything else on that CPU. Moving the reader to ring 3
  over IPC removes the constraint that created the hack.

The microkernel-native answer is the move the filesystem already made: run the
driver as a ring-3 server holding only its own capabilities, reached over IPC, so
a driver bug is no longer automatically a capability-system compromise.

---

## 2. Design decision: full hardware delegation

Two shapes were considered.

- **Thin kernel primitives.** Keep tiny cap-gated pokes in the kernel (write a VGA
  cell, emit a serial byte, drain a scancode) and move only the *logic* to ring 3.
  Smallest and safest, but leaves `in`/`out` in the kernel.
- **Full hardware delegation (chosen).** The server owns the hardware: the VGA
  framebuffer is mapped into its address space, it runs `in`/`out` natively via a
  per-task TSS I/O-permission bitmap, and IRQ1 is routed to it as a notification.
  The kernel keeps *near-zero* console code — only a minimal serial writer for
  panic and early boot. This is the truest microkernel form and the strongest
  blast-radius reduction, at the cost of three new kernel mechanisms.

Full delegation is the design of record. The tradeoff: native port I/O costs a
one-time bitmap setup and a larger, TSS-surgery change, but no per-access syscall
and no residual device logic in ring 0.

### Architecture

```
  ring-3  ┌─────────────── console_server ───────────────┐
          │  output: VGA cells, cursor, scroll, ANSI/SGR, │
          │          8x8 font, mode init                  │
          │  input:  ps2_translate, line edit, echo,      │
          │          password masking                     │
          │  ── in/out (native) ──▶ 0x3F8/0x60/0x64/0x3Cx │  (TSS io-bitmap)
          │  ── writes ──────────▶ 0xB8000 mapped in AS   │  (map-phys-to-user)
          │  ◀── SYS_WAIT_NOTIFY(kbd badge) ── IRQ1        │  (IRQ→notify bridge)
          │  ◀── IPC requests ─── shell / ring-3 tasks     │  (fs_server-shaped)
          └───────────────────────────────────────────────┘
  kernel  minimal serial putbyte for panic / early boot only
```

---

## 3. New kernel mechanisms

The event-delivery half already exists: `sys_notify` / `sys_wait_notify`
(`src/kernel/syscall_ipc.c`) wake a `TASK_BLOCKED_NOTIF` task by patching its saved
trap frame under `ipc_lock` — no cross-address-space copy — and a task waits on it
via `SYS_WAIT_NOTIFY`. Fault→signal delivery to ring 3 also exists
(`try_deliver_fault_signal`, `src/kernel/idt.c`). Three mechanisms are missing, all
on the hardware-access side. Each is independently testable before the server
depends on it.

### 3.1 Map a physical frame into a user address space

- **New syscall** `SYS_MAP_PHYS(paddr, vaddr, len, flags)`, cap-gated, validating
  the request against a **fixed device-frame allowlist** — the VGA text buffer
  `0xB8000` and the `0xA0000` font plane used by mode init — and mapping it
  `PAGE_USER` into the caller's address space.
- **Reuse:** wraps the existing static `user_map_page()` (`src/kernel/paging.c`);
  the PTE walk/alloc (`user_pte_slot`, which already refuses the kernel half) and
  the TLB-shootdown IPI (vector `0xFB`) are already there. The only new surface is
  the guarded, allowlisted entry point.
- **Guardrails:** allowlist is a compile-time table (no arbitrary physical
  address); `vaddr` must lie in the user half and not collide with the image or
  stack window; fail closed on any mismatch.

### 3.2 Per-task TSS I/O-permission bitmap (native `in`/`out`)

Today the TSS is a bare `TSS64_SIZE = 104` with **no I/O bitmap** and `iomap_base`
unset (`src/kernel/gdt.c`), so any ring-3 `in`/`out` faults `#GP` — port I/O from
ring 3 is impossible. This is the highest-risk mechanism because it touches boot
assembly and the context-switch hot path.

- Grow the TSS to `104 + 8192 + 1` bytes (a 8 KiB bitmap covering all 65536 ports
  plus the mandatory terminating `0xFF`) and set `iomap_base = 104`. Touch the boot
  `tss64` in `src/boot/multiboot.S`, `encode_tss_desc()`'s limit and `setup_ap_tss`
  (`src/kernel/gdt.c`). IOPL stays 0 throughout.
- **Allowlist by clearing bits:** only the console ports are cleared (allowed) —
  serial `0x3F8-0x3FF`, keyboard `0x60`/`0x64`, VGA CRTC/sequencer/graphics
  `0x3C0-0x3DF` and `0x3B4-0x3DA`; every other bit stays set (denied).
- **Per-task swap:** the active bitmap must reflect the running task. Extend the
  existing RSP0-update path `set_tss_kernel_stack()` (`src/kernel/gdt.c`, already
  called on every switch) to also select the running task's bitmap — the populated
  console bitmap for the driver, the all-denied default for everyone else — driven
  by a TCB flag (or bitmap pointer). No other task ever sees a cleared bit.

### 3.3 Route IRQ1 (keyboard) to a userspace notification

- **New syscall** `SYS_IRQ_REGISTER(irq, notif_slot, badge)`, cap-gated, recording
  `(task, slot, badge)` for an IRQ line.
- **Bridge:** the vector-33 handler (`src/kernel/idt.c`), instead of translating and
  buffering the scancode itself, EOIs the PIC and calls the `sys_notify` wake path
  for the registered driver. The driver then reads the scancode itself via native
  `inb(0x60)` (§3.2). The PS/2 output buffer stays full until `0x60` is read, which
  naturally gates the next IRQ, so no scancode is lost and no spurious IRQ races.
- **Serial input** is polled today (COM1 has no IRQ). The driver polls `0x3FD`/`0x3F8`
  natively; a timer-driven wake (routing the PIT tick, or a periodic notification)
  lets it re-poll each ~10 ms tick — the same latency the current polled path has.
- **Interrupt-context safety** must be confirmed: `sys_notify` only patches a saved
  frame and sets state under `ipc_lock`, with no reschedule, so it is safe in shape
  to call from the IRQ handler — to be validated under `SMP=1`.

---

## 4. Capability model

`CAP_CONSOLE` (type 8) already exists, but it is a **software privilege token** — it
gates kernel-shell operations (`ps` full view, `kill`, `dmesg`, poweroff,
`rotate_keys`; `src/kernel/kshell.c`), not hardware. It is not reused here.

Add a **hardware device capability** — e.g. `CAP_IO_DEVICE` — carrying which of
{port-range, mmio-frame, irq-line} it authorizes, following the cap-type enum in
`src/include/kernel.h` and the root-cnode template in `src/kernel/capability.c`.
The three new syscalls (§3) are gated on it in the `src/kernel/syscall.c` dispatch
table exactly as `CAP_BLOCK_DEV` gates the object-store syscalls today. Only
`console_server` is ever endowed with it — by `init`, via `cap_install_from_root`,
the same way `fs_server` is handed the object-store cap. Possession is authority
and nothing else holds it, so no other task can map device memory, touch a device
port, or claim an IRQ.

---

## 5. `console_server` (ring-3 process)

Modeled directly on `fs_server` (`userspace/fs_server.c`).

- **Protocol** `include/console_proto.h`, mirroring `include/fs_proto.h`: a magic,
  a request/response pair ≤256 B, `CON_OP_*` operations (`WRITE`, `GETLINE`,
  `READ`, `GETPASS`, and likely `CLEAR` / `SETCOLOR`), and well-known endpoint
  indices.
- **`_start` loop**, copied in shape from `fs_server.c`: initialize hardware (map
  `0xB8000`, program the VGA mode, `serial_init`, `keyboard_init` — all now native
  in ring 3), `sys_notify` a readiness badge to `init`, then a select-style loop
  that services **both** the request endpoint (`sys_ipc_recv` + `sys_ipc_sender` +
  `sys_ipc_reply_to`, routed to each client by kernel-attested identity for
  concurrent use) **and** the keyboard notification (`sys_wait_notify`). A line
  read blocks the *requesting client's* IPC call, while the server blocks on the
  notification for input — the scheduler runs everyone else. This is precisely what
  dissolves the unpreemptible-spin problem.
- **Logic moved out of the kernel**, behavior-preserving (the ELF-loader-to-Rust
  discipline — move first, improve later):
  - Output — `print_char`, ANSI/SGR coloring, cursor, scroll,
    `vga_initialize_text_mode_80x50`, `load_8x8_font` (from `src/kernel/terminal.c`).
  - Input — `ps2_translate` (`src/kernel/idt.c`), line editing / echo / backspace
    (from `h_get_line`), password masking (from `h_get_pass`).

---

## 6. Client cutover

`SYS_WRITE`, `SYS_GET_LINE`, `SYS_READ`, `SYS_GET_PASS` (`src/kernel/syscall.c`)
become thin IPC shims to `console_server`, or clients connect and call it directly.
Add `SYS_CONNECT_CONSOLE_SERVER`, modeled on `h_connect_fs_server`
(`src/kernel/syscall_fs.c`), so any task can obtain an endpoint cap; the server is
a reference monitor. The console is a shared resource, so kernel-attested identity
matters mostly for **reply routing** (`SYS_IPC_REPLY_TO` delivers each reply into
the requesting client's blocked call, never a shared mailbox) rather than for
authorization — but the attested-identity discipline is kept.

The ring-3 shell (`userspace/shell.c`) needs **no logic change**: its `println` /
`sys_get_line` / `sys_get_pass` calls traverse IPC transparently.

---

## 7. Boot ordering and the panic path

- **`init` sequence** becomes: spawn and endow **`console_server` first**, wait its
  readiness notification, then `fs_server`, then the shell. The current "shell waits
  on `fs_server` because the console read is an unpreemptible spin" ordering hack is
  removed — the constraint that created it no longer exists once input is an
  IRQ→notification serviced in ring 3.
- **The kernel keeps a minimal serial `outb` writer** (the core of
  `serial_write_char`, `src/kernel/terminal.c`) for the panic and early-boot path
  (`src/kernel/main.c`, the `cli; hlt` fatal idiom, before any scheduler or IRQs)
  and for ring-3 fault reporting from the IDT. This is a **deliberate residual**:
  "console in ring 3" is not literally total, and this document says so plainly
  rather than dressing it up. There is no `panic()` today — fatal paths print and
  spin-halt — and that synchronous, lock-free serial path must remain in the kernel
  to be usable during a fault.

---

## 8. SMP

The I/O-permission bitmap lives in the **running CPU's** TSS, and RSP0/IST are
already loaded per-CPU (`src/kernel/gdt.c`). For v1, **pin `console_server` to the
BSP** so only the BSP TSS ever carries a populated bitmap; per-CPU bitmap migration
(the driver running on any core) is future work. The default (non-SMP) build is
unaffected, and the `SMP=1` matrix (`altconfigs` CI) stays green.

---

## 9. Implementation plan (commit-per-job)

Each job is one focused, behavior-verified change with a smoke gate where
applicable, on the same cadence as the ELF-loader jobs. J2–J4 are independent
enabling mechanisms; J5 is the single cutover; J6 realizes and proves the win.

| Job | Change | Gate |
|-----|--------|------|
| **J1** | This RFC (docs only). | — |
| **J2** | `SYS_MAP_PHYS` + `CAP_IO_DEVICE` (mmio-frame) + allowlist, over `user_map_page`. | new `smoke-*`: a probe maps `0xB8000`, writes a cell, asserts it. |
| **J3** | TSS I/O-bitmap: grow TSS, `iomap_base`, per-task swap in `set_tss_kernel_stack`, cap-gated grant. | new `smoke-*`: probe `outb`/`inb` on an allowed port (ok) and a denied port (`#GP`→signal); falsification: neuter the grant → allowed access faults. |
| **J4** | `SYS_IRQ_REGISTER` + vector-33 → `sys_notify`; serial re-poll wake. | new `smoke-*`: probe registers, keys scripted via `tools/session_test.py`, receives notifications, reads scancodes natively. |
| **J5** | `console_proto.h` + `console_server` + `init` reorder + client syscalls→IPC shims; keep panic serial writer. | existing `smoke-session`, `smoke-modules`, `smoke-coreutils-shell` pass unchanged, now over the ring-3 console. |
| **J6** | Remove dead in-kernel console (leave panic serial); prove isolation; update `ROADMAP.md` + `LIMITATIONS.md`. | new negative `smoke-*`: a fault inside the driver kills only `console_server`, kernel + capability system + audit log survive. |

---

## 10. Verification strategy

- **Per-mechanism (J2–J4):** each new gated `smoke-*` target drives a userspace
  probe under headless QEMU and carries a **falsification check** (neuter the
  mechanism → the test goes red), matching the `smoke-stackguard` discipline.
- **End-to-end (J5):** the existing black-box session tests (`make smoke-session`,
  `smoke-modules`, `smoke-coreutils-shell`, `tools/session_test.py`) must pass
  unchanged — login, `whoami`, coreutils, man pages — now served by the ring-3
  console. This is the behavior-preserving proof.
- **Isolation (J6):** a scripted scenario provokes a fault inside the console driver
  and asserts the kernel survives — serial still responds, the capability system
  and audit log are intact. This is the actual privilege-separation guarantee, made
  concrete rather than asserted.
- Keep the `altconfigs` matrix (DEBUG_SHELL / MINIMAL_SECURE / SMP) green
  throughout.

---

## 11. Risks and open questions

- **TSS surgery (J3)** is the riskiest change — boot assembly plus the
  context-switch hot path. Land it standalone with its own falsification-tested gate
  before any server depends on it.
- **IRQ-context notify (J4):** confirm taking `ipc_lock` from the vector-33 handler
  is safe under `SMP=1` (it patches a saved frame with no reschedule; validate it).
- **Password entry over IPC:** masking now happens in ring 3. Ensure the plaintext
  line never transits a shared or pollable buffer — the identity-routed
  `SYS_IPC_REPLY_TO` reply delivers it only to the caller.
- **Deliberate residual:** the in-kernel panic serial writer means the console is
  not *entirely* out of the kernel. Stated here as a limitation, not theater — an
  unused-looking control is worse than an honestly-scoped one (the lesson recorded
  in the Phase 6 "don't wire up empty validators" non-goal).

---

## 12. Follow-on (out of scope for this cutover)

- The scancode / line-edit / escape parsers, once in ring 3, are candidates to move
  into the `horus_shell` `no_std` Rust crate and join the existing `fuzz` harness —
  the same likelihood-reduction the ELF loader got, now on top of the
  consequence-reduction this RFC delivers.
- Per-CPU I/O-bitmap migration (drop the BSP pin).
- Generalizing the three mechanisms into a reusable device-driver framework if a
  second driver (block, network) follows the console out of the kernel.
