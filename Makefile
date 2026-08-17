CC     = gcc
LD     = ld
AS     = gcc

export SOURCE_DATE_EPOCH ?= 1609459200

# Horus is x86-64 only, kernel and userspace alike: the kernel runs in 64-bit
# long mode and ring-3 tasks now run under a 64-bit code segment (see
# USERSPACE_CFLAGS). The only 32-bit code left is the boot path that has to
# exist -- the multiboot entry stage and the AP startup trampoline. An x86 CPU
# starts in real mode, GRUB hands over in 32-bit protected mode, and an AP comes
# out of SIPI in real mode; those .code16/.code32 blocks are how long mode is
# reached in the first place, so they are not "leftover 32-bit", they are the
# on-ramp. (userspace/elftest.o is also 32-bit, deliberately -- it is the test
# image for the loader's ELFCLASS32 path. See USERSPACE_CFLAGS_32.)
# -MMD -MP emit a .d per object listing its headers, pulled in via `-include`
# below. Without them, editing a header rebuilt NOTHING that included it: the
# link happily reused stale objects compiled against the old declarations, so a
# signature change could report a clean build and then miscompile (or link an
# object whose idea of a struct layout no longer matches). Header deps are not a
# nicety here — they are what makes a green local build mean anything.
# -mno-sse -mno-mmx -mno-80387: the kernel must not touch FPU/SSE/MMX state.
#
# Ring-3 SSE is fully supported -- each task's register file is saved/restored
# around every kernel entry (tcb_t.fpu_state, see interrupt_handler64). What the
# kernel must not do is participate: it has no FPU state of its own to keep, so
# any xmm it touches is pure collateral damage to the interrupted task, and
# anything it leaves behind is a confidentiality leak into ring 3. Left to
# itself gcc auto-vectorises ordinary integer loops -- paging.o alone had 125 xmm
# references and storage.o 166 -- so this is not a theoretical exposure.
#
# Keeping the kernel out of the FPU also keeps the save/restore cheap: it only
# has to happen on a ring-3 boundary, never on a ring-0 -> ring-0 interrupt.
#
# This was invisible while userspace was i386: SSE2 is not in that baseline, so
# the generated code never held a live xmm across a syscall. Under -m64 SSE2 IS
# the baseline. gcc compiled a 16-byte fill in the fs client into a broadcast
# plus one `movups`, hoisted the broadcast out of the loop, and left it live in
# xmm0 across sys_ipc_call -- so the fs_server's leftover xmm0 got stored as file
# data and written to disk, with every checksum agreeing (smoke-fs-conc).
# -mstack-protector-guard=global is not optional company for -fstack-protector-*:
# GCC's x86-64 default reads the canary from %gs:0x28, which in a kernel with no
# per-CPU GS base is a garbage address, and __stack_chk_guard would go entirely
# unreferenced. See the stack-protector block in src/kernel/crypto.c.
CFLAGS = -m64 -ffreestanding -fno-pic -fno-pie -MMD -MP \
         -fstack-protector-strong -mstack-protector-guard=global \
         -mno-sse -mno-mmx -mno-80387 \
         -Wall -Wextra -Wformat -Wformat-security -Werror=vla -O2 -pipe \
         -I src/include -I include -std=gnu99 -fno-builtin -mcmodel=kernel -frandom-seed=horus -fdebug-prefix-map=$(CURDIR)=/horus
ASFLAGS = -m64 -ffreestanding -fno-pic -fno-pie -x assembler-with-cpp -c -I src/include
LDFLAGS = -T linker64.ld -m elf_x86_64 -nostdlib -static --build-id=none
RUST_TARGET ?= x86_64-unknown-none


OBJS = src/boot/multiboot.o \
       src/kernel/terminal.o \
       src/kernel/main.o \
       src/kernel/gdt.o \
       src/kernel/idt.o \
       src/kernel/paging.o \
       src/kernel/capability.o \
       src/kernel/scheduler.o \
       src/kernel/smp.o \
       src/kernel/acpi.o \
       src/kernel/aslr.o \
       src/kernel/syscall.o \
       src/kernel/kshell.o \
       src/kernel/loader.o \
       src/kernel/kaudit.o \
       src/kernel/kusers.o \
       src/kernel/syscall_fs.o \
       src/kernel/kspawn.o \
       src/kernel/selftest.o \
       src/kernel/syscall_ipc.o \
       src/kernel/syscall_hw.o \
       src/kernel/ramfs.o \
       src/kernel/storage.o \
       src/kernel/crypto.o \
       src/kernel/tpm.o \
       src/kernel/pipe.o \
       src/kernel/untyped.o \
       src/kernel/ata.o

MINIMAL_SECURE ?= 0
ifeq ($(MINIMAL_SECURE),1)
CFLAGS += -DMINIMAL_SECURE=1
endif

DEBUG_SHELL ?= 0
ifeq ($(DEBUG_SHELL),1)
CFLAGS += -DDEBUG_SHELL
endif

# ELF_SELFTEST=1 embeds a real multi-segment ELF and runs an in-kernel
# self-test of try_elf_load + W^X at boot (prints ELF_SELFTEST: PASS/FAIL to
# serial). Gated so the default/ship kernel is unaffected. ASFLAGS also gets
# the define so the gated .incbin in multiboot.S is included.
ELF_SELFTEST ?= 0
ifeq ($(ELF_SELFTEST),1)
CFLAGS  += -DELF_SELFTEST
ASFLAGS += -DELF_SELFTEST
ELF_SELFTEST_DEP = userspace/elftest.elf
endif

# ELF64_SELFTEST=1 embeds the same elftest.c linked as a 64-bit static-PIE and
# runs an in-kernel self-test of the loader's x86-64 RELA relocation path
# (elf_apply_relocations_x86_64) plus W^X on an ELF64 image. The image is loaded
# and inspected, never executed, so this does not depend on the 64-bit ring-3
# ABI. Gated off the ship kernel.
ELF64_SELFTEST ?= 0
ifeq ($(ELF64_SELFTEST),1)
CFLAGS  += -DELF64_SELFTEST
ASFLAGS += -DELF64_SELFTEST
ELF64_SELFTEST_DEP = userspace/elftest64.elf
endif

# ASLR_SELFTEST=1 spawns several PIE images at boot and asserts the loader
# actually randomises the image base, and that every base keeps the premap inside
# one page table (ASLR_SELFTEST: PASS). Reuses the ELF self-test's embedded image.
# Gated off the ship kernel.
ASLR_SELFTEST ?= 0
ifeq ($(ASLR_SELFTEST),1)
CFLAGS  += -DASLR_SELFTEST
ASFLAGS += -DASLR_SELFTEST
ASLR_SELFTEST_DEP = userspace/elftest64.elf
endif

# PREEMPT_SELFTEST=1 embeds a flat userspace tracer and, at boot, spawns two
# copies of it and proves the timer preempts/time-slices them (prints
# PREEMPT_SELFTEST: PASS to serial). Gated so the default/ship kernel is
# unaffected. ASFLAGS also gets the define for the gated .incbin in multiboot.S.
PREEMPT_SELFTEST ?= 0
ifeq ($(PREEMPT_SELFTEST),1)
CFLAGS  += -DPREEMPT_SELFTEST
ASFLAGS += -DPREEMPT_SELFTEST
PREEMPT_SELFTEST_DEP = userspace/preempttest.bin
endif

# SIGNAL_SELFTEST=1 embeds a flat userspace payload that registers a fault
# handler then faults on purpose, and boots it to prove the handler runs
# instead of the task being killed (prints SIGNAL_SELFTEST: PASS to serial).
# Gated so the default/ship kernel is unaffected.
SIGNAL_SELFTEST ?= 0
ifeq ($(SIGNAL_SELFTEST),1)
CFLAGS  += -DSIGNAL_SELFTEST
ASFLAGS += -DSIGNAL_SELFTEST
SIGNAL_SELFTEST_DEP = userspace/sigtest.bin
endif

# TSD_SELFTEST=1 embeds a flat payload that registers a fault handler then
# executes RDTSC. With CR4.TSD engaged the ring-3 RDTSC #GPs into the handler
# (prints TSD_SELFTEST: PASS); if it returned a timestamp the payload prints
# FAIL. Gated so the default/ship kernel is unaffected.
TSD_SELFTEST ?= 0
ifeq ($(TSD_SELFTEST),1)
CFLAGS  += -DTSD_SELFTEST
ASFLAGS += -DTSD_SELFTEST
TSD_SELFTEST_DEP = userspace/tsdtest.bin
endif

# E820_SELFTEST=1 makes kernel_main assert (after paging_init) that the physical
# pool was sized from the multiboot2 memory map — the free frame count exceeds
# the pre-E820 default under the harness's -m 512M. Pure kernel assertion, no
# userspace payload. Gated off the ship kernel.
E820_SELFTEST ?= 0
ifeq ($(E820_SELFTEST),1)
CFLAGS  += -DE820_SELFTEST
endif

# STORAGE_ATA=1 makes the filesystem's block store the ATA disk (persistent)
# instead of the default in-RAM virtual disk. storage_init() probes the disk and
# formats-on-first-boot. Pair with a QEMU -drive (see `make run-ata`).
STORAGE_ATA ?= 0
ifeq ($(STORAGE_ATA),1)
CFLAGS  += -DSTORAGE_ATA
endif

# FS_SELFTEST=1 embeds the userspace fs_server and a client, spawns both at
# boot, and drives the filesystem end-to-end over IPC against the encrypted
# object store (prints FS_SELFTEST: PASS to serial). Gated off the ship kernel.
FS_SELFTEST ?= 0
ifeq ($(FS_SELFTEST),1)
CFLAGS  += -DFS_SELFTEST
ASFLAGS += -DFS_SELFTEST
FS_SELFTEST_DEP = userspace/fs_server.bin userspace/fsclient.bin
endif

# INIT_FS_SELFTEST=1 is the Phase-1 boot-time FS integration test: ring-3 init
# launches the userspace fs_server and provisions it purely by delegation
# (SYS_CAP_GRANT) instead of direct root-cnode installs, then launches the client
# that drives it. Proves the delegated server still serves end-to-end (the client
# prints FS_SELFTEST: PASS). fs_server is already always embedded; only the client
# needs adding. Gated off the ship kernel.
INIT_FS_SELFTEST ?= 0
ifeq ($(INIT_FS_SELFTEST),1)
CFLAGS  += -DINIT_FS_SELFTEST
ASFLAGS += -DINIT_FS_SELFTEST
INIT_FS_SELFTEST_DEP = userspace/fsclient.bin
endif

# PERSIST_SELFTEST=1 builds the FS self-test client in reboot-persistence mode: it
# writes a sentinel file on the first boot (prints PERSIST_SELFTEST: WROTE) and, on
# a later boot against the same disk image, reads it back and verifies it (prints
# PERSIST_SELFTEST: PASS). Reuses the FS_SELFTEST kernel driver (spawns server +
# client); pair with STORAGE_ATA=1 and drive it with the two-boot `make
# smoke-fs-persist`. The USERSPACE_CFLAGS half is applied after that variable is
# defined below.
PERSIST_SELFTEST ?= 0
ifeq ($(PERSIST_SELFTEST),1)
CFLAGS  += -DFS_SELFTEST -DPERSIST_SELFTEST
ASFLAGS += -DFS_SELFTEST
FS_SELFTEST_DEP = userspace/fs_server.bin userspace/fsclient.bin
endif

# PERM_SELFTEST=1 builds the FS self-test client in ownership/permission mode: it
# drives the fs_server's zero-trust access control end-to-end — root builds a
# scenario, then the client re-authenticates as a non-root user and the server
# enforces owner/group/other rwx against the caller's KERNEL-ATTESTED uid (a
# client cannot forge who it is). Reuses the FS_SELFTEST kernel driver (spawns
# server + client); the ephemeral RAM backend is sufficient.
PERM_SELFTEST ?= 0
ifeq ($(PERM_SELFTEST),1)
CFLAGS  += -DFS_SELFTEST -DPERM_SELFTEST
ASFLAGS += -DFS_SELFTEST
FS_SELFTEST_DEP = userspace/fs_server.bin userspace/fsclient.bin
endif

# CONC_SELFTEST=1 builds the FS self-test in multi-client concurrency mode: the
# kernel spawns one server and several client tasks that hammer it at once, each
# verifying it receives its own replies (SYS_IPC_REPLY_TO routes by the request's
# kernel-recorded sender). Reuses the FS_SELFTEST kernel driver + client binary.
CONC_SELFTEST ?= 0
ifeq ($(CONC_SELFTEST),1)
CFLAGS  += -DFS_SELFTEST -DCONC_SELFTEST
ASFLAGS += -DFS_SELFTEST
FS_SELFTEST_DEP = userspace/fs_server.bin userspace/fsclient.bin
endif

# WAL_CRASHTEST=1 builds the in-kernel journal crash-recovery test: boot 1 commits
# a write and halts before applying it; boot 2 replays the committed transaction
# at mount. Pure kernel (no userspace bins); driven by the two-boot smoke-fs-wal.
WAL_CRASHTEST ?= 0
ifeq ($(WAL_CRASHTEST),1)
CFLAGS  += -DWAL_CRASHTEST
ASFLAGS += -DWAL_CRASHTEST
endif

# WAL_NO_FLUSH=1 is the CONTROL ARM for [I-10]: it compiles every journal
# durability barrier out, restoring the pre-2026-08-16 kernel in which the ATA
# driver had no FLUSH CACHE opcode and the write-ahead log's ordering held only
# because the emulator persisted every write on its own. The gates that witness
# the fix (smoke-fs-wal-flush, smoke-fs-wal-order) must FAIL against this build;
# see docs/BUILDING.md "Defect-reproducing builds". Never ship it.
WAL_NO_FLUSH ?= 0
ifeq ($(WAL_NO_FLUSH),1)
CFLAGS  += -DWAL_NO_FLUSH
ASFLAGS += -DWAL_NO_FLUSH
endif

# BIGFILE_SELFTEST=1 builds the in-kernel large-file / double-indirect test: it
# writes blocks across the direct, single-indirect and double-indirect mapping
# regions of one inode and reads them back. Pure kernel (no userspace bins);
# driven by the single-boot smoke-fs-large.
BIGFILE_SELFTEST ?= 0
ifeq ($(BIGFILE_SELFTEST),1)
CFLAGS  += -DBIGFILE_SELFTEST
ASFLAGS += -DBIGFILE_SELFTEST
endif

# TPM_SELFTEST=1 builds the in-kernel TPM seal/unseal round-trip (roadmap 2.2
# stage 2): seal a known value under a PolicyPCR(PCR8,PCR9) and unseal it under
# the live PCRs. Needs an emulated TPM at boot; driven by smoke-tpm-seal-roundtrip.
TPM_SELFTEST ?= 0
ifeq ($(TPM_SELFTEST),1)
CFLAGS  += -DTPM_SELFTEST
endif

# PIPE_SELFTEST=1 builds the in-kernel pipe-object exercise (roadmap userspace:
# shell pipelines): round-trip, EOF/EPIPE, back-pressure, scrub-on-free — fast and
# deterministic, no coreutil image loading. Driven by smoke-pipe.
PIPE_SELFTEST ?= 0
ifeq ($(PIPE_SELFTEST),1)
CFLAGS  += -DPIPE_SELFTEST
endif

# TPM_KEK_SELFTEST=1 builds the in-kernel TPM-sealed-KEK end-to-end test (roadmap
# 2.2 stage 3): format the vdisk in TPM mode, unlock it, then perturb PCR[9] and
# require the re-unlock to be refused. Needs an emulated TPM; driven by
# smoke-tpm-seal.
TPM_KEK_SELFTEST ?= 0
ifeq ($(TPM_KEK_SELFTEST),1)
CFLAGS  += -DTPM_KEK_SELFTEST
endif

# NEWLIB_SELFTEST=1 embeds hello_newlib (newlib + posix + malloc on Horus) and
# spawns it at boot to verify printf/sprintf/malloc/string ops work end-to-end
# (prints NEWLIB_SELFTEST: PASS to serial).  Gated off the ship kernel.
NEWLIB_SELFTEST ?= 0
ifeq ($(NEWLIB_SELFTEST),1)
CFLAGS  += -DNEWLIB_SELFTEST
ASFLAGS += -DNEWLIB_SELFTEST
NEWLIB_SELFTEST_DEP = userspace/hello_newlib.bin
endif

# COREUTILS_SELFTEST=1 embeds the vendored GNU coreutils echo(1) -- unmodified
# upstream source built against the Horus port shim (userspace/ports/coreutils)
# -- and runs it at boot with an argument vector, letting its own argv joining
# and -e backslash-escape handling produce the marker (prints
# "COREUTILS_SELFTEST: PASS echo ran!" to serial). Gated off the ship kernel, so
# the ISO carries neither the ~400 KiB image nor any GPLv3-derived binary.
# CAPTEST_SELFTEST=1 spawns captest at boot: a ring-3 conformance exerciser for
# the syscall surface and the capability model, asserting mostly on the REFUSALS
# (unheld caps, post-revoke use, grants outside the descendants rule, bad input)
# -- prints "CAPTEST: PASS <n> checks" to serial. captest is embedded in every
# build already, so this only gates the boot-time run.
CAPTEST_SELFTEST ?= 0
ifeq ($(CAPTEST_SELFTEST),1)
CFLAGS  += -DCAPTEST_SELFTEST
ASFLAGS += -DCAPTEST_SELFTEST
endif

# The set of utilities ported so far. Each is an unmodified upstream .c in
# $(COREUTILS_DIR) built into its own static-PIE binary; adding one is a matter of
# extending this list once its gnulib surface is covered by port/.
COREUTILS_PROGS = echo true false basename dirname cat head seq wc printf tail
COREUTILS_BINS  = $(addprefix userspace/coreutils_,$(addsuffix .bin,$(COREUTILS_PROGS)))

# The utilities are NOT baked into the kernel image. COREUTILS_MODULES=1 ships
# them as GRUB multiboot2 modules: the boot.iso rule copies each utility .bin onto
# the ISO and emits a `module2` line, GRUB loads them into RAM outside the kernel
# image (so the 16 MiB image budget stops applying and ALL of them fit at once),
# the fs_server provisions each into /bin at boot, and the shell runs them from
# there (see boot.iso below, provision_boot_modules() in userspace/fs_server.c,
# and try_run_from_bin() in userspace/shell.c). Off by default, so the shipped ISO
# carries no GPLv3-derived binary; the coreutils smoke tests turn it on.
#
# BOOT_MODULES is a space-separated list of `<file>:<dest-path>` pairs the boot.iso
# rule consumes; `dest-path` is where the fs_server provisions the module in the
# store (relative to the root) — `bin/<name>` for a runnable binary,
# `usr/share/man/<name>` for a man page. The fs_server creates any missing parent
# directories on the way.
#
# COREUTILS_MODULE_SET picks which utilities to ship as modules (default: all of
# them). The 16 MiB store volume holds every ported coreutils binary at once, so
# smoke-modules ships the full set; smoke-coreutils-shell overrides it with a
# smaller set only to keep that focused test fast. Each shipped utility also ships
# its plain-text man page (userspace/man/<name>) to usr/share/man, and hier(7) —
# the filesystem-layout page — always ships.
COREUTILS_MODULE_SET ?= $(COREUTILS_PROGS)
COREUTILS_MODULES    ?= 0
ifeq ($(COREUTILS_MODULES),1)
BOOT_MODULES        += $(foreach p,$(COREUTILS_MODULE_SET),userspace/coreutils_$(p).bin:bin/$(p))
BOOT_MODULE_DEP     += $(foreach p,$(COREUTILS_MODULE_SET),userspace/coreutils_$(p).bin)
BOOT_MODULES        += userspace/man/hier:usr/share/man/hier \
                       $(foreach p,$(COREUTILS_MODULE_SET),userspace/man/$(p):usr/share/man/$(p))
BOOT_MODULE_DEP     += userspace/man/hier \
                       $(foreach p,$(COREUTILS_MODULE_SET),userspace/man/$(p))
endif

# TCC (Tiny C Compiler) — a native C compiler ported to run as a ring-3 program
# on Horus. Like the coreutils it is NOT baked into the kernel image: TCC_MODULE=1
# ships it as a GRUB multiboot2 module the fs_server provisions into /bin, plus its
# man page. Vendored (LGPL 2.1) source lives in $(TCC_DIR); see its README. Off by
# default (the release ISO carries no ported binary); `make run` and smoke-tcc
# turn it on. Compiling *on* Horus additionally needs headers+libc+crt on the FS —
# a follow-up; today /bin/tcc runs (version/help, -c to an object) from the store.
TCC_MODULE ?= 0
ifeq ($(TCC_MODULE),1)
BOOT_MODULES    += userspace/tcc.bin:bin/tcc userspace/man/tcc:usr/share/man/tcc
BOOT_MODULE_DEP += userspace/tcc.bin userspace/man/tcc
endif

# TERM_MODULE=1 ships termtest into /bin — the raw-terminal-layer proof driven by
# smoke-term. Not part of a normal boot.
TERM_MODULE ?= 0
ifeq ($(TERM_MODULE),1)
BOOT_MODULES    += userspace/termtest.bin:bin/termtest
BOOT_MODULE_DEP += userspace/termtest.bin
endif

# NOTIFY_SELFTEST=1 embeds notifytest and, at boot, spawns it twice (a waiter and
# a sender) to prove the async SYS_NOTIFY / SYS_WAIT_NOTIFY badge round-trip works
# end-to-end (prints NOTIFY_SELFTEST: PASS to serial). Gated off the ship kernel.
NOTIFY_SELFTEST ?= 0
ifeq ($(NOTIFY_SELFTEST),1)
CFLAGS  += -DNOTIFY_SELFTEST
ASFLAGS += -DNOTIFY_SELFTEST
NOTIFY_SELFTEST_DEP = userspace/notifytest.bin
endif

# MAPPHYS_SELFTEST=1 embeds mapphystest and, at boot, spawns it endowed with a
# CAP_IO_DEVICE cap; the probe maps the allowlisted VGA framebuffer into its own
# address space via SYS_MAP_PHYS, reads back a kernel-seeded sentinel (proving the
# mapping is the real physical frame), writes+reads a magic, and confirms an
# off-allowlist frame is refused (prints MAPPHYS_SELFTEST: PASS to serial). First
# driver-privilege-separation job (Phase 6); gated off the ship kernel.
MAPPHYS_SELFTEST ?= 0
ifeq ($(MAPPHYS_SELFTEST),1)
CFLAGS  += -DMAPPHYS_SELFTEST
ASFLAGS += -DMAPPHYS_SELFTEST
MAPPHYS_SELFTEST_DEP = userspace/mapphystest.bin
endif

# IOPORT_SELFTEST=1 embeds ioporttest and, at boot, spawns it endowed with a
# CAP_IO_DEVICE cap; the probe requests native port I/O (SYS_IOPORT_GRANT / TSS
# I/O-permission bitmap), then confirms an allowlisted console port (serial line
# status) can be read while a non-allowlisted port (CMOS) still #GPs (prints
# IOPORT_SELFTEST: PASS to serial). Second driver-privilege-separation job
# (Phase 6); gated off the ship kernel.
IOPORT_SELFTEST ?= 0
ifeq ($(IOPORT_SELFTEST),1)
CFLAGS  += -DIOPORT_SELFTEST
ASFLAGS += -DIOPORT_SELFTEST
IOPORT_SELFTEST_DEP = userspace/ioporttest.bin
endif

# IRQ_SELFTEST=1 embeds irqtest and, at boot, spawns it endowed with a
# CAP_IO_DEVICE cap; the probe routes the timer IRQ to a notification
# (SYS_IRQ_REGISTER), blocks in SYS_WAIT_NOTIFY, and a real hardware timer
# interrupt wakes it with the registered badge (prints IRQ_SELFTEST: PASS to
# serial). Third driver-privilege-separation job (Phase 6); gated off the ship
# kernel.
IRQ_SELFTEST ?= 0
ifeq ($(IRQ_SELFTEST),1)
CFLAGS  += -DIRQ_SELFTEST
ASFLAGS += -DIRQ_SELFTEST
IRQ_SELFTEST_DEP = userspace/irqtest.bin
endif

# CONSOLE_SELFTEST=1 embeds the userspace console_server + a client and, at boot,
# stands up the server (which owns the console hardware via SYS_MAP_PHYS +
# SYS_IOPORT_GRANT) and has the client drive it over IPC. The server emits the
# client's line to serial with its own hands, so CONSOLE_SELFTEST: PASS on serial
# proves the whole ring-3 console output path (client -> IPC -> server ->
# hardware). First J5 cutover milestone (Phase 6); gated off the ship kernel.
CONSOLE_SELFTEST ?= 0
ifeq ($(CONSOLE_SELFTEST),1)
CFLAGS  += -DCONSOLE_SELFTEST
ASFLAGS += -DCONSOLE_SELFTEST
CONSOLE_SELFTEST_DEP = userspace/consoletest.bin
endif

# CONSOLE_ISOLATION_TEST=1 is the Phase-6 close-out blast-radius proof: the ring-3
# console_server takes ownership of the console hardware and then deliberately
# faults. Because it now runs in ring 3, the kernel contains the fault (delivers it
# to the server's own handler) and keeps running -- proof that a bug in the console
# driver can no longer reach kernel memory or the capability system (prints
# CONSOLE_ISOLATION: PASS to serial). console_server is always embedded; the flag
# reaches its userspace build too, so it carries the deliberate fault. Gated off the
# ship kernel.
CONSOLE_ISOLATION_TEST ?= 0
ifeq ($(CONSOLE_ISOLATION_TEST),1)
CFLAGS  += -DCONSOLE_ISOLATION_TEST
ASFLAGS += -DCONSOLE_ISOLATION_TEST
endif

# RECVBLOCK_SELFTEST=1 embeds a server/client pair around one endpoint and, at
# boot, has the server wait with SYS_IPC_RECV_BLOCK while the client dawdles
# before each request (roadmap 1.3). The server asserts it made exactly ONE
# receive syscall per message -- the witness that it slept rather than polled --
# and that the wake left it holding the one-shot reply right; it prints
# RECVBLOCK_SELFTEST: PASS from ring 3. Gated off the ship kernel.
RECVBLOCK_SELFTEST ?= 0
ifeq ($(RECVBLOCK_SELFTEST),1)
CFLAGS  += -DRECVBLOCK_SELFTEST
ASFLAGS += -DRECVBLOCK_SELFTEST
RECVBLOCK_SELFTEST_DEP = userspace/recvblocksrv.bin userspace/recvblockcli.bin
endif

# KFAULT_INJECT=1 makes the kernel take a deliberate supervisor page fault on a
# timer tick once a ring-3 console_server owns the console -- G-8's exact
# signature (a read of 0x94), in the exact state where the kernel's fault report
# used to be inaudible. KFAULT_INJECT_TICKS is how many owned ticks to wait, and
# needs to be past the login prompt so the report is provably AFTER the console
# handover. Test-only; `make smoke-kfault` sets it and nothing else does.
KFAULT_INJECT ?= 0
KFAULT_INJECT_TICKS ?= 400
ifeq ($(KFAULT_INJECT),1)
CFLAGS  += -DKFAULT_INJECT -DKFAULT_INJECT_TICKS=$(KFAULT_INJECT_TICKS)
ASFLAGS += -DKFAULT_INJECT
endif

# RESUME_RSP_INJECT=1 forces interrupt_handler64's resume %rsp to a bogus 4 once,
# after the console handover -- the literal value G-8's 2026-08-13 capture
# recorded. It exists so the floor guard in idt.c can be GATED rather than waited
# on: the natural event is ~1 boot in 150, and "no PANIC line appeared" is worth
# nothing until the guard is known to be able to speak on that path.
#
# Three arms, all test-only, all set by `make smoke-resume-guard*`:
#   RESUME_RSP_INJECT=1                  the guard must be heard
#   RESUME_RSP_INJECT_PRECLAIM=1         ... even behind another CPU's fatal claim
#   RESUME_GUARD_DISABLE=1               guard compiled out: the silence, on demand
RESUME_RSP_INJECT ?= 0
RESUME_RSP_INJECT_TICKS ?= 400
RESUME_RSP_INJECT_PRECLAIM ?= 0
RESUME_GUARD_DISABLE ?= 0
ifeq ($(RESUME_RSP_INJECT),1)
CFLAGS += -DRESUME_RSP_INJECT -DRESUME_RSP_INJECT_TICKS=$(RESUME_RSP_INJECT_TICKS)
endif
ifeq ($(RESUME_RSP_INJECT_PRECLAIM),1)
CFLAGS += -DRESUME_RSP_INJECT_PRECLAIM
endif
ifeq ($(RESUME_GUARD_DISABLE),1)
CFLAGS += -DRESUME_GUARD_DISABLE
endif
# RESUME_GUARD_LEGACY_FATAL=1 restores the guard's pre-fix kfault_begin(1) /
# kfault_end(1) bracket, whose claim is permanent and whose losers halt without
# printing. The control arm for the fix itself: built with PRECLAIM it must be
# INAUDIBLE, which is the defect reproduced on demand.
RESUME_GUARD_LEGACY_FATAL ?= 0
ifeq ($(RESUME_GUARD_LEGACY_FATAL),1)
CFLAGS += -DRESUME_GUARD_LEGACY_FATAL
endif

# ---- G-8: the window between giving a task up and leaving its kernel stack ----
#
# KSTACK_RELEASE_EARLY=1 restores the pre-fix release site -- the outgoing task is
# published as claimable inside the switch path, while this CPU still has ~30
# instructions of ISR epilogue to execute on that task's kernel stack. That is the
# defect, on demand.
#
# KSTACK_RACE_WIDEN=1 stretches that window with a spin so the race is entered on
# essentially every switch instead of at G-8's ~2-3% per boot. It is orthogonal to
# the arm above and is set in BOTH, which is the whole point: the same widened
# window must be harmless with the fix and fatal without it. A one-armed run here
# would prove nothing -- see TESTS.md on the two 150-boot arms that established
# only that the fault was main's.
#
# KSTACK_RACE_WIDEN_SPINS is the spin count. It has to be long enough for another
# CPU to take a timer tick (10 ms at 100 Hz), select the released task and resume
# it into ring 3, and short enough that the fixed arm still finishes a session
# inside SESSION_TIMEOUT. Derived by measurement, not chosen: see TESTS.md.
KSTACK_RELEASE_EARLY ?= 0
KSTACK_RACE_WIDEN ?= 0
KSTACK_RACE_WIDEN_SPINS ?= 200000
# ...and WHICH CPUs do it. Only the CPUs in this mask linger; the rest take and
# resume at full speed. That split is the whole trick, and it is a measurement:
# spinning on EVERY switch is self-defeating, because the CPU that must take the
# released task reaches the same spin on its own switch and is always a full spin
# behind. Widening everywhere reproduced on only 2 boots in 7; one switch in 8, on
# 0 in 3. 0x5 lingers on cpu 0 and cpu 2 and takes on cpu 1 and cpu 3, under the
# `-smp 4` the gate boots.
KSTACK_RACE_WIDEN_CPUMASK ?= 0x5
ifeq ($(KSTACK_RELEASE_EARLY),1)
CFLAGS += -DKSTACK_RELEASE_EARLY
endif
ifeq ($(KSTACK_RACE_WIDEN),1)
CFLAGS += -DKSTACK_RACE_WIDEN -DKSTACK_RACE_WIDEN_SPINS=$(KSTACK_RACE_WIDEN_SPINS) \
          -DKSTACK_RACE_WIDEN_CPUMASK=$(KSTACK_RACE_WIDEN_CPUMASK)
endif

# USER_HEAP_HIGH_BASE=1 places every user heap at 8 GiB instead of 16 MiB, which
# is what makes finding [I-2] REACHABLE rather than latent: the heap syscalls
# computed the new break in 32 bits, so a base above 2^32 wrapped. Used by
# `make smoke-heap64` in both directions -- with the roadmap 1.5 fix the session
# must run normally; built from a tree without it, sbrk fails for every request
# and userspace cannot allocate at all. See src/include/kernel.h.
USER_HEAP_HIGH_BASE ?= 0
ifeq ($(USER_HEAP_HIGH_BASE),1)
CFLAGS += -DUSER_HEAP_HIGH_BASE
endif


# KFAULT_LEGACY_PRINTLN=1 restores the pre-fix reporting of a CPL-0 page fault
# (println(), i.e. klog-only once console_server owns the console). The CONTROL
# ARM for the gate above: with it, the report must NOT appear on serial. Without
# a build that reproduces the defect, "the report is audible" is a claim rather
# than a measurement. Never a shipping config.
KFAULT_LEGACY_PRINTLN ?= 0
ifeq ($(KFAULT_LEGACY_PRINTLN),1)
CFLAGS  += -DKFAULT_LEGACY_PRINTLN
ASFLAGS += -DKFAULT_LEGACY_PRINTLN
endif

# COW_SELFTEST=1 embeds cowtest and, at boot, reads two fresh heap pages (each
# aliasing the shared zero page) then writes one, proving the write breaks
# copy-on-write into a private page without disturbing its sibling (prints
# COW_SELFTEST: PASS). Gated off the ship kernel.
COW_SELFTEST ?= 0
ifeq ($(COW_SELFTEST),1)
CFLAGS  += -DCOW_SELFTEST
ASFLAGS += -DCOW_SELFTEST
COW_SELFTEST_DEP = userspace/cowtest.bin
endif

# PROC_SELFTEST=1 embeds the proctest driver and, at boot, drives SYS_EXIT +
# SYS_KILL from ring 3, confirming both a self-exiting child and a killed child
# reach the dead state (prints PROC_SELFTEST: PASS). Gated off the ship kernel.
PROC_SELFTEST ?= 0
ifeq ($(PROC_SELFTEST),1)
CFLAGS  += -DPROC_SELFTEST
ASFLAGS += -DPROC_SELFTEST
PROC_SELFTEST_DEP = userspace/proctest.bin userspace/exectest.bin userspace/grantee.bin userspace/sigtarget.bin userspace/faulter.bin userspace/sigwaiter.bin userspace/argtest.bin userspace/preempttest.bin
endif

# SMP brings up the application processors (multi-core) at boot: the BSP reads the
# real CPU count from the ACPI MADT (src/kernel/acpi.c), wakes every AP with a
# broadcast INIT-SIPI-SIPI, and each walks itself to long mode via the real-mode
# trampoline (src/boot/ap_trampoline.S). It is ON by default now; a uniprocessor
# (or SMP=0) build simply finds one CPU and skips AP bringup entirely, so the
# single-core path stays intact. Run under QEMU with -smp N (`make run` passes
# -smp $(SMP_CPUS); see also `make smoke-smp`). Build SMP=0 to compile it out
# completely. ASFLAGS also gets the define so the gated .incbin of the trampoline
# blob in multiboot.S is included.
# SMP_SELFTEST=1 implies SMP=1 and, at boot, spawns a pool of forever-looping
# workers and proves the application processors pull and run them concurrently
# (prints SMP_SELFTEST: PASS to serial). Drives `make smoke-smp`.
CPU_SELFTEST ?= 0
ifeq ($(CPU_SELFTEST),1)
CFLAGS  += -DCPU_SELFTEST
ASFLAGS += -DCPU_SELFTEST
endif

# PERCPU_SELFTEST=1 proves this_cpu()'s TSS-selector derivation (finding [I-6]:
# it replaced an uncached LAPIC MMIO read on the hottest kernel path) agrees with
# the LAPIC on EVERY core that comes online, and that EFER.SCE stays clear so the
# staged-but-not-SMP-safe SYSCALL path remains unreachable. Implies SMP=1: on a
# single core the mapping (TR - 0x38)/0x10 is right by accident, so a UP run
# would prove nothing and the test fails rather than passing vacuously.
PERCPU_SELFTEST ?= 0
ifeq ($(PERCPU_SELFTEST),1)
CFLAGS  += -DPERCPU_SELFTEST
ASFLAGS += -DPERCPU_SELFTEST
SMP := 1
endif

# FLUSH_SELFTEST=1 makes kernel_main verify the side-channel flush-on-switch
# mechanism (detection matches CPUID, the gated IBPB/L1D/VERW barriers execute
# without #GP, and the switch policy flushes on a task change only). Prints
# FLUSH_SELFTEST: PASS/FAIL; make smoke-flush asserts on it under a QEMU CPU that
# advertises the primitives.
FLUSH_SELFTEST ?= 0
ifeq ($(FLUSH_SELFTEST),1)
CFLAGS  += -DFLUSH_SELFTEST
endif

# STACKGUARD_SELFTEST=1 makes kernel_main assert (right after
# stack_protector_init) that the stack canary was re-seeded from the CSPRNG at
# boot — i.e. the live __stack_chk_guard is no longer the published compile-time
# constant (nor 0). Guards against the "-fstack-protector-strong is on but the
# guard is the reproducible-build default" silent-inertness class. Drives
# `make smoke-stackguard`.
STACKGUARD_SELFTEST ?= 0
ifeq ($(STACKGUARD_SELFTEST),1)
CFLAGS  += -DSTACKGUARD_SELFTEST
endif

WX_SELFTEST ?= 0
ifeq ($(WX_SELFTEST),1)
CFLAGS  += -DWX_SELFTEST
ASFLAGS += -DWX_SELFTEST
endif

ASPACE_SELFTEST ?= 0
ifeq ($(ASPACE_SELFTEST),1)
CFLAGS  += -DASPACE_SELFTEST
ASFLAGS += -DASPACE_SELFTEST
endif

# NZCOW_SELFTEST=1 makes kernel_main (after paging_init) drive the generic,
# non-zero copy-on-write break end-to-end: private copy on the shared write, and
# an in-place upgrade for the sole owner, with correct refcounts. Prints
# NZCOW_SELFTEST: PASS/FAIL; make smoke-nzcow asserts on it.
NZCOW_SELFTEST ?= 0
ifeq ($(NZCOW_SELFTEST),1)
CFLAGS  += -DNZCOW_SELFTEST
endif

SMP_SELFTEST ?= 0
ifeq ($(SMP_SELFTEST),1)
SMP := 1
CFLAGS  += -DSMP_SELFTEST
ASFLAGS += -DSMP_SELFTEST
SMP_SELFTEST_DEP = userspace/preempttest.bin
endif

SMP ?= 1
ifeq ($(SMP),1)
CFLAGS  += -DSMP
ASFLAGS += -DSMP
AP_TRAMPOLINE_DEP = src/boot/ap_trampoline.bin
endif

# SCHED_INVARIANTS=1 machine-checks the scheduler's claim invariant
#   task_running_cpu[t] == c  <=>  percpu_current_task[c] == t
# at every tick and at each idle-park, panicking with the offending task and CPU
# instead of livelocking silently thousands of ticks later. Off in the ship
# kernel (it costs a MAX_TASKS + MAX_CPUS scan per tick, under the scheduler
# lock); on for the SMP smoke jobs, which is where the races are.
# IRQ_POLICY_AUDIT=1 measures roadmap 1.1's central question: how often does
# spin_unlock's unconditional `sti` enable interrupts that the CALLER had masked?
# Observation only -- the sti still fires exactly as before, so the build boots
# identically. See the note above spin_lock in scheduler.c.
IRQ_POLICY_AUDIT ?= 0
ifeq ($(IRQ_POLICY_AUDIT),1)
CFLAGS  += -DIRQ_POLICY_AUDIT
endif

# "Observation only ... boots identically" above is NOT true of the session, and
# these two knobs are how that was established. The audit reports out of the timer
# ISR on the polled UART; the tick-200 one lands after ring-3 console_server has
# taken the serial line, and an audit build fails tools/session_test.py at a rate
# the ship kernel does not. IRQ_POLICY_REPORT_LATE=0 drops that report (keeping
# the tick-40 one, which fires while the kernel still owns the console);
# IRQ_POLICY_REPORT_EVERY=N adds a one-line total every N ticks. See TESTS.md.
IRQ_POLICY_QUIET ?= 1
ifneq ($(IRQ_POLICY_QUIET),1)
CFLAGS  += -DIRQ_POLICY_QUIET=$(IRQ_POLICY_QUIET)
endif
IRQ_POLICY_REPORT_LATE ?= 1
ifneq ($(IRQ_POLICY_REPORT_LATE),1)
CFLAGS  += -DIRQ_POLICY_REPORT_LATE=$(IRQ_POLICY_REPORT_LATE)
endif
# IRQ_LEGACY_GLOBAL_LOCK=1 rebuilds the PRE-1.1 spinlock: one global nesting
# depth shared by every CPU, incremented non-atomically, with an unconditional
# `sti` on the outermost release. That is findings [C-3] and [C-3.1] exactly as
# they stood, and it is the CONTROL ARM the IF-preserving per-CPU lock was
# measured against -- the same role EP_QUEUE_SLOTS=1 plays for roadmap 1.3.
#
# Under IRQ_POLICY_AUDIT=1 the two builds count the SAME predicate (a release
# whose caller had IF clear): the legacy build reports it as `accidental` and
# fires the sti, the default build reports it as `suppressed` and does not. Equal
# totals on one workload is the evidence that the fix removed those enablements
# and nothing else. NEVER SHIP THIS.
IRQ_LEGACY_GLOBAL_LOCK ?= 0
ifeq ($(IRQ_LEGACY_GLOBAL_LOCK),1)
CFLAGS  += -DIRQ_LEGACY_GLOBAL_LOCK
endif

IRQ_POLICY_REPORT_EVERY ?= 0
ifneq ($(IRQ_POLICY_REPORT_EVERY),0)
CFLAGS  += -DIRQ_POLICY_REPORT_EVERY=$(IRQ_POLICY_REPORT_EVERY)u
endif

SCHED_INVARIANTS ?= 0
ifeq ($(SCHED_INVARIANTS),1)
CFLAGS  += -DSCHED_INVARIANTS
ASFLAGS += -DSCHED_INVARIANTS
endif

# HANG_WATCHDOG=1 dumps the scheduler's view of every task once the boot has run
# HANG_WATCHDOG_TICKS ticks without finishing, then lets it continue.
#
# It exists because some self-tests are SILENT on the happy path -- smoke-fs-conc
# prints nothing at all between "[fs_server] filesystem provisioned" and its single
# PASS -- so a wedge and a slow run produce byte-identical serial logs, and finding
# G-8 signature C is exactly that: 120 seconds of nothing, on a uniprocessor boot,
# with no way to tell which. The dump distinguishes "nobody is stuck, it was slow"
# from "task N is blocked on an endpoint nobody will ever signal".
#
# Deliberately does NOT halt: halting would prevent a merely-slow boot from going
# on to pass, which is the hypothesis under test. The harness's own timeout still
# fails the boot; this only makes the log say why. Off in the ship kernel.
# EP_QUEUE_SLOTS: depth of each endpoint's bounded FIFO (roadmap 1.3, [I-5]).
#
# 1 degenerates the ring to the single-slot mailbox it replaced, which is how the
# queue's benefit is measured rather than asserted. Each slot costs IPC_MSG_MAX + 8
# bytes per endpoint, so the depth is a real memory/contention trade and belongs in
# a knob rather than buried in a header.
EP_QUEUE_SLOTS ?=
ifneq ($(EP_QUEUE_SLOTS),)
CFLAGS += -DEP_QUEUE_SLOTS=$(EP_QUEUE_SLOTS)
endif

HANG_WATCHDOG ?= 0
HANG_WATCHDOG_TICKS ?= 4000
ifeq ($(HANG_WATCHDOG),1)
CFLAGS  += -DHANG_WATCHDOG -DHANG_WATCHDOG_TICKS=$(HANG_WATCHDOG_TICKS)
ASFLAGS += -DHANG_WATCHDOG
endif

OBJS += src/kernel/lowlevel64.o

all: kernel.elf

RUST_ENABLED := 1
ifneq ($(origin RUST_ENABLED),command line)
RUST_ENABLED := 1
endif

ifeq ($(RUST_ENABLED),1)
  ifeq ($(shell command -v cargo >/dev/null 2>&1 && echo yes),)
    $(error cargo not found. Install Rust: rustup target add $(RUST_TARGET))
  endif
  ifeq ($(shell rustup target list --installed 2>/dev/null | grep -q $(RUST_TARGET) && echo yes),)
    $(error rust target $(RUST_TARGET) missing: rustup target add $(RUST_TARGET))
  endif
endif

RUST_LIB := rust/target/$(RUST_TARGET)/release/libhorus_shell.a

.PHONY: rust
rust:
	@cargo build --release --manifest-path rust/Cargo.toml --target $(RUST_TARGET)
	@test -f $(RUST_LIB) || (echo "ERROR: $(RUST_LIB) missing"; exit 1)

with-rust:
	$(MAKE) RUST_ENABLED=1

ifeq ($(RUST_ENABLED),1)
RUST_EXTRA_OBJS := src/kernel/rust_memory_stubs.o
else
RUST_EXTRA_OBJS := src/kernel/rust_shims.o
endif

# Boot-module hash manifest (audit A4). Generated from the very same BOOT_MODULES
# list the boot.iso rule ships, so the kernel embeds the SHA-256 of exactly the
# payloads it was built to carry and refuses anything else at boot
# (boot_module_verify_all). A build with no modules gets an empty manifest and
# therefore refuses every module it is handed — fail closed.
#
# src/kernel/main.c includes it, so it must exist before any kernel object is
# compiled; the generator rewrites the file only when its content changes, so an
# unchanged module set does not trigger a rebuild. BOOT_MODULE_DEP puts the module
# payloads themselves in the prerequisites: change a shipped binary and the
# manifest (and the kernel) are regenerated.
MODULE_MANIFEST := src/kernel/boot_module_manifest.h

$(MODULE_MANIFEST): tools/gen_module_manifest.sh $(BOOT_MODULE_DEP)
	@tools/gen_module_manifest.sh $@ $(BOOT_MODULES)

src/kernel/main.o: $(MODULE_MANIFEST)
# tpm.c also embeds the manifest (measures it into PCR[8]).
src/kernel/tpm.o: $(MODULE_MANIFEST)

# linker64.ld is a real input to this link (LDFLAGS carries -T linker64.ld), so
# it belongs in the prerequisites: without it, editing the script leaves a stale
# kernel.elf sitting on disk and make reports "up to date".
kernel.elf: $(RUST_LIB) $(OBJS) $(RUST_EXTRA_OBJS) linker64.ld
ifeq ($(RUST_ENABLED),1)
	$(LD) $(LDFLAGS) -o $@ --whole-archive $(RUST_LIB) --no-whole-archive $(OBJS) $(RUST_EXTRA_OBJS)
else
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(RUST_EXTRA_OBJS)
endif

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(AS) $(ASFLAGS) $< -o $@

src/boot/multiboot.o: userspace/shell.bin userspace/init.bin userspace/hello.bin userspace/captest.bin userspace/fs_server.bin userspace/console_server.bin $(ELF_SELFTEST_DEP) $(ELF64_SELFTEST_DEP) $(ASLR_SELFTEST_DEP) $(PREEMPT_SELFTEST_DEP) $(SIGNAL_SELFTEST_DEP) $(TSD_SELFTEST_DEP) $(FS_SELFTEST_DEP) $(INIT_FS_SELFTEST_DEP) $(NEWLIB_SELFTEST_DEP) $(NOTIFY_SELFTEST_DEP) $(MAPPHYS_SELFTEST_DEP) $(IOPORT_SELFTEST_DEP) $(IRQ_SELFTEST_DEP) $(CONSOLE_SELFTEST_DEP) $(RECVBLOCK_SELFTEST_DEP) $(COW_SELFTEST_DEP) $(AP_TRAMPOLINE_DEP) $(SMP_SELFTEST_DEP) $(PROC_SELFTEST_DEP)

# AP startup trampoline: 16-bit real-mode code assembled with -m32 (the .code16
# directive emits the right encodings) and linked flat at its SIPI load address
# 0x8000, then emitted as a raw binary that multiboot.S embeds via .incbin.
src/boot/ap_trampoline.o: src/boot/ap_trampoline.S
	$(CC) -m32 -ffreestanding -fno-pic -x assembler-with-cpp -c $< -o $@
src/boot/ap_trampoline.bin: src/boot/ap_trampoline.o
	$(LD) -m elf_i386 -Ttext=0x8000 --oformat binary -o $@ $<

src/kernel/rust_shims.o: src/kernel/rust_shims.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/rust_stubs.o: src/kernel/rust_stubs.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/rust_memory_stubs.o: src/kernel/rust_memory_stubs.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/storage.o: src/kernel/storage.c
	$(CC) $(CFLAGS) -c $< -o $@

# No -msse2 -maes: that was for a hand-rolled AES-NI cipher this file no longer
# has (see the comment above secure_zero — both the AES-NI and software paths
# were removed; encryption-at-rest is ChaCha20 + HMAC-SHA256 in safe Rust).
# Only cpu_has_aesni() survives, and reporting a CPUID bit needs no SSE. Keeping
# the flags let gcc auto-vectorise this file into xmm the kernel never saves.
src/kernel/crypto.o: src/kernel/crypto.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/ata.o: src/kernel/ata.c
	$(CC) $(CFLAGS) -c $< -o $@

ifeq ($(RUST_ENABLED),1)
$(RUST_LIB): rust/src/lib.rs rust/Cargo.toml rust/src/capability.rs rust/src/crypto.rs rust/src/memory.rs
	@cargo build --locked --release --manifest-path rust/Cargo.toml --target $(RUST_TARGET) || cargo build --release --manifest-path rust/Cargo.toml --target $(RUST_TARGET)
	@test -f $(RUST_LIB) || (echo "ERROR: $(RUST_LIB) missing"; exit 1)
endif

# `run` is the interactive/dev target: it ships the ported coreutils and their man
# pages as boot modules (RUN_MODULES=1 by default), so an interactive session comes
# up with /bin populated and `man` reading /usr/share/man. Set RUN_MODULES=0 for a
# module-free (GPLv3-clean) boot; the plain `boot.iso` / release target stays
# module-free regardless.
RUN_MODULES ?= 1
run: kernel.elf
	@$(MAKE) --no-print-directory COREUTILS_MODULES=$(RUN_MODULES) TCC_MODULE=$(RUN_MODULES) boot.iso
	@echo "Console on this terminal. Quit QEMU with Ctrl-A X; QEMU monitor with Ctrl-A C."
	qemu-system-x86_64 -m 512M -cpu qemu64,+aes,+rdrand,+smep,+smap \
		-smp $(SMP_CPUS) \
		-machine accel=kvm:tcg -display none \
		-serial mon:stdio \
		-device isa-debug-exit,iobase=0x604,iosize=0x04 \
		-net none -no-reboot -no-shutdown -cdrom boot.iso

# Like `run`, but with an emulated TPM 2.0 (swtpm) attached so measured boot
# (roadmap 2.2) engages — you'll see the `[tpm] PCR8=.. PCR9=..` line and, once a
# store opts into TPM sealing, the KEK unseal. Needs swtpm + swtpm_setup.
.PHONY: run-tpm
run-tpm: kernel.elf
	@command -v swtpm >/dev/null 2>&1 || { echo "run-tpm needs swtpm (apt install swtpm)"; exit 1; }
	@$(MAKE) --no-print-directory COREUTILS_MODULES=$(RUN_MODULES) boot.iso
	@D=$$(mktemp -d); swtpm_setup --tpm2 --tpmstate $$D --overwrite >/dev/null 2>&1; \
	 swtpm socket --tpm2 --tpmstate dir=$$D --ctrl type=unixio,path=$$D/sock --daemon --pid file=$$D/pid; \
	 echo "TPM state in $$D. Quit QEMU with Ctrl-A X."; \
	 qemu-system-x86_64 -m 512M -cpu qemu64,+aes,+rdrand,+smep,+smap -smp $(SMP_CPUS) \
	    -machine accel=kvm:tcg -display none -serial mon:stdio \
	    -chardev socket,id=chrtpm,path=$$D/sock -tpmdev emulator,id=tpm0,chardev=chrtpm \
	    -device tpm-tis,tpmdev=tpm0 \
	    -device isa-debug-exit,iobase=0x604,iosize=0x04 \
	    -net none -no-reboot -no-shutdown -cdrom boot.iso; \
	 kill $$(cat $$D/pid) 2>/dev/null; rm -rf $$D


# The @HORUS_MODULES@ marker in grub.cfg is replaced with a `module2` line per
# BOOT_MODULES entry (empty when none), so GRUB loads each utility image into RAM
# alongside the kernel. Modules live outside kernel.elf — the kernel records them
# from the multiboot2 tags and the fs_server installs them into /bin.
boot.iso: kernel.elf grub.cfg $(BOOT_MODULE_DEP)
	@rm -rf isofiles
	@mkdir -p isofiles/boot/grub
	@cp kernel.elf isofiles/boot/kernel.elf
	@cp kernel.elf isofiles/kernel.elf
	@: > isofiles/mods.txt
	@for pair in $(BOOT_MODULES); do \
	    f=$${pair%%:*}; name=$${pair##*:}; base=$$(basename $$f); \
	    cp $$f isofiles/boot/$$base; \
	    printf '    module2 /boot/%s %s\n' "$$base" "$$name" >> isofiles/mods.txt; \
	 done
	@awk '/@HORUS_MODULES@/{while((getline l < "isofiles/mods.txt")>0) print l; next} {print}' \
	    grub.cfg > isofiles/boot/grub/grub.cfg
	@rm -f isofiles/mods.txt
	@grub-mkrescue -o $@ isofiles 2>&1 || (echo "grub-mkrescue failed (install grub-pc-bin xorriso)" && exit 1)
	@rm -rf isofiles

clean: userspace-clean
	rm -f kernel.elf src/boot/*.o src/boot/*.bin src/kernel/*.o src/kernel/rust_*.o
	rm -f src/boot/*.d src/kernel/*.d userspace/*.d
	rm -rf rust/target

clean-rust:
	rm -rf rust/target

iso: kernel.elf
	@mkdir -p iso/boot/grub && cp kernel.elf iso/boot/ && cp grub.cfg iso/boot/grub/grub.cfg
	@grub-mkrescue -o horus.iso iso 2>/dev/null || true

# Userspace is built position-independent (-fPIE): the shipped binaries are
# linked as static-PIE ELFs (ET_DYN) and loaded by the kernel at a randomized
# base (ASLR), which relocates them. GCC's GOTOFF addressing keeps freestanding
# code position-independent (usually zero dynamic relocations). The gated flat
# self-test payloads (preempttest/sigtest) reuse the same objects linked as a
# fixed-base flat image; PIE objects link cleanly at a fixed address too.
# Userspace is 64-bit. -mno-red-zone matches the kernel's own setting: the red
# zone is not safe across an interrupt frame, and a ring-3 task takes interrupts.
USERSPACE_CFLAGS = -m64 -ffreestanding -fPIE -fno-plt -fno-stack-protector \
                   -mno-red-zone -Wall -Wextra -O2 -I include -std=gnu99 -fno-builtin
# IRQ_POLICY_AUDIT changes which syscalls EXIST, so userspace has to be told:
# SYS_IRQ_POLICY_INFO answers SYS_ERR_PERM in an audit build and SYS_ERR_NOSYS in
# a ship build, and captest asserts the exact code. Without this the kernel and
# the test disagree about which kernel they are in — which is precisely how the
# check first failed, and it failed loudly rather than passing on the wrong one.
ifeq ($(IRQ_POLICY_AUDIT),1)
USERSPACE_CFLAGS += -DIRQ_POLICY_AUDIT
endif
USERSPACE_CFLAGS_64 = $(USERSPACE_CFLAGS)
# 32-bit, for the i386 ELF-loader self-test image ONLY (userspace/elftest.o ->
# elftest.elf). Nothing shipped is 32-bit any more, but the loader still parses
# and relocates ELFCLASS32 images, and smoke-elf is the only gate on that path.
# Building the test image with the (now 64-bit) USERSPACE_CFLAGS would silently
# turn smoke-elf into a duplicate of smoke-elf64 and leave the i386 relocator
# untested. See elftest64.o for the 64-bit sibling built from the same source.
USERSPACE_CFLAGS_32 = -m32 -ffreestanding -fPIE -fno-plt -fno-stack-protector \
                      -Wall -Wextra -O2 -I include -std=gnu99 -fno-builtin
# init.c switches to the delegated-fs-server boot path under this flag, so the
# userspace build of init must see it too (kernel CFLAGS alone won't reach it).
ifeq ($(INIT_FS_SELFTEST),1)
USERSPACE_CFLAGS += -DINIT_FS_SELFTEST
endif
ifeq ($(PERSIST_SELFTEST),1)
USERSPACE_CFLAGS += -DPERSIST_SELFTEST
endif
ifeq ($(PERM_SELFTEST),1)
USERSPACE_CFLAGS += -DPERM_SELFTEST
endif
ifeq ($(CONC_SELFTEST),1)
USERSPACE_CFLAGS += -DCONC_SELFTEST
endif
# console_server.c grows a deliberate-fault path under this flag, so its userspace
# build must see it too (kernel CFLAGS alone won't reach it).
ifeq ($(CONSOLE_ISOLATION_TEST),1)
USERSPACE_CFLAGS += -DCONSOLE_ISOLATION_TEST
endif

userspace/%.o: userspace/%.c
	$(CC) $(USERSPACE_CFLAGS) -c $< -o $@

# Static-PIE (ET_DYN) link for the shipped, ASLR-loaded binaries.
# malloc.o is always linked so any binary can call malloc/free without
# extra Makefile rules.
MALLOC_OBJ = userspace/malloc.o
userspace/%.pie.elf: userspace/%.o $(MALLOC_OBJ) userspace/pie.ld
	$(LD) -m elf_x86_64 -pie -T userspace/pie.ld -o $@ $< $(MALLOC_OBJ)

# Newlib-linked PIE ELFs: compiled with newlib headers, linked against libc.a.
# crt0.o provides _start → posix_init() → main().
NEWLIB_INC      = newlib/install/x86_64-elf/include
NEWLIB_LIB      = newlib/install/x86_64-elf/lib
# -I userspace/include supplies the Horus libc extensions newlib lacks (termios,
# sys/ioctl) — after the newlib headers so it only fills gaps, never shadows.
NEWLIB_CFLAGS   = $(USERSPACE_CFLAGS) -I $(NEWLIB_INC) -I userspace/include
NEWLIB_GLUE_OBJS = userspace/newlib_glue.o userspace/newlib_glue64.o \
                   userspace/posix.o userspace/crt0.o

# newlib/ is gitignored -- an upstream dependency, not project source -- so a
# fresh checkout has no libc.a and no newlib headers. Build it on demand rather
# than assuming it: without this, $(NEWLIB_INC) simply does not exist, -I finds
# nothing, and #include <stdio.h> silently falls through to the host's glibc
# headers and fails somewhere confusing. The script no-ops when already built.
$(NEWLIB_LIB)/libc.a:
	@tools/build_newlib.sh

# Everything compiled with NEWLIB_CFLAGS needs the headers that rule installs.
userspace/newlib_glue.o: userspace/newlib_glue.c $(NEWLIB_LIB)/libc.a
	$(CC) $(NEWLIB_CFLAGS) -c $< -o $@

userspace/newlib_glue64.o: userspace/newlib_glue64.c $(NEWLIB_LIB)/libc.a
	$(CC) $(NEWLIB_CFLAGS) -c $< -o $@

# posix.o is shared libc glue linked into every newlib program. It needs the
# Horus termios/ioctl headers (userspace/include) so its struct termios is the
# same one curses/nano see — before the host's, which -ffreestanding does not
# suppress. Explicit rule so the generic userspace/%.o (no such -I) is not used.
userspace/posix.o: userspace/posix.c
	$(CC) $(USERSPACE_CFLAGS) -I userspace/include -c $< -o $@

userspace/crt0.o: userspace/crt0.c
	$(CC) $(USERSPACE_CFLAGS) -c $< -o $@

userspace/hello_newlib.o: userspace/hello_newlib.c $(NEWLIB_LIB)/libc.a
	$(CC) $(NEWLIB_CFLAGS) -c $< -o $@

userspace/hello_newlib.pie.elf: userspace/hello_newlib.o $(NEWLIB_GLUE_OBJS) \
                                userspace/malloc.o userspace/pie.ld
	$(LD) -m elf_x86_64 -pie -T userspace/pie.ld -o $@ \
	    userspace/crt0.o userspace/hello_newlib.o userspace/newlib_glue.o \
	    userspace/newlib_glue64.o userspace/posix.o userspace/malloc.o \
	    -L$(NEWLIB_LIB) -lc

userspace/hello_newlib.bin: userspace/hello_newlib.pie.elf tools/mkheadered
	@./tools/mkheadered $< $@ "hello_newlib"

# termtest — exercises the console raw-terminal layer (termios + winsize + raw
# read/write) end to end; shipped as a /bin module by TERM_MODULE=1 (smoke-term).
userspace/termtest.o: userspace/termtest.c $(NEWLIB_LIB)/libc.a
	$(CC) $(NEWLIB_CFLAGS) -c $< -o $@

userspace/termtest.pie.elf: userspace/termtest.o $(NEWLIB_GLUE_OBJS) \
                            userspace/malloc.o userspace/pie.ld
	$(LD) -m elf_x86_64 -pie -T userspace/pie.ld -o $@ \
	    userspace/crt0.o userspace/termtest.o userspace/newlib_glue.o \
	    userspace/newlib_glue64.o userspace/posix.o userspace/malloc.o \
	    -L$(NEWLIB_LIB) -lc

userspace/termtest.bin: userspace/termtest.pie.elf tools/mkheadered
	@./tools/mkheadered $< $@ "termtest"

# ---- GNU coreutils port (userspace/ports/coreutils) -------------------------
# Unmodified upstream coreutils sources compiled against a small Horus port shim
# (config.h / system.h / assure.h / c-ctype.h / port.c) instead of autoconf +
# gnulib. The upstream .c files are GPLv3 and are NOT edited; the shim is MIT.
# See userspace/ports/coreutils/README.md.
#
# The shim's include dir comes FIRST so its config.h/system.h win over anything
# of the same name, then the newlib headers.
COREUTILS_DIR    = userspace/ports/coreutils
# -ffunction-sections/-fdata-sections + --gc-sections at link time: the shared
# port objects (gnulib.o especially) define far more than any one utility uses
# -- argmatch, xstrtol, the argv iterator, ... -- and without dead-code
# elimination all of it lands in every binary, bloating each by ~150 KiB and
# blowing the kernel image's 16 MiB budget once several are embedded. With it,
# each binary carries only the functions it actually references.
COREUTILS_CFLAGS = $(USERSPACE_CFLAGS) -ffunction-sections -fdata-sections \
                   -I $(COREUTILS_DIR)/port -I $(NEWLIB_INC)

# The port shim: runtime glue (port.o) plus the gnulib-module implementations
# (gnulib.o -- xalloc, inttostr, xstrtol, xdectoint, ...). Both are Horus code
# and compile warning-clean under the full warning set, unlike the vendored
# upstream .c below.
COREUTILS_PORT_OBJS = $(COREUTILS_DIR)/port/port.o $(COREUTILS_DIR)/port/gnulib.o

$(COREUTILS_DIR)/port/port.o: $(COREUTILS_DIR)/port/port.c $(NEWLIB_LIB)/libc.a
	$(CC) $(COREUTILS_CFLAGS) -c $< -o $@

$(COREUTILS_DIR)/port/gnulib.o: $(COREUTILS_DIR)/port/gnulib.c $(NEWLIB_LIB)/libc.a
	$(CC) $(COREUTILS_CFLAGS) -c $< -o $@

# Vendored upstream: compiled as-is. -Wno-unused-parameter because upstream is
# built with its own warning set, and a port must not have to edit the source to
# stay quiet under ours. -Wno-implicit-fallthrough / -Wno-return-type quiet tail.c,
# whose control flow ends functions with error(EXIT_FAILURE, …): gnulib marks that
# path _Noreturn, but the MIT shim's error() cannot be unconditionally noreturn (it
# returns for status 0), so GCC cannot prove the source is unreachable.
$(COREUTILS_DIR)/%.o: $(COREUTILS_DIR)/%.c $(NEWLIB_LIB)/libc.a
	$(CC) $(COREUTILS_CFLAGS) -Wno-unused-parameter -Wno-sign-compare -Wno-type-limits \
	    -Wno-implicit-fallthrough -Wno-return-type -c $< -o $@

userspace/coreutils_%.pie.elf: $(COREUTILS_DIR)/%.o $(COREUTILS_PORT_OBJS) \
                               $(NEWLIB_GLUE_OBJS) userspace/malloc.o userspace/pie.ld
	$(LD) -m elf_x86_64 -pie --gc-sections -T userspace/pie.ld -o $@ \
	    userspace/crt0.o $< $(COREUTILS_PORT_OBJS) \
	    userspace/newlib_glue.o userspace/newlib_glue64.o userspace/posix.o \
	    userspace/malloc.o -L$(NEWLIB_LIB) -lc

# The header's embedded name is what spawn-by-name matches, so it is the plain
# utility name ("cat"), not the coreutils_ file prefix.
userspace/coreutils_%.bin: userspace/coreutils_%.pie.elf tools/mkheadered
	@./tools/mkheadered $< $@ "$*"

# ---- TCC (Tiny C Compiler) port ---------------------------------------------
# Vendored 0.9.27 x86_64 subset (9 units) + a small Horus glue file, linked with
# the same newlib crt0/glue/malloc as the coreutils into a Horus static-PIE.
TCC_DIR   = userspace/ports/tcc
TCC_UNITS = libtcc tccpp tccgen tccelf tccasm x86_64-gen x86_64-link i386-asm tcc
TCC_OBJS  = $(addprefix $(TCC_DIR)/build/,$(addsuffix .o,$(TCC_UNITS))) \
            $(TCC_DIR)/build/horus_glue.o
# Unmodified upstream, compiled -w. Deliberately NO `-I include`: TCC must resolve
# <errno.h>/<stdio.h> to newlib, not the kernel's SYS_ERR_* header. CONFIG_TCC_STATIC
# drops <dlfcn.h>; the -run JIT (tccrun.c) is excluded and its symbols are stubbed
# in port/horus_glue.c. getcwd/file-I/O come from posix.c + newlib_glue*.c.
TCC_CFLAGS = -m64 -ffreestanding -fPIE -fno-plt -fno-stack-protector -mno-red-zone \
             -O2 -std=gnu99 -fno-builtin -w \
             -I $(NEWLIB_INC) -I $(TCC_DIR) -I $(TCC_DIR)/port
TCC_DEFS   = -DTCC_TARGET_X86_64 -DCONFIG_TCC_STATIC -DONE_SOURCE=0 \
             -DCONFIG_TCCDIR='"/usr/lib/tcc"'

$(TCC_DIR)/build/%.o: $(TCC_DIR)/%.c $(NEWLIB_LIB)/libc.a
	@mkdir -p $(TCC_DIR)/build
	$(CC) $(TCC_CFLAGS) $(TCC_DEFS) -c $< -o $@

$(TCC_DIR)/build/horus_glue.o: $(TCC_DIR)/port/horus_glue.c $(NEWLIB_LIB)/libc.a
	@mkdir -p $(TCC_DIR)/build
	$(CC) $(TCC_CFLAGS) $(TCC_DEFS) -c $< -o $@

userspace/tcc.pie.elf: $(TCC_OBJS) $(NEWLIB_GLUE_OBJS) userspace/malloc.o userspace/pie.ld
	$(LD) -m elf_x86_64 -pie --gc-sections -T userspace/pie.ld -o $@ \
	    userspace/crt0.o $(TCC_OBJS) \
	    userspace/newlib_glue.o userspace/newlib_glue64.o userspace/posix.o \
	    userspace/malloc.o -L$(NEWLIB_LIB) -lc

userspace/tcc.bin: userspace/tcc.pie.elf tools/mkheadered
	@./tools/mkheadered $< $@ "tcc"

# Fixed-base flat link (used by the gated selftest payloads that are embedded
# raw and loaded at USER_AREA_BASE without relocation).
userspace/%.elf: userspace/%.o
	$(LD) -m elf_x86_64 -Ttext=0x400000 -o $@ $<

# The ELF-loader self-test image is linked with a custom script that produces
# distinct page-aligned R+X / R+W / R PT_LOAD segments (explicit rule wins over
# the pattern rule above). It is kept as a real ELF, never objcopy-flattened.
# 32-bit on purpose -- the i386 loader/relocator path still exists and this is
# its only gate. See USERSPACE_CFLAGS_32.
userspace/elftest.o: userspace/elftest.c
	$(CC) $(USERSPACE_CFLAGS_32) -c -o $@ $<

userspace/elftest.elf: userspace/elftest.o userspace/elftest.ld
	$(LD) -m elf_i386 -pie -T userspace/elftest.ld -o $@ $<

# The same elftest.c, linked as a 64-bit static-PIE, to exercise the loader's
# x86-64 RELA path (elf_apply_relocations_x86_64). One source for both bitnesses:
# the markers and the selfptr relocation under test are identical, and only the
# pointer width and reloc encoding differ -- which is exactly what is being
# tested. Its _start is never executed: the ELF64 self-test loads and inspects
# the image, then frees the slot, so this needs no 64-bit ring-3 ABI (Stage 3c).
userspace/elftest64.o: userspace/elftest.c
	$(CC) $(USERSPACE_CFLAGS_64) -c -o $@ $<

userspace/elftest64.elf: userspace/elftest64.o userspace/elftest.ld
	$(LD) -m elf_x86_64 -pie -T userspace/elftest.ld -o $@ $<

userspace/%.raw: userspace/%.elf
	objcopy -O binary $< $@

tools/mkheadered: tools/mkheadered.c
	$(CC) -o $@ $<

# Shipped binaries: HORU-wrap the static-PIE ELF (real ELF payload, so the
# kernel's do_spawn routes it through try_elf_load with ASLR + relocations).
SHIPPED_PIE_BINS = userspace/shell.bin userspace/init.bin userspace/hello.bin \
                   userspace/fs_server.bin userspace/captest.bin \
                   userspace/console_server.bin
$(SHIPPED_PIE_BINS): userspace/%.bin: userspace/%.pie.elf tools/mkheadered
	@./tools/mkheadered $< $@ "$*"

# PIE test-only binaries (not shipped): built via the same static-PIE path as
# the shipped bins, but kept out of $(SHIPPED_PIE_BINS)/`userspace`. proctest is
# PIE (not flat) because it dereferences .rodata string literals, which on 32-bit
# -fPIE go through the GOT and only resolve once try_elf_load applies the
# R_386_RELATIVE relocations — the flat load path does not.
PIE_TEST_BINS = userspace/fsclient.bin userspace/proctest.bin userspace/exectest.bin userspace/grantee.bin userspace/sigtarget.bin userspace/faulter.bin userspace/sigwaiter.bin userspace/argtest.bin userspace/notifytest.bin userspace/cowtest.bin userspace/mapphystest.bin userspace/ioporttest.bin userspace/irqtest.bin userspace/consoletest.bin userspace/recvblocksrv.bin userspace/recvblockcli.bin
$(PIE_TEST_BINS): userspace/%.bin: userspace/%.pie.elf tools/mkheadered
	@./tools/mkheadered $< $@ "$*"

# execve-from-fd self-test: embed a real, already-built program image (hello) as
# a C byte array so proctest can hand it to SYS_SPAWN_IMAGE — the same bytes a
# client would read from a file. Generated from the .bin with coreutils only
# (od/tr/grep/paste, present in CI); a PROC_SELFTEST-only prerequisite of proctest.
userspace/hello_image.h: userspace/hello.bin
	@printf 'static const unsigned char hello_image[] = {' > $@
	@od -An -v -tu1 $< | tr -s ' ' '\n' | grep -v '^$$' | paste -sd, >> $@
	@printf '};\nstatic const unsigned hello_image_len = sizeof(hello_image);\n' >> $@

userspace/proctest.o: userspace/hello_image.h

# Flat self-test payloads: HORU-wrap the objcopy'd raw image (loaded flat).
userspace/%.bin: userspace/%.raw tools/mkheadered
	@name="$$(basename $@ .bin)"; ./tools/mkheadered $< $@ "$$name"

userspace: $(SHIPPED_PIE_BINS)

userspace-clean:
	rm -f userspace/*.o userspace/*.elf userspace/*.pie.elf userspace/*.raw userspace/*.bin userspace/*_image.h tools/mkheadered

# Build with the gated CPU-protection self-test and require the kernel to report
# SMEP and SMAP both detected AND present in CR4. smoke_test.sh boots QEMU with
# -cpu qemu64,+smep,+smap, so the features are advertised and "not detected" is a
# bug rather than an honest answer. Runtime proof, because a detection bug reads
# as correct in source and is indistinguishable from a CPU without the feature:
# leaf 7 was queried with a stale ECX for the project's whole history and both
# protections were silently off. No MARKER_ONLY -- the run must print PASS *and*
# still reach the login prompt, so this proves the hardening is on and that
# having it on does not break the boot.
# Build with the gated W^X self-test and require the kernel to report that its
# own image is mapped r-x/r--/rw- AND that no leaf anywhere in the kernel half is
# both writable and executable. The sweep is the point: every hole this policy
# closed was an alias — a second mapping of the same frames — and checking
# .text's own PTE would have caught none of them. No MARKER_ONLY: the run must
# print PASS *and* still reach the login prompt.
# Build with the gated address-space reclaim self-test and require the kernel to
# report that rebuilding a task slot returns the pages the previous occupant
# held. Asserts on the pool count, not on the code path: a reclaim that frees
# only part of the tree still fails.
.PHONY: smoke-aspace
smoke-aspace:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory ASPACE_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='ASPACE_SELFTEST: PASS' \
		FAIL_MARKER='ASPACE_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Drive the generic (non-zero) copy-on-write break end-to-end: a shared, non-zero
# COW frame (refcount 2) aliased by two PTEs; the first write must copy to a
# private frame (content preserved, sibling untouched), the sole-owner write must
# upgrade in place with no new allocation. Gates the privileged page-copy path
# that fork would use but nothing else reaches (previously untested).
.PHONY: smoke-nzcow
smoke-nzcow:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NZCOW_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='NZCOW_SELFTEST: PASS' \
		FAIL_MARKER='NZCOW_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

.PHONY: smoke-wx
smoke-wx:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory WX_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='WX_SELFTEST: PASS' \
		FAIL_MARKER='WX_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# The W^X self-test built SMP=1, booted on multiple cores: the same PASS marker,
# plus the per-CPU AP IST fault-stack guard assertions that only exist (and only
# have an ap_ist array to check) under SMP. The default smoke-wx is single-core
# and does not carry those stacks.
.PHONY: smoke-wx-smp
smoke-wx-smp:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory WX_SELFTEST=1 SMP=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 SMP_CPUS=$(SMP_CPUS) REQUIRE_MARKER='WX_SELFTEST: PASS' \
		FAIL_MARKER='WX_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

.PHONY: smoke-cpu
smoke-cpu:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CPU_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='CPU_SELFTEST: PASS' \
		FAIL_MARKER='CPU_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Per-CPU identity self-test. Boots multi-core and requires every online core to
# have confirmed, on itself, that the TSS-selector derivation in this_cpu()
# agrees with the LAPIC -- the independent oracle it replaced (finding [I-6]).
# Multi-core is the point: on one CPU the mapping (TR - 0x38)/0x10 yields 0 for
# the only right answer, so a UP run cannot fail and the test refuses to pass.
# Also asserts EFER.SCE is clear, keeping the staged SYSCALL path unreachable.
.PHONY: smoke-percpu
smoke-percpu:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PERCPU_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) SMP_CPUS=$(SMP_CPUS) REQUIRE_MARKER='PERCPU_SELFTEST: PASS' \
		FAIL_MARKER='PERCPU_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Flush-on-switch self-test. NOTE: TCG (the CI accelerator -- no KVM) does not
# emulate the IBPB / L1D-flush / MDS CPUID features, so under CI they read absent
# and the gated barriers are skipped (which is exactly why the gating is safe: no
# wrmsr is issued on a CPU that lacks the feature). CI therefore gates the switch
# POLICY (flush on a task change only) and that the flush path runs without
# faulting; the barrier wrmsr/VERW execution and detection-accuracy engage on real
# hardware / KVM, where the log shows `sched: flush-on-switch IBPB L1D MDS`.
.PHONY: smoke-flush
smoke-flush:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FLUSH_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='FLUSH_SELFTEST: PASS' \
		FAIL_MARKER='FLUSH_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# SMT co-residency: boot the shipped kernel under an SMT topology (2 cores x 2
# threads) and assert the two sibling threads are PARKED -- never scheduled -- so
# no untrusted ring-3 work co-resides on a core. Also proves the parked siblings
# + TLB-shootdown accounting do not wedge boot (the marker only appears if the
# system reached the login prompt). Uses the default (shipped) kernel; parking is
# always-on, not a build flag.
.PHONY: smoke-smt
smoke-smt:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) QEMU_SMP='4,cores=2,threads=2' \
		REQUIRE_MARKER='SMT siblings parked' \
		FAIL_MARKER='SMT_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

.PHONY: smoke-stackguard
smoke-stackguard:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory STACKGUARD_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='STACKGUARD_SELFTEST: PASS' \
		FAIL_MARKER='STACKGUARD_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build the kernel with the gated ELF-loader self-test, boot it headless, and
# require the in-kernel self-test to report PASS on serial (in addition to the
# normal boot reaching userspace). Runtime-verifies the try_elf_load + W^X path.
.PHONY: smoke-elf
smoke-elf:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory ELF_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='ELF_SELFTEST: PASS' \
		FAIL_MARKER='ELF_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

smoke-elf64:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory ELF64_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='ELF64_SELFTEST: PASS' \
		FAIL_MARKER='ELF64_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Image-base ASLR: spawn several PIE images and assert the load base actually
# varies and stays inside the premap-containment bound (ASLR_SELFTEST: PASS).
.PHONY: smoke-aslr
smoke-aslr:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory ASLR_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='ASLR_SELFTEST: PASS' \
		FAIL_MARKER='ASLR_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated preemption self-test, boot headless, and require the
# in-kernel test to report PASS -- runtime proof that the timer time-slices two
# non-yielding ring-3 tasks.
.PHONY: smoke-preempt
smoke-preempt:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PREEMPT_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='PREEMPT_SELFTEST: PASS' \
		FAIL_MARKER='PREEMPT_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated signal self-test, boot headless, and require the handler
# to run on a deliberate fault -- runtime proof that a ring-3 fault is delivered
# to a registered handler instead of killing the task.
.PHONY: smoke-signal
smoke-signal:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SIGNAL_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='SIGNAL_SELFTEST: PASS' \
		FAIL_MARKER='SIGNAL_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated TSD self-test, boot headless, and require the marker that
# proves a ring-3 RDTSC faulted into its handler (CR4.TSD engaged).
smoke-tsd:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory TSD_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='TSD_SELFTEST: PASS' \
		FAIL_MARKER='TSD_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated E820 self-test, boot headless, and require the marker
# proving the physical pool was sized from the multiboot2 memory map (boots to
# the login prompt as normal and asserts the marker along the way).
smoke-e820:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory E820_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='E820_SELFTEST: PASS' \
		FAIL_MARKER='E820_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated filesystem self-test, boot headless, and require the
# client to report PASS -- runtime proof that the userspace fs_server serves a
# client over IPC against the kernel's encrypted object store. `STORAGE=ata`
# runs the same test against a real ATA disk image (the persistent backend).
ifeq ($(STORAGE),ata)
SMOKE_FS_FLAGS = STORAGE_ATA=1
SMOKE_FS_ENV   = SMOKE_DISK=horus-fs.img
SMOKE_FS_PREP  = dd if=/dev/zero of=horus-fs.img bs=512 count=$(BLOCKS_PER_DISK) status=none
# Sizes the test ATA disk image; MUST match the kernel's volume, so read the
# authoritative value straight from the C #define rather than duplicating it (a
# stale copy silently truncates the image below the on-disk layout the kernel
# formats, which fails only once the volume is large enough to notice).
BLOCKS_PER_DISK ?= $(shell grep -oE '#define[[:space:]]+BLOCKS_PER_DISK[[:space:]]+[0-9]+' src/include/kernel.h | grep -oE '[0-9]+')
else
SMOKE_FS_FLAGS =
SMOKE_FS_ENV   =
SMOKE_FS_PREP  = true
endif
.PHONY: smoke-fs
smoke-fs:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FS_SELFTEST=1 $(SMOKE_FS_FLAGS)
	@$(MAKE) --no-print-directory boot.iso
	@$(SMOKE_FS_PREP)
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 $(SMOKE_FS_ENV) REQUIRE_MARKER='FS_SELFTEST: PASS' \
		FAIL_MARKER='FS_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Boot-time FS integration test: ring-3 init brings up the fs_server by delegation
# (SYS_CAP_GRANT) and the delegated server serves the client end-to-end. Reuses
# the fs client's PASS/FAIL markers ("INIT_FS_SELFTEST: FAIL ..." also matches the
# FAIL substring). `STORAGE=ata` runs it against the persistent ATA backend.
.PHONY: smoke-init-fs
smoke-init-fs:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory INIT_FS_SELFTEST=1 $(SMOKE_FS_FLAGS)
	@$(MAKE) --no-print-directory boot.iso
	@$(SMOKE_FS_PREP)
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 $(SMOKE_FS_ENV) REQUIRE_MARKER='FS_SELFTEST: PASS' \
		FAIL_MARKER='FS_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Reboot-survival test: boot twice against ONE persistent ATA disk image. Boot 1
# writes a sentinel file (PERSIST_SELFTEST: WROTE); boot 2, on the same image,
# reads it back and verifies it byte-for-byte (PERSIST_SELFTEST: PASS) — proving
# the encrypted object store and its per-block crypto metadata (nonces/tags)
# survive a reboot. Argon2id KEK derivation + format-on-first-boot run under TCG,
# so allow a generous timeout.
# Same as BLOCKS_PER_DISK above: sized from the kernel's C #define so the two-boot
# persistent-disk images are never smaller than the volume the kernel formats.
PERSIST_BLOCKS  ?= $(shell grep -oE '#define[[:space:]]+BLOCKS_PER_DISK[[:space:]]+[0-9]+' src/include/kernel.h | grep -oE '[0-9]+')
PERSIST_TIMEOUT ?= 300
.PHONY: smoke-fs-persist
smoke-fs-persist:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PERSIST_SELFTEST=1 STORAGE_ATA=1 HANG_WATCHDOG=1 HANG_WATCHDOG_TICKS=6000
	@$(MAKE) --no-print-directory boot.iso
	@dd if=/dev/zero of=persist.img bs=512 count=$(PERSIST_BLOCKS) status=none
	@echo "[persist] boot 1/2 — write sentinel to a fresh encrypted disk"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=persist.img \
		REQUIRE_MARKER='PERSIST_SELFTEST: WROTE' FAIL_MARKER='PERSIST_SELFTEST: FAIL' \
		tools/smoke_test.sh boot.iso
	@echo "[persist] boot 2/2 — verify the file survived (same disk image)"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=persist.img \
		REQUIRE_MARKER='PERSIST_SELFTEST: PASS' FAIL_MARKER='PERSIST_SELFTEST: FAIL' \
		tools/smoke_test.sh boot.iso
	@echo "[persist] PASS — encrypted file survived a reboot"

# Zero-trust ownership & permissions: root builds a scenario, the client then
# re-authenticates as a non-root user and the fs_server enforces owner/group/other
# rwx against the caller's kernel-attested uid (denied reads/writes/creates/chmod
# it isn't entitled to; owner and root allowed). Proves a client cannot access
# what its real uid disallows.
.PHONY: smoke-fs-perms
smoke-fs-perms:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PERM_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='PERM_SELFTEST: PASS' \
		FAIL_MARKER='PERM_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Multi-client concurrency: one fs_server, several clients hammering it at once,
# each verifying it receives its own replies (no cross-talk, no lost replies).
# The coordinator prints CONC_SELFTEST: PASS only after every worker completes.
# Journal crash-recovery: boot QEMU twice against one disk image. Boot 1 commits a
# write to the journal and halts BEFORE applying it (simulating a crash); boot 2
# replays the committed transaction at mount and confirms the write survived —
# proving redo recovery (and that a mid-write crash can't brick or corrupt the fs).
.PHONY: smoke-fs-wal
smoke-fs-wal:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory WAL_CRASHTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@dd if=/dev/zero of=wal.img bs=512 count=$(PERSIST_BLOCKS) status=none
	@echo "[wal] boot 1/2 — commit a write, then crash before applying it"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=wal.img \
		WAIT_FOR_EXIT=1 \
		REQUIRE_MARKER='WAL_CRASHTEST: crashed-after-commit' FAIL_MARKER='WAL_CRASHTEST: FAIL' \
		tools/smoke_test.sh boot.iso
	@echo "[wal] boot 2/2 — recover the committed transaction, verify the data"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=wal.img \
		REQUIRE_MARKER='WAL_CRASHTEST: PASS' FAIL_MARKER='WAL_CRASHTEST: FAIL' \
		tools/smoke_test.sh boot.iso
	@echo "[wal] PASS — committed transaction replayed after a crash"

# smoke-fs-wal-flush — the [I-10] durability gate.
#
# smoke-fs-wal above proves the REDO LOGIC is correct. It cannot say anything
# about DURABILITY, because it runs under cache=writethrough where QEMU commits
# every guest write to the host image on its own. Switching it to cache=writeback
# would not help either: guest writes then land in the host PAGE CACHE, which
# outlives the QEMU process, so killing QEMU still loses nothing and a kernel
# with no FLUSH CACHE at all passes identically. There is no cache mode in which
# "did the guest flush?" changes the outcome of a two-boot test.
#
# So invert the observation: make the flush FAIL and watch the kernel react.
# blkdebug returns EIO for every flush_to_disk; a kernel with the barriers issues
# the command, sees the error, and refuses the transaction out loud. The
# WAL_NO_FLUSH=1 control arm issues no command, so no error is ever raised and
# the message never appears — which is what makes this falsifiable rather than
# decorative. Run `make smoke-fs-wal-flush-control` to see it fail on demand.
#
# SMOKE_DISK_CACHE=writeback is REQUIRED here and is not a preference. Under
# cache=writethrough QEMU implements each guest write as a write followed by a
# flush, so an error injected on flush_to_disk fails ORDINARY WRITES too: the
# volume cannot be formatted, storage_unlock fails, and the guest never reaches a
# journal commit at all. The gate then times out having tested nothing.
#
# That is not hypothetical — it is how this target failed in CI on its first run
# (PR #158, `WAL_CRASHTEST: FAIL unlock`) while passing locally, because QEMU
# 10.0.11 satisfies writethrough with O_DSYNC and emits no flush_to_disk per
# write, whereas the runner's older QEMU emits one. Under writeback a write is
# just a write, so the only flush_to_disk events are the guest's own FLUSH CACHE
# commands — exactly, and only, what this gate is trying to observe.

# Assert every ci.yml job is classified as merge-gating or exempted with a
# reason ([C-6]). Pure text analysis -- no build, no QEMU -- so it costs nothing
# to run before opening a PR, which is when the answer still matters.
.PHONY: check-gating
check-gating:
	@tools/check_ci_gating.py

.PHONY: smoke-fs-wal-flush
smoke-fs-wal-flush:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory WAL_CRASHTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@dd if=/dev/zero of=wal-flush.img bs=512 count=$(PERSIST_BLOCKS) status=none
	@echo "[wal-flush] every FLUSH CACHE fails with EIO; the journal must refuse to commit"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=wal-flush.img \
		SMOKE_DISK_BLKDEBUG=tools/blkdebug-flush-eio.conf SMOKE_DISK_CACHE=writeback \
		REQUIRE_MARKER='WAL: FLUSH FAILED before commit header' \
		FAIL_MARKER='WAL_CRASHTEST: crashed-after-commit' \
		tools/smoke_test.sh boot.iso
	@echo "[wal-flush] PASS — the commit record is flushed, and the flush's result is checked"

# The control arm for the gate above: the same run against a kernel built with
# the barriers compiled out. The refusal marker MUST NOT appear. If this target
# passes, smoke-fs-wal-flush is not testing what it claims to.
.PHONY: smoke-fs-wal-flush-control
smoke-fs-wal-flush-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory WAL_CRASHTEST=1 WAL_NO_FLUSH=1
	@$(MAKE) --no-print-directory boot.iso
	@dd if=/dev/zero of=wal-flush-control.img bs=512 count=$(PERSIST_BLOCKS) status=none
	@echo "[wal-flush-control] barriers compiled out: the refusal must NOT appear"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=wal-flush-control.img \
		SMOKE_DISK_BLKDEBUG=tools/blkdebug-flush-eio.conf SMOKE_DISK_CACHE=writeback \
		REQUIRE_MARKER='WAL_CRASHTEST: crashed-after-commit' \
		ABSENT_MARKER='WAL: FLUSH FAILED' \
		tools/smoke_test.sh boot.iso
	@echo "[wal-flush-control] PASS — the defect reproduces: no flush is issued, nothing objects"

# smoke-fs-wal-order — the [I-10] ORDERING gate.
#
# smoke-fs-wal-flush proves a flush is issued and its result checked. It cannot
# prove the flush is in the right place, and place is the whole property: a
# barrier after the commit header instead of before it passes error injection
# identically while losing the write-ahead rule outright. This traces the IDE
# command register and asserts the commit sequence ends
#   0x30 (data) -> 0xe7 (barrier A) -> 0x30 (header) -> 0xe7 (barrier B).
# tools/smoke_test.sh fails closed if this QEMU has no trace backend, so the
# assertion can never pass by observing nothing.
.PHONY: smoke-fs-wal-order
smoke-fs-wal-order:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory WAL_CRASHTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@dd if=/dev/zero of=wal-order.img bs=512 count=$(PERSIST_BLOCKS) status=none
	@rm -f wal-order.trace
	@echo "[wal-order] tracing IDE commands through one journal commit"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=wal-order.img \
		SMOKE_TRACE=ide_ioport_write SMOKE_TRACE_FILE=wal-order.trace \
		REQUIRE_MARKER='WAL_CRASHTEST: crashed-after-commit' \
		FAIL_MARKER='WAL_CRASHTEST: FAIL' \
		tools/smoke_test.sh boot.iso
	@tools/check_wal_order.sh wal-order.trace
	@echo "[wal-order] PASS — the barriers bracket the commit record in the right order"

# Control arm for the ordering gate: barriers compiled out, so no 0xe7 is ever
# issued and check_wal_order.sh must FAIL. Inverted with `!` so the target
# succeeds only when the checker rejects the defective build.
.PHONY: smoke-fs-wal-order-control
smoke-fs-wal-order-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory WAL_CRASHTEST=1 WAL_NO_FLUSH=1
	@$(MAKE) --no-print-directory boot.iso
	@dd if=/dev/zero of=wal-order-control.img bs=512 count=$(PERSIST_BLOCKS) status=none
	@rm -f wal-order-control.trace
	@echo "[wal-order-control] barriers compiled out: the ordering check must REJECT this"
	@SMOKE_TIMEOUT=$(PERSIST_TIMEOUT) MARKER_ONLY=1 SMOKE_DISK=wal-order-control.img \
		SMOKE_TRACE=ide_ioport_write SMOKE_TRACE_FILE=wal-order-control.trace \
		REQUIRE_MARKER='WAL_CRASHTEST: crashed-after-commit' \
		tools/smoke_test.sh boot.iso
	@if tools/check_wal_order.sh wal-order-control.trace; then \
		echo "[wal-order-control] FAIL — the checker accepted a kernel with no barriers"; \
		exit 1; \
	else \
		echo "[wal-order-control] PASS — the defect reproduces and the checker rejects it"; \
	fi

# CONC_SELFTEST drives several concurrent clients through the fs_server and waits
# for all of them, so it runs longer than the single-client smoke tests the 40s
# default was sized for. On a loaded machine it exceeded that budget and failed as
# a TIMEOUT with no CONC_SELFTEST: FAIL -- i.e. the test never reached a verdict,
# which reads as a red gate but is not evidence of a defect. Give it its own
# budget, as smoke-fs-persist / smoke-fs-wal already do with PERSIST_TIMEOUT.
#
# This is a max-wait, not a sleep: a healthy run still finishes in seconds, so the
# larger budget costs nothing when things are working and only buys headroom when
# the host is starved. It deliberately does NOT weaken the verdict -- a real
# CONC_SELFTEST: FAIL still fails immediately, and a genuine hang still fails,
# just after a wait long enough to distinguish "hung" from "slow".
CONC_TIMEOUT ?= 120
.PHONY: smoke-fs-conc
smoke-fs-conc:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CONC_SELFTEST=1 HANG_WATCHDOG=1 HANG_WATCHDOG_TICKS=6000
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(CONC_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='CONC_SELFTEST: PASS' \
		FAIL_MARKER='CONC_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Supply-chain falsification: prove the pinned newlib SHA-256 actually refuses a
# tampered artifact, and still accepts the genuine one.
#
# tools/build_newlib.sh downloads a 9 MiB tarball and pins its hash. That pin is
# the only thing between a compromised upstream and the libc every userspace
# binary links against. An unexercised pin is an assumption, not a control -- and
# the failure mode is silent, because a gate that has quietly stopped checking
# looks exactly like a gate that has nothing to reject.
#
# Runs both directions: bad bytes must be refused (before unpacking, with the
# artifact quarantined so it cannot wedge the next build), and the genuine
# tarball must pass -- because a gate that refuses everything would sail through
# the negative case alone. Needs no network for the negative control.
.PHONY: smoke-newlib-tamper
smoke-newlib-tamper:
	@tools/newlib_tamper_test.sh

.PHONY: smoke-newlib
smoke-newlib:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NEWLIB_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='NEWLIB_SELFTEST: PASS' \
		FAIL_MARKER='NEWLIB_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the vendored GNU coreutils utilities and run them at boot as ring-3
# tasks. The required marker is produced by UPSTREAM's own code path -- echo
# joins its argv with spaces and expands the -e escapes (\x20 -> space,
# \x21 -> '!'), while basename/dirname exercise their real path splitting -- so a
# pass means genuine third-party source ran correctly on Horus, not that we
# printed a string. See userspace/ports/coreutils/README.md.
# Build with the gated capability/syscall conformance test and require its
# marker. The checks are overwhelmingly negative -- a kernel that granted
# everything would fail this, which a "does the call work" test would not catch.
.PHONY: smoke-captest
smoke-captest:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='CAPTEST: PASS' \
		FAIL_MARKER='CAPTEST: FAIL' tools/smoke_test.sh boot.iso

# Modules + residency gate: ship ALL ported coreutils as GRUB boot modules, boot
# normally, and prove (a) every one is provisioned into /bin FROM the modules (not
# baked into the kernel image — the transport proof, each a ~450-610 KiB image
# reaching the filesystem without living in the 16 MiB kernel image), and (b) all
# of them fit at once on the 16 MiB store volume (no "did not fit"), which is what
# the multi-block bitmap + off-.bss vdisk + hierarchical meta-MAC deliver. Then it
# runs printf and tail from /bin. Uses the default COREUTILS_MODULE_SET (all).
# See tools/modules_session.py.
# Boot-module integrity gate (audit A4). Builds the kernel WITH the module hash
# manifest embedded, then assembles a second ISO carrying the same kernel but one
# CORRUPTED module payload (one byte flipped, size unchanged, so only the SHA-256
# differs) and boots that. The kernel must refuse exactly the tampered module and
# still come up — proving the manifest check is what stops an altered ISO from
# planting a root-owned binary in /bin, rather than that being trusted to the boot
# chain. Falsification-tested: with the verification removed, the tampered module
# provisions happily and this test goes green-to-red.
.PHONY: smoke-modules-tamper
smoke-modules-tamper:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1 tamper.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='boot module refused (no manifest match)' \
		tools/smoke_test.sh tamper.iso
	@rm -f tamper.iso

# Staged only by smoke-modules-tamper, and only ever under COREUTILS_MODULES=1 —
# BOOT_MODULES is empty otherwise, and a "tampered" ISO with no modules would
# prove nothing.
tamper.iso: kernel.elf grub.cfg $(BOOT_MODULE_DEP)
	@tools/tamper_module_iso.sh $@ kernel.elf grub.cfg $(BOOT_MODULES)

# Measured boot (roadmap 2.2): boot under an emulated TPM (swtpm) and assert the
# PCR[8]/PCR[9] the kernel measured into the TPM equal the values recomputed on
# the host from the reproducible boot-module manifest. External verification of
# the boot hash chain, not the guest's own word. Skips cleanly where swtpm is
# absent.
.PHONY: smoke-tpm
smoke-tpm:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) tools/smoke_tpm.sh boot.iso

# Falsification twin: tamper one module payload, boot under the TPM, and require
# that the module is refused AND that the measured PCRs DIVERGE from the clean
# manifest — proof the measurement reflects what actually loaded. Neuter the
# measurement (or the A4 check) and this goes green-to-red.
.PHONY: smoke-tpm-tamper
smoke-tpm-tamper:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1 tamper.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_MISMATCH=1 tools/smoke_tpm.sh tamper.iso
	@rm -f tamper.iso

# Seal/unseal round-trip (roadmap 2.2 stage 2): build the TPM_SELFTEST kernel,
# boot under an emulated TPM, and require the in-kernel seal-then-unseal test to
# report PASS — runtime proof the PolicyPCR seal path works end-to-end.
.PHONY: smoke-tpm-seal-roundtrip
smoke-tpm-seal-roundtrip:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1 TPM_SELFTEST=1
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1 TPM_SELFTEST=1 boot.iso
	@SWTPM_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='TPM_SEAL_SELFTEST: PASS' \
		FAIL_MARKER='TPM_SEAL_SELFTEST: FAIL' \
		tools/run_with_swtpm.sh boot.iso

# TPM-sealed vdisk KEK (roadmap 2.2 stage 3): boot the TPM_KEK_SELFTEST kernel
# under an emulated TPM and require the in-kernel test to PASS — proof that a
# measured-good boot unlocks the sealed volume and a changed PCR[9] leaves it
# locked (the TPM, not our code, enforces the release).
.PHONY: smoke-tpm-seal
smoke-tpm-seal:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1 TPM_KEK_SELFTEST=1
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1 TPM_KEK_SELFTEST=1 boot.iso
	@SWTPM_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='TPM_KEK_SELFTEST: PASS' \
		FAIL_MARKER='TPM_KEK_SELFTEST: FAIL' \
		tools/run_with_swtpm.sh boot.iso

.PHONY: smoke-modules
smoke-modules:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1 boot.iso
	@SESSION_TIMEOUT=$(SMOKE_TIMEOUT) tools/modules_session.py boot.iso

# Ship head/seq/wc as GRUB modules and drive them through the REAL ring-3 shell
# over serial: create a file, run head/wc/seq on it and assert the counts and
# lines. This exercises the whole path a user takes -- the shell resolving
# /bin/<name>, loading the ~450-610 KiB image over the fs_server, spawning it with
# argv, the utility opening a file through its own fs_server connection, and
# waiting for it to finish -- all from a filesystem, not the kernel image.
.PHONY: smoke-coreutils-shell smoke-tcc
smoke-coreutils-shell:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1 COREUTILS_MODULE_SET="head seq wc"
	@$(MAKE) --no-print-directory COREUTILS_MODULES=1 COREUTILS_MODULE_SET="head seq wc" boot.iso
	@SESSION_TIMEOUT=$(SMOKE_TIMEOUT) tools/coreutils_session.py boot.iso

# smoke-tcc ships the ported Tiny C Compiler as a boot module, has the fs_server
# provision it into /bin, then runs `tcc -v` through the real ring-3 shell and
# asserts on tcc's own version banner — proving /bin/tcc loads and runs on Horus.
# The ~1 MiB image loads slowly over the fs_server, so this uses a longer budget.
smoke-tcc:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory TCC_MODULE=1
	@$(MAKE) --no-print-directory TCC_MODULE=1 boot.iso
	@SESSION_TIMEOUT=$(SMOKE_TIMEOUT) tools/tcc_session.py boot.iso

# smoke-term proves the console raw-terminal layer (termios raw mode, TIOCGWINSZ,
# raw read/write through the ring-3 console_server) by running termtest from /bin,
# sending it one key over serial, and asserting on the geometry + key + PASS.
.PHONY: smoke-term
smoke-term:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory TERM_MODULE=1
	@$(MAKE) --no-print-directory TERM_MODULE=1 boot.iso
	@SESSION_TIMEOUT=$(SMOKE_TIMEOUT) tools/term_session.py boot.iso

# Build with the gated large-file self-test, boot headless, and require the
# in-kernel test to report PASS -- runtime proof that a single inode can map
# blocks through the double-indirect region (large files) on the encrypted
# object store, and that freeing the whole tree succeeds.
.PHONY: smoke-pipe
smoke-pipe:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PIPE_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='PIPE_SELFTEST: PASS' \
		FAIL_MARKER='PIPE_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

.PHONY: smoke-fs-large
smoke-fs-large:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory BIGFILE_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='BIGFILE_SELFTEST: PASS' \
		FAIL_MARKER='BIGFILE_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated SMP self-test, boot headless under -smp 4, and require the
# in-kernel test to report PASS -- runtime proof that the application processors
# come online and concurrently run scheduled user tasks. SMP_CPUS drives QEMU's
# core count.
SMP_CPUS ?= 4
.PHONY: smoke-smp
smoke-smp:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SMP_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 SMP_CPUS=$(SMP_CPUS) REQUIRE_MARKER='SMP_SELFTEST: PASS' \
		FAIL_MARKER='SMP_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated process-control self-test, boot headless, and require the
# in-kernel driver to report PASS -- runtime proof that SYS_EXIT and SYS_KILL
# terminate tasks (a self-exiting child and a killed child both reach dead).
.PHONY: smoke-proc
smoke-proc:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@# Require the LAST marker proctest prints. The '+signal' marker is emitted by
	@# sigtarget partway through; requiring it let the harness kill QEMU before the
	@# closing spawn-suspend witness ever ran, so that check was dead code. The
	@# suspend marker strictly follows it (proctest waits for sigtarget to exit
	@# first), so requiring it proves the whole chain completed.
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='PROC_SELFTEST: suspend OK' \
		FAIL_MARKER='PROC_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated notification self-test, boot headless, and require the
# in-kernel waiter to report PASS -- runtime proof that SYS_NOTIFY delivers a
# badge to a task blocked in SYS_WAIT_NOTIFY (async notifications end-to-end).
.PHONY: smoke-notify
smoke-notify:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NOTIFY_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='NOTIFY_SELFTEST: PASS' \
		FAIL_MARKER='NOTIFY_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated map-phys self-test, boot headless, and require the ring-3
# probe to report PASS -- runtime proof that a CAP_IO_DEVICE-endowed task can map
# the allowlisted VGA framebuffer into its own address space (SYS_MAP_PHYS) and
# that the mapping is the real device frame, while an off-list frame is refused.
# First driver-privilege-separation job; see docs/proposals/console-server.md.
.PHONY: smoke-mapphys
smoke-mapphys:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory MAPPHYS_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='MAPPHYS_SELFTEST: PASS' \
		FAIL_MARKER='MAPPHYS_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated port-I/O self-test, boot headless, and require the ring-3
# probe to report PASS -- runtime proof that a CAP_IO_DEVICE-endowed task granted
# native port I/O (TSS I/O bitmap) can read an allowlisted console port while a
# non-allowlisted port still #GPs. Second driver-privilege-separation job; see
# docs/proposals/console-server.md.
.PHONY: smoke-ioport
smoke-ioport:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory IOPORT_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='IOPORT_SELFTEST: PASS' \
		FAIL_MARKER='IOPORT_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated IRQ-notification self-test, boot headless, and require the
# ring-3 probe to report PASS -- runtime proof that a CAP_IO_DEVICE-endowed task
# can route a hardware IRQ (the timer) to an async notification (SYS_IRQ_REGISTER)
# and be woken by a real interrupt. Third driver-privilege-separation job; see
# docs/proposals/console-server.md.
.PHONY: smoke-irq
smoke-irq:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory IRQ_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='IRQ_SELFTEST: PASS' \
		FAIL_MARKER='IRQ_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated ring-3 console-server self-test, boot headless, and require
# the client's line to appear on serial -- runtime proof that a ring-3
# console_server, owning the console hardware (SYS_MAP_PHYS + SYS_IOPORT_GRANT),
# served a client's write over IPC and drove the serial port itself. First J5
# cutover milestone; see docs/proposals/console-server.md.
.PHONY: smoke-console
smoke-console:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CONSOLE_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='CONSOLE_SELFTEST: PASS' \
		FAIL_MARKER='CONSOLE_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated console blast-radius test, boot headless, and require the
# marker proving the ring-3 console_server's deliberate fault was contained (the
# kernel stayed alive to print it). Phase 6 close-out; see docs/proposals/console-server.md.
.PHONY: smoke-console-isolation
smoke-console-isolation:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CONSOLE_ISOLATION_TEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='CONSOLE_ISOLATION: PASS' \
		FAIL_MARKER='CONSOLE_ISOLATION: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated copy-on-write self-test, boot headless, and require that a
# write to a read-only shared-zero page breaks COW into a private page without
# disturbing its sibling (COW_SELFTEST: PASS).
.PHONY: smoke-cow
smoke-cow:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory COW_SELFTEST=1
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='COW_SELFTEST: PASS' \
		FAIL_MARKER='COW_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Scripted integration session: build the shipped kernel and drive the *real*
# ring-3 shell over serial (login, identity, and a capability-gated admin op
# allowed for root but denied for a standard user), asserting on the responses.
# Unlike the marker self-tests, nothing is compiled into the kernel — it is a
# black-box test of the actual login/shell/syscall path. Prints SESSION_TEST: PASS.
.PHONY: smoke-session
smoke-session:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory boot.iso
	@python3 tools/session_test.py boot.iso

# Regression guard for the SMP console-INPUT corruption: drive the real ring-3
# shell over serial under -smp 4. Where smoke-console-smp covers console *output*
# (the doubled banner), this covers the interactive round-trip — login, coreutils,
# least-privilege checks. The bug it guards: a blocking SYS_IPC_CALL whose peer was
# busy on another core had no task to switch to, so the kernel resumed the caller
# with a fabricated zero-length reply instead of blocking. The shell then read a
# stale reply buffer, so typed usernames/passwords arrived empty or truncated and
# logins failed intermittently (roughly half the time under -smp 4). The fix idles
# the CPU (ipc_block_switch -> enter_cpu_idle) so the cross-core reply lands and a
# timer tick reschedules the woken caller. The per-step timeout absorbs 4-core TCG
# emulation slowness (no KVM in CI): -smp 4 oversubscribes a 2-vCPU GitHub runner,
# so a step that is ~1s locally can stall for many seconds when the runner is
# starved. 60s proved marginal (a loaded runner blew past it on the apropos step,
# reddening main after #93 with no code fault — the test passes cleanly locally), so
# the budget is 120s. It is a max-wait, not a sleep, so green runs are unaffected.
.PHONY: smoke-session-smp
smoke-session-smp:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory boot.iso
	@QEMU_SMP=4 SESSION_TIMEOUT=120 python3 tools/session_test.py boot.iso

# Soak of the above. The IPC lost-reply race this gates against (see CHANGES.md:
# a reply delivered while the client was committed to blocking but not yet
# visibly blocked was dropped AND reported to the server as delivered) wedged the
# shell mid-print on roughly 1 boot in 5. A single run therefore MISSES it four
# times out of five — which is exactly how it survived: every individual smoke
# job was green most of the time, and the one that wasn't looked like flakiness.
#
# N boots give 1 - 0.8^N detection: 89% at 10, 96% at 15, 99.6% at 25. Measured
# against the pre-fix kernel it failed 9 times in 45 interleaved boots; the fixed
# kernel was 25/25 and 0 failures across every soak since.
#
# This is the honest gate for a probabilistic defect: one boot cannot witness it,
# so the test does not pretend a single green boot is evidence. Requires ALL runs
# to pass — one hang is a failure, never a retry.
#
# ---- FINDING G-8 (2026-08-09 - 2026-08-17): closed, and this soak gates again ---
#
# For eight days a residual failure survived here at roughly 2-3% per boot, and
# this comment carried the two candidate explanations -- a genuine kernel wedge, or
# the apropos step exceeding its budget on a starved host -- because a failure rate
# is not a diagnosis. It was the first.
#
# A switch path published the outgoing task as claimable while the CPU making the
# switch was still executing ISR C frames on that task's kernel stack. Another CPU
# took it, resumed it to ring 3, and its next trap re-entered the ISR on the same
# stack at the same depth, rewriting the frames the first CPU had not finished
# reading -- including the resume %rsp on its way to the epilogue. See
# scheduler.c's note at percpu_deferred_release[], and `make smoke-kstack-race`
# plus its control arm, which reproduce it on demand instead of at 1 boot in 150.
#
# The rate, paired and adjacent-boot alternating over 1600 boots at -smp 4: the
# pre-fix release site 31/800, the shipped deferred release 0/800, Fisher exact
# two-sided p = 6.9e-10. That is the number this comment has demanded since
# 2026-08-09, and the CI job is GATING again as of 2026-08-17.
#
# It stays a soak rather than a single boot: the class of defect it covers is
# probabilistic, and one green boot says nothing about a 2-3% event -- which is
# exactly how the lost-reply race passed every green smoke job. Never re-run it.
# The failing run's serial log is kept, which is why the loop below stopped
# sending output to /dev/null.
SOAK_RUNS ?= 15
# Minimum [ok] steps a run must report before it counts as a pass.
#
# A green exit status is not evidence that the work happened. If session_test.py
# ever degrades -- an expect loop that matches nothing, a step list that silently
# empties -- it can exit 0 having proven nothing, and a soak built on exit status
# alone would report N/N green over N boots that tested air. So each run must
# also emit the SESSION_TEST: PASS marker AND clear this floor; a run that exits
# 0 with too few checks is reported as VACUOUS and fails the gate, which is the
# loudest possible version of "this test stopped testing".
#
# Set below the current step count (~14 under SMP) so ordinary additions do not
# trip it, but far enough above zero to catch a collapse.
SOAK_MIN_CHECKS ?= 8
# Where a failing run's evidence is kept. The soak used to reuse ONE mktemp log,
# overwrite it every iteration, delete it at the end, and print `tail -20` of the
# failure -- so the diagnostic was destroyed by the harness that observed it.
# G-8 is rare enough that this cost real reproduction cycles: on #142, CI caught
# an occurrence and retained "PAGE FAULT at 0x525c71a094 err=" and nothing else.
# Each run now writes the FULL serial via SESSION_SERIAL_LOG (which session_test.py
# has always supported and nothing set); passing runs are deleted, failing ones
# are kept with their stdout beside them. CI uploads this directory.
SOAK_EVIDENCE_DIR ?= soak-evidence
.PHONY: smoke-session-smp-soak
smoke-session-smp-soak:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory boot.iso
	@echo "[soak] $(SOAK_RUNS) boots; any single hang fails the gate"
	@echo "[soak] evidence from failing runs is kept in $(SOAK_EVIDENCE_DIR)/"
	@rm -rf $(SOAK_EVIDENCE_DIR); mkdir -p $(SOAK_EVIDENCE_DIR); \
	fail=0; vacuous=0; log=$$(mktemp); \
	for i in $$(seq 1 $(SOAK_RUNS)); do \
	    rc=0; n=$$(printf '%03d' $$i); \
	    ser=$(SOAK_EVIDENCE_DIR)/run-$$n.serial.log; \
	    QEMU_SMP=4 SESSION_TIMEOUT=120 SESSION_SERIAL_LOG="$$ser" \
	        python3 tools/session_test.py boot.iso >"$$log" 2>&1 || rc=$$?; \
	    checks=$$(grep -c '\[ok\]' "$$log" 2>/dev/null || echo 0); \
	    if [ $$rc -eq 0 ] && grep -q 'SESSION_TEST: PASS' "$$log" && [ "$$checks" -ge $(SOAK_MIN_CHECKS) ]; then \
	        echo "[soak] run $$i/$(SOAK_RUNS): pass ($$checks checks)"; \
	        rm -f "$$ser"; \
	    else \
	        cp "$$log" $(SOAK_EVIDENCE_DIR)/run-$$n.stdout.log; \
	        if [ $$rc -eq 0 ] && grep -q 'SESSION_TEST: PASS' "$$log"; then \
	            echo "[soak] run $$i/$(SOAK_RUNS): VACUOUS - exited 0 with only $$checks checks (expected >= $(SOAK_MIN_CHECKS))"; \
	            vacuous=$$((vacuous+1)); \
	        else \
	            echo "[soak] run $$i/$(SOAK_RUNS): FAIL (exit $$rc, $$checks checks)"; \
	            fail=$$((fail+1)); \
	        fi; \
	        echo "----- run $$n, last 20 lines (FULL serial: $$ser) -----"; tail -20 "$$log"; \
	        grep -aiE 'EXCEPTION|PAGE FAULT|PANIC|claim:|rip=|rsp=' "$$ser" 2>/dev/null \
	            | sed 's/^/  [fault] /' | head -20; \
	        echo "------------------------------------------------------"; \
	    fi; \
	done; rm -f "$$log"; \
	if [ $$fail -ne 0 ] || [ $$vacuous -ne 0 ]; then \
	    echo "SESSION_SOAK: FAIL $$fail/$(SOAK_RUNS) hung, $$vacuous/$(SOAK_RUNS) vacuous"; \
	    echo "SESSION_SOAK: evidence retained in $(SOAK_EVIDENCE_DIR)/ ($$(ls $(SOAK_EVIDENCE_DIR) | wc -l) files)"; \
	    exit 1; \
	fi; \
	rmdir $(SOAK_EVIDENCE_DIR) 2>/dev/null || true; \
	echo "SESSION_SOAK: PASS $(SOAK_RUNS)/$(SOAK_RUNS) boots completed the session (>= $(SOAK_MIN_CHECKS) checks each)"

# Regression guard for the SMP console-output corruption: boot the SHIPPED kernel
# (no self-test flag) under -smp 4 and require it to reach the ring-3 login banner
# intact. This is the multi-core case the default smoke test never exercised —
# with SMP the default, the kernel's print() and the ring-3 console_server both
# drove the same COM1 UART + VGA buffer, so on different cores every byte came out
# twice, interleaved ("HHoorruuss ... MMiiccrrookkeerrnneell"). Two things fail a
# regressed kernel here: the clean banner substring "Horus Secure Microkernel"
# never appears (it is broken up by the doubling) so the run times out, and the
# doubled signature trips FAIL_MARKER for a fast, explicit failure. The fix makes
# the console single-writer (console ownership handed to the ring-3 server; the
# kernel's print() stops touching the hardware while a ring-3 owner is live).
.PHONY: smoke-console-smp
smoke-console-smp:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) SMP_CPUS=$(SMP_CPUS) FAIL_MARKER='HHoorruuss' \
		tools/smoke_test.sh boot.iso

# Same boot, N times, on ONE build, with QEMU pinned to a small host CPU set.
#
# smoke-console-smp guards the ring-3 startup handshake, and the failure modes it
# is meant to catch are races: they show up in a fraction of boots and not at all
# on an idle many-core host, where each guest vCPU gets a core of its own and the
# window never opens. A single green run of the target above is therefore weak
# evidence about a scheduling change -- which is exactly the evidence roadmap 1.1
# will be leaning on when it instruments this handshake.
#
# STRESS_RUNS boots, STRESS_CPUSET host CPUs (default 2, matching a CI runner),
# STRESS_MAX_FAIL permitted failures (default 0). See tools/stress_boot.sh.
.PHONY: smoke-console-smp-stress
smoke-console-smp-stress:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory
	@$(MAKE) --no-print-directory boot.iso
	@SMP_CPUS=$(SMP_CPUS) SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) FAIL_MARKER='HHoorruuss' \
		tools/stress_boot.sh boot.iso

# The same startup handshake with the scheduler's claim invariant machine-checked
# (SCHED_INVARIANTS=1): a violation panics naming the task, the CPU and the site,
# turning "the boot hung and everything still looks RUNNABLE" into an attributable
# failure.
#
# This target used to be documented as "expected to fail", reporting
#
#   stale scheduler claim: task 1 claimed by cpu N but that cpu was running 4
#
# in about one boot in five. That was NOT a scheduler defect. Task 1 is `init` and
# task 4 is the shell it was in the middle of SPAWNING: do_spawn installs the child
# as the CPU's current task for the whole ELF load so the loader's copy_to_user
# lands in the child's address space, while init stays correctly claimed by that
# CPU. The auditor was reading a deliberate impersonation as a leak. Declaring the
# window (sched_impersonate_enter/exit, scheduler.c) took it from 10 failures in 20
# to 0 in 30, pinned. See TESTS.md.
#
# A single boot is weak evidence for an intermittent scheduling bug -- the lesson
# smoke-console-smp cost -- so CI gates on the -stress variant below, which reports
# a rate. Use this one for a quick local check while working on the scheduler.
# Roadmap 1.1 step 2: assert IF at the boot milestones so a change to interrupt
# policy cannot arrive silently. The expectations are MEASURED (all zero today),
# not designed -- see the note above irq_expect[] in scheduler.c. When step 3
# lands the IF-preserving lock some will change, and the diff will have to say so.
# Roadmap 1.1 step 2b: the supported way to MEASURE the audit, as opposed to
# smoke-irq-policy below, which GATES the boot window.
#
# Not a CI check -- it produces a number, and a number is not a pass/fail. It is
# here so the measurement is reproducible and so nobody re-derives it by making
# the kernel print at the UART again, which is what corrupted every earlier
# figure (see the note above IRQ_POLICY_QUIET in scheduler.c). Quiet is the
# default, so the kernel writes nothing and the counters come back in band.
.PHONY: measure-irq-policy
measure-irq-policy:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory IRQ_POLICY_AUDIT=1
	@$(MAKE) --no-print-directory IRQ_POLICY_AUDIT=1 boot.iso
	@python3 tools/irq_policy_measure.py boot.iso

.PHONY: smoke-irq-policy
smoke-irq-policy:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory IRQ_POLICY_AUDIT=1 IRQ_POLICY_QUIET=0
	@$(MAKE) --no-print-directory IRQ_POLICY_AUDIT=1 IRQ_POLICY_QUIET=0 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='IRQ_POLICY: PASS' FAIL_MARKER='IRQ_POLICY: FAIL' \
		tools/smoke_test.sh boot.iso

# Can the kernel be heard when it faults in its own code?
#
# The inverse of every other smoke target: it wants a kernel fault, and fails if
# the kernel takes one quietly. KFAULT_INJECT makes it fault on purpose once a
# ring-3 console_server owns the console -- the state in which print() reaches
# only the klog -- and tools/kfault_test.sh requires the report to appear on
# serial AFTER the login prompt.
.PHONY: smoke-heap64
# Roadmap 1.5 / finding [I-2]: the heap syscalls and the pager's region gate must
# be 64-bit clean. Latent on the default base -- every heap sits under 100 MiB --
# so this builds with USER_HEAP_HIGH_BASE=1, which puts the heap at 8 GiB and
# makes the truncation REACHABLE. captest exercises sbrk/brk directly and then
# writes to the page it was given, so it covers both the arithmetic and the
# demand-paging path.
#
# The control arm is the point, and it is available on demand: build this target
# from a tree without the 1.5 fix and captest reports CAPTEST: FAIL
# (sbrk-grow-failed) rather than passing quietly. See TESTS.md.
smoke-heap64:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 USER_HEAP_HIGH_BASE=1
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 USER_HEAP_HIGH_BASE=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='CAPTEST: PASS' \
		FAIL_MARKER='CAPTEST: FAIL' tools/smoke_test.sh boot.iso

.PHONY: smoke-kfault
smoke-kfault:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory KFAULT_INJECT=1
	@$(MAKE) --no-print-directory KFAULT_INJECT=1 boot.iso
	@KFAULT_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_REPORT=1 tools/kfault_test.sh boot.iso

# The control arm. Same injection, reporting restored to println(): the report
# must NOT reach serial. A gate whose failing arm has never been built is not
# evidence that the passing arm measures anything.
.PHONY: smoke-kfault-legacy
smoke-kfault-legacy:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory KFAULT_INJECT=1 KFAULT_LEGACY_PRINTLN=1
	@$(MAKE) --no-print-directory KFAULT_INJECT=1 KFAULT_LEGACY_PRINTLN=1 boot.iso
	@KFAULT_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_REPORT=0 tools/kfault_test.sh boot.iso

# Does the resume-%rsp floor guard in idt.c actually fire, and can it be heard?
#
# Until this existed, every "the guard did not catch it" statement about G-8 was
# an inference from an absent line, and an absent line proves nothing about an
# instrument never shown to be capable of speaking. The natural event is ~1 boot
# in 150, so this does not wait for it: RESUME_RSP_INJECT forces the dispatcher
# to return a bogus resume %rsp of 4 -- G-8's own recorded value -- once, after
# the console handover, and the guard's PANIC line must reach serial after the
# login prompt.
#
# Three arms, because one of them alone would not be evidence. See TESTS.md.
RESUME_GUARD_RE = PANIC: dispatcher returned a bogus resume rsp=0x4

.PHONY: smoke-resume-guard
smoke-resume-guard:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 boot.iso
	@KFAULT_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_REPORT=1 \
		REPORT_RE='$(RESUME_GUARD_RE)' REPORT_LABEL='bogus resume rsp' \
		tools/kfault_test.sh boot.iso

# The arm that witnesses the fix. Same injection, but the permanent panic claim
# is taken first -- the state another CPU's FATAL exception leaves behind, and
# the exact state of the 2026-08-13 capture, where cpu 3 halted holding it. The
# guard used to report under kfault_begin(1), which loses that claim and halts
# WITHOUT PRINTING; build this target with that bracket restored and it fails.
.PHONY: smoke-resume-guard-preclaim
smoke-resume-guard-preclaim:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 RESUME_RSP_INJECT_PRECLAIM=1
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 RESUME_RSP_INJECT_PRECLAIM=1 boot.iso
	@KFAULT_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_REPORT=1 \
		REPORT_RE='$(RESUME_GUARD_RE)' REPORT_LABEL='bogus resume rsp' \
		tools/kfault_test.sh boot.iso

# Control arm for the FIX. Same injection, same preclaim, but the guard's pre-fix
# kfault_begin(1)/kfault_end(1) bracket restored: the permanent claim is already
# held, so this CPU halts without emitting a byte and the report must NOT appear.
# That is the defect, on demand -- and it is what makes smoke-resume-guard-preclaim
# a measurement rather than a story about one capture.
.PHONY: smoke-resume-guard-legacy
smoke-resume-guard-legacy:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 RESUME_RSP_INJECT_PRECLAIM=1 \
		RESUME_GUARD_LEGACY_FATAL=1
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 RESUME_RSP_INJECT_PRECLAIM=1 \
		RESUME_GUARD_LEGACY_FATAL=1 boot.iso
	@KFAULT_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_REPORT=0 \
		REPORT_RE='$(RESUME_GUARD_RE)' REPORT_LABEL='bogus resume rsp' \
		tools/kfault_test.sh boot.iso

# Control arm for the GUARD: same injected value, guard compiled out. The PANIC
# line must NOT appear -- this is G-8's silence, reproduced on demand.
.PHONY: smoke-resume-guard-nofloor
smoke-resume-guard-nofloor:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 RESUME_GUARD_DISABLE=1
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 RESUME_GUARD_DISABLE=1 boot.iso
	@KFAULT_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_REPORT=0 \
		REPORT_RE='$(RESUME_GUARD_RE)' REPORT_LABEL='bogus resume rsp' \
		tools/kfault_test.sh boot.iso

# Two CPUs on one kernel stack -- finding G-8, and the gate that closes it.
#
# A switch path hands the outgoing task to another CPU while the CPU making the
# switch still has ~30 instructions of ISR epilogue to run ON THAT TASK'S KERNEL
# STACK. A CPU that takes the task inside that window resumes it to ring 3, and
# its next trap re-enters the ISR on the same stack at the same depth running the
# same functions -- so it rewrites exactly the words the first CPU has not
# finished reading. See scheduler.c's note at percpu_deferred_release[].
#
# The window is a few tens of instructions wide, which is why the natural event
# is G-8's ~2-3% per boot and why two 150-boot arms were needed to observe it
# once. KSTACK_RACE_WIDEN=1 stretches it with a spin, so BOTH arms answer in one
# boot each:
#
#   smoke-kstack-race          widened window, deferred release (shipped):
#                              the claim is held across the window, nothing can
#                              take the stack, and the session completes.
#   smoke-kstack-race-control  widened window, PRE-FIX release site: another CPU
#                              takes the stack and the detector says so.
#
# The control arm is the load-bearing one. Without it, the first arm proves only
# that a kernel with a spin in it still boots. With it, the same widened window
# is fatal without the fix and harmless with it, which is the difference between
# a measurement and a story -- and this file has already paid for that lesson
# twice on this finding.
#
# Note what the control arm's own report shows about why G-8 resisted diagnosis:
# `claim: task 4 running_cpu=0 percpu_current=[4,0,0,0]` -- the scheduler claim
# invariant HOLDS while two CPUs are on one kernel stack, because the task really
# is running on exactly one CPU. The other one is merely still leaving. That is
# bit-for-bit the observation that retired the shared-stack hypothesis in
# TESTS.md, and it was never evidence against it.
KSTACK_RACE_RE = PANIC: two CPUs on one kernel stack
# Per-step budget for the widened session. The widening costs real time, and this
# is deliberately far above what it needs on a fast host: a REQUIRED gate that goes
# red because a CI runner was slow teaches the re-run reflex, which is the habit
# this repo blames for smoke-console-smp surviving months of CI. Generous costs
# nothing when the session is fast.
KSTACK_RACE_TIMEOUT ?= 600

.PHONY: smoke-kstack-race
smoke-kstack-race:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory KSTACK_RACE_WIDEN=1 boot.iso
	@echo "[kstack] widened window + deferred release: the session must complete"
	@log=$$(mktemp); rc=0; \
	QEMU_SMP=4 SESSION_TIMEOUT=$(KSTACK_RACE_TIMEOUT) SESSION_SERIAL_LOG="$$log" \
	    python3 tools/session_test.py boot.iso || rc=$$?; \
	if grep -qa '$(KSTACK_RACE_RE)' "$$log"; then \
	    echo "KSTACK RACE: FAIL - two CPUs shared a kernel stack with the fix in place"; \
	    grep -a -A 6 '$(KSTACK_RACE_RE)' "$$log" | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	fi; \
	if [ $$rc -ne 0 ]; then \
	    echo "KSTACK RACE: FAIL - session did not complete under the widened window (exit $$rc)"; \
	    tail -20 "$$log" | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	fi; \
	rm -f "$$log"; \
	echo "KSTACK RACE: PASS - session completed, no shared kernel stack"

# The defect, on demand. Same widened window, pre-fix release site. Two things
# must be true and both are checked: the detector's line must appear, AND the
# session must not pass -- a build that reproduced the race and still reported
# success would mean the harness had stopped reading the wire.
.PHONY: smoke-kstack-race-control
smoke-kstack-race-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory KSTACK_RACE_WIDEN=1 KSTACK_RELEASE_EARLY=1 boot.iso
	@echo "[kstack] widened window + PRE-FIX release: the race must reproduce"
	@log=$$(mktemp); rc=0; \
	QEMU_SMP=4 SESSION_TIMEOUT=$(KSTACK_RACE_TIMEOUT) SESSION_SERIAL_LOG="$$log" \
	    python3 tools/session_test.py boot.iso || rc=$$?; \
	if ! grep -qa '$(KSTACK_RACE_RE)' "$$log"; then \
	    echo "KSTACK RACE CONTROL: FAIL - the pre-fix build did NOT reproduce the race."; \
	    echo "  The control arm is what makes smoke-kstack-race a measurement; if it"; \
	    echo "  stops reproducing, the widened window or the detector has decayed."; \
	    tail -20 "$$log" | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	fi; \
	if [ $$rc -eq 0 ]; then \
	    echo "KSTACK RACE CONTROL: FAIL - the race reproduced but the session reported PASS"; \
	    rm -f "$$log"; exit 1; \
	fi; \
	grep -a -A 6 '$(KSTACK_RACE_RE)' "$$log" | head -8 | sed 's/^/  /'; \
	rm -f "$$log"; \
	echo "KSTACK RACE CONTROL: PASS - the pre-fix release site shares a kernel stack, as it must"

# Roadmap 1.3: the blocking receive really sleeps, and the wake really carries
# the reply right. See RECVBLOCK_SELFTEST above for what the markers mean.
.PHONY: smoke-recvblock
smoke-recvblock:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory RECVBLOCK_SELFTEST=1
	@$(MAKE) --no-print-directory RECVBLOCK_SELFTEST=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='RECVBLOCK_SELFTEST: PASS' \
		FAIL_MARKER='RECVBLOCK_SELFTEST: FAIL' \
		tools/smoke_test.sh boot.iso

# The same gate under -smp 4. The interesting half of the blocking receive is a
# CROSS-CPU wake: the sender completes the receive, so the reply right has to be
# minted into a cspace that is not the current one, and the woken server can be
# picked up by another CPU the instant its state flips. On one CPU that ordering
# cannot be wrong in a way anything observes, which is exactly why the first
# version of this feature passed every single-CPU gate and still hung under load.
# This does not RELIABLY catch that race -- see TESTS.md for the loaded
# reproduction that does -- but it is the cheap part, and it costs one boot.
.PHONY: smoke-recvblock-smp
smoke-recvblock-smp:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory RECVBLOCK_SELFTEST=1
	@$(MAKE) --no-print-directory RECVBLOCK_SELFTEST=1 boot.iso
	@SMP_CPUS=4 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='RECVBLOCK_SELFTEST: PASS' \
		FAIL_MARKER='RECVBLOCK_SELFTEST: FAIL' \
		tools/smoke_test.sh boot.iso

.PHONY: smoke-sched-invariants
smoke-sched-invariants:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SCHED_INVARIANTS=1
	@$(MAKE) --no-print-directory SCHED_INVARIANTS=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) SMP_CPUS=$(SMP_CPUS) FAIL_MARKER='PANIC:' \
		tools/smoke_test.sh boot.iso

# The gating form: N pinned boots of the claim-checking kernel, reported as a rate.
#
# STRESS_RUNS defaults to 30. Sizing it needs a per-boot failure rate to reason
# from, and the honest one to use is the LOWEST observed, not the most convenient:
# the violation this gates ran at 10 in 20 pinned to two host cores locally, but
# was historically reported at ~1 boot in 5 in CI. Take 20%:
#
#   10 boots  ->  1 - 0.8^10 = 89%    (better than one run, but ~1 regression in 9
#                                      would still merge green)
#   30 boots  ->  1 - 0.8^30 = 99.8%
#
# 30 costs about 90 seconds -- the job builds once and each boot exits on its
# marker in ~2.5s -- so there is no reason to buy the weaker number. An earlier
# version of this comment claimed 10 boots put a miss "below one in a thousand",
# which was arithmetic done against the 50% local rate and wrong for the runner
# this actually gates.
.PHONY: smoke-sched-invariants-stress
smoke-sched-invariants-stress:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SCHED_INVARIANTS=1
	@$(MAKE) --no-print-directory SCHED_INVARIANTS=1 boot.iso
	@STRESS_RUNS=$${STRESS_RUNS:-30} SMP_CPUS=$(SMP_CPUS) SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) \
		FAIL_MARKER='PANIC:' STRESS_GATE=marker tools/stress_boot.sh boot.iso

.PHONY: test
# The local sweep: the Rust unit tests, then a clean full build.
#
# The `cargo test` line used to end in `|| true`, so every one of the Rust unit
# tests -- including the capability-algebra tests that are the named witness for
# SECURITY.md S2..S5 -- could fail while `make test` exited 0. CI was never
# affected (the `rust` job runs cargo test directly and is a required check), so
# the only thing it misled was a developer running the command the README tells
# them to run. That is the same defect #154 removed from the `security` CI job:
# a gate that structurally cannot fail reads as coverage while providing none.
#
# This is deliberately NOT the full self-test sweep -- it does not boot QEMU. Run
# the `smoke-*` targets for that; `make smoke` is the shortest useful one.
test:
	cargo test --manifest-path rust/Cargo.toml --release
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory all

# Headless QEMU smoke-boot test: boot the kernel and confirm it reaches the
# ring-3 shell banner with no fault/panic on serial. SMOKE_TIMEOUT overrides
# the wait (seconds).
SMOKE_TIMEOUT ?= 40
.PHONY: smoke
# Clean-build like every sibling smoke-* target, and for the same reason. As a
# plain `boot.iso` dependency this booted whatever kernel the *previous* target
# happened to leave behind: run `make smoke-newlib && make smoke` and boot.iso is
# already newer than its prerequisites, so make rebuilds nothing and `smoke`
# silently tests the NEWLIB_SELFTEST kernel. That reads as a spurious failure
# here (it times out waiting for the shell banner), but the same staleness can
# just as easily report a pass for a kernel the sources no longer describe.
# CI never saw it -- each job is a fresh checkout -- so it only bites locally,
# which is exactly where a misleading result costs the most debugging.
smoke:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) tools/smoke_test.sh boot.iso

.PHONY: reproducible-build verify-build
reproducible-build:
	@rm -f kernel.elf boot.iso
	@SOURCE_DATE_EPOCH=1609459200 $(MAKE) --no-print-directory clean all
	@sha256sum kernel.elf boot.iso > .build.sha 2>/dev/null || true
	@echo "Reproducible build recorded."

verify-build: reproducible-build
	@echo "Verify complete."

.PHONY: security security-install semgrep trivy gitleaks cppcheck flawfinder cargo-audit

security: semgrep trivy gitleaks cppcheck flawfinder cargo-audit
	@echo ""
	@echo "✅ Security scan complete."
	@echo "   Review all output above for findings."
	@echo "   High-severity issues should be fixed before merging."

security-install:
	@echo "Installing security tools (this may require sudo)..."
	sudo apt-get update
	sudo apt-get install -y cppcheck flawfinder
	# Semgrep
	pipx install semgrep || pip install --user semgrep
	# Trivy (official install script)
	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
	# gitleaks (via Go)
	go install github.com/gitleaks/gitleaks@latest || echo "⚠️  Install Go to get gitleaks binary"
	# cargo-audit for Rust
	cargo install cargo-audit || true
	@echo "Installation finished. You may need to add ~/.local/bin or /usr/local/bin to your PATH."

semgrep:
	@echo "=== Semgrep (C + Rust + security rules) ==="
	command -v semgrep >/dev/null 2>&1 || pipx install semgrep
	semgrep --version
	semgrep --config=auto --config=p/ci --error .

trivy:
	@echo "=== Trivy (secrets + misconfigs + vulns) ==="
	command -v trivy >/dev/null 2>&1 || (curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin)
	trivy --version
	trivy fs --scanners vuln,secret,misconfig .

gitleaks:
	@echo "=== gitleaks (secrets in git history) ==="
	command -v gitleaks >/dev/null 2>&1 || \
	( \
		GITLEAKS_VERSION=8.30.1; \
		curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v$${GITLEAKS_VERSION}/gitleaks_$${GITLEAKS_VERSION}_linux_x64.tar.gz | \
		sudo tar -xz -C /usr/local/bin gitleaks \
	)
	gitleaks detect --source . --verbose || true

cppcheck:
	@echo "=== cppcheck (C static analysis) ==="
	command -v cppcheck >/dev/null 2>&1 || sudo apt-get install -y cppcheck
	cppcheck --version
	cppcheck --enable=all --inconclusive --suppress=missingIncludeSystem src/ include/ rust/ 2>&1 | head -80 || true

flawfinder:
	@echo "=== flawfinder (C/C++ security weaknesses) ==="
	command -v flawfinder >/dev/null 2>&1 || pipx install flawfinder || pip install flawfinder
	flawfinder --version
	flawfinder src/ include/ 2>&1 | head -60 || true

cargo-audit:
	@echo "=== cargo-audit (Rust dependency advisories) ==="
	(cd rust && cargo audit) || echo "cargo-audit not installed or no advisories found"

# Header dependencies generated by -MMD (see CFLAGS). Must come after all rules.
-include $(OBJS:.o=.d) $(RUST_EXTRA_OBJS:.o=.d)
