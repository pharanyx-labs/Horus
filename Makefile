CC     = gcc
LD     = ld
OBJCOPY = objcopy
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


# ---- defect-flag provenance -------------------------------------------------
#
# Two problems, one mechanism.
#
# (1) A -D flag is NOT a prerequisite of an object file. `make FLAG=1` then
#     `make` without `clean` leaves every unchanged .c compiled WITH the flag,
#     and the build says nothing. On 2026-08-20 that produced a measurement
#     campaign whose kernel still carried KSP_GUARD_INJECT: the [G-9] guard
#     "fired" in 2 of 3 boots with the injected constant, which for a few minutes
#     looked like a reproduction of the very defect being hunted. It was caught
#     because -7 is implausibly exact and 67% is implausibly high -- i.e. by
#     luck, not by method.
#
# (2) A serial transcript did not say which flags produced it, so a log could not
#     be audited after the fact. Every measurement in this project is read off
#     the wire, which makes that a hole in the evidence rather than a nicety.
#
# So: the whole kernel CFLAGS string is stamped into .build-flags, every object
# depends on it, and a change forces a rebuild -- covering ALL flags, not just
# the defect ones. And the active defect flags are compiled in as a string the
# kernel prints at boot, so a transcript is self-describing.
#
# DEFECT_FLAGS is the list from docs/BUILDING.md's "Defect-reproducing builds"
# table. Adding a control arm means adding it here in the same commit, exactly
# as CLAUDE.md already requires for that table.
DEFECT_FLAGS = \
	IRQ_LEGACY_GLOBAL_LOCK USER_HEAP_HIGH_BASE \
	KFAULT_INJECT KFAULT_LEGACY_PRINTLN \
	KSTACK_RELEASE_EARLY KSTACK_RACE_WIDEN KSTACK0_SHARED_PARK KSTACK0_PARK_TRACE \
	RESUME_GUARD_FLOOR_ONLY RESUME_GUARD_BSS_ONLY RESUME_GUARD_DISABLE \
	RESUME_GUARD_LEGACY_FATAL RESUME_RSP_INJECT RESUME_RSP_INJECT_PRECLAIM \
	CR3_RECLAIM_UNGUARDED EXEC_REENTER_GLOBAL \
	SPAWN_OWNER_UNCHECKED SPAWN_STAGE_UNSERIALISED SPAWN_STAGE_WIDEN SPAWN_STAGE_TRACE \
	REPRO_SHA_UNCHECKED WAL_NO_FLUSH WAL_CRASHTEST \
	KLOG_WRITE_UNGATED SYSCALL_PTR_TRUNC32 KSP_GUARD_INJECT KSP_GUARD_ALWAYS \
	BUILD_FLAGS_UNSTAMPED SYSCALL_COVERAGE \
	LIBHORUS_RETRY_ANY LIBHORUS_STRNCPY_UNTERMINATED CLAIM_TRACE CLAIM_RELEASE_SKIP SWITCH_COMMIT_EARLY DEFER_CLEAR_EARLY DEFER_WINDOW_WIDEN \
	FRAME_INDEX_UNCHECKED FRAME_RIGHTS_UNCHECKED FRAME_REGION_NO_ROLLBACK FRAME_REGION_ROLLBACK_WIDE \
	FRAME_PAGES_SAME_PHYS FRAME_INFO_BY_INDEX COW_ARENA_UNGUARDED RAMFS_SLOT3_GATE \
	FORK_SHARE_WRITABLE FORK_ARENA_UNCHECKED \
	FORK_CSPACE_FLAT_COPY FORK_CSPACE_ORPHAN_COPY \
	EXEC_RESET_CSPACE EXEC_ROOT_CSPACE \
	FPU_NO_SAVE FPU_NO_RESTORE \
	VFS_FIRST_MATCH VFS_MOUNT_UNGATED \
	RNG_UNSEEDED_PROBE RNG_UNSEEDED_LEGACY \
	POSIX_LEGACY_WALK HVFS_DOTDOT_SERVER \
	MEASURED_BOOT_REQUIRED MEASURED_VOLUME_EXEMPT_NONE \
	LEGACY_SYSCALLS_PRESENT CAP_ENUMERATE_UNGATED CLOCK_TSC_RESOLUTION \
	TASKINFO_WIDE_AUTHORITY GETLINE_SLOT3_FALLBACK CAP_LOOKUP_ASSERT_HANG \
	IOMMU_NO_FRAME_TEARDOWN IOMMU_NO_TASK_TEARDOWN \
	IO_DEVICE_OBJECT_UNCHECKED IO_DEVICE_PORTS_GLOBAL IO_DEVICE_IRQ_UNCHECKED \
	IO_DEVICE_CAP_UNCHECKED NET_NO_BUSMASTER NET_NO_DECODE \
	DMA_ADDR_FRAME_ONLY NET_IOMMU_NO_MAP IRQ_NO_MASK_ON_FIRE IRQ_ACK_UNGATED \
	IRQ_FORCE_PIC POLL_NOTIFY_UNGATED MSI_VECTOR_FROM_USER MSIX_TABLE_MAPPABLE \
	SHLIB_TEXT_WRITABLE SHLIB_DATA_SHARED SHLIB_DATA_UNINITIALISED \
	SHLIB_BASE_FIXED SHLIB_INFO_UNGATED SHLIB_INFO_TYPE_ONLY

# Active = set to 1. EP_QUEUE_SLOTS is a DEPTH rather than a boolean and is
# listed separately: its defect arm is the value 1 (a single-slot endpoint, the
# pre-[I-5] shape), and any other value is an ordinary build.
# Deferred (`=`, not `:=`): the flag variables get their `?= 0` defaults further
# down this file, so an immediate expansion here would evaluate them before they
# exist. Command-line settings are visible either way; deferring is what makes an
# in-file default correct too.
DEFECT_ACTIVE = $(strip \
	$(foreach f,$(DEFECT_FLAGS),$(if $(filter 1,$($(f))),$(f))) \
	$(if $(filter 1,$(EP_QUEUE_SLOTS)),EP_QUEUE_SLOTS))
DEFECT_ACTIVE_STR = $(if $(DEFECT_ACTIVE),$(DEFECT_ACTIVE),none)
CFLAGS += -DDEFECT_FLAGS_STR='"$(DEFECT_ACTIVE_STR)"'

# `all` stays the default goal. This block introduces the first explicit targets
# in the file, and in make the FIRST target wins by default -- without this,
# plain `make` silently stopped building the kernel and only printed a flag list.
# Everything downstream (make iso, make smoke, CI) still worked, because those
# name their targets, which is exactly why it would have gone unnoticed.
.DEFAULT_GOAL := all

# What flags would this build carry? Answers without building anything, so a
# measurement script can record the configuration it is about to boot.
.PHONY: print-defect-flags
print-defect-flags:
	@echo "$(DEFECT_ACTIVE_STR)"

# A -D flag is not a prerequisite of an object file, so `make FLAG=1` followed by
# `make` leaves stale objects compiled with the flag and says nothing. Stamping
# the flag strings into a file that every object depends on makes any change to
# them a rebuild. The whole CFLAGS/ASFLAGS strings are stamped, not just the
# defect list -- the failure is generic and so is the fix.
#
# Rewritten only when the content differs, so it does not itself force a rebuild
# on every invocation.
.build-flags: FORCE
	@printf '%s\n%s\n' '$(CFLAGS)' '$(ASFLAGS)' > $@.tmp; \
	 cmp -s $@.tmp $@ || mv $@.tmp $@; \
	 rm -f $@.tmp
.PHONY: FORCE
FORCE:


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
       src/kernel/syscall_vm.o \
       src/kernel/storage.o \
       src/kernel/crypto.o \
       src/kernel/tpm.o \
       src/kernel/pipe.o \
       src/kernel/untyped.o \
       src/kernel/pci.o \
       src/kernel/iommu.o \
       src/kernel/ioapic.o \
       src/kernel/msi.o \
       src/kernel/shlib.o \
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

# KLOG_FORGE_SELFTEST=1 embeds klogtest and, at boot, spawns it endowed with a
# CAP_KERNEL_LOG capability (READ -- that is the only right root_cnode[15] mints,
# and delegation may only narrow). The probe reads the kernel message ring, floods
# SYS_WRITE fd 1 with 28800 bytes -- more than the 16 KiB ring holds -- and reads
# the ring again: it must contain none of the flood and must still contain the
# marker the kernel seeded before ring-3 entry (prints KLOGTEST: PASS to serial).
# The witness for [H-2]; gated off the ship kernel.
KLOG_FORGE_SELFTEST ?= 0
ifeq ($(KLOG_FORGE_SELFTEST),1)
CFLAGS  += -DKLOG_FORGE_SELFTEST
ASFLAGS += -DKLOG_FORGE_SELFTEST
KLOG_FORGE_SELFTEST_DEP = userspace/klogtest.bin
endif

# KLOG_WRITE_UNGATED=1 rebuilds the pre-2026-08-20 h_write: a ring-3 write goes
# into the kernel log with no authority tested at all ([H-2]). Not a build option
# -- a control arm. `smoke-klog-forge-control` sets it and REQUIRES the FAIL
# marker; `smoke-klog-forge` must go red under it.
# SYSCALL_PTR_TRUNC32=1 restores the pre-2026-08-20 sys_dmesg/sys_audit_digest
# wrappers, which passed their buffer as (uint32_t)(unsigned long)ptr and so
# handed the kernel the low 32 bits of an address the caller never named
# (issue #176). Not a build option -- a control arm. Every static in a PIE image
# is above 4 GiB (USER_IMAGE_ASLR_BASE is 16 GiB), so under this flag
# smoke-klog-forge's probe cannot read the log back at all.
# The flag is applied to USERSPACE_CFLAGS further down, AFTER that variable is
# assigned with `=` -- setting it here would be silently overwritten, which is
# the same shape of silent loss as the defect it reproduces.
# SYSCALL_COVERAGE=1 records the first entry into each syscall HANDLER BODY and
# reports it on the wire as `SYSCOV <n>`. Not a defect arm and not a shipping
# configuration -- a measurement instrument, like SPAWN_STAGE_TRACE and
# KSTACK0_PARK_TRACE. See tools/check_syscall_coverage.py.
# KSP_GUARD_INJECT=1 forges the exact value [G-9] was seen to hand back (-7) in
# task_exit_switch, so the producer-side guard has a falsifying arm. A guard that
# has never been seen to fire is not a guard. Never a shipping configuration.
KSP_GUARD_INJECT ?= 0
ifeq ($(KSP_GUARD_INJECT),1)
CFLAGS += -DKSP_GUARD_INJECT
endif

# RNG_UNSEEDED_PROBE=1 asks the CSPRNG for output before entropy_init() and
# reports on the wire whether it was refused -- the instrument for the seed gate
# (S30), not a defect in itself. Both arms of `make smoke-rng-seed` set it.
RNG_UNSEEDED_PROBE ?= 0
ifeq ($(RNG_UNSEEDED_PROBE),1)
CFLAGS += -DRNG_UNSEEDED_PROBE
endif

# RNG_UNSEEDED_LEGACY=1 is the defect: it passes the `rng_unseeded_legacy` cargo
# feature down to the Rust staticlib, compiling the `!self.seeded` check out of
# RngState::fill so an unseeded pool serves keystream under the published startup
# key. Unlike every other flag in this list it is not a -D: the defect lives in
# Rust, so it must reach cargo. It IS stamped into DEFECT FLAGS all the same --
# a transcript that does not name it is a transcript nobody can audit.
# POSIX_LEGACY_WALK=1 restores posix.c's private path walker, the pre-2026-08-23
# copy that resolved neither "." nor ".." -- it looked both up as literal
# directory entries, which fs_server never creates. `make smoke-newlib` must go
# red under it.
# MEASURED_BOOT_REQUIRED=1 is a POLICY flag, not a defect arm: it makes an
# unavailable measured boot fatal instead of a log line, and refuses to unlock a
# persistent volume that was never sealed. Off by default because this kernel is
# expected to boot on TPM-less machines (docs/LIMITATIONS.md 2.9); it is in this
# list because a transcript taken under it describes a different machine, which
# is exactly what DEFECT FLAGS exists to record.
# LEGACY_SYSCALLS_PRESENT=1 restores the four dispatch entries retired on
# 2026-08-23: SYS_CLEAR (5), SYS_SYSINFO (6), SYS_DEBUG_EXEC (7) and
# SYS_EXEC_LEGACY (14). The last one is the reason the flag exists -- it creates
# a TASK, authorised on cspace slot 3, which is the legacy CAP_FRAME every task
# is born holding. `make smoke-passwd-probe` must go red under it.
# CAP_ENUMERATE_UNGATED=1 removes SYS_CAP_ENUMERATE's declared capability, so
# the central gate admits every caller and the capability graph becomes readable
# by any ring-3 task. `make smoke-captest` must go red under it (roadmap 3.6).
# CLOCK_TSC_RESOLUTION=1 makes SYS_CLOCK_GETTIME report real microseconds off
# the calibrated TSC instead of PIT ticks -- a more accurate clock that hands
# ring 3 back the cycle-accurate timer CR4.TSD spends a control-register bit to
# deny (roadmap 2.2). `make smoke-captest` must go red under it.
# TASKINFO_WIDE_AUTHORITY=1 restores the pre-2026-08-24 acceptance set for
# SYS_GET_TASK_INFO: CAP_USER or CAP_AUDIT also answer "may I see the process
# list" (roadmap 3.6). `make smoke-proc` must go red under it -- the witness is
# `grantee`, which holds a granted CAP_AUDIT and no CAP_DEBUG.
# GETLINE_SLOT3_FALLBACK=1 restores the pre-2026-08-24 fallback in h_get_line:
# an UNTYPED cap_lookup on slot 3, the legacy CAP_FRAME every task is born
# holding, as an alternative to CAP_CONSOLE. `make smoke-captest` must go red
# under it -- by TIMEOUT, because captest then reaches the console read and
# blocks rather than printing a marker.
GETLINE_SLOT3_FALLBACK ?= 0
ifeq ($(GETLINE_SLOT3_FALLBACK),1)
CFLAGS += -DGETLINE_SLOT3_FALLBACK
endif

# CAP_LOOKUP_ASSERT_HANG=1 restores the pre-2026-08-29 source-slot resolver in
# cap_mint/cap_transfer: a helper that spun forever on a NULL cap_lookup, while
# holding cap_lock with interrupts masked. All three inputs that make cap_lookup
# return NULL are caller-chosen and the handlers validate nothing, so under this
# arm any unprivileged task stops the machine with one syscall (S52).
# `make smoke-captest` must go red under it -- by TIMEOUT, because the task is
# wedged inside the syscall and prints nothing at all.
CAP_LOOKUP_ASSERT_HANG ?= 0
ifeq ($(CAP_LOOKUP_ASSERT_HANG),1)
CFLAGS += -DCAP_LOOKUP_ASSERT_HANG
endif

# IOMMU_TEARDOWN_SELFTEST=1 builds the in-kernel witness for S53. Not a defect
# flag: it adds a test, it does not remove a check, so it is not in DEFECT_FLAGS.
IOMMU_TEARDOWN_SELFTEST ?= 0
ifeq ($(IOMMU_TEARDOWN_SELFTEST),1)
CFLAGS += -DIOMMU_TEARDOWN_SELFTEST
endif

# IOMMU_NO_FRAME_TEARDOWN=1 restores the pre-2026-08-29 destroy_dyn_frame: the
# frame's bytes are scrubbed and returned to the arena while every device
# translation of them stays installed (S53).
IOMMU_NO_FRAME_TEARDOWN ?= 0
ifeq ($(IOMMU_NO_FRAME_TEARDOWN),1)
CFLAGS += -DIOMMU_NO_FRAME_TEARDOWN
endif

# IOMMU_NO_TASK_TEARDOWN=1 restores the pre-2026-08-29 task_teardown, which
# released every other device resource a dying task held -- IRQ route, MSI route,
# port grant, console -- and left its IOMMU domain populated (S53).
IOMMU_NO_TASK_TEARDOWN ?= 0
ifeq ($(IOMMU_NO_TASK_TEARDOWN),1)
CFLAGS += -DIOMMU_NO_TASK_TEARDOWN
endif

TASKINFO_WIDE_AUTHORITY ?= 0
ifeq ($(TASKINFO_WIDE_AUTHORITY),1)
CFLAGS += -DTASKINFO_WIDE_AUTHORITY
endif

CLOCK_TSC_RESOLUTION ?= 0
ifeq ($(CLOCK_TSC_RESOLUTION),1)
CFLAGS += -DCLOCK_TSC_RESOLUTION
endif

CAP_ENUMERATE_UNGATED ?= 0
ifeq ($(CAP_ENUMERATE_UNGATED),1)
CFLAGS += -DCAP_ENUMERATE_UNGATED
endif

LEGACY_SYSCALLS_PRESENT ?= 0
ifeq ($(LEGACY_SYSCALLS_PRESENT),1)
CFLAGS += -DLEGACY_SYSCALLS_PRESENT
endif

MEASURED_BOOT_REQUIRED ?= 0
ifeq ($(MEASURED_BOOT_REQUIRED),1)
CFLAGS += -DMEASURED_BOOT_REQUIRED
endif

# MEASURED_VOLUME_EXEMPT_NONE=1 removes the ephemeral-vdisk exemption from the
# rule above, so the sealed-volume refusal is reached on an ordinary boot. It is
# how that refusal is falsified: the exemption is the flag's one hole, and an arm
# that cannot enter the branch cannot show it fires.
MEASURED_VOLUME_EXEMPT_NONE ?= 0
ifeq ($(MEASURED_VOLUME_EXEMPT_NONE),1)
CFLAGS += -DMEASURED_VOLUME_EXEMPT_NONE
endif

POSIX_LEGACY_WALK ?= 0

# HVFS_DOTDOT_SERVER=1 restores hvfs's original ".." branch, which asked the
# SERVER to look up a ".." entry. fs_server creates none, so the branch could
# only ever return NOENT: it was dead code from #195 until 2026-08-23, and the
# only test touching ".." used the pinned case, which returns before it.
HVFS_DOTDOT_SERVER ?= 0

RNG_UNSEEDED_LEGACY ?= 0
ifeq ($(RNG_UNSEEDED_LEGACY),1)
CFLAGS += -DRNG_UNSEEDED_LEGACY
RUST_FEATURES := rng_unseeded_legacy
endif
RUST_FEATURE_ARGS = $(if $(RUST_FEATURES),--features $(RUST_FEATURES))

# KSP_GUARD_ALWAYS=1 makes ksp_is_bogus() reject EVERY stack pointer -- the
# false-positive mutation that every inject-and-look arm would happily pass.
# `make smoke-ksp-guard` must go red under it.
KSP_GUARD_ALWAYS ?= 0
ifeq ($(KSP_GUARD_ALWAYS),1)
CFLAGS += -DKSP_GUARD_ALWAYS
endif

SYSCALL_COVERAGE ?= 0
ifeq ($(SYSCALL_COVERAGE),1)
CFLAGS += -DSYSCALL_COVERAGE
endif

SYSCALL_PTR_TRUNC32 ?= 0

KLOG_WRITE_UNGATED ?= 0
ifeq ($(KLOG_WRITE_UNGATED),1)
CFLAGS += -DKLOG_WRITE_UNGATED
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

# DEVCAP_SELFTEST=1 embeds devcaptest and, at boot, spawns it holding TWO device
# capabilities: the legacy platform device (VGA/UART/PS-2/PIT) and the machine's
# PCI network controller. The probe proves each capability reaches its own
# device's frames, ports and interrupt line and is REFUSED the other's, in both
# directions (prints DEVCAPTEST: PASS to serial). The witness that a CAP_IO_DEVICE
# names a device rather than conferring the console; gated off the ship kernel.
# Needs a NIC on the machine: run it under `tools/smoke_test.sh` with SMOKE_NET=1.
DEVCAP_SELFTEST ?= 0
ifeq ($(DEVCAP_SELFTEST),1)
CFLAGS  += -DDEVCAP_SELFTEST
ASFLAGS += -DDEVCAP_SELFTEST
DEVCAP_SELFTEST_DEP = userspace/devcaptest.bin
endif

# IO_DEVICE_OBJECT_UNCHECKED=1 rebuilds SYS_MAP_PHYS's pre-2026-08-28 authority
# check: the capability's `object` is ignored and the frame is tested against the
# compiled-in VGA allowlist instead, so ANY device capability reaches the console
# framebuffer. Control arm for the [C-1]-shaped defect this all exists to close;
# `make smoke-devcap-object-control` requires DEVCAPTEST: FAIL nic-cap-mapped-vga.
IO_DEVICE_OBJECT_UNCHECKED ?= 0
ifeq ($(IO_DEVICE_OBJECT_UNCHECKED),1)
CFLAGS += -DIO_DEVICE_OBJECT_UNCHECKED
endif

# IO_DEVICE_PORTS_GLOBAL=1 rebuilds the pre-2026-08-28 TSS I/O bitmap: one
# console port set, loaded by every grant whatever device the capability named.
# `make smoke-devcap-ports-control` requires FAIL nic-cap-got-console-ports.
IO_DEVICE_PORTS_GLOBAL ?= 0
ifeq ($(IO_DEVICE_PORTS_GLOBAL),1)
CFLAGS += -DIO_DEVICE_PORTS_GLOBAL
endif

# IO_DEVICE_IRQ_UNCHECKED=1 rebuilds the pre-2026-08-28 SYS_IRQ_REGISTER, which
# accepted any routable IRQ from any holder of the type, so a NIC driver could
# subscribe to the console's keyboard. `make smoke-devcap-irq-control` requires
# FAIL nic-cap-took-platform-irq.
IO_DEVICE_IRQ_UNCHECKED ?= 0
ifeq ($(IO_DEVICE_IRQ_UNCHECKED),1)
CFLAGS += -DIO_DEVICE_IRQ_UNCHECKED
endif

# The shared object every SHLIB_SELFTEST task maps. -fvisibility=hidden is not
# cosmetic: an exported symbol can be interposed, so the linker emits
# R_X86_64_64 against the dynamic symbol for it, and shlib_init refuses anything
# but R_X86_64_RELATIVE -- a library whose calls resolve somewhere the loader did
# not compute is a library nobody chose. Hidden visibility makes every reference
# internal and every relocation RELATIVE.
#
# -e shlib_exports puts the export table's address in e_entry. A shared object has
# no entry point in the runnable sense, so the field is free, and using it means
# the loader neither guesses a layout nor trusts a section name to survive the
# toolchain.
#
# -T userspace/shlib.ld splits the object into a SHARED read+exec segment and a
# PER-TASK read+write one, page-aligned apart. That split is S50 and the reason
# the script exists; see the header comment there for what the default script
# does instead and why it cannot work.
userspace/shlibdemo.so: userspace/shlibdemo.c userspace/shlib.ld
	$(CC) -shared -fPIC -m64 -ffreestanding -nostdlib -fno-stack-protector \
	  -fno-plt -fvisibility=hidden -Wl,-e,shlib_exports -Wl,--build-id=none \
	  -Wl,-T,userspace/shlib.ld \
	  -O2 -o $@ $<

# SHLIB_SELFTEST=1 embeds that object and, at boot, loads it once into frames and
# spawns TWO tasks that each map it read+exec from a capability that never held
# WRITE. Both call into the same physical pages; neither can modify them
# (SHLIBTEST: PASS). Roadmap 2.5's mechanism; gated off the ship kernel.
SHLIB_SELFTEST ?= 0
ifeq ($(SHLIB_SELFTEST),1)
CFLAGS  += -DSHLIB_SELFTEST
ASFLAGS += -DSHLIB_SELFTEST
SHLIB_SELFTEST_DEP = userspace/shlibdemo.so userspace/shlibtest.bin userspace/shlibpeer.bin
endif

# SHLIBC_SELFTEST=1 loads the REAL shared libc instead of the demo object and
# spawns a task that calls into it. Roadmap 2.5's remaining claim: the mechanism
# runs newlib, not only an object written to demonstrate the mechanism.
#
# Separate from SHLIB_SELFTEST because shlib.c loads ONE object and which object
# is a build choice. The two never build together, which is also why they can
# share a capability-slot convention.
SHLIBC_SELFTEST ?= 0
ifeq ($(SHLIBC_SELFTEST),1)
CFLAGS  += -DSHLIBC_SELFTEST
ASFLAGS += -DSHLIBC_SELFTEST
SHLIBC_SELFTEST_DEP = userspace/libc.so userspace/libctest.bin userspace/hello_shared.bin
endif

# NET_SELFTEST=1 embeds netd and, at boot, spawns it holding exactly two
# capabilities -- a CAP_IO_DEVICE naming the machine's NIC, and the untyped region
# it builds its DMA rings from. It brings up virtio-net over the legacy I/O BAR
# and completes an ARP exchange with QEMU's user-mode gateway (NETTEST: PASS).
# Roadmap 2.6's first half; needs SMOKE_NET=user, which is what `make smoke-net`
# passes. Gated off the ship kernel: adding a driver to every image is a separate
# decision from proving one works.
NET_SELFTEST ?= 0
ifeq ($(NET_SELFTEST),1)
CFLAGS  += -DNET_SELFTEST
ASFLAGS += -DNET_SELFTEST
NET_SELFTEST_DEP = userspace/netd.bin
endif

# NET_NO_BUSMASTER=1 has netd enable I/O decode but NOT bus mastering.
#
# NO GATE, DELIBERATELY, and the reason is a measurement: with the bit clear the
# driver still completes the entire ARP exchange under QEMU, because the emulator
# does not enforce PCI bus-master enable for virtio-net. The arm cannot fail here,
# and a control arm that cannot fail cannot gate -- the same call as
# SPAWN_STAGE_UNSERIALISED. Kept because a real NIC will not DMA without it, and
# because the day this runs on hardware the arm becomes real. What IS observable
# is NET_NO_DECODE, below.
NET_NO_BUSMASTER ?= 0

# NET_NO_DECODE=1 has netd ask for NO decode bits at all, so the device stops
# answering its own I/O BAR and the register file reads back as floating bus. The
# arm for SYS_DEVICE_ENABLE: it writes the one configuration-space register ring 3
# can reach, and this is what shows the write lands. `make smoke-net-decode-control`
# requires `NETTEST: FAIL mac-not-valid` -- the first register whose value the
# driver checks rather than merely stores. This comment named a different marker
# than the recipe asserted until 2026-08-29.
NET_NO_DECODE ?= 0

# NET_IOMMU_NO_MAP=1 has netd ask SYS_DMA_ADDR for its frames' addresses WITHOUT
# installing the device mappings (the DMA_ADDR_NO_MAP flag). Every capability
# check still runs and every address returned is correct -- what is withheld is
# the one thing that lets the device reach the memory. THE ARM FOR S45: under it
# the device's address space stays empty, no descriptor is ever read, and DD
# never comes back. `make smoke-net-iommu-control` requires
# NETTEST: FAIL dma-never-completed, and it only means anything on a machine with
# an IOMMU, which is why that gate boots with SMOKE_IOMMU=1.
NET_IOMMU_NO_MAP ?= 0

# IRQ_NO_MASK_ON_FIRE=1 leaves a registered interrupt line UNMASKED when it fires,
# which is what a kernel does if it treats an EOI as the end of the story. A legacy
# PCI interrupt is level-triggered: the device holds the line until its driver
# services it, so the PIC re-delivers immediately, ring 3 never runs, the driver
# never clears the device, and the machine stops making progress permanently.
#
# THE ARM FOR S46, and it asserts a STALL rather than a marker -- a livelocked
# machine prints nothing more, which is the honest shape of this defect.
# `make smoke-net-irq-storm-control` requires NETTEST: PASS to have been reached
# and NETTEST: IRQ PASS to be ABSENT.
# IRQ_FORCE_PIC=1 skips I/O APIC bring-up so interrupts route through the 8259 --
# not a defect, but the configuration every machine without a MADT I/O APIC entry
# runs, and the one the mask-on-fire arm reproduces on. Keeps the fallback tested
# rather than merely present.
IRQ_FORCE_PIC ?= 0
ifeq ($(IRQ_FORCE_PIC),1)
CFLAGS += -DIRQ_FORCE_PIC
endif

IRQ_NO_MASK_ON_FIRE ?= 0
ifeq ($(IRQ_NO_MASK_ON_FIRE),1)
CFLAGS += -DIRQ_NO_MASK_ON_FIRE
endif

# IRQ_ACK_UNGATED=1 drops the capability check from SYS_IRQ_ACK, so unmasking an
# interrupt line stops being an authority question. `make smoke-captest-irq-ack-control`
# requires CAPTEST: FAIL irq-ack-without-cap-io-device.
# POLL_NOTIFY_UNGATED=1 drops SYS_POLL_NOTIFY's capability check, so any task can
# poll any notification and consume another task's badges -- finding C-2's shape
# in a new syscall. `make smoke-captest-poll-notify-control`.
# MSI_VECTOR_FROM_USER=1 has SYS_MSI_REGISTER honour a vector the CALLER supplies
# -- the shape this syscall takes the moment anyone decides a driver "knows best"
# which vector it wants. netd's arm then asks for 13 (#GP) and the machine starts
# taking general-protection faults attributed to whatever was interrupted.
#
# THE ARM FOR S47, and the reason the real ABI has no vector field at all.
# `make smoke-net-msi-vector-control` asserts a STALL: a machine faulting on a
# vector nothing expects does not get to print a marker.
# MSIX_TABLE_MAPPABLE=1 drops the refusal, so a driver can map its own device's
# MSI-X vector table -- ordinary device memory inside a BAR it holds a capability
# for. The table entry carries the interrupt VECTOR, so this is S47's guarantee
# undone through a door S47 does not cover: the driver writes the vector itself,
# in its own address space, with no syscall involved.
#
# THE ARM FOR S48. `make smoke-net-msix-table-control` requires
# NETTEST: FAIL msix-table-mapped.
# SHLIB_TEXT_WRITABLE=1 mints the shared library's frame capability WITH the
# write right, so a task can map the library writable and patch code another task
# executes. The arm for S49: shlibtest overwrites shlib_magic through a writable
# alias while executing through its read+exec one, and the PEER -- which asked for
# nothing but read+exec -- runs the patch. `make smoke-shlib-writable-control`
# requires SHLIBTEST: FAIL peer-saw-patched-code.
SHLIB_TEXT_WRITABLE ?= 0
ifeq ($(SHLIB_TEXT_WRITABLE),1)
CFLAGS += -DSHLIB_TEXT_WRITABLE
endif

# SHLIB_DATA_SHARED=1 endows every task with the SAME frame for the shared
# library's writable data, instead of a private copy carved from the template.
# One task's store to the library's .data is then visible to every other -- for
# real newlib that is another task's errno, stdio buffers and malloc arena.
#
# THE DISCLOSURE ARM FOR S50. `make smoke-shlib-data-shared-control` requires
# SHLIBTEST: FAIL peer-saw-our-data.
# SHLIB_BASE_FIXED=1 restores the pre-2026-08-29 compiled-in library base, so
# every boot loads the shared library at the same address. That was defensible
# for a three-page demo and is not once newlib moves onto this mechanism: ~135
# KiB of executable code at an address printed in the binary, in every task --
# and a REGRESSION, since a program's static libc lives inside its own PIE image,
# which the loader already randomises.
#
# THE ARM FOR S51. `make smoke-shlib-aslr-control` boots twice and requires the
# two reported bases to be IDENTICAL, which is what the base gate requires them
# not to be.
SHLIB_BASE_FIXED ?= 0
ifeq ($(SHLIB_BASE_FIXED),1)
CFLAGS += -DSHLIB_BASE_FIXED
endif

# SHLIB_INFO_UNGATED=1 removes SYS_SHLIB_INFO's capability test entirely, making
# the shared library's base ambient information any task can ask for -- which
# defeats randomising it, since an attacker with code execution anywhere can
# simply ask where the shared code is. The whole gate goes, not just the
# ownership half: with the type check left in place a wrong-type slot would be
# refused anyway and the arm would pass for a reason unrelated to the authority.
#
# THE ARM FOR S51's second half. `make smoke-shlib-info-control` requires
# SHLIBTEST: FAIL shlib-info-with-wrong-cap-type.
SHLIB_INFO_UNGATED ?= 0
ifeq ($(SHLIB_INFO_UNGATED),1)
CFLAGS += -DSHLIB_INFO_UNGATED
endif

# SHLIB_INFO_TYPE_ONLY=1 keeps SYS_SHLIB_INFO's type check and drops the OBJECT
# test, so any CAP_FRAME answers -- including a task's own private copy of the
# library's data page, which says nothing about holding the library's code.
# Separate from SHLIB_INFO_UNGATED because they break different rules, and
# because with only that arm the object rule has never been shown to fire.
#
# `make smoke-shlib-info-object-control` requires
# SHLIBTEST: FAIL shlib-info-with-data-frame.
SHLIB_INFO_TYPE_ONLY ?= 0
ifeq ($(SHLIB_INFO_TYPE_ONLY),1)
CFLAGS += -DSHLIB_INFO_TYPE_ONLY
endif

SHLIB_DATA_SHARED ?= 0
ifeq ($(SHLIB_DATA_SHARED),1)
CFLAGS += -DSHLIB_DATA_SHARED
endif

# SHLIB_DATA_UNINITIALISED=1 gives each task a PRIVATE data frame and zero-fills
# it rather than copying the library's initial image. Loss, not disclosure, and
# separable from SHLIB_DATA_SHARED on purpose: each arm's other half still
# passes, which is what shows the two checks are independent. Same shape as the
# FPU pair (FPU_NO_SAVE / FPU_NO_RESTORE), for the same reason.
#
# THE INITIALISATION ARM FOR S50. `make smoke-shlib-data-init-control` requires
# SHLIBTEST: FAIL data-not-initialised.
SHLIB_DATA_UNINITIALISED ?= 0
ifeq ($(SHLIB_DATA_UNINITIALISED),1)
CFLAGS += -DSHLIB_DATA_UNINITIALISED
endif

MSIX_TABLE_MAPPABLE ?= 0
ifeq ($(MSIX_TABLE_MAPPABLE),1)
CFLAGS += -DMSIX_TABLE_MAPPABLE
endif

MSI_VECTOR_FROM_USER ?= 0
ifeq ($(MSI_VECTOR_FROM_USER),1)
CFLAGS += -DMSI_VECTOR_FROM_USER
USERSPACE_CFLAGS_EXTRA_MSI = -DMSI_VECTOR_FROM_USER
endif

POLL_NOTIFY_UNGATED ?= 0
ifeq ($(POLL_NOTIFY_UNGATED),1)
CFLAGS += -DPOLL_NOTIFY_UNGATED
endif

IRQ_ACK_UNGATED ?= 0
ifeq ($(IRQ_ACK_UNGATED),1)
CFLAGS += -DIRQ_ACK_UNGATED
endif

# DMA_ADDR_FRAME_ONLY=1 drops SYS_DMA_ADDR's device-capability requirement, so the
# call is gated on the frame alone -- the shape it takes if the device capability
# is read as documentation rather than as a requirement. Under it any task that
# ever retyped a page learns the kernel's physical layout. `make
# smoke-frame-dma-control` requires FRAMETEST: FAIL dma-addr-without-device-cap.
DMA_ADDR_FRAME_ONLY ?= 0
ifeq ($(DMA_ADDR_FRAME_ONLY),1)
CFLAGS += -DDMA_ADDR_FRAME_ONLY
endif


# IO_DEVICE_CAP_UNCHECKED=1 removes the capability lookup from iodev_from_slot
# entirely, so every caller of a device syscall resolves to the platform device
# while holding nothing. It is the arm for the GATE HAVING MOVED: the three device
# syscalls lost their fixed slot-10 dispatch entries when the lookup moved into
# the handler, and an arm that only bypasses the object check cannot say whether
# a capability is still required at all. `make smoke-captest-devcap-control`
# requires CAPTEST: FAIL map-phys-without-cap-io-device.
IO_DEVICE_CAP_UNCHECKED ?= 0
ifeq ($(IO_DEVICE_CAP_UNCHECKED),1)
CFLAGS += -DIO_DEVICE_CAP_UNCHECKED
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
# LIBHORUS_SELFTEST=1 embeds a ring-3 task that asserts libhorus's own contracts
# -- the bounds and termination guarantees every freestanding program now depends
# on, and ipc_call_retry's refusal-is-not-retried property, which is a security
# property (finding G-8 signature C) rather than a convenience. Sharing a runtime
# concentrates risk: a bug here breaks init, shell, fs_server and console_server
# at once, so the shared copy is held to a standard the seven private copies
# never were. Prints LIBHORUS_SELFTEST: PASS from ring 3. Gated off the ship kernel.
# CLAIM_TRACE=1 is an INSTRUMENT, not a defect arm -- it changes no behaviour, it
# reports. percpu_deferred_release[] is one slot per CPU; if a CPU ever defers a
# second release before its ISR epilogue consumed the first, the first task's
# claim is orphaned and the audit that later finds it names the wrong site. This
# says so at the overwrite. Same role SPAWN_STAGE_TRACE plays for the staging
# window. Requires SCHED_INVARIANTS for the auditor it complements.
CLAIM_TRACE ?= 0
ifeq ($(CLAIM_TRACE),1)
CFLAGS  += -DCLAIM_TRACE
ASFLAGS += -DCLAIM_TRACE
endif

# CLAIM_RELEASE_SKIP=1 removes `call sched_release_deferred` from the ISR
# epilogue, so a CPU reaches ring 3 still owing a release. It is the falsifying
# arm for the ring-3 claim invariant added 2026-08-21 -- without it that guard
# would be an assertion nobody had ever seen fire, which is the shape this repo
# already records costing it a fortnight.
CLAIM_RELEASE_SKIP ?= 0
ifeq ($(CLAIM_RELEASE_SKIP),1)
CFLAGS  += -DCLAIM_RELEASE_SKIP
ASFLAGS += -DCLAIM_RELEASE_SKIP
endif

# SWITCH_COMMIT_EARLY=1 restores the pre-2026-08-21 order in task_exit_switch:
# commit the switch, then validate the resume value. ksp_refuse() returns 0, which
# is ALSO that function's legal "nothing runnable, caller parks" return, so its
# callers park the CPU and the task it just claimed is orphaned forever. Pair with
# KSP_GUARD_INJECT=1 to make it deterministic.
SWITCH_COMMIT_EARLY ?= 0
ifeq ($(SWITCH_COMMIT_EARLY),1)
CFLAGS  += -DSWITCH_COMMIT_EARLY
ASFLAGS += -DSWITCH_COMMIT_EARLY
endif

# DEFER_CLEAR_EARLY=1 restores the pre-fix order in sched_release_deferred: drop
# the auditor's exemption (percpu_deferred_release[]) BEFORE taking the lock that
# drops the claim, leaving the task claimed, un-exempt and mid-release for the
# width of a lock acquisition.
DEFER_CLEAR_EARLY ?= 0
ifeq ($(DEFER_CLEAR_EARLY),1)
CFLAGS  += -DDEFER_CLEAR_EARLY
ASFLAGS += -DDEFER_CLEAR_EARLY
endif

# DEFER_WINDOW_WIDEN=1 is not a defect -- it stretches that window so the pair is
# deterministic. Set in BOTH arms when measuring, like KSTACK_RACE_WIDEN.
DEFER_WINDOW_WIDEN ?= 0
ifeq ($(DEFER_WINDOW_WIDEN),1)
CFLAGS  += -DDEFER_WINDOW_WIDEN
ASFLAGS += -DDEFER_WINDOW_WIDEN
endif
ifeq ($(SWITCH_COMMIT_EARLY),1)
CFLAGS  += -DSWITCH_COMMIT_EARLY
ASFLAGS += -DSWITCH_COMMIT_EARLY
endif
ifeq ($(CLAIM_RELEASE_SKIP),1)
CFLAGS  += -DCLAIM_RELEASE_SKIP
ASFLAGS += -DCLAIM_RELEASE_SKIP
endif

# FRAME_SELFTEST=1 embeds the ring-3 witness for frame capabilities (roadmap
# 2.1). Two tasks: one holds a CAP_UNTYPED, retypes a KOBJ_FRAME out of it, maps
# it, and asserts every refusal the map path owes -- the legacy slot-3 CAP_FRAME
# every task is born with, W|X together, a kernel-half address, a misaligned one,
# a double map, an unmap of a page it never mapped. It then mints a READ-only
# copy of the frame capability, delegates it, and the second task proves both
# halves of what shared memory has to mean: it SEES the first task's bytes, and
# it CANNOT obtain a writable mapping. Prints FRAMETEST: PASS <n> checks from
# ring 3. Gated off the ship kernel.
# RAMFS_SLOT3_GATE=1 restores the four pre-2026-08-22 gates into the in-kernel
# ramfs -- SYS_OPEN, 15 (create), 16 (list) and SYS_READ's fd>=3 branch -- each
# of which authorised on cspace slot 3 with SC_ANYTYPE. Slot 3 holds the legacy
# CAP_FRAME create_task installs in every task, so all four were satisfied by a
# capability nobody asked for and everybody has: [C-1]'s shape, on the last
# gates still wearing it. Behind them sits the file kusers.c writes the user
# database into.
# VFS_SELFTEST=1 embeds dev_server (a second filesystem server, holding nothing
# but its own endpoint) and vfstest, which mounts fs_server at "/" and
# dev_server at "/dev" and asserts which server each path reaches. A mount table
# with one mount cannot demonstrate anything, so the second server IS the test.
VFS_SELFTEST ?= 0
ifeq ($(VFS_SELFTEST),1)
CFLAGS  += -DVFS_SELFTEST
ASFLAGS += -DVFS_SELFTEST
VFS_SELFTEST_DEP = userspace/dev_server.bin userspace/vfstest.bin
endif

# VFS_FIRST_MATCH=1 makes hvfs_resolve return the first matching mount instead
# of the longest-prefix one. "/" matches every path, so with it installed first
# EVERY /dev path is addressed to the root filesystem -- which has an inode 0 of
# its own and therefore ANSWERS ABOUT A DIFFERENT OBJECT rather than failing.
# Wrong-server-answered, not permission-denied, which is why the witness checks
# which server replied. USERSPACE only (hvfs is a ring-3 library).
VFS_FIRST_MATCH ?= 0

# VFS_MOUNT_UNGATED=1 removes hvfs_mount's probe, so a prefix string alone
# installs a mount over a slot holding no capability. Every path under it is
# then addressed to nothing, one failed operation at a time. USERSPACE only.
VFS_MOUNT_UNGATED ?= 0

RAMFS_SLOT3_GATE ?= 0
ifeq ($(RAMFS_SLOT3_GATE),1)
CFLAGS  += -DRAMFS_SLOT3_GATE
ASFLAGS += -DRAMFS_SLOT3_GATE
# The in-kernel ramfs is built ONLY for this control arm. Its ring-3 surface was
# retired with [H-3] and its last real consumer -- the user database save/load
# pair -- was deleted 2026-08-22 as code that had never run, so nothing in the
# ship build references it. It survives here because the arm restores those four
# gates and a gate needs something behind it to be worth restoring.
OBJS += src/kernel/ramfs.o
endif

# PASSWD_PROBE=1 embeds a ring-3 task that runs as the ordinary uid-1000 account
# with no capability anyone delegated to it, and asserts all four doors into the
# in-kernel ramfs are shut: it cannot open the user database, read bytes out of
# any ramfs fd, create a file, or list the contents. Prints
# PASSWDPROBE: PASS <n> checks from ring 3.
PASSWD_PROBE ?= 0
ifeq ($(PASSWD_PROBE),1)
CFLAGS  += -DPASSWD_PROBE
ASFLAGS += -DPASSWD_PROBE
PASSWD_PROBE_DEP = userspace/passwdprobe.bin
endif

FRAME_SELFTEST ?= 0
ifeq ($(FRAME_SELFTEST),1)
CFLAGS  += -DFRAME_SELFTEST
ASFLAGS += -DFRAME_SELFTEST
FRAME_SELFTEST_DEP = userspace/frametest.bin userspace/framepeer.bin
endif

# FRAME_INDEX_UNCHECKED=1 is the falsifying arm for the frame-index bound: it
# makes CAP_FRAME.object a PHYSICAL ADDRESS that is mapped directly, which is the
# shortcut a frame-mapping syscall invites and which the index exists to refuse.
# It is reachable on the first boot from a capability the kernel hands out
# itself -- slot 3's legacy CAP_FRAME, object USER_AREA_BASE -- so under this arm
# any task maps physical 0x400000 into ring 3. See src/kernel/untyped.c.
FRAME_INDEX_UNCHECKED ?= 0
ifeq ($(FRAME_INDEX_UNCHECKED),1)
CFLAGS  += -DFRAME_INDEX_UNCHECKED
ASFLAGS += -DFRAME_INDEX_UNCHECKED
endif

# FRAME_RIGHTS_UNCHECKED=1 is the falsifying arm for the rights floor on
# SYS_MAP_FRAME: cap_lookup is asked for no rights at all, so any live CAP_FRAME
# satisfies it and the PTE is built from the request. Delegation then stops
# reducing -- a READ-only frame capability maps writable and the delegate's write
# lands. It targets the floor rather than the `have & want` intersection
# deliberately: given the floor the intersection is arithmetically redundant, so
# an arm against it could not fail. See the note in src/kernel/syscall_vm.c.
FRAME_RIGHTS_UNCHECKED ?= 0
ifeq ($(FRAME_RIGHTS_UNCHECKED),1)
CFLAGS  += -DFRAME_RIGHTS_UNCHECKED
ASFLAGS += -DFRAME_RIGHTS_UNCHECKED
endif

# FRAME_REGION_NO_ROLLBACK=1 is the falsifying arm for SYS_MAP_REGION's
# partial-failure policy: it removes the unwind, so a run that fails part-way
# reports the failure and KEEPS the pages it had already mapped. That is prefix
# semantics -- what untyped_retype does deliberately, and what a mapping call
# must not do, because a PTE is authority and the caller has just been told it
# got none. The argument is at the SYS_MAP_REGION comment in
# src/kernel/syscall_vm.c; this arm is what stops it being only an argument.
FRAME_REGION_NO_ROLLBACK ?= 0
ifeq ($(FRAME_REGION_NO_ROLLBACK),1)
CFLAGS  += -DFRAME_REGION_NO_ROLLBACK
ASFLAGS += -DFRAME_REGION_NO_ROLLBACK
endif

# FRAME_REGION_ROLLBACK_WIDE=1 is the OTHER direction of the same policy: the
# unwind walks the whole REQUESTED range instead of the pages actually
# installed, re-deriving each frame from its slot. It is the plausible mistake --
# the range is in the arguments and re-deriving looks like it saves an array --
# and it lets ring 3 destroy a mapping it dislikes by asking to map a region
# across it. Without an arm, "the rollback withdraws only what this call
# installed" is a sentence rather than a property.
FRAME_REGION_ROLLBACK_WIDE ?= 0
ifeq ($(FRAME_REGION_ROLLBACK_WIDE),1)
CFLAGS  += -DFRAME_REGION_ROLLBACK_WIDE
ASFLAGS += -DFRAME_REGION_ROLLBACK_WIDE
endif

# FRAME_PAGES_SAME_PHYS=1 is the falsifying arm for the LENGTH a frame now
# carries: map_run advances the virtual cursor and not the physical one, so every
# page of a sized frame aliases the run's first page. It is the plausible slip --
# one of two cursors forgotten in a loop that reads correctly -- and it does not
# crash: the caller gets the pages it asked for, present, writable, correctly
# righted, silently sharing one page of storage. A buffer that quietly aliases
# itself is worse than one that fails to map, because nothing reports it.
FRAME_PAGES_SAME_PHYS ?= 0
ifeq ($(FRAME_PAGES_SAME_PHYS),1)
CFLAGS  += -DFRAME_PAGES_SAME_PHYS
ASFLAGS += -DFRAME_PAGES_SAME_PHYS
endif

# FRAME_INFO_BY_INDEX=1 is the falsifying arm for SYS_FRAME_PAGES' authority:
# the handler reads its argument as a frame INDEX rather than as a cspace slot,
# so no capability is consulted at all. It is finding C-1's shape -- authority
# taken from somewhere other than the capability naming the resource -- and
# something worse besides: a task holding nothing can walk indices and learn
# which frames are live and how large, across every task in the system. An
# object-existence oracle out of a syscall that looks like it returns a number.
FRAME_INFO_BY_INDEX ?= 0
ifeq ($(FRAME_INFO_BY_INDEX),1)
CFLAGS  += -DFRAME_INFO_BY_INDEX
ASFLAGS += -DFRAME_INFO_BY_INDEX
endif

# COW_ARENA_UNGUARDED=1 removes the guard at the top of cow_break_pte, so a
# copy-on-write break on a page belonging to a kernel object proceeds. It is the
# defect roadmap 2.1's "what does a COW break mean for a capability two tasks
# hold" was asking about, and it is two holes at once: the shared branch
# allocates from the ANONYMOUS pool, so a frame holder obtains a private writable
# page no untyped region paid for -- ambient resource, which this kernel does not
# have -- and the PTE is repointed at memory no capability names, so the mapping
# silently stops being the object and the frame's `1 + mappings` pin arithmetic
# stops describing reality. Nothing reaches it today; see the guard's comment for
# why that is a circumstance rather than a property, and why the arm exists now.
COW_ARENA_UNGUARDED ?= 0
ifeq ($(COW_ARENA_UNGUARDED),1)
CFLAGS  += -DCOW_ARENA_UNGUARDED
ASFLAGS += -DCOW_ARENA_UNGUARDED
endif

# FORK_SHARE_WRITABLE=1 clones a forked child's address space WITHOUT downgrading
# the leaves: both trees point at the same frames, both still writable, neither
# marked PAGE_COW. It is the shape a fork gets when "share the page tables" is
# mistaken for "copy the memory", and it is not a subtle failure -- the parent
# and the child are one process with two schedulable contexts, and every write
# either makes is immediately visible to the other. forktest's parent-side check
# (FORKTEST: FAIL parent-clobbered) is what sees it. Roadmap 2.3, S39.
FORK_SHARE_WRITABLE ?= 0
ifeq ($(FORK_SHARE_WRITABLE),1)
CFLAGS  += -DFORK_SHARE_WRITABLE
ASFLAGS += -DFORK_SHARE_WRITABLE
endif

# FORK_ARENA_UNCHECKED=1 removes clone_user_aspace's refusal to clone a PTE whose
# frame belongs to the untyped arena, so forking with a CAP_FRAME mapped
# succeeds. The child then holds a live mapping of a kernel object that NO
# capability of its own names: revoking the parent's CAP_FRAME sweeps the
# parent's PTE and leaves the child's behind, and whichever side writes first
# meets cow_break_pte's own arena guard and is killed for it. Sibling of
# COW_ARENA_UNGUARDED above and aimed one layer up -- that one asks what a break
# does, this one asks whether the mapping should have been cloned at all.
# Roadmap 2.3, S40.
FORK_ARENA_UNCHECKED ?= 0
ifeq ($(FORK_ARENA_UNCHECKED),1)
CFLAGS  += -DFORK_ARENA_UNCHECKED
ASFLAGS += -DFORK_ARENA_UNCHECKED
endif

# FORK_CSPACE_FLAT_COPY=1 copies the parent's capabilities into the child
# verbatim -- same serial, same badge, same generation -- instead of deriving
# them. The child then holds capabilities that are INDISTINGUISHABLE from the
# parent's, and a serial is supposed to name exactly one capability. The harm is
# revocation flowing sideways instead of down: rust_cap_revoke_global's sweep
# nulls every capability whose serial matches the revoked root's, across every
# cspace, so the child revoking its OWN slot destroys the parent's capability
# too. Any task can fork, so that is a cross-task revocation primitive available
# to every task in the system. Roadmap 2.3, S41.
FORK_CSPACE_FLAT_COPY ?= 0
ifeq ($(FORK_CSPACE_FLAT_COPY),1)
CFLAGS  += -DFORK_CSPACE_FLAT_COPY
ASFLAGS += -DFORK_CSPACE_FLAT_COPY
endif

# FORK_CSPACE_ORPHAN_COPY=1 gives the child's copies a fresh serial -- so the
# flat-copy defect above is absent -- but leaves `badge` as the source's, so the
# copy is not a CHILD of the parent's capability in the derivation tree. It is a
# second ROOT holding the parent's authority. mark_children_of never marks it and
# its serial matches no revocation root, so revoking the parent's capability
# leaves the child's working: a revocation hole reachable from ring 3 by any task
# that can fork. This is finding 3.3's shape -- a capability keyed to a serial no
# sweep reaches -- applied to a whole cspace at once, and it is the one the
# derivation exists to prevent. Roadmap 2.3, S41.
FORK_CSPACE_ORPHAN_COPY ?= 0
ifeq ($(FORK_CSPACE_ORPHAN_COPY),1)
CFLAGS  += -DFORK_CSPACE_ORPHAN_COPY
ASFLAGS += -DFORK_CSPACE_ORPHAN_COPY
endif

# EXEC_RESET_CSPACE=1 makes SYS_EXEC_NAMED / SYS_EXEC_IMAGE discard every
# capability at or above KERNEL_RESERVED_CAPS, so the execed image keeps only the
# birth endowment create_task installs. It is the "give the new image a clean
# slate" instinct written out, and it breaks the pairing a shell needs: a task
# that forks, is endowed, and then execs arrives with nothing. Everything the
# task was DELEGATED -- its console endpoint included -- is gone, which is why
# forkexecee reports through the capability graph rather than the console: under
# this arm a console write is exactly the channel the defect closes. Roadmap 2.3,
# S42.
EXEC_RESET_CSPACE ?= 0
ifeq ($(EXEC_RESET_CSPACE),1)
CFLAGS  += -DEXEC_RESET_CSPACE
ASFLAGS += -DEXEC_RESET_CSPACE
endif

# EXEC_ROOT_CSPACE=1 keeps every capability across the exec but re-mints each one
# as a ROOT: fresh serial, no badge. The task's AUTHORITY is untouched and every
# check that asks "can it still do the thing" passes -- which is the whole
# difficulty. What it loses is its position in the derivation graph, so a
# revocation aimed at whatever the capability was derived from no longer reaches
# it. Reachable from ring 3 by any task that may exec, and combined with SYS_FORK
# it is an authority-laundering primitive: fork to inherit a derived copy, exec to
# turn it into a root nobody can revoke. Finding 3.3's shape, one syscall over
# from FORK_CSPACE_ORPHAN_COPY. Roadmap 2.3, S42.
EXEC_ROOT_CSPACE ?= 0
ifeq ($(EXEC_ROOT_CSPACE),1)
CFLAGS  += -DEXEC_ROOT_CSPACE
ASFLAGS += -DEXEC_ROOT_CSPACE
endif

# FPU_NO_SAVE=1 drops the fxsave on the way out of ring 3, so a task's xmm/x87
# register file is never captured and it is handed a STALE image on its next
# entry. It destroys the task's own state and discloses nothing: fputest loses
# its sentinel, fpupeer still sees only its own restored file. The INTEGRITY half
# of S16.
FPU_NO_SAVE ?= 0
ifeq ($(FPU_NO_SAVE),1)
CFLAGS  += -DFPU_NO_SAVE
ASFLAGS += -DFPU_NO_SAVE
endif

# FPU_NO_RESTORE=1 drops the fxrstor on the way back to ring 3, so a task simply
# inherits whatever the previously-running task left in the physical registers.
# That is the disclosure S16 names, and it is the arm that matters: fpupeer reads
# fputest's sentinel out of registers it never wrote. Not the mirror of
# FPU_NO_SAVE -- one loses state, this one leaks it, which is why they are two
# arms and not one.
FPU_NO_RESTORE ?= 0
ifeq ($(FPU_NO_RESTORE),1)
CFLAGS  += -DFPU_NO_RESTORE
ASFLAGS += -DFPU_NO_RESTORE
endif

LIBHORUS_SELFTEST ?= 0
ifeq ($(LIBHORUS_SELFTEST),1)
CFLAGS  += -DLIBHORUS_SELFTEST
ASFLAGS += -DLIBHORUS_SELFTEST
LIBHORUS_SELFTEST_DEP = userspace/libhorustest.bin
endif

# LIBHORUS_RETRY_ANY=1 restores the pre-libhorus retry loop -- `while (r < 0)
# spin_delay();` -- which retries EVERY negative rc including SYS_ERR_PERM. That
# is finding G-8 signature C on demand: a denied task spins forever and the
# refusal is indistinguishable from a hang. USERSPACE only (libhorus is a ring-3
# library), so it goes on USERSPACE_CFLAGS, not CFLAGS.
LIBHORUS_RETRY_ANY ?= 0

# LIBHORUS_STRNCPY_UNTERMINATED=1 restores C strncpy's semantics for ustrncpy:
# terminate only if the source fits. Its callers write a name into a fixed buffer
# and then treat it as a C string, so the unterminated case is the one nobody
# tests and an attacker picks. USERSPACE only, as above.
LIBHORUS_STRNCPY_UNTERMINATED ?= 0

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
# Which bogus value to inject. 4 is the 2026-08-13 capture and exercises the
# guard's FLOOR; -7 is the 2026-08-17 capture and exercises the CEILING added
# after a real boot showed -7 sailing over a floor-only test (0xFFFFFFFFFFFFFFF9
# is above 0xFFFF800000000000). Both halves of the guard need an arm.
RESUME_RSP_INJECT_VALUE ?= 4
# RESUME_GUARD_FLOOR_ONLY=1 restores the pre-2026-08-18 floor-only predicate --
# the blind spot on demand. `make smoke-resume-guard-negative-control` builds it
# and requires the report to be ABSENT, the same shape as KFAULT_LEGACY_PRINTLN.
RESUME_GUARD_FLOOR_ONLY ?= 0
ifeq ($(RESUME_GUARD_FLOOR_ONLY),1)
CFLAGS += -DRESUME_GUARD_FLOOR_ONLY
endif
# RESUME_GUARD_BSS_ONLY=1 restores the bound the ceiling shipped with on
# 2026-08-18: [__bss_start, __bss_end) and nothing else, on the premise that every
# 64-bit kernel stack is a .bss array. The IST stacks are in .data, IST1 serves
# #PF, and the guard halts on a rejection -- so that build dies on the first ring-3
# page fault of any workload that takes one. This is the FALSE-POSITIVE arm: unlike
# every other RESUME_GUARD_* flag it does not make the guard miss something, it
# makes it reject something legal. `make smoke-resume-guard-ist-control` builds it
# and requires the false rejection to be PRESENT.
RESUME_GUARD_BSS_ONLY ?= 0
ifeq ($(RESUME_GUARD_BSS_ONLY),1)
CFLAGS += -DRESUME_GUARD_BSS_ONLY
endif
ifeq ($(RESUME_RSP_INJECT),1)
CFLAGS += -DRESUME_RSP_INJECT -DRESUME_RSP_INJECT_TICKS=$(RESUME_RSP_INJECT_TICKS) \
          -DRESUME_RSP_INJECT_VALUE='$(RESUME_RSP_INJECT_VALUE)'
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
# EXEC_REENTER_GLOBAL=1 restores the pre-2026-08-17 exec hand-off: ONE shared
# `int` naming the task whose exec re-entry is pending, consumed on the exit of
# every syscall on every CPU with no test that the exec belonged to that CPU.
# That is finding [G-9]: an exec armed on one core is taken by another, which
# claims the exec'ing task, installs its CR3 and resumes its freshly fabricated
# trap frame while the core that ran the exec is still on that same frame.
# Per-CPU storage is the fix; this flag is the defect on demand, and is what
# `make smoke-exec-reenter-control` builds.
EXEC_REENTER_GLOBAL ?= 0
ifeq ($(EXEC_REENTER_GLOBAL),1)
CFLAGS += -DEXEC_REENTER_GLOBAL
endif
# CR3_RECLAIM_UNGUARDED=1 restores the pre-2026-08-17 slot reclaim in
# create_user_pagedir: free the previous occupant's page tables unconditionally,
# on the uniprocessor argument that "the caller is on the kernel CR3, so the tree
# is not the one any CPU is walking". Another CPU routinely IS -- one parked in
# kernel_idle never reloads CR3, and SYS_KILL marks a task dead while it still
# runs in ring 3 on another core. That is finding [G-10]: the freed frames return
# to the pool and are handed out as ordinary pages while another core is still
# translating through them. `make smoke-cr3-reclaim-control` builds it.
CR3_RECLAIM_UNGUARDED ?= 0
ifeq ($(CR3_RECLAIM_UNGUARDED),1)
CFLAGS += -DCR3_RECLAIM_UNGUARDED
endif
# ---- roadmap 1.7: the spawn/exec staging window -----------------------------
#
# SPAWN_STAGE_UNSERIALISED=1 restores the pre-2026-08-18 spawn path: no lock at
# all over the arm -> consume window on the process-wide staging (the ELF staging
# buffer, the armed header, the staged argv). Two CPUs then interleave through
# it, which is what roadmap 1.7 is about.
#
# NO SMOKE TARGET USES THIS, deliberately. Measured over 16 boots at -smp 4 with
# SPAWN_STAGE_WIDEN=1 holding the window open: 214 entries, 0 contended, in both
# arms -- every spawner in the tree is init or one of its children, so two of
# them are never in the window at once. A control arm that cannot fail cannot
# gate anything. Kept for the day a workload has two live spawners; the theft it
# would then re-enable is REPORTED rather than executed, because do_spawn's owner
# check refuses a foreign image.
SPAWN_STAGE_UNSERIALISED ?= 0
ifeq ($(SPAWN_STAGE_UNSERIALISED),1)
CFLAGS += -DSPAWN_STAGE_UNSERIALISED
endif
# SPAWN_STAGE_WIDEN=1 is NOT a defect. It widens the arm -> consume window with a
# fixed spin so the interleaving is entered on most boots instead of on a lucky
# one, and it is set in BOTH arms when measuring -- that is what makes the pair a
# measurement rather than two unrelated runs. Same role KSTACK_RACE_WIDEN plays
# for [G-8]. Never ship it: it makes every spawn slower on purpose.
SPAWN_STAGE_WIDEN ?= 0
SPAWN_STAGE_WIDEN_SPINS ?= 12000000
ifeq ($(SPAWN_STAGE_WIDEN),1)
CFLAGS += -DSPAWN_STAGE_WIDEN -DSPAWN_STAGE_WIDEN_SPINS=$(SPAWN_STAGE_WIDEN_SPINS)u
endif
# SPAWN_OWNER_UNCHECKED=1 restores the pre-2026-08-18 consume: any task may spawn
# whatever image is armed, whoever armed it. That is finding [G-11] -- SYS_SUDO
# authenticates the caller and then elevates an image that need never have been
# theirs. `make smoke-spawn-owner-control` builds it and requires the self-test
# to FAIL.
# SPAWN_STAGE_TRACE=1 is NOT a defect either: it reports every arrival at the
# staging window that finds another CPU already inside it. That is the
# reachability half of the measurement -- a serialised build with zero thefts
# says nothing unless the window was actually entered twice. Set in BOTH arms.
SPAWN_STAGE_TRACE ?= 0
ifeq ($(SPAWN_STAGE_TRACE),1)
CFLAGS += -DSPAWN_STAGE_TRACE
endif
SPAWN_OWNER_UNCHECKED ?= 0
ifeq ($(SPAWN_OWNER_UNCHECKED),1)
CFLAGS += -DSPAWN_OWNER_UNCHECKED
endif
# SPAWN_OWNER_SELFTEST=1 runs the deterministic [G-11] witness at boot: forge a
# foreign owner on a legitimately staged image, require the spawn to be refused,
# then re-arm honestly and require it to succeed. Drives `make smoke-spawn-owner`.
SPAWN_OWNER_SELFTEST ?= 0
ifeq ($(SPAWN_OWNER_SELFTEST),1)
CFLAGS += -DSPAWN_OWNER_SELFTEST
endif

# KSTACK0_SHARED_PARK=1 restores the pre-2026-08-17 park target: all three
# fault/exit fallbacks in idt.c resume the CPU on tasks[0].kernel_stack_top, ONE
# stack shared by every CPU that takes the path. Two CPUs parked there both run
# `sti; hlt` on it and both push a trap frame at the same address on the next
# tick -- S20, in the one place g_kstack_inflight cannot see it (that mask is
# keyed on task ids and task 0 is legitimately current on several CPUs at once).
# The defect, on demand.
KSTACK0_SHARED_PARK ?= 0
ifeq ($(KSTACK0_SHARED_PARK),1)
CFLAGS += -DKSTACK0_SHARED_PARK
endif
# KSTACK0_PARK_TRACE=1 prints a line every time a CPU parks in the ring-0
# idle/reaper loop after the last runnable task died. Test-only, and the way the
# reachability of that path was measured rather than assumed (0 parks per healthy
# session; 5-8 per boot on a task-killing workload).
#
# NEVER BUILD THIS INTO A GATE THAT MATCHES AN EXACT STRING ON SERIAL, AND DO NOT
# ASSUME IT IS PASSIVE. It emits through kfault_*, which writes bytes straight to
# COM1 and bypasses console ownership -- correct for a panic, and a SECOND
# CONCURRENT WRITER during a live session (finding #126's hazard).
#
# It corrupts whatever ring-3 is printing, AND it perturbs the run enough to kill
# it: on the fixed kernel at -smp 4, 20 boots each, PROC_SELFTEST died 8 times
# with this flag and 0 times without it (2026-08-22; Fisher one-sided p = 0.0016).
# Any measurement taken in this configuration is a measurement of an instrumented
# system -- the ~40% "pre-existing claim leak" the park job's own comment carried
# for days was exactly that, 9/20 on a build with this flag in it. First the
# corruption:
#
#   PARKTRACE cpu=3 rsp=0xffffffff806ff0PROC_SELFTEST: PASS exit+kill+spawn
#
# `smoke-kstack-park` did build it and failed 10 boots in 25 on main because of it,
# with gate failure and a corrupted marker correlating 10 for 10. Only
# `smoke-kstack-park-control` may use it, because its assertion is the trace itself
# rather than a marker the trace can break.
KSTACK0_PARK_TRACE ?= 0
ifeq ($(KSTACK0_PARK_TRACE),1)
CFLAGS += -DKSTACK0_PARK_TRACE
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
# FPU_SELFTEST=1 embeds fputest + fpupeer and boots into them: two ring-3 tasks
# share one CPU, one loads a sentinel into all sixteen xmm registers and requires
# it intact across 64 switches, the other requires never to see it. The witness
# for SECURITY.md S16, whose witness column was an em-dash until 2026-08-28.
# Prints FPUTEST: PASS twice; `make smoke-fpu` asserts on both.
FPU_SELFTEST ?= 0
ifeq ($(FPU_SELFTEST),1)
CFLAGS  += -DFPU_SELFTEST
ASFLAGS += -DFPU_SELFTEST
FPU_SELFTEST_DEP = userspace/fputest.bin userspace/fpupeer.bin
endif

# FORK_SELFTEST=1 embeds forktest and boots straight into it: it forks itself and
# asserts from ring 3 that the child's memory is a copy-on-write COPY of the
# parent's (S39) and that a task with a CAP_FRAME mapped is refused (S40).
# Prints FORKTEST: PASS/FAIL; `make smoke-fork` asserts on it. Gated off the
# ship kernel. Roadmap 2.3.
FORK_SELFTEST ?= 0
ifeq ($(FORK_SELFTEST),1)
CFLAGS  += -DFORK_SELFTEST
ASFLAGS += -DFORK_SELFTEST
FORK_SELFTEST_DEP = userspace/forktest.bin
endif

# FORKEXEC_SELFTEST=1 embeds forkexectest + forkexecee and boots straight into
# them: the driver forks itself, the child replaces its image with
# SYS_EXEC_NAMED, and the driver then asserts from ring 3 that the exec replaced
# the IMAGE and not the AUTHORITY (S42) -- and that its own memory survived the
# reclaim of the cloned address space the exec performed (S39). Prints
# FORKEXECTEST: PASS/FAIL; `make smoke-forkexec` asserts on it. Gated off the
# ship kernel. Roadmap 2.3.
FORKEXEC_SELFTEST ?= 0
ifeq ($(FORKEXEC_SELFTEST),1)
CFLAGS  += -DFORKEXEC_SELFTEST
ASFLAGS += -DFORKEXEC_SELFTEST
FORKEXEC_SELFTEST_DEP = userspace/forkexectest.bin userspace/forkexecee.bin
endif

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

# Every object rebuilds when the flag strings change. See .build-flags above.
#
# BUILD_FLAGS_UNSTAMPED=1 removes that dependency -- the pre-2026-08-21 build, in
# which a -D flag was invisible to make. Not a build option, a control arm:
# `smoke-defect-flags-rebuild-control` builds it and REQUIRES the stale flag to
# survive a flagless rebuild, which is the defect this mechanism exists to stop.
BUILD_FLAGS_UNSTAMPED ?= 0
ifneq ($(BUILD_FLAGS_UNSTAMPED),1)
$(OBJS): .build-flags
endif

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
	@cargo build --release --manifest-path rust/Cargo.toml --target $(RUST_TARGET) $(RUST_FEATURE_ARGS)
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

src/boot/multiboot.o: userspace/shell.bin userspace/init.bin userspace/hello.bin userspace/captest.bin userspace/fs_server.bin userspace/console_server.bin $(ELF_SELFTEST_DEP) $(ELF64_SELFTEST_DEP) $(ASLR_SELFTEST_DEP) $(PREEMPT_SELFTEST_DEP) $(SIGNAL_SELFTEST_DEP) $(TSD_SELFTEST_DEP) $(FS_SELFTEST_DEP) $(INIT_FS_SELFTEST_DEP) $(NEWLIB_SELFTEST_DEP) $(NOTIFY_SELFTEST_DEP) $(KLOG_FORGE_SELFTEST_DEP) $(MAPPHYS_SELFTEST_DEP) $(DEVCAP_SELFTEST_DEP) $(NET_SELFTEST_DEP) $(SHLIB_SELFTEST_DEP) $(SHLIBC_SELFTEST_DEP) $(IOPORT_SELFTEST_DEP) $(IRQ_SELFTEST_DEP) $(CONSOLE_SELFTEST_DEP) $(RECVBLOCK_SELFTEST_DEP) $(LIBHORUS_SELFTEST_DEP) $(FRAME_SELFTEST_DEP) $(PASSWD_PROBE_DEP) $(VFS_SELFTEST_DEP) $(COW_SELFTEST_DEP) $(FORK_SELFTEST_DEP) $(FORKEXEC_SELFTEST_DEP) $(FPU_SELFTEST_DEP) $(AP_TRAMPOLINE_DEP) $(SMP_SELFTEST_DEP) $(PROC_SELFTEST_DEP)

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
# Every .rs, not a hand-maintained subset: this list named five files out of the
# crate's fifteen, so editing rng.rs (or aead.rs, or ps.rs) rebuilt nothing and
# the kernel linked the previous staticlib. Same failure as the -D flags that
# survived a flagless rebuild -- a measurement taken against a source file the
# binary does not contain. Found while adding the seed gate, whose control arm
# would have been measured on a stale library.
#
# .build-flags is a prerequisite for the same reason the objects have it: a cargo
# FEATURE is not a file either, so `make RNG_UNSEEDED_LEGACY=1` followed by a
# plain `make` would leave the defective staticlib linked into a build whose
# every .c was recompiled without the flag. The flag is stamped into CFLAGS
# precisely so that this file changes and cargo re-runs.
$(RUST_LIB): rust/Cargo.toml .build-flags $(wildcard rust/src/*.rs)
	@cargo build --locked --release --manifest-path rust/Cargo.toml --target $(RUST_TARGET) $(RUST_FEATURE_ARGS) || cargo build --release --manifest-path rust/Cargo.toml --target $(RUST_TARGET) $(RUST_FEATURE_ARGS)
	@test -f $(RUST_LIB) || (echo "ERROR: $(RUST_LIB) missing"; exit 1)
endif

# `run` is the interactive/dev target: it ships the ported coreutils and their man
# pages as boot modules (RUN_MODULES=1 by default), so an interactive session comes
# up with /bin populated and `man` reading /usr/share/man. Set RUN_MODULES=0 for a
# module-free (GPLv3-clean) boot; the plain `boot.iso` / release target stays
# module-free regardless.
RUN_MODULES ?= 1
# `make run` boots WITH an emulated TPM when swtpm is installed, and without one
# otherwise. The measured-boot path (PCR 8/9, and the sealed volume KEK) is the
# configuration the security properties are stated over, so booting it by default
# means the system you actually run is the one the documentation describes --
# rather than the no-TPM fallback that every log used to show.
#
# NO_TPM=1 forces the plain boot: the fallback needs to stay easy to reach,
# because it is what a machine without a TPM gets and it should not be a path
# nobody ever exercises deliberately.
run: kernel.elf
	@if command -v swtpm >/dev/null 2>&1 && [ "$(NO_TPM)" != 1 ]; then \
	    echo "[run] swtpm found -- booting with an emulated TPM (NO_TPM=1 to skip)"; \
	    $(MAKE) --no-print-directory run-tpm; \
	 else \
	    $(MAKE) --no-print-directory run-plain; \
	 fi

.PHONY: run-plain
run-plain: kernel.elf
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

# A bare ISO with no boot modules -- `boot.iso` above is the one that boots a
# usable system, and the one `make run`/`make smoke` use. The grub-mkrescue
# line here used to end `2>/dev/null || true`, so `make iso` announced success
# and left no horus.iso when the tool was missing. Same defect class as the
# build-hash recording step (see reproducible-build below): a step that cannot
# fail. It now reports like boot.iso's does.
iso: kernel.elf
	@mkdir -p iso/boot/grub && cp kernel.elf iso/boot/ && cp grub.cfg iso/boot/grub/grub.cfg
	@grub-mkrescue -o horus.iso iso 2>&1 || (echo "grub-mkrescue failed (install grub-pc-bin xorriso)" && exit 1)

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
# Issue #176's control arm. Applied HERE, at top level: USERSPACE_CFLAGS is
# assigned with `=` just above, so setting it beside the other control-arm flags
# would be overwritten -- and it must not sit inside another flag's ifeq, which
# is where it was first written and where it silently never fired.
ifeq ($(SYSCALL_PTR_TRUNC32),1)
USERSPACE_CFLAGS += -DSYSCALL_PTR_TRUNC32
endif
# netd's two control arms, HERE for the same reason and not one line earlier.
# Both live in userspace/netd.c, so they are userspace flags; putting them beside
# their `?= 0` defaults several hundred lines up would have them overwritten by
# the `=` assignment above and never fire -- which is the exact way
# SYSCALL_PTR_TRUNC32 was first written and silently did nothing.
ifeq ($(NET_NO_BUSMASTER),1)
USERSPACE_CFLAGS += -DNET_NO_BUSMASTER
endif
ifeq ($(NET_NO_DECODE),1)
USERSPACE_CFLAGS += -DNET_NO_DECODE
endif
ifeq ($(NET_IOMMU_NO_MAP),1)
USERSPACE_CFLAGS += -DNET_IOMMU_NO_MAP
endif
# Both halves of the S47 arm: the kernel must honour the extra argument AND the
# driver must supply one, so the flag reaches both compilations.
ifeq ($(MSI_VECTOR_FROM_USER),1)
USERSPACE_CFLAGS += -DMSI_VECTOR_FROM_USER
endif
ifeq ($(SHLIB_TEXT_WRITABLE),1)
USERSPACE_CFLAGS += -DSHLIB_TEXT_WRITABLE
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

# Both libhorus control arms are RING-3 flags: they change a userspace library,
# not the kernel, so they belong on USERSPACE_CFLAGS. Applied here, at top level,
# AFTER USERSPACE_CFLAGS is assigned with `=` and outside any other flag's ifeq --
# the same placement SYSCALL_PTR_TRUNC32 needs, and for the same reason: inside
# another conditional they would apply only when that condition held, and the arm
# would silently build the fixed code.
ifeq ($(LIBHORUS_RETRY_ANY),1)
USERSPACE_CFLAGS += -DLIBHORUS_RETRY_ANY
endif
ifeq ($(LIBHORUS_STRNCPY_UNTERMINATED),1)
USERSPACE_CFLAGS += -DLIBHORUS_STRNCPY_UNTERMINATED
endif
# The two hvfs control arms are ring-3 for the same reason and need the same
# top-level placement: hvfs is a userspace library, and inside another flag's
# ifeq these would silently build the fixed code.
ifeq ($(VFS_FIRST_MATCH),1)
USERSPACE_CFLAGS += -DVFS_FIRST_MATCH
endif
ifeq ($(VFS_MOUNT_UNGATED),1)
USERSPACE_CFLAGS += -DVFS_MOUNT_UNGATED
endif
# The two migration arms (roadmap 2.4), ring-3 and top-level for the same reason.
ifeq ($(POSIX_LEGACY_WALK),1)
USERSPACE_CFLAGS += -DPOSIX_LEGACY_WALK
endif
ifeq ($(HVFS_DOTDOT_SERVER),1)
USERSPACE_CFLAGS += -DHVFS_DOTDOT_SERVER
endif

userspace/%.o: userspace/%.c
	$(CC) $(USERSPACE_CFLAGS) -c $< -o $@

# Static-PIE (ET_DYN) link for the shipped, ASLR-loaded binaries.
# malloc.o is always linked so any binary can call malloc/free without
# extra Makefile rules.
MALLOC_OBJ = userspace/malloc.o

# libhorus is available to every freestanding binary: it is the shared runtime
# those programs previously hand-copied 22 definitions of. Offering it
# unconditionally rather than per-program is what makes adding a server a
# one-line change (see USERPROG below).
#
# AN ARCHIVE, NOT AN OBJECT, and that distinction was measured rather than
# assumed. A plain .o is linked whole. The first draft of this rule added one to
# every binary and the comment claimed the cost was nil; `size` said otherwise:
#
#   captest .text     9339 -> 10389   (+1050, for a library it never calls)
#   fs_server .text   9899 -> 10285   (+386)
#
# With the archive, a member is extracted only when it resolves an undefined
# symbol, and captest returns to 9339 exactly -- byte-identical to before
# libhorus existed. fs_server stays at 10285: it uses seven of these functions
# and now carries the whole member rather than its own seven copies. That is the
# trade, stated in bytes rather than asserted.
#
# The archive must come AFTER the objects that reference it on the link line;
# ld resolves archives in order, and an archive listed first sees no undefined
# symbols yet and contributes nothing.
#
# ADDED to the newlib link rules on 2026-08-23, reversing the note that stood
# here. It said: not added, because those programs have a real libc and a second
# memcpy under a different name is an ambiguity waiting to be resolved wrongly.
#
# What changed is what needs it. posix.c -- the libc glue every newlib program
# links -- carried its own path walker, one of the three the hvfs namespace was
# written to replace, and hvfs.o is the member that replaces it. The ambiguity
# the note feared does not arise: nothing in libhorus.o is named `memcpy`. The
# symbols are `umemcpy`, `umemset`, `ustrncpy` (which hvfs.o references),
# `uslen`, `ustreq`, `kput*`, `spin_delay*` and `ipc_call_retry`, none of which
# collide with anything in libc, and the linker resolves each exactly once.
#
# It costs the ~200 bytes of libhorus.o in a newlib binary, and buys one walker
# instead of three. The alternative -- giving hvfs.o private static copies of
# three helpers -- would have cost the audited ones: `ustrncpy`'s termination is
# what LIBHORUS_STRNCPY_UNTERMINATED falsifies, and a private copy would not be
# covered by that arm.
#
# hvfs.o is a SEPARATE member rather than part of libhorus.o, and that is the
# same measurement again: a program that resolves no path (captest, klogtest,
# framepeer) must not carry the mount table and the walker. Two members means
# ld extracts each only when something references it.
LIBHORUS_LIB = userspace/libhorus.a
LIBHORUS_OBJS = userspace/libhorus.o userspace/hvfs.o
$(LIBHORUS_LIB): $(LIBHORUS_OBJS)
	$(AR) rcs $@ $(LIBHORUS_OBJS)

userspace/%.pie.elf: userspace/%.o $(MALLOC_OBJ) $(LIBHORUS_LIB) userspace/pie.ld
	$(LD) -m elf_x86_64 -pie -T userspace/pie.ld -o $@ $< $(MALLOC_OBJ) $(LIBHORUS_LIB)

# Adding a freestanding userspace program is one line:
#
#     $(eval $(call USERPROG,myserver))
#
# which declares userspace/myserver.c -> userspace/myserver.pie.elf and adds it
# to USERPROGS so the ISO rule picks it up. Before this, each program needed its
# own hand-written stanza and its own reading of the pattern rules, which is why
# several of them ended up subtly different from each other.
#
# It does NOT wire capability delegation -- that is init.c's launch_*() and it is
# deliberately manual. Which authority a program receives is the security
# decision this whole system exists to make explicit, and a macro that guessed
# would be a macro that granted. See docs/ARCHITECTURE.md, "Adding a userspace
# program".
define USERPROG
USERPROGS += userspace/$(1).pie.elf
userspace/$(1).pie.elf: userspace/$(1).o $$(MALLOC_OBJ) $$(LIBHORUS_LIB) userspace/pie.ld
endef

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
                                userspace/malloc.o $(LIBHORUS_LIB) userspace/pie.ld
	$(LD) -m elf_x86_64 -pie -T userspace/pie.ld -o $@ \
	    userspace/crt0.o userspace/hello_newlib.o userspace/newlib_glue.o \
	    userspace/newlib_glue64.o userspace/posix.o userspace/malloc.o \
	    $(LIBHORUS_LIB) -L$(NEWLIB_LIB) -lc

userspace/hello_newlib.bin: userspace/hello_newlib.stripped.elf tools/mkheadered
	@./tools/mkheadered $< $@ "hello_newlib"

# termtest — exercises the console raw-terminal layer (termios + winsize + raw
# read/write) end to end; shipped as a /bin module by TERM_MODULE=1 (smoke-term).
userspace/termtest.o: userspace/termtest.c $(NEWLIB_LIB)/libc.a
	$(CC) $(NEWLIB_CFLAGS) -c $< -o $@

userspace/termtest.pie.elf: userspace/termtest.o $(NEWLIB_GLUE_OBJS) \
                            userspace/malloc.o $(LIBHORUS_LIB) userspace/pie.ld
	$(LD) -m elf_x86_64 -pie -T userspace/pie.ld -o $@ \
	    userspace/crt0.o userspace/termtest.o userspace/newlib_glue.o \
	    userspace/newlib_glue64.o userspace/posix.o userspace/malloc.o \
	    $(LIBHORUS_LIB) -L$(NEWLIB_LIB) -lc

userspace/termtest.bin: userspace/termtest.stripped.elf tools/mkheadered
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

# ---- The shared libc (roadmap 2.5) -----------------------------------------
#
# newlib, its port glue and libhorus linked into ONE shared object that
# src/kernel/shlib.c can load: ~135 KiB of text shared between every task, and a
# writable segment instantiated per task (S50).
#
# NOT YET LINKED AGAINST. Programs still link libc.a statically. What this
# target does today is make the object real and CHECK it, so the three
# separate ways of producing one the kernel would refuse cannot come back
# silently -- each was found by building this, and none of them is a link error:
#
#   * without the port's syscall glue, 10 undefined symbols and 10 JUMP_SLOTs
#   * without -Bsymbolic, intra-library references become GLOB_DAT
#   * ONE weak-undefined symbol (__on_exit_args) emits a GLOB_DAT by itself,
#     unless -z nodynamic-undefined-weak says to resolve it statically to 0
#
# The remaining work is the CALLER side, and it has a real blocker recorded in
# docs/LIMITATIONS.md: a program's direct reference to a DATA symbol cannot be
# redirected to the library's copy without a GOT. `_impure_ptr` survives that
# (it is a pointer TO per-task state, so a program can hold its own copy of the
# pointer), but `optarg`/`optind` are the state itself and would desynchronise.
COREUTILS_ALL_OBJS = $(addprefix $(COREUTILS_DIR)/,$(addsuffix .o,$(COREUTILS_PROGS))) \
                     $(COREUTILS_PORT_OBJS)

# Compiled -fPIC, and every one of these is also built non-PIC for the static
# link. Separate objects rather than reusing them: the shared object needs PIC
# and the static programs must keep the exact objects they ship with, so the two
# builds do not share intermediate state.
userspace/%.pic.o: userspace/%.c $(NEWLIB_LIB)/libc.a
	$(CC) $(NEWLIB_CFLAGS) -fPIC -c $< -o $@

# The export table, derived from what the programs actually reference. See
# tools/gen_libc_exports.sh for why it is generated and why order is the ABI.
# The providers after `--` are the objects that go into libc.so, so the export
# set is what the LIBRARY has rather than only what newlib has: the port's glue
# is in there too, and posix_init is the entry point a shared-linked program
# needs before main.
LIBC_SO_GLUE_OBJS = userspace/newlib_glue.o userspace/newlib_glue64.o \
                    userspace/posix.o userspace/hvfs.o userspace/libhorus.o

userspace/libc_exports.c: $(COREUTILS_ALL_OBJS) $(LIBC_SO_GLUE_OBJS) $(NEWLIB_LIB)/libc.a tools/gen_libc_exports.sh
	@./tools/gen_libc_exports.sh $(NEWLIB_LIB)/libc.a $@ $(COREUTILS_ALL_OBJS) -- $(LIBC_SO_GLUE_OBJS)

LIBC_SO_OBJS = userspace/libc_exports.pic.o userspace/newlib_glue.pic.o \
               userspace/newlib_glue64.pic.o userspace/posix.pic.o \
               userspace/hvfs.pic.o userspace/libhorus.pic.o

userspace/libc.so: $(LIBC_SO_OBJS) userspace/shlib.ld $(NEWLIB_LIB)/libc.a
	$(CC) -shared -fPIC -m64 -nostdlib -Wl,--build-id=none \
	  -Wl,-e,shlib_exports -Wl,-T,userspace/shlib.ld \
	  -Wl,-Bsymbolic -Wl,-z,nodynamic-undefined-weak \
	  -o $@ $(LIBC_SO_OBJS) -L$(NEWLIB_LIB) -lc

# ---- Linking a program against the shared libc -------------------------------
#
# The stub archive is what a program links INSTEAD of libc.a: one tail-jump
# thunk per exported function, plus the startup shim that binds the library and
# the crt0 that runs it before main. See tools/gen_libc_stubs.sh for why the
# thunks are assembly and why the scratch register is %r11.
userspace/libc_stubs.S: userspace/libc_exports.c tools/gen_libc_stubs.sh
	@./tools/gen_libc_stubs.sh $< $@

userspace/libc_stubs.o: userspace/libc_stubs.S
	$(CC) $(USERSPACE_CFLAGS) -c $< -o $@

userspace/shlib_start.o: userspace/shlib_start.c userspace/libc_exports.h
	$(CC) $(USERSPACE_CFLAGS) -I userspace -c $< -o $@

userspace/crt0_shared.o: userspace/crt0_shared.c
	$(CC) $(USERSPACE_CFLAGS) -c $< -o $@

LIBC_STUB_LIB = userspace/libc_stubs.a
$(LIBC_STUB_LIB): userspace/libc_stubs.o userspace/shlib_start.o
	@rm -f $@
	@$(AR) rcs $@ $^

# A program linked this way carries NO libc: crt0_shared, its own objects, and
# the stubs. Not $(NEWLIB_GLUE_OBJS), not malloc.o, not -lc -- all of that is in
# the library. Compiled against newlib's headers all the same, because the
# declarations are still newlib's; only the definitions moved.
userspace/hello_shared.o: userspace/hello_shared.c $(NEWLIB_LIB)/libc.a
	$(CC) $(NEWLIB_CFLAGS) -c $< -o $@

userspace/hello_shared.pie.elf: userspace/hello_shared.o userspace/crt0_shared.o \
                                $(LIBC_STUB_LIB) userspace/pie.ld
	$(LD) -m elf_x86_64 -pie --gc-sections -T userspace/pie.ld -o $@ \
	    userspace/crt0_shared.o userspace/hello_shared.o $(LIBC_STUB_LIB)

# Every shared object in the tree must be one the loader accepts. A static gate
# because the properties are decidable by reading the object, and because a
# refusal at boot is a correct behaviour with a terrible diagnostic: the library
# is simply absent, and the first symptom is a fault on a call into nothing.
.PHONY: check-shared-objects
check-shared-objects: userspace/shlibdemo.so userspace/libc.so
	@python3 tools/check_shared_object.py $^

userspace/coreutils_%.pie.elf: $(COREUTILS_DIR)/%.o $(COREUTILS_PORT_OBJS) \
                               $(NEWLIB_GLUE_OBJS) userspace/malloc.o $(LIBHORUS_LIB) userspace/pie.ld
	$(LD) -m elf_x86_64 -pie --gc-sections -T userspace/pie.ld -o $@ \
	    userspace/crt0.o $< $(COREUTILS_PORT_OBJS) \
	    userspace/newlib_glue.o userspace/newlib_glue64.o userspace/posix.o \
	    userspace/malloc.o $(LIBHORUS_LIB) -L$(NEWLIB_LIB) -lc

# The header's embedded name is what spawn-by-name matches, so it is the plain
# utility name ("cat"), not the coreutils_ file prefix.
# ---- Strip before shipping ---------------------------------------------------
#
# MEASURED 2026-08-29, and it changes what roadmap 2.5 is for. A newlib-linked
# `coreutils_echo` is 404,528 bytes on disk, of which `size` accounts for only
# ~88 KiB of text+data+bss: `.debug_info` alone is 144,065 bytes, and the DWARF
# sections together are about 77% of the file. Every one of those bytes was being
# shipped in the boot module and stored on the volume.
#
#   original     404,528
#   strip-debug  103,816
#   strip-all     94,128
#
# So the "~450 KiB each" that justified sharing a libc is mostly debug info, not
# libc. Stripping saves ~310 KiB per binary across 11 of them; sharing libc saves
# the ~70 KiB of libc text each, once. The order of magnitude was in the DWARF.
#
# --strip-all rather than --strip-debug: nothing in this system reads a ring-3
# binary's symbol table -- the loader parses PT_LOAD and the kernel does not
# symbolise ring-3 faults -- so the extra 9,688 bytes are as unused as the DWARF.
#
# The UNSTRIPPED .pie.elf stays on disk and is what to point a debugger or
# addr2line at. Only what ships is stripped, which is the distinction worth
# keeping: this reduces the image, not the ability to diagnose it.
userspace/%.stripped.elf: userspace/%.pie.elf
	@$(OBJCOPY) --strip-all $< $@

# Keep the unstripped .pie.elf. Inserting a stripping step turns it into a make
# INTERMEDIATE -- a file created only to chain two rules -- and make deletes those
# when it is done, which would have quietly made the sentence above ("the
# unstripped .pie.elf stays on disk") false the moment it was written.
#
# .PRECIOUS, NOT .SECONDARY, AND THE DIFFERENCE COST THREE GREEN GATES.
#
# The first attempt was a bare `.SECONDARY:`. With no prerequisites that does not
# mean "keep the file I just named" -- it means EVERY target in the build is
# treated as intermediate. Intermediate has a second meaning beyond deletion:
# make will not CREATE a missing intermediate when the ultimate target already
# exists. userspace-clean's globs did not cover *.a, so userspace/libhorus.a
# survived `make clean`; libhorus.o and hvfs.o did not, and make then declined to
# rebuild them because the archive above them was present. Every program in the
# tree linked a libhorus.a built from the PREVIOUS invocation's flags.
#
# That is a fail-open of the worst kind, because it fails GREEN: the
# LIBHORUS_RETRY_ANY control arm stopped reproducing its own defect (the stale
# archive still held the FIXED ipc_call_retry, so the arm reported PASS where it
# must report the spin), and smoke-vfs and smoke-newlib failed on a stale hvfs.o.
# A control arm that cannot fail is not a control arm, and nothing about the
# symptom pointed at the line that caused it.
#
# .PRECIOUS affects deletion and nothing else -- it never marks a target
# intermediate, so it cannot change what make decides to rebuild. It is the
# narrow tool for the narrow job.
#
# The .stripped.elf is deliberately NOT listed, and does not need to be: a file
# named explicitly as a prerequisite of a static pattern rule (the .bin rules
# below) is not intermediate, so make never deletes it. Only the .pie.elf is at
# risk, because it is reached ONLY by chaining the %.stripped.elf pattern onto
# the %.pie.elf pattern -- an intermediate make invented. Verified in both
# directions before this line was written: with .PRECIOUS commented out,
# `make clean && make userspace/hello.bin` leaves hello.stripped.elf and DELETES
# hello.pie.elf; with it, both survive.
.PRECIOUS: userspace/%.pie.elf

userspace/coreutils_%.bin: userspace/coreutils_%.stripped.elf tools/mkheadered
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

userspace/tcc.pie.elf: $(TCC_OBJS) $(NEWLIB_GLUE_OBJS) userspace/malloc.o $(LIBHORUS_LIB) userspace/pie.ld
	$(LD) -m elf_x86_64 -pie --gc-sections -T userspace/pie.ld -o $@ \
	    userspace/crt0.o $(TCC_OBJS) \
	    userspace/newlib_glue.o userspace/newlib_glue64.o userspace/posix.o \
	    userspace/malloc.o $(LIBHORUS_LIB) -L$(NEWLIB_LIB) -lc

userspace/tcc.bin: userspace/tcc.stripped.elf tools/mkheadered
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
$(SHIPPED_PIE_BINS): userspace/%.bin: userspace/%.stripped.elf tools/mkheadered
	@./tools/mkheadered $< $@ "$*"

# PIE test-only binaries (not shipped): built via the same static-PIE path as
# the shipped bins, but kept out of $(SHIPPED_PIE_BINS)/`userspace`. proctest is
# PIE (not flat) because it dereferences .rodata string literals, which on 32-bit
# -fPIE go through the GOT and only resolve once try_elf_load applies the
# R_386_RELATIVE relocations — the flat load path does not.
PIE_TEST_BINS = userspace/fsclient.bin userspace/proctest.bin userspace/exectest.bin userspace/grantee.bin userspace/sigtarget.bin userspace/faulter.bin userspace/sigwaiter.bin userspace/argtest.bin userspace/notifytest.bin userspace/cowtest.bin userspace/forktest.bin userspace/forkexectest.bin userspace/forkexecee.bin userspace/fputest.bin userspace/fpupeer.bin userspace/mapphystest.bin userspace/devcaptest.bin userspace/netd.bin userspace/shlibtest.bin userspace/shlibpeer.bin userspace/ioporttest.bin userspace/irqtest.bin userspace/consoletest.bin userspace/recvblocksrv.bin userspace/recvblockcli.bin userspace/klogtest.bin userspace/libhorustest.bin userspace/frametest.bin userspace/framepeer.bin userspace/passwdprobe.bin userspace/dev_server.bin userspace/vfstest.bin userspace/libctest.bin userspace/hello_shared.bin
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

# The shared library's layout, derived from the object rather than written down
# in the tests. shlibtest.c and shlibpeer.c held a hardcoded export-table offset
# (SHLIB_VA + 0x4000) until 2026-08-29; shlib.ld moved it, and a test reading the
# wrong address does not fail honestly -- it reads whatever is there. Generated
# from shlibdemo.so so the two cannot disagree.
userspace/shlib_offsets.h: userspace/shlibdemo.so tools/shlib_offsets.sh
	@./tools/shlib_offsets.sh $< $@

userspace/shlibtest.o userspace/shlibpeer.o: userspace/shlib_offsets.h

# libctest indexes the shared libc's export table, so it needs the header
# generated alongside that table -- never a remembered number.
#
# THE HEADER NEEDS A RULE OF ITS OWN, and not having one was a real defect.
# One run of the generator produces BOTH files, but make understands
# single-output rules: only libc_exports.c was a known target, so a prerequisite
# on the .h gave "No rule to make target 'userspace/libc_exports.h'" on any tree
# that did not already have one. Invisible locally, where a previous run had
# always left the file behind; five seconds into a clean CI checkout otherwise.
#
# Depending on the .c instead was tried and is NOT sufficient: with the .c
# current and the .h deleted on its own, make consults no rule for the .h at all
# and the compile fails on a missing include. So the .o depends on the .h, and
# the .h has a rule that regenerates it -- guarded, because the generator writes
# both files and rewriting the .c on every miss would make it look newer than
# everything downstream of it.
userspace/libctest.o: userspace/libc_exports.h
userspace/libctest.o: CPPFLAGS += -I userspace

userspace/libc_exports.h: userspace/libc_exports.c
	@[ -f $@ ] || ./tools/gen_libc_exports.sh $(NEWLIB_LIB)/libc.a $< $(COREUTILS_ALL_OBJS)

# Flat self-test payloads: HORU-wrap the objcopy'd raw image (loaded flat).
userspace/%.bin: userspace/%.raw tools/mkheadered
	@name="$$(basename $@ .bin)"; ./tools/mkheadered $< $@ "$$name"

userspace: $(SHIPPED_PIE_BINS)

userspace-clean:
	rm -f userspace/*.o userspace/*.a userspace/*.so userspace/*.elf userspace/*.pie.elf userspace/*.stripped.elf userspace/*.raw userspace/*.bin userspace/*_image.h userspace/shlib_offsets.h userspace/libc_exports.c userspace/libc_exports.h userspace/libc_stubs.S tools/mkheadered

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
	@$(MAKE) --no-print-directory ASPACE_SELFTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory NZCOW_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='NZCOW_SELFTEST: PASS' \
		FAIL_MARKER='NZCOW_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Control arm -- the arena guard. COW_ARENA_UNGUARDED=1 lets a copy-on-write
# break proceed on a page belonging to a kernel object. The selftest drives it
# with a REAL KOBJ_FRAME whose refcount is 2, so the arm takes the SHARED branch:
# a page is allocated from the anonymous pool (paid for by no untyped region),
# the PTE is repointed away from the object, and the frame's pin drops. At
# refcount 1 the break would only upgrade the PTE in place, which is the wrong
# half of the defect to measure. The FAIL marker must be PRESENT.
.PHONY: smoke-nzcow-arena-control
smoke-nzcow-arena-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NZCOW_SELFTEST=1 COW_ARENA_UNGUARDED=1
	@$(MAKE) --no-print-directory NZCOW_SELFTEST=1 COW_ARENA_UNGUARDED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='NZCOW_SELFTEST: FAIL arena-cow-broken' \
		tools/smoke_test.sh boot.iso
	@echo "NZCOW ARENA CONTROL: PASS - unguarded, a kernel object's page is copied out from under it"

.PHONY: smoke-wx
smoke-wx:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory WX_SELFTEST=1
	@$(MAKE) --no-print-directory WX_SELFTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory WX_SELFTEST=1 SMP=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 SMP_CPUS=$(SMP_CPUS) REQUIRE_MARKER='WX_SELFTEST: PASS' \
		FAIL_MARKER='WX_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

.PHONY: smoke-cpu
smoke-cpu:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CPU_SELFTEST=1
	@$(MAKE) --no-print-directory CPU_SELFTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory PERCPU_SELFTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory FLUSH_SELFTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory STACKGUARD_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='STACKGUARD_SELFTEST: PASS' \
		FAIL_MARKER='STACKGUARD_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build the kernel with the gated ELF-loader self-test, boot it headless, and
# require the in-kernel self-test to report PASS on serial (in addition to the
# normal boot reaching userspace). Runtime-verifies the try_elf_load + W^X path.
.PHONY: smoke-elf
smoke-elf:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory ELF_SELFTEST=1
	@$(MAKE) --no-print-directory ELF_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='ELF_SELFTEST: PASS' \
		FAIL_MARKER='ELF_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

smoke-elf64:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory ELF64_SELFTEST=1
	@$(MAKE) --no-print-directory ELF64_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='ELF64_SELFTEST: PASS' \
		FAIL_MARKER='ELF64_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Image-base ASLR: spawn several PIE images and assert the load base actually
# varies and stays inside the premap-containment bound (ASLR_SELFTEST: PASS).
.PHONY: smoke-aslr
smoke-aslr:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory ASLR_SELFTEST=1
	@$(MAKE) --no-print-directory ASLR_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='ASLR_SELFTEST: PASS' \
		FAIL_MARKER='ASLR_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated preemption self-test, boot headless, and require the
# in-kernel test to report PASS -- runtime proof that the timer time-slices two
# non-yielding ring-3 tasks.
.PHONY: smoke-preempt
smoke-preempt:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PREEMPT_SELFTEST=1
	@$(MAKE) --no-print-directory PREEMPT_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='PREEMPT_SELFTEST: PASS' \
		FAIL_MARKER='PREEMPT_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated signal self-test, boot headless, and require the handler
# to run on a deliberate fault -- runtime proof that a ring-3 fault is delivered
# to a registered handler instead of killing the task.
.PHONY: smoke-signal
smoke-signal:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SIGNAL_SELFTEST=1
	@$(MAKE) --no-print-directory SIGNAL_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='SIGNAL_SELFTEST: PASS' \
		FAIL_MARKER='SIGNAL_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated TSD self-test, boot headless, and require the marker that
# proves a ring-3 RDTSC faulted into its handler (CR4.TSD engaged).
smoke-tsd:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory TSD_SELFTEST=1
	@$(MAKE) --no-print-directory TSD_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='TSD_SELFTEST: PASS' \
		FAIL_MARKER='TSD_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated E820 self-test, boot headless, and require the marker
# proving the physical pool was sized from the multiboot2 memory map (boots to
# the login prompt as normal and asserts the marker along the way).
smoke-e820:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory E820_SELFTEST=1
	@$(MAKE) --no-print-directory E820_SELFTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory FS_SELFTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory INIT_FS_SELFTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory PERSIST_SELFTEST=1 STORAGE_ATA=1 HANG_WATCHDOG=1 HANG_WATCHDOG_TICKS=6000 boot.iso
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
	@$(MAKE) --no-print-directory PERM_SELFTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory WAL_CRASHTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory WAL_CRASHTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory WAL_CRASHTEST=1 WAL_NO_FLUSH=1 boot.iso
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
	@$(MAKE) --no-print-directory WAL_CRASHTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory WAL_CRASHTEST=1 WAL_NO_FLUSH=1 boot.iso
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
	@$(MAKE) --no-print-directory CONC_SELFTEST=1 HANG_WATCHDOG=1 HANG_WATCHDOG_TICKS=6000 boot.iso
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
	@$(MAKE) --no-print-directory NEWLIB_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='NEWLIB_SELFTEST: PASS' \
		FAIL_MARKER='NEWLIB_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# ---- roadmap 2.4: the libc walks paths through hvfs -------------------------
# Both arms assert on hello_newlib's "." / ".." checks, which are the migration's
# witness: they are the paths a libc program passes to open(), and they are what
# a private walker got wrong.
#
# Control arm 1 -- the walker itself. POSIX_LEGACY_WALK=1 restores posix.c's
# private copy, which resolved neither "." nor "..".
.PHONY: smoke-newlib-walk-control
smoke-newlib-walk-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NEWLIB_SELFTEST=1 POSIX_LEGACY_WALK=1
	@$(MAKE) --no-print-directory NEWLIB_SELFTEST=1 POSIX_LEGACY_WALK=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='NEWLIB_SELFTEST: FAIL dot-here' \
		tools/smoke_test.sh boot.iso

# Control arm 2 -- the ".." branch hvfs shipped with. HVFS_DOTDOT_SERVER=1 asks
# the server for a ".." entry it never creates, so the pinned case still works
# and the descending case does not. The marker is specifically dotdot-back: an
# arm that reddened the whole suite would not show that this branch, and only
# this branch, was dead.
.PHONY: smoke-newlib-dotdot-control
smoke-newlib-dotdot-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NEWLIB_SELFTEST=1 HVFS_DOTDOT_SERVER=1
	@$(MAKE) --no-print-directory NEWLIB_SELFTEST=1 HVFS_DOTDOT_SERVER=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='NEWLIB_SELFTEST: FAIL dotdot-back' \
		tools/smoke_test.sh boot.iso

# Build with the vendored GNU coreutils utilities and run them at boot as ring-3
# tasks. The required marker is produced by UPSTREAM's own code path -- echo
# joins its argv with spaces and expands the -e escapes (\x20 -> space,
# \x21 -> '!'), while basename/dirname exercise their real path splitting -- so a
# pass means genuine third-party source ran correctly on Horus, not that we
# printed a string. See userspace/ports/coreutils/README.md.
# Build with the gated capability/syscall conformance test and require its
# marker. The checks are overwhelmingly negative -- a kernel that granted
# everything would fail this, which a "does the call work" test would not catch.
# Control arm for the capability-graph readout (roadmap 3.6). Without the
# declared capability the central gate admits everyone, and captest -- which
# holds no CAP_DEBUG -- reads another task's cspace. The FAIL marker names that
# specific check, so an arm reddening captest for any other reason does not
# satisfy it.
# Control arm for the clock's RESOLUTION (roadmap 2.2). The tempting version of
# this syscall reports real microseconds from the TSC: strictly more accurate,
# strictly more useful, and it undoes CR4.TSD by handing ring 3 the
# cycle-accurate timer that bit exists to deny. captest's
# `clock-resolution-finer-than-a-pit-tick` check must fire.
# Control arm for console INPUT authority. GETLINE_SLOT3_FALLBACK=1 puts back the
# untyped slot-3 lookup, and captest -- which holds that decoy and no CAP_CONSOLE
# -- gets past the gate into the console read and BLOCKS there.
#
# So this arm asserts the ABSENCE of `CAPTEST: PASS` rather than the presence of
# a FAIL marker: a task blocked inside a syscall prints nothing at all, and there
# is no line to require. The absence is the evidence -- captest completes in
# well under the timeout in every other configuration, including both other arms
# over this same binary.
.PHONY: smoke-captest-getline-control
smoke-captest-getline-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 GETLINE_SLOT3_FALLBACK=1
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 GETLINE_SLOT3_FALLBACK=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_STALL='CAPTEST: begin' \
		ABSENT_MARKER='CAPTEST: PASS' \
		tools/smoke_test.sh boot.iso

# Control arm for S52: a refused capability operation must RETURN, not halt.
# CAP_LOOKUP_ASSERT_HANG=1 puts back the helper that spun on a NULL lookup inside
# cap_mint/cap_transfer, holding cap_lock with IF=0. captest's section-12 probes
# hand those calls an empty and an out-of-range source slot -- both of which any
# ring-3 task may name -- and the guest never comes back.
#
# Like the getline arm above, the evidence is an ABSENCE: a task wedged inside a
# syscall prints nothing, so there is no FAIL line to require. EXPECT_STALL makes
# that two-sided rather than a bare timeout -- the run must first REACH the probe
# marker and only then stop, which is why smoke_test.sh refuses EXPECT_STALL
# without ABSENT_MARKER ("a stall proves nothing"). Reaching
# `CAPTEST: cap-derivation-probes` and never reaching `CAPTEST: PASS` is the
# reproduction; a boot that died earlier fails this arm rather than satisfying it.
.PHONY: smoke-captest-mint-hang-control
smoke-captest-mint-hang-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 CAP_LOOKUP_ASSERT_HANG=1
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 CAP_LOOKUP_ASSERT_HANG=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_STALL='CAPTEST: cap-derivation-probes' \
		ABSENT_MARKER='CAPTEST: PASS' \
		tools/smoke_test.sh boot.iso

# The device half of captest: this task holds no CAP_IO_DEVICE, and the four
# device syscalls have no dispatch-table slot, so the handler's own lookup is the
# whole gate. Drop it and captest maps the console's framebuffer holding nothing.
.PHONY: smoke-captest-devcap-control
smoke-captest-devcap-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 IO_DEVICE_CAP_UNCHECKED=1
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 IO_DEVICE_CAP_UNCHECKED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='CAPTEST: FAIL map-phys-without-cap-io-device' \
		tools/smoke_test.sh boot.iso

# SYS_IRQ_ACK's authority. Unmasking an interrupt line decides that a device may
# interrupt this machine again; drop the capability check and any task can do it
# for hardware it does not hold.
# SYS_POLL_NOTIFY's gate. Non-blocking changes when the answer comes back, never
# who may ask -- so it takes the same CAP_NOTIFICATION + READ check the blocking
# wait does. Ungated, any task polls any notification and learns another task's
# badges, which is finding C-2 in a new syscall.
#
# The marker is the WRONG-TYPE check, not the empty-slot one, and that is not
# arbitrary: ungated, the slot is used as a raw notification index, and an empty
# high slot (200) is out of range so it still fails -- for the wrong reason, but
# it fails, so that check cannot witness this defect. Slot 3 IS a valid index, so
# it is the one that comes back IPC_AGAIN instead of refused. A refusal test only
# detects a missing gate when the ungated path would otherwise SUCCEED.
.PHONY: smoke-captest-poll-notify-control
smoke-captest-poll-notify-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 POLL_NOTIFY_UNGATED=1
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 POLL_NOTIFY_UNGATED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='CAPTEST: FAIL poll-notify-with-wrong-cap-type' \
		tools/smoke_test.sh boot.iso

.PHONY: smoke-captest-irq-ack-control
smoke-captest-irq-ack-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 IRQ_ACK_UNGATED=1
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 IRQ_ACK_UNGATED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='CAPTEST: FAIL irq-ack-without-cap-io-device' \
		tools/smoke_test.sh boot.iso

.PHONY: smoke-captest-clock-control
smoke-captest-clock-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 CLOCK_TSC_RESOLUTION=1
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 CLOCK_TSC_RESOLUTION=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='CAPTEST: FAIL clock-resolution-finer-than-a-pit-tick' \
		tools/smoke_test.sh boot.iso

.PHONY: smoke-captest-capenum-control
smoke-captest-capenum-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 CAP_ENUMERATE_UNGATED=1
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 CAP_ENUMERATE_UNGATED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='CAPTEST: FAIL cap-enumerate-without-cap-debug' \
		tools/smoke_test.sh boot.iso

.PHONY: smoke-captest
smoke-captest:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 boot.iso
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
# ---- [H-2]: the kernel log is not a ring-3 scratchpad -----------------------
# A ring-3 probe endowed with CAP_KERNEL_LOG (READ, the only right that exists
# for it) floods SYS_WRITE fd 1 with 28800 bytes -- more than the 16 KiB ring --
# and then reads the ring back through SYS_DMESG. It must find NONE of the flood
# (no forgery) and must still find the marker the kernel seeded before ring-3
# entry (no eviction). Both halves are asserted because a half-fix passes either
# one alone: rate-limiting keeps the marker and still leaks the forgery, and
# dropping the bytes while still advancing the ring loses the marker.
.PHONY: smoke-klog-forge
smoke-klog-forge:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory KLOG_FORGE_SELFTEST=1
	@$(MAKE) --no-print-directory KLOG_FORGE_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='KLOGTEST: PASS' \
		FAIL_MARKER='KLOGTEST: FAIL' tools/smoke_test.sh boot.iso

# Control arm for the above: KLOG_WRITE_UNGATED=1 restores the pre-2026-08-20
# h_write, which appended every ring-3 byte to the kernel log with no authority
# tested. The FAIL marker must be PRESENT -- deterministically, on every boot,
# since nothing here is racy. If this arm ever goes green, the gate above is
# passing for a reason other than the one it claims.
# ---- defect-flag provenance -------------------------------------------------
# Every boot states which defect-reproducing flags built it. A clean kernel must
# say so POSITIVELY: an absent line is ambiguous between "clean", "the reporting
# was removed" and "the boot died early", and only one of those is good news.
.PHONY: smoke-defect-flags
smoke-defect-flags:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='DEFECT FLAGS: none' \
		FAIL_MARKER='DEFECT FLAGS: unknown' tools/smoke_test.sh boot.iso

# The same kernel built WITH a defect arm must name it. Without this, the gate
# above is satisfied by a kernel that prints "none" unconditionally.
.PHONY: smoke-defect-flags-control
smoke-defect-flags-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory KSP_GUARD_INJECT=1
	@$(MAKE) --no-print-directory KSP_GUARD_INJECT=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='DEFECT FLAGS: KSP_GUARD_INJECT' tools/smoke_test.sh boot.iso

# THE FOOTGUN ITSELF. Build with an injection, then rebuild WITHOUT `clean` and
# without the flag -- exactly the sequence that produced a false [G-9]
# "reproduction" on 2026-08-20. The kernel must come out clean.
.PHONY: smoke-defect-flags-rebuild
smoke-defect-flags-rebuild:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory KSP_GUARD_INJECT=1
	@$(MAKE) --no-print-directory
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='DEFECT FLAGS: none' \
		FAIL_MARKER='DEFECT FLAGS: KSP_GUARD_INJECT' tools/smoke_test.sh boot.iso

# Control arm for it: BUILD_FLAGS_UNSTAMPED=1 drops the dependency, so the
# flagless rebuild recompiles nothing and the injected kernel survives. The stale
# flag must be REPORTED -- the announcement is compiled into the same stale
# object set, so it stays truthful about what is actually in the image.
.PHONY: smoke-defect-flags-rebuild-control
smoke-defect-flags-rebuild-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory BUILD_FLAGS_UNSTAMPED=1 KSP_GUARD_INJECT=1
	@$(MAKE) --no-print-directory BUILD_FLAGS_UNSTAMPED=1
	@$(MAKE) --no-print-directory BUILD_FLAGS_UNSTAMPED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='DEFECT FLAGS: KSP_GUARD_INJECT' tools/smoke_test.sh boot.iso

# ---- [G-9]: a bogus resume %rsp is refused where it is produced -------------
# The FALSE-POSITIVE arm, and the one whose absence is a known way to ship a
# regression. `smoke-ksp-guard-control` injects a bogus value and asks whether
# the guard fires -- it measures false NEGATIVES, so a predicate that rejected
# every stack pointer would satisfy it. This asks the opposite question: on an
# ordinary boot, where every resume value is legal, the guard must stay SILENT.
#
# That is exactly how the resume-%rsp guard shipped a bound which rejected the
# IST stacks (see smoke-resume-guard-ist): every arm it had injected a bogus
# value, none asked whether it stayed quiet on a good one, and ten CI gates went
# red at once. This pair does not repeat that.
#
# Deliberately the DEFAULT workload rather than PROC_SELFTEST: the latter still
# trips [G-9] on ~1-2% of boots, which would make this gate intermittently red
# for a reason that is not about the guard. Booting to a ring-3 login exercises
# every switch path this guard sits on.
.PHONY: smoke-ksp-guard
smoke-ksp-guard:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory
	@$(MAKE) --no-print-directory boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) FAIL_MARKER='SCHED BOGUS KSP' \
		tools/smoke_test.sh boot.iso


# The producer-side half of the resume guard. KSP_GUARD_INJECT=1 forges -7 -- the
# exact value [G-9] was seen to hand back -- in task_exit_switch, the producer the
# PROC_SELFTEST workload drives. The report must name that producer.
#
# Asserts on the marker and not on the boot's verdict: the point is that the CPU
# REFUSED and parked rather than iretq'ing onto -7, so the session continuing is
# the success condition, not a clean exit status.
.PHONY: smoke-ksp-guard-control
smoke-ksp-guard-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 KSP_GUARD_INJECT=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 KSP_GUARD_INJECT=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='SCHED BOGUS KSP from task_exit_switch' \
		tools/smoke_test.sh boot.iso

# ---- CSPRNG seed gate (S30) ------------------------------------------------
# RngState::fill refuses to emit keystream from a pool that has never been
# reseeded from real entropy. Until 2026-08-23 it did not look: the property was
# held up by boot ordering (entropy_init runs before the first consumer and halts
# if the pool did not take), which is a fact about one call site rather than
# anything the RNG enforced.
#
# Both arms build with RNG_UNSEEDED_PROBE=1, which asks the pool for 16 bytes
# immediately before entropy_init() and prints what it got. The probe reports
# rather than halts, so both arms boot on and the gate reads its answer off the
# wire in the same shape.
#
# The base arm asserts BOTH directions in one boot, deliberately without
# MARKER_ONLY: the refusal marker must appear, AND the boot must still reach the
# ring-3 shell banner. A gate that only checked the refusal would be passed by a
# fill() that refuses everything -- the KSP_GUARD_ALWAYS mutation, one aisle over
# in this file.
.PHONY: smoke-rng-seed
smoke-rng-seed:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory RNG_UNSEEDED_PROBE=1
	@$(MAKE) --no-print-directory RNG_UNSEEDED_PROBE=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) \
		REQUIRE_MARKER='RNGPROBE: REFUSED unseeded request' \
		FAIL_MARKER='RNGPROBE: SERVED unseeded keystream' \
		tools/smoke_test.sh boot.iso

# The falsifying arm. RNG_UNSEEDED_LEGACY=1 passes the `rng_unseeded_legacy`
# cargo feature down, compiling the check out of RngState::fill; the same probe
# then receives ChaCha20 keystream under the published startup key and cannot
# tell it from randomness. Deterministic straight-line boot code, so a single
# boot settles it -- unlike the [G-8] arms, there is no race here to sample.
#
# MARKER_ONLY, unlike the base arm: this build's whole ASLR and stack-guard story
# is drawn from an unseeded pool, and what happens to the session afterwards is
# not what is being measured.
.PHONY: smoke-rng-seed-control
smoke-rng-seed-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory RNG_UNSEEDED_PROBE=1 RNG_UNSEEDED_LEGACY=1
	@$(MAKE) --no-print-directory RNG_UNSEEDED_PROBE=1 RNG_UNSEEDED_LEGACY=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='RNGPROBE: SERVED unseeded keystream' \
		tools/smoke_test.sh boot.iso

# ---- syscall handler-entry coverage ----------------------------------------
# Measures which syscall HANDLER BODIES a tracked workload actually enters, and
# diffs the union against .github/syscall-coverage.yml.
#
# The distinction that matters is "entered", not "named by a test". captest is a
# REFUSAL suite by construction -- its checks for SYS_DMESG and SYS_AUDIT_DIGEST
# both assert SYS_ERR_PERM, and the central capability gate returns before the
# handler runs -- so both syscalls were tested, neither handler had ever
# executed, and issue #176 sat behind 100 passing checks.
#
# Three builds, because the three workloads need different kernels; their
# coverage is unioned. No arm asserts on its workload's own verdict: this gate is
# about which handlers ran, and making it also a session/captest/modules
# regression gate would have it go red for reasons that are already somebody
# else's gate.
#
# The modules arm is what drives the pipe syscalls. The pipeline runner executes
# /bin PROGRAMS, and only a COREUTILS_MODULES=1 image provisions them -- in a
# default boot `cat` and `wc` are shell builtins and the runner reports "not
# found in /bin". That image cannot run session_test.py either: with /bin/echo
# present, `echo hello > note` stops redirecting and prints literally, so the two
# workloads genuinely need separate images rather than one merged script.
.PHONY: smoke-syscall-coverage
smoke-syscall-coverage:
	@set -eu; \
	cov="$(SYSCOV_EVIDENCE_DIR)"; rm -rf "$$cov"; mkdir -p "$$cov"; \
	$(MAKE) --no-print-directory clean; \
	$(MAKE) --no-print-directory SYSCALL_COVERAGE=1; \
	$(MAKE) --no-print-directory SYSCALL_COVERAGE=1 boot.iso; \
	SESSION_SERIAL_LOG="$$cov/session.log" SESSION_TIMEOUT=$(SYSCOV_SESSION_TIMEOUT) \
	    python3 tools/session_test.py boot.iso >/dev/null 2>&1 || true; \
	$(MAKE) --no-print-directory clean; \
	$(MAKE) --no-print-directory SYSCALL_COVERAGE=1 CAPTEST_SELFTEST=1; \
	$(MAKE) --no-print-directory SYSCALL_COVERAGE=1 CAPTEST_SELFTEST=1 boot.iso; \
	SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='CAPTEST: PASS' \
	    tools/smoke_test.sh boot.iso > "$$cov/captest.log" 2>&1 || true; \
	$(MAKE) --no-print-directory clean; \
	$(MAKE) --no-print-directory SYSCALL_COVERAGE=1 COREUTILS_MODULES=1; \
	$(MAKE) --no-print-directory SYSCALL_COVERAGE=1 COREUTILS_MODULES=1 boot.iso; \
	SESSION_SERIAL_LOG="$$cov/modules.log" SESSION_TIMEOUT=$(SYSCOV_SESSION_TIMEOUT) \
	    tools/modules_session.py boot.iso >/dev/null 2>&1 || true; \
	echo "syscov: serial transcripts kept in $$cov/"; \
	python3 tools/check_syscall_coverage.py "$$cov/session.log" "$$cov/captest.log" \
	    "$$cov/modules.log"

# The three transcripts are KEPT rather than made in a mktemp that the shell
# deletes on the way out. A failure here is "which syscall stopped being
# entered", and answering that needs the wire, not the exit status -- the same
# reason the SMP soak keeps its evidence. Gitignored; never committed.
SYSCOV_EVIDENCE_DIR ?= .syscov-evidence

SYSCOV_SESSION_TIMEOUT ?= 180

# ---- issue #176: a user pointer reaches the kernel full-width ---------------
# The static-storage half of smoke-klog-forge. SYSCALL_PTR_TRUNC32=1 restores the
# truncating wrappers; the probe's buffer is a static, hence above 4 GiB, hence
# truncated -- so it cannot read the kernel log back and reports FAIL setup.
# Requires that FAIL to be PRESENT. If this arm ever goes green the probe has
# stopped using a static buffer and the ABI half of the gate is inert.
.PHONY: smoke-klog-forge-abi-control
smoke-klog-forge-abi-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory KLOG_FORGE_SELFTEST=1 SYSCALL_PTR_TRUNC32=1
	@$(MAKE) --no-print-directory KLOG_FORGE_SELFTEST=1 SYSCALL_PTR_TRUNC32=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='KLOGTEST: FAIL setup' \
		tools/smoke_test.sh boot.iso

.PHONY: smoke-klog-forge-control
smoke-klog-forge-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory KLOG_FORGE_SELFTEST=1 KLOG_WRITE_UNGATED=1
	@$(MAKE) --no-print-directory KLOG_FORGE_SELFTEST=1 KLOG_WRITE_UNGATED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='KLOGTEST: FAIL' \
		tools/smoke_test.sh boot.iso

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

# ---- fail-closed measured boot (docs/LIMITATIONS.md 2.9) --------------------
# The kernel used to boot happily with no TPM: PCRs unextended, volume key never
# sealed, S11 and S12 simply not applying rather than failing closed. #197 fixed
# the CI half (SWTPM_REQUIRED=1 stops four gates passing without measuring); this
# is the kernel half, as a policy a deployment opts into.
#
# BASE ARM: the policy must not break a machine that satisfies it. Build with
# MEASURED_BOOT_REQUIRED=1, boot under the emulated TPM, and require the boot to
# reach `tpm: measured boot OK` -- a gate that only checked the refusal would be
# passed by a kernel that halts on every boot.
.PHONY: smoke-measured-boot-required
smoke-measured-boot-required:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory MEASURED_BOOT_REQUIRED=1
	@$(MAKE) --no-print-directory MEASURED_BOOT_REQUIRED=1 boot.iso
	@SWTPM_TIMEOUT=$(SMOKE_TIMEOUT) REQUIRE_MARKER='tpm: measured boot OK' \
		FAIL_MARKER='PANIC: measured boot required' \
		tools/run_with_swtpm.sh boot.iso

# CONTROL ARM 1: the same kernel with NO TPM -- which is what an ordinary
# `tools/smoke_test.sh` run gives, since QEMU has no TPM unless swtpm is wired in.
# It must halt, not proceed. This is the exact case 2.9 described.
#
# EXPECT_FAULT, not REQUIRE_MARKER: the refusal says PANIC, which is in the
# harness's FAULT_RE on purpose (a refusal must redden CI rather than scroll
# past), so a marker assertion would lose to the fault verdict before it was
# evaluated. EXPECT_FAULT inverts that verdict for the NAMED fault only -- any
# other fault still fails the arm, which is what stops this passing on an
# unrelated crash.
.PHONY: smoke-measured-boot-required-control
smoke-measured-boot-required-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory MEASURED_BOOT_REQUIRED=1
	@$(MAKE) --no-print-directory MEASURED_BOOT_REQUIRED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) \
		EXPECT_FAULT='PANIC: measured boot required but unavailable (no TPM present)' \
		tools/smoke_test.sh boot.iso

# CONTROL ARM 2: the volume half. A never-sealed volume unlocks on the password
# alone, which is the downgrade the policy exists to refuse -- but the default
# boot runs on the EPHEMERAL vdisk, which is exempt by design (RAM-only, one
# boot, key discarded). MEASURED_VOLUME_EXEMPT_NONE=1 removes the exemption so
# the refusal is reached on an ordinary boot, under a TPM that is present and
# measuring. Without this arm the branch would ship unexecuted.
.PHONY: smoke-measured-boot-required-volume-control
smoke-measured-boot-required-volume-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory MEASURED_BOOT_REQUIRED=1 MEASURED_VOLUME_EXEMPT_NONE=1
	@$(MAKE) --no-print-directory MEASURED_BOOT_REQUIRED=1 MEASURED_VOLUME_EXEMPT_NONE=1 boot.iso
	@SWTPM_TIMEOUT=$(SMOKE_TIMEOUT) \
		EXPECT_FAULT='PANIC: measured boot required but the volume is not sealed' \
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
	@$(MAKE) --no-print-directory PIPE_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='PIPE_SELFTEST: PASS' \
		FAIL_MARKER='PIPE_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

.PHONY: smoke-fs-large
smoke-fs-large:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory BIGFILE_SELFTEST=1
	@$(MAKE) --no-print-directory BIGFILE_SELFTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory SMP_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 SMP_CPUS=$(SMP_CPUS) REQUIRE_MARKER='SMP_SELFTEST: PASS' \
		FAIL_MARKER='SMP_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated process-control self-test, boot headless, and require the
# in-kernel driver to report PASS -- runtime proof that SYS_EXIT and SYS_KILL
# terminate tasks (a self-exiting child and a killed child both reach dead).
# Control arm for the introspection narrowing (roadmap 3.6, second half).
# TASKINFO_WIDE_AUTHORITY=1 lets CAP_USER or CAP_AUDIT answer "may I see the
# process list" again. The witness is `grantee`: it holds a granted CAP_AUDIT --
# proved live by its own SYS_READ_AUDIT check first -- and no CAP_DEBUG, so it
# is the one task in the tree that can tell the two acceptance sets apart.
.PHONY: smoke-proc-taskinfo-control
smoke-proc-taskinfo-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 TASKINFO_WIDE_AUTHORITY=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 TASKINFO_WIDE_AUTHORITY=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='PROC_SELFTEST: FAIL grant-audit-bought-introspection' \
		tools/smoke_test.sh boot.iso

.PHONY: smoke-proc
smoke-proc:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 boot.iso
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
	@$(MAKE) --no-print-directory NOTIFY_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='NOTIFY_SELFTEST: PASS' \
		FAIL_MARKER='NOTIFY_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated map-phys self-test, boot headless, and require the ring-3
# probe to report PASS -- runtime proof that a CAP_IO_DEVICE-endowed task can map
# the allowlisted VGA framebuffer into its own address space (SYS_MAP_PHYS) and
# that the mapping is the real device frame, while an off-list frame is refused.
# First driver-privilege-separation job; see docs/design/console-server.md.
.PHONY: smoke-mapphys
smoke-mapphys:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory MAPPHYS_SELFTEST=1
	@$(MAKE) --no-print-directory MAPPHYS_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='MAPPHYS_SELFTEST: PASS' \
		FAIL_MARKER='MAPPHYS_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated port-I/O self-test, boot headless, and require the ring-3
# probe to report PASS -- runtime proof that a CAP_IO_DEVICE-endowed task granted
# native port I/O (TSS I/O bitmap) can read an allowlisted console port while a
# non-allowlisted port still #GPs. Second driver-privilege-separation job; see
# docs/design/console-server.md.
.PHONY: smoke-ioport
smoke-ioport:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory IOPORT_SELFTEST=1
	@$(MAKE) --no-print-directory IOPORT_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='IOPORT_SELFTEST: PASS' \
		FAIL_MARKER='IOPORT_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated IRQ-notification self-test, boot headless, and require the
# ring-3 probe to report PASS -- runtime proof that a CAP_IO_DEVICE-endowed task
# can route a hardware IRQ (the timer) to an async notification (SYS_IRQ_REGISTER)
# and be woken by a real interrupt. Third driver-privilege-separation job; see
# docs/design/console-server.md.
.PHONY: smoke-irq
smoke-irq:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory IRQ_SELFTEST=1
	@$(MAKE) --no-print-directory IRQ_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='IRQ_SELFTEST: PASS' \
		FAIL_MARKER='IRQ_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated ring-3 console-server self-test, boot headless, and require
# the client's line to appear on serial -- runtime proof that a ring-3
# console_server, owning the console hardware (SYS_MAP_PHYS + SYS_IOPORT_GRANT),
# served a client's write over IPC and drove the serial port itself. First J5
# cutover milestone; see docs/design/console-server.md.
.PHONY: smoke-console
smoke-console:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CONSOLE_SELFTEST=1
	@$(MAKE) --no-print-directory CONSOLE_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='CONSOLE_SELFTEST: PASS' \
		FAIL_MARKER='CONSOLE_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

# ---- A network driver in ring 3, holding one device capability --------------
#
# Roadmap 2.6's first half, and the demonstration the architecture exists for.
# netd brings up virtio-net over the legacy I/O BAR and completes an ARP exchange
# with QEMU's user-mode gateway. Its whole authority is a CAP_IO_DEVICE naming the
# NIC plus one untyped region -- no console, no filesystem, no ambient anything.
#
# SMOKE_NET=user rather than 1: the authority gates need a device on the bus, this
# one needs something at the other end of the wire.
# ---- Shared library text: executed by many, writable by none ----------------
#
# Roadmap 2.5's mechanism. One shared object, loaded once into frames at boot,
# mapped read+exec by TWO tasks that each execute it. The size argument for
# sharing a libc is obvious; the security argument is that sharing it WRITABLY
# would be a code-injection primitive between every task that maps it, which is
# strictly worse than the per-program static copies it replaces.
.PHONY: smoke-shlib
smoke-shlib:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='SHLIBTEST: PASS' \
		FAIL_MARKER='SHLIBTEST: FAIL' tools/smoke_test.sh boot.iso

# The arm for S49, and it is the attack rather than a stand-in for one: the
# capability carries WRITE, shlibtest maps the library a second time writable and
# overwrites a function through that alias while executing through its read+exec
# one, and the PEER -- which asked for nothing but read+exec -- runs the patch.
#
# The refusal checks are skipped under this flag on purpose. They cannot pass
# there, and stopping at the first of them would make the marker "a writable
# mapping was obtainable" rather than what the other task then executes.
.PHONY: smoke-shlib-writable-control
smoke-shlib-writable-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_TEXT_WRITABLE=1
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_TEXT_WRITABLE=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='SHLIBTEST: FAIL peer-saw-patched-code' \
		tools/smoke_test.sh boot.iso

# ---- S50, arm 1: the library's writable data, SHARED ------------------------
#
# Every task endowed with the same frame for the library's .data, instead of a
# private copy. shlibtest writes its sentinel; the peer, which wrote nothing,
# reads it back. For real newlib that value is another task's errno, stdio
# buffers and malloc arena -- so this is disclosure AND corruption, and it is
# why a libc could not simply be moved onto the S49 mechanism as it stood.
#
# The marker is the PEER's, not shlibtest's: shlibtest cannot tell a private
# copy from a shared one by looking at its own writes. Only the task that never
# wrote can witness it.
# ---- S51: the shared library's base is drawn per boot, not compiled in -------
#
# TWO BOOTS, because the property is not observable from inside one. A single
# run cannot tell a random base from a fixed one -- it sees an address either
# way. So both boots report theirs (SHLIBBASE: <hex>, from shlibtest) and the
# gate requires the two to DIFFER.
#
# The base gate and its control arm are the same script with the comparison
# inverted, which is what makes the pair a measurement rather than two tests.
#
# A NOTE ON WHAT "DIFFER" PROVES, since it is weaker than it looks. Two unequal
# draws are consistent with a 1-bit source. This gate is a smoke test for
# "the base is not a constant", not a randomness test -- the entropy claim rests
# on aslr_random_offset, which is rejection-sampled over 2^30 positions and is
# the same source the image loader uses. Stated rather than implied.
.PHONY: smoke-shlib-aslr smoke-shlib-aslr-control
# ---- The real shared libc, called from ring 3 -------------------------------
#
# Roadmap 2.5's remaining claim. Everything under smoke-shlib demonstrates the
# MECHANISM's properties on a three-page demo object; this boots the real thing
# -- newlib, its port glue and libhorus in one shared object -- and requires a
# ring-3 task to map it and call into it.
#
# A demo object cannot fail the way a libc can: newlib has writable state
# (_impure_ptr -- errno, stdio buffers, atexit list, rand state), calls back into
# the port's syscall glue, and allocates. Each crosses the shared/private
# boundary S50 draws, and none was exercised by an object whose whole data
# segment was one int.
# ---- A program LINKED against the shared libc --------------------------------
#
# smoke-shlibc proves the library works, by indexing its export table by hand.
# This proves a PROGRAM can be built against it: hello_shared.c is ordinary C --
# it calls printf and strlen by NAME -- and links no libc at all, only the
# generated stub archive and the crt0 that binds the library before main.
#
# Measured, same source and flags, only the libc link differing:
#   static libc  106,392 bytes
#   shared libc   13,088 bytes   (8.1x smaller)
#
# THE CHECK BEFORE THE BOOT IS THE FALSIFICATION. If hello_shared had linked
# libc.a it would print exactly the same thing and prove nothing, so every libc
# symbol it defines must be a THUNK -- 14 bytes of mov+jmp -- and not real code.
# That is the property; the marker on its own is not.
#
# No runtime control arm, deliberately, and the reason is worth recording. The
# obvious one -- emit %rax thunks instead of %r11, the variadic-ABI hazard -- is
# PROBABILISTIC: %al too large merely makes a callee spill more xmm registers
# than needed, so it misbehaves only when the table pointer's low byte is small,
# and the base is randomised per boot (S51). An off-by-one index arm crashes the
# task rather than printing a marker. A gate must not assert something it can
# only sometimes observe, so the deterministic static check is the falsification.
.PHONY: smoke-shlibc-link
smoke-shlibc-link:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SHLIBC_SELFTEST=1
	@$(MAKE) --no-print-directory SHLIBC_SELFTEST=1 boot.iso
	@# Every libc symbol hello_shared defines must be a thunk, not an
	@# implementation. 16 bytes is the ceiling for `mov m64,%r11; jmp *disp(%r11)`.
	@python3 -c "import subprocess,sys; \
o=subprocess.run(['nm','-S','--defined-only','userspace/hello_shared.pie.elf'],capture_output=True,text=True).stdout; \
w=[l for l in o.splitlines() if len(l.split())==4 and l.split()[3] in ('printf','sprintf','strlen','strcmp','malloc','free','memset','exit','posix_init') and int(l.split()[1],16)>16]; \
sys.exit('[shlibc-link] FAIL: '+', '.join(x.split()[3]+' is '+str(int(x.split()[1],16))+' bytes, not a thunk' for x in w) if w else 0)"
	@echo "[shlibc-link] every libc symbol in hello_shared is a thunk; the code is in the library"
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='HELLOSHARED: PASS' FAIL_MARKER='FAIL' \
		tools/smoke_test.sh boot.iso

.PHONY: smoke-shlibc
smoke-shlibc:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SHLIBC_SELFTEST=1
	@$(MAKE) --no-print-directory SHLIBC_SELFTEST=1 boot.iso
	@# The probe must not carry a static copy of what it is testing. If libctest
	@# defined strlen itself, the call would resolve locally, the library would
	@# never be entered, and LIBCTEST: PASS would mean nothing -- a witness has to
	@# be behind the mechanism it witnesses. Checked rather than assumed, and
	@# checked BEFORE the boot so a failure names this rather than a marker.
	@for sym in strlen strcmp sprintf _impure_ptr; do \
		if nm --defined-only userspace/libctest.pie.elf 2>/dev/null | grep -qw "$$sym"; then \
			echo "[shlibc] FAIL: libctest defines $$sym itself -- the call would never reach the library"; \
			exit 1; \
		fi; \
	done
	@echo "[shlibc] libctest defines none of the symbols it calls; they can only come from the library"
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='LIBCTEST: PASS' FAIL_MARKER='LIBCTEST: FAIL' \
		tools/smoke_test.sh boot.iso

smoke-shlib-aslr:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 boot.iso
	@$(MAKE) --no-print-directory shlib-aslr-compare EXPECT=differ

smoke-shlib-aslr-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_BASE_FIXED=1
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_BASE_FIXED=1 boot.iso
	@$(MAKE) --no-print-directory shlib-aslr-compare EXPECT=same

# The shared half. Boots twice, keeps each boot's serial log, and compares the
# reported base. Both boots must also PASS -- a base that differs because the
# second boot died before printing one would otherwise read as success.
.PHONY: shlib-aslr-compare
shlib-aslr-compare:
	@rm -f .shlib-base-1.log .shlib-base-2.log
	@echo "[shlib-aslr] boot 1/2"
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 SMOKE_LOG=.shlib-base-1.log \
		REQUIRE_MARKER='SHLIBTEST: PASS' FAIL_MARKER='SHLIBTEST: FAIL' \
		tools/smoke_test.sh boot.iso
	@echo "[shlib-aslr] boot 2/2"
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 SMOKE_LOG=.shlib-base-2.log \
		REQUIRE_MARKER='SHLIBTEST: PASS' FAIL_MARKER='SHLIBTEST: FAIL' \
		tools/smoke_test.sh boot.iso
	@b1=$$(grep -m1 -o 'SHLIBBASE: [0-9a-f]*' .shlib-base-1.log | awk '{print $$2}'); \
	 b2=$$(grep -m1 -o 'SHLIBBASE: [0-9a-f]*' .shlib-base-2.log | awk '{print $$2}'); \
	 if [ -z "$$b1" ] || [ -z "$$b2" ]; then \
	   echo "[shlib-aslr] FAIL: a boot reported no base (1='$$b1' 2='$$b2')"; exit 1; fi; \
	 echo "[shlib-aslr] boot1=$$b1 boot2=$$b2 (expecting: $(EXPECT))"; \
	 if [ "$(EXPECT)" = "differ" ]; then \
	   if [ "$$b1" = "$$b2" ]; then \
	     echo "[shlib-aslr] FAIL: the library loaded at the same address twice"; exit 1; fi; \
	   echo "[shlib-aslr] PASS: the base is not a constant"; \
	 else \
	   if [ "$$b1" != "$$b2" ]; then \
	     echo "[shlib-aslr] FAIL: the arm did not fix the base"; exit 1; fi; \
	   echo "[shlib-aslr] PASS (control): the base was identical, as the defect requires"; \
	 fi

# ---- S51, second half: the base is not ambient information ------------------
#
# The refusal arm. Under SHLIB_INFO_UNGATED the syscall answers whoever asks, so
# shlibtest's wrong-TYPE probe (a CAP_TCB) succeeds where it must be refused.
#
# The marker names the wrong-TYPE check rather than the wrong-OBJECT one purely
# because the probe stops at its first failure and that check runs first; both
# are what the gate asserts, and both succeed under this arm.
smoke-shlib-info-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_INFO_UNGATED=1
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_INFO_UNGATED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='SHLIBTEST: FAIL shlib-info-with-wrong-cap-type' \
		tools/smoke_test.sh boot.iso

# The object half of the same gate: the type is right, the frame is not the
# library's. Under this arm the wrong-TYPE probe is still refused, so the probe
# reaches the second check and it is that one which fires -- which is what shows
# the object rule can fail on its own.
smoke-shlib-info-object-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_INFO_TYPE_ONLY=1
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_INFO_TYPE_ONLY=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='SHLIBTEST: FAIL shlib-info-with-data-frame' \
		tools/smoke_test.sh boot.iso

smoke-shlib-data-shared-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_DATA_SHARED=1
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_DATA_SHARED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='SHLIBTEST: FAIL peer-saw-our-data' \
		tools/smoke_test.sh boot.iso

# ---- S50, arm 2: the copy is private, but never initialised -----------------
#
# A private frame per task, zero-filled rather than copied from the library's
# image. LOSS where the arm above is DISCLOSURE, and two flags rather than one
# because they break different halves of S50 -- the FPU pair is the same shape
# for the same reason.
#
# WHAT SEPARABILITY IS ACTUALLY WITNESSED, since only one direction of it is.
# Under arm 1 the data IS correctly initialised, and that is observable on the
# wire: `SHLIBTEST: data initialised from the image, and written` prints before
# the peer reports the disclosure. The reverse is NOT observed -- under this arm
# shlibtest fails its own initialisation check and exits before it ever resumes
# the peer, so the peer's privacy check does not run. The privacy property does
# still hold here in the code (a fresh frame is carved either way; only the copy
# is skipped), but this arm does not witness it and the claim is not made.
#
# That asymmetry is the probe stopping at its first failure, which is a choice
# about what an arm demonstrates rather than an accident -- the same reason
# smoke-shlib-writable-control skips the refusal checks deliberately. Recorded
# rather than papered over: a detector that halts truncates its own evidence.
#
# A libc whose data is private but uninitialised is a libc whose _impure_ptr is
# NULL: it does not leak anything, it just does not work. That is a different
# defect and it gets a different arm.
smoke-shlib-data-init-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_DATA_UNINITIALISED=1
	@$(MAKE) --no-print-directory SHLIB_SELFTEST=1 SHLIB_DATA_UNINITIALISED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='SHLIBTEST: FAIL data-not-initialised' \
		tools/smoke_test.sh boot.iso

# The MSI path, on an 82574L -- the device model that HAS an MSI capability, and
# the one whose receive path works (5 boots in 5), so this gate also asserts a
# real ARP exchange end to end: transmit, MSI, receive. The
# kernel allocates the vector and programs the device; the driver names a device
# and a notification and never a vector, because the ABI gives it nowhere to say
# one (S47).
.PHONY: smoke-net
smoke-net:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NET_SELFTEST=1
	@$(MAKE) --no-print-directory NET_SELFTEST=1 boot.iso
	@SMOKE_NET=e1000e SMOKE_IOMMU=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='NETTEST: RX PASS' \
		FAIL_MARKER='NETTEST: FAIL' tools/smoke_test.sh boot.iso

# S53. A device translation must not outlive the capability that authorised it.
# SYS_DMA_ADDR installs an IOMMU entry for a frame; frame_map_refcount counts CPU
# mappings only, so a device mapping neither keeps the frame alive nor was torn
# down when it died. destroy_dyn_frame scrubbed the run and returned it to the
# arena with the device's translation still installed -- a device-side
# use-after-free, and the third capability-free path to a page in a file whose
# comments already reason carefully about the second.
#
# An in-kernel witness rather than a DMA, and the reason is in the selftest's own
# header: proving it with a packet means pointing a live device at a page the
# arena has already reallocated, which is committing the bug to observe the fix.
# It boots with SMOKE_IOMMU (it needs a real VT-d unit) and SMOKE_NET (it needs a
# device to own a domain).
.PHONY: smoke-iommu-teardown
smoke-iommu-teardown:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory IOMMU_TEARDOWN_SELFTEST=1
	@$(MAKE) --no-print-directory IOMMU_TEARDOWN_SELFTEST=1 boot.iso
	@SMOKE_NET=e1000 SMOKE_IOMMU=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='IOMMUTEST: PASS' \
		FAIL_MARKER='IOMMUTEST: FAIL' tools/smoke_test.sh boot.iso

# The falsifying arm: destroy_dyn_frame as it stood until 2026-08-29, scrubbing
# and releasing the run while leaving every device translation of it in place.
# The marker names the specific check rather than any IOMMUTEST failure, so an
# arm that reddens the test for some other reason does not satisfy it.
.PHONY: smoke-iommu-teardown-control
smoke-iommu-teardown-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory IOMMU_TEARDOWN_SELFTEST=1 IOMMU_NO_FRAME_TEARDOWN=1
	@$(MAKE) --no-print-directory IOMMU_TEARDOWN_SELFTEST=1 IOMMU_NO_FRAME_TEARDOWN=1 boot.iso
	@SMOKE_NET=e1000 SMOKE_IOMMU=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='IOMMUTEST: FAIL device-still-translates-destroyed-frame' \
		tools/smoke_test.sh boot.iso

# S47's arm. The kernel honours a caller-supplied vector and netd asks for 13,
# so the NIC raises #GP at the machine. The kernel then processes a
# general-protection fault that never happened, against whatever context the
# message interrupted -- measured, the driver is rejected by the loader validator
# and the kernel takes a supervisor page fault.
#
# Asserts a FAULT rather than a marker or a stall, because that is what this
# defect IS. The precise downstream symptom is not stable (a misinterpreted
# exception frame goes wrong in whichever way it goes wrong first), so the
# assertion names the task the fault is attributed to rather than the flavour of
# fault -- the point being that a device chose a vector and something died.
.PHONY: smoke-net-msi-vector-control
smoke-net-msi-vector-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NET_SELFTEST=1 MSI_VECTOR_FROM_USER=1
	@$(MAKE) --no-print-directory NET_SELFTEST=1 MSI_VECTOR_FROM_USER=1 boot.iso
	@SMOKE_NET=e1000e SMOKE_IOMMU=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) \
		EXPECT_FAULT='task 1' tools/smoke_test.sh boot.iso

# S48's arm. The MSI-X vector table lives in a BAR, so without an explicit
# refusal a driver maps it like any other register page and writes its own
# interrupt vector -- no syscall, no capability check, nothing to gate. The
# refusal is what makes S47 hold for MSI-X as well as MSI.
.PHONY: smoke-net-msix-table-control
smoke-net-msix-table-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NET_SELFTEST=1 MSIX_TABLE_MAPPABLE=1
	@$(MAKE) --no-print-directory NET_SELFTEST=1 MSIX_TABLE_MAPPABLE=1 boot.iso
	@SMOKE_NET=e1000e SMOKE_IOMMU=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='NETTEST: FAIL msix-table-mapped' tools/smoke_test.sh boot.iso

# The INTx path, on an 82540EM -- a device model with NO MSI capability, so the
# driver falls back to a wire and S46's mask-until-acknowledged applies. Both
# gates run the same driver against the same code; only the device differs, which
# is what makes the fallback a tested path rather than an assumption.
.PHONY: smoke-net-intx
smoke-net-intx:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NET_SELFTEST=1
	@$(MAKE) --no-print-directory NET_SELFTEST=1 boot.iso
	@SMOKE_NET=e1000 SMOKE_IOMMU=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='NETTEST: MASK PASS' \
		FAIL_MARKER='NETTEST: FAIL' tools/smoke_test.sh boot.iso

# S46's mask, tested DIRECTLY and on the routing the ship build uses. Since
# SYS_POLL_NOTIFY exists a driver can observe that a notification did NOT arrive,
# so the property no longer has to be witnessed through a livelock: while the line
# is masked the poll must report IPC_AGAIN, and after the ack a badge must come.
# Deterministic, marker-based, and it fails on the I/O APIC path where the storm
# arm cannot.
.PHONY: smoke-net-mask-control
smoke-net-mask-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NET_SELFTEST=1 IRQ_NO_MASK_ON_FIRE=1
	@$(MAKE) --no-print-directory NET_SELFTEST=1 IRQ_NO_MASK_ON_FIRE=1 boot.iso
	@SMOKE_NET=e1000 SMOKE_IOMMU=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='NETTEST: FAIL irq-while-masked' tools/smoke_test.sh boot.iso

# ON THE PIC PATH (IRQ_FORCE_PIC=1), deliberately. Measured 2026-08-28: QEMU
# storms on the 8259 and does NOT on the I/O APIC, so this arm can only fail on
# the PIC -- and an arm that cannot fail cannot gate. The KERNEL LOGIC under test
# is identical either way (mask the line before acknowledging it); only the
# controller the mask lands in differs. Running it here also keeps the 8259
# fallback exercised, which every machine with no MADT I/O APIC entry uses.
#
# A level-triggered line left unmasked when it fires storms: the PIC re-delivers,
# ring 3 never runs, and the driver that would clear the device never gets the
# chance. Asserts a STALL, because that is what a livelocked machine looks like --
# NETTEST: PASS reached (the DMA property still holds) and IRQ PASS never arriving.
.PHONY: smoke-net-irq-storm-control
smoke-net-irq-storm-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NET_SELFTEST=1 IRQ_NO_MASK_ON_FIRE=1 IRQ_FORCE_PIC=1
	@$(MAKE) --no-print-directory NET_SELFTEST=1 IRQ_NO_MASK_ON_FIRE=1 IRQ_FORCE_PIC=1 boot.iso
	@SMOKE_NET=e1000 SMOKE_IOMMU=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) \
		EXPECT_STALL='NETTEST: PASS' ABSENT_MARKER='NETTEST: IRQ PASS' \
		tools/smoke_test.sh boot.iso

# The arm for S45, and the reason the IOMMU is a property rather than a boot
# message. Same driver, same device, same capability checks -- only the device
# MAPPINGS withheld. The device's address space then stays empty, it cannot read
# its own descriptor ring, and the completion never comes back.
.PHONY: smoke-net-iommu-control
smoke-net-iommu-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NET_SELFTEST=1 NET_IOMMU_NO_MAP=1
	@$(MAKE) --no-print-directory NET_SELFTEST=1 NET_IOMMU_NO_MAP=1 boot.iso
	@SMOKE_NET=e1000 SMOKE_IOMMU=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='NETTEST: FAIL dma-never-completed' tools/smoke_test.sh boot.iso

# Control arm 1 of 2: no decode bits at all, so the device stops answering its own
# I/O BAR. The arm for SYS_DEVICE_ENABLE -- it writes the one configuration-space
# register ring 3 can reach, and this is what shows the write lands rather than
# returning 0 and doing nothing.
#
# It is NOT the bus-master arm, which is what this started as. Measured: with bus
# mastering clear the driver still completes the exchange, because QEMU does not
# enforce the bit for virtio-net. See NET_NO_BUSMASTER above.
.PHONY: smoke-net-decode-control
smoke-net-decode-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory NET_SELFTEST=1 NET_NO_DECODE=1
	@$(MAKE) --no-print-directory NET_SELFTEST=1 NET_NO_DECODE=1 boot.iso
	@SMOKE_NET=e1000 SMOKE_IOMMU=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='NETTEST: FAIL mac-not-valid' tools/smoke_test.sh boot.iso

# ---- Device capabilities: a CAP_IO_DEVICE names a device --------------------
#
# Base gate. Boots with a virtio-net NIC on the bus (SMOKE_NET=1) and a probe
# holding two device capabilities, and requires DEVCAPTEST: PASS -- every
# cross-device request refused AND every own-device request served. The second
# half is what makes this a gate rather than a way to pass: a kernel that refuses
# all three syscalls satisfies the negatives and fails P3/P4.
.PHONY: smoke-devcap
smoke-devcap:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory DEVCAP_SELFTEST=1
	@$(MAKE) --no-print-directory DEVCAP_SELFTEST=1 boot.iso
	@SMOKE_NET=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='DEVCAPTEST: PASS' \
		FAIL_MARKER='DEVCAPTEST: FAIL' tools/smoke_test.sh boot.iso

# Control arm 1 of 3: the capability's object is not consulted and SYS_MAP_PHYS
# tests the frame against the old compiled-in VGA allowlist, so the NIC
# capability maps the console's framebuffer. The FAIL marker MUST be present.
.PHONY: smoke-devcap-object-control
smoke-devcap-object-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory DEVCAP_SELFTEST=1 IO_DEVICE_OBJECT_UNCHECKED=1
	@$(MAKE) --no-print-directory DEVCAP_SELFTEST=1 IO_DEVICE_OBJECT_UNCHECKED=1 boot.iso
	@SMOKE_NET=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='DEVCAPTEST: FAIL nic-cap-mapped-vga' tools/smoke_test.sh boot.iso

# Control arm 2 of 3: one global TSS I/O bitmap, loaded with the console's ports
# by every grant whatever device was named, so the NIC capability reads COM1.
#
# The probe reads the SAME port under two grants for this arm's sake -- see the
# long note in userspace/devcaptest.c. The first arrangement had it read the NIC's
# own port, which under this defect is the port that is DENIED, so the probe
# faulted there and never reached the read this arm exists to observe.
.PHONY: smoke-devcap-ports-control
smoke-devcap-ports-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory DEVCAP_SELFTEST=1 IO_DEVICE_PORTS_GLOBAL=1
	@$(MAKE) --no-print-directory DEVCAP_SELFTEST=1 IO_DEVICE_PORTS_GLOBAL=1 boot.iso
	@SMOKE_NET=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='DEVCAPTEST: FAIL nic-cap-got-console-ports' tools/smoke_test.sh boot.iso

# Control arm 3 of 3: SYS_IRQ_REGISTER does not check the line against the named
# device, so the NIC capability subscribes to the console's keyboard interrupt.
.PHONY: smoke-devcap-irq-control
smoke-devcap-irq-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory DEVCAP_SELFTEST=1 IO_DEVICE_IRQ_UNCHECKED=1
	@$(MAKE) --no-print-directory DEVCAP_SELFTEST=1 IO_DEVICE_IRQ_UNCHECKED=1 boot.iso
	@SMOKE_NET=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='DEVCAPTEST: FAIL nic-cap-took-platform-irq' tools/smoke_test.sh boot.iso

# Build with the gated console blast-radius test, boot headless, and require the
# marker proving the ring-3 console_server's deliberate fault was contained (the
# kernel stayed alive to print it). Phase 6 close-out; see docs/design/console-server.md.
.PHONY: smoke-console-isolation
smoke-console-isolation:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CONSOLE_ISOLATION_TEST=1
	@$(MAKE) --no-print-directory CONSOLE_ISOLATION_TEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='CONSOLE_ISOLATION: PASS' \
		FAIL_MARKER='CONSOLE_ISOLATION: FAIL' tools/smoke_test.sh boot.iso

# Build with the gated copy-on-write self-test, boot headless, and require that a
# write to a read-only shared-zero page breaks COW into a private page without
# disturbing its sibling (COW_SELFTEST: PASS).
.PHONY: smoke-cow
smoke-cow:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory COW_SELFTEST=1
	@$(MAKE) --no-print-directory COW_SELFTEST=1 boot.iso
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
# The negative arms match the VALUE they inject, not just the banner. Reusing
# RESUME_GUARD_RE (which ends in `0x4`) made both of them meaningless: the
# EXPECT_REPORT=1 arm failed against a guard that was in fact reporting
# correctly, and -- worse -- the EXPECT_REPORT=0 control PASSED because a regex
# that can never match is trivially absent. A control arm that cannot fail is
# not a control arm.
RESUME_GUARD_NEG_RE = PANIC: dispatcher returned a bogus resume rsp=0xfffffffffffffff9

.PHONY: smoke-resume-guard
smoke-resume-guard:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 boot.iso
	@KFAULT_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_REPORT=1 \
		REPORT_RE='$(RESUME_GUARD_RE)' REPORT_LABEL='bogus resume rsp' \
		tools/kfault_test.sh boot.iso

# The negative half of the guard. A floor with no ceiling catches a returned 0,
# 1 or 4 and misses every small NEGATIVE value: -7 is 0xFFFFFFFFFFFFFFF9, which
# is ABOVE 0xFFFF800000000000. That is not hypothetical -- a PROC_SELFTEST boot
# at -smp 4 on 2026-08-17 put -7 into the resume %rsp, passed the old guard, and
# faulted at rsp-8 inside the epilogue's first push with a banner naming the stub
# and nothing about where the value came from.
.PHONY: smoke-resume-guard-negative
smoke-resume-guard-negative:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 RESUME_RSP_INJECT_VALUE=-7
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 RESUME_RSP_INJECT_VALUE=-7 boot.iso
	@KFAULT_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_REPORT=1 \
		REPORT_RE='$(RESUME_GUARD_NEG_RE)' REPORT_LABEL='bogus negative resume rsp' \
		tools/kfault_test.sh boot.iso

# The control arm, and the one that makes the pair a measurement. Same -7, but
# with the floor-only predicate restored: the guard must NOT be heard. Without
# it, smoke-resume-guard-negative is consistent with "the guard was already
# catching this", which is exactly what everyone believed until a boot proved
# otherwise. Requires the report to be ABSENT -- same shape as
# smoke-kfault-legacy.
.PHONY: smoke-resume-guard-negative-control
smoke-resume-guard-negative-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 RESUME_RSP_INJECT_VALUE=-7 RESUME_GUARD_FLOOR_ONLY=1
	@$(MAKE) --no-print-directory RESUME_RSP_INJECT=1 RESUME_RSP_INJECT_VALUE=-7 RESUME_GUARD_FLOOR_ONLY=1 boot.iso
	@KFAULT_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_REPORT=0 \
		REPORT_RE='$(RESUME_GUARD_NEG_RE)' REPORT_LABEL='bogus negative resume rsp' \
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

# Does the guard stay SILENT on a legal resume %rsp? Every arm above injects a
# bogus value and asks whether the report appears -- they measure false negatives,
# and a predicate that rejected every value in the address space would pass all of
# them. This pair measures the other direction, and it exists because that gap was
# not theoretical for even one commit.
#
# The ceiling added on 2026-08-18 bounded the guard to [__bss_start, __bss_end) on
# the premise that every 64-bit kernel stack is a .bss array. The IST stacks are in
# .data (multiboot.S emits them beside gdt64/tss64), IST1 serves #DF/#GP/#PF, and
# the guard's response to a rejection is to halt -- so that kernel died on the
# first ring-3 page fault any workload took, reporting a resume %rsp of
# 0xffffffff801a9f50, which is 0xf50 into ist1_stack_bottom's page. Ten CI gates
# went red at once and every resume-guard arm stayed green, because none of them
# could see a false positive.
#
# The workload is captest: it faults through IST1 as a matter of course, and it
# already prints a hard success marker. No injection in either arm -- the point is
# what the guard does to values the kernel produces on its own.
#
#   smoke-resume-guard-ist          shipped predicate: CAPTEST: PASS, no report.
#   smoke-resume-guard-ist-control  RESUME_GUARD_BSS_ONLY=1: the false rejection,
#                                   on demand, and captest never finishes.
# The banner is matched as a FIXED string up to the high half's leading digits,
# so it names "the guard rejected a kernel-image address" without pinning the
# exact stack offset, which shifts with the image layout. Not kfault_test.sh:
# that anchors its verdict after the console handover, and neither arm here ever
# reaches a login prompt -- the control arm dies inside captest, which is the
# whole point.
RESUME_GUARD_IST_RE = PANIC: dispatcher returned a bogus resume rsp=0xffffffff8

.PHONY: smoke-resume-guard-ist
smoke-resume-guard-ist:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 REQUIRE_MARKER='CAPTEST: PASS' \
		ABSENT_MARKER='$(RESUME_GUARD_IST_RE)' tools/smoke_test.sh boot.iso

.PHONY: smoke-resume-guard-ist-control
smoke-resume-guard-ist-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 RESUME_GUARD_BSS_ONLY=1
	@$(MAKE) --no-print-directory CAPTEST_SELFTEST=1 RESUME_GUARD_BSS_ONLY=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) EXPECT_FAULT='$(RESUME_GUARD_IST_RE)' \
		tools/smoke_test.sh boot.iso

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

# A BOOT THE WORKLOAD DIED IN IS INCONCLUSIVE, NOT A MISS -- and until
# 2026-08-27 this arm scored it as a failure. Two outcomes were conflated:
#
#   * the detector fires -- two CPUs shared a kernel stack. The property is
#     BROKEN. Fails immediately, on any attempt, and is never retried.
#   * the session does not complete -- the workload died or timed out at
#     `-smp 4` under a window this build DELIBERATELY WIDENS so it is entered on
#     every switch. That says nothing about whether two CPUs shared a stack. It
#     is the absence of evidence, and it was being scored as evidence against.
#
# This is the third time this exact lesson has had to be learned in this file.
# `smoke-kstack-park`'s control arm scored its own strongest reproductions as
# misses, and the repair -- recorded four hundred lines down -- was to name a
# died-in boot inconclusive and boot again. `KSTACK_RACE_CONTROL_BOOTS`, forty
# lines below THIS target, has carried the sample-size half since 2026-08-19.
# The arm next door got neither, and reddened a PR on 2026-08-27 whose diff was
# an early return in a function no live session calls.
#
# So: up to KSTACK_RACE_BOOTS attempts, stopping at the first COMPLETED session.
# The property assertion is unchanged and is not weakened -- the detector still
# fails the build on sight, on every attempt, and a retry can never turn a
# detected race into a pass.
#
# THE FENCE THAT MAKES THE RETRY HONEST: if every attempt is inconclusive the
# gate FAILS. A kernel that never boots must not pass by exhausting the loop,
# which is the obvious way for a retry to become a way of not testing. The
# inconclusive runs are named and tallied on the way past, so a build that is
# merely slow to die is visible rather than silently absorbed.
KSTACK_RACE_BOOTS ?= 4

.PHONY: smoke-kstack-race
smoke-kstack-race:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory KSTACK_RACE_WIDEN=1 boot.iso
	@echo "[kstack] widened window + deferred release: the session must complete"
	@log=$$(mktemp); n=0; done=0; incon=0; \
	while [ $$n -lt $(KSTACK_RACE_BOOTS) ]; do \
	    n=$$((n+1)); rc=0; \
	    QEMU_SMP=4 SESSION_TIMEOUT=$(KSTACK_RACE_TIMEOUT) SESSION_SERIAL_LOG="$$log" \
	        python3 tools/session_test.py boot.iso || rc=$$?; \
	    if grep -qa '$(KSTACK_RACE_RE)' "$$log"; then \
	        echo "KSTACK RACE: FAIL - two CPUs shared a kernel stack with the fix in place (attempt $$n)"; \
	        grep -a -A 6 '$(KSTACK_RACE_RE)' "$$log" | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	    fi; \
	    if [ $$rc -eq 0 ]; then done=$$n; break; fi; \
	    incon=$$((incon+1)); \
	    echo "  attempt $$n/$(KSTACK_RACE_BOOTS): INCONCLUSIVE - session did not complete (exit $$rc), no race detected either; retrying"; \
	    tail -5 "$$log" | sed 's/^/    /'; \
	done; \
	if [ $$done -eq 0 ]; then \
	    echo "KSTACK RACE: FAIL - no attempt completed a session in $(KSTACK_RACE_BOOTS) tries"; \
	    echo "  Every attempt was inconclusive, which is NOT a pass: a kernel that never"; \
	    echo "  boots must not satisfy this gate by exhausting the loop. Either the"; \
	    echo "  workload is broken, or the widened window has become unsurvivable."; \
	    tail -20 "$$log" | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	fi; \
	rm -f "$$log"; \
	if [ $$incon -gt 0 ]; then \
	    echo "KSTACK RACE: PASS - session completed on attempt $$done of $(KSTACK_RACE_BOOTS), no shared kernel stack ($$incon inconclusive)"; \
	else \
	    echo "KSTACK RACE: PASS - session completed, no shared kernel stack"; \
	fi

# The defect, on demand. Same widened window, pre-fix release site. Two things
# must be true and both are checked: the detector's line must appear, AND the
# session must not pass -- a build that reproduced the race and still reported
# success would mean the harness had stopped reading the wire.
.PHONY: smoke-kstack-race-control
# The pre-fix release site reproduces the race PROBABILISTICALLY, and this arm
# used to assert it from a SINGLE boot. Measured 2026-08-19: 7 reproductions in
# 12 boots on a workstation (58%), so it misses about 42% of the time there. On
# CI it reddened main TWICE the same day -- runs 32244509317 and 32251467694,
# two of the last eight runs -- with the fixed arm green in the same job both
# times, on trees whose content had already passed that same job on a branch.
#
# A single boot cannot assert a probabilistic event; this repository's own rule
# is to quote a rate over N boots, and the arm was quoting one while asserting
# from n=1.
#
# So it boots up to KSTACK_RACE_CONTROL_BOOTS times and stops at the first
# reproduction, naming the boot it came on. At the measured 58% the expected
# cost is under two boots, and the chance of a false failure across 8 is
# 0.42^8 -- about one run in a thousand. Nothing is weakened: a mechanism that
# has actually decayed reproduces on none of the 8 and fails exactly as before,
# which is what the message below is for. The fixed arm is left at one boot on
# purpose -- its assertion is that the panic NEVER appears, which a single boot
# can falsify, and its statistical power comes from smoke-session-smp-soak and
# tools/stress_boot.sh rather than from this pair.
KSTACK_RACE_CONTROL_BOOTS ?= 8

smoke-kstack-race-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory KSTACK_RACE_WIDEN=1 KSTACK_RELEASE_EARLY=1 boot.iso
	@echo "[kstack] widened window + PRE-FIX release: the race must reproduce"
	@log=$$(mktemp); hit=0; n=0; rc=0; \
	while [ $$n -lt $(KSTACK_RACE_CONTROL_BOOTS) ]; do \
	    n=$$((n+1)); rc=0; \
	    QEMU_SMP=4 SESSION_TIMEOUT=$(KSTACK_RACE_TIMEOUT) SESSION_SERIAL_LOG="$$log" \
	        python3 tools/session_test.py boot.iso || rc=$$?; \
	    if grep -qa '$(KSTACK_RACE_RE)' "$$log"; then hit=$$n; break; fi; \
	    echo "  boot $$n/$(KSTACK_RACE_CONTROL_BOOTS): no race yet"; \
	done; \
	if [ $$hit -eq 0 ]; then \
	    echo "KSTACK RACE CONTROL: FAIL - the pre-fix build did NOT reproduce the race"; \
	    echo "  in $(KSTACK_RACE_CONTROL_BOOTS) boots. It reproduced 7 of 12 when this arm"; \
	    echo "  was written, so a clean sweep of 8 is about one run in a thousand by"; \
	    echo "  chance. The control arm is what makes smoke-kstack-race a measurement;"; \
	    echo "  if it stops reproducing, the widened window or the detector has decayed."; \
	    tail -20 "$$log" | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	fi; \
	if [ $$rc -eq 0 ]; then \
	    echo "KSTACK RACE CONTROL: FAIL - the race reproduced but the session reported PASS"; \
	    rm -f "$$log"; exit 1; \
	fi; \
	grep -a -A 6 '$(KSTACK_RACE_RE)' "$$log" | head -8 | sed 's/^/  /'; \
	rm -f "$$log"; \
	echo "KSTACK RACE CONTROL: PASS - the pre-fix release site shares a kernel stack, as it must (boot $$hit of $(KSTACK_RACE_CONTROL_BOOTS))"

# Where a CPU parks when the last task it was running dies -- S20's second path.
#
# The three fault/exit fallbacks in idt.c resume the CPU at kernel_idle() when
# task_exit_switch() finds nothing else runnable. All three used
# tasks[0].kernel_stack_top: ONE stack, shared by every CPU that takes the path.
# Two CPUs parked there both `sti; hlt` on it and both push a trap frame at the
# same address on the next tick.
#
# g_kstack_inflight cannot see this -- it is keyed on task ids and skips task 0,
# which is legitimately the current task on several CPUs at once as the idle
# sentinel -- which is why this half of [G-8] survived the 2026-08-17 fix and was
# recorded as an unwitnessed lead rather than patched. It has a witness now.
#
# Measured with KSTACK0_PARK_TRACE=1 on the PROC_SELFTEST workload at -smp 4,
# which kills tasks on purpose: the path is entered 5-8 times per boot and two
# CPUs were parked on that one stack 2-3 times per boot, 3 boots out of 3.
#
# Both arms boot the same task-killing workload. The fixed arm asserts FOUR
# things, because three of them can pass vacuously on their own: the self-test
# completes, the park path was actually entered, every CPU parked on a DIFFERENT
# stack, and the collision report is absent. Without the "was it entered" check a
# kernel that simply never parks would score a green gate.
KSTACK_PARK_RE = PANIC: two CPUs parking on one kernel stack
# A boot that ends here did not run the workload to the end, so it never got the
# chance to park a second CPU. It is INCONCLUSIVE for the control arm, not a
# miss -- see the note above smoke-kstack-park-control. It is caused by this
# arm's own instrument (KSTACK0_PARK_TRACE, measured below) and happens on the
# FIXED build too, which is why it may never be read as evidence FOR the defect
# either.
KSTACK_PARK_TRUNC_RE = PROC_SELFTEST: FAIL
# The task-killing self-test under -smp 4 needs well past the 40s default: it
# reaches `altstack OK` and then times out mid-suspend. Measured, not guessed --
# three gate runs failed on exactly that before the budget was raised.
KSTACK_PARK_TIMEOUT ?= 180

# Both arms assert the SAME property, read off KSTACK0_PARK_TRACE: whether any one
# park stack was used by more than one CPU. That is deterministic. The detector's
# PANIC is not -- it fires only when two CPUs are parked at the SAME INSTANT, and
# a first draft of the control arm that gated on it reproduced 2 boots in 3.
# Whether the park target is per-CPU or shared is a property of the code; whether
# two CPUs happen to be parked simultaneously is a property of the schedule, and
# only the first is what this gate is about. The PANIC is still required to be
# absent on the fixed arm, where it is a free corroboration.
# ---- WHY THIS ARM DOES *NOT* BUILD KSTACK0_PARK_TRACE ------------------------
#
# It did, and it made this gate fail 10 boots in 25 on main. PARKTRACE emits through
# kfault_*, which writes bytes STRAIGHT TO COM1, bypassing console ownership --
# correct for a panic, where "there is no owner left worth being polite to", and
# wrong here. The park path fires 5-8 times a boot from interrupt context while
# proctest writes its markers from ring 3 via sys_write: two writers, one UART,
# nothing serialising them. A trace landing inside the 24 bytes of
# `PROC_SELFTEST: suspend OK` corrupts it, the exact-string match never matches,
# and the run times out:
#
#   PARKTRACE cpu=3 rsp=0xffffffff806ff0PROC_SELFTEST: PASS exit+kill+spawn
#
# Measured over 25 boots of one pinned ISO: 10 failures, and in ALL TEN the marker
# was corrupted while all 15 passes had it intact -- gate failure <=> corrupted
# marker, 10 for 10, so this is the mechanism and not a correlation. It went in on
# six green samples; at a 40% failure rate the chance of that is ~5%, which is what
# sampling six times instead of measuring buys you. This file's own rule --
# "a single green run says nothing" -- applied to the gate rather than the kernel.
#
# There is a SECOND reason, found 2026-08-22 and worse than the first: the trace
# does not merely corrupt the marker, it kills the workload. Same fixed kernel,
# same host, -smp 4, 20 boots each -- 8 of 20 died with KSTACK0_PARK_TRACE=1
# against 0 of 20 without it (Fisher one-sided p = 0.0016). This arm asserts that
# the self-test COMPLETES, so building the trace would have handed it a ~40%
# false-red on top of the marker corruption. The control arm cannot avoid the
# trace -- its assertion is the trace -- and pays for it by treating a boot the
# workload died in as inconclusive rather than as a miss.
#
# So reachability moves to the control arm, which is where it belongs and where
# smoke-resume-guard already puts it. That arm requires a park stack shared between
# CPUs, which cannot happen unless the path is entered on two CPUs -- so if the
# workload ever stops killing tasks, the PAIR still fails. This arm then needs no
# kernel output at all, and with no second writer on the UART it is deterministic.
.PHONY: smoke-kstack-park
smoke-kstack-park:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 boot.iso
	@log=$$(mktemp); rc=0; \
	SMOKE_TIMEOUT=$(KSTACK_PARK_TIMEOUT) SMOKE_LOG="$$log" MARKER_ONLY=1 SMP_CPUS=4 \
	    REQUIRE_MARKER='PROC_SELFTEST: suspend OK' FAIL_MARKER='PROC_SELFTEST: FAIL' \
	    tools/smoke_test.sh boot.iso >/dev/null 2>&1 || rc=$$?; \
	if [ $$rc -ne 0 ]; then \
	    echo "KSTACK PARK: FAIL - the task-killing self-test did not complete (exit $$rc)"; \
	    tail -20 "$$log" 2>/dev/null | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	fi; \
	if grep -qa '$(KSTACK_PARK_RE)' "$$log"; then \
	    echo "KSTACK PARK: FAIL - two CPUs parked on one kernel stack"; \
	    grep -a -A 4 '$(KSTACK_PARK_RE)' "$$log" | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	fi; \
	rm -f "$$log"; \
	echo "KSTACK PARK: PASS - task-killing workload completed on 4 CPUs, no shared park stack"

# The defect, on demand: the same task-killing workload with the shared park
# restored. At least one park stack must come back used by more than one CPU.
#
# This arm carries BOTH halves of the argument, which is why the arm above needs no
# kernel output. A park stack shared between two CPUs cannot occur unless the park
# path is entered on two CPUs, so requiring it proves reachability as well as the
# defect -- and if the workload ever stops killing tasks, this arm goes red and the
# pair fails. Without it, `smoke-kstack-park` is consistent with "the path is
# unreachable", which is exactly what it looks like on a HEALTHY session: 0 parks in
# 3 boots.
#
# This is the one arm that MAY build KSTACK0_PARK_TRACE, because its assertion is
# the trace and not a marker. The trace writes directly to COM1 and will corrupt
# proctest's output (see the note on the arm above) -- here that is harmless, and
# the smoke harness's exit status is deliberately not the assertion for the same
# reason.
#
# ---- WHY THIS ARM BOOTS MORE THAN ONCE -------------------------------------
#
# A SHARED park needs two CPUs to reach the park path in the same boot, and how
# many get there is a property of the schedule, not of the build. Measured
# 2026-08-22 over 12 boots at -smp 4: reproduced in 9. 75% per boot means a
# single-boot assertion reports a false red one run in four.
#
# It asserted from one boot until 2026-08-22 and got away with it while the job
# was advisory. Promoting it to merge-gating (#190) made that a ~25% chance of
# reddening `main` per run, and it duly failed on the first unrelated PR to run
# against it. This is the same lesson KSTACK_RACE_CONTROL_BOOTS already carries
# four hundred lines up -- "never assert a probabilistic event from one boot",
# which reddened `main` twice on 2026-08-19 -- applied to the arm next door that
# did not get it at the time.
#
# ---- WHY 8 BOOTS WAS NOT ENOUGH EITHER, AND WHAT ACTUALLY FIXES IT -----------
#
# That measurement read the three misses as "exactly ONE park in the whole boot,
# so a shared stack was impossible in that boot" -- the workload simply did not
# kill enough tasks -- and from there treated the boots as INDEPENDENT, reasoning
# that 0.25^8 is "one run in 65000" and so a clean sweep had to mean decay rather
# than noise.
#
# The independence was the error, and `main` proved it on 9476799: 8 misses out of
# 8, in a run GitHub reported green because the job could not fail (see ci.yml).
# Re-measured 12 boots locally on the same commit: 10 reproduced, and BOTH misses
# had the same shape as all eight of CI's -- one park traced, then
# `KERNEL FATAL EXCEPTION` and `PROC_SELFTEST: FAIL`. The workload DIED. It did not
# decline to kill tasks; it never got to the end.
#
# ---- AND IT IS THIS ARM'S OWN INSTRUMENT DOING IT ---------------------------
#
# Measured 2026-08-22 on the FIXED kernel, same workload, same host, -smp 4,
# 20 boots each:
#
#     PROC_SELFTEST=1 KSTACK0_PARK_TRACE=1   ->  8 of 20 boots died
#     PROC_SELFTEST=1                        ->  0 of 20 boots died
#
# Fisher one-sided p = 0.0016. KSTACK0_PARK_TRACE writes through kfault_* straight
# to COM1 from interrupt context, 5-10 times a boot; that is enough to kill the
# workload on ~40% of boots. It is not the shared park -- the fixed build does it
# -- and it is not a [G-9] residual in anything shipped: the uninstrumented build
# is 0 for 20 here, consistent with the 0-in-200 that promoted this gate.
#
# Two things follow. The rate is a property of the HOST'S TIMING, which is the
# correlated cause that destroys independence and is why a CI runner turned
# "one run in 65000" into 8 for 8. And the ~40% the pre-promotion job comment
# attributed to the workload ("a pre-existing scheduler claim leak on ~40% of
# boots, 9/20 at -smp 4 against 0/20 at -smp 1") was measured on the INSTRUMENTED
# build: 9/20 then, 8/20 now. The instrument was in the room the whole time.
# A bigger N cannot fix a biased sample.
#
# ---- AND WHY THE OBVIOUS FIX IS WRONG ----------------------------------------
#
# The tempting move is to count "parked, then the kernel died" as a third witness:
# the defect corrupted a live stack and the machine fell over, which is the defect
# reproducing at full strength, and the base arm requires the FIXED build to
# complete this same workload -- so the pair looks like it differs by exactly that.
#
# It does not. Falsified 2026-08-22 by running that predicate against the fixed
# build with KSTACK0_PARK_TRACE=1: boots of 6, 10 and 8 parks and then, on the
# fourth, ONE park and a `KERNEL FATAL EXCEPTION`. Identical shape, no shared park
# anywhere in the build -- and then 8 of 20 on the same build, below. The crash is
# the instrument, not this defect, and a witness that fires on the fixed build is
# not a witness. It went in and came straight back out; this paragraph is what it
# left behind.
#
# ---- WHAT IS CORRECT -----------------------------------------------------------
#
# A boot the workload died in is INCONCLUSIVE. It is not evidence against the
# defect (the path was never exercised to the end) and it is not evidence for it
# (the fixed build dies the same way). So it is not counted in either direction:
# the loop names it, keeps a tally, and boots again, up to
# KSTACK_PARK_CONTROL_ATTEMPTS. The N of 8 now counts boots that RAN TO COMPLETION.
#
# This is worth what it costs because conclusive boots are not a coin flip at all:
# of the 12 boots measured on 2026-08-22, all 10 that completed reproduced the
# shared park -- 10 for 10. The schedule-dependence the 8-boot budget was bought to
# cover lives almost entirely in whether the boot survives, and that is precisely
# the part that is now measured instead of gambled on.
#
# Exhausting the attempts is a RED, and a differently-worded one: a run that could
# not measure must not be able to look like a run that measured and found the
# defect. Fail closed, and say which failure it was.
KSTACK_PARK_CONTROL_BOOTS ?= 8
# Hard cap on total boots, inconclusive ones included, so a host where the trace
# kills nearly every boot fails in bounded time instead of looping. A conclusive
# boot reproduced the defect 10 times out of 10, so one is enough and the cap only
# has to outlast the truncation: at the 40% measured here that is 0.4^24, and even
# at the 8-in-8 a CI runner managed it is 0.63^24 on the 95% lower bound. A run
# that needs more than 24 has a rate worth writing down before it has a bigger
# number.
KSTACK_PARK_CONTROL_ATTEMPTS ?= 24

.PHONY: smoke-kstack-park-control
smoke-kstack-park-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 KSTACK0_PARK_TRACE=1 KSTACK0_SHARED_PARK=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 KSTACK0_PARK_TRACE=1 KSTACK0_SHARED_PARK=1 boot.iso
	@log=$$(mktemp); hit=0; n=0; good=0; bad=0; rc=0; dup=""; \
	while [ $$n -lt $(KSTACK_PARK_CONTROL_ATTEMPTS) ] \
	      && [ $$good -lt $(KSTACK_PARK_CONTROL_BOOTS) ]; do \
	    n=$$((n+1)); rc=0; \
	    SMOKE_TIMEOUT=$(KSTACK_PARK_TIMEOUT) SMOKE_LOG="$$log" MARKER_ONLY=1 SMP_CPUS=4 \
	        REQUIRE_MARKER='PROC_SELFTEST: suspend OK' FAIL_MARKER='PROC_SELFTEST: FAIL' \
	        tools/smoke_test.sh boot.iso >/dev/null 2>&1 || rc=$$?; \
	    : "captured, and deliberately NOT the assertion: this arm halts a CPU on"; \
	    : "purpose, so whether the self-test still finishes is a property of the"; \
	    : "schedule. The assertion is the shared park stack below. rc=$$rc"; \
	    dup=$$(grep -ha PARKTRACE "$$log" \
	           | sed -n 's/.*cpu=\([0-9]*\) rsp=\([^ ]*\).*/\2 \1/p' \
	           | sort -u | awk '{c[$$1]++} END {for (r in c) if (c[r] > 1) print r}'); \
	    : "The kernel's OWN detector is the other, stronger witness, and it has to"; \
	    : "count: sched_note_park HALTS the machine the moment it sees the second"; \
	    : "CPU, so on those boots the second PARKTRACE line is never printed and"; \
	    : "the duplicate-rsp test above sees only one. Requiring two trace lines"; \
	    : "therefore MISSES exactly the boots where the defect fired hardest --"; \
	    : "observed 2026-08-22, a boot whose log carried the PANIC and was still"; \
	    : "scored as a miss. Either signal is the same event."; \
	    if [ -z "$$dup" ] && grep -qa '$(KSTACK_PARK_RE)' "$$log"; then \
	        dup=$$(grep -ha '$(KSTACK_PARK_RE)' "$$log" \
	               | sed -n 's/.*rsp=\([^ ]*\).*/\1 (from the kernel panic)/p' | head -1); \
	    fi; \
	    if [ -n "$$dup" ]; then hit=$$n; break; fi; \
	    : "A boot that died in the workload never reached the end of the path, so"; \
	    : "it says nothing about whether two CPUs would have shared a stack. Count"; \
	    : "it, name it, and do NOT spend a boot of the budget on it -- but never"; \
	    : "read it as evidence FOR the defect: the fixed build does it too."; \
	    if grep -qa '$(KSTACK_PARK_TRUNC_RE)' "$$log"; then \
	        bad=$$((bad+1)); \
	        echo "  attempt $$n: INCONCLUSIVE, the workload died after $$(grep -hac PARKTRACE "$$log") park(s) -- not counted"; \
	    else \
	        good=$$((good+1)); \
	        echo "  boot $$good/$(KSTACK_PARK_CONTROL_BOOTS): $$(grep -hac PARKTRACE "$$log") park(s), none shared"; \
	    fi; \
	done; \
	if [ $$hit -eq 0 ] && [ $$good -lt $(KSTACK_PARK_CONTROL_BOOTS) ]; then \
	    echo "KSTACK PARK CONTROL: FAIL - could not MEASURE the shared park."; \
	    echo "  $$bad of $$n attempts died in the workload before the park path could be"; \
	    echo "  entered on two CPUs, leaving $$good conclusive boot(s) of the"; \
	    echo "  $(KSTACK_PARK_CONTROL_BOOTS) wanted. KSTACK0_PARK_TRACE does that to ~40% of boots"; \
	    echo "  on the FIXED kernel too, so it is the instrument and not this defect --"; \
	    echo "  but an arm that cannot measure fails closed rather than passing."; \
	    echo "  Raise KSTACK_PARK_CONTROL_ATTEMPTS only with a rate to justify it."; \
	    tail -20 "$$log" 2>/dev/null | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	fi; \
	if [ $$hit -eq 0 ]; then \
	    echo "KSTACK PARK CONTROL: FAIL - the shared park did NOT reproduce in"; \
	    echo "  $$good boots that ran to completion ($$bad more died and were not counted)."; \
	    echo "  EVERY conclusive boot reproduced it when this arm was measured -- 10 of 10"; \
	    echo "  on 2026-08-22 -- so a clean sweep of $$good is evidence that the shared park"; \
	    echo "  has stopped being restored or the PARKTRACE detector has decayed, not noise."; \
	    tail -20 "$$log" 2>/dev/null | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	fi; \
	cpus=$$(grep -ha PARKTRACE "$$log" | grep -o 'cpu=[0-9]*' | sort -u | wc -l); \
	echo "  shared park stack(s): $$dup   (distinct CPUs parking: $$cpus)"; \
	if grep -qa '$(KSTACK_PARK_RE)' "$$log"; then \
	    grep -a -A 3 '$(KSTACK_PARK_RE)' "$$log" | head -4 | sed 's/^/  /'; \
	fi; \
	rm -f "$$log"; \
	echo "KSTACK PARK CONTROL: PASS - the shared park puts two CPUs on one stack, as it must (boot $$hit of $(KSTACK_PARK_CONTROL_BOOTS))"

# ---- [G-9], exec hand-off component: the re-entry belongs to the CPU that armed it
#
# g_exec_reenter_task was ONE global consumed on the exit of every syscall on
# every CPU, so an exec armed on one core was taken by another -- which claimed
# the exec'ing task, installed its CR3 and resumed the trap frame the exec tail
# had just built, while the core that ran the exec was still on that same frame.
#
# BOTH ARMS ARE MARKER ASSERTIONS, NOT EXIT STATUSES, and deliberately so: the
# PROC_SELFTEST workload at -smp 4 still fails 2 boots in 30 (~7%) on the rest of
# [G-9] -- the bogus resume %rsp -- which has nothing to do with this property.
# Gating on "did the boot finish" would make this pair a detector for that.
# Gating on the marker asks only the question these arms exist to ask.
# (Read "~27% of boots on [G-10]" until 2026-08-18: that rate predates [G-10]'s
# page-table fix, and [G-10] closed that day.)
#
# The control arm needs MANY boots because the theft is a race: measured 5 hits
# in 20 boots (25%/boot), against 0 in 30 for the fix. One boot would report a
# false green three times in four.
EXEC_REENTER_RUNS ?= 20
EXEC_REENTER_TIMEOUT ?= 180
EXEC_REENTER_RE = exec re-entry taken by the wrong cpu

.PHONY: smoke-exec-reenter
smoke-exec-reenter:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 boot.iso
	@log=$$(mktemp); rc=0; \
	for i in $$(seq 1 $(EXEC_REENTER_RUNS)); do \
	    one=$$(mktemp); \
	    SMOKE_TIMEOUT=$(EXEC_REENTER_TIMEOUT) SMOKE_LOG="$$one" MARKER_ONLY=1 SMP_CPUS=4 \
	        REQUIRE_MARKER='PROC_SELFTEST: suspend OK' FAIL_MARKER='PANIC:' \
	        tools/smoke_test.sh boot.iso >/dev/null 2>&1 || rc=$$?; \
	    cat "$$one" >> "$$log"; rm -f "$$one"; \
	done; \
	: "rc is captured and deliberately NOT the assertion: the rest of [G-9]"; \
	: "still stalls 2 in 30 of these boots, and gating on completion would"; \
	: "make this pair a detector for that, not a witness. rc=$$rc"; \
	hits=$$(grep -ca '$(EXEC_REENTER_RE)' "$$log"); \
	if [ "$$hits" -ne 0 ]; then \
	    echo "EXEC REENTER: FAIL - the exec hand-off was taken by the wrong CPU ($$hits/$(EXEC_REENTER_RUNS) boots)"; \
	    grep -a -A 1 '$(EXEC_REENTER_RE)' "$$log" | head -6 | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	fi; \
	rm -f "$$log"; \
	echo "EXEC REENTER: PASS - no CPU took another CPU's exec re-entry in $(EXEC_REENTER_RUNS) boots at -smp 4"

# ---- [G-10]: a slot's page tables are not recycled while a CPU is on them
#
# create_user_pagedir() used to free the previous occupant's address space
# unconditionally, justified by "the caller is on the kernel CR3, so the tree is
# not the one any CPU is walking" -- a uniprocessor argument. A CPU parked in
# kernel_idle never reloads CR3, and SYS_KILL marks a task dead while it is still
# running in ring 3 elsewhere, so the freed frames went back to the pool and were
# handed out as ordinary pages while another core still translated through them.
#
# The visible symptom is a supervisor WRITE fault at 0xFEE000B0 -- the LAPIC EOI
# register, which lives in each task's own pml4[0] identity map and disappears
# when its leaf PTE is recycled. Measured 2026-08-17: 6 boots in 30 before,
# 0 in 30 after.
#
# The two arms assert different markers, deliberately. The fixed arm asserts the
# BEHAVIOUR (no such fault), because that is the property. The control arm
# asserts the CR3UAF report, because the free-in-use happens on every boot while
# the fault it causes only lands ~20% of the time -- gating the control on the
# fault would make it flaky for no gain.
CR3_RECLAIM_RUNS ?= 20
CR3_RECLAIM_TIMEOUT ?= 180
CR3_RECLAIM_RE = PAGE FAULT at 0xfee000b0

.PHONY: smoke-cr3-reclaim
smoke-cr3-reclaim:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 boot.iso
	@log=$$(mktemp); rc=0; \
	for i in $$(seq 1 $(CR3_RECLAIM_RUNS)); do \
	    one=$$(mktemp); \
	    SMOKE_TIMEOUT=$(CR3_RECLAIM_TIMEOUT) SMOKE_LOG="$$one" MARKER_ONLY=1 SMP_CPUS=4 \
	        REQUIRE_MARKER='PROC_SELFTEST: suspend OK' FAIL_MARKER='PROC_SELFTEST: FAIL' \
	        tools/smoke_test.sh boot.iso >/dev/null 2>&1 || rc=$$?; \
	    cat "$$one" >> "$$log"; rm -f "$$one"; \
	done; \
	: "rc captured, not asserted on: the rest of [G-9] still fails ~7% of these"; \
	: "boots and this gate is not about that. rc=$$rc"; \
	hits=$$(grep -ca '$(CR3_RECLAIM_RE)' "$$log"); \
	if [ "$$hits" -ne 0 ]; then \
	    echo "CR3 RECLAIM: FAIL - the LAPIC page vanished from a live address space ($$hits/$(CR3_RECLAIM_RUNS) boots)"; \
	    grep -a -A 4 '$(CR3_RECLAIM_RE)' "$$log" | head -8 | sed 's/^/  /'; rm -f "$$log"; exit 1; \
	fi; \
	rm -f "$$log"; \
	echo "CR3 RECLAIM: PASS - no recycled page table faulted in $(CR3_RECLAIM_RUNS) boots at -smp 4"

.PHONY: smoke-cr3-reclaim-control
smoke-cr3-reclaim-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 CR3_RECLAIM_UNGUARDED=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 CR3_RECLAIM_UNGUARDED=1 boot.iso
	@log=$$(mktemp); rc=0; \
	for i in $$(seq 1 3); do \
	    one=$$(mktemp); \
	    SMOKE_TIMEOUT=$(CR3_RECLAIM_TIMEOUT) SMOKE_LOG="$$one" MARKER_ONLY=1 SMP_CPUS=4 \
	        REQUIRE_MARKER='PROC_SELFTEST: suspend OK' FAIL_MARKER='PANIC:' \
	        tools/smoke_test.sh boot.iso >/dev/null 2>&1 || rc=$$?; \
	    cat "$$one" >> "$$log"; rm -f "$$one"; \
	done; \
	: "rc captured, not asserted on: this arm halts on purpose. rc=$$rc"; \
	hits=$$(grep -ca 'CR3UAF' "$$log"); \
	if [ "$$hits" -eq 0 ]; then \
	    echo "CR3 RECLAIM CONTROL: FAIL - the unguarded reclaim did NOT free a tree in use."; \
	    echo "  This arm carries reachability for the pair: if the free-in-use stops"; \
	    echo "  happening with the guard removed, smoke-cr3-reclaim proves nothing."; \
	    echo "  Measured 2026-08-17: 20 boots in 20."; \
	    rm -f "$$log"; exit 1; \
	fi; \
	grep -a 'CR3UAF' "$$log" | head -2 | sed 's/^/  /'; \
	rm -f "$$log"; \
	echo "CR3 RECLAIM CONTROL: PASS - the unguarded reclaim frees an address space in use ($$hits/3 boots)"

# ---- [G-11]: the staged image can only be spawned by the task that armed it
#
# Deterministic, single-threaded, and both directions. The self-test forges the
# state a second task's arm leaves behind -- a legitimately staged image whose
# recorded owner is another task -- and requires do_spawn to refuse it, then
# re-arms honestly and requires the spawn to succeed. A gate that only checked
# the refusal would pass on a kernel that refused every spawn.
#
# The control arm is the falsification: SPAWN_OWNER_UNCHECKED=1 restores the
# pre-2026-08-18 consume and the self-test reports
# "FAIL foreign-image-spawned pid 1" on every boot.
.PHONY: smoke-spawn-owner
smoke-spawn-owner:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SPAWN_OWNER_SELFTEST=1
	@$(MAKE) --no-print-directory SPAWN_OWNER_SELFTEST=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='SPAWN_OWNER_SELFTEST: PASS' \
		FAIL_MARKER='SPAWN_OWNER_SELFTEST: FAIL' tools/smoke_test.sh boot.iso

.PHONY: smoke-spawn-owner-control
smoke-spawn-owner-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SPAWN_OWNER_SELFTEST=1 SPAWN_OWNER_UNCHECKED=1
	@$(MAKE) --no-print-directory SPAWN_OWNER_SELFTEST=1 SPAWN_OWNER_UNCHECKED=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='SPAWN_OWNER_SELFTEST: FAIL foreign-image-spawned' \
		tools/smoke_test.sh boot.iso
	@echo "SPAWN OWNER CONTROL: PASS - unchecked, a foreign staged image is spawned"

.PHONY: smoke-exec-reenter-control
smoke-exec-reenter-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 EXEC_REENTER_GLOBAL=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 EXEC_REENTER_GLOBAL=1 boot.iso
	@log=$$(mktemp); rc=0; \
	for i in $$(seq 1 $(EXEC_REENTER_RUNS)); do \
	    one=$$(mktemp); \
	    SMOKE_TIMEOUT=$(EXEC_REENTER_TIMEOUT) SMOKE_LOG="$$one" MARKER_ONLY=1 SMP_CPUS=4 \
	        REQUIRE_MARKER='PROC_SELFTEST: suspend OK' FAIL_MARKER='PANIC:' \
	        tools/smoke_test.sh boot.iso >/dev/null 2>&1 || rc=$$?; \
	    cat "$$one" >> "$$log"; rm -f "$$one"; \
	done; \
	: "rc captured, not asserted on -- this arm halts a CPU on purpose. rc=$$rc"; \
	hits=$$(grep -ca '$(EXEC_REENTER_RE)' "$$log"); \
	if [ "$$hits" -eq 0 ]; then \
	    echo "EXEC REENTER CONTROL: FAIL - the shared hand-off did NOT reproduce in $(EXEC_REENTER_RUNS) boots."; \
	    echo "  This arm carries reachability for the pair: if the theft stops happening with"; \
	    echo "  the global restored, then smoke-exec-reenter's green says nothing either."; \
	    echo "  Expected ~25%/boot (measured 5 in 20 on 2026-08-17)."; \
	    rm -f "$$log"; exit 1; \
	fi; \
	grep -a '$(EXEC_REENTER_RE)' "$$log" | head -2 | sed 's/^/  /'; \
	rm -f "$$log"; \
	echo "EXEC REENTER CONTROL: PASS - the shared hand-off is taken by the wrong CPU ($$hits/$(EXEC_REENTER_RUNS) boots), as it must be"

# Roadmap 1.3: the blocking receive really sleeps, and the wake really carries
# the reply right. See RECVBLOCK_SELFTEST above for what the markers mean.
# ---- The claim-release invariant ------------------------------------------
#
# "A CPU in ring 3 owes no deferred release." Every route to ring 3 goes through
# an epilogue and every epilogue must call sched_release_deferred(); a CPU
# observed in ring 3 still owing one means some path reached user mode without
# paying, and that task's claim is stuck forever -- unschedulable by every CPU
# including its holder. That is the [G-9] leak's shape.
#
# It is stated as an invariant rather than left to the periodic claim audit
# because the audit CANNOT see it: sched_assert_claims() deliberately exempts a
# task whose holder's deferred slot names it. An unpaid debt hides inside the
# very exemption that keeps the auditor honest.
# ---- Validate before committing a switch ------------------------------------
#
# task_exit_switch() returns 0 for TWO incompatible things: "nothing runnable,
# caller parks" (no claim taken) and, via ksp_refuse(), "I already claimed `next`
# and named it current, but its resume value is bogus". Its three callers in
# idt.c all read `if (rsp) return rsp;` and otherwise park the CPU -- so a
# refusal was indistinguishable from an empty run queue and `next` stayed claimed
# forever, unschedulable by every CPU including the holder. That is a [G-9] leak,
# and the resume guard added FOR [G-9] is what produced it.
#
# KSP_GUARD_INJECT forges the bogus value, so this pair is deterministic where
# the natural event reproduces at ~3% -- a gate rather than a soak.
#
# The base arm asserts BOTH directions on markers rather than on completion: the
# guard's own report must be PRESENT (so a build where it never fires cannot pass
# by silence) and `stale scheduler claim` ABSENT. It cannot require the workload
# to finish, because under this artificial injection every resume value is forged
# bogus, so each CPU refuses in turn and the session stalls -- which is the
# residual behaviour the fix trades for, and is expected here.
# ---- The auditor's exemption must outlive the release ------------------------
#
# percpu_deferred_release[] is not just a CPU's to-do note: sched_assert_claims()
# uses it as the EXEMPTION that says "this claim is mid-handover, not leaked".
# sched_release_deferred() used to clear it BEFORE taking the lock that drops the
# claim, so for the width of a lock acquisition the task was claimed, un-exempt
# and mid-release -- and an audit landing there reported a leak that was not one.
# That is the residual [G-9], and it was the CHECKER, not the scheduler.
#
# DEFER_WINDOW_WIDEN stretches that window, so the pair is deterministic where the
# natural event sits at ~4.5% with variance wide enough that 200-boot arms could
# not tell 4.5% from 6.5% (measured: baseline ran 2/50 then 9/200). Set in BOTH
# arms -- that is what makes it a measurement, as with KSTACK_RACE_WIDEN.
#
#   widened + pre-fix order : 8 of 10 boots panic
#   widened + fixed order   : 0 of 10          (Fisher p ~ 0.0007)
#   natural rate            : 9/200 -> 0/200   (Fisher p ~ 0.0036)
DEFER_EXEMPTION_BOOTS ?= 8
.PHONY: smoke-defer-exemption
smoke-defer-exemption:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 DEFER_WINDOW_WIDEN=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 DEFER_WINDOW_WIDEN=1 boot.iso
	@SMP_CPUS=4 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='PROC_SELFTEST: suspend OK' \
		FAIL_MARKER='stale scheduler claim' \
		tools/smoke_test.sh boot.iso

# Control arm. Same widening, exemption cleared early: the audit must accuse.
# Reproduces in 8 boots of 10, so this tries up to DEFER_EXEMPTION_BOOTS and
# stops at the first reproduction -- never assert a probabilistic event from one
# boot, which is the mistake `smoke-kstack-race-control` records costing two red
# mains on 2026-08-19.
.PHONY: smoke-defer-exemption-control
smoke-defer-exemption-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 DEFER_WINDOW_WIDEN=1 DEFER_CLEAR_EARLY=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 DEFER_WINDOW_WIDEN=1 DEFER_CLEAR_EARLY=1 boot.iso
	@n=0; hit=0; \
	while [ $$n -lt $(DEFER_EXEMPTION_BOOTS) ]; do \
	    n=$$((n+1)); \
	    if SMP_CPUS=4 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) tools/smoke_test.sh boot.iso 2>&1 \
	         | grep -q 'stale scheduler claim'; then \
	        echo "[defer] reproduced on boot $$n of $(DEFER_EXEMPTION_BOOTS)"; hit=1; break; \
	    fi; \
	done; \
	if [ $$hit -eq 0 ]; then \
	    echo "DEFER CONTROL: FAIL - the pre-fix order did not reproduce in $$n boots"; exit 1; \
	fi

.PHONY: smoke-switch-commit
smoke-switch-commit:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 KSP_GUARD_INJECT=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 KSP_GUARD_INJECT=1 boot.iso
	@SMP_CPUS=4 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='SCHED BOGUS KSP from task_exit_switch' \
		FAIL_MARKER='stale scheduler claim' \
		tools/smoke_test.sh boot.iso

# Control arm: same injection, pre-fix ordering. The claim is taken before the
# value is validated, the refusal parks the CPU, and the claim is orphaned --
# every boot.
.PHONY: smoke-switch-commit-control
smoke-switch-commit-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 KSP_GUARD_INJECT=1 SWITCH_COMMIT_EARLY=1
	@$(MAKE) --no-print-directory PROC_SELFTEST=1 SCHED_INVARIANTS=1 KSP_GUARD_INJECT=1 SWITCH_COMMIT_EARLY=1 boot.iso
	@n=0; hit=0; \
	while [ $$n -lt $(SWITCH_COMMIT_CONTROL_BOOTS) ]; do \
	    n=$$((n+1)); \
	    out=$$(SMP_CPUS=4 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) \
	        EXPECT_FAULT='stale scheduler claim' \
	        tools/smoke_test.sh boot.iso 2>&1); rc=$$?; \
	    echo "$$out" | tail -2 | sed 's/^/  /'; \
	    if [ $$rc -eq 0 ]; then hit=$$n; break; fi; \
	    case "$$out" in \
	      *"timed out"*|*"exited before the banner"*) \
	        echo "  attempt $$n/$(SWITCH_COMMIT_CONTROL_BOOTS): INCONCLUSIVE - the boot reached neither the fault nor the banner; retrying" ;; \
	      *) \
	        echo "SWITCH COMMIT CONTROL: FAIL - committing the switch early did NOT leave a stale claim"; \
	        echo "  The run COMPLETED without it, which is a real miss and is not retried."; \
	        exit 1 ;; \
	    esac; \
	done; \
	if [ $$hit -eq 0 ]; then \
	    echo "SWITCH COMMIT CONTROL: FAIL - no attempt reproduced the defect in $(SWITCH_COMMIT_CONTROL_BOOTS) boots"; \
	    echo "  Every attempt was inconclusive. Exhausting the loop is a FAILURE, not a pass."; \
	    exit 1; \
	fi; \
	echo "SWITCH COMMIT CONTROL: PASS - observed on boot $$hit of $(SWITCH_COMMIT_CONTROL_BOOTS)"

.PHONY: smoke-claim-release
smoke-claim-release:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SCHED_INVARIANTS=1
	@$(MAKE) --no-print-directory SCHED_INVARIANTS=1 boot.iso
	@SMP_CPUS=4 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) \
		FAIL_MARKER='deferred release outstanding' \
		tools/smoke_test.sh boot.iso

# Control arm. CLAIM_RELEASE_SKIP=1 removes the release from the ISR epilogue, so
# every switching CPU reaches ring 3 owing one and the guard must fire. Without
# this arm the gate above would be an assertion nobody had ever seen fire -- and
# this file already records what that costs: `smoke-ksp-guard` shipped a control
# arm with no positive counterpart, and the resume-guard shipped a bound that
# rejected the IST stacks.
.PHONY: smoke-claim-release-control
# ---- The two control arms that assert a SCHEDULING-DEPENDENT fault ---------
#
# Both boot a deliberately-broken kernel at SMP_CPUS=4 and require a specific
# fault. Three outcomes are possible and they are NOT the same:
#
#   * the fault appears            -> the defect reproduced. PASS.
#   * the run completes without it -> the defect did NOT reproduce. FAIL, at
#                                     once, never retried: for a deterministic
#                                     defect that is a real miss and retrying it
#                                     would be how an N-try loop becomes a way
#                                     of passing.
#   * the boot never reaches either -> INCONCLUSIVE. No evidence either way, and
#                                     until 2026-08-27 this was the ONLY way
#                                     these arms could go red. Retried.
#
# Measured: 1 failure in the last 10 CI runs on main for
# smoke-claim-release-control, with its base arm green in the same job.
CLAIM_RELEASE_CONTROL_BOOTS ?= 3
SWITCH_COMMIT_CONTROL_BOOTS ?= 3

smoke-claim-release-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SCHED_INVARIANTS=1 CLAIM_RELEASE_SKIP=1
	@$(MAKE) --no-print-directory SCHED_INVARIANTS=1 CLAIM_RELEASE_SKIP=1 boot.iso
	@n=0; hit=0; \
	while [ $$n -lt $(CLAIM_RELEASE_CONTROL_BOOTS) ]; do \
	    n=$$((n+1)); \
	    out=$$(SMP_CPUS=4 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) \
	        EXPECT_FAULT='ring 3 reached with a deferred release outstanding' \
	        tools/smoke_test.sh boot.iso 2>&1); rc=$$?; \
	    echo "$$out" | tail -2 | sed 's/^/  /'; \
	    if [ $$rc -eq 0 ]; then hit=$$n; break; fi; \
	    case "$$out" in \
	      *"timed out"*|*"exited before the banner"*) \
	        echo "  attempt $$n/$(CLAIM_RELEASE_CONTROL_BOOTS): INCONCLUSIVE - the boot reached neither the fault nor the banner; retrying" ;; \
	      *) \
	        echo "CLAIM RELEASE CONTROL: FAIL - the skipped release did NOT trip the guard"; \
	        echo "  The run COMPLETED without it, which is a real miss and is not retried."; \
	        exit 1 ;; \
	    esac; \
	done; \
	if [ $$hit -eq 0 ]; then \
	    echo "CLAIM RELEASE CONTROL: FAIL - no attempt reproduced the defect in $(CLAIM_RELEASE_CONTROL_BOOTS) boots"; \
	    echo "  Every attempt was inconclusive. Exhausting the loop is a FAILURE, not a pass."; \
	    exit 1; \
	fi; \
	echo "CLAIM RELEASE CONTROL: PASS - observed on boot $$hit of $(CLAIM_RELEASE_CONTROL_BOOTS)"

# ---- Frame capabilities (roadmap 2.1, finding F-2.1) ------------------------
#
# The base gate. Two ring-3 tasks and one physical page: one retypes a KOBJ_FRAME
# out of its CAP_UNTYPED, maps it, asserts every refusal the map path owes, then
# mints a READ-only copy and delegates it; the other proves it sees the shared
# bytes and cannot obtain a writable mapping. Both directions in one target,
# which is what tools/check_gate_pairs.py asks of every gate that has a control
# arm: an arm that injects a defect and looks for the check firing measures false
# NEGATIVES only, and a predicate that rejects everything satisfies all of them.
# ---- The VFS mount table (roadmap 2.4) -------------------------------------
#
# Two servers, two mounts, one namespace. Both directions in one target: the
# positive half reads zeros through /dev/zero and keeps /bin on the root mount,
# the adversarial half asserts a mount needs a capability and that longest
# prefix wins.
.PHONY: smoke-vfs
smoke-vfs:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory VFS_SELFTEST=1
	@$(MAKE) --no-print-directory VFS_SELFTEST=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='VFSTEST: PASS' \
		FAIL_MARKER='VFSTEST: FAIL' \
		tools/smoke_test.sh boot.iso

# Control arm 1 -- routing. VFS_FIRST_MATCH=1 returns the first matching mount,
# and "/" matches everything, so /dev/zero is addressed to the root filesystem.
# It does not fail: that server has an inode 0 of its own and answers about a
# different object. The FAIL marker must be PRESENT.
.PHONY: smoke-vfs-prefix-control
smoke-vfs-prefix-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory VFS_SELFTEST=1 VFS_FIRST_MATCH=1
	@$(MAKE) --no-print-directory VFS_SELFTEST=1 VFS_FIRST_MATCH=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='VFSTEST: FAIL wrong-server-answered' \
		tools/smoke_test.sh boot.iso
	@echo "VFS PREFIX CONTROL: PASS - first match sends /dev/zero to the wrong server"

# Control arm 2 -- the mount gate. VFS_MOUNT_UNGATED=1 removes hvfs_mount's
# probe, so a prefix string alone installs a mount over a slot holding no
# capability. The FAIL marker must be PRESENT.
.PHONY: smoke-vfs-mount-control
smoke-vfs-mount-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory VFS_SELFTEST=1 VFS_MOUNT_UNGATED=1
	@$(MAKE) --no-print-directory VFS_SELFTEST=1 VFS_MOUNT_UNGATED=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='VFSTEST: FAIL mounted-without-a-capability' \
		tools/smoke_test.sh boot.iso
	@echo "VFS MOUNT CONTROL: PASS - a prefix alone installs a mount"

# ---- The in-kernel ramfs is not reachable from ring 3 ----------------------
.PHONY: smoke-passwd-probe
smoke-passwd-probe:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PASSWD_PROBE=1
	@$(MAKE) --no-print-directory PASSWD_PROBE=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='PASSWDPROBE: PASS' \
		FAIL_MARKER='PASSWDPROBE: FAIL' \
		tools/smoke_test.sh boot.iso

# Control arm. RAMFS_SLOT3_GATE=1 restores the four slot-3 gates AND rebuilds the
# in-kernel ramfs they lead to (it is out of the ship build entirely since its
# last consumer was deleted); an ordinary uid-1000 task with no delegated
# capability then opens a seeded file, reads bytes out of it, creates a file and
# lists the store. The FAIL marker must be PRESENT.
# Control arm 2 for the same probe: the four legacy dispatch entries restored.
# The one that matters is SYS_EXEC_LEGACY -- under this flag the uid-1000 probe
# calls syscall 14 and is handed a task id, which is what it did on 2026-08-23
# against the tree as it then stood. The FAIL marker names that specific door,
# so an arm that reddened the probe for any other reason would not satisfy it.
.PHONY: smoke-passwd-probe-legacy-control
smoke-passwd-probe-legacy-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PASSWD_PROBE=1 LEGACY_SYSCALLS_PRESENT=1
	@$(MAKE) --no-print-directory PASSWD_PROBE=1 LEGACY_SYSCALLS_PRESENT=1 boot.iso
	@SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='PASSWDPROBE: FAIL legacy-exec-spawned-a-task' \
		tools/smoke_test.sh boot.iso

.PHONY: smoke-passwd-probe-control
smoke-passwd-probe-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory PASSWD_PROBE=1 RAMFS_SLOT3_GATE=1
	@$(MAKE) --no-print-directory PASSWD_PROBE=1 RAMFS_SLOT3_GATE=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='PASSWDPROBE: FAIL opened-a-ramfs-file' \
		tools/smoke_test.sh boot.iso
	@echo "PASSWD PROBE CONTROL: PASS - slot-3 gated, an ordinary user reads the store"

# ---- XMM register-file isolation (SECURITY.md S16) ------------------------
# Both halves in one target: fputest requires its own sentinel intact across 64
# switches, fpupeer requires never to see it. -smp 1 because the leak needs the
# two tasks to interleave on ONE physical register file; on separate cores they
# would not share one and the test would pass for the wrong reason.
.PHONY: smoke-fpu
smoke-fpu:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FPU_SELFTEST=1
	@$(MAKE) --no-print-directory FPU_SELFTEST=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FPUTEST: PASS no-xmm-leak' \
		FAIL_MARKER='FPUTEST: FAIL' \
		tools/smoke_test.sh boot.iso

# Control arm 1 -- the disclosure, and the one S16 is about. FPU_NO_RESTORE=1
# drops the fxrstor on the way back to ring 3, so a task inherits whatever the
# previously-running task left in the physical registers. The FAIL marker must be
# PRESENT.
.PHONY: smoke-fpu-leak-control
smoke-fpu-leak-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FPU_SELFTEST=1 FPU_NO_RESTORE=1
	@$(MAKE) --no-print-directory FPU_SELFTEST=1 FPU_NO_RESTORE=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FPUTEST: FAIL peer-saw-sentinel' \
		tools/smoke_test.sh boot.iso
	@echo "FPU LEAK CONTROL: PASS - unrestored, a task reads its predecessor's xmm"

# Control arm 2 -- the other half, which is loss rather than disclosure.
# FPU_NO_SAVE=1 never captures a task's registers, so it is handed a stale image
# on its next entry. Separable from arm 1 on purpose: one loses state, the other
# leaks it, and a single arm would have conflated them. The FAIL marker must be
# PRESENT.
.PHONY: smoke-fpu-save-control
smoke-fpu-save-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FPU_SELFTEST=1 FPU_NO_SAVE=1
	@$(MAKE) --no-print-directory FPU_SELFTEST=1 FPU_NO_SAVE=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FPUTEST: FAIL own-xmm-lost' \
		tools/smoke_test.sh boot.iso
	@echo "FPU SAVE CONTROL: PASS - unsaved, a task loses its own register file"

# ---- fork (roadmap 2.3) ---------------------------------------------------
# The base arm. forktest forks itself and asserts that the child's memory is a
# COPY of the parent's in both directions (S39), and that a task with a
# CAP_FRAME mapped is refused -- and that unmapping it makes the same call
# succeed, so the refusal is about the frame rather than about fork being broken
# (S40). -smp 1: the parent's post-fork write has to be in flight while the child
# is watching for it, and one CPU makes that ordering the scheduler's rather than
# the host's.
.PHONY: smoke-fork
smoke-fork:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FORK_SELFTEST=1
	@$(MAKE) --no-print-directory FORK_SELFTEST=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FORKTEST: PASS' \
		FAIL_MARKER='FORKTEST: FAIL' \
		tools/smoke_test.sh boot.iso

# Control arm 1 -- the copy. FORK_SHARE_WRITABLE=1 leaves both trees' leaves
# writable and unmarked, so parent and child share every page. The child's write
# to its own copy then lands in the parent's, and the parent reads it back.
# The FAIL marker must be PRESENT.
.PHONY: smoke-fork-share-control
smoke-fork-share-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FORK_SELFTEST=1 FORK_SHARE_WRITABLE=1
	@$(MAKE) --no-print-directory FORK_SELFTEST=1 FORK_SHARE_WRITABLE=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FORKTEST: FAIL parent-clobbered' \
		tools/smoke_test.sh boot.iso
	@echo "FORK SHARE CONTROL: PASS - unmarked, a fork shares its parent's pages"

# Control arm 2 -- the kernel object. FORK_ARENA_UNCHECKED=1 clones a PTE whose
# frame belongs to the untyped arena instead of refusing the fork, so a task with
# a CAP_FRAME mapped forks successfully and the child holds a mapping of an
# object no capability of its own names. The FAIL marker must be PRESENT.
.PHONY: smoke-fork-arena-control
smoke-fork-arena-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FORK_SELFTEST=1 FORK_ARENA_UNCHECKED=1
	@$(MAKE) --no-print-directory FORK_SELFTEST=1 FORK_ARENA_UNCHECKED=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FORKTEST: FAIL forked-with-frame-mapped' \
		tools/smoke_test.sh boot.iso
	@echo "FORK ARENA CONTROL: PASS - unchecked, a mapped kernel object is cloned"

# Control arm 3 -- the derivation. FORK_CSPACE_FLAT_COPY=1 copies the parent's
# capabilities verbatim, same serial and all, so two capabilities share one
# identity. The child's copy is then indistinguishable from the parent's, which
# forktest reads directly out of the derivation graph with SYS_CAP_ENUMERATE.
# The harm is revocation flowing sideways: the sweep nulls by serial across every
# cspace, so the child revoking its own slot would destroy the parent's.
# The FAIL marker must be PRESENT.
.PHONY: smoke-fork-cspace-flat-control
smoke-fork-cspace-flat-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FORK_SELFTEST=1 FORK_CSPACE_FLAT_COPY=1
	@$(MAKE) --no-print-directory FORK_SELFTEST=1 FORK_CSPACE_FLAT_COPY=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FORKTEST: FAIL child-cap-shares-serial' \
		tools/smoke_test.sh boot.iso
	@echo "FORK CSPACE FLAT CONTROL: PASS - copied verbatim, two caps share one serial"

# Control arm 4 -- the parent edge, and the one the whole change exists for.
# FORK_CSPACE_ORPHAN_COPY=1 gives each copy a fresh serial (so arm 3's defect is
# absent) but leaves `badge` as the source's, so the copy is not a CHILD of the
# parent's capability -- it is a second ROOT holding the parent's authority.
# Revoking the parent's then leaves the child's working: the revocation hole
# docs/LIMITATIONS.md 2.11 was opened to record. The FAIL marker must be PRESENT.
.PHONY: smoke-fork-cspace-orphan-control
smoke-fork-cspace-orphan-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FORK_SELFTEST=1 FORK_CSPACE_ORPHAN_COPY=1
	@$(MAKE) --no-print-directory FORK_SELFTEST=1 FORK_CSPACE_ORPHAN_COPY=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FORKTEST: FAIL child-cap-not-derived' \
		tools/smoke_test.sh boot.iso
	@echo "FORK CSPACE ORPHAN CONTROL: PASS - fresh serial, no parent edge, revoke misses it"

# ---- fork + exec, the pairing (roadmap 2.3) -------------------------------
# The base arm. forkexectest forks itself, lets the child replace its image with
# forkexecee through SYS_EXEC_NAMED, and then asserts that the exec replaced the
# IMAGE and not the AUTHORITY: the inherited capability is still there, still
# works, still carries the same serial and badge, and the driver's revoke still
# reaches it three generations down (S42). It also re-reads its own page, which
# the child wrote to and then execed away from -- the exec RECLAIMS the cloned
# address space, and nothing else in the tree frees a cloned space while its
# parent is still running (S39, one layer on from smoke-fork).
# -smp 1 for smoke-fork's reason: the rendezvous is the scheduler's, not the
# host's.
.PHONY: smoke-forkexec
smoke-forkexec:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FORKEXEC_SELFTEST=1
	@$(MAKE) --no-print-directory FORKEXEC_SELFTEST=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FORKEXECTEST: PASS' \
		FAIL_MARKER='FORKEXECTEST: FAIL' \
		tools/smoke_test.sh boot.iso

# Control arm 1 -- the exec discards. EXEC_RESET_CSPACE=1 nulls every capability
# above the birth endowment, so the execed image arrives holding nothing it was
# given. The FAIL marker must be PRESENT.
.PHONY: smoke-forkexec-reset-control
smoke-forkexec-reset-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FORKEXEC_SELFTEST=1 EXEC_RESET_CSPACE=1
	@$(MAKE) --no-print-directory FORKEXEC_SELFTEST=1 EXEC_RESET_CSPACE=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FORKEXECTEST: FAIL exec-dropped-inherited-cap' \
		tools/smoke_test.sh boot.iso
	@echo "FORKEXEC RESET CONTROL: PASS - a clean slate loses what the task was given"

# Control arm 2 -- the exec launders, and the one the property exists for.
# EXEC_ROOT_CSPACE=1 keeps every capability but re-mints it as a root: same
# authority, no lineage. The task can still do everything it could before, which
# is why nothing but the derivation graph can see it -- and the driver's revoke
# no longer reaches the child's copy. The FAIL marker must be PRESENT.
.PHONY: smoke-forkexec-root-control
smoke-forkexec-root-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FORKEXEC_SELFTEST=1 EXEC_ROOT_CSPACE=1
	@$(MAKE) --no-print-directory FORKEXEC_SELFTEST=1 EXEC_ROOT_CSPACE=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FORKEXECTEST: FAIL child-cap-survived-revoke-after-exec' \
		tools/smoke_test.sh boot.iso
	@echo "FORKEXEC ROOT CONTROL: PASS - re-minted as a root, the parent's revoke misses it"

.PHONY: smoke-frame
smoke-frame:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FRAMETEST: PASS' \
		FAIL_MARKER='FRAMETEST: FAIL' \
		tools/smoke_test.sh boot.iso

# Control arm 1 -- the index bound. FRAME_INDEX_UNCHECKED=1 makes
# CAP_FRAME.object a physical address that is mapped directly, which is the
# shortcut a frame-mapping syscall invites. It is reachable from a capability the
# kernel hands out itself: every task is born holding a CAP_FRAME in slot 3 whose
# object is USER_AREA_BASE, so under this arm any task maps physical 0x400000
# into ring 3. The FAIL marker must be PRESENT.
.PHONY: smoke-frame-index-control
smoke-frame-index-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_INDEX_UNCHECKED=1
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_INDEX_UNCHECKED=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FRAMETEST: FAIL legacy-cap-mapped' \
		tools/smoke_test.sh boot.iso
	@echo "FRAME INDEX CONTROL: PASS - unchecked, the legacy slot-3 CAP_FRAME maps"

# Control arm 2 -- the rights floor. FRAME_RIGHTS_UNCHECKED=1 asks cap_lookup for
# no rights at all, so any live CAP_FRAME satisfies it and the PTE is built from
# the request: a READ-only delegate obtains a writable mapping and its write
# lands. Aimed at the FLOOR rather than at the `have & want` intersection on
# purpose -- given the floor the intersection is arithmetically redundant, so an
# arm against it could not fail, and a control arm that cannot fail measures
# nothing. The FAIL marker must be PRESENT.
.PHONY: smoke-frame-rights-control
smoke-frame-rights-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_RIGHTS_UNCHECKED=1
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_RIGHTS_UNCHECKED=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FRAMETEST: FAIL readonly-delegate-wrote' \
		tools/smoke_test.sh boot.iso
	@echo "FRAME RIGHTS CONTROL: PASS - unchecked, a READ-only delegate writes"

# Control arm 3 -- the partial-failure policy. FRAME_REGION_NO_ROLLBACK=1 drops
# the unwind from SYS_MAP_REGION, so a run that fails part-way keeps the pages it
# had already mapped: the caller is told the region was not mapped and holds two
# pages of it. frametest maps a blocker in the MIDDLE of a four-page run, so the
# failure is at page 2 and pages 0 and 1 are the ones left behind; it then probes
# them by mapping over them, which is refused when they are still present.
# The FAIL marker must be PRESENT.
.PHONY: smoke-frame-region-control
smoke-frame-region-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_REGION_NO_ROLLBACK=1
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_REGION_NO_ROLLBACK=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FRAMETEST: FAIL region-rollback-page0' \
		tools/smoke_test.sh boot.iso
	@echo "FRAME REGION CONTROL: PASS - without the unwind, a failed region keeps its pages"

# Control arm 4 -- the same policy from the other side. FRAME_REGION_ROLLBACK_WIDE=1
# unwinds the whole REQUESTED range rather than the pages the call installed, so
# the pre-existing mapping that caused the refusal is torn down by the cleanup.
# frametest maps the blocker from the run's OWN page-2 frame precisely so this
# arm can reach it: against an unrelated frame, user_unmap_frame_page's
# expect_phys test would refuse the wide unmap by itself and the arm could not
# fail. The FAIL marker must be PRESENT.
.PHONY: smoke-frame-region-wide-control
smoke-frame-region-wide-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_REGION_ROLLBACK_WIDE=1
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_REGION_ROLLBACK_WIDE=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FRAMETEST: FAIL region-rollback-ate-blocker' \
		tools/smoke_test.sh boot.iso
	@echo "FRAME REGION WIDE CONTROL: PASS - a whole-range unwind eats the mapping that refused it"

# Control arm 5 -- the length a frame carries. FRAME_PAGES_SAME_PHYS=1 advances
# the virtual cursor without the physical one, so every page of a sized frame
# aliases the first. frametest writes a distinct word per page and reads them
# all back, which is the only way to tell a real run from an aliased one: both
# map, both are writable, and only one of them stores what you wrote.
# The FAIL marker must be PRESENT.
.PHONY: smoke-frame-pages-control
smoke-frame-pages-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_PAGES_SAME_PHYS=1
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_PAGES_SAME_PHYS=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FRAMETEST: FAIL sized-pages-distinct' \
		tools/smoke_test.sh boot.iso
	@echo "FRAME PAGES CONTROL: PASS - a sized frame whose pages all alias page 0"

# Control arm 6 -- SYS_FRAME_PAGES' authority. FRAME_INFO_BY_INDEX=1 reads the
# argument as a frame index rather than a cspace slot, so framepeer -- which
# holds exactly one delegated CAP_FRAME and nothing else -- gets answers about
# frames it holds no capability to. Slots 1 and 2 are empty in that task while
# frame indices 1 and 2 are live, which is what makes the two indistinguishable
# to a handler that confuses them. The FAIL marker must be PRESENT.
.PHONY: smoke-frame-info-control
smoke-frame-info-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_INFO_BY_INDEX=1
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 FRAME_INFO_BY_INDEX=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FRAMETEST: FAIL peer-frame-pages-not-an-index' \
		tools/smoke_test.sh boot.iso
	@echo "FRAME INFO CONTROL: PASS - a delegate reads frames it holds no capability to"

# SYS_DMA_ADDR's second capability. The call answers with a physical address, and
# it is gated on a device capability as well as the frame -- because a holder of a
# bus-mastering device already reaches all of memory, so the disclosure adds
# nothing to THAT caller, while handing it to anyone who retyped a page gives out
# the kernel's layout for no purpose they could act on. frametest is the witness:
# it holds frames and no device capability at all.
.PHONY: smoke-frame-dma-control
smoke-frame-dma-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 DMA_ADDR_FRAME_ONLY=1
	@$(MAKE) --no-print-directory FRAME_SELFTEST=1 DMA_ADDR_FRAME_ONLY=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='FRAMETEST: FAIL dma-addr-without-device-cap' \
		tools/smoke_test.sh boot.iso
	@echo "FRAME DMA CONTROL: PASS - a task with no device capability learns a bus address"

.PHONY: smoke-libhorus
smoke-libhorus:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory LIBHORUS_SELFTEST=1
	@$(MAKE) --no-print-directory LIBHORUS_SELFTEST=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='LIBHORUS_SELFTEST: PASS' \
		FAIL_MARKER='LIBHORUS_SELFTEST: FAIL' \
		tools/smoke_test.sh boot.iso

# Control arm 1 -- the security one. LIBHORUS_RETRY_ANY=1 restores the loop that
# retries EVERY negative rc, so the selftest's call against an empty capability
# slot never returns and the PASS marker never appears.
#
# The assertion is the marker's ABSENCE, and it has to be: a test for a hang has
# nothing to compare, because the code under test does not come back to be
# compared. Same shape as smoke-kfault-legacy. Without this arm, smoke-libhorus
# would pass identically against a library that spins on every refusal -- which
# is precisely the defect it exists to reject.
.PHONY: smoke-libhorus-retry-control
smoke-libhorus-retry-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory LIBHORUS_SELFTEST=1 LIBHORUS_RETRY_ANY=1
	@$(MAKE) --no-print-directory LIBHORUS_SELFTEST=1 LIBHORUS_RETRY_ANY=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='LIBHORUS_SELFTEST: calling an empty slot' \
		FAIL_MARKER='LIBHORUS_SELFTEST: PASS' \
		tools/smoke_test.sh boot.iso

# Control arm 2 -- the termination guarantee. LIBHORUS_STRNCPY_UNTERMINATED=1
# restores C strncpy's semantics, so the truncating copy leaves no NUL and the
# selftest reports strncpy-truncate-unterminated. Here the FAIL marker must be
# PRESENT: the defect is detectable rather than fatal, so this arm asserts the
# check fires rather than that the boot dies.
.PHONY: smoke-libhorus-strncpy-control
smoke-libhorus-strncpy-control:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory LIBHORUS_SELFTEST=1 LIBHORUS_STRNCPY_UNTERMINATED=1
	@$(MAKE) --no-print-directory LIBHORUS_SELFTEST=1 LIBHORUS_STRNCPY_UNTERMINATED=1 boot.iso
	@SMP_CPUS=1 SMOKE_TIMEOUT=$(SMOKE_TIMEOUT) MARKER_ONLY=1 \
		REQUIRE_MARKER='LIBHORUS_SELFTEST: FAIL strncpy-truncate-unterminated' \
		FAIL_MARKER='LIBHORUS_SELFTEST: PASS' \
		tools/smoke_test.sh boot.iso

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

# ---- reproducible builds -------------------------------------------------
#
# The artifacts a reproducible build must cover. boot.iso is on this list
# because it is the artifact a third party actually obtains; until 2026-08-19
# the recording step silently settled for kernel.elf alone (see
# tools/record_build_sha.sh for how three mechanisms conspired to keep that
# quiet, and TESTS.md for the gate that now refuses it).
REPRO_ARTIFACTS := kernel.elf boot.iso

# The epoch is pinned rather than taken from the environment: a build whose
# timestamps depend on when it ran cannot be compared to one that ran later,
# which is the whole exercise.
REPRO_EPOCH := 1609459200

ifeq ($(REPRO_SHA_UNCHECKED),1)
# CONTROL ARM -- restores the pre-2026-08-19 behaviour, and it takes BOTH
# halves to reproduce the defect. Recording with a swallowed status is harmless
# while every artifact exists; what made it silent is that the goal list did not
# build boot.iso, so the sha256sum it hid was always a failing one. Restore only
# the `|| true` and the arm passes for the wrong reason.
REPRO_GOALS  := all
REPRO_RECORD := sha256sum $(REPRO_ARTIFACTS) > .build.sha 2>/dev/null || true
else
REPRO_GOALS  := all boot.iso
REPRO_RECORD := $(CURDIR)/tools/record_build_sha.sh $(REPRO_ARTIFACTS)
endif

.PHONY: reproducible-build verify-build
reproducible-build:
	@rm -f $(REPRO_ARTIFACTS) .build.sha
# `clean` is a separate invocation from the build goals on purpose: as one
# goal list under -j they are free to run concurrently, and a clean racing a
# compile is a build that reports whatever it happens to finish with.
	@SOURCE_DATE_EPOCH=$(REPRO_EPOCH) $(MAKE) --no-print-directory clean
	@SOURCE_DATE_EPOCH=$(REPRO_EPOCH) $(MAKE) --no-print-directory $(REPRO_GOALS)
	@$(REPRO_RECORD)
	@echo "Reproducible build recorded: $(REPRO_ARTIFACTS)"

verify-build: reproducible-build
	@echo "Verify complete."

# The gate on the recording step itself. Host-side and sub-second: it exercises
# $(REPRO_RECORD) in the exact form `reproducible-build` invokes it, against a
# scratch directory rather than a real build, because what is under test is the
# step's behaviour when an artifact is absent -- not the compiler.
#
# Both directions, deliberately. An incomplete build must be refused AND a
# complete one must be recorded: a recording step that refused everything would
# pass a one-directional test while making the target permanently red.
.PHONY: smoke-repro-sha
smoke-repro-sha:
	@rm -rf .repro-sha-test && mkdir -p .repro-sha-test
	@: > .repro-sha-test/kernel.elf
	@cd .repro-sha-test && if $(REPRO_RECORD) >record.log 2>&1; then 	    echo "REPRO_SHA: FAIL recorded-a-build-missing-$(word 2,$(REPRO_ARTIFACTS))"; 	    exit 1; 	 elif [ -e .build.sha ]; then 	    echo "REPRO_SHA: FAIL partial-record-left-behind"; 	    exit 1; 	 else 	    echo "REPRO_SHA: PASS refused an incomplete build, wrote nothing"; 	 fi
	@: > .repro-sha-test/boot.iso
	@cd .repro-sha-test && if $(REPRO_RECORD) >>record.log 2>&1; then 	    n=$$(wc -l < .build.sha); 	    if [ "$$n" -ne $(words $(REPRO_ARTIFACTS)) ]; then 	        echo "REPRO_SHA: FAIL recorded $$n of $(words $(REPRO_ARTIFACTS)) artifacts"; exit 1; 	    fi; 	    for a in $(REPRO_ARTIFACTS); do 	        grep -q " $$a$$" .build.sha || { echo "REPRO_SHA: FAIL $$a not recorded"; exit 1; }; 	    done; 	    echo "REPRO_SHA: PASS recorded $$n artifacts, $(REPRO_ARTIFACTS)"; 	 else 	    echo "REPRO_SHA: FAIL refused a complete build"; 	    cat record.log; exit 1; 	 fi
	@rm -rf .repro-sha-test

# The load-bearing arm. Without it, smoke-repro-sha is consistent with a
# recording step that was never reached.
.PHONY: smoke-repro-sha-control repro-sha-control-arm
smoke-repro-sha-control:
	@$(MAKE) --no-print-directory REPRO_SHA_UNCHECKED=1 repro-sha-control-arm

# Not named smoke-*: it is how smoke-repro-sha-control re-enters make with the
# flag set, not a gate of its own, and every count in the docs is derived by
# grepping for ^smoke-.
repro-sha-control-arm:
	@rm -rf .repro-sha-test && mkdir -p .repro-sha-test
	@: > .repro-sha-test/kernel.elf
	@cd .repro-sha-test && if $(REPRO_RECORD); then 	    n=$$(wc -l < .build.sha 2>/dev/null || echo 0); 	    echo "REPRO_SHA_CONTROL: FAIL recorded $$n of $(words $(REPRO_ARTIFACTS)) artifacts and reported success"; 	 else 	    echo "REPRO_SHA_CONTROL: the control arm REFUSED -- it no longer reproduces the defect"; 	    exit 1; 	 fi
	@rm -rf .repro-sha-test

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
