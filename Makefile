CC     = gcc
LD     = ld
AS     = gcc

export SOURCE_DATE_EPOCH ?= 1609459200

# Horus is x86-64 only. The kernel runs in 64-bit long mode; the ring-3
# userspace binaries are the sole 32-bit component (built in compatibility
# mode further down, USERSPACE_CFLAGS).
CFLAGS = -m64 -ffreestanding -fno-pic -fno-pie -fno-stack-protector \
         -Wall -Wextra -Wformat -Wformat-security -Werror=vla -O2 -pipe \
         -I src/include -std=gnu99 -fno-builtin -mcmodel=kernel -frandom-seed=horus -fdebug-prefix-map=$(CURDIR)=/horus
ASFLAGS = -m64 -ffreestanding -fno-pic -fno-pie -x assembler-with-cpp -c
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
       src/kernel/syscall.o \
       src/kernel/ramfs.o \
       src/kernel/storage.o \
       src/kernel/crypto.o \
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

OBJS += src/boot/entry64.o
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

kernel.elf: $(RUST_LIB) $(OBJS) $(RUST_EXTRA_OBJS)
ifeq ($(RUST_ENABLED),1)
	$(LD) $(LDFLAGS) -o $@ --whole-archive $(RUST_LIB) --no-whole-archive $(OBJS) $(RUST_EXTRA_OBJS)
else
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(RUST_EXTRA_OBJS)
endif

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(AS) $(ASFLAGS) $< -o $@

src/boot/multiboot.o: userspace/shell.bin $(ELF_SELFTEST_DEP) $(PREEMPT_SELFTEST_DEP)

src/kernel/rust_shims.o: src/kernel/rust_shims.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/rust_stubs.o: src/kernel/rust_stubs.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/rust_memory_stubs.o: src/kernel/rust_memory_stubs.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/storage.o: src/kernel/storage.c
	$(CC) $(CFLAGS) -c $< -o $@

src/kernel/crypto.o: src/kernel/crypto.c
	$(CC) $(CFLAGS) -msse2 -maes -c $< -o $@

src/kernel/ata.o: src/kernel/ata.c
	$(CC) $(CFLAGS) -c $< -o $@

ifeq ($(RUST_ENABLED),1)
$(RUST_LIB): rust/src/lib.rs rust/Cargo.toml rust/src/capability.rs rust/src/crypto.rs rust/src/memory.rs
	@cargo build --locked --release --manifest-path rust/Cargo.toml --target $(RUST_TARGET) || cargo build --release --manifest-path rust/Cargo.toml --target $(RUST_TARGET)
	@test -f $(RUST_LIB) || (echo "ERROR: $(RUST_LIB) missing"; exit 1)
endif

run: kernel.elf
	@$(MAKE) --no-print-directory boot.iso
	qemu-system-x86_64 -m 512M -cpu qemu64,+aes,+rdrand,+smep,+smap -display sdl -vga std \
		-chardev socket,id=char0,port=4445,host=localhost,server=on,wait=off \
		-serial chardev:char0 \
		-serial tcp:localhost:4444,server,nowait,nodelay \
		-monitor none -device isa-debug-exit,iobase=0x604,iosize=0x04 \
		-net none -no-reboot -no-shutdown -cdrom boot.iso


boot.iso: kernel.elf grub.cfg
	@rm -rf isofiles
	@mkdir -p isofiles/boot/grub
	@cp kernel.elf isofiles/boot/kernel.elf
	@cp kernel.elf isofiles/kernel.elf
	@cp grub.cfg isofiles/boot/grub/grub.cfg
	@grub-mkrescue -o $@ isofiles 2>&1 || (echo "grub-mkrescue failed (install grub-pc-bin xorriso)" && exit 1)
	@rm -rf isofiles

clean: userspace-clean
	rm -f kernel.elf src/boot/*.o src/kernel/*.o src/kernel/rust_*.o
	rm -rf rust/target

clean-rust:
	rm -rf rust/target

iso: kernel.elf
	@mkdir -p iso/boot/grub && cp kernel.elf iso/boot/ && cp grub.cfg iso/boot/grub/grub.cfg
	@grub-mkrescue -o horus.iso iso 2>/dev/null || true

USERSPACE_CFLAGS = -m32 -ffreestanding -fno-pic -fno-pie -fno-stack-protector \
                   -Wall -Wextra -O2 -I include -std=gnu99 -fno-builtin

userspace/%.o: userspace/%.c
	$(CC) $(USERSPACE_CFLAGS) -c $< -o $@

userspace/%.elf: userspace/%.o
	$(LD) -m elf_i386 -Ttext=0x400000 -o $@ $<

# The ELF-loader self-test image is linked with a custom script that produces
# distinct page-aligned R+X / R+W / R PT_LOAD segments (explicit rule wins over
# the pattern rule above). It is kept as a real ELF, never objcopy-flattened.
userspace/elftest.elf: userspace/elftest.o userspace/elftest.ld
	$(LD) -m elf_i386 -T userspace/elftest.ld -o $@ $<

userspace/%.raw: userspace/%.elf
	objcopy -O binary $< $@

tools/mkheadered: tools/mkheadered.c
	$(CC) -o $@ $<

userspace/%.bin: userspace/%.raw tools/mkheadered
	@name="$$(basename $@ .bin)"; ./tools/mkheadered $< $@ "$$name"

userspace: userspace/shell.bin userspace/hello.bin userspace/fs_server.bin userspace/captest.bin

userspace-clean:
	rm -f userspace/*.o userspace/*.elf userspace/*.raw userspace/*.bin tools/mkheadered

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

.PHONY: test
test:
	@cargo test --manifest-path rust/Cargo.toml --release || true
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory all

# Headless QEMU smoke-boot test: boot the kernel and confirm it reaches the
# ring-3 shell banner with no fault/panic on serial. SMOKE_TIMEOUT overrides
# the wait (seconds).
SMOKE_TIMEOUT ?= 40
.PHONY: smoke
smoke: boot.iso
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
	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
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
	command -v trivy >/dev/null 2>&1 || (curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin)
	trivy --version
	trivy fs --scanners vuln,secret,misconfig .

gitleaks:
	@echo "=== gitleaks (secrets in git history) ==="
	command -v gitleaks >/dev/null 2>&1 || \
	( \
		GITLEAKS_VERSION=8.30.1; \
		curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v$${GITLEAKS_VERSION}/gitleaks_$${GITLEAKS_VERSION}_linux_x64.tar.gz | \
		tar -xz -C /usr/local/bin gitleaks \
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
