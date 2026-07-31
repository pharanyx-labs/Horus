#!/bin/sh
# Fetch and build the x86_64-elf newlib that the libc port links against.
#
# newlib/ is gitignored: it is an upstream dependency, not project source, so a
# fresh checkout -- CI included -- has no libc.a and `make smoke-newlib` cannot
# link. This script is that missing step. It is idempotent: once libc.a is in
# place it exits immediately, so an existing local tree is never rebuilt or
# clobbered.
#
# There is no real x86_64-elf cross-compiler in play. newlib/tools/ holds thin
# wrappers that aim the target toolchain at the host gcc in 64-bit freestanding
# mode, which is all a freestanding libc needs. Keep the wrapper flags in sync
# with USERSPACE_CFLAGS in the Makefile: objects built here get linked directly
# against objects built with those flags. -mno-red-zone matches the kernel and
# the userspace build: the red zone is not safe across an interrupt frame.

set -eu

NEWLIB_VERSION=4.5.0.20241231
NEWLIB_SHA256=33f12605e0054965996c25c1382b3e463b0af91799001f5bb8c0630f2ec8c852
NEWLIB_URL=https://sourceware.org/pub/newlib/newlib-${NEWLIB_VERSION}.tar.gz

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NEWLIB_DIR=$ROOT/newlib
PREFIX=$NEWLIB_DIR/install
SRC=$NEWLIB_DIR/src
BUILD=$NEWLIB_DIR/build
TOOLS=$NEWLIB_DIR/tools
TARBALL=$NEWLIB_DIR/newlib-${NEWLIB_VERSION}.tar.gz

if [ -f "$PREFIX/x86_64-elf/lib/libc.a" ]; then
	echo "newlib: $PREFIX/x86_64-elf/lib/libc.a already built, nothing to do"
	exit 0
fi

mkdir -p "$NEWLIB_DIR"

# Fetch and verify. The checksum is pinned: this is a network dependency in a
# repo that otherwise pins every action by SHA, so it gets the same treatment.
#
# --retry-all-errors is load-bearing, not belt-and-braces. Plain `--retry N`
# retries only what curl calls a TRANSIENT error: a timeout, an FTP 4xx, or an
# HTTP 408/429/500/502/503/504. A connection that dies mid-body is CURLE_RECV_ERROR
# (exit 56), which is NOT in that set -- so `--retry 3` alone never fired for it,
# and a single dropped read reddened CI with a build failure that had nothing to
# do with the tree. That is exactly what happened on PR #116. --retry-all-errors
# widens the retry to any failure; -C - resumes the partial transfer rather than
# restarting a 9 MiB download from zero.
#
# Resuming into a partial file is only safe BECAUSE the checksum below is
# unconditional: a resumed-but-corrupt tarball cannot reach the build, it can
# only fail verification. Verification runs on every invocation, not just after a
# fetch, so a tarball that arrived by any means -- resumed, cached, or dropped in
# by hand -- is checked before it is trusted.
if [ ! -f "$TARBALL" ]; then
	echo "newlib: fetching $NEWLIB_URL"
	curl -sfL --retry 5 --retry-delay 3 --retry-all-errors \
	     --connect-timeout 30 --max-time 900 -C - -o "$TARBALL.tmp" "$NEWLIB_URL" || {
		echo "newlib: fetch failed (curl exit $?) -- leaving the partial file for resume" >&2
		exit 1
	}
	mv "$TARBALL.tmp" "$TARBALL"
fi

# Fail closed, and fail CLEAN. Quarantining the rejected artifact matters: the
# fetch above is skipped whenever $TARBALL exists, so leaving a bad tarball in
# place wedges the tree -- every subsequent build re-reads the same bad bytes and
# fails identically, with no path back other than a manual rm. Moving it aside
# lets the next run re-fetch, while still keeping the evidence for inspection and
# still refusing to build from it now.
echo "newlib: verifying tarball checksum"
if ! echo "$NEWLIB_SHA256  $TARBALL" | sha256sum -c - >/dev/null 2>&1; then
	got=$(sha256sum "$TARBALL" 2>/dev/null | cut -d' ' -f1)
	mv -f "$TARBALL" "$TARBALL.rejected" 2>/dev/null || true
	echo "newlib: CHECKSUM MISMATCH -- refusing to build" >&2
	echo "newlib: expected $NEWLIB_SHA256" >&2
	echo "newlib: got      ${got:-<unreadable>}" >&2
	echo "newlib: quarantined the rejected artifact at $TARBALL.rejected" >&2
	echo "newlib: a re-run will re-fetch; if it mismatches again, do NOT bypass this --" >&2
	echo "newlib: either upstream changed the artifact or the download is being tampered with." >&2
	exit 1
fi
echo "newlib: checksum OK ($NEWLIB_SHA256)"

if [ ! -f "$SRC/configure" ]; then
	echo "newlib: extracting"
	rm -rf "$SRC"
	mkdir -p "$SRC"
	tar xzf "$TARBALL" -C "$SRC" --strip-components=1
fi

# Target-toolchain wrappers. configure looks these up on PATH by target triple.
echo "newlib: writing x86_64-elf toolchain wrappers"
mkdir -p "$TOOLS"
for tool in gcc cc; do
	cat >"$TOOLS/x86_64-elf-$tool" <<'EOF'
#!/bin/sh
exec gcc -m64 -ffreestanding -fno-stack-protector -fno-builtin -mno-red-zone "$@"
EOF
done
for tool in ar ranlib strip; do
	cat >"$TOOLS/x86_64-elf-$tool" <<EOF
#!/bin/sh
exec $tool "\$@"
EOF
done
chmod +x "$TOOLS"/x86_64-elf-*

PATH=$TOOLS:$PATH
export PATH

if [ ! -f "$BUILD/Makefile" ]; then
	echo "newlib: configuring"
	mkdir -p "$BUILD"
	cd "$BUILD"
	"$SRC/configure" \
		--target=x86_64-elf \
		--prefix="$PREFIX" \
		--disable-multilib \
		--disable-newlib-supplied-syscalls \
		--enable-newlib-reent-small \
		--enable-newlib-io-c99-formats
fi

# Build the newlib target only, never the full tree. libgloss is board-support
# syscall glue for real boards; this port supplies its own via
# newlib_glue.c/posix.c (hence --disable-newlib-supplied-syscalls), so it is
# dead weight here -- and it does not survive gcc >= 14, which promoted
# implicit-int/implicit-function-declaration to errors that its K&R-era sources
# trip on immediately. all-target-newlib yields libc.a/libg.a/libm.a, which is
# exactly what userspace/hello_newlib.pie.elf links against.
echo "newlib: building"
cd "$BUILD"
make -j"$(nproc 2>/dev/null || echo 2)" all-target-newlib

# stdio64.o has to be added by hand, and this is the subtle part.
#
# The x86_64-elf-gcc wrapper is really the host gcc, so it defines __linux__.
# newlib's libc/include/sys/config.h keys __LARGE64_FILES off __linux__, so a
# bare-metal target quietly takes the Linux branch and stdio's findfp.c emits
# references to __swrite64/__sseek64. Those live in libc/stdio64/stdio64.c --
# but configure.host leaves stdio64_dir empty for every target upstream, so the
# directory is never built and the archive ends up one object short of linking.
#
# Building the whole directory is not an option: its other members (fseeko64.c
# et al.) need a struct stat64 that this target's headers do not define, and
# they fail to compile. stdio64.c alone builds cleanly, and it is the only
# member anything references -- userspace/newlib_glue64.c exists precisely to
# supply its _lseek64_r/_fstat64_r hooks, so the port already assumes this
# object is present.
# stdio64.c pulls in "local.h" from libc/stdio, which is not on the include
# path automake generates for the stdio64 directory (it never expects to build
# it). CPPFLAGS is the one slot the generated rule leaves open, so inject it there.
echo "newlib: building stdio64.o (see comment: __linux__ leak via the gcc wrapper)"
make -C x86_64-elf/newlib libc/stdio64/libc_a-stdio64.o \
	CPPFLAGS="-I$SRC/newlib/libc/stdio"
ar rs x86_64-elf/newlib/libc.a x86_64-elf/newlib/libc/stdio64/libc_a-stdio64.o

make install-target-newlib

test -f "$PREFIX/x86_64-elf/lib/libc.a" || {
	echo "newlib: build finished but $PREFIX/x86_64-elf/lib/libc.a is missing" >&2
	exit 1
}
echo "newlib: built $PREFIX/x86_64-elf/lib/libc.a"
