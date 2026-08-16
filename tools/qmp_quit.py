#!/usr/bin/env python3
"""Ask a running QEMU to exit, over its QMP monitor socket.

Finding [I-11]: the two-boot journal test ended boot 1 by SIGKILLing QEMU the
instant a marker appeared on serial. That made "the guest finished" a string
match rather than a process exit, so a genuine WAL regression and a harness that
shot QEMU a moment early produced byte-identical output — a gate that cannot
distinguish the defect it exists to catch from its own flakiness.

Roadmap 1.55 proposed having the guest end itself through `isa-debug-exit`. That
does not work: on QEMU 10.0.11 a byte write to port 0x604 does not terminate the
process (measured with and without -no-shutdown), and the `lidt 0x0; int $0x0`
triple-fault fallback faults while *reading* the descriptor at address 0, so the
kernel's own handler catches it and prints a PAGE FAULT the harness correctly
fails on. Both were tried and reverted.

QMP works. `quit` shuts QEMU down cleanly — it closes its block backends rather
than being shot holding them — and exits 0, which the harness can wait on.

Exits non-zero on any failure so the caller can fail closed; a silent no-op here
would put the harness straight back to timing out on a guest it never asked to
leave.

Usage: tools/qmp_quit.py <socket-path> [timeout-seconds]
"""
import json
import socket
import sys
import time


def main():
    if len(sys.argv) < 2:
        print("usage: qmp_quit.py <socket-path> [timeout]", file=sys.stderr)
        return 2
    path = sys.argv[1]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0

    # The socket appears asynchronously after QEMU starts, so wait for it rather
    # than racing startup.
    deadline = time.time() + timeout
    sock = None
    while time.time() < deadline:
        try:
            sock = socket.socket(socket.AF_UNIX)
            sock.settimeout(timeout)
            sock.connect(path)
            break
        except (FileNotFoundError, ConnectionRefusedError, OSError):
            sock = None
            time.sleep(0.1)
    if sock is None:
        print(f"qmp_quit: could not connect to {path} within {timeout}s", file=sys.stderr)
        return 1

    try:
        f = sock.makefile("rw")
        greeting = f.readline()
        if '"QMP"' not in greeting:
            print(f"qmp_quit: unexpected greeting: {greeting.strip()[:120]}", file=sys.stderr)
            return 1
        # QMP refuses commands until capabilities are negotiated.
        f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n")
        f.flush()
        if '"return"' not in f.readline():
            print("qmp_quit: capabilities handshake failed", file=sys.stderr)
            return 1
        f.write(json.dumps({"execute": "quit"}) + "\n")
        f.flush()
        # QEMU may close the connection before replying to `quit`; that is
        # success, not an error, so a dropped read here is not fatal.
        try:
            f.readline()
        except OSError:
            pass
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
