#!/usr/bin/env python3
"""Press the keys a layout disagrees about, and check the CHARACTERS produced.

WHY THIS IS NOT smoke-keyboard. That gate types a login and proves the keyboard
path works end to end -- 8042, IRQ, ring-3 poll, translate, echo. It says nothing
about WHICH character a key produces, because every letter it types is the same
on every layout. The defect this gate exists for is entirely in that difference:
on an ISO keyboard the key carrying `\\` and `|` is scancode 0x56, which the
reader dropped before any lookup, and four more keys came back as their US
counterparts. Reported from an IdeaPad 1 14IGL05 (UK) as "I cannot type | into
the shell" -- which the shell supports, it runs pipelines.

SO THE ASSERTION IS THE CHARACTER, one per key, compared against the layout the
build was asked for. Keys that agree across layouts are not worth pressing here;
these seven are exactly the ones that do not.

ADDING A LAYOUT IS ADDING A ROW to EXPECT below, which is the same bargain
include/ps2_scancode.h makes: a keyboard is data.

Input is driven through QEMU's emulated 8042 over QMP `send-key`, never at COM1.
A serial byte runs no part of the translation this is testing.
"""
import argparse, json, os, socket, subprocess, sys, time

# qcode -> what each layout must produce. "" means the key produces nothing,
# which is a real answer: UK Shift+3 is a pound sign and this console is ASCII.
KEYS = [
    (["less"],                 "ISO 102nd key (0x56)"),
    (["shift", "less"],        "Shift+ISO 102nd key"),
    (["backslash"],            "0x2B, left of Enter"),
    (["shift", "backslash"],   "Shift+0x2B"),
    (["shift", "2"],           "Shift+2"),
    (["shift", "apostrophe"],  "Shift+apostrophe"),
    (["shift", "3"],           "Shift+3"),
]
EXPECT = {
    "us": ["",   "",  "\\", "|", "@", '"', "#"],
    "uk": ["\\", "|", "#",  "~", '"', "@", ""],
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso", required=True)
    ap.add_argument("--layout", required=True, choices=sorted(EXPECT))
    ap.add_argument("--boot-timeout", type=int, default=90)
    ap.add_argument("--expect-ignored", action="store_true",
                    help="the arm: the build asked for --layout but must behave as 'us'")
    ap.add_argument("--log", default="/tmp/horus-keymap-evidence.log")
    a = ap.parse_args()

    want = EXPECT["us"] if a.expect_ignored else EXPECT[a.layout]
    qs = "/tmp/horus-keymap-qmp.sock"
    if os.path.exists(qs):
        os.unlink(qs)
    if os.path.exists(a.log):
        os.unlink(a.log)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(qs)
    srv.listen(1)
    qemu = subprocess.Popen(
        ["qemu-system-x86_64", "-m", "512M", "-smp", "2", "-display", "none",
         "-qmp", f"unix:{qs}", "-net", "none", "-no-reboot", "-no-shutdown",
         "-serial", f"file:{a.log}", "-cdrom", a.iso],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    srv.settimeout(a.boot_timeout)
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        qemu.kill()
        print("KEYMAP: FAIL QEMU never opened the QMP socket")
        return 1
    f = conn.makefile("rw")

    def qmp(**kw):
        f.write(json.dumps(kw) + "\n")
        f.flush()
        while True:
            line = f.readline()
            if not line:
                return None
            m = json.loads(line)
            if "return" in m or "error" in m:
                return m

    f.readline()
    qmp(execute="qmp_capabilities")

    def log():
        return open(a.log, "rb").read().decode("utf8", "replace") if os.path.exists(a.log) else ""

    end = time.time() + a.boot_timeout
    while time.time() < end and "horus login:" not in log():
        time.sleep(0.4)
    if "horus login:" not in log():
        qemu.kill()
        print(f"KEYMAP: FAIL the guest never reached a login prompt (evidence: {a.log})")
        return 1
    time.sleep(2)

    got = []
    for keys, _label in KEYS:
        before = len(log())
        qmp(execute="send-key",
            arguments={"keys": [{"type": "qcode", "data": k} for k in keys]})
        time.sleep(0.8)
        got.append(log()[before:])

    # Announced by the kernel on every boot; a mismatch here means the build is
    # not the build this run thinks it is.
    stated = ""
    for line in log().splitlines():
        if "kbd: layout " in line:
            stated = line.split("kbd: layout ", 1)[1].strip()
    qemu.kill()
    qemu.wait()

    # A DEAD KEYBOARD PRODUCES NOTHING, and so does a layout that maps nothing --
    # so a run where no key produced a character says nothing about layouts and
    # is reported as such rather than scored either way.
    if not any(got):
        print(f"KEYMAP: FAIL no key produced a character at all -- the keyboard is dead, "
              f"which is inconclusive about the layout (evidence: {a.log})")
        return 1

    fail = 0
    print(f"  build says: kbd: layout {stated or '(not stated)'}"
          f"   expecting: {'us (arm)' if a.expect_ignored else a.layout}")
    for (keys, label), w, g in zip(KEYS, want, got):
        ok = (g == w)
        if not ok:
            fail = 1
        print(f"  [{'ok' if ok else 'FAIL'}] {label:24s} -> {g!r:8s} want {w!r}")

    if fail:
        print(f"KEYMAP: FAIL {'the arm honoured the layout it was told to ignore' if a.expect_ignored else a.layout + ' characters are wrong'} "
              f"(evidence: {a.log})")
        return 1
    if a.expect_ignored:
        print("KEYMAP: PASS the arm ignores the layout and types US, as it must")
    else:
        print(f"KEYMAP: PASS every key produces its {a.layout} character")
    os.path.exists(a.log) and os.unlink(a.log)
    return 0


if __name__ == "__main__":
    sys.exit(main())
