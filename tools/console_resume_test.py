#!/usr/bin/env python3
"""Nothing may be left stranded below the prompt when the console changes hands.

WHAT WAS WRONG. console_server's write position started at 0, so the first line
it printed landed on row 0 -- on top of the OLDEST line of a boot log that was
already most of a screen long. The tail of the kernel's log was then left sitting
BELOW the login prompt, stranded, with the prompt apparently in the middle of the
screen. Measured 2026-09-12 on a clean boot: prompt at row 16, eighteen further
rows of earlier output beneath it, and a stray '.' in the bottom-right corner
left by the mapping's own round-trip probe.

The kernel maintains the 6845's cursor registers all through the boot, so where
it had got to was readable the whole time. This server now reads them at the
handover and continues there.

THE ASSERTION IS A SHAPE, NOT A STRING: find the cursor (two screendumps with
nothing typed between them -- the only cell that changes is the one that blinks),
then require NO ROW BELOW IT to carry text. That is what "the log ends where you
are typing" means on a screen, it needs no OCR, and it fails exactly the defect
above. A blank screen cannot pass it, because a run with no text at all and no
cursor is reported inconclusive.
"""
import argparse, json, os, socket, subprocess, sys, time

FB_W, CELL_W, CELL_H = 720, 9, 8
INK_ROW = 50          # a row with more than this many non-zero bytes has text
MIN_ROWS_WITH_TEXT = 8


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso", required=True)
    ap.add_argument("--boot-timeout", type=int, default=60)
    ap.add_argument("--expect-stranded", action="store_true")
    ap.add_argument("--shots", default="/tmp/horus-resume-evidence")
    a = ap.parse_args()

    os.makedirs(a.shots, exist_ok=True)
    qs = os.path.join(a.shots, "qmp.sock")
    ss = os.path.join(a.shots, "serial.sock")
    for x in (qs, ss):
        if os.path.exists(x):
            os.unlink(x)
    qsrv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    qsrv.bind(qs)
    qsrv.listen(1)
    qemu = subprocess.Popen(
        ["qemu-system-x86_64", "-m", "512M", "-machine", "q35", "-smp", "2",
         "-display", "none", "-qmp", f"unix:{qs}", "-net", "none",
         "-no-reboot", "-no-shutdown",
         "-serial", f"unix:{ss},server=on,wait=off", "-cdrom", a.iso],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    qsrv.settimeout(a.boot_timeout)
    try:
        qc, _ = qsrv.accept()
    except socket.timeout:
        qemu.kill()
        print("CONSOLE_RESUME: FAIL QEMU never opened the QMP socket")
        return 1
    f = qc.makefile("rw")

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
    sc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for _ in range(60):
        try:
            sc.connect(ss)
            break
        except OSError:
            time.sleep(0.5)
    sc.settimeout(0.5)

    buf = b""
    end = time.time() + a.boot_timeout
    while time.time() < end:
        try:
            d = sc.recv(65536)
        except Exception:
            d = b""
        if d:
            buf += d
        else:
            time.sleep(0.05)
        if b"horus login:" in buf:
            break
    if b"horus login:" not in buf:
        qemu.kill()
        print(f"CONSOLE_RESUME: FAIL the guest never reached a login prompt "
              f"(evidence in {a.shots})")
        return 1
    time.sleep(3)

    def pixels(name):
        path = os.path.join(a.shots, name)
        if os.path.exists(path):
            os.unlink(path)
        qmp(execute="screendump", arguments={"filename": path})
        time.sleep(1.2)
        if not os.path.exists(path):
            return None, 0, 0
        d = open(path, "rb").read()
        parts = d.split(b"\n", 3)
        w, h = map(int, parts[1].split())
        return (parts[3] if len(parts) > 3 else None), w, h

    p1, w, h = pixels("1.ppm")
    time.sleep(0.55)
    p2, _, _ = pixels("2.ppm")
    qemu.kill()
    qemu.wait()
    if not p1 or not p2:
        print(f"CONSOLE_RESUME: FAIL no screendump (evidence in {a.shots})")
        return 1

    idx = [i // 3 for i, (x, y) in enumerate(zip(p1, p2)) if x != y]
    rows_c = {(i // w) // CELL_H for i in idx}
    if len(rows_c) != 1:
        print(f"CONSOLE_RESUME: FAIL no single blinking cell found -- inconclusive about "
              f"where the prompt is (evidence in {a.shots})")
        return 1
    cursor_row = rows_c.pop()

    ink = []
    for r in range(h // CELL_H):
        n = 0
        for y in range(r * CELL_H, (r + 1) * CELL_H):
            b0 = y * w * 3
            n += sum(1 for i in range(b0, b0 + w * 3) if p1[i])
        ink.append(n)
    texty = [r for r, v in enumerate(ink) if v > INK_ROW]
    if len(texty) < MIN_ROWS_WITH_TEXT:
        print(f"CONSOLE_RESUME: FAIL the screen has almost no text ({len(texty)} rows) -- "
              f"inconclusive (evidence in {a.shots})")
        return 1

    stranded = [r for r in texty if r > cursor_row]
    verdict = f"cursor row={cursor_row}, rows with text below it={stranded}"

    if a.expect_stranded:
        if stranded:
            print(f"CONSOLE_RESUME: PASS the arm strands the old log below the prompt, as it "
                  f"must ({verdict})")
            return 0
        print(f"CONSOLE_RESUME: FAIL the arm left nothing stranded; CONSOLE_NO_RESUME did not "
              f"reproduce the defect ({verdict})")
        return 1

    if stranded:
        print(f"CONSOLE_RESUME: FAIL the tail of the kernel's boot log is stranded below the "
              f"prompt ({verdict}, evidence in {a.shots})")
        return 1
    print(f"CONSOLE_RESUME: PASS the log ends where the prompt is ({verdict})")
    for n in ("1.ppm", "2.ppm"):
        try:
            os.unlink(os.path.join(a.shots, n))
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
