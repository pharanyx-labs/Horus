#!/usr/bin/env python3
"""The hardware cursor must follow the text.

WHAT WAS WRONG. The 6845 keeps the cursor position in its own register pair, not
in the cell array, so writing characters does not move it -- it stays where the
last writer put it. The kernel calls update_cursor after every emit_char;
console_server never wrote those registers at all, so from the moment it took the
console the cursor FROZE where the kernel had left it. Measured 2026-09-12: the
blinking cell sat at row 36, column 0, unmoved while a user name was typed at the
login prompt and again at the password prompt. A cursor that does not follow the
text is worse than none -- it points confidently at the wrong place, and on a
masked password field the cursor is the only feedback there is.

HOW THE CURSOR IS FOUND WITHOUT OCR. Two screendumps 0.55s apart with NOTHING
typed between them: the only thing that changes is the blinking cursor, so the
differing pixels are its cell. Mapped back through the 720x400 raster (9 px per
column, 8 per row on the 80x50 grid) that gives a row and a column.

THE ASSERTION IS A DISPLACEMENT, not a position: type N characters and require
the cursor to advance exactly N columns on the same row. That needs no knowledge
of the prompt's text or length, and it fails both ways a cursor can be wrong --
frozen (it does not move) and merely misplaced (it moves by the wrong amount).

A RUN WHERE THE CURSOR CANNOT BE FOUND IS INCONCLUSIVE, not a failure of the
property, and says so: no blinking cell means either a dead boot or a display
with no cursor at all, and neither is what this measures.

  smoke-console-cursor          the gate
  smoke-console-cursor-control  CONSOLE_NO_CURSOR=1, which must NOT move it
"""
import argparse, json, os, socket, subprocess, sys, time

TYPED = "abcde"          # five characters -> five columns
FB_W, CELL_W, CELL_H = 720, 9, 8


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso", required=True)
    ap.add_argument("--boot-timeout", type=int, default=60)
    ap.add_argument("--expect-frozen", action="store_true")
    ap.add_argument("--shots", default="/tmp/horus-cursor-evidence")
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
        print("CONSOLE_CURSOR: FAIL QEMU never opened the QMP socket")
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

    log = {"buf": b""}

    def pump(seconds):
        end = time.time() + seconds
        while time.time() < end:
            try:
                d = sc.recv(65536)
            except Exception:
                d = b""
            if d:
                log["buf"] += d
            else:
                time.sleep(0.05)

    def wait(token, timeout):
        end = time.time() + timeout
        while time.time() < end:
            pump(0.4)
            if token in log["buf"].decode("utf8", "replace"):
                return True
        return False

    def pixels(name):
        path = os.path.join(a.shots, name)
        if os.path.exists(path):
            os.unlink(path)
        qmp(execute="screendump", arguments={"filename": path})
        time.sleep(1.0)
        if not os.path.exists(path):
            return None
        d = open(path, "rb").read()
        parts = d.split(b"\n", 3)
        return parts[3] if len(parts) > 3 else None

    def cursor_cell(tag):
        """The one cell that changes when nothing is typed: the blinking cursor."""
        a1 = pixels(f"{tag}-1.ppm")
        time.sleep(0.55)
        a2 = pixels(f"{tag}-2.ppm")
        if not a1 or not a2:
            return None
        idx = [i // 3 for i, (x, y) in enumerate(zip(a1, a2)) if x != y]
        if not idx:
            return None
        rows = {(i // FB_W) // CELL_H for i in idx}
        cols = {(i % FB_W) // CELL_W for i in idx}
        if len(rows) != 1 or len(cols) != 1:
            return None          # more than one cell moved: not a clean reading
        return rows.pop(), cols.pop()

    def fail(msg):
        with open(os.path.join(a.shots, "serial.log"), "wb") as fh:
            fh.write(log["buf"])
        qemu.kill()
        qemu.wait()
        print(f"CONSOLE_CURSOR: FAIL {msg} (evidence in {a.shots})")
        return 1

    if not wait("horus login:", a.boot_timeout):
        return fail("the guest never reached a login prompt")
    time.sleep(2)

    before = cursor_cell("1-before")
    if before is None:
        return fail("no blinking cell found -- either the boot died or this display has no "
                    "cursor at all, and neither is what this gate measures")

    sc.sendall(TYPED.encode())
    time.sleep(2)
    after = cursor_cell("2-after")
    if after is None:
        return fail("no blinking cell after typing -- inconclusive")

    qemu.kill()
    qemu.wait()

    moved = after[1] - before[1]
    same_row = after[0] == before[0]
    correct = same_row and moved == len(TYPED)
    verdict = f"before=r{before[0]}c{before[1]} after=r{after[0]}c{after[1]} moved={moved}"

    if a.expect_frozen:
        if before != after:
            print(f"CONSOLE_CURSOR: FAIL the arm's cursor moved; CONSOLE_NO_CURSOR did not "
                  f"reproduce the defect ({verdict})")
            return 1
        print(f"CONSOLE_CURSOR: PASS the arm's cursor is frozen, as it must be ({verdict})")
        return 0

    if not correct:
        return fail(f"the cursor did not follow the text -- typing {len(TYPED)} characters "
                    f"should advance it {len(TYPED)} columns on one row ({verdict})")
    print(f"CONSOLE_CURSOR: PASS the cursor follows the text ({verdict})")
    for n in ("1-before-1.ppm", "1-before-2.ppm", "2-after-1.ppm", "2-after-2.ppm"):
        try:
            os.unlink(os.path.join(a.shots, n))
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
