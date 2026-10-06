#!/usr/bin/env python3
"""Run every Kani control arm and require each one to make its proof FAIL.

A Kani proof is evidence only if it can fail. Each proof in this tree was
falsified once when it was written, by putting a defect back and watching the
proof report `VERIFICATION:- FAILED`, but that was a one-off recorded in a
comment: nothing re-ran it, so a later change that made the property vacuous
(an assumption that excludes every interesting input, a harness that no longer
reaches the code) would have left the proof green and meaningless. This
re-runs every recorded arm, the way every boot gate's control arm is re-run
(CLAUDE.md §2).

`.github/kani-arms.yml` lists the arms: a harness, a file under rust/, an exact
text to find (it must occur exactly once) and what to replace it with, and
optionally cargo features. For each arm this copies rust/ to a scratch
directory once, applies that one mutation, runs `cargo kani --harness`, and
restores the file. The arm passes only on `VERIFICATION:- FAILED`. A
SUCCESSFUL proof means the arm no longer reaches the property; no verdict at
all (a compile error, a timeout) is reported as such and also fails, because an
arm that cannot run proves nothing either way.

The repository is never modified: every mutation happens in the copy. Each
arm's full Kani output is written to --log-dir and kept whatever the result,
because a red run is exactly when somebody needs it (§2).

Usage:  tools/kani_arms.py [--log-dir DIR] [--only ARM_ID ...] [--timeout S]
Exit 0 if every arm made its proof fail, 1 otherwise.
"""
import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
ARMS = ROOT / ".github" / "kani-arms.yml"


def verdict(output):
    if "VERIFICATION:- FAILED" in output:
        return "FAILED"
    if "VERIFICATION:- SUCCESSFUL" in output:
        return "SUCCESSFUL"
    return "NO VERDICT"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default="kani-arm-logs")
    ap.add_argument("--only", nargs="*", default=None)
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args()

    arms = (yaml.safe_load(ARMS.read_text()) or {}).get("arms") or []
    if args.only:
        unknown = set(args.only) - {a["id"] for a in arms}
        if unknown:
            sys.exit(f"kani_arms: no arm with id {sorted(unknown)}")
        arms = [a for a in arms if a["id"] in args.only]
    if not arms:
        sys.exit("kani_arms: no arms to run -- refusing to report a pass having run nothing")

    logs = pathlib.Path(args.log_dir)
    logs.mkdir(parents=True, exist_ok=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix="kani-arms-"))
    crate = work / "rust"
    shutil.copytree(ROOT / "rust", crate, ignore=shutil.ignore_patterns("target"))

    results = []
    for arm in arms:
        rel = pathlib.Path(arm["file"]).relative_to("rust")
        path = crate / rel
        original = path.read_text()
        n = original.count(arm["find"])
        if n != 1:
            results.append((arm, "ANCHOR", 0))
            print(f"  {arm['id']}: its find text occurs {n} times in {arm['file']}, not once", flush=True)
            continue
        path.write_text(original.replace(arm["find"], arm["replace"]))
        cmd = ["cargo", "kani", "--harness", arm["harness"]]
        for f in arm.get("features") or []:
            cmd += ["--features", f]
        start = time.time()
        try:
            r = subprocess.run(cmd, cwd=crate, capture_output=True, text=True, timeout=args.timeout)
            out = r.stdout + r.stderr
        except subprocess.TimeoutExpired as e:
            # Partial output may arrive as bytes or str depending on the
            # platform; keep whatever there is, since it is the evidence.
            def text(x):
                return x.decode(errors="replace") if isinstance(x, bytes) else (x or "")
            out = text(e.stdout) + text(e.stderr) + f"\n[kani_arms] timed out after {args.timeout} s\n"
        finally:
            path.write_text(original)
        secs = round(time.time() - start)
        v = verdict(out)
        (logs / f"{arm['id']}.log").write_text(out)
        results.append((arm, v, secs))
        print(f"  {arm['id']} ({arm['harness']}): {v} in {secs} s", flush=True)

    bad = [(a, v) for a, v, _ in results if v != "FAILED"]
    print(f"\narms run: {len(results)}   made their proof fail: {len(results) - len(bad)}")
    if bad:
        print("\nFAIL: these arms did not make their proof fail, so the proof is not shown to be able to:")
        for a, v in bad:
            print(f"  - {a['id']} on {a['harness']}: {v} (log: {logs / (a['id'] + '.log')})")
        return 1
    print("PASS: every Kani proof with an arm still goes red when its defect is put back")
    return 0


if __name__ == "__main__":
    sys.exit(main())
