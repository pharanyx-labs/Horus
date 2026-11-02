#!/usr/bin/env python3
"""The pull-request installs of PyYAML accept only the recorded files.

Every `pip install` in `.github/workflows/ci.yml` that names PyYAML must pass
`--require-hashes`, `--no-deps`, and `.github/pyyaml-pin.txt`. The pin names
`pyyaml==6.0.3` and nothing else, and every hash is a sha256. A missing file,
a second package, or an install that can accept any wheel of that version is
a refusal.

The harness shows a file whose hash is not in the pin does not install.
Success prints `pyyaml-pin: ok`.
"""

import re
import sys
from pathlib import Path

PIN_REL = Path(".github/pyyaml-pin.txt")
CI_REL = Path(".github/workflows/ci.yml")
HASH_RE = re.compile(r"^sha256:([0-9a-f]{64})$")


def fail(msg):
    print(f"pyyaml-pin: {msg}")
    return 1


def parse_pin(text):
    """Return the list of sha256 hex digests, or an error string."""
    logical = []
    buf = ""
    continued = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            if continued:
                return "pin: a continued line is not closed"
            continue
        if line.endswith("\\"):
            buf += line[:-1].strip() + " "
            continued = True
            continue
        buf += line
        logical.append(" ".join(buf.split()))
        buf = ""
        continued = False
    if continued or buf:
        return "pin: a continued line is not closed"
    if len(logical) != 1:
        return f"pin: expected one requirement, found {len(logical)}"
    parts = logical[0].split()
    if not parts or parts[0] != "pyyaml==6.0.3":
        return "pin: requirement is not pyyaml==6.0.3"
    hashes = []
    for part in parts[1:]:
        if not part.startswith("--hash="):
            return "pin: unexpected token beside the hashes"
        match = HASH_RE.match(part[len("--hash="):])
        if not match:
            return "pin: a hash is not sha256 of 64 hex digits"
        hashes.append(match.group(1))
    if not hashes:
        return "pin: no hashes"
    if len(hashes) != len(set(hashes)):
        return "pin: a hash is repeated"
    return hashes


def check_ci(text):
    """Return None when every PyYAML install is pinned, else an error."""
    installs = []
    for number, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        # The checker steps name this pin. Only a pip line is an install.
        if "pyyaml" in low and "pip" in low:
            installs.append((number, line.strip()))
    if len(installs) < 2:
        return "ci.yml: fewer than two PyYAML installs"
    user = 0
    plain = 0
    for number, line in installs:
        if not line.startswith("run:"):
            return f"ci.yml:{number}: PyYAML is not on a pip install run line"
        body = line[len("run:"):].strip()
        flags = body.split()
        if not flags or flags[0] != "pip" or len(flags) < 2 or flags[1] != "install":
            return f"ci.yml:{number}: PyYAML line is not a pip install"
        if "--require-hashes" not in flags:
            return f"ci.yml:{number}: install does not require hashes"
        if "--no-deps" not in flags:
            return f"ci.yml:{number}: install can pull another dependency"
        if "-r" not in flags or ".github/pyyaml-pin.txt" not in flags:
            return f"ci.yml:{number}: install does not use the pin file"
        if "pyyaml==" in body.lower():
            return f"ci.yml:{number}: version pin is inline instead of in the pin file"
        if "--user" in flags:
            user += 1
        else:
            plain += 1
    if user < 1 or plain < 1:
        return "ci.yml: both the plain installs and the --user installs must stay"
    return None


def main():
    try:
        pin_text = PIN_REL.read_text(encoding="utf-8")
    except OSError:
        return fail("pin: cannot read .github/pyyaml-pin.txt")
    parsed = parse_pin(pin_text)
    if isinstance(parsed, str):
        return fail(parsed)
    try:
        ci_text = CI_REL.read_text(encoding="utf-8")
    except OSError:
        return fail("ci.yml: cannot read .github/workflows/ci.yml")
    error = check_ci(ci_text)
    if error:
        return fail(error)
    print("pyyaml-pin: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
