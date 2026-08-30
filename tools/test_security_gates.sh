#!/usr/bin/env bash
# Falsify the two security scanners that roadmap 4.3 promoted to gating.
#
# Both used to swallow their result inside the Makefile -- `gitleaks ... || true`
# and `cargo audit || echo "cargo-audit not installed or no advisories found"`.
# The second is the worse of the two: the message names two conditions that need
# OPPOSITE responses, and a real advisory printed the reassuring half and exited
# 0. A scanner that cannot fail is not a scanner, so each is now exercised
# against a tree mutated to make it fire.
#
# THE CLEAN DIRECTION IS NOT IN THIS FILE, DELIBERATELY. Four "does it fire"
# arms are all satisfied by a scanner that rejects everything, and the honest
# clean arm for gitleaks is the real repository with its real history -- which
# is exactly what `make gitleaks` does in CI. A PR going green IS that arm, on
# the only tree whose cleanliness anyone cares about. Arm S2 below is a weaker
# local stand-in that at least catches "rejects any input at all".
#
# NOTE ON THE PLANTED SECRET: it is assembled at runtime from fragments that do
# not match gitleaks' pattern individually. Writing the literal here would put a
# detectable secret in this repository's history permanently, and `make gitleaks`
# would then fail on every future run -- the test breaking the thing it tests.
#
# Mutations are applied to a COPY. Nothing here can leave the tree modified.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

have () { command -v "$1" >/dev/null 2>&1; }

pass () { echo "  $1: $2"; PASSES=$((PASSES+1)); }
fail () { echo "  $1: $2"; FAILS=$((FAILS+1)); }

echo "Falsifying the roadmap 4.3 security gates:"

# ---------------------------------------------------------------- gitleaks ---
if ! have gitleaks; then
  fail S1 "gitleaks is NOT INSTALLED, so its gate was not exercised. \
That is a broken test run, not a pass -- CI installs it in the step above."
else
  # S1. A secret in the tree must fail the scan. This is the arm the `|| true`
  #     defeated: gitleaks found things and the build went green regardless.
  d="$(mktemp -d)"
  ( cd "$d" && git init -q . && git config user.email t@e && git config user.name t
    frag_a="AKIA"; frag_b="IOSFODNN7EXAMPLE"
    printf 'aws_access_key_id = %s%s\n' "$frag_a" "$frag_b" > creds.txt
    git add creds.txt && git commit -qm "planted" ) >/dev/null 2>&1
  if ( cd "$d" && gitleaks detect --source . --redact ) >/dev/null 2>&1; then
    fail S1 "NOT CAUGHT -- a planted credential did not fail the scan"
  else
    pass S1 "caught -- a planted credential fails the scan"
  fi
  rm -rf "$d"

  # S2. The weaker half: a scanner that rejected every input would satisfy S1.
  #     The real clean arm is CI running this against the actual history.
  d="$(mktemp -d)"
  ( cd "$d" && git init -q . && git config user.email t@e && git config user.name t
    echo "static int frobnicate(void) { return 42; }" > ok.c
    git add ok.c && git commit -qm "innocuous" ) >/dev/null 2>&1
  if ( cd "$d" && gitleaks detect --source . --redact ) >/dev/null 2>&1; then
    pass S2 "clean, correctly -- an innocuous tree passes"
  else
    fail S2 "WRONGLY CAUGHT -- an innocuous tree failed the scan"
  fi
  rm -rf "$d"

  # S3. The redaction, which only matters BECAUSE the gate now runs: an
  #     unredacted finding prints the secret into a public CI log, so the
  #     detector becomes the disclosure. Assert the value does not appear.
  d="$(mktemp -d)"
  ( cd "$d" && git init -q . && git config user.email t@e && git config user.name t
    frag_a="AKIA"; frag_b="IOSFODNN7EXAMPLE"
    printf 'aws_access_key_id = %s%s\n' "$frag_a" "$frag_b" > creds.txt
    git add creds.txt && git commit -qm "planted" ) >/dev/null 2>&1
  out="$( cd "$d" && gitleaks detect --source . --verbose --redact 2>&1 )"
  if grep -qF "AKIA""IOSFODNN7EXAMPLE" <<<"$out"; then
    fail S3 "the secret VALUE was printed despite --redact"
  else
    pass S3 "the finding is reported with the value redacted"
  fi
  rm -rf "$d"
fi

# ------------------------------------------------------------- cargo-audit ---
# S4 and S5 test the Makefile PLUMBING, which is where the defect was. The
# scanner's own detection is upstream's business; what broke here was that its
# exit status never reached make.

# S4. A failing `cargo audit` must fail the target. Mutated to a command that
#     always fails, so the arm does not need a vulnerable dependency (which
#     would rot the moment the advisory was withdrawn).
d="$(mktemp -d)"; mkdir -p "$d/rust"
sed 's|^\tcd rust && cargo audit$|\tcd rust \&\& false|' "$ROOT/Makefile" > "$d/Makefile"
if grep -q "cd rust && false" "$d/Makefile"; then
  out="$( cd "$d" && make cargo-audit 2>&1 )"; rc=$?
  # The failure must come from the MUTATION, not from make giving up earlier.
  # This Makefile aborts at parse time without a toolchain, and a temp copy has
  # no sources -- so "it failed" on its own would be satisfied by a parse error
  # and the arm would pass having tested nothing. Require the target to have
  # actually started.
  if [ $rc -eq 0 ]; then
    fail S4 "NOT CAUGHT -- a failing cargo audit did not fail the target"
  elif ! grep -q "=== cargo-audit" <<<"$out"; then
    fail S4 "failed BEFORE the target ran (parse error?), so nothing was tested"
  else
    pass S4 "caught -- a failing cargo audit fails the target"
  fi
else
  fail S4 "MUTATION FAILED -- the `cd rust && cargo audit` anchor moved"
fi
rm -rf "$d"

# S5. THE ARM FOR THE ORIGINAL WORDING. `|| echo "cargo-audit not installed or
#     no advisories found"` reported a MISSING SCANNER as a clean scan. An
#     absent tool must now fail rather than reassure.
# The real toolchain must stay reachable: the Makefile aborts at PARSE time if
# `cargo` is absent or the bare-metal rust target is missing, and either of those
# is a different failure that would let this arm pass for the wrong reason (it
# did, twice, while this was being written). So the stub PASSES THROUGH to the
# real cargo for everything and fails only on `audit`, which is what an
# uninstalled cargo-audit looks like -- and keeps the arm deterministic whether
# or not cargo-audit happens to be installed on the machine running it.
d="$(mktemp -d)"; mkdir -p "$d/rust" "$d/stubbin"
REAL_CARGO="$(command -v cargo || echo /nonexistent)"
{ printf '#!/bin/sh\n[ "$1" = "audit" ] && exit 1\nexec %s "$@"\n' "$REAL_CARGO"; } > "$d/stubbin/cargo"
chmod +x "$d/stubbin/cargo"
cp "$ROOT/Makefile" "$d/Makefile"
out="$( cd "$d" && PATH="$d/stubbin:$PATH" make cargo-audit 2>&1 )"; rc=$?
if [ $rc -eq 0 ]; then
  fail S5 "NOT CAUGHT -- a missing cargo-audit was reported as a clean scan"
elif ! grep -qi "NOT INSTALLED" <<<"$out"; then
  # Doubles as the did-it-actually-run check: this string can only come from the
  # recipe body, so a parse-time abort cannot satisfy the arm.
  fail S5 "failed, but did not say the scanner was missing (a fixable scan reads as a finding)"
else
  pass S5 "caught -- a missing scanner is a broken scan, not a clean one"
fi
rm -rf "$d"

echo
echo "arms passed: $PASSES, failed: $FAILS"
[ "$FAILS" -eq 0 ] || exit 1
