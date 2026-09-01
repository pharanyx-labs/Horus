#!/usr/bin/env bash
# The installer is embedded in EVERY build and init launches it, so this sweeps
# the gates whose images it could perturb -- not just its own three.
set -u
T="smoke-installer smoke-installer-refuse smoke-installer-refuse-control
   smoke smoke-captest smoke-proc smoke-session smoke-init-fs smoke-init-provision
   smoke-storage-survey smoke-storage-noformat smoke-storage-noformat-control
   smoke-users-persist smoke-vfs smoke-libhorus smoke-tui smoke-modules"
: > SWEEP.txt
for t in $T; do
  printf "%-38s" "$t" >> SWEEP.txt
  if timeout 1500 make "$t" > "sweep_$t.log" 2>&1; then echo "PASS" >> SWEEP.txt
  else echo "FAIL" >> SWEEP.txt; fi
done
echo "=== SWEEP ==="; cat SWEEP.txt
