#!/usr/bin/env bash
# Refresh the local code graph. USE THIS INSTEAD OF `graphify update .`.
#
# graphify extracts each language on its own, so a C function calling a
# `#[no_mangle] pub extern "C"` Rust function yields no edge at all. That is not
# a missing detail in a convenience tool -- CLAUDE.md §0 makes graphify the
# MANDATORY first step before reading any source, so a blind spot there is a
# confident wrong answer at the moment nobody has looked at the code yet.
#
# It has already happened. On 2026-08-30 `graphify explain rust_cap_lookup`
# listed only unit tests and Kani harnesses as callers. The reasonable reading --
# that the function is not on a live path -- is false: src/kernel/capability.c
# calls it on every capability check the kernel performs. A raw grep is what
# caught it, which is exactly the step the graph exists to make unnecessary.
#
# So: extract, then inject the FFI edges, then ASSERT they are there. The
# assertion matters because the injector depends on graphify's node schema
# (labels carry a trailing "()", ids are derived from paths). If that changes
# upstream, the injector silently produces nothing, and a silent nothing here
# restores the exact failure this script exists to prevent.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[graph] extracting (AST only, no API cost)"
graphify update .

echo "[graph] injecting C <-> Rust FFI edges"
python3 tools/ffi_edges.py

echo "[graph] verifying the boundary is visible"
python3 tools/ffi_edges.py --check

echo "[graph] done. graphify-out/ is gitignored and stays local (CLAUDE.md §0)."
