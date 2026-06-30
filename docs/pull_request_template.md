## Description
<!-- Concise summary of the change. Link to related issue if applicable. -->

## Motivation / Rationale
<!-- Why is this change needed? What problem does it solve? -->

## Security Impact
**REQUIRED for any change touching capability system, memory management, IPC, scheduler, crypto, auth, audit, build/CI, or FFI boundary.**

- Does this change preserve all existing security invariants (capability lineage/revocation correctness, no ambient authority, FFI safety, isolation guarantees)?
- What new attack surface or trust assumption is introduced?
- How was the change reviewed against the threat model in SECURITY.md and ARCHITECTURE.md?
- List any new capabilities, rights, or kernel objects added.

<!-- Example answers:
- Yes, revocation sweep + generation bump still covers all derived caps.
- No new ambient authority paths.
- Tested with new property-based test in rust/src/capability.rs.
-->

## Testing Performed
- [ ] `make` builds cleanly (no new warnings)
- [ ] `make test` / `cargo test --release` passes
- [ ] `make reproducible-build` still produces identical artifacts
- [ ] `make smoke` passes (headless QEMU boot to the shell banner; required if userspace, the loader, paging, or boot changed)
- [ ] New or updated unit/property tests added for security-critical logic
- [ ] Security scans (`make security`) reviewed; no new high-severity findings

## Checklist
- [ ] I have read `docs/ARCHITECTURE.md`, `docs/LIMITATIONS.md`, and `CONTRIBUTING.md`
- [ ] Changes to security-critical paths include explicit explanation of invariants preserved
- [ ] Documentation updated (ARCHITECTURE.md, LIMITATIONS.md, code comments)
- [ ] No new external dependencies introduced without justification
- [ ] This PR does not increase the C unsafe surface or add `unsafe` in rust/src/capability.rs / memory.rs / crypto.rs

## Screenshots / Logs (if UI or boot behavior changed)
<!-- Optional but helpful for reviewers -->

## Related Issues / PRs
<!-- e.g. Closes #xx, Depends on #yy -->
