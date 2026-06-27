---
name: Security Report / Vulnerability
about: Report a potential security issue in Horus (use GitHub Security Advisory for private reports when possible)
title: "[SECURITY] "
labels: security, bug
assignees: yossicohenmcr-ctrl
---

**⚠️ IMPORTANT: For sensitive vulnerabilities, please use GitHub Security Advisories (Settings → Security → Advisories → New draft advisory) instead of a public issue. This creates a private thread.**

## Summary
<!-- One-sentence description of the suspected issue -->

## Component(s) Affected
- [ ] Capability system / revocation / lineage
- [ ] Memory management / paging / FFI boundary
- [ ] IPC / scheduler
- [ ] Cryptography / RNG / key derivation
- [ ] Authentication / audit logging
- [ ] Build / CI / supply chain
- [ ] Other: ________________

## Detailed Description
<!-- Steps to reproduce, expected vs actual behavior, relevant code paths or syscalls -->

## Impact Assessment
- Confidentiality / Integrity / Availability impact?
- Can an unprivileged task escalate privileges or bypass capability checks?
- Is this a new issue or regression from a previous state?
- Any known workarounds?

## Environment
- Horus commit / version:
- Build configuration (BITS=64, DEBUG_SHELL, MINIMAL_SECURE, RUST_ENABLED):
- Host / QEMU version:
- CPU features (if relevant, e.g. SMEP/SMAP, RDRAND, AES-NI):

## Proof of Concept / Reproduction Steps
<!-- If safe to share publicly; otherwise note "available privately" -->

## Suggested Fix or Mitigation (optional)

## Disclosure Preference
- [ ] I would like credit if a fix is published
- [ ] Please keep my name private

---

**References**
- SECURITY.md (vulnerability disclosure process)
- docs/LIMITATIONS.md (known issues that are out of scope for new reports)
- CONTRIBUTING.md (how security changes are reviewed)
