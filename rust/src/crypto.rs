//! (Reserved) crypto module.
//!
//! This module previously held a custom, unaudited ARX/XOR-rotate block-key
//! derivation and MAC. Those have been removed in favour of audited-standard
//! primitives:
//!   * `crate::sha256` — SHA-256, HMAC-SHA256, PBKDF2, HKDF
//!   * `crate::rng`    — ChaCha20 CSPRNG + RDRAND seeding
//!
//! The kernel's storage layer (`src/kernel/storage.c`) now derives per-block
//! keys via HKDF-SHA256 and authenticates blocks via HMAC-SHA256, calling the
//! FFI exposed from `crate::sha256`. Bulk AES-CTR encryption remains in C
//! (`src/kernel/crypto.c`).
//!
//! Intentionally empty: no custom cryptographic constructions live here.
