#ifndef HORUS_TPM_H
#define HORUS_TPM_H

/* TPM 2.0 measured boot (roadmap 2.2).
 *
 * A minimal TPM 2.0 TIS (FIFO) driver, driven once at boot, that records the
 * reproducible boot hash chain — a kernel identity token plus the embedded
 * boot-module manifest (audit A4) — into the TPM's PCRs, so the boot state can
 * be attested at runtime rather than only checked at build time.
 *
 * Best-effort by design: on a machine with no TPM (the default, and the plain
 * release boot.iso) the whole subsystem is a no-op and boot continues normally.
 * A dedicated CI gate (`make smoke-tpm`) always attaches an emulated TPM and
 * asserts the measured PCRs equal the values recomputed from the reproducible
 * manifest on the host.
 *
 * The TIS transport, big-endian command marshalling, and PCR read-back all live
 * in src/kernel/tpm.c; the register-level detail is private to that file. */

#include <stdint.h>
#include <stddef.h>

/* OS-owned PCRs (firmware/SeaBIOS measures into 0..7). We extend:
 *   PCR[8] <- H(kernel identity token || serialized module manifest)
 *   PCR[9] <- each verified boot module's SHA-256, in manifest order
 * SHA-256 bank. */
#define TPM_PCR_KERNEL_IDENTITY   8
#define TPM_PCR_BOOT_MODULES      9

/* A sealed secret: the TPM2_Create outputs (public + private) for a keyedhash
 * object whose unseal is gated by a PolicyPCR over PCR[8]/PCR[9]. Fixed-size so
 * it can be embedded verbatim in the on-disk superblock (roadmap 2.2 stage 3).
 * A keyedhash sealed object's TPM2B_PUBLIC and TPM2B_PRIVATE are both well under
 * these caps in practice. */
#define TPM_SEALED_PUB_MAX   256
#define TPM_SEALED_PRIV_MAX  256
struct tpm_sealed_blob {
    uint16_t pub_len;
    uint16_t priv_len;
    uint8_t  pub[TPM_SEALED_PUB_MAX];
    uint8_t  priv[TPM_SEALED_PRIV_MAX];
};

/* Seal a 32-byte secret so it can only be recovered by a TPM whose PCR[8]/PCR[9]
 * match the values current *at seal time* (i.e. a measured-good boot). The TPM
 * enforces the release policy; our code never sees the secret unless the TPM
 * agrees. Returns 0 on success. Self-contained: requests/releases locality. */
int tpm_seal_secret(const uint8_t secret[32], struct tpm_sealed_blob *out);

/* Recover a secret sealed by tpm_seal_secret. Succeeds only if the live
 * PCR[8]/PCR[9] satisfy the sealed PolicyPCR — otherwise the TPM refuses the
 * unseal and this returns non-zero (the volume stays locked, stage 3). */
int tpm_unseal_secret(const struct tpm_sealed_blob *in, uint8_t secret_out[32]);

/* TPM_SELFTEST build hook: seal a known value and unseal it under live PCRs,
 * asserting round-trip equality. Prints TPM_SEAL_SELFTEST: PASS/FAIL/SKIP. */
void tpm_seal_selftest(void);

/* Test-only: extend PCR[9] with an arbitrary value so a subsequently-attempted
 * unseal of a blob sealed against the earlier PCRs is refused. Used by the KEK
 * seal self-test to model a tampered/changed measurement within one boot. */
void tpm_test_extend_boot_pcr(void);

/* Probe for a usable TPM 2.0 TIS device at the standard locality-0 MMIO base.
 * Returns 1 if present (a plausible vendor id and a responsive interface),
 * 0 otherwise. Cheap; safe to call before tpm_measured_boot. */
int tpm_present(void);

/* Discover the TPM, ensure it is started, and extend the reproducible boot hash
 * chain into PCR[8]/PCR[9]. Reads the two PCRs back and prints them on the
 * serial console as a `[tpm] PCR8=<hex> PCR9=<hex>` marker the smoke test keys
 * on. Best-effort: prints `[tpm] no TPM present` and returns if none is found,
 * or `[tpm] measured boot FAILED` (without halting) on a transport error. Call
 * once at boot, right after boot_module_verify_all(). */
void tpm_measured_boot(void);

#endif /* HORUS_TPM_H */
