/*
 * TPM 2.0 measured boot over the TIS (FIFO) interface — roadmap 2.2.
 *
 * A deliberately small, boot-time-only TPM 2.0 driver. It runs once, on the BSP,
 * after boot_module_verify_all() and before any userspace exists, with interrupts
 * off and no other CPU touching the device — so the transport is a straight
 * poll-with-timeout loop, no locking, no interrupt handshake.
 *
 * What it measures (SHA-256 PCR bank, OS-owned PCRs — SeaBIOS already owns 0..7):
 *   PCR[8] <- H( "horus-measured-boot-v1" || serialized boot-module manifest )
 *             a kernel-identity token bound to the exact module set this
 *             reproducible image attests to (audit A4's embedded manifest).
 *   PCR[9] <- each verified boot module's SHA-256, extended in manifest order.
 *             A module that fails A4 verification is not measured, so tampering
 *             with a module payload changes PCR[9] — the property the Track 2
 *             sealing work (stages 2-3) will bind a secret to.
 *
 * Best-effort: if no TPM is discovered the whole thing is a no-op and boot
 * continues. A machine legitimately without a TPM is not a failure; a store that
 * later opts into TPM sealing is what makes the measurement load-bearing.
 *
 * Transport reference: TCG PC Client Platform TPM Profile (PTP), TIS/FIFO.
 */

#include "kernel.h"

/* The manifest table (BOOT_MODULE_DIGESTS / BOOT_MODULE_DIGEST_COUNT). Generated
 * from the same BOOT_MODULES list the ISO is built from; each TU that includes it
 * gets its own const copy, which is fine. */
#include "boot_module_manifest.h"

/* ---- TIS register map (locality 0 at 0xFED40000) -------------------------- */

#define TPM_TIS_BASE        0xFED40000ULL

#define TPM_REG_ACCESS      0x000   /* 1 byte  */
#define TPM_REG_STS         0x018   /* 4 bytes: flags in byte0, burstCount 8..23 */
#define TPM_REG_DATA_FIFO   0x024   /* 1 byte  */
#define TPM_REG_DID_VID     0xF00   /* 4 bytes */

/* TPM_ACCESS bits */
#define ACCESS_VALID        0x80
#define ACCESS_ACTIVE_LOC   0x20
#define ACCESS_REQUEST_USE  0x02

/* TPM_STS bits (byte 0) */
#define STS_VALID           0x80
#define STS_COMMAND_READY   0x40
#define STS_TPM_GO          0x20
#define STS_DATA_AVAIL      0x10
#define STS_EXPECT          0x08

/* ---- TPM 2.0 command constants -------------------------------------------- */

#define TPM_ST_NO_SESSIONS  0x8001
#define TPM_ST_SESSIONS     0x8002

#define TPM_CC_STARTUP      0x00000144u
#define TPM_CC_PCR_EXTEND   0x00000182u
#define TPM_CC_PCR_READ     0x0000017Eu

#define TPM_SU_CLEAR        0x0000
#define TPM_RS_PW           0x40000009u
#define TPM_ALG_SHA256      0x000B

#define TPM_RC_SUCCESS      0x00000000u
#define TPM_RC_INITIALIZE   0x00000100u   /* Startup after already-started: benign */

/* A TPM response is small; a PCR_Read reply is well under this. */
#define TPM_IO_MAX          512

static volatile uint8_t *g_tpm = 0;   /* mapped MMIO base, 0 until probed */

/* ---- MMIO accessors ------------------------------------------------------- */

static inline uint8_t  tpm_r8(uint32_t off)  { return *(volatile uint8_t  *)(g_tpm + off); }
static inline void     tpm_w8(uint32_t off, uint8_t v)  { *(volatile uint8_t  *)(g_tpm + off) = v; }
static inline uint32_t tpm_r32(uint32_t off) { return *(volatile uint32_t *)(g_tpm + off); }

/* ---- big-endian buffer helpers -------------------------------------------- */

static void be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static void be32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }
static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* ---- bounded polling ------------------------------------------------------
 * read_tsc() advances with the guest; assume no less than ~1 GHz, so a budget of
 * ~3e9 cycles is a generous multi-second ceiling on real hardware and under TCG
 * (where the TPM answers promptly regardless). Returns 1 if the predicate held
 * before the deadline, 0 on timeout. */
#define TPM_TIMEOUT_CYCLES  3000000000ULL

static int tpm_wait_sts(uint8_t mask, uint8_t want) {
    uint64_t start = read_tsc();
    for (;;) {
        if ((tpm_r8(TPM_REG_STS) & mask) == want) return 1;
        if (read_tsc() - start > TPM_TIMEOUT_CYCLES) return 0;
        __asm__ volatile("pause");
    }
}

static uint32_t tpm_burst(void) {
    /* burstCount is bits 8..23 of STS. */
    return (tpm_r32(TPM_REG_STS) >> 8) & 0xFFFF;
}

/* ---- TIS locality + command/response -------------------------------------- */

static int tpm_request_locality(void) {
    tpm_w8(TPM_REG_ACCESS, ACCESS_REQUEST_USE);
    uint64_t start = read_tsc();
    for (;;) {
        uint8_t a = tpm_r8(TPM_REG_ACCESS);
        if ((a & (ACCESS_VALID | ACCESS_ACTIVE_LOC)) == (ACCESS_VALID | ACCESS_ACTIVE_LOC))
            return 1;
        if (read_tsc() - start > TPM_TIMEOUT_CYCLES) return 0;
        __asm__ volatile("pause");
    }
}

static void tpm_release_locality(void) {
    /* Writing activeLocality relinquishes locality 0. */
    tpm_w8(TPM_REG_ACCESS, ACCESS_ACTIVE_LOC);
}

/* Submit one command (cmd/cmd_len) and read the response into rsp (capacity
 * rsp_cap). Returns the response length on success, or a negative value on any
 * transport timeout / framing error. Response is the full TPM frame including the
 * 10-byte header (tag,size,rc). */
static int tpm_transact(const uint8_t *cmd, uint32_t cmd_len,
                        uint8_t *rsp, uint32_t rsp_cap) {
    if (!g_tpm) return -1;

    /* 1. Move to commandReady. */
    tpm_w8(TPM_REG_STS, STS_COMMAND_READY);
    if (!tpm_wait_sts(STS_COMMAND_READY, STS_COMMAND_READY)) return -2;

    /* 2. Feed the command through the FIFO, honouring burstCount, leaving the
     *    final byte for a separate write so we can check Expect clears. */
    uint32_t i = 0;
    while (i < cmd_len - 1) {
        uint32_t burst = tpm_burst();
        if (burst == 0) {
            if (!tpm_wait_sts(STS_VALID, STS_VALID)) return -3;
            continue;
        }
        while (burst-- && i < cmd_len - 1) tpm_w8(TPM_REG_DATA_FIFO, cmd[i++]);
        if (!tpm_wait_sts(STS_VALID | STS_EXPECT, STS_VALID | STS_EXPECT)) return -4;
    }
    tpm_w8(TPM_REG_DATA_FIFO, cmd[cmd_len - 1]);
    /* TPM should now have exactly what it expects: Valid set, Expect clear. */
    if (!tpm_wait_sts(STS_VALID | STS_EXPECT, STS_VALID)) return -5;

    /* 3. Execute. */
    tpm_w8(TPM_REG_STS, STS_TPM_GO);

    /* 4. Wait for a response and drain it. */
    if (!tpm_wait_sts(STS_VALID | STS_DATA_AVAIL, STS_VALID | STS_DATA_AVAIL)) return -6;

    uint32_t got = 0;
    uint32_t expected = 10;   /* until the size field is parsed */
    while (got < expected) {
        uint32_t burst = tpm_burst();
        if (burst == 0) {
            if (!(tpm_r8(TPM_REG_STS) & STS_DATA_AVAIL)) break;   /* no more coming */
            __asm__ volatile("pause");
            continue;
        }
        while (burst-- && got < expected) {
            if (got >= rsp_cap) return -7;
            rsp[got++] = tpm_r8(TPM_REG_DATA_FIFO);
            if (got == 6) {                       /* have tag(2)+size(4): learn length */
                expected = rd_be32(rsp + 2);
                if (expected < 10 || expected > rsp_cap) return -8;
            }
        }
    }
    if (got != expected) return -9;

    /* 5. Back to idle. */
    tpm_w8(TPM_REG_STS, STS_COMMAND_READY);
    return (int)got;
}

/* Response return code (bytes 6..9), or 0xFFFFFFFF if the frame is too short. */
static uint32_t tpm_rc(const uint8_t *rsp, int len) {
    if (len < 10) return 0xFFFFFFFFu;
    return rd_be32(rsp + 6);
}

/* ---- typed commands ------------------------------------------------------- */

static int tpm_startup(void) {
    uint8_t cmd[12];
    be16(cmd + 0, TPM_ST_NO_SESSIONS);
    be32(cmd + 2, 12);
    be32(cmd + 6, TPM_CC_STARTUP);
    be16(cmd + 10, TPM_SU_CLEAR);
    uint8_t rsp[TPM_IO_MAX];
    int n = tpm_transact(cmd, sizeof(cmd), rsp, sizeof(rsp));
    if (n < 0) return -1;
    uint32_t rc = tpm_rc(rsp, n);
    /* Already started by firmware/GRUB is the common, benign case. */
    if (rc == TPM_RC_SUCCESS || rc == TPM_RC_INITIALIZE) return 0;
    return -1;
}

static int tpm_pcr_extend(uint32_t pcr, const uint8_t digest[32]) {
    /* Frame is exactly 65 bytes (10 header + 12 pcrHandle/authSize + 9 auth +
     * 6 TPML/alg + 32 digest); round up for headroom. */
    uint8_t cmd[80];
    uint32_t p = 0;
    be16(cmd + p, TPM_ST_SESSIONS);            p += 2;
    be32(cmd + p, 0);                          p += 4;   /* size, patched below */
    be32(cmd + p, TPM_CC_PCR_EXTEND);          p += 4;
    be32(cmd + p, pcr);                        p += 4;   /* pcrHandle */
    /* authorization area: TPM_RS_PW, empty nonce, no attrs, empty hmac (size 9) */
    be32(cmd + p, 9);                          p += 4;
    be32(cmd + p, TPM_RS_PW);                  p += 4;
    be16(cmd + p, 0);                          p += 2;   /* nonce size */
    cmd[p++] = 0;                                        /* session attributes */
    be16(cmd + p, 0);                          p += 2;   /* hmac size */
    /* TPML_DIGEST_VALUES: count 1, SHA-256, 32 bytes */
    be32(cmd + p, 1);                          p += 4;
    be16(cmd + p, TPM_ALG_SHA256);             p += 2;
    for (int i = 0; i < 32; i++) cmd[p++] = digest[i];
    be32(cmd + 2, p);                                    /* commandSize */

    uint8_t rsp[TPM_IO_MAX];
    int n = tpm_transact(cmd, p, rsp, sizeof(rsp));
    if (n < 0) return -1;
    return tpm_rc(rsp, n) == TPM_RC_SUCCESS ? 0 : -1;
}

/* Read one PCR from the SHA-256 bank into out32. */
static int tpm_pcr_read(uint32_t pcr, uint8_t out32[32]) {
    uint8_t cmd[20];
    uint32_t p = 0;
    be16(cmd + p, TPM_ST_NO_SESSIONS);         p += 2;
    be32(cmd + p, 0);                          p += 4;   /* size, patched */
    be32(cmd + p, TPM_CC_PCR_READ);            p += 4;
    /* TPML_PCR_SELECTION: count 1 */
    be32(cmd + p, 1);                          p += 4;
    be16(cmd + p, TPM_ALG_SHA256);             p += 2;
    cmd[p++] = 3;                                        /* sizeofSelect */
    cmd[p++] = 0; cmd[p++] = 0; cmd[p++] = 0;            /* bitmap, set below */
    cmd[p - 3 + (pcr / 8)] |= (uint8_t)(1u << (pcr % 8));
    be32(cmd + 2, p);

    uint8_t rsp[TPM_IO_MAX];
    int n = tpm_transact(cmd, p, rsp, sizeof(rsp));
    if (n < 0 || tpm_rc(rsp, n) != TPM_RC_SUCCESS) return -1;

    /* Parse: header(10) | pcrUpdateCounter(4) | TPML_PCR_SELECTION | TPML_DIGEST.
     * Walk the selection list, then the digest list, and copy the first digest. */
    uint32_t o = 10 + 4;
    if (o + 4 > (uint32_t)n) return -1;
    uint32_t sel_count = rd_be32(rsp + o); o += 4;
    for (uint32_t s = 0; s < sel_count; s++) {
        if (o + 3 > (uint32_t)n) return -1;
        uint8_t sz = rsp[o + 2];               /* sizeofSelect */
        o += 3 + sz;                           /* skip hash(2)+size(1)+bitmap */
    }
    if (o + 4 > (uint32_t)n) return -1;
    uint32_t dig_count = rd_be32(rsp + o); o += 4;
    if (dig_count < 1) return -1;
    if (o + 2 > (uint32_t)n) return -1;
    uint32_t dsz = ((uint32_t)rsp[o] << 8) | rsp[o + 1]; o += 2;
    if (dsz != 32 || o + 32 > (uint32_t)n) return -1;
    for (int i = 0; i < 32; i++) out32[i] = rsp[o + i];
    return 0;
}

/* ---- probe ---------------------------------------------------------------- */

int tpm_present(void) {
    if (!g_tpm) {
        ensure_tpm_tis_mapped();
        g_tpm = (volatile uint8_t *)TPM_TIS_BASE;
    }
    uint32_t idvid = tpm_r32(TPM_REG_DID_VID);
    if (idvid == 0xFFFFFFFFu || idvid == 0) return 0;
    /* A live TIS reports a valid status in ACCESS. */
    return (tpm_r8(TPM_REG_ACCESS) & ACCESS_VALID) ? 1 : 0;
}

/* ---- measurement ---------------------------------------------------------- */

static int name_eq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}

/* Fixed-length so kernel and host verifier agree byte-for-byte. */
static const char KERNEL_ID_TAG[] = "horus-measured-boot-v1";

/* Build H = SHA256( TAG || for each manifest entry: path || be32(size) || sha256 )
 * and extend it into PCR[8]. TAG excludes the trailing NUL. */
static int measure_kernel_identity(void) {
    static uint8_t ser[4096];
    uint32_t p = 0;

    for (uint32_t i = 0; KERNEL_ID_TAG[i]; i++) {
        if (p >= sizeof(ser)) return -1;
        ser[p++] = (uint8_t)KERNEL_ID_TAG[i];
    }
    const uint32_t ndig = BOOT_MODULE_DIGEST_COUNT;
    for (uint32_t d = 0; d < ndig; d++) {
        const struct boot_module_digest *e = &BOOT_MODULE_DIGESTS[d];
        for (uint32_t k = 0; e->path[k]; k++) {
            if (p >= sizeof(ser)) return -1;
            ser[p++] = (uint8_t)e->path[k];
        }
        if (p + 4 + 32 > sizeof(ser)) return -1;
        be32(ser + p, e->size); p += 4;
        for (int k = 0; k < 32; k++) ser[p++] = e->sha256[k];
    }

    uint8_t h[32];
    if (rust_sha256(ser, p, h) != 0) return -1;
    return tpm_pcr_extend(TPM_PCR_KERNEL_IDENTITY, h);
}

/* Extend PCR[9] with each verified boot module's SHA-256, iterating the manifest
 * in order so the measurement is deterministic regardless of GRUB's module tag
 * order. A manifest entry with no matching *verified* module present is skipped —
 * so a tampered (refused) module drops out of the PCR. */
static int measure_boot_modules(void) {
    const uint32_t ndig = BOOT_MODULE_DIGEST_COUNT;
    const uint32_t nmod = boot_module_count();
    for (uint32_t d = 0; d < ndig; d++) {
        const struct boot_module_digest *e = &BOOT_MODULE_DIGESTS[d];
        for (uint32_t m = 0; m < nmod; m++) {
            const struct boot_module *bm = boot_module_get(m);
            if (!bm || !bm->verified) continue;
            if (!name_eq(bm->name, e->path)) continue;
            if (tpm_pcr_extend(TPM_PCR_BOOT_MODULES, e->sha256) != 0) return -1;
            break;
        }
    }
    return 0;
}

static void print_hex32(const uint8_t *b) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        print_char(hexd[b[i] >> 4]);
        print_char(hexd[b[i] & 0xF]);
    }
}

void tpm_measured_boot(void) {
    if (!tpm_present()) {
        println("[tpm] no TPM present -- measured boot skipped");
        return;
    }
    if (!tpm_request_locality()) {
        println("[tpm] measured boot FAILED (locality)");
        return;
    }

    int ok = (tpm_startup() == 0)
          && (measure_kernel_identity() == 0)
          && (measure_boot_modules() == 0);

    if (!ok) {
        println("[tpm] measured boot FAILED (transport)");
        tpm_release_locality();
        return;
    }

    uint8_t pcr8[32], pcr9[32];
    if (tpm_pcr_read(TPM_PCR_KERNEL_IDENTITY, pcr8) != 0 ||
        tpm_pcr_read(TPM_PCR_BOOT_MODULES,   pcr9) != 0) {
        println("[tpm] measured boot FAILED (readback)");
        tpm_release_locality();
        return;
    }

    print("[tpm] PCR8="); print_hex32(pcr8);
    print(" PCR9=");      print_hex32(pcr9);
    println("");
    println("[tpm] measured boot OK");
    tpm_release_locality();
}
