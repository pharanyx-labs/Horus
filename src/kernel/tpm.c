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

#define TPM_CC_STARTUP           0x00000144u
#define TPM_CC_PCR_EXTEND        0x00000182u
/* Stage 2 (seal/unseal) command codes */
#define TPM_CC_CREATE_PRIMARY    0x00000131u
#define TPM_CC_CREATE            0x00000153u
#define TPM_CC_LOAD              0x00000157u
#define TPM_CC_UNSEAL            0x0000015Eu
#define TPM_CC_FLUSH_CONTEXT     0x00000165u
#define TPM_CC_START_AUTH_SESSION 0x00000176u
#define TPM_CC_POLICY_PCR        0x0000017Fu
#define TPM_CC_POLICY_GET_DIGEST 0x00000189u

/* Handles / algorithms for the sealing template */
#define TPM_RH_OWNER        0x40000001u
#define TPM_RH_NULL         0x40000007u
#define TPM_ALG_NULL        0x0010
#define TPM_ALG_ECC         0x0023
#define TPM_ALG_KEYEDHASH   0x0008
#define TPM_ALG_AES         0x0006
#define TPM_ALG_CFB         0x0043
#define TPM_ECC_NIST_P256   0x0003
#define TPM_SE_POLICY       0x01
#define TPM_SE_TRIAL        0x03
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
static int tpm_transact_once(const uint8_t *cmd, uint32_t cmd_len,
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

/* Transient TPM warnings that mean "ask again": the TPM is self-testing an
 * algorithm on first use (TESTING), yielded (YIELDED), or asked for a retry
 * (RETRY). Common right after a CreatePrimary triggers ECC/AES self-tests. */
#define TPM_RC_YIELDED   0x00000908u
#define TPM_RC_TESTING   0x0000090Au
#define TPM_RC_RETRY     0x00000922u

/* tpm_transact_once + bounded retry on the transient warnings above, so a caller
 * never has to think about first-use self-test timing. */
static int tpm_transact(const uint8_t *cmd, uint32_t cmd_len,
                        uint8_t *rsp, uint32_t rsp_cap) {
    for (int attempt = 0; attempt < 32; attempt++) {
        int n = tpm_transact_once(cmd, cmd_len, rsp, rsp_cap);
        if (n < 0) return n;
        uint32_t rc = tpm_rc(rsp, n);
        if (rc != TPM_RC_RETRY && rc != TPM_RC_TESTING && rc != TPM_RC_YIELDED)
            return n;
        for (volatile int d = 0; d < 100000; d++) __asm__ volatile("pause");
    }
    return -10;   /* still transient after many tries */
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
        ensure_tpm_tis_mapped(NULL);   /* kernel pml4; user pagedirs map it at creation */
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
        kmsg("tpm: no TPM present, measured boot skipped");
        return;
    }
    if (!tpm_request_locality()) {
        kmsg("tpm: measured boot FAILED (locality)");
        return;
    }

    int ok = (tpm_startup() == 0)
          && (measure_kernel_identity() == 0)
          && (measure_boot_modules() == 0);

    if (!ok) {
        kmsg("tpm: measured boot FAILED (transport)");
        tpm_release_locality();
        return;
    }

    uint8_t pcr8[32], pcr9[32];
    if (tpm_pcr_read(TPM_PCR_KERNEL_IDENTITY, pcr8) != 0 ||
        tpm_pcr_read(TPM_PCR_BOOT_MODULES,   pcr9) != 0) {
        kmsg("tpm: measured boot FAILED (readback)");
        tpm_release_locality();
        return;
    }

    kmsg_begin(); print("tpm: PCR8="); print_hex32(pcr8);
    print(" PCR9=");      print_hex32(pcr9);
    println("");
    kmsg("tpm: measured boot OK");
    tpm_release_locality();
}

/* ===========================================================================
 * Stage 2 — seal a secret under a PolicyPCR(PCR[8],PCR[9]) and unseal it.
 *
 * The TPM enforces the release policy: a secret sealed here comes back only from
 * a TPM whose live PCR[8]/PCR[9] match the values at seal time — i.e. a
 * measured-good boot of this exact image + module set. No HMAC/parameter-
 * encryption sessions are used (authorization is password/empty for the storage
 * hierarchy and a bare policy session for the unseal); the transport is the
 * in-process swtpm/QEMU channel. A hardware bus would want session parameter
 * encryption — noted as follow-up. The storage primary is recreated
 * deterministically from the Owner seed each boot, so nothing is stored in TPM
 * NV; only the (public,private) sealed blob is persisted (in the superblock,
 * stage 3).
 * ======================================================================== */

/* cursor writers */
static uint32_t put16(uint8_t *b, uint32_t p, uint16_t v) { be16(b + p, v); return p + 2; }
static uint32_t put32(uint8_t *b, uint32_t p, uint32_t v) { be32(b + p, v); return p + 4; }
static uint32_t putbuf(uint8_t *b, uint32_t p, const uint8_t *s, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) b[p + i] = s[i];
    return p + n;
}
/* password (empty) authorization area — 9 bytes */
static uint32_t put_pw_auth(uint8_t *b, uint32_t p) {
    p = put32(b, p, TPM_RS_PW);   /* authHandle */
    p = put16(b, p, 0);           /* nonce size */
    b[p++] = 0;                   /* sessionAttributes */
    p = put16(b, p, 0);           /* hmac size */
    return p;
}
/* TPML_PCR_SELECTION selecting PCR[8] and PCR[9] in the SHA-256 bank */
static uint32_t put_pcr_selection(uint8_t *b, uint32_t p) {
    p = put32(b, p, 1);                 /* count */
    p = put16(b, p, TPM_ALG_SHA256);    /* hash */
    b[p++] = 3;                         /* sizeofSelect */
    b[p++] = 0;                         /* PCR 0..7 */
    b[p++] = (uint8_t)((1u << (TPM_PCR_KERNEL_IDENTITY - 8)) |
                       (1u << (TPM_PCR_BOOT_MODULES  - 8)));   /* PCR 8..15 */
    b[p++] = 0;                         /* PCR 16..23 */
    return p;
}

/* Read a big-endian u16 with bounds check; returns 0 and sets *ok=0 on overrun. */
static uint16_t rd16(const uint8_t *b, uint32_t off, uint32_t len, int *ok) {
    if (off + 2 > len) { *ok = 0; return 0; }
    return (uint16_t)((b[off] << 8) | b[off + 1]);
}

/* StartAuthSession: trial (TPM_SE_TRIAL) or policy (TPM_SE_POLICY). */
static int tpm_start_session(uint8_t se_type, uint32_t *session) {
    static const uint8_t nonce[16] = {0};
    uint8_t cmd[64];
    uint32_t p = 0;
    p = put16(cmd, p, TPM_ST_NO_SESSIONS);
    p = put32(cmd, p, 0);                    /* size, patched */
    p = put32(cmd, p, TPM_CC_START_AUTH_SESSION);
    p = put32(cmd, p, TPM_RH_NULL);          /* tpmKey */
    p = put32(cmd, p, TPM_RH_NULL);          /* bind */
    p = put16(cmd, p, sizeof(nonce));        /* nonceCaller */
    p = putbuf(cmd, p, nonce, sizeof(nonce));
    p = put16(cmd, p, 0);                    /* encryptedSalt */
    cmd[p++] = se_type;                      /* sessionType */
    p = put16(cmd, p, TPM_ALG_NULL);         /* symmetric = NULL */
    p = put16(cmd, p, TPM_ALG_SHA256);       /* authHash */
    be32(cmd + 2, p);

    uint8_t rsp[256];
    int n = tpm_transact(cmd, p, rsp, sizeof(rsp));
    if (n < 0 || tpm_rc(rsp, n) != TPM_RC_SUCCESS || n < 14) return -1;
    *session = rd_be32(rsp + 10);            /* sessionHandle (handle area) */
    return 0;
}

/* PolicyPCR: bind the (trial or policy) session to the current PCR[8]/PCR[9]. */
static int tpm_policy_pcr(uint32_t session) {
    uint8_t cmd[64];
    uint32_t p = 0;
    p = put16(cmd, p, TPM_ST_NO_SESSIONS);
    p = put32(cmd, p, 0);
    p = put32(cmd, p, TPM_CC_POLICY_PCR);
    p = put32(cmd, p, session);              /* policySession (handle) */
    p = put16(cmd, p, 0);                    /* pcrDigest empty -> use current PCRs */
    p = put_pcr_selection(cmd, p);
    be32(cmd + 2, p);

    uint8_t rsp[64];
    int n = tpm_transact(cmd, p, rsp, sizeof(rsp));
    return (n >= 0 && tpm_rc(rsp, n) == TPM_RC_SUCCESS) ? 0 : -1;
}

/* PolicyGetDigest: read the accumulated policyDigest (from a trial session). */
static int tpm_policy_get_digest(uint32_t session, uint8_t out32[32]) {
    uint8_t cmd[32];
    uint32_t p = 0;
    p = put16(cmd, p, TPM_ST_NO_SESSIONS);
    p = put32(cmd, p, 0);
    p = put32(cmd, p, TPM_CC_POLICY_GET_DIGEST);
    p = put32(cmd, p, session);
    be32(cmd + 2, p);

    uint8_t rsp[128];
    int n = tpm_transact(cmd, p, rsp, sizeof(rsp));
    if (n < 0 || tpm_rc(rsp, n) != TPM_RC_SUCCESS) return -1;
    int ok = 1;
    uint16_t dsz = rd16(rsp, 10, (uint32_t)n, &ok);
    if (!ok || dsz != 32 || 12 + 32 > (uint32_t)n) return -1;
    for (int i = 0; i < 32; i++) out32[i] = rsp[12 + i];
    return 0;
}

/* Build the TPMT_PUBLIC of the ECC storage primary (restricted decrypt parent)
 * into b at p; returns the new cursor. Deterministic template -> deterministic
 * primary from the Owner seed. */
static uint32_t put_primary_public(uint8_t *b, uint32_t p) {
    p = put16(b, p, TPM_ALG_ECC);
    p = put16(b, p, TPM_ALG_SHA256);         /* nameAlg */
    p = put32(b, p, 0x00030072u);            /* fixedTPM|fixedParent|sensitiveDataOrigin
                                              * |userWithAuth|restricted|decrypt */
    p = put16(b, p, 0);                      /* authPolicy: none */
    /* TPMS_ECC_PARMS */
    p = put16(b, p, TPM_ALG_AES);            /* symmetric.algorithm */
    p = put16(b, p, 128);                    /* symmetric.keyBits */
    p = put16(b, p, TPM_ALG_CFB);            /* symmetric.mode */
    p = put16(b, p, TPM_ALG_NULL);           /* scheme */
    p = put16(b, p, TPM_ECC_NIST_P256);      /* curveID */
    p = put16(b, p, TPM_ALG_NULL);           /* kdf */
    /* unique TPMS_ECC_POINT: empty x,y */
    p = put16(b, p, 0);
    p = put16(b, p, 0);
    return p;
}

/* CreatePrimary(Owner) -> loaded parent handle. */
static int tpm_create_primary(uint32_t *parent) {
    uint8_t cmd[256];
    uint32_t p = 0;
    p = put16(cmd, p, TPM_ST_SESSIONS);
    p = put32(cmd, p, 0);
    p = put32(cmd, p, TPM_CC_CREATE_PRIMARY);
    p = put32(cmd, p, TPM_RH_OWNER);         /* primaryHandle (handle area) */
    p = put32(cmd, p, 9);                    /* authorizationSize */
    p = put_pw_auth(cmd, p);
    /* inSensitive: empty userAuth + empty data */
    p = put16(cmd, p, 4);                    /* TPM2B_SENSITIVE_CREATE size */
    p = put16(cmd, p, 0);                    /*   userAuth */
    p = put16(cmd, p, 0);                    /*   data */
    /* inPublic */
    uint32_t pub_sz_at = p; p = put16(cmd, p, 0);
    uint32_t pub_start = p;
    p = put_primary_public(cmd, p);
    be16(cmd + pub_sz_at, (uint16_t)(p - pub_start));
    p = put16(cmd, p, 0);                    /* outsideInfo */
    p = put32(cmd, p, 0);                    /* creationPCR: count 0 */
    be32(cmd + 2, p);

    uint8_t rsp[1024];
    int n = tpm_transact(cmd, p, rsp, sizeof(rsp));
    if (n < 0 || tpm_rc(rsp, n) != TPM_RC_SUCCESS || n < 14) return -1;
    *parent = rd_be32(rsp + 10);             /* objectHandle */
    return 0;
}

/* Create a keyedhash sealed object holding secret[32], gated by policyDigest. */
static int tpm_create_sealed(uint32_t parent, const uint8_t secret[32],
                             const uint8_t policy[32], struct tpm_sealed_blob *out) {
    uint8_t cmd[256];
    uint32_t p = 0;
    p = put16(cmd, p, TPM_ST_SESSIONS);
    p = put32(cmd, p, 0);
    p = put32(cmd, p, TPM_CC_CREATE);
    p = put32(cmd, p, parent);               /* parentHandle */
    p = put32(cmd, p, 9);                    /* authorizationSize */
    p = put_pw_auth(cmd, p);
    /* inSensitive: empty userAuth + data=secret[32] */
    p = put16(cmd, p, 2 + 2 + 32);           /* TPM2B_SENSITIVE_CREATE size */
    p = put16(cmd, p, 0);                    /*   userAuth */
    p = put16(cmd, p, 32);                   /*   data size */
    p = putbuf(cmd, p, secret, 32);
    /* inPublic: keyedhash, fixedTPM|fixedParent, authPolicy=policy, scheme NULL */
    uint32_t pub_sz_at = p; p = put16(cmd, p, 0);
    uint32_t pub_start = p;
    p = put16(cmd, p, TPM_ALG_KEYEDHASH);
    p = put16(cmd, p, TPM_ALG_SHA256);       /* nameAlg */
    p = put32(cmd, p, 0x00000012u);          /* fixedTPM|fixedParent (policy-gated) */
    p = put16(cmd, p, 32);                   /* authPolicy size */
    p = putbuf(cmd, p, policy, 32);
    p = put16(cmd, p, TPM_ALG_NULL);         /* scheme */
    p = put16(cmd, p, 0);                    /* unique: empty */
    be16(cmd + pub_sz_at, (uint16_t)(p - pub_start));
    p = put16(cmd, p, 0);                    /* outsideInfo */
    p = put32(cmd, p, 0);                    /* creationPCR: count 0 */
    be32(cmd + 2, p);

    uint8_t rsp[1024];
    int n = tpm_transact(cmd, p, rsp, sizeof(rsp));
    if (n < 0 || tpm_rc(rsp, n) != TPM_RC_SUCCESS) return -1;

    /* Response params start after header(10) + parameterSize(4). */
    int ok = 1;
    uint32_t o = 14;
    uint16_t priv_len = rd16(rsp, o, (uint32_t)n, &ok); o += 2;
    if (!ok || priv_len == 0 || priv_len > TPM_SEALED_PRIV_MAX || o + priv_len > (uint32_t)n) return -1;
    out->priv_len = priv_len;
    for (uint16_t i = 0; i < priv_len; i++) out->priv[i] = rsp[o + i];
    o += priv_len;
    uint16_t pub_len = rd16(rsp, o, (uint32_t)n, &ok); o += 2;
    if (!ok || pub_len == 0 || pub_len > TPM_SEALED_PUB_MAX || o + pub_len > (uint32_t)n) return -1;
    out->pub_len = pub_len;
    for (uint16_t i = 0; i < pub_len; i++) out->pub[i] = rsp[o + i];
    return 0;
}

/* Load a sealed blob under the parent -> object handle. */
static int tpm_load_sealed(uint32_t parent, const struct tpm_sealed_blob *in, uint32_t *obj) {
    uint8_t cmd[16 + TPM_SEALED_PRIV_MAX + TPM_SEALED_PUB_MAX + 16];
    uint32_t p = 0;
    p = put16(cmd, p, TPM_ST_SESSIONS);
    p = put32(cmd, p, 0);
    p = put32(cmd, p, TPM_CC_LOAD);
    p = put32(cmd, p, parent);
    p = put32(cmd, p, 9);
    p = put_pw_auth(cmd, p);
    p = put16(cmd, p, in->priv_len);
    p = putbuf(cmd, p, in->priv, in->priv_len);
    p = put16(cmd, p, in->pub_len);
    p = putbuf(cmd, p, in->pub, in->pub_len);
    be32(cmd + 2, p);

    uint8_t rsp[512];
    int n = tpm_transact(cmd, p, rsp, sizeof(rsp));
    if (n < 0 || tpm_rc(rsp, n) != TPM_RC_SUCCESS || n < 14) return -1;
    *obj = rd_be32(rsp + 10);
    return 0;
}

/* Unseal the object, authorized by a policy session already bound via PolicyPCR. */
static int tpm_do_unseal(uint32_t obj, uint32_t session, uint8_t out32[32]) {
    uint8_t cmd[64];
    uint32_t p = 0;
    p = put16(cmd, p, TPM_ST_SESSIONS);
    p = put32(cmd, p, 0);
    p = put32(cmd, p, TPM_CC_UNSEAL);
    p = put32(cmd, p, obj);                  /* itemHandle */
    p = put32(cmd, p, 9);                    /* authorizationSize */
    p = put32(cmd, p, session);              /* policy session handle */
    p = put16(cmd, p, 0);                    /* nonce */
    cmd[p++] = 0;                            /* sessionAttributes */
    p = put16(cmd, p, 0);                    /* hmac */
    be32(cmd + 2, p);

    uint8_t rsp[256];
    int n = tpm_transact(cmd, p, rsp, sizeof(rsp));
    if (n < 0 || tpm_rc(rsp, n) != TPM_RC_SUCCESS) return -1;
    int ok = 1;
    uint16_t dsz = rd16(rsp, 14, (uint32_t)n, &ok);   /* after header+parameterSize */
    if (!ok || dsz != 32 || 16 + 32 > (uint32_t)n) return -1;
    for (int i = 0; i < 32; i++) out32[i] = rsp[16 + i];
    return 0;
}

static void tpm_flush(uint32_t handle) {
    if (!handle) return;
    uint8_t cmd[16];
    uint32_t p = 0;
    p = put16(cmd, p, TPM_ST_NO_SESSIONS);
    p = put32(cmd, p, 0);
    p = put32(cmd, p, TPM_CC_FLUSH_CONTEXT);
    p = put32(cmd, p, handle);
    be32(cmd + 2, p);
    uint8_t rsp[32];
    (void)tpm_transact(cmd, p, rsp, sizeof(rsp));
}

/* Bring the TPM up far enough for a seal/unseal at storage-unlock time (which is
 * long after tpm_measured_boot released locality). Idempotent-ish: startup is
 * tolerant of already-started. Returns 0 on success. */
static int tpm_session_prep(void) {
    if (!tpm_present()) return -1;
    if (!tpm_request_locality()) return -1;
    if (tpm_startup() != 0) { tpm_release_locality(); return -1; }
    return 0;
}

int tpm_seal_secret(const uint8_t secret[32], struct tpm_sealed_blob *out) {
    if (tpm_session_prep() != 0) return -1;

    uint32_t parent = 0, trial = 0;
    uint8_t policy[32];
    int rc = -1;

    if (tpm_create_primary(&parent) != 0) { println("[tpm] seal: create_primary"); goto done; }
    if (tpm_start_session(TPM_SE_TRIAL, &trial) != 0) { println("[tpm] seal: start_session"); goto done; }
    if (tpm_policy_pcr(trial) != 0) { println("[tpm] seal: policy_pcr"); goto done; }
    if (tpm_policy_get_digest(trial, policy) != 0) { println("[tpm] seal: policy_get_digest"); goto done; }
    if (tpm_create_sealed(parent, secret, policy, out) != 0) { println("[tpm] seal: create_sealed"); goto done; }
    rc = 0;

done:
    if (trial)  tpm_flush(trial);
    if (parent) tpm_flush(parent);
    tpm_release_locality();
    return rc;
}

int tpm_unseal_secret(const struct tpm_sealed_blob *in, uint8_t secret_out[32]) {
    if (tpm_session_prep() != 0) return -1;

    uint32_t parent = 0, obj = 0, sess = 0;
    int rc = -1;

    if (tpm_create_primary(&parent) != 0) goto done;
    if (tpm_load_sealed(parent, in, &obj) != 0) goto done;
    if (tpm_start_session(TPM_SE_POLICY, &sess) != 0) goto done;
    if (tpm_policy_pcr(sess) != 0) goto done;
    /* The TPM releases the secret only if the live PCRs satisfy the sealed
     * policy; otherwise tpm_do_unseal returns non-zero and the secret is never
     * exposed. */
    if (tpm_do_unseal(obj, sess, secret_out) != 0) { sess = 0; goto done; }
    rc = 0;

done:
    /* A consumed policy session (continueSession=0) is auto-flushed by the TPM;
     * flush only if we did not reach a successful unseal. */
    if (sess)   tpm_flush(sess);
    if (obj)    tpm_flush(obj);
    if (parent) tpm_flush(parent);
    tpm_release_locality();
    return rc;
}

/* Test-only: change PCR[9] so a blob sealed against the earlier state stops
 * unsealing. Self-contained locality handling. */
void tpm_test_extend_boot_pcr(void) {
    uint8_t junk[32];
    for (int i = 0; i < 32; i++) junk[i] = (uint8_t)(0x5A + i);
    if (tpm_present() && tpm_request_locality()) {
        (void)tpm_pcr_extend(TPM_PCR_BOOT_MODULES, junk);
        tpm_release_locality();
    }
}

/* ---- round-trip self-test (TPM_SELFTEST build) ---------------------------- */

void tpm_seal_selftest(void) {
    if (!tpm_present()) { println("TPM_SEAL_SELFTEST: SKIP (no TPM)"); return; }

    uint8_t secret[32];
    for (int i = 0; i < 32; i++) secret[i] = (uint8_t)(0xA0 ^ i);

    struct tpm_sealed_blob blob;
    if (tpm_seal_secret(secret, &blob) != 0) { println("TPM_SEAL_SELFTEST: FAIL (seal)"); return; }

    uint8_t got[32];
    if (tpm_unseal_secret(&blob, got) != 0) { println("TPM_SEAL_SELFTEST: FAIL (unseal)"); return; }
    if (!rust_ct_eq(secret, got, 32)) { println("TPM_SEAL_SELFTEST: FAIL (mismatch)"); return; }

    /* Negative case — the enforcement that stage 3 rests on: perturb PCR[9], then
     * the very same blob must NO LONGER unseal (the TPM denies the PolicyPCR). If
     * it still unseals, the seal was not actually bound to the measurement and the
     * whole scheme is theatre — fail loudly. (Test build only; corrupting PCR[9]
     * here is harmless, nothing downstream consults it.) */
    uint8_t junk[32];
    for (int i = 0; i < 32; i++) junk[i] = (uint8_t)i;
    if (tpm_present() && tpm_request_locality()) {
        (void)tpm_pcr_extend(TPM_PCR_BOOT_MODULES, junk);
        tpm_release_locality();
    }
    uint8_t must_fail[32];
    if (tpm_unseal_secret(&blob, must_fail) == 0) {
        println("TPM_SEAL_SELFTEST: FAIL (unseal succeeded under wrong PCRs!)");
        return;
    }

    print("[tpm] sealed blob pub="); print_decimal(blob.pub_len);
    print(" priv="); print_decimal(blob.priv_len);
    println(" ; unseal correctly denied after PCR change");
    println("TPM_SEAL_SELFTEST: PASS");
}
