/* kusers.c -- user accounts + authentication: the user DB, Argon2id password
 * hashing, salted verification, the encrypted userdb persistence, and the
 * auth/sudo/passwd/useradd/userdel/rotate-keys syscall handlers. Owns the
 * user table. Split out of syscall.c. */
#include "syscall_internal.h"

static struct user_account users[MAX_USERS];
static int user_count = 0;
static uint32_t next_uid = 1000;

uint8_t kernel_pepper[16];

/* THE PEPPER IS NOT USED FOR ACCOUNT HASHES ANY MORE (SECURITY.md S62), and that is what makes
 * accounts able to survive a reboot at all.
 *
 * kernel_pepper is fresh random bytes every boot. It fed strong_password_hash
 * both when a password was set and when it was verified, so a hash from one boot
 * could never verify in the next -- WHATEVER it was stored in. docs/LIMITATIONS.md
 * 2.6 calls that reason 3, and calls it the one that shapes the fix: persisting
 * the table is not sufficient, or even meaningful, while the hash is boot-local.
 *
 * What replaces it is not a second secret but the volume: the table is sealed
 * under a key derived from disk_key (storage_users_save), which is itself sealed
 * under the TPM policy where there is a TPM. Encryption at rest is doing the job
 * the pepper was being asked to do, and unlike the pepper it also works on a
 * machine with no TPM -- the common case, and the reason an earlier revision of
 * 2.6 that proposed TPM-sealing the pepper was superseded.
 *
 * The per-user random salt stays, and is what stops one rainbow table covering
 * every account. kernel_pepper itself stays too: audit_chain_start still keys
 * the audit chain from it, which is per-boot on purpose. */
static const uint8_t account_pepper[16] = { 0 };

/* Has the on-disk table been consulted this boot? Set once, either by a
 * successful load or by seeding a volume that has none yet. */
static int g_users_restored = 0;

/* Set when the on-disk table is PRESENT but does not authenticate. Distinct from
 * "no table yet", and the distinction is the whole point: treating a bad tag as
 * an empty volume reseeds the compiled-in root/user accounts, which hands anyone
 * who can scribble on the region a downgrade to a known password. While this is
 * set every login is refused -- an account database that fails its own integrity
 * check is not a thing to guess around, and a machine that will not log anyone in
 * is a better outcome than one that logs in the wrong person. */
static int g_users_tampered = 0;

/* Write the table back. Silent when there is no volume: a diskless or
 * unformatted machine keeps the compiled-in accounts and loses them at
 * power-off, which is the documented fallback rather than a failure -- a
 * research prototype has to boot on a machine with no disk. */
void users_persist(void)
{
    if (storage_users_save(users, sizeof(users)) == 0) g_users_restored = 1;
}

/* UNLOCK, THEN IDENTIFY.
 *
 * The table lives inside the volume, so it cannot be consulted until the volume
 * opens -- which inverts the order docs/LIMITATIONS.md 2.6 describes: the
 * password is offered to the storage layer FIRST, and only then is the caller
 * identified against the table that unlocking made readable. That is sound
 * because storage_unlock authenticates: it succeeds only if the offered password
 * opens a key slot, which is an AEAD unwrap and fails closed on a wrong one.
 *
 * A wrong password simply leaves the volume shut and the table unrestored, and
 * the caller then fails verify_password against whatever is in RAM -- the same
 * refusal it would have got before, reached a different way.
 */
static void users_unlock_and_restore(const char *pw, size_t len)
{
    if (g_users_restored) return;
    if (storage_unlock(pw, len) != 0) return;      /* no volume, or wrong password */

    int rc = storage_users_load(users, sizeof(users));
    if (rc == -3) {
        /* Present and unauthentic. Do NOT reseed and do NOT write: preserve the
         * region so an operator can look at it, and refuse logins meanwhile. */
        g_users_tampered = 1;
        print("USERS: the on-disk account table failed its integrity check; "
              "logins refused\n");
        audit_log(AUDIT_AUTH, 0, 0, "user table integrity failure");
        return;
    }
    if (rc == 0) {
        g_users_restored = 1;
        /* Rebuild the RAM-only bookkeeping the table does not carry. */
        user_count = 0;
        next_uid   = 1000;
        for (int i = 0; i < MAX_USERS; i++) {
            if (!users[i].valid) continue;
            user_count++;
            if (users[i].uid >= next_uid) next_uid = users[i].uid + 1;
        }
    } else {
        /* rc == -2: the volume opened and carries no table yet, so this is its
         * first boot. Seed it from what users_init put in RAM so the NEXT boot
         * has something to load. Only -2 reaches here; a failed tag was handled
         * above and never reseeds. */
        users_persist();
    }
}
#ifdef USERS_PEPPER_PER_BOOT
/* CONTROL ARM -- never ship. Restores the per-boot pepper in account hashes, so
 * a password set in one boot cannot verify in the next however faithfully the
 * table was stored. See make smoke-users-persist-control. */
#define ACCOUNT_PEPPER kernel_pepper
#else
#define ACCOUNT_PEPPER account_pepper
#endif

static void generate_salt(uint8_t *salt, size_t len) {
    /* Per-password random salt drawn from the central CSPRNG (RDRAND/TSC-jitter
     * seeded), replacing the old predictable LCG-over-ticks generator. */
    secure_random_bytes(salt, len);
}

/* Password hash = Argon2id(password, salt || pepper), memory-hard.
 *
 * - Argon2id (RFC 9106) is the reviewed, memory-hard KDF, implemented in safe
 *   Rust (rust/src/argon2.rs) on the crate's own BLAKE2b and validated against
 *   the argon2-cffi reference vectors. It replaces PBKDF2-HMAC-SHA256: unlike
 *   PBKDF2, it forces an attacker to spend memory as well as time, defeating
 *   the cheap GPU/ASIC parallel brute force PBKDF2 is vulnerable to.
 * - The 16-byte per-boot kernel pepper is concatenated into the salt so an
 *   attacker who exfiltrates the user database alone still lacks a secret
 *   needed to mount an offline dictionary attack.
 * - The raw 32-byte tag is stored (PASS_HASH_LEN == 32), preserving full
 *   entropy. The 4 MiB scratch buffer is a kernel static; hashing runs
 *   non-preemptibly inside the syscall, so the single shared buffer is safe.
 */
static uint64_t argon2_scratch[ARGON2_M_COST_KIB * 128];

static void strong_password_hash(const char *password, const uint8_t *salt,
                                 const uint8_t *pepper, uint8_t *out_hash) {
    uint8_t combined_salt[PASS_SALT_LEN + 16];
    for (int i = 0; i < PASS_SALT_LEN; i++) combined_salt[i] = salt[i];
    for (int i = 0; i < 16; i++) combined_salt[PASS_SALT_LEN + i] = pepper[i];

    rust_argon2id_hash((const uint8_t *)password, kstrlen(password),
                       combined_salt, sizeof(combined_salt),
                       ARGON2_T_COST, ARGON2_M_COST_KIB, ARGON2_P_COST,
                       argon2_scratch, sizeof(argon2_scratch) / sizeof(argon2_scratch[0]),
                       out_hash, PASS_HASH_LEN);

    secure_zero(combined_salt, sizeof(combined_salt));
}

int kernel_argon2id(const uint8_t *pwd, size_t plen,
                    const uint8_t *salt, size_t salt_len,
                    uint8_t *out, size_t out_len)
{
    return rust_argon2id_hash(pwd, plen, salt, salt_len,
                              ARGON2_T_COST, ARGON2_M_COST_KIB, ARGON2_P_COST,
                              argon2_scratch,
                              sizeof(argon2_scratch) / sizeof(argon2_scratch[0]),
                              out, out_len);
}

int set_user_password(uint32_t uid, const char *new_password) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && users[i].uid == uid) {
            generate_salt(users[i].salt, PASS_SALT_LEN);
            strong_password_hash(new_password, users[i].salt, ACCOUNT_PEPPER,
                                 users[i].pass_hash);
            return 0;
        }
    }
    return -1;
}

static int verify_user_password(const char *name, const char *password) {
    struct user_account *u = NULL;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            int match = 1;
            for (size_t j = 0; j < 32 && name[j]; j++) {
                if (users[i].name[j] != name[j]) { match = 0; break; }
            }
            if (match && name[kstrlen(users[i].name)] == 0) {
                u = &users[i];
                break;
            }
        }
    }
    /* Run the same work whether or not the account exists, to deny an attacker
     * a timing oracle for username enumeration: always derive the (deliberately
     * expensive) Argon2id hash and run a constant-time compare. When the user is
     * absent we hash against a zero salt and compare the result against itself,
     * then discard the (necessarily "equal") outcome and fail. */
    static const uint8_t dummy_salt[PASS_SALT_LEN]; /* zero-initialized */
    uint8_t computed[PASS_HASH_LEN];
    const uint8_t *salt   = u ? u->salt      : dummy_salt;
    const uint8_t *expect = u ? u->pass_hash : computed;

    strong_password_hash(password, salt, ACCOUNT_PEPPER, computed);
    int eq = rust_ct_eq(computed, expect, PASS_HASH_LEN);
    return (u && eq) ? 1 : 0;
}

/* ---- The user database does not persist, and the mechanism that claimed to ----
 *
 * Deleted 2026-08-22: USERDB_MAGIC/TAG_LEN, compute_userdb_tag, userdb_tag_valid,
 * users_save_to_ramfs, users_load_from_ramfs, users_persist. Roughly ninety lines
 * that had never once done anything, for three independent reasons:
 *
 *   1. ramfs_write took no offset -- it memcpy'd to data[0] and set size = len on
 *      every call -- so of the four writes the save made, only the last survived.
 *      ramfs_read had no position either, so the load's sequential reads were
 *      equally broken.
 *   2. Nothing persisted the ramfs. ramfs_files[] is .bss; it dies at reboot. And
 *      users_load_from_ramfs was called exactly once, from users_init, at boot,
 *      when that table is still zeroed -- so it opened nothing and returned
 *      immediately, every boot, forever.
 *   3. Password hashes are BOOT-LOCAL by construction. kernel_pepper is fresh
 *      random every boot and feeds both strong_password_hash at set time and at
 *      verify time, so a hash from one boot cannot verify in the next whatever it
 *      is stored in. compute_userdb_tag MAC'd under the same pepper, so even a
 *      correctly written file could never have validated across a reboot.
 *
 * Any one of those alone made it dead; all three were present. Deleting is the
 * honest state -- accounts are seeded from the constants below on every boot and
 * useradd/userdel/passwd last until reboot. docs/LIMITATIONS.md 2.6 says so.
 *
 * Making it real is a separate change and it is the pepper that decides it, not
 * the storage: the pepper has to survive the reboot for a stored hash to mean
 * anything, which is why the plan is to TPM-seal it under PolicyPCR(8,9) exactly
 * as storage.c already seals the volume KEK. Note fs_superblock.kek_salt, which
 * excludes the pepper with the comment "must be reproducible across reboots from
 * the same pwd" -- the same conclusion, reached earlier, one field away. */

void users_init(void) {
    for (int i = 0; i < MAX_USERS; i++) {
        users[i].valid = 0;
        /* NOT left to the static zero-initialiser, which reads as slot 0 -- a
         * VALID index, and the one the formatting password owns. Every account
         * would then claim root's slot: an admin password change would revoke it
         * as the "old" slot and lock the machine's owner out of their own
         * volume. KEYSLOT_NONE is the only honest starting value, because an
         * account that has never had a password set has no slot. */
        users[i].keyslot = KEYSLOT_NONE;
    }
    user_count = 0;
    next_uid = 1000;

    /* Per-boot secret pepper from the central CSPRNG (RDRAND/TSC-jitter seeded),
     * replacing the predictable LCG-over-ticks generator. */
    secure_random_bytes(kernel_pepper, sizeof(kernel_pepper));

    /* Seed the tamper-evident audit chain now that its key (the pepper) exists,
     * before any audit_log() can fire from a syscall. */
    audit_chain_start();

    users[0].uid = 0;
    users[0].gid = 0;
    kstrcpy(users[0].name, "root");
    kstrcpy(users[0].home, "/");
    kstrcpy(users[0].shell, "/bin/shell");
    users[0].auth_fail_count = 0;
    users[0].auth_lockout_until = 0;
    users[0].valid = 1;

    set_user_password(0, "rootpass");
    user_count = 1;

    users[1].uid = 1000;
    users[1].gid = 100;
    kstrcpy(users[1].name, "user");
    kstrcpy(users[1].home, "/home/user");
    kstrcpy(users[1].shell, "/bin/shell");
    users[1].auth_fail_count = 0;
    users[1].auth_lockout_until = 0;
    users[1].valid = 1;
    set_user_password(1000, "password");
    user_count = 2;

    /* The load that used to sit here is gone with the rest of the path (see the
     * note above): it ran at exactly this point on every boot, against a .bss
     * table that is zeroed at exactly this point on every boot, and returned
     * without opening anything. The block below was written to cope with
     * whatever state it left the database in; that state is now simply the
     * seeded one, and the block is kept because it is still the thing that
     * guarantees the "user" account exists. */
    int dev_idx = -1;
    for (int ii = 0; ii < MAX_USERS; ii++) {
        if (users[ii].valid && kstrcmp(users[ii].name, "user") == 0) { dev_idx = ii; break; }
    }
    if (dev_idx < 0) {
        /* Account missing: create it with the default password and persist so
         * subsequent boots pick up the correct (possibly later changed) password.
         * Only runs on first boot or after a corrupted ramfs wipes the database. */
        for (int ii = 0; ii < MAX_USERS; ii++) if (!users[ii].valid) { dev_idx = ii; break; }
        if (dev_idx >= 0) {
            users[dev_idx].uid = 1000;
            users[dev_idx].gid = 100;
            kstrcpy(users[dev_idx].name, "user");
            kstrcpy(users[dev_idx].home, "/home/user");
            users[dev_idx].auth_fail_count = 0;
            users[dev_idx].auth_lockout_until = 0;
            kstrcpy(users[dev_idx].shell, "/bin/shell");
            users[dev_idx].valid = 1;
            user_count = dev_idx + 1;
            /* Pass uid 1000, not the slot index — set_user_password searches by
             * uid, not by position, so passing dev_idx would silently fail. */
            set_user_password(1000, "password");
        }
    }
    /* The old code had an unconditional set_user_password("password") here that
     * ran even when the account was loaded from ramfs with a changed password,
     * resetting it every reboot and making SYS_PASSWD useless for "user". */
}


/* Administrative authority over the user database: possession of CAP_USER, and
 * nothing else.
 *
 * This used to end `return tasks[get_current_task()].uid == 0;`. That fallback
 * was the last surviving piece of finding I-1 — ambient uid-0 authority running
 * parallel to the capability graph — and it outlived the fix because roadmap 0.2
 * swept `syscall.c` and `syscall_fs.c` for `uid != 0` gates and never reached
 * kusers.c. SECURITY.md S18, LIMITATIONS 1.2 and ARCHITECTURE G-2 all claimed it
 * was gone; SYS_USERADD / SYS_USERDEL / SYS_PASSWD are SC_NONE in the dispatch
 * table, so this function WAS the gate, and a ring-3 task at uid 0 holding no
 * capability at all could create accounts with an arbitrary uid/gid and reset
 * any other user's password. Since uid is the identity fs_server authorises
 * every file operation against (SYS_IPC_SENDER), authority over the account
 * table is authority over the filesystem's whole subject namespace.
 *
 * Nothing legitimate depended on it. CAP_USER is minted once in the primordial
 * root cnode (capability.c), delegated to `init` (kshell.c), propagated to a
 * child by do_spawn_inner only when the SPAWNER already holds it, and granted to
 * the elevated task h_sudo creates. So the shell, its children, and sudo all
 * still pass; what stops passing is a task that was never given the authority
 * and was relying on its uid to supply it.
 *
 * The slot-6 convention is itself unlovely — authority ought not depend on WHERE
 * a capability sits — but that is a separate change (audit H-6) and widening it
 * here would mean touching every CAPSLOT_* consumer at once. */
static int current_user_is_admin(void) {
    struct capability *c = cap_lookup(CAPSLOT_USER, CAP_USER, CAP_RIGHT_ALL);
    return c != NULL;
}

int do_useradd(uint32_t uid, uint32_t gid, const char *name, const char *initial_password) {
    if (!current_user_is_admin()) return -1;
    if (user_count >= MAX_USERS) return -2;
    if (kstrlen(name) == 0 || kstrlen(name) >= 32) return -3;

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            if (users[i].uid == uid) return -4;
            if (kstrcmp(users[i].name, name) == 0) return -5;
        }
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (!users[i].valid) {
            users[i].uid = uid;
            users[i].gid = gid;
            kstrcpy(users[i].name, name);
            kstrcpy(users[i].home, "/home/");
            size_t hlen = kstrlen(users[i].home);
            kstrcpy(users[i].home + hlen, name);
            kstrcpy(users[i].shell, "/bin/shell");
            users[i].auth_fail_count = 0;
            users[i].auth_lockout_until = 0;
            /* No slot yet, and stated rather than inherited: this record may be
             * a reused array entry whose previous owner had one, and a stale
             * index here would have the next password change revoke a slot that
             * now belongs to somebody else. do_passwd grants the real one. */
            users[i].keyslot = KEYSLOT_NONE;
            if (initial_password && *initial_password) {
                set_user_password(uid, initial_password);
            } else {
                /* No initial password supplied: lock the account by storing random
                 * bytes in pass_hash. Argon2id output is pseudorandom but derived
                 * from (password, salt, pepper) — storing arbitrary random bytes
                 * means no password can ever produce a match, so the account is
                 * inaccessible until an explicit SYS_PASSWD call sets a real hash.
                 * This closes the window where `useradd name` (empty password)
                 * followed by a crash or kill left a live account anyone could
                 * authenticate to with "". */
                generate_salt(users[i].salt, PASS_SALT_LEN);
                secure_random_bytes(users[i].pass_hash, PASS_HASH_LEN);
            }
            users[i].valid = 1;
            user_count++;
            if (uid >= next_uid) next_uid = uid + 1;
            /* No persist call: the account lives until reboot. The audit entry
             * below is the only durable record that it was ever created. */
            audit_log(AUDIT_USER_MGMT, uid, 0, "useradd");
            users_persist();
            return 0;
        }
    }
    return -6;
}

/* Read one account's public metadata into a KERNEL buffer; the handler copies it
 * out. Returns 1 when `out` was filled, 0 when `index` is past the last account,
 * and -1 when the caller holds no CAP_USER.
 *
 * THE GATE IS THE SAME ONE useradd/userdel/passwd USE, and it is a capability
 * rather than a uid: current_user_is_admin() asks cap_lookup for CAP_USER at
 * CAPSLOT_USER and nothing else. That matters here more than it looks, because
 * the temptation with a read-only call is to leave it ungated on the grounds
 * that names are not secrets. They are not, but "no ambient authority" is a
 * property of the SYSTEM, not of each syscall argued individually, and an
 * ungated enumeration is exactly the ambient path CLAUDE.md exists to refuse:
 * every task would learn the account table by asking.
 *
 * THE INDEX IS DENSE OVER VALID ACCOUNTS, not an array position. The array is
 * sparse -- do_userdel clears `valid` and leaves the slot -- so exporting array
 * positions would export MAX_USERS to every caller and make a hole in the middle
 * of the table look like the end of it. A caller loops from 0 until this returns
 * 0 and never needs to know how the kernel stores accounts.
 *
 * FIELDS ARE COPIED ONE AT A TIME, deliberately, rather than the record being
 * memcpy'd into a smaller struct. user_account also holds pass_hash, salt,
 * keyslot and the lockout counters; a struct-shaped copy would export whatever
 * happened to be laid out inside the exported extent the day somebody added a
 * field. This way an addition to user_account cannot leak by adjacency. */
int do_userlist(uint32_t index, struct user_entry *out) {
#ifndef USERLIST_UNGATED
    if (!current_user_is_admin()) return -1;
#endif
    if (!out) return -1;

    uint32_t seen = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (!users[i].valid) continue;
        if (seen == index) {
            out->uid = users[i].uid;
            out->gid = users[i].gid;
            kstrcpy(out->name, users[i].name);
            kstrcpy(out->home, users[i].home);
            return 1;
        }
        seen++;
    }
    return 0;
}

int do_userdel(uint32_t uid) {
    if (!current_user_is_admin()) return -1;
    if (uid == 0) return -2;

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && users[i].uid == uid) {
            users[i].valid = 0;
            user_count--;
            users_persist();
            return 0;
        }
    }
    return -3;
}

/* The account record for a uid, or NULL. Wanted by do_passwd, which has to write
 * the key-slot index back into the account that owns it. */
static struct user_account *find_user_by_uid(uint32_t uid) {
    for (int i = 0; i < MAX_USERS; i++)
        if (users[i].valid && users[i].uid == uid) return &users[i];
    return NULL;
}

/* Set an account's password, and make that password OPEN THE VOLUME.
 *
 * ---- WHY A PASSWORD CHANGE TOUCHES THE DISK AT ALL ------------------------
 *
 * A Horus volume is sealed to key slots (**S61**): up to HORUS_KEYSLOTS wraps of
 * the same disk_key, each under a KEK derived from one password. h_auth calls
 * users_unlock_and_restore(typed_password) BEFORE it consults the account table,
 * because on a sealed volume the table it would otherwise read is the
 * compiled-in one users_init seeded. So an account with no slot cannot be the
 * FIRST login after a power cycle: its password opens nothing, the persisted
 * table is never loaded, the account is not found, and the login is refused. It
 * works perfectly on a machine somebody else has already opened, which is what
 * made this survivable and hard to see.
 *
 * That was docs/LIMITATIONS.md 2.6b. `storage_keyslot_add` has existed since S61
 * and its only caller was a selftest; `user_account.keyslot` has existed with a
 * comment saying what it is for and was assigned in exactly one place, also a
 * selftest. The mechanism and the field were both already here. This is the
 * caller.
 *
 * ---- THE ORDER IS THE FAIL-SAFE, AND IT IS DELIBERATE ---------------------
 *
 * The slot is added BEFORE the hash is changed, and the account's OLD slot is
 * removed only after the new one is written. Three consequences, each of which
 * is the reason for it:
 *
 *   - A failure to grant a slot changes NOTHING. The old password still works
 *     and still opens the volume, and the caller is told the change did not
 *     happen. The alternative -- set the hash, then fail to grant -- produces an
 *     account whose password was accepted and which cannot log in after a
 *     reboot, which is 2.6b again with a success code in front of it.
 *   - We never dip to one active slot, so storage_keyslot_remove's refusal to
 *     drop the last one cannot strand us mid-change.
 *   - A crash between the add and the remove LEAKS a slot rather than losing
 *     one. Two passwords opening the volume is recoverable; none is not.
 *
 * ---- WHAT IS NOT A FAILURE ------------------------------------------------
 *
 * Changing your OWN password takes storage_rekey, not a new slot: the slot this
 * boot opened is already yours, and re-sealing it in place is what keeps every
 * other user working (a second slot would leave the old password valid). The
 * index is recorded here so a later admin change can revoke it.
 *
 * And on a machine with NO PERSISTENT VOLUME -- the ephemeral RAM vdisk, which
 * is every diskless boot -- there is no slot to grant and none is wanted: the
 * volume does not outlive the boot, and the account works from the RAM table for
 * as long as it exists. Refusing there would break every diskless useradd.
 */
int do_passwd(uint32_t target_uid, const char *new_password) {
    uint32_t my_uid = tasks[get_current_task()].uid;
    int is_admin = current_user_is_admin();

    if (!is_admin && my_uid != target_uid) return -1;

    struct user_account *u = find_user_by_uid(target_uid);
    if (!u) return -1;

    size_t plen = kstrlen(new_password);

    if (target_uid == my_uid) {
        /* Re-wrap disk_key under the new KEK so storage_unlock(new_password)
         * succeeds on the next boot. Without it the on-disk wrap still requires
         * the old password and the volume is unopenable by its owner. */
        int rc = set_user_password(target_uid, new_password);
        if (rc != 0) return rc;
        storage_rekey(new_password, plen);
        /* Record which slot is ours, so an admin changing this password later
         * can revoke exactly it. storage_unlocked_slot() is the slot the login
         * that started this session opened. */
        if (storage_volume_is_persistent()) u->keyslot = storage_unlocked_slot();
    } else {
        uint32_t fresh = KEYSLOT_NONE;
#ifdef PASSWD_NO_KEYSLOT
        /* CONTROL ARM -- never ship. The pre-2026-09-02 behaviour: an admin sets
         * another account's password and no key slot is granted, so the password
         * opens the account and not the VOLUME. The account then works only on a
         * machine somebody else has already unlocked, which is
         * docs/LIMITATIONS.md 2.6b exactly. Everything else here is unchanged --
         * the hash is still set and the call still reports success -- because the
         * defect was never a failure, it was a success that left out the half
         * nobody could see. See make smoke-installer-accounts-control. */
#else
        if (storage_volume_is_persistent()) {
            uint32_t idx = 0;
            if (storage_keyslot_add(new_password, plen, target_uid, &idx) != 0) {
                /* Nothing has changed yet. Say so rather than setting a password
                 * that cannot open the machine after a reboot. */
                audit_log(AUDIT_USER_MGMT, target_uid, -1, "passwd: no key slot available");
                return -6;
            }
            fresh = idx;
        }
#endif

        int rc = set_user_password(target_uid, new_password);
        if (rc != 0) {
            if (fresh != KEYSLOT_NONE) storage_keyslot_remove(fresh);   /* unwind */
            return rc;
        }

        if (fresh != KEYSLOT_NONE) {
            uint32_t old = u->keyslot;
            u->keyslot = fresh;
            /* Now, and only now, is the old password's slot spent. */
            if (old != KEYSLOT_NONE && old != fresh) storage_keyslot_remove(old);
        }
    }

    users_persist();
    return 0;
}


static struct user_account *find_user_by_name(const char *name) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && kstrlen(users[i].name) == kstrlen(name)) {
            int match = 1;
            for (size_t j = 0; name[j]; j++) {
                if (users[i].name[j] != name[j]) { match = 0; break; }
            }
            if (match) return &users[i];
        }
    }
    return NULL;
}

static int verify_password(const char *name, const char *pass) {
    return verify_user_password(name, pass);
}



void h_auth(struct interrupt_frame64 *r) {
    uint32_t now = get_system_ticks();

    char uname[32];
    char upass[32];
    if (copy_from_user(uname, (void*)(addr_t)r->rbx, 31) != 0 ||
        copy_from_user(upass, (void*)(addr_t)r->rcx, 31) != 0) {
        r->rax = (uint32_t)SYS_ERR_FAULT;
        return;
    }
    uname[31] = 0;
    upass[31] = 0;

    /* Global anti-spray cooldown: refuse all auth attempts kernel-wide
     * while it is active, so cycling usernames cannot dodge per-account
     * lockout. Policy + arithmetic live in rust/src/auth.rs. */
    /* An unauthentic account table refuses every login, before any password is
     * looked at. See g_users_tampered. */
    if (g_users_tampered) {
        secure_zero(uname, sizeof(uname));
        secure_zero(upass, sizeof(upass));
        r->rax = (uint32_t)SYS_ERR_AUTH;
        return;
    }

    if (rust_auth_global_locked(now)) {
        secure_zero(uname, sizeof(uname));
        secure_zero(upass, sizeof(upass));
        r->rax = (uint32_t)SYS_ERR_AUTH;
        return;
    }

    /* Open the volume with this password first, so the table consulted below is
     * the PERSISTED one rather than the compiled-in defaults users_init seeded.
     * No-op after the first successful login of a boot, and a no-op on a machine
     * with no volume -- see users_unlock_and_restore. */
    users_unlock_and_restore(upass, kstrlen(upass));

    struct user_account *u = find_user_by_name(uname);
    if (u && rust_auth_is_locked(u->auth_lockout_until, now)) {
        secure_zero(uname, sizeof(uname));
        secure_zero(upass, sizeof(upass));
        r->rax = (uint32_t)SYS_ERR_AUTH;
        return;
    }

    if (verify_password(uname, upass)) {
        rust_auth_global_on_success();
        if (u) {
            u->auth_fail_count = 0;
            u->auth_lockout_until = 0;


            tasks[get_current_task()].uid = u->uid;
            tasks[get_current_task()].gid = u->gid;


            {
                char *mat = upass;
                size_t mlen = kstrlen(upass);
                derive_and_store_user_file_key(u->uid, mat, mlen);
                /* Unlock ATA storage (or format+seal on first boot).
                 * Uses the same password: same Argon2id input, different
                 * salt (kek_salt vs login salt||pepper) → independent keys. */
                storage_unlock(mat, mlen);
            }

            if (r->rdx) {
                uint32_t uid = u->uid;
                copy_to_user((void*)(addr_t)r->rdx, &uid, sizeof(uid));
            }
            audit_log(AUDIT_AUTH, 0, 0, "login success");
        }
        r->rax = 0;
    } else {
        rust_auth_global_on_failure(now);
        if (u) {
            uint32_t new_count = u->auth_fail_count;
            uint64_t new_lockout = 0;
            rust_auth_on_failure(u->auth_fail_count, now, &new_count, &new_lockout);
            u->auth_fail_count = new_count;
            if (new_lockout) u->auth_lockout_until = (uint32_t)new_lockout;
        }
        audit_log(AUDIT_AUTH, 0, -1, "login failure");
        r->rax = (uint32_t)SYS_ERR_AUTH;
    }
    /* Don't leave the cleartext password (and username) sitting in the
     * kernel stack frame after authentication completes. */
    secure_zero(uname, sizeof(uname));
    secure_zero(upass, sizeof(upass));
}

/* SYS_SUDO: re-auth the current user, then spawn an armed program as uid 0. */
void h_sudo(struct interrupt_frame64 *r) {
    uint32_t now = get_system_ticks();
    struct user_account *cur_user = NULL;
    uint32_t cur_uid = tasks[get_current_task()].uid;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid && users[i].uid == cur_uid) {
            cur_user = &users[i];
            break;
        }
    }
    if (rust_auth_global_locked(now)) {
        r->rax = (uint32_t)SYS_ERR_AUTH;
        return;
    }
    if (cur_user && rust_auth_is_locked(cur_user->auth_lockout_until, now)) {
        r->rax = (uint32_t)SYS_ERR_AUTH;
        return;
    }

    char upass[32];
    if (copy_from_user(upass, (void*)(addr_t)r->rbx, 31) != 0) {
        secure_zero(upass, sizeof(upass));
        r->rax = (uint32_t)SYS_ERR_FAULT;
        return;
    }
    upass[31] = 0;

    struct user_account *cur = cur_user;
    if (!cur) {
        uint32_t cur_uid2 = tasks[get_current_task()].uid;
        for (int i = 0; i < MAX_USERS; i++) {
            if (users[i].valid && users[i].uid == cur_uid2) {
                cur = &users[i];
                break;
            }
        }
    }
    if (!cur) {
        secure_zero(upass, sizeof(upass));
        r->rax = (uint32_t)SYS_ERR_NOENT;
        return;
    }

    if (!verify_password(cur->name, upass)) {
        rust_auth_global_on_failure(now);
        if (cur_user) {
            uint32_t new_count = cur_user->auth_fail_count;
            uint64_t new_lockout = 0;
            rust_auth_on_failure(cur_user->auth_fail_count, now, &new_count, &new_lockout);
            cur_user->auth_fail_count = new_count;
            if (new_lockout) cur_user->auth_lockout_until = (uint32_t)new_lockout;
        }
        secure_zero(upass, sizeof(upass));
        r->rax = (uint32_t)SYS_ERR_AUTH;
        return;
    }
    rust_auth_global_on_success();
    if (cur_user) {
        cur_user->auth_fail_count = 0;
        cur_user->auth_lockout_until = 0;
    }


    {
        char *mat = upass;
        size_t mlen = kstrlen(upass);
        derive_and_store_user_file_key(cur->uid, mat, mlen);

    }
    /* Password material is no longer needed past key derivation; clear it
     * from the kernel stack frame on every remaining exit path. */
    secure_zero(upass, sizeof(upass));

    /* Nothing to elevate. NOENT ("no such object") rather than INVAL: the
     * argument was not invalid, it was correct — the caller authenticated. What
     * is missing is an armed image to spawn. Reporting that as "invalid
     * argument" told a user who had just typed the right password that their
     * password was the problem.
     *
     * Audited separately, and NOT as a success. The audit entry used to be
     * written above this check, so a sudo that granted no privilege at all —
     * because there was nothing to spawn — still logged "sudo success". An
     * auditor would read a successful elevation that never happened. The
     * credential use is worth recording either way, so record what it was. */
    /* The armed image and the sudo are SEPARATE syscalls, so this is the one
     * consumer of the staging that cannot be inside the arming task's bracket.
     * Take the lock for the consume alone -- it stops an arm landing underneath
     * this spawn -- and let do_spawn's owner check ([G-11], loader.c) decide
     * whether the image is this caller's to elevate. Before that check, a task
     * that authenticated correctly could be made to spawn ANOTHER task's image
     * at uid 0: the password proved who was asking, and nothing proved what was
     * being asked for. */
    spawn_stage_acquire();
    if (!program_armed) {
        spawn_stage_release();
        audit_log(AUDIT_SUDO, 0, 0, "sudo auth ok, no image armed (nothing elevated)");
        r->rax = (uint32_t)SYS_ERR_NOENT;
        return;
    }
    if (!staged_image_owned_by_current()) {
        spawn_stage_release();
        /* Audited as a refusal, not as a failure: a correct password that was
         * about to elevate somebody else's program is the interesting event. */
        audit_log(AUDIT_SUDO, 0, (uint32_t)staged_owner_task,
                  "sudo refused: armed image belongs to another task");
        r->rax = (uint32_t)SYS_ERR_PERM;
        return;
    }

    /* CHARGED TO THE CALLER, not to the kernel reserve. SYS_SUDO is ring-3
     * initiated -- the shell asks for it, holding its own CAP_UNTYPED -- so the
     * task it creates is the caller's to pay for, exactly as SYS_SPAWN's is
     * (S57). Routing it through the kernel reserve instead would have been the
     * easy line and would have been wrong twice: the reserve is sized at exactly
     * MAX_TASKS cspaces on the assumption that it is drawn on ONCE PER SLOT at
     * boot, and repeated sudo into recycled slots is not that; and a task whose
     * cspace came from the reserve, occupying a slot whose next occupant is
     * charged elsewhere, is the sort of cross-region tenancy a future
     * untyped-region reset would have to reason about. Keeping every post-boot
     * creation on the caller's region means kernel-initiated creation is boot
     * only, into fresh slots, and no kernel task's cspace ever lives in a
     * delegated region. */
    uint32_t sudo_ut;
    if (spawn_untyped_region_for(get_current_task(), &sudo_ut) != 0) {
        spawn_stage_release();
        audit_log(AUDIT_SUDO, 0, 0, "sudo refused: caller holds no CAP_UNTYPED");
        r->rax = (uint32_t)SYS_ERR_PERM;
        return;
    }
    int pid = do_spawn_charged(0, sudo_ut);
    spawn_stage_release();
    if (pid > 0) {
        tasks[pid].uid = 0;
        tasks[pid].gid = 0;

        /* Allocate the three fresh serials BEFORE taking cap_lock:
         * cap_alloc_fresh_serial() grabs cap_lock itself and the lock
         * is not recursive, so calling it inside the locked region
         * (as this path previously did) deadlocks the kernel on the
         * first sudo. Same ordering do_spawn uses. */
        uint32_t s3 = cap_alloc_fresh_serial();
        uint32_t s6 = cap_alloc_fresh_serial();
        uint32_t s7 = cap_alloc_fresh_serial();

        spin_lock(&cap_lock);
        tasks[pid].cspace[3].type   = CAP_FRAME;
        /* Least privilege: a memory frame needs only read/write/execute,
         * not the mint/revoke/grant/audit bits CAP_RIGHT_ALL carried.
         * Mask comes from rust/src/auth.rs (single source of truth). */
        tasks[pid].cspace[3].rights = rust_sudo_frame_rights();
        tasks[pid].cspace[3].object = USER_VIRT_BASE;
        tasks[pid].cspace[3].badge  = 0;
        tasks[pid].cspace[3].serial = s3;
        tasks[pid].cspace[3].generation = rust_lineage_current(s3); /* finding 3.3 */

        tasks[pid].cspace[6].type   = CAP_USER;
        tasks[pid].cspace[6].rights = CAP_RIGHT_ALL;
        tasks[pid].cspace[6].object = 0;
        tasks[pid].cspace[6].badge  = 0xC0DE0006U;
        tasks[pid].cspace[6].serial = s6;
        tasks[pid].cspace[6].generation = rust_lineage_current(s6); /* finding 3.3 */

        tasks[pid].cspace[7].type   = CAP_TCB;
        tasks[pid].cspace[7].rights = CAP_RIGHT_ALL;
        tasks[pid].cspace[7].object = pid;
        tasks[pid].cspace[7].badge  = 0;
        tasks[pid].cspace[7].serial = s7;
        tasks[pid].cspace[7].generation = rust_lineage_current(s7); /* finding 3.3 */
        spin_unlock(&cap_lock);
        audit_log(AUDIT_SUDO, 0, (uint32_t)pid, "sudo success: spawned uid 0");
    } else {
        audit_log(AUDIT_SUDO, 0, 0, "sudo auth ok, spawn failed (nothing elevated)");
    }
    r->rax = pid;
}

/* SYS_GET_PASS: read a line with masked echo; scrubs the scratch buffer. */
void h_get_pass(struct interrupt_frame64 *r) {
    void *user_buf = (void *)(addr_t)r->rbx;
    uint32_t max_len = r->rcx;
    if (max_len > 127) max_len = 127;

    /* Fail closed while a ring-3 console server owns the serial UART (see
     * h_get_line): the kernel must not race the owner reading a typed password. */
    if (console_hw_owned()) { r->rax = (uint32_t)-1; return; }

    char line[128];
    uint32_t len = 0;
    char ch;

    while (len < max_len) {
        ch = console_getc();

        if (ch == '\r' || ch == '\n') {
            print("\n");
            break;
        }
        if (ch == '\b' || ch == 0x7F) {
            if (len > 0) { len--; print("\b \b"); }
            continue;
        }
        if ((unsigned char)ch < 32) continue;

        print("*");
        line[len++] = ch;
    }
    line[len] = 0;

    if (copy_to_user(user_buf, line, len + 1) != 0) {
        for (uint32_t i = 0; i < 128; i++) line[i] = 0;
        r->rax = -1;
        return;
    }

    for (uint32_t i = 0; i < 128; i++) line[i] = 0;

    r->rax = len;
}

/* SYS_READ_AUDIT: copy the audit ring buffer to userspace.
 * Capability (slot 7, READ, type CAP_AUDIT) is enforced centrally by the table. */

void h_useradd(struct interrupt_frame64 *r) {
    uint32_t uid = r->rbx;
    uint32_t gid = r->rcx;
    char name[32];
    if (copy_from_user(name, (void*)(addr_t)r->rdx, 31) != 0) {
        r->rax = -1; return;
    }
    name[31] = 0;
    r->rax = do_useradd(uid, gid, name, "");
}
void h_userdel(struct interrupt_frame64 *r) {
    r->rax = do_userdel(r->rbx);
}
/* SYS_USERLIST: one account's public metadata. SC_NONE in the table with the
 * capability tested in do_userlist, matching useradd/userdel/passwd -- the four
 * account calls answer to one gate written once.
 *
 * THE BUFFER IS FILLED IN THE KERNEL AND COPIED ONCE. do_userlist writes a
 * kernel-local struct and this copies it out, so a user pointer is never handed
 * to code that walks the account table; and the copy is skipped entirely unless
 * do_userlist returned 1, so a refused or past-the-end call writes nothing to
 * ring 3 at all. A caller cannot tell an empty index from a refusal by looking
 * at its buffer, which is the direction that has to fail closed. */
void h_userlist(struct interrupt_frame64 *r) {
    struct user_entry e;
    /* ZEROED BEFORE IT IS FILLED, and this is not defensive habit. kstrcpy
     * terminates the string and leaves the rest of name[32]/home[64] as it
     * found it, and copy_to_user copies sizeof(e) -- so without this, every
     * byte of this stack frame past each string is handed to ring 3. A short
     * account name would export whatever the previous kernel call left there. */
    secure_zero(&e, sizeof(e));
    int rc = do_userlist((uint32_t)r->rbx, &e);
    if (rc != 1) { r->rax = (uint32_t)(rc < 0 ? SYS_ERR_PERM : 0); return; }
    if (copy_to_user((void *)(addr_t)r->rcx, &e, sizeof(e)) != 0) {
        r->rax = (uint32_t)SYS_ERR_FAULT;
        return;
    }
    r->rax = 1;
}
void h_passwd(struct interrupt_frame64 *r) {
    uint32_t target = r->rbx;
    char newpass[32];
    if (copy_from_user(newpass, (void*)(addr_t)r->rcx, 31) != 0) {
        r->rax = -1; return;
    }
    newpass[31] = 0;
    r->rax = do_passwd(target, newpass);
    secure_zero(newpass, sizeof(newpass));
}

/* SYS_ROTATE_KEYS (36): slot-8 READ, type CAP_CONSOLE enforced by the table. */
void h_rotate_keys(struct interrupt_frame64 *r) {
    r->rax = (uint32_t)do_rotate_keys();
}

/* FS ops (38-45): authority is the per-call dir/file capability, checked inside
 * the sys_fs_* helpers (slot is an argument, so not table-expressible). */


#ifdef USERS_PERSIST_SELFTEST
/* Accounts survive a reboot (docs/LIMITATIONS.md 2.6).
 *
 * TWO BOOTS ON ONE DISK. Phase is read off the volume: boot 1 finds no such
 * account and creates one, boot 2 finds it and checks its password still
 * verifies. No boot counter, and nothing in RAM decides which phase it is.
 *
 * BOTH DIRECTIONS ON BOOT 2, because "the password verifies" alone is satisfied
 * by a kernel that accepts everything -- which is exactly what a table restored
 * as all-zero salts and hashes could look like. The wrong password must be
 * refused by the same restored record.
 */
#define UPS_ROOT_PW  "rootpass"
#define UPS_NAME     "persisted"
#define UPS_PW       "persist-correct-horse"
#define UPS_WRONG_PW "persist-wrong-horse"

void users_persist_selftest(void)
{
#ifdef USERS_TAMPER_INJECT
    /* Boot 2 under the tamper arm: scribble on the sealed table before it is
     * read, as an attacker with disk access would. The table is PRESENT and
     * unauthentic -- the case that must never be mistaken for "no table yet",
     * because reseeding there restores the compiled-in root password. */
    {
        struct user_account *pre = find_user_by_name(UPS_NAME);
        (void)pre;
        if (storage_users_corrupt_for_test() != 0) {
            print("USERS_SELFTEST: FAIL could-not-inject-tamper\n"); return;
        }
        users_unlock_and_restore(UPS_ROOT_PW, kstrlen(UPS_ROOT_PW));
        if (!g_users_tampered) {
            print("USERS_SELFTEST: FAIL tampered-table-was-accepted\n"); return;
        }
        if (find_user_by_name(UPS_NAME)) {
            print("USERS_SELFTEST: FAIL tampered-table-still-restored-an-account\n"); return;
        }
        print("USERS_SELFTEST: TAMPER-REFUSED\n");
        return;
    }
#endif
    users_unlock_and_restore(UPS_ROOT_PW, kstrlen(UPS_ROOT_PW));

    struct user_account *u = find_user_by_name(UPS_NAME);
    if (!u) {
        /* Boot 1 -- create the account and push the table to disk. */
        int slot = -1;
        for (int i = 0; i < MAX_USERS; i++) if (!users[i].valid) { slot = i; break; }
        if (slot < 0) { print("USERS_SELFTEST: FAIL no-free-user-slot\n"); return; }
        users[slot].uid = 4242;
        users[slot].gid = 4242;
        kstrcpy(users[slot].name,  UPS_NAME);
        kstrcpy(users[slot].home,  "/");
        kstrcpy(users[slot].shell, "/bin/shell");
        users[slot].auth_fail_count = 0;
        users[slot].auth_lockout_until = 0;
        users[slot].keyslot = KEYSLOT_NONE;
        users[slot].valid = 1;
        user_count++;
        if (set_user_password(4242, UPS_PW) != 0) {
            print("USERS_SELFTEST: FAIL set-password\n"); return;
        }
        /* It must verify NOW, in the boot that set it -- otherwise a boot-2
         * failure cannot be told from "never worked". */
        if (!verify_password(UPS_NAME, UPS_PW)) {
            print("USERS_SELFTEST: FAIL password-does-not-verify-in-the-boot-that-set-it\n");
            return;
        }
        users_persist();
        if (!g_users_restored) { print("USERS_SELFTEST: FAIL table-not-written\n"); return; }
        print("USERS_SELFTEST: WROTE\n");
        return;
    }

    /* Boot 2 -- the account came back off the disk. */
    if (u->uid != 4242) { print("USERS_SELFTEST: FAIL restored-uid-wrong\n"); return; }
    if (!verify_password(UPS_NAME, UPS_PW)) {
        print("USERS_SELFTEST: FAIL hash-did-not-survive-the-reboot\n");
        return;
    }
    if (verify_password(UPS_NAME, UPS_WRONG_PW)) {
        print("USERS_SELFTEST: FAIL wrong-password-accepted\n");
        return;
    }
    print("USERS_SELFTEST: PASS\n");
}
#endif
