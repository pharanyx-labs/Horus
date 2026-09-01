/* The Horus installer: the program that lays a system down on a bare disk.
 *
 * ---- WHAT THIS IS, IN AUTHORITY TERMS -------------------------------------
 *
 * It is not a user interface with a formatting step in it. It is the one task in
 * the system holding CAP_STORAGE_FORMAT, and everything else here -- the
 * screens, the confirmation, the password field -- exists to decide whether to
 * exercise that capability once. Read it that way and the shape follows.
 *
 * WHAT IT HOLDS, EXHAUSTIVELY. init grants it three things and nothing else:
 *
 *   CAPSLOT_STORAGE_FORMAT  CAP_STORAGE_FORMAT (READ|WRITE) -- survey the disk,
 *                           and destroy what is on it. The whole privilege
 *                           question of this program is this one capability.
 *   CAPSLOT_USER            CAP_USER -- set the first root password. This is
 *                           administering the user database, which is exactly
 *                           what CAP_USER names, and it is granted rather than
 *                           inferred: do_passwd would ALSO accept this task on
 *                           the strength of its uid being 0 and equal to the
 *                           target's, and relying on that would be trusting a
 *                           caller for who it claims to be. The capability is
 *                           the authority; the uid is a coincidence.
 *   CAPSLOT_CONSOLE_EP      A WRITE-only console client endpoint -- draw and
 *                           read keys. Every task with a console has this; it
 *                           confers nothing an ordinary program lacks.
 *
 * WHAT IT DOES NOT HOLD, and each absence is load-bearing. No
 * CAP_ENCRYPTED_STORAGE: it cannot read one byte of the volume it replaces, and
 * an installer that could read the disk it is about to destroy would be a
 * disclosure path wearing a maintenance hat. No CAP_UNTYPED: it cannot create a
 * task, so nothing it does can outlive it. No CAP_BOOT_MODULE: it does not copy
 * the base system itself. That last one is the design decision worth stating,
 * so it is stated where it happens, at do_install below.
 *
 * ---- WHY THE PASSWORD IS ASKED FOR ONCE AND USED TWICE ---------------------
 *
 * The volume is sealed to a password (SYS_STORAGE_FORMAT), and the root account
 * is verified against a password (SYS_AUTH). Those are different mechanisms with
 * different salts, and a login needs BOTH to succeed with the same typed string:
 * h_auth opens the volume with what was typed and then checks the account table
 * that opening made readable. Seal the volume to one password and leave the
 * account on the compiled-in default and the machine is unopenable by anybody --
 * a working install that nobody can log into. So one password is asked for,
 * confirmed, and applied to both. Getting this wrong produces a disk that looks
 * perfectly installed and refuses every login, which is why smoke-installer
 * powers the machine off and logs in rather than believing the format's return
 * code.
 *
 * ---- WHAT IT DELIBERATELY DOES NOT DO --------------------------------------
 *
 *   - It does not install over an existing volume. A recognised volume is
 *     refused with a message, not offered as a choice. Overwriting a filesystem
 *     somebody may still want is a different act needing a different
 *     confirmation, and offering it in a menu next to "install onto blank
 *     media" is how the two get confused at 2am.
 *   - It does not choose between disks. There is one ATA device and
 *     SYS_STORAGE_INFO reports it or reports nothing; enumerating several is a
 *     block-layer change, not an installer one. tui_menu is used for the
 *     yes/no, so the day a second disk exists the menu is already the shape it
 *     needs to be.
 *   - It does not partition, and there is no bootloader step. The volume is the
 *     disk.
 */
#include "syscall.h"
#include "libhorus.h"
#include "tui.h"
#include "console_proto.h"

/* ---- markers ------------------------------------------------------------
 *
 * Everything a gate asserts on goes out as ONE console write, never through the
 * TUI. Two reasons, and the second is the one that bites: the TUI's damage diff
 * emits a run of changed cells with a cursor address in front of it, so a line
 * of text on the screen is not a contiguous string on the wire and a harness
 * looking for one would be reading a picture. And a marker split across two
 * writes can be cut in half by another task's output
 * (docs/LIMITATIONS.md 2.6a), so each is assembled whole and sent once. This is
 * the same reason tuitest and consoletest have their own say().
 */
static struct con_request  say_rq;
static struct con_response say_rp;

static void say(const char *a, const char *b)
{
    unsigned n = 0;
    for (const char *c = a; c && *c && n < CON_IO_MAX - 1; c++) say_rq.data[n++] = (uint8_t)*c;
    for (const char *c = b; c && *c && n < CON_IO_MAX - 1; c++) say_rq.data[n++] = (uint8_t)*c;
    say_rq.data[n++] = '\n';
    say_rq.magic = CON_PROTO_MAGIC;
    say_rq.op    = CON_OP_WRITE;
    say_rq.len   = n;
    for (int t = 0; t < 64; t++) {
        if (sys_ipc_call(CAPSLOT_CONSOLE_EP, 0, &say_rq, sizeof(say_rq), &say_rp) >= 0) return;
        sys_yield();
    }
}

/* Decimal into a caller-owned buffer. No varargs anywhere in this program, for
 * the reason tui.h gives: there is no format string to get wrong. */
static void utoa10(uint64_t v, char *out, unsigned cap)
{
    char tmp[24];
    unsigned n = 0;
    if (cap == 0) return;
    if (v == 0) tmp[n++] = '0';
    while (v && n < sizeof(tmp)) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    unsigned i = 0;
    while (n && i + 1 < cap) out[i++] = tmp[--n];
    out[i] = 0;
}

/* ---- screen furniture --------------------------------------------------- */

#define ROW_TITLE   1
#define ROW_BODY    4
#define ROW_PROMPT  14
#define ROW_FIELD   16
#define ROW_STATUS  21

static void frame(const char *title)
{
    tui_clear();
    tui_box(0, 0, tui_rows() - 1, tui_cols(), TUI_A_NORMAL);
    tui_text(ROW_TITLE, 3, "Horus installer", TUI_A_BOLD);
    tui_text(ROW_TITLE + 1, 3, title, TUI_A_NORMAL);
}

static void status(const char *s)
{
    tui_field(ROW_STATUS, 3, tui_cols() - 6, s, TUI_A_DIM);
}

/* ---- the confirmation ---------------------------------------------------
 *
 * A TYPED WORD, not a menu, and not a default-No button.
 *
 * The thing being confirmed is destruction, and the property that matters is
 * that it cannot happen by holding down return. A menu whose default is Cancel
 * still turns into a format with two keystrokes; a word that has to be typed
 * cannot be reached by any sequence of keys that is not the word. This is S63's
 * lesson at the other end of the system: there, a password typed at a login
 * prompt was taken as consent to format, and the repair was to make formatting
 * require an act that means only that.
 *
 * The menu below it is still a menu, because "which of these do I want" is what
 * a menu is for -- it just is not what consent is for.
 */
#define CONFIRM_WORD "FORMAT"

/* ---- state -------------------------------------------------------------- */

static struct storage_info g_si;

/* The password, and the only copy of it in this program. Static rather than on
 * the stack because it is 32 bytes twice over and a ring-3 stack is not the
 * place for them (the same reason tui.c keeps its request buffers static), and
 * because a single named place is a single place to erase. */
static char g_pw[STORAGE_FORMAT_PASSWORD_MAX + 1];
static char g_pw2[STORAGE_FORMAT_PASSWORD_MAX + 1];

static void wipe_passwords(void)
{
    /* Erased on every exit path, including the failures. A refused install has
     * held the operator's chosen password in memory just as long as a successful
     * one. `volatile` so the write is not optimised away as dead. */
    volatile char *a = (volatile char *)g_pw;
    volatile char *b = (volatile char *)g_pw2;
    for (unsigned i = 0; i < sizeof(g_pw); i++)  a[i] = 0;
    for (unsigned i = 0; i < sizeof(g_pw2); i++) b[i] = 0;
}

/* ---- steps -------------------------------------------------------------- */

/* Draw what is about to be destroyed, and ask. Returns 1 to proceed, 0 to stop.
 *
 * The size is shown in blocks AND in MiB. Not decoration: an operator
 * recognising their disk is the only check in this program that the machine
 * being installed is the machine they think they are standing at, and a block
 * count alone is not a number anybody recognises. */
static int screen_confirm(void)
{
    char blocks[24], mib[24];
    utoa10(g_si.total_blocks, blocks, sizeof(blocks));
    utoa10((g_si.total_blocks * (uint64_t)g_si.block_size) / (1024u * 1024u),
           mib, sizeof(mib));

    frame("Install onto the attached disk");

    tui_text(ROW_BODY, 3, "This will DESTROY everything on:", TUI_A_BOLD);
    tui_text(ROW_BODY + 2, 5, "the attached ATA disk", TUI_A_NORMAL);
    tui_text(ROW_BODY + 3, 5, "size:", TUI_A_NORMAL);
    tui_text(ROW_BODY + 3, 14, blocks, TUI_A_NORMAL);
    tui_text(ROW_BODY + 3, 30, "blocks", TUI_A_NORMAL);
    tui_text(ROW_BODY + 4, 14, mib, TUI_A_NORMAL);
    tui_text(ROW_BODY + 4, 30, "MiB", TUI_A_NORMAL);
    tui_text(ROW_BODY + 6, 3,
             "A new encrypted volume will be created and sealed to a password", TUI_A_NORMAL);
    tui_text(ROW_BODY + 7, 3,
             "you choose next. Nothing on the disk survives this.", TUI_A_NORMAL);

    static const char *const choices[] = { "Cancel, change nothing", "Continue" };
    int sel = 0;   /* Cancel is the default, and the cursor starts on it. */
    tui_text(ROW_PROMPT - 2, 3, "Choose, then press enter:", TUI_A_NORMAL);
    status("arrows to choose  -  enter to accept  -  esc to cancel");
    tui_flush();
    say("INSTALLER: waiting on the destroy-this-disk choice", "");
    if (tui_menu(ROW_PROMPT, 5, 32, choices, 2, &sel) != 0) return 0;
    if (sel != 1) return 0;

    /* THE MENU IS NOT THE CONSENT. See CONFIRM_WORD above: a choice that can be
     * reached by holding return is not a decision to destroy a disk. */
    frame("Confirm");
    tui_text(ROW_BODY, 3, "Type", TUI_A_NORMAL);
    tui_text(ROW_BODY, 8, CONFIRM_WORD, TUI_A_BOLD);
    tui_text(ROW_BODY, 8 + (int)sizeof(CONFIRM_WORD), "to erase the disk, or esc to stop.",
             TUI_A_NORMAL);
    tui_text(ROW_BODY + 2, 3, "Anything else cancels.", TUI_A_NORMAL);
    status("this is the last question before the disk is erased");

    char typed[16];
    tui_text(ROW_FIELD - 1, 3, "confirm:", TUI_A_NORMAL);
    tui_flush();
    say("INSTALLER: waiting on the typed confirmation", "");
    if (tui_input(ROW_FIELD, 12, 12, typed, sizeof(typed), 0) != 0) return 0;

#ifdef INSTALLER_NO_CONFIRM
    /* CONTROL ARM -- never ship. The typed word is read and then not compared,
     * so the install proceeds whatever was typed -- including nothing.
     *
     * The comparison is what is removed rather than the whole screen, and that
     * is deliberate: removing the screen would also remove the keystrokes the
     * harness sends, and the two arms would then be driving different
     * conversations. With only the comparison gone, both arms type the same
     * wrong word and differ solely in what the program does about it. See
     * make smoke-installer-refuse-control. */
    (void)typed;
    return 1;
#else
    return ustreq(typed, CONFIRM_WORD);
#endif
}

/* Ask for the password twice. Returns 1 on a confirmed, usable password. */
static int screen_password(void)
{
    for (;;) {
        frame("Choose the root password");
        tui_text(ROW_BODY, 3, "This password does two things, and it must be one password:",
                 TUI_A_NORMAL);
        tui_text(ROW_BODY + 2, 5, "it seals the volume's encryption key, and", TUI_A_NORMAL);
        tui_text(ROW_BODY + 3, 5, "it is the password for the root account.", TUI_A_NORMAL);
        tui_text(ROW_BODY + 5, 3,
                 "There is no recovery. A forgotten password is a lost volume.", TUI_A_BOLD);
        status("typing is not shown  -  esc to cancel the install");

        tui_text(ROW_FIELD - 1, 3, "password:", TUI_A_NORMAL);
        tui_flush();
        say("INSTALLER: waiting on the password", "");
        if (tui_input(ROW_FIELD, 14, STORAGE_FORMAT_PASSWORD_MAX,
                      g_pw, sizeof(g_pw), TUI_IN_MASK) != 0) return 0;

        tui_text(ROW_FIELD + 1, 3, "again:", TUI_A_NORMAL);
        tui_flush();
        say("INSTALLER: waiting on the password again", "");
        if (tui_input(ROW_FIELD + 2, 14, STORAGE_FORMAT_PASSWORD_MAX,
                      g_pw2, sizeof(g_pw2), TUI_IN_MASK) != 0) return 0;

        if (g_pw[0] == 0) {
            status("an empty password would seal the volume to nothing - try again");
            tui_flush();
            continue;
        }
        if (!ustreq(g_pw, g_pw2)) {
            /* Both fields are cleared before asking again. Leaving the first one
             * populated would mean the second attempt is confirming a string the
             * operator can no longer see and may not have meant. */
            wipe_passwords();
            status("the two did not match - try again");
            tui_flush();
            continue;
        }
        return 1;
    }
}

/* Do it. Returns 0 on success.
 *
 * THE BASE SYSTEM IS NOT COPIED HERE, and that is a decision rather than an
 * omission. fs_server already provisions /bin and the directory skeleton from
 * the boot modules the moment the store becomes readable -- it polls for exactly
 * that, because a sealed ATA volume is locked until somebody opens it (see the
 * `if (!provisioned)` fallback in fs_server's loop). So the installer's job is
 * to make the volume exist and be open; the task that already holds
 * CAP_ENCRYPTED_STORAGE and CAP_BOOT_MODULE does the copying.
 *
 * Writing the files from here instead would mean granting the installer both of
 * those capabilities -- the authority to read every boot module and to write
 * anywhere in the object store -- to duplicate a loop that already exists in the
 * task whose job it is. That is a strictly larger installer holding strictly
 * more authority to achieve the same bytes on disk.
 */
static int do_install(void)
{
    frame("Installing");
    tui_text(ROW_BODY, 3, "Creating the encrypted volume. Do not power off.", TUI_A_NORMAL);
    status("this takes a moment");
    tui_flush();

    /* The marker goes out BEFORE the call, not after. If the format wedges or
     * the machine dies mid-write, a transcript that says "formatting" and stops
     * is evidence; one that says nothing is indistinguishable from an installer
     * that never got here. */
    say("INSTALLER: formatting", "");

    unsigned plen = uslen(g_pw);
    int rc = sys_storage_format(g_pw, plen);
    if (rc != 0) {
        char n[24];
        utoa10((uint64_t)(unsigned)(-rc), n, sizeof(n));
        say("INSTALLER: FAIL format refused rc=-", n);
        return -1;
    }

    /* The account half. Without it the volume opens and no login succeeds: the
     * account table on a fresh volume is the compiled-in default, so `root`
     * still wants the built-in password while the VOLUME wants the one just
     * chosen, and h_auth needs the same typed string to satisfy both. */
    if (sys_passwd(0, g_pw) != 0) {
        say("INSTALLER: FAIL could not set the root password", "");
        return -1;
    }

    /* VERIFY BY ASKING THE KERNEL AGAIN, not by trusting the return code. A
     * format that reported success and left the volume unmounted or locked is
     * exactly the failure this program exists to not produce quietly. */
    struct storage_info after;
    if (sys_storage_info(&after) != 0) {
        say("INSTALLER: FAIL cannot read the volume back", "");
        return -1;
    }
    if (!after.recognised || !after.unlocked) {
        say("INSTALLER: FAIL the volume did not come up after formatting", "");
        return -1;
    }
    return 0;
}

/* ---- entry -------------------------------------------------------------- */

void _start(void)
{
    if (tui_begin() != 0) {
        /* No console server: draw nothing rather than proceed blind. An
         * installer that cannot show what it is about to destroy must not
         * destroy it, so this is a refusal and not a fallback to line output. */
        kput("INSTALLER: FAIL no console server; refusing to install unattended\n");
        sys_exit();
    }

    if (sys_storage_info(&g_si) != 0) {
        tui_end();
        say("INSTALLER: FAIL no CAP_STORAGE_FORMAT; nothing to install with", "");
        sys_exit();
    }

    if (!g_si.present) {
        frame("Nothing to install onto");
        tui_text(ROW_BODY, 3, "This machine has no persistent disk attached.", TUI_A_NORMAL);
        tui_text(ROW_BODY + 2, 3, "It is running from the ephemeral store, which lasts",
                 TUI_A_NORMAL);
        tui_text(ROW_BODY + 3, 3, "until the power goes off.", TUI_A_NORMAL);
        status("press any key");
        tui_flush();
        (void)tui_getkey();
        tui_end();
        say("INSTALLER: no disk", "");
        sys_exit();
    }

    if (g_si.recognised) {
        /* Refused, not offered. See the header: installing over a filesystem
         * somebody may still want is a different act needing a different
         * confirmation, and putting it in the same menu is how the two get
         * confused. */
        frame("This disk already has a Horus volume");
        tui_text(ROW_BODY, 3, "Installing over an existing volume is not something this",
                 TUI_A_NORMAL);
        tui_text(ROW_BODY + 1, 3, "installer will do. Nothing has been changed.", TUI_A_NORMAL);
        status("press any key");
        tui_flush();
        (void)tui_getkey();
        tui_end();
        say("INSTALLER: nothing was written; the disk already holds a volume", "");
        sys_exit();
    }

    if (!screen_confirm()) {
        frame("Cancelled");
        tui_text(ROW_BODY, 3, "Nothing was written. The disk is exactly as it was.",
                 TUI_A_NORMAL);
        tui_flush();
        tui_end();
        wipe_passwords();
        say("INSTALLER: nothing was written", "");
        sys_exit();
    }

    if (!screen_password()) {
        frame("Cancelled");
        tui_text(ROW_BODY, 3, "Nothing was written. The disk is exactly as it was.",
                 TUI_A_NORMAL);
        tui_flush();
        tui_end();
        wipe_passwords();
        say("INSTALLER: nothing was written", "");
        sys_exit();
    }

    int rc = do_install();
    wipe_passwords();

    if (rc != 0) {
        tui_end();
        sys_exit();
    }

    frame("Installed");
    tui_text(ROW_BODY, 3, "The volume is created, sealed and open.", TUI_A_NORMAL);
    tui_text(ROW_BODY + 2, 3, "Log in as root with the password you chose.", TUI_A_NORMAL);
    status("");
    tui_flush();
    tui_end();
    say("INSTALLER: PASS installed", "");
    sys_exit();
}
