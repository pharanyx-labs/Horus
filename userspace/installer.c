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
 *
 * ---- WHY THE CONSENT IS THE LAST THING ASKED (2026-09-06) ------------------
 *
 * The typed word used to be the SECOND question: choose Continue, type FORMAT,
 * and then answer five more screens about passwords and account names before
 * anything was written. That ordering is wrong on the only ground this program
 * is judged by. Consent to destroy a disk should be adjacent to the destruction:
 * a word typed before a five-screen conversation is a word typed about a machine
 * state the operator can no longer see, and by the time it is acted on they have
 * been thinking about something else for a minute.
 *
 * So the order is now: show what will be destroyed and ask whether to go on,
 * collect every answer, SHOW THEM BACK, and only then ask for the word --
 * immediately before the format, with nothing in between. This is the shape
 * every mainstream installer converged on, and the reason is the same one.
 *
 * THE REVIEW SCREEN IS ALSO THE ONLY WAY TO FIX A TYPO, and that is where it
 * belongs rather than in the library. A form layer with tab-navigation between
 * fields was designed and rejected: see include/tui.h, which has always said
 * that a program which has to be READ before it is trusted does not get a widget
 * set. A form is a third blocking loop over the keyboard, holding an array of
 * field descriptors and deciding on the caller's behalf which field the next
 * keystroke edits -- inside the library that stands between a keystroke and this
 * program's one capability. What is here instead is a tui_menu choosing which
 * question to ask again and a tui_input asking it, which is the same behaviour
 * built from the two interactions that already existed, in the file a reviewer
 * of this program's consent is already reading.
 *
 * THE REVIEW MENU DEFAULTS TO "Install now", AND THAT IS NOT A WEAKENING.
 * The property being relied on has never been "the menu is hard to reach"; it is
 * that THE FORMAT IS REACHABLE ONLY THROUGH A WORD THAT IS TYPED AND COMPARED.
 * No sequence of return presses spells F-O-R-M-A-T, so where the highlight
 * starts changes how many keys an operator who has already answered everything
 * must press, and changes nothing about what consent costs. Do not "fix" this
 * default back to Cancel on security grounds; the gate is the word.
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

/* say(), then tell the TUI its screen is no longer what it thinks it is.
 *
 * EVERY MARKER IN THIS PROGRAM GOES THROUGH HERE, and that is the point. A
 * marker is a cooked console write to the same UART the TUI draws on, so it
 * lands at wherever the terminal's cursor is -- which, on a screen that has just
 * drawn a password field, is inside the password field. The library cannot see
 * a write it did not make, so its damage diff believes those cells are still
 * correct and never repaints them: the text sits there through this screen and
 * every screen after it.
 *
 * Found on 2026-09-06 by rendering this program's own serial stream through a VT
 * emulator, which showed `*******INSTALLER: waiting on the user password again`
 * written across a live install's password row. Every installer gate was green
 * at the time and none of them could have caught it -- they assert on the
 * markers, which are on the wire either way.
 *
 * The repaint is not done here: whoever draws next flushes, and that flush is
 * now a full one. The one place that does not draw next is do_install, which
 * flushes explicitly. */
static void mark(const char *a, const char *b)
{
    say(a, b);
    tui_invalidate();
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
/* ---- the look ----------------------------------------------------------
 *
 * One accent, and everything else is the terminal's own colours. A screen that
 * asks whether to erase a disk is not the place to demonstrate a palette: the
 * red is spent on the one sentence that says what is about to be destroyed, and
 * spending it anywhere else is what makes an operator stop reading it.
 *
 * These are attributes, not a theme system. There is no runtime switch, no
 * configuration and no table -- eight names, used directly. */
#define C_FRAME   ((uint16_t)TUI_FG(TUI_C_BLUE))
#define C_TITLE   ((uint16_t)(TUI_FG(TUI_C_CYAN) | TUI_A_BOLD))
#define C_SUBTITLE ((uint16_t)TUI_A_BOLD)
#define C_TEXT    ((uint16_t)TUI_A_NORMAL)
#define C_LABEL   ((uint16_t)TUI_FG(TUI_C_CYAN))
#define C_VALUE   ((uint16_t)TUI_A_BOLD)
#define C_DANGER  ((uint16_t)(TUI_FG(TUI_C_RED) | TUI_A_BOLD))
#define C_OK      ((uint16_t)(TUI_FG(TUI_C_GREEN) | TUI_A_BOLD))
#define C_HINT    ((uint16_t)TUI_A_DIM)

/* ---- screen furniture ---------------------------------------------------
 *
 * The 80x24 console, divided once. Every screen in this program is this frame
 * with a different body, so the operator's eye learns where the title, the
 * question and the keys are on the first screen and does not have to look for
 * them again on the one that erases the disk.
 *
 * NOTHING HERE COUNTS COLUMNS BY HAND ANY MORE. Every line of prose used to be
 * placed at a literal column, which is silently wrong the moment somebody edits
 * the sentence above it -- on screens whose whole job is to be read accurately.
 * Body text goes through tui_wrap, which is the reason that call exists. */
#define BOX_H       23
#define MARGIN      3
#define ROW_TITLE   1
#define ROW_SUB     2
#define ROW_RULE_T  3
#define ROW_BODY    5
#define ROW_RULE_B  19
#define ROW_STATUS  20
#define ROW_HINT    21
#define BODY_ROWS   (ROW_RULE_B - ROW_BODY)

static int body_w(void) { return tui_cols() - 2 * MARGIN; }

/* A horizontal rule with tees, drawn with the terminal's line glyphs. The tees
 * are what make it read as one frame divided rather than three boxes stacked. */
static void rule(int row)
{
    int last = tui_cols() - 1;
    for (int c = 1; c < last; c++)
        tui_putc(row, c, TUI_ACS_HLINE, (uint16_t)(C_FRAME | TUI_A_ACS));
    tui_putc(row, 0,    TUI_ACS_LTEE, (uint16_t)(C_FRAME | TUI_A_ACS));
    tui_putc(row, last, TUI_ACS_RTEE, (uint16_t)(C_FRAME | TUI_A_ACS));
}

static void frame(const char *title)
{
    tui_clear();
    tui_box(0, 0, BOX_H, tui_cols(), C_FRAME);
    tui_text(ROW_TITLE, MARGIN, "Horus installer", C_TITLE);
    tui_text(ROW_SUB,   MARGIN, title, C_SUBTITLE);
    rule(ROW_RULE_T);
    rule(ROW_RULE_B);
}

/* The status line: one sentence about what just happened, or what is wrong. */
static void status(const char *s, uint16_t attr)
{
    tui_field(ROW_STATUS, MARGIN, body_w(), s, attr);
}

/* The key hints. Always present, always in the same place, always dim -- an
 * operator who does not know that esc cancels is an operator who will guess. */
static void hint(const char *s)
{
    tui_field(ROW_HINT, MARGIN, body_w(), s, C_HINT);
}

/* Body prose. Returns the row after the last one used, so a caller stacks
 * paragraphs without counting. */
static int para(int row, const char *s, uint16_t attr)
{
    int used = tui_wrap(row, MARGIN, body_w(), ROW_RULE_B - row, s, attr);
    return row + used;
}

/* A label and its field, on one row. The label is the accent colour and the
 * value is bold: a form where every word looks the same is a form people fill
 * in without reading. */
#define LABEL_COL   (MARGIN + 2)
#define FIELD_COL   (MARGIN + 20)
#define FIELD_W     STORAGE_FORMAT_PASSWORD_MAX
#define LABEL_W     (FIELD_COL - LABEL_COL - 1)

/* tui_field, not tui_text, and the difference is a real collision rather than
 * tidiness. One of these labels is the account NAME, which the operator chose
 * and which USER_NAME_MAX allows fifteen characters of -- long enough to reach
 * the value column and overwrite what it says. A field truncates at its width,
 * so the columns cannot move however long the answer is, which is the property
 * tui_field exists for and the reason menus use it too. */
static void label(int row, const char *s)
{
    tui_field(row, LABEL_COL, LABEL_W, s, C_LABEL);
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
 * The menus in this program are still menus, because "which of these do I want"
 * is what a menu is for -- it just is not what consent is for.
 */
#define CONFIRM_WORD "FORMAT"

/* ---- state -------------------------------------------------------------- */

static struct storage_info g_si;

/* WHICH DEVICE THE INSTALL GOES ONTO, a position in the machine's enumeration.
 *
 * It is state of this program rather than of the kernel, and it is passed to
 * SYS_STORAGE_FORMAT as an argument rather than selected by an earlier call: the
 * act that destroys a disk names the disk it destroys (SECURITY.md S83). 0 is
 * the machine's own nomination and is what a one-disk install uses without ever
 * showing a menu. */
static unsigned g_target;

/* The password, and the only copy of it in this program. Static rather than on
 * the stack because it is 32 bytes twice over and a ring-3 stack is not the
 * place for them (the same reason tui.c keeps its request buffers static), and
 * because a single named place is a single place to erase. */
static char g_pw[STORAGE_FORMAT_PASSWORD_MAX + 1];
static char g_pw2[STORAGE_FORMAT_PASSWORD_MAX + 1];

/* The unprivileged account: its name, and its password twice. Same reasoning as
 * the pair above -- static so there is one named place to erase, not a ring-3
 * stack frame holding two more copies of a secret. */
#define USER_NAME_MAX 15
static char g_user[USER_NAME_MAX + 1];
static char g_upw[STORAGE_FORMAT_PASSWORD_MAX + 1];
static char g_upw2[STORAGE_FORMAT_PASSWORD_MAX + 1];

/* The uid the everyday account gets. 1000 is the convention, and it is the uid
 * users_init already seeds a compiled-in `user` account at -- which is exactly
 * why the install DELETES that account before creating this one at the same
 * number. See do_install. */
#define USER_UID  1000
#define USER_GID  100

static void wipe_user_password(void)
{
    volatile char *c = (volatile char *)g_upw;
    volatile char *d = (volatile char *)g_upw2;
    for (unsigned i = 0; i < sizeof(g_upw); i++)  c[i] = 0;
    for (unsigned i = 0; i < sizeof(g_upw2); i++) d[i] = 0;
}

static void wipe_passwords(void)
{
    /* Erased on every exit path, including the failures. A refused install has
     * held the operator's chosen password in memory just as long as a successful
     * one. `volatile` so the write is not optimised away as dead. */
    volatile char *a = (volatile char *)g_pw;
    volatile char *b = (volatile char *)g_pw2;
    for (unsigned i = 0; i < sizeof(g_pw); i++)   a[i] = 0;
    for (unsigned i = 0; i < sizeof(g_pw2); i++)  b[i] = 0;
    wipe_user_password();
    /* The NAME is not a secret and is deliberately not wiped here: do_install
     * reports it back on the finished screen, and an operator who has just been
     * asked to remember a login should be shown which one. */
}

/* ---- the survey --------------------------------------------------------
 *
 * What is about to be destroyed, and a chance to stop before being asked for
 * anything. The size is shown in blocks AND in MiB: an operator recognising
 * their disk is the only check in this program that the machine being installed
 * is the machine they are standing at, and a block count alone is not a number
 * anybody recognises.
 */
static void disk_size(char *blocks, unsigned bcap, char *mib, unsigned mcap)
{
    utoa10(g_si.total_blocks, blocks, bcap);
    utoa10((g_si.total_blocks * (uint64_t)g_si.block_size) / (1024u * 1024u), mib, mcap);
}

/* ---- choosing a disk ----------------------------------------------------
 *
 * Only asked when there is something to ask. A machine with one disk shows no
 * menu at all and installs onto device 0, which is byte for byte the
 * conversation this program had before it could count past one -- the harness
 * scenarios that drive a single-disk install were not taught a new keystroke,
 * because they should not need one.
 *
 * BUILT FROM tui_menu, like every other choice here, and the labels are the
 * SIZE of each disk rather than a device number. "ata0" and "ata1" are what the
 * kernel calls them and they are not what an operator recognises; the size is
 * the only thing on this screen that lets somebody say "that is the one I
 * meant". It is the same argument the survey screen makes for showing MiB
 * alongside blocks.
 *
 * The list is built from SYS_STORAGE_DEVICE rather than from the machine-wide
 * survey, because that is the enumeration the index is a position in -- reading
 * one and indexing the other is how the wrong disk gets erased by a program
 * whose every individual step was right.
 */
#define TARGET_MAX 8

static char g_target_labels[TARGET_MAX][40];
static const char *g_target_items[TARGET_MAX];
static unsigned g_target_count;

static void build_target_list(void)
{
    g_target_count = 0;
    for (unsigned d = 0; d < g_si.device_count && d < TARGET_MAX; d++) {
        struct storage_info di;
        for (unsigned z = 0; z < sizeof(di); z++) ((char *)&di)[z] = 0;
        if (sys_storage_device(d, &di) != 0) continue;

        char mib[24];
        utoa10((di.total_blocks * (uint64_t)di.block_size) / (1024u * 1024u),
               mib, sizeof(mib));

        char *out = g_target_labels[g_target_count];
        unsigned n = 0;
        const char *pre = "disk ";
        for (const char *c = pre; *c && n < sizeof(g_target_labels[0]) - 1; c++) out[n++] = *c;
        char idx[8];
        utoa10(d, idx, sizeof(idx));
        for (const char *c = idx; *c && n < sizeof(g_target_labels[0]) - 1; c++) out[n++] = *c;
        const char *mid = "  -  ";
        for (const char *c = mid; *c && n < sizeof(g_target_labels[0]) - 1; c++) out[n++] = *c;
        for (const char *c = mib; *c && n < sizeof(g_target_labels[0]) - 1; c++) out[n++] = *c;
        const char *suf = " MiB";
        for (const char *c = suf; *c && n < sizeof(g_target_labels[0]) - 1; c++) out[n++] = *c;
        out[n] = 0;

        g_target_items[g_target_count] = out;
        g_target_count++;
    }
}

/* Returns 1 with g_target set, 0 if the operator cancelled. */
static int screen_target(void)
{
    build_target_list();

    /* Nothing to choose between: the machine's own nomination stands, and no
     * screen is shown. */
    if (g_target_count <= 1) {
        g_target = 0;
        return 1;
    }

    frame("Choose the disk to install onto");
    int r = para(ROW_BODY, "This machine has more than one disk. Everything on the one you "
                           "choose is erased; the others are not touched.", C_TEXT);
    r += 2;

    int sel = 0;
    status("Nothing has been written yet.", C_TEXT);
    hint("arrows to choose  -  enter to accept  -  esc to cancel");
    tui_flush();
    mark("INSTALLER: waiting on the disk choice", "");
    if (tui_menu(r, MARGIN + 2, 40, g_target_items, (int)g_target_count, &sel) != 0) return 0;

    /* tui_menu clamps to 0..n-1, and this is the caller that clamp exists for:
     * the returned index is about to be handed to the call that erases a disk.
     * Re-checked here anyway -- the bound belongs to whoever indexes with it. */
    if (sel < 0 || (unsigned)sel >= g_target_count) return 0;
    g_target = (unsigned)sel;
    return 1;
}

static int screen_survey(void)
{
    char blocks[24], mib[24];
    disk_size(blocks, sizeof(blocks), mib, sizeof(mib));

    frame("Install onto the attached disk");

    int r = para(ROW_BODY, "This will DESTROY everything on the attached disk.", C_DANGER);
    r++;
    label(r, "device");
    /* NOT "the attached ATA disk", which this said until 2026-09-08 and which
     * became false the moment a machine could boot with an SD/eMMC card as its
     * only storage. This is the screen whose entire job is telling an operator
     * WHICH device is about to be destroyed, so a hard-coded controller type is
     * the one kind of inaccuracy it cannot afford.
     *
     * It names no controller at all rather than reporting one: `struct
     * storage_info` carries no device name, and adding one is an ABI change
     * across the syscall boundary (the struct is declared in both rings, which
     * is the S71 shape, gated by tools/check_abi_structs.py). The size and the
     * device index below already identify the target; the controller type does
     * not, and a wrong one is worse than none. */
    tui_text(r, FIELD_COL, "the attached disk", C_VALUE);
    r++;
    label(r, "size");
    tui_text(r, FIELD_COL, blocks, C_VALUE);
    tui_text(r, FIELD_COL + 12, "blocks", C_TEXT);
    r++;
    tui_text(r, FIELD_COL, mib, C_VALUE);
    tui_text(r, FIELD_COL + 12, "MiB", C_TEXT);
    r += 2;
    r = para(r, "A new encrypted volume will be created and sealed to a password you "
                "choose next. Nothing on the disk survives this.", C_TEXT);

    static const char *const choices[] = { "Cancel, change nothing", "Continue" };
    int sel = 0;   /* Cancel is the default, and the cursor starts on it. */
    status("Nothing has been written yet.", C_TEXT);
    hint("arrows to choose  -  enter to accept  -  esc to cancel");
    tui_flush();
    mark("INSTALLER: waiting on the destroy-this-disk choice", "");
    if (tui_menu(r + 1, MARGIN + 2, 32, choices, 2, &sel) != 0) return 0;
    return sel == 1;
}

/* ---- the questions -----------------------------------------------------
 *
 * One function per question, each re-runnable on its own, because the review
 * screen re-asks exactly one of them at a time. That is what stops this program
 * growing a second copy of any question: "ask for the root password" has one
 * implementation whether it is the first pass or a correction.
 */
static int ask_root_password(void)
{
    for (;;) {
        frame("Choose the root password");
        int r = para(ROW_BODY,
                     "This password does two things, and it must be one password: it seals "
                     "the volume's encryption key, and it is the password for the root "
                     "account.", C_TEXT);
        r++;
        r = para(r, "There is no recovery. A forgotten password is a lost volume.", C_DANGER);

        label(r + 2, "password");
        label(r + 4, "again");
        hint("typing is not shown  -  esc to cancel the install");
        tui_flush();

        mark("INSTALLER: waiting on the password", "");
        if (tui_input(r + 2, FIELD_COL, FIELD_W, g_pw, sizeof(g_pw), TUI_IN_MASK) != 0) return 0;
        mark("INSTALLER: waiting on the password again", "");
        if (tui_input(r + 4, FIELD_COL, FIELD_W, g_pw2, sizeof(g_pw2), TUI_IN_MASK) != 0) return 0;

        if (g_pw[0] == 0) {
            status("An empty password would seal the volume to nothing. Try again.", C_DANGER);
            tui_flush();
            continue;
        }
        if (!ustreq(g_pw, g_pw2)) {
            /* Both fields are cleared before asking again. Leaving the first one
             * populated would mean the second attempt is confirming a string the
             * operator can no longer see and may not have meant. */
            wipe_passwords();
            status("The two did not match. Try again.", C_DANGER);
            tui_flush();
            continue;
        }
        return 1;
    }
}

/* THE NAME IS BOUNDED AND CHECKED HERE, not left to the kernel to refuse. It is
 * lowercase letters and digits, must start with a letter, and cannot be `root`.
 * do_useradd would refuse a duplicate name anyway, but a refusal arriving as a
 * return code AFTER the disk has been formatted is a bad place to discover a
 * typo -- every question in this program is asked before anything is written. */
static int name_ok(const char *n)
{
    if (n[0] < 'a' || n[0] > 'z') return 0;          /* must start with a letter */
    for (unsigned i = 0; n[i]; i++) {
        char c = n[i];
        int lower = (c >= 'a' && c <= 'z');
        int digit = (c >= '0' && c <= '9');
        if (!lower && !digit) return 0;
    }
    return !ustreq(n, "root");
}

/* WHY THERE ARE TWO ACCOUNTS AT ALL. A machine whose only login is root is a
 * machine every session is administered from, and this project's whole argument
 * is that authority should be held only when it is being exercised. The
 * installer is the one moment an operator can be asked for both without it
 * feeling like an extra chore, so it asks. */
static int ask_user_name(void)
{
    for (;;) {
        frame("Create your everyday account");
        int r = para(ROW_BODY,
                     "Day-to-day work should not be done as root, so this machine gets a "
                     "second account with no administrative authority.", C_TEXT);
        r++;
        r = para(r, "Its password also unlocks the disk at boot, so either account can be "
                    "the first login after the machine is powered on.", C_TEXT);

        label(r + 2, "username");
        hint("lowercase letters and digits  -  esc to cancel the install");
        tui_flush();

        mark("INSTALLER: waiting on the user name", "");
        if (tui_input(r + 2, FIELD_COL, USER_NAME_MAX, g_user, sizeof(g_user), 0) != 0) return 0;

        if (!name_ok(g_user)) {
            status("A name is lowercase letters and digits, starts with a letter, "
                   "and is not root.", C_DANGER);
            tui_flush();
            continue;
        }
        return 1;
    }
}

static int ask_user_password(void)
{
    for (;;) {
        frame("Set the password for your account");
        int r = para(ROW_BODY,
                     "This is the password for the everyday account. It must be different "
                     "from the root password.", C_TEXT);
        r++;
        label(r + 1, "account");
        tui_text(r + 1, FIELD_COL, g_user, C_VALUE);

        label(r + 3, "password");
        label(r + 5, "again");
        hint("typing is not shown  -  esc to cancel the install");
        tui_flush();

        mark("INSTALLER: waiting on the user password", "");
        if (tui_input(r + 3, FIELD_COL, FIELD_W, g_upw, sizeof(g_upw), TUI_IN_MASK) != 0) return 0;
        mark("INSTALLER: waiting on the user password again", "");
        if (tui_input(r + 5, FIELD_COL, FIELD_W, g_upw2, sizeof(g_upw2), TUI_IN_MASK) != 0) return 0;

        if (g_upw[0] == 0) {
            status("An empty password would leave this account unusable. Try again.", C_DANGER);
            tui_flush();
            continue;
        }
        if (!ustreq(g_upw, g_upw2)) {
            /* Both cleared before asking again, for the reason the root pair
             * gives: confirming a string the operator can no longer see is not
             * confirmation. */
            wipe_user_password();
            status("The two did not match. Try again.", C_DANGER);
            tui_flush();
            continue;
        }
        /* THE TWO PASSWORDS MUST DIFFER. Identical ones would put the same
         * secret in two key slots and give the everyday account root's password
         * -- which is the separation this screen exists to create, undone by an
         * operator taking the shortest path. */
        if (ustreq(g_upw, g_pw)) {
            wipe_user_password();
            status("This must not be the root password. The two accounts are separate.",
                   C_DANGER);
            tui_flush();
            continue;
        }
        return 1;
    }
}

/* ---- the review --------------------------------------------------------
 *
 * Everything that was answered, shown back, with the chance to change any of it
 * -- and the last screen before the word is asked for.
 *
 * PASSWORDS ARE SHOWN AS "set", NEVER AS THEMSELVES OR AS A LENGTH. The whole
 * point of tui_input's mask is that the clear text never reaches a cell; a
 * review screen that printed it back, or printed one asterisk per character,
 * would hand back at the end what was protected all the way through. The length
 * of a password is worth something to somebody watching the screen, which is the
 * same reason tui_input pads with spaces rather than with its mask.
 */
static int review_returns_install(void)
{
    char blocks[24], mib[24];

    for (;;) {
        disk_size(blocks, sizeof(blocks), mib, sizeof(mib));
        frame("Review before installing");

        int r = para(ROW_BODY, "Check this, then choose. Nothing has been written yet.", C_TEXT);
        r++;

        label(r, "disk");
        tui_text(r, FIELD_COL, mib, C_VALUE);
        tui_text(r, FIELD_COL + 12, "MiB - everything on it is erased", C_DANGER);
        r++;
        label(r, "root");
        tui_text(r, FIELD_COL, "password set", C_VALUE);
        r++;
        label(r, g_user);
        tui_text(r, FIELD_COL, "password set", C_VALUE);
        r += 2;

        static const char *const choices[] = {
            "Install now - this erases the disk",
            "Change the account name",
            "Change the root password",
            "Change the everyday password",
            "Cancel, change nothing",
        };
        /* Defaults to Install. See the header: the gate is the typed word, not
         * where this highlight starts. */
        int sel = 0;
        hint("arrows to choose  -  enter to accept  -  esc to cancel");
        tui_flush();
        mark("INSTALLER: waiting on the review choice", "");
        if (tui_menu(r, MARGIN + 2, 40, choices, 5, &sel) != 0) return 0;

        if (sel == 0) return 1;
        if (sel == 4) return 0;

        if (sel == 1) {
            if (!ask_user_name()) return 0;
        } else if (sel == 2) {
            if (!ask_root_password()) return 0;
            /* CHANGING ROOT'S PASSWORD CAN INVALIDATE THE OTHER ONE, and the
             * check that catches it lives in ask_user_password -- which is not
             * running. Without this, an operator who changes root's password to
             * whatever the everyday account already uses gets both accounts on
             * one secret, and the separation the second account exists to create
             * is gone with no screen having said anything. Re-ask rather than
             * refuse at the end: the answer that has to change is the one being
             * asked for again. */
            if (ustreq(g_upw, g_pw)) {
                wipe_user_password();
                if (!ask_user_password()) return 0;
            }
        } else if (sel == 3) {
            if (!ask_user_password()) return 0;
        }
    }
}

/* The word. Immediately before the format, with nothing between it and the
 * call that destroys the disk. */
static int screen_confirm_word(void)
{
    frame("Type the word to erase this disk");

    int r = para(ROW_BODY, "This is the last question before the disk is erased.", C_DANGER);
    r++;
    r = para(r, "Type " CONFIRM_WORD " to go ahead. Anything else, or esc, stops and "
                "changes nothing.", C_TEXT);

    label(r + 2, "confirm");
    status("", C_TEXT);
    hint("type the word  -  enter to accept  -  esc to stop");
    tui_flush();

    char typed[16];
    mark("INSTALLER: waiting on the typed confirmation", "");
    if (tui_input(r + 2, FIELD_COL, 12, typed, sizeof(typed), 0) != 0) return 0;

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

/* The screen shown while the format runs.
 *
 * THERE IS NO PROGRESS BAR, AND THAT IS A DECISION. sys_storage_format is one
 * blocking call: this task is inside it from the moment it starts until the
 * volume exists, and it learns nothing on the way. A bar drawn over it would be
 * an animation with no measurement behind it, which on the one screen an
 * operator is asked not to power off is worse than no bar -- a stalled real bar
 * and a smooth fake one say opposite things about whether to keep waiting. So
 * this says what is happening, says it can take minutes on a slow disk, and then
 * stops moving. [G-13] is the finding that made "how long is this allowed to
 * take" a measured question; the answer lives in the gate, not in a spinner. */
static void screen_working(void)
{
    frame("Installing");
    int r = para(ROW_BODY, "Creating the encrypted volume.", C_TEXT);
    r++;
    r = para(r, "This can take several minutes on a slow disk, and the screen will not "
                "change while it runs.", C_TEXT);
    r++;
    (void)para(r, "Do not power off.", C_DANGER);
    status("", C_TEXT);
    hint("");
    tui_flush();
}

/* ---- the install -------------------------------------------------------- */

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
    screen_working();

    /* The marker goes out BEFORE the call, not after. If the format wedges or
     * the machine dies mid-write, a transcript that says "formatting" and stops
     * is evidence; one that says nothing is indistinguishable from an installer
     * that never got here. */
    mark("INSTALLER: formatting", "");
    /* Repaint over the marker BEFORE going into the format. Every other marker
     * is followed by a screen that draws itself; this one is followed by a
     * blocking call that can run for minutes, so without this the working screen
     * carries `INSTALLER: formatting` across it for the whole install -- on the
     * one screen an operator is asked to sit and look at. */
    tui_flush();

    unsigned plen = uslen(g_pw);
    int rc = sys_storage_format(g_target, g_pw, plen);
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

    /* ---- the everyday account ---------------------------------------------
     *
     * THE COMPILED-IN ACCOUNT IS DELETED FIRST, and that is the security half of
     * this block rather than tidiness. users_init seeds `user` at uid 1000 with
     * the password `password`, and a fresh volume's table is seeded from exactly
     * that RAM image -- so without this, every installed Horus machine ships a
     * working login whose password is printed in the source and in
     * docs/BUILDING.md. Deleting it and recreating the same uid under a name and
     * password the operator chose is the whole point of asking them.
     *
     * A missing account is not an error here: `userdel` on a machine whose table
     * has already been replaced has nothing to remove, and refusing would make
     * a second install of the same image fail for being tidy.
     */
    (void)sys_userdel(USER_UID);

    if (sys_useradd(USER_UID, USER_GID, g_user) != 0) {
        say("INSTALLER: FAIL could not create the account ", g_user);
        return -1;
    }

    /* AND THIS IS WHERE THE ACCOUNT BECOMES ABLE TO BOOT THE MACHINE.
     * do_passwd grants a key slot when an admin sets another account's password
     * (docs/LIMITATIONS.md 2.6b, closed), so this one call both sets the hash and
     * authorises the password to open the volume. It fails closed: no slot, no
     * password change, and the install stops here rather than finishing with an
     * account that cannot be the first login after a power cycle. */
    if (sys_passwd(USER_UID, g_upw) != 0) {
        say("INSTALLER: FAIL could not set the password for ", g_user);
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

/* Every exit that changed nothing goes through here, so "nothing was written"
 * is one sentence in one place rather than five copies that can drift apart --
 * and the marker a gate asserts on is emitted by the same code that draws the
 * screen saying it. */
static void leave_untouched(const char *why)
{
    frame("Cancelled");
    (void)para(ROW_BODY, "Nothing was written. The disk is exactly as it was.", C_TEXT);
    status(why, C_TEXT);
    hint("");
    tui_flush();
    tui_end();
    wipe_passwords();
    say("INSTALLER: nothing was written", "");
    sys_exit();
}

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
        int r = para(ROW_BODY, "This machine has no persistent disk attached.", C_TEXT);
        r++;
        (void)para(r, "It is running from the ephemeral store, which lasts until the power "
                      "goes off.", C_TEXT);
        status("", C_TEXT);
        hint("press any key");
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
        int r = para(ROW_BODY, "Installing over an existing volume is not something this "
                               "installer will do.", C_TEXT);
        r++;
        (void)para(r, "Nothing has been changed.", C_TEXT);
        status("", C_TEXT);
        hint("press any key");
        tui_flush();
        (void)tui_getkey();
        tui_end();
        say("INSTALLER: nothing was written; the disk already holds a volume", "");
        sys_exit();
    }

    /* THE ORDER: show what is at stake, collect every answer, show them back,
     * and only then ask for the word. See the header for why the word is last
     * rather than second. Every question is asked before anything is written,
     * so an operator who changes their mind at any point up to the word has
     * cost themselves nothing but typing. */
    if (!screen_survey())            leave_untouched("You chose not to install.");
    if (!screen_target())            leave_untouched("You chose not to install.");
    if (!ask_root_password())        leave_untouched("The install was cancelled.");
    if (!ask_user_name())            leave_untouched("The install was cancelled.");
    if (!ask_user_password())        leave_untouched("The install was cancelled.");
    if (!review_returns_install())   leave_untouched("You chose not to install.");
    if (!screen_confirm_word())      leave_untouched("The disk was not erased.");

    int rc = do_install();
    wipe_passwords();

    if (rc != 0) {
        tui_end();
        sys_exit();
    }

    frame("Installed");
    int r = para(ROW_BODY, "The volume is created, sealed and open.", C_OK);
    r++;
    r = para(r, "Two accounts exist, and either password opens the disk:", C_TEXT);
    r++;
    label(r, "root");
    tui_text(r, FIELD_COL, "administers this machine", C_TEXT);
    r++;
    label(r, g_user);
    tui_text(r, FIELD_COL, "everything else", C_TEXT);
    r += 2;
    (void)para(r, "Log in with the passwords you chose.", C_TEXT);
    status("", C_TEXT);
    hint("");
    tui_flush();
    tui_end();
    say("INSTALLER: PASS installed", "");
    sys_exit();
}
