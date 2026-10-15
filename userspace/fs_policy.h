/* The filesystem policy: parse /etc/fs.policy, compile one principal's grants,
 * and answer what a capability reached through them may do
 * (docs/design/filesystem.md §6.2, §6.4, decision 13).
 *
 * PURE ON PURPOSE. Nothing here makes a syscall, reads the store or keeps state
 * between calls: fs_server hands it bytes and an account and gets a tree back.
 * That is what lets the same code be compiled on the host and tested line by
 * line (make smoke-fs-policy), including every way a policy can be malformed,
 * where a boot could only ever show the default. It is included by fs_server.c
 * and by tools/fs_policy_test.c, and by nothing else.
 *
 * THE LANGUAGE. One grant per line, three fields separated by spaces or tabs:
 *
 *     principal   path            rights
 *     @all        /bin            read,lookup,exec
 *     alice       /home/alice     all
 *     @self       ~               all
 *     @self       /tmp            read,write,lookup,create,delete,setattr
 *
 *   principal  an account name, @all (every authenticated session), @admin (the
 *              administrator, the account with uid 0, as the shell's login has
 *              always defined it), or @self (each account, for its own home).
 *   path       absolute, components separated by "/", each a name fs_server
 *              would accept (not empty, not "." or "..", shorter than a
 *              directory entry's name). "~" is the account's home, and only
 *              with @self; it applies only to a home of the form /home/<name>,
 *              so an account whose home is "/" (root's) gets nothing from it.
 *              "/tmp" with @self is the session's PRIVATE /tmp (§6.3): a
 *              directory fs_server makes for that session alone and removes at
 *              its end, which the session sees as /tmp. @self takes "~" or
 *              "/tmp" and nothing else.
 *   rights     comma-separated: read, write, append, exec, lookup, create,
 *              delete, setattr, or all.
 *
 * "#" starts a comment; blank lines are ignored. ANYTHING ELSE IS MALFORMED and
 * the whole file is refused, never the lines that did parse (§6.4): an unknown
 * principal group, an unknown right, a relative path, a missing field, a line or
 * file over its bound. `grant` and `snapshot` are refused too, deliberately: a
 * session's root carries GRANT because decision 10's spawner grants depend on
 * it, and there are no snapshots before v12, so a policy naming either would be
 * written in the belief that it does something it does not.
 *
 * THE RULE ONCE COMPILED. A principal's matching lines become a tree of path
 * nodes. A node's rights are the union of every grant at or above it, so a
 * deeper grant can only add (admin's "/ all" is not narrowed by an "@all /usr
 * read" line). A node with nothing granted at or above it is only on the way
 * to a grant: it gives LOOKUP and a listing filtered to the names that lead to
 * grants, and a name under it that leads to none is absent.
 *
 * WHO ELSE REACHES AN OBJECT (§7.1, decisions 16 and 17). The tree also holds
 * the grants of every OTHER principal that lie inside the session's own reach,
 * as nodes of their own where they need one, so that a stat can bound who else
 * may read or write what it names: `other` at a node is the union of those
 * grants at or above it. They change nothing the session may do or see. "Other"
 * is every grant whose principal is not the session's account: @all, lines
 * naming other accounts, and every other account's home (a wildcard under
 * /home, since accounts are added at run time). Never the administrator's
 * (@admin, or lines naming the uid-0 account): mode bits have never bounded
 * the administrator. Never a private /tmp, which nobody else reaches. */
#ifndef HORUS_FS_POLICY_H
#define HORUS_FS_POLICY_H

#include <stdint.h>
#include "fs_proto.h"

#define FSP_MAX_BYTES   4096   /* a longer /etc/fs.policy is malformed */
#define FSP_MAX_LINES   64     /* grant lines, comments not counted */
#define FSP_MAX_DEPTH   8      /* path components in one grant */
#define FSP_NAME        FS_DIRENT_NAME
#define FSP_PRINCIPAL   32     /* struct user_entry's name field */
#define FSP_NODES       32     /* nodes in one compiled session, root included */
/* A token names a node in five bits (fs_proto.h, decision 17). */
typedef char fsp_nodes_fit_token[(FSP_NODES - 1 <= FS_TOKEN_NODE_MASK) ? 1 : -1];

/* What a pass-through node lets through: walk past it, and list it filtered. */
#define FSP_PASS_RIGHTS (FS_R_LOOKUP | FS_R_READ)

struct fsp_line {
    char     principal[FSP_PRINCIPAL];
    char     comp[FSP_MAX_DEPTH][FSP_NAME];
    uint8_t  depth;          /* 0 is "/" */
    uint8_t  home;           /* the path was "~" */
    uint8_t  tmp;            /* @self /tmp: the session's private /tmp */
    uint32_t rights;
};

struct fsp_policy {
    unsigned        n;
    struct fsp_line line[FSP_MAX_LINES];
};

struct fsp_node {
    char     name[FSP_NAME]; /* "" for the root */
    int16_t  parent;         /* -1 for the root, which is always node 0 */
    uint8_t  nchild;
    uint32_t granted;        /* written for exactly this path */
    uint32_t eff;            /* granted at or above: what an operation here may use */
    uint32_t below;          /* eff over the whole subtree: what a capability here must carry */
    /* The object a capability at this node was minted for, recorded by fs_server
     * when it mints one (a tracked capability names its node by inode). */
    uint32_t ino, gen;
    uint8_t  bound;
    /* The session's private /tmp (@self /tmp): fs_server answers this name with
     * the directory it made for the session, never with the volume's entry. */
    uint8_t  private_tmp;
    /* Other principals (§7.1): `ogrant` is written for exactly this path, and
     * `other` is the union at or above it, what bounds who else reaches it. */
    uint32_t ogrant;
    uint32_t other;
    /* The wildcard under /home: every other account's home. It answers any
     * name its parent has no node for (fsp_match), and its ogrant applies to
     * every sibling but the session's own home (self_home). It has no name. */
    uint8_t  wild;
    uint8_t  self_home;
};

struct fsp_tree {
    unsigned        n;
    struct fsp_node node[FSP_NODES];
    /* The other principals' grants did not fit, so none were kept and every
     * bound in this session is every right (fsp_other). */
    uint8_t         other_full;
};

/* Who the session is for, as the kernel's account list says. `admin_name` is
 * the uid-0 account's name, whose lines are the administrator's and so never
 * "other" (decision 16); 0 if there is none. */
struct fsp_who {
    const char *name;
    const char *home;
    int         admin;       /* uid 0 */
    const char *admin_name;
};

/* Decision 9's default for the ephemeral store of a live boot. */
static const char fsp_default_text[] =
    "@admin  /     all\n"
    "@all    /bin  read,lookup,exec\n"
    "@all    /lib  read,lookup\n"
    "@all    /usr  read,lookup,exec\n"
    "@self   ~     all\n"
    "@self   /tmp  read,write,lookup,create,delete,setattr\n";

/* The policy an installed volume starts with (roadmap 2.10 step 3(c), S148):
 * fs_server writes it as /etc/fs.policy when it provisions a persistent volume
 * that has no /etc yet, which is a volume nobody has configured. The live
 * default's grants, and read on the two configuration files every login reads
 * (docs/design/configuration.md), which hold no secret. It is a file the
 * administrator edits, so it says what it is. Never written over: a volume
 * that has an /etc has had its say, and one without a usable policy file gives
 * the administrator alone (fsp_load), so deleting it narrows and never widens. */
static const char fsp_installed_text[] =
    "# /etc/fs.policy - who may reach which part of the filesystem. See fs.policy(5).\n"
    "#\n"
    "# Horus wrote this once, when it first set this volume up, and will never\n"
    "# write it again. A login's session reaches only what a line here grants it;\n"
    "# rights only add up. A file that does not parse, or no file at all, gives\n"
    "# the administrator \"/ all\" and nobody anything else.\n"
    "#\n"
    "# principal  path              rights\n"
    "@admin       /                 all\n"
    "@all         /bin              read,lookup,exec\n"
    "@all         /lib              read,lookup\n"
    "@all         /usr              read,lookup,exec\n"
    "@all         /etc/shell.conf   read\n"
    "@all         /etc/login.conf   read\n"
    "@self        ~                 all\n"
    "@self        /tmp              read,write,lookup,create,delete,setattr\n";

_Static_assert(sizeof(fsp_installed_text) - 1 <= FSP_MAX_BYTES,
               "the installed policy must be one the parser accepts");

/* A persistent volume with no usable policy (decision 9, §6.4): the
 * administrator gets the root, so they can log in and write one, and nobody
 * else gets anything. */
static const char fsp_admin_only_text[] = "@admin / all\n";

/* ---- small freestanding helpers ------------------------------------------- */

static int fsp_streq(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static unsigned fsp_len(const char *s)
{
    unsigned n = 0;
    while (s[n]) n++;
    return n;
}

/* Copy [s, s+n) into a buffer of `cap` bytes; 0 if it does not fit. */
static int fsp_copy(char *dst, unsigned cap, const char *s, unsigned n)
{
    if (n >= cap) return 0;
    for (unsigned i = 0; i < n; i++) dst[i] = s[i];
    dst[n] = 0;
    return 1;
}

/* fs_server's own rule for a name (fs_name_ok), restated here so the parser
 * accepts no path the server would refuse to walk. */
static int fsp_name_ok(const char *n, unsigned len)
{
    if (len == 0 || len >= FSP_NAME) return 0;
    if (n[0] == '.' && (len == 1 || (len == 2 && n[1] == '.'))) return 0;
    for (unsigned i = 0; i < len; i++) if (n[i] == '/' || n[i] == 0) return 0;
    return 1;
}

/* Split an absolute path into components. Returns the depth, or -1. */
static int fsp_split(const char *p, unsigned len, char comp[FSP_MAX_DEPTH][FSP_NAME])
{
    if (len == 0 || p[0] != '/') return -1;
    int depth = 0;
    unsigned at = 1;
    while (at < len) {
        unsigned s = at;
        while (at < len && p[at] != '/') at++;
        if (!fsp_name_ok(p + s, at - s) || depth >= FSP_MAX_DEPTH) return -1;
        fsp_copy(comp[depth++], FSP_NAME, p + s, at - s);
        if (at < len) {
            at++;                               /* the "/" */
            if (at == len) return -1;           /* a trailing "/" names nothing */
        }
    }
    return depth;
}

static uint32_t fsp_right(const char *w, unsigned n)
{
    static const struct { const char *name; uint32_t bit; } r[] = {
        { "read", FS_R_READ }, { "write", FS_R_WRITE }, { "append", FS_R_APPEND },
        { "exec", FS_R_EXEC }, { "lookup", FS_R_LOOKUP }, { "create", FS_R_CREATE },
        { "delete", FS_R_DELETE }, { "setattr", FS_R_SETATTR }, { "all", FS_R_ALL },
    };
    for (unsigned i = 0; i < sizeof(r) / sizeof(r[0]); i++) {
        if (fsp_len(r[i].name) != n) continue;
        unsigned k = 0;
        while (k < n && r[i].name[k] == w[k]) k++;
        if (k == n) return r[i].bit;
    }
    return 0;
}

/* ---- parsing -------------------------------------------------------------- */

/* Parse `len` bytes. Returns 0 with *out filled, or -1 with out->n = 0 and
 * *bad_line the 1-based line that failed (0 for the file as a whole). */
static int fsp_parse(const char *text, uint32_t len, struct fsp_policy *out, unsigned *bad_line)
{
    out->n = 0;
    *bad_line = 0;
    if (len > FSP_MAX_BYTES) return -1;

    unsigned lineno = 0;
    uint32_t at = 0;
    while (at < len) {
        uint32_t s = at;
        while (at < len && text[at] != '\n') at++;
        uint32_t e = at;                         /* [s, e) is one line */
        if (at < len) at++;
        lineno++;

        /* Fields, split on spaces and tabs, up to a "#". */
        const char *f[4];
        unsigned fl[4], nf = 0;
        uint32_t i = s;
        for (;;) {
            while (i < e && (text[i] == ' ' || text[i] == '\t' || text[i] == '\r')) i++;
            if (i >= e || text[i] == '#') break;
            uint32_t fs = i;
            while (i < e && text[i] != ' ' && text[i] != '\t' && text[i] != '\r' && text[i] != '#') i++;
            if (nf == 4) { *bad_line = lineno; out->n = 0; return -1; }
            f[nf] = text + fs; fl[nf] = i - fs; nf++;
        }
        if (nf == 0) continue;                   /* blank or comment */
        if (nf != 3 || out->n >= FSP_MAX_LINES) { *bad_line = lineno; out->n = 0; return -1; }

        struct fsp_line *l = &out->line[out->n];
        for (unsigned k = 0; k < sizeof(*l); k++) ((char *)l)[k] = 0;

        /* Principal: an account name, or one of the three groups. */
        if (!fsp_copy(l->principal, FSP_PRINCIPAL, f[0], fl[0])) { *bad_line = lineno; out->n = 0; return -1; }
        for (unsigned k = 0; k < fl[0]; k++)
            if (f[0][k] == 0 || f[0][k] == '/' || f[0][k] == ',') { *bad_line = lineno; out->n = 0; return -1; }
        int self = fsp_streq(l->principal, "@self");
        if (l->principal[0] == '@' && !self &&
            !fsp_streq(l->principal, "@all") && !fsp_streq(l->principal, "@admin")) {
            *bad_line = lineno; out->n = 0; return -1;
        }

        /* Path: "~" or "/tmp" with @self and only there, else absolute. */
        if (fl[1] == 1 && f[1][0] == '~') {
            if (!self) { *bad_line = lineno; out->n = 0; return -1; }
            l->home = 1;
        } else if (self) {
            if (fl[1] != 4 || f[1][0] != '/' || f[1][1] != 't' || f[1][2] != 'm' || f[1][3] != 'p') {
                *bad_line = lineno; out->n = 0; return -1;
            }
            l->tmp = 1;
            l->depth = 1;
            fsp_copy(l->comp[0], FSP_NAME, "tmp", 3);
        } else {
            int d = fsp_split(f[1], fl[1], l->comp);
            if (d < 0) { *bad_line = lineno; out->n = 0; return -1; }
            l->depth = (uint8_t)d;
        }

        /* Rights: a comma-separated list, every word known, none empty. */
        uint32_t r = 0, w = 0;
        while (w <= fl[2]) {
            uint32_t ws = w;
            while (w < fl[2] && f[2][w] != ',') w++;
            uint32_t bit = fsp_right(f[2] + ws, w - ws);
            if (bit == 0) { *bad_line = lineno; out->n = 0; return -1; }
            r |= bit;
            w++;
        }
        l->rights = r;
        out->n++;
    }
    return 0;
}

/* Which policy applies, and its parsed form. `ephemeral` comes from
 * SYS_FS_STORE_KIND, never from a request; `have_file` and `text` from
 * /etc/fs.policy on the store, which a live boot does not consult. Returns an
 * FS_SESSION_SRC_*; *bad_line is set for FS_SESSION_SRC_MALFORMED. */
static int fsp_load(int ephemeral, int have_file, const char *text, uint32_t len,
                    struct fsp_policy *p, unsigned *bad_line)
{
    *bad_line = 0;
    if (ephemeral) {
        (void)fsp_parse(fsp_default_text, sizeof(fsp_default_text) - 1, p, bad_line);
        return FS_SESSION_SRC_DEFAULT;
    }
    if (have_file && fsp_parse(text, len, p, bad_line) == 0) return FS_SESSION_SRC_FILE;
    unsigned ignored;
    (void)fsp_parse(fsp_admin_only_text, sizeof(fsp_admin_only_text) - 1, p, &ignored);
    return have_file ? FS_SESSION_SRC_MALFORMED : FS_SESSION_SRC_ADMIN_ONLY;
}

/* ---- compiling ------------------------------------------------------------ */

static int fsp_child_of(const struct fsp_tree *t, int parent, const char *name)
{
    for (unsigned i = 1; i < t->n; i++)
        if (t->node[i].parent == parent && fsp_streq(t->node[i].name, name)) return (int)i;
    return -1;
}

/* Add `rights` at the path, making nodes along it. -1 when the tree is full.
 * Returns the node otherwise. */
static int fsp_grant(struct fsp_tree *t, char comp[][FSP_NAME], unsigned depth, uint32_t rights)
{
    int cur = 0;
    for (unsigned d = 0; d < depth; d++) {
        int c = fsp_child_of(t, cur, comp[d]);
        if (c < 0) {
            if (t->n >= FSP_NODES) return -1;
            c = (int)t->n++;
            struct fsp_node *nn = &t->node[c];
            for (unsigned k = 0; k < sizeof(*nn); k++) ((char *)nn)[k] = 0;
            fsp_copy(nn->name, FSP_NAME, comp[d], fsp_len(comp[d]));
            nn->parent = (int16_t)cur;
            t->node[cur].nchild++;
        }
        cur = c;
    }
    t->node[cur].granted |= rights;
    return cur;
}

/* ---- other principals (§7.1) --------------------------------------------- */

/* A new node under `parent`, inside the session's reach: it inherits what the
 * session may do there and changes none of it. -1 when the tree is full. */
static int fsp_add_other(struct fsp_tree *t, int parent, const char *name, int wild)
{
    if (t->n >= FSP_NODES) return -1;
    int c = (int)t->n++;
    struct fsp_node *nn = &t->node[c];
    for (unsigned k = 0; k < sizeof(*nn); k++) ((char *)nn)[k] = 0;
    if (!wild) fsp_copy(nn->name, FSP_NAME, name, fsp_len(name));
    nn->wild = (uint8_t)wild;
    nn->parent = (int16_t)parent;
    nn->eff = nn->below = t->node[parent].eff;
    t->node[parent].nchild++;
    return c;
}

/* Record another principal's grant of `rights` at the path. A grant the session
 * cannot reach any part of is left out: it bounds nothing the session can stat.
 * So is one through a private /tmp, which is not the volume's /tmp at all. A
 * named node is made only where the session's own rights already reach (eff),
 * so no name becomes visible that was not; the wildcard is the exception, and
 * says why. -1 when the tree is full. */
static int fsp_other_grant(struct fsp_tree *t, char comp[][FSP_NAME], unsigned depth,
                           int wild_last, uint32_t rights)
{
    int cur = 0;
    for (unsigned d = 0; d < depth; d++) {
        if (t->node[cur].private_tmp) return 0;
        int last_wild = wild_last && d == depth - 1;
        int c = -1;
        for (unsigned i = 1; i < t->n; i++) {
            const struct fsp_node *nn = &t->node[i];
            if (nn->parent != cur) continue;
            if (last_wild ? nn->wild : (!nn->wild && fsp_streq(nn->name, comp[d]))) { c = (int)i; break; }
        }
        if (c < 0) {
            /* The wildcard is made under any node, a pass-through included,
             * because it covers the names that ARE nodes there too: a session
             * granted /home/bob/shared walks through /home/bob, which bob's own
             * home grant reaches. It cannot make a name visible: it has no
             * children and, under a pass-through, no rights (fsp_step). */
            if (t->node[cur].eff == 0 && !last_wild) return 0;
            c = fsp_add_other(t, cur, comp[d], last_wild);
            if (c < 0) return -1;
        }
        cur = c;
    }
    if (t->node[cur].private_tmp) return 0;
    t->node[cur].ogrant |= rights;
    return 0;
}

/* Add every other principal's grants to a compiled tree and set each node's
 * `other`. If they do not fit, the tree is put back exactly as the session's
 * own grants left it and other_full says every bound is every right: what the
 * session may do never depends on whether the others fitted. */
static void fsp_compile_others(const struct fsp_policy *p, const struct fsp_who *who,
                               struct fsp_tree *t)
{
    const unsigned own_n = t->n;
    int full = 0;
    for (unsigned i = 0; i < p->n && !full; i++) {
        const struct fsp_line *l = &p->line[i];
        if (l->tmp) continue;                       /* a private /tmp: nobody else's */
        if (fsp_streq(l->principal, "@admin")) continue;
        if (l->home) {
            /* Every other account's home, /home/<name>. The session's own is
             * excluded where the wildcard is applied (self_home). */
            char comp[2][FSP_NAME];
            fsp_copy(comp[0], FSP_NAME, "home", 4);
            comp[1][0] = 0;
            if (fsp_other_grant(t, comp, 2, 1, l->rights) < 0) full = 1;
            continue;
        }
        if (l->principal[0] != '@') {
            if (fsp_streq(l->principal, who->name)) continue;                    /* the session's own */
            if (who->admin_name && fsp_streq(l->principal, who->admin_name)) continue;  /* the administrator's */
        }
        if (fsp_other_grant(t, (char (*)[FSP_NAME])l->comp, l->depth, 0, l->rights) < 0) full = 1;
    }
    if (full) {
        for (unsigned i = own_n; i < t->n; i++) t->node[t->node[i].parent].nchild--;
        t->n = own_n;
        for (unsigned i = 0; i < t->n; i++) t->node[i].ogrant = 0;
        t->other_full = 1;
    }

    /* The session's own home, which the wildcard never covers. */
    {
        char comp[FSP_MAX_DEPTH][FSP_NAME];
        int d = fsp_split(who->home, fsp_len(who->home), comp);
        if (d == 2 && fsp_streq(comp[0], "home")) {
            int h = fsp_child_of(t, 0, "home");
            int c = h >= 0 ? fsp_child_of(t, h, comp[1]) : -1;
            if (c >= 0) t->node[c].self_home = 1;
        }
    }

    /* Parents before children, as fsp_grant and fsp_add_other append. */
    for (unsigned i = 0; i < t->n; i++) {
        struct fsp_node *nn = &t->node[i];
        if (nn->private_tmp) { nn->other = 0; continue; }
        uint32_t up = 0;
        if (nn->parent >= 0) {
            up = t->node[nn->parent].other;
            if (!nn->wild && !nn->self_home)
                for (unsigned k = 1; k < t->n; k++)
                    if (t->node[k].wild && t->node[k].parent == nn->parent) up |= t->node[k].ogrant;
        }
        nn->other = nn->ogrant | up;
    }
}

/* Compile the lines that apply to `who` into *t. Returns 0, or -1 when they do
 * not fit FSP_NODES (the session is refused; nothing partial is used). */
static int fsp_compile(const struct fsp_policy *p, const struct fsp_who *who, struct fsp_tree *t)
{
    for (unsigned k = 0; k < sizeof(t->node[0]); k++) ((char *)&t->node[0])[k] = 0;
    t->node[0].parent = -1;
    t->n = 1;
    t->other_full = 0;          /* a grant set's tree is reused by its next session */

    for (unsigned i = 0; i < p->n; i++) {
        const struct fsp_line *l = &p->line[i];
        if (l->home) {
            /* @self ~: the account's own home, only as /home/<name>. */
            char comp[FSP_MAX_DEPTH][FSP_NAME];
            int d = fsp_split(who->home, fsp_len(who->home), comp);
            if (d != 2 || !fsp_streq(comp[0], "home")) continue;
            if (fsp_grant(t, comp, 2, l->rights) < 0) return -1;
            continue;
        }
        if (l->tmp) {
            /* @self /tmp: every session has its own, whoever the account. */
            int n = fsp_grant(t, (char (*)[FSP_NAME])l->comp, 1, l->rights);
            if (n < 0) return -1;
            t->node[n].private_tmp = 1;
            continue;
        }
        /* A group is matched by what the account is, never by its name: an
         * account that happened to be called "@admin" must not be given the
         * administrator's lines, so a line names an account only when it does
         * not begin with "@". */
        int match = fsp_streq(l->principal, "@all") ||
                    (fsp_streq(l->principal, "@admin") && who->admin) ||
                    (l->principal[0] != '@' && fsp_streq(l->principal, who->name));
        if (!match) continue;
        if (fsp_grant(t, (char (*)[FSP_NAME])l->comp, l->depth, l->rights) < 0) return -1;
    }

#ifdef FS_SESSION_GRANTS_ROOT
    /* CONTROL ARM, never ship (make smoke-fs-cap-session-control and
     * make smoke-fs-policy-control): every session is given the root, whatever
     * the policy says, which is the defect decision 13's gate exists to catch. */
    t->node[0].granted |= FS_R_ALL;
#endif

    /* Parents come before children (fsp_grant appends), so one pass down sets
     * eff and one pass up sets below. */
    for (unsigned i = 0; i < t->n; i++) {
        struct fsp_node *nn = &t->node[i];
        nn->eff = nn->granted | (nn->parent >= 0 ? t->node[nn->parent].eff : 0);
        nn->below = nn->eff;
#ifndef FSP_PASS_RIGHTS_UNCARRIED
        /* A DIRECTORY ON THE WAY TO A GRANT IS WALKED THROUGH, and a capability
         * to it must carry what fsp_op_rights lets an operation there use, or
         * the walk stops at it. Its subtree's rights did not always include
         * that: "@all /etc/shell.conf read" gave /etc only READ, so nothing in
         * /etc could be looked up (found 2026-10-15 by the first policy to
         * grant a file alone, S148). Nothing wider follows: operations here
         * are held to FSP_PASS_RIGHTS, and a child gets its own grant. */
        if (nn->eff == 0 && nn->nchild > 0) nn->below = FSP_PASS_RIGHTS;
#else
        /* CONTROL ARM, never ship (make smoke-fs-policy-pass-control): the
         * subtree's rights alone, so a directory whose grants below are on
         * files only cannot be walked through. */
#endif
    }
    for (unsigned i = t->n; i-- > 1; )
        t->node[t->node[i].parent].below |= t->node[i].below;

    /* A grant below a private /tmp names a path inside a directory made fresh
     * for the session, which can mean nothing; refusing it is the honest answer,
     * as for any line that cannot do what it says. */
    for (unsigned i = 1; i < t->n; i++)
        if (t->node[i].private_tmp && t->node[i].nchild > 0) return -1;

    fsp_compile_others(p, who, t);
    return 0;
}

/* ---- answering ------------------------------------------------------------ */

/* What an operation at tracked node `n` may use, before the capability's own
 * rights are intersected. */
static uint32_t fsp_op_rights(const struct fsp_tree *t, int n)
{
    return t->node[n].eff ? t->node[n].eff : FSP_PASS_RIGHTS;
}

/* The node for `name` under node `n`: one of that name, or else the wildcard
 * (every other account's home), or -1. */
static int fsp_match(const struct fsp_tree *t, int n, const char *name)
{
    int c = fsp_child_of(t, n, name);
    if (c >= 0) return c;
    for (unsigned i = 1; i < t->n; i++)
        if (t->node[i].wild && t->node[i].parent == n) return (int)i;
    return -1;
}

/* The step from tracked node `n` to its entry `name`, whose type is
 * `is_dir` (1) or not (0). Returns:
 *    1  the child is tracked at node *child, and its capability carries *carry;
 *    0  the child is untracked, *child is the node at or above it (what its
 *       token names, decision 17), and its capability carries *carry;
 *   -1  the name is absent from this session (NOENT, never PERM).
 * A tracked child is a directory on the way to a deeper node; a granted path
 * with nothing deeper, or anything below a granted path that the policy does
 * not name, is untracked and from there the kernel's intersection bounds it. */
static int fsp_step(const struct fsp_tree *t, int n, const char *name, int is_dir,
                    int *child, uint32_t *carry)
{
    int c = fsp_match(t, n, name);
    if (c >= 0) {
        const struct fsp_node *cn = &t->node[c];
        if (cn->nchild > 0 && is_dir) { *child = c; *carry = cn->below; return 1; }
        /* A file the policy names a path through has nothing below it: only
         * what is granted at or above it applies, and without that it is
         * absent rather than readable as a pass-through. */
        if (cn->eff == 0) return -1;
        *child = c; *carry = cn->eff;
        return 0;
    }
    if (t->node[n].eff == 0) return -1;
    *child = n; *carry = t->node[n].eff;
    return 0;
}

/* Is a name under node `n` one the policy names, for anyone? Such a name
 * decides which grants reach what is under it, so moving an object onto it or
 * off it would change who reaches the object without changing the bound in
 * the capabilities already minted to it (§5.5, condition 2, within one
 * directory). Under the wildcard every name is one. */
static int fsp_names(const struct fsp_tree *t, int n, const char *name)
{
    return fsp_match(t, n, name) >= 0;
}

/* THE MODE BITS (§7.1): `r` for READ; `w` for WRITE or APPEND on a file, CREATE
 * or DELETE on a directory, the rights that change one; `x` for EXEC on a file,
 * LOOKUP on a directory. One mapping for the caller's rights and for everyone
 * else's, so an append-only grant shows as `w`: a bound must never understate. */
static uint32_t fsp_bits(uint32_t r, int is_dir)
{
    uint32_t b = 0;
    if (r & FS_R_READ) b |= 4u;
    if (r & (is_dir ? (FS_R_CREATE | FS_R_DELETE) : (FS_R_WRITE | FS_R_APPEND))) b |= 2u;
    if (r & (is_dir ? FS_R_LOOKUP : FS_R_EXEC)) b |= 1u;
    return b;
}

/* Owner bits from the caller's rights, group bits always zero, other bits from
 * the bound on everyone else's. */
static uint32_t fsp_mode(uint32_t own, uint32_t other, int is_dir)
{
    return (fsp_bits(own, is_dir) << 6) | fsp_bits(other, is_dir);
}

/* Is `name` under tracked node `n` the session's private /tmp? */
static int fsp_is_private(const struct fsp_tree *t, int n, const char *name)
{
    int c = fsp_child_of(t, n, name);
    return c >= 0 && t->node[c].private_tmp;
}

/* Is `name` (of the given type) listed under tracked node `n`? */
static int fsp_visible(const struct fsp_tree *t, int n, const char *name, int is_dir)
{
    int c; uint32_t r;
    return fsp_step(t, n, name, is_dir, &c, &r) >= 0;
}

/* THE TRUTHFUL CHMOD (§7.2, decision 18). Nothing is stored: a chmod succeeds
 * when the mode it asks for is already true, and is refused when it is not, so
 * that a user who asks for privacy on a file that is shared learns it is shared.
 * True means: no set-user-id, set-group-id or sticky bit, which this system has
 * no meaning for (§6.3); group bits zero, as stat reports them; other bits
 * EXACTLY the bound on everyone else's rights, so a looser mode is refused as
 * firmly as a tighter one (it would report an exposure that is not real); and
 * owner bits among the caller's own, since showing fewer of one's own rights
 * claims no protection that is false. That last is what lets `chmod 600`
 * succeed on a home's files, which the default policy grants EXEC. */
static int fsp_chmod_true(uint32_t mode, uint32_t own, uint32_t other, int is_dir)
{
    if (mode & 07000u) return 0;
    if (mode & 00070u) return 0;
    if ((mode & 00007u) != fsp_bits(other, is_dir)) return 0;
    return (((mode >> 6) & 07u) & ~fsp_bits(own, is_dir)) == 0;
}

/* THE TRUTHFUL CHOWN (§7.2): the owner stat reports is the caller, so a chown
 * to the caller's own uid and primary group, or to -1 (leave it), is true and
 * every other is not. */
static int fsp_chown_true(uint32_t uid, uint32_t gid, uint32_t cuid, uint32_t cgid)
{
    return (uid == 0xFFFFFFFFu || uid == cuid) && (gid == 0xFFFFFFFFu || gid == cgid);
}

#endif /* HORUS_FS_POLICY_H */
