/* Host test of the filesystem policy (userspace/fs_policy.h): the parser, the
 * choice of policy by store kind, and the compiled rule (docs/design/filesystem.md
 * §6.2, §6.4, decision 13). `make smoke-fs-policy` builds and runs it.
 *
 * WHY ON THE HOST. A boot can only ever show the compiled-in default, since the
 * RAM store of a self-test boot is ephemeral and so never consults a policy
 * file. Every way a file can be malformed, and the rule that a persistent
 * volume without one gives the administrator alone, are pure functions of their
 * input, so they are tested here line by line against the same code fs_server
 * compiles. The boot half is make smoke-fs-cap (FSCAPTEST's session checks).
 *
 * Prints FS_POLICY_TEST: PASS <n> checks, or FS_POLICY_TEST: FAIL <name> for
 * the first check that did not hold, and exits non-zero then. The bounds on who
 * else reaches an object (§7.1, decisions 16 and 17) are tested here too, every
 * kind of principal against every kind of path, since a boot shows only the
 * default.
 * FS_SESSION_GRANTS_ROOT=1 (make smoke-fs-policy-control) must turn it red with
 * FAIL user-root-not-granted: an ordinary account's root is granted. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../userspace/fs_policy.h"

static int checks;

static void check(int ok, const char *name)
{
    if (!ok) {
        printf("FS_POLICY_TEST: FAIL %s\n", name);
        exit(1);
    }
    checks++;
}

static struct fsp_policy pol;
static struct fsp_tree tree;

static int parses(const char *text, unsigned *bad)
{
    unsigned b;
    int r = fsp_parse(text, (uint32_t)strlen(text), &pol, bad ? bad : &b);
    return r == 0;
}

/* Compile `text` for `who` (it must parse). */
static int compile(const char *text, const char *name, const char *home, int admin)
{
    unsigned bad;
    if (fsp_parse(text, (uint32_t)strlen(text), &pol, &bad) != 0) return -2;
    struct fsp_who who = { name, home, admin, "root" };
    return fsp_compile(&pol, &who, &tree);
}

/* Walk `path` (absolute, each component a directory unless `last_file`) from
 * the root through the compiled tree. Returns -1 if a name is absent, else 1 or
 * 0 for tracked or untracked at the end, with *carry what a capability there
 * carries and *node its node. */
static int walk(const char *path, int last_file, uint32_t *carry, int *node)
{
    char comp[FSP_MAX_DEPTH][FSP_NAME];
    int d = fsp_split(path, (unsigned)strlen(path), comp);
    if (d < 0) return -9;
    int n = tree.node[0].nchild > 0 ? 0 : -1;
    uint32_t c = tree.node[0].below;
    for (int k = 0; k < d; k++) {
        if (n < 0) continue;                    /* untracked: nothing left to apply */
        int child;
        int r = fsp_step(&tree, n, comp[k], !(last_file && k == d - 1), &child, &c);
        if (r < 0) return -1;
        n = r == 1 ? child : -1;
    }
    *carry = c;
    *node = n;
    return n >= 0;
}

/* The bound on everyone else's rights over `path`: the `other` of the node at
 * or above it, as fs_server reads it from a token. -2 if the name is absent. */
static int64_t bound(const char *path, int last_file)
{
    char comp[FSP_MAX_DEPTH][FSP_NAME];
    int d = fsp_split(path, (unsigned)strlen(path), comp);
    if (d < 0) return -9;
    int n = tree.node[0].nchild > 0 ? 0 : -1, at = 0;
    for (int k = 0; k < d; k++) {
        if (n < 0) continue;
        int child;
        uint32_t c;
        int r = fsp_step(&tree, n, comp[k], !(last_file && k == d - 1), &child, &c);
        if (r < 0) return -2;
        at = child;
        n = r == 1 ? child : -1;
    }
    return tree.node[at].other;
}

#define RX (FS_R_READ | FS_R_LOOKUP | FS_R_EXEC)

int main(void)
{
    unsigned bad;
    uint32_t carry;
    int node;

    /* ---- the language ---- */
    check(parses(fsp_default_text, 0) && pol.n == 6, "default-parses");
    check(parses(fsp_admin_only_text, 0) && pol.n == 1, "admin-only-parses");
    check(parses("# a comment\n\n   \n@all /bin read # trailing\r\n", 0) && pol.n == 1 &&
          pol.line[0].rights == FS_R_READ, "comments-blank-crlf");
    check(parses("alice\t/home/alice\tread,write,lookup", 0) && pol.n == 1 &&
          pol.line[0].depth == 2 && strcmp(pol.line[0].comp[1], "alice") == 0, "tabs-no-final-newline");
    check(parses("@all / all\n", 0) && pol.line[0].depth == 0 && pol.line[0].rights == FS_R_ALL, "root-path");
    check(parses("@self /tmp read\n", 0) && pol.line[0].tmp && !pol.line[0].home, "self-tmp-parses");
    check(parses("@all /tmp read\n", 0) && !pol.line[0].tmp, "all-tmp-is-a-path");

    static const struct { const char *text; const char *name; unsigned line; } bad_cases[] = {
        { "@staff /x read\n", "unknown-group", 1 },
        { "@all /x grant\n", "grant-refused", 1 },
        { "@all /x snapshot\n", "snapshot-refused", 1 },
        { "@all /x reed\n", "unknown-right", 1 },
        { "@all x read\n", "relative-path", 1 },
        { "@all /x/ read\n", "trailing-slash", 1 },
        { "@all /x//y read\n", "empty-component", 1 },
        { "@all /x/../y read\n", "dotdot-component", 1 },
        { "@all /./y read\n", "dot-component", 1 },
        { "@all /aaaaaaaaaaaaaaaaaaaaaaaa read\n", "component-too-long", 1 },
        { "@all /a/b/c/d/e/f/g/h/i read\n", "path-too-deep", 1 },
        { "@all /x read extra\n", "four-fields", 1 },
        { "@all /x\n", "two-fields", 1 },
        { "alice ~ read\n", "home-without-self", 1 },
        { "@self /home/x read\n", "self-without-home", 1 },
        { "@self /tmp/x read\n", "self-below-tmp", 1 },
        { "@self /var read\n", "self-other-path", 1 },
        { "@self /tmpx read\n", "self-tmp-prefix", 1 },
        { "@all /x read,,write\n", "empty-right", 1 },
        { "@all /x read,\n", "trailing-comma", 1 },
        { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa /x read\n", "principal-too-long", 1 },
        { "# ok\n@all /bin read\n@all /x nope\n", "bad-line-numbered", 3 },
    };
    for (unsigned i = 0; i < sizeof(bad_cases) / sizeof(bad_cases[0]); i++) {
        int ok = !parses(bad_cases[i].text, &bad) && pol.n == 0 && bad == bad_cases[i].line;
        check(ok, bad_cases[i].name);
    }
    {
        static char big[FSP_MAX_BYTES + 2];
        memset(big, ' ', sizeof(big) - 1);
        check(!parses(big, &bad) && pol.n == 0, "file-too-large");
        static char many[FSP_MAX_LINES * 20 + 32];
        many[0] = 0;
        for (int i = 0; i <= FSP_MAX_LINES; i++) strcat(many, "@all /bin read\n");
        check(!parses(many, &bad) && pol.n == 0 && bad == FSP_MAX_LINES + 1, "too-many-lines");
        char nul[] = "@all /bin read\n@a\0l /x read\n";
        check(fsp_parse(nul, sizeof(nul) - 1, &pol, &bad) != 0 && pol.n == 0, "nul-byte");
    }

    /* ---- the default, for an ordinary account ---- */
    check(compile(fsp_default_text, "user", "/home/user", 0) == 0, "compile-user");
    check(tree.node[0].eff == 0 && tree.node[0].nchild == 5, "user-root-not-granted");
    check(fsp_op_rights(&tree, 0) == FSP_PASS_RIGHTS, "user-root-lookup-and-list-only");
    check(walk("/etc", 0, &carry, &node) == -1, "user-reached-ungranted");
    check(walk("/etc/passwd", 1, &carry, &node) == -1, "user-reached-under-ungranted");
    check(walk("/bin", 0, &carry, &node) == 0 && carry == (FS_R_READ | FS_R_LOOKUP | FS_R_EXEC),
          "user-bin-read-only");
    check(walk("/bin/ls", 1, &carry, &node) == 0 && !(carry & (FS_R_WRITE | FS_R_CREATE)),
          "user-below-bin-read-only");
    check(walk("/home", 0, &carry, &node) == 1 && carry == FS_R_ALL &&
          fsp_op_rights(&tree, node) == FSP_PASS_RIGHTS, "user-home-dir-tracked-pass-through");
    check(walk("/home/user", 0, &carry, &node) == 0 && carry == FS_R_ALL, "user-own-home-all");
    check(walk("/home/other", 0, &carry, &node) == -1, "user-other-home-absent");
    check(walk("/home/user/deep/er", 0, &carry, &node) == 0 && carry == FS_R_ALL, "user-below-home");
    check(walk("/home", 0, &carry, &node) == 1 &&
          fsp_visible(&tree, node, "user", 1) && !fsp_visible(&tree, node, "other", 1),
          "user-home-listing-filtered");
    check(fsp_visible(&tree, 0, "bin", 1) && fsp_visible(&tree, 0, "usr", 1) &&
          !fsp_visible(&tree, 0, "etc", 1) && !fsp_visible(&tree, 0, "sbin", 1),
          "user-root-listing-filtered");
    /* ITS OWN /tmp: private, read-write, never exec, and listed. */
    check(fsp_is_private(&tree, 0, "tmp") && !fsp_is_private(&tree, 0, "bin"), "user-tmp-private");
    check(walk("/tmp", 0, &carry, &node) == 0 &&
          carry == (FS_R_READ | FS_R_WRITE | FS_R_LOOKUP | FS_R_CREATE | FS_R_DELETE | FS_R_SETATTR),
          "user-tmp-rights-no-exec");
    check(fsp_visible(&tree, 0, "tmp", 1), "user-tmp-listed");
    /* A file standing where the policy names a directory on the way to a grant
     * is absent, never readable as a pass-through. */
    check(walk("/home", 1, &carry, &node) == -1, "pass-through-file-absent");

    /* ---- which policy applies ---- */
    {
        const char *junk = "this is not a policy\n";
        const char *good = "@all /bin read\n";
        check(fsp_load(1, 1, junk, (uint32_t)strlen(junk), &pol, &bad) == FS_SESSION_SRC_DEFAULT &&
              pol.n == 6, "ephemeral-ignores-file");
        check(fsp_load(0, 0, 0, 0, &pol, &bad) == FS_SESSION_SRC_ADMIN_ONLY && pol.n == 1,
              "persistent-absent-admin-only");
        check(fsp_load(0, 1, junk, (uint32_t)strlen(junk), &pol, &bad) == FS_SESSION_SRC_MALFORMED &&
              pol.n == 1 && bad == 1, "persistent-malformed-admin-only");
        check(fsp_load(0, 1, good, (uint32_t)strlen(good), &pol, &bad) == FS_SESSION_SRC_FILE &&
              pol.n == 1, "persistent-file");

        /* Admin-only means it: an ordinary account compiles to nothing at all. */
        struct fsp_who user = { "user", "/home/user", 0, "root" }, root = { "root", "/", 1, "root" };
        (void)fsp_load(0, 0, 0, 0, &pol, &bad);
        check(fsp_compile(&pol, &user, &tree) == 0 && tree.node[0].below == 0, "admin-only-gives-user-nothing");
        check(fsp_compile(&pol, &root, &tree) == 0 && tree.node[0].eff == FS_R_ALL &&
              tree.node[0].nchild == 0, "admin-only-gives-admin-root");
    }

    /* ---- the default, for the administrator ---- */
    check(compile(fsp_default_text, "root", "/", 1) == 0, "compile-admin");
    check(tree.node[0].eff == FS_R_ALL, "admin-root-all");
    check(walk("/etc", 0, &carry, &node) == 0 && carry == FS_R_ALL, "admin-reaches-etc");
    /* A NARROWER LINE BELOW NEVER NARROWS A WIDER ONE ABOVE: "@all /usr read"
     * must not take admin's "/ all" away inside /usr. */
    check(walk("/usr", 0, &carry, &node) == 0 && carry == FS_R_ALL, "admin-usr-not-narrowed");
    check(walk("/home/anyone", 0, &carry, &node) == 0 && carry == FS_R_ALL, "admin-reaches-every-home");
    check(fsp_is_private(&tree, 0, "tmp"), "admin-tmp-private-too");

    /* ---- a deeper grant adds ---- */
    {
        const char *t = "@all /usr read,lookup\nalice /usr/local all\n";
        check(compile(t, "alice", "/home/alice", 0) == 0, "compile-deeper");
        check(walk("/usr", 0, &carry, &node) == 1 &&
              fsp_op_rights(&tree, node) == (FS_R_READ | FS_R_LOOKUP), "deeper-parent-tracked-narrow");
        check(walk("/usr/local", 0, &carry, &node) == 0 && carry == FS_R_ALL, "deeper-grant-reachable");
        check(walk("/usr/bin", 0, &carry, &node) == 0 && carry == (FS_R_READ | FS_R_LOOKUP),
              "deeper-sibling-narrow");
        /* For bob, alice's /usr/local is a bound (§7.1), a node of his tree,
         * and gives him nothing: read and lookup there as everywhere in /usr. */
        check(compile(t, "bob", "/home/bob", 0) == 0 &&
              walk("/usr", 0, &carry, &node) >= 0 && carry == (FS_R_READ | FS_R_LOOKUP) &&
              walk("/usr/local", 0, &carry, &node) == 0 && carry == (FS_R_READ | FS_R_LOOKUP) &&
              bound("/usr/local/f", 1) == FS_R_ALL, "deeper-not-for-others");
    }

    /* ---- @self, only as /home/<name> ---- */
    check(compile("@self ~ all\n", "x", "/", 0) == 0 && tree.node[0].below == 0, "self-root-home-nothing");
    check(compile("@self ~ all\n", "x", "/home/a/b", 0) == 0 && tree.node[0].below == 0, "self-deep-home-nothing");
    check(compile("@self ~ all\n", "x", "/srv/x", 0) == 0 && tree.node[0].below == 0, "self-elsewhere-nothing");
    check(compile("@self ~ read\n", "x", "/home/x", 0) == 0 &&
          walk("/home/x", 0, &carry, &node) == 0 && carry == FS_R_READ, "self-home");

    /* ---- named accounts and @admin ---- */
    check(compile("alice /srv all\n", "bob", "/home/bob", 0) == 0 && tree.node[0].below == 0, "name-is-exact");
    check(compile("@admin /srv all\n", "bob", "/home/bob", 0) == 0 && tree.node[0].below == 0, "admin-line-not-for-user");
    check(compile("@admin / all\n", "@admin", "/home/x", 0) == 0 && tree.node[0].below == 0,
          "account-named-like-a-group");

    /* ---- a grant below a private /tmp can mean nothing, so it is refused ---- */
    check(compile("@self /tmp all\nalice /tmp/x read\n", "alice", "/home/alice", 0) == -1,
          "grant-below-private-tmp-refused");
    check(compile("@self /tmp all\nalice /tmp/x read\n", "bob", "/home/bob", 0) == 0,
          "grant-below-private-tmp-only-for-its-account");

    /* ---- bounds ---- */
    {
        static char wide[FSP_MAX_LINES * 24];
        wide[0] = 0;
        for (int i = 0; i < FSP_NODES; i++) {
            char l[24];
            snprintf(l, sizeof(l), "@all /d%d read\n", i);
            strcat(wide, l);
        }
        check(compile(wide, "u", "/home/u", 0) == -1, "nodes-overflow-refused");
    }

    /* ---- who else reaches it (§7.1) ---- */
    check(compile(fsp_default_text, "user", "/home/user", 0) == 0, "compile-user-bounds");
    check(bound("/home/user/f", 1) == 0, "user-own-home-private");
    check(bound("/tmp/f", 1) == 0, "user-tmp-private-bound");
    check(bound("/bin/ls", 1) == RX, "user-bin-shared-with-all");
    check(compile(fsp_default_text, "root", "/", 1) == 0, "compile-admin-bounds");
    check(bound("/home/user/f", 1) == FS_R_ALL, "admin-sees-every-home-shared");
    check(bound("/etc/passwd", 1) == 0, "admin-etc-private");
    check(bound("/bin/ls", 1) == RX, "admin-bin-shared-with-all");
    check(bound("/tmp/f", 1) == 0, "admin-tmp-private-bound");
    /* An object reachable through another grant is bounded by it, and adding
     * that grant as a node changes nothing the session may do or see. */
    {
        const char *t = "@self ~ all\nbob /home/alice/shared read,lookup\n";
        check(compile(t, "alice", "/home/alice", 0) == 0, "compile-shared");
        check(bound("/home/alice/f", 1) == 0, "home-outside-shared-private");
        check(bound("/home/alice/shared/f", 1) == (FS_R_READ | FS_R_LOOKUP), "shared-subdir-bounded");
        check(bound("/home/alice/shared/deep/f", 1) == (FS_R_READ | FS_R_LOOKUP), "shared-deeper-bounded");
        check(walk("/home/alice/shared", 0, &carry, &node) == 0 && carry == FS_R_ALL,
              "other-node-changes-no-rights");
        check(walk("/home/alice", 0, &carry, &node) == 1 &&
              fsp_names(&tree, node, "shared") && !fsp_names(&tree, node, "notes"),
              "names-policy-paths");
        check(walk("/home/alice", 0, &carry, &node) == 1 && fsp_visible(&tree, node, "notes", 0),
              "other-node-hides-nothing");
    }
    /* Another's grant the session cannot reach any part of adds nothing. */
    {
        check(compile("@self ~ all\n", "alice", "/home/alice", 0) == 0, "compile-plain");
        unsigned plain = tree.n;
        check(compile("@self ~ all\nbob /srv/data read\n", "alice", "/home/alice", 0) == 0 &&
              tree.n == plain && !fsp_visible(&tree, 0, "srv", 1), "other-outside-reach-ignored");
    }
    /* DECISION 16: the administrator's lines, by group or by name, are never
     * "other"; an ordinary account granted "/" by name is. */
    check(compile("@admin / all\nroot /home/carol read\n@self ~ all\n", "carol", "/home/carol", 0) == 0 &&
          bound("/home/carol/f", 1) == 0, "admin-lines-not-other");
    check(compile("ops / all\n@self ~ all\n", "user", "/home/user", 0) == 0 &&
          bound("/home/user/f", 1) == FS_R_ALL, "ordinary-root-grant-counts");
    /* The wildcard: every other account's home, never the session's own. */
    check(compile("ops / all\n@self ~ all\n", "ops", "/home/ops", 0) == 0, "compile-wildcard");
    check(bound("/home/ops/f", 1) == 0, "wildcard-skips-own-home");
    check(bound("/home/bob/f", 1) == FS_R_ALL, "wildcard-covers-others");
    /* Another account's home grant lies ABOVE a grant of the session's own,
     * reached through a pass-through, and still bounds what is under it; the
     * wildcard there makes no other home visible. */
    check(compile("alice /home/bob/shared read,lookup\n@self ~ all\n", "alice", "/home/alice", 0) == 0 &&
          bound("/home/bob/shared/f", 1) == FS_R_ALL, "other-home-above-own-grant");
    check(walk("/home", 0, &carry, &node) == 1 && !fsp_visible(&tree, node, "carol", 1) &&
          walk("/home/carol", 0, &carry, &node) == -1, "wildcard-under-pass-through-hides");
    check(walk("/home", 0, &carry, &node) == 1 && fsp_names(&tree, node, "anyone"), "wildcard-names-every-home");
    /* A PRIVATE /tmp IS NOBODY ELSE'S: no grant above it reaches into it, and a
     * grant through the volume's /tmp is not about it. */
    check(compile("bob / read\n@self /tmp all\n", "alice", "/home/alice", 0) == 0 &&
          bound("/tmp/f", 1) == 0, "private-tmp-not-inherited");
    check(compile("@self /tmp all\nbob /tmp/x read\n", "alice", "/home/alice", 0) == 0 &&
          tree.n == 2, "other-through-private-tmp-skipped");
    /* OTHERS THAT DO NOT FIT leave the session's own tree exactly as it was and
     * say every bound is every right. */
    {
        static char wide[FSP_MAX_LINES * 24];
        strcpy(wide, "ops / all\n");
        for (int i = 0; i < FSP_NODES; i++) {
            char l[24];
            snprintf(l, sizeof(l), "bob /d%d read\n", i);
            strcat(wide, l);
        }
        check(compile(wide, "ops", "/home/ops", 0) == 0 && tree.other_full && tree.n == 1 &&
              tree.node[0].nchild == 0 && tree.node[0].ogrant == 0, "others-overflow-falls-back");
        /* The same tree, the next session: nothing of the last one is kept. */
        check(compile("ops / all\n@self ~ all\n", "ops", "/home/ops", 0) == 0 && !tree.other_full &&
              bound("/home/bob/f", 1) == FS_R_ALL, "tree-reuse-clears-overflow");
    }

    /* ---- the mode bits (§7.1) ---- */
    check(fsp_mode(FS_R_ALL & FS_R_FILE_MASK, 0, 0) == 0700, "mode-private-file");
    check(fsp_mode(FS_R_READ | FS_R_EXEC, RX, 0) == 0505, "mode-shared-program");
    check(fsp_mode(FS_R_READ | FS_R_LOOKUP | FS_R_CREATE, FS_R_READ | FS_R_LOOKUP, 1) == 0705, "mode-dir");
    check(fsp_mode(FS_R_APPEND, FS_R_APPEND, 0) == 0202, "mode-append-is-w");
    check(fsp_mode(FS_R_DELETE, 0, 1) == 0200, "mode-dir-delete-is-w");

    /* ---- chmod and chown answer the truth (§7.2, decision 18) ---- */
    {
        const uint32_t file_all = FS_R_ALL & FS_R_FILE_MASK;
        check(fsp_chmod_true(0600, file_all, 0, 0), "chmod-600-private-true");
        check(fsp_chmod_true(0700, file_all, 0, 0), "chmod-700-private-true");
        check(!fsp_chmod_true(0644, file_all, 0, 0), "chmod-looser-refused");
        check(!fsp_chmod_true(0600, file_all, RX, 0), "chmod-600-shared-refused");
        check(fsp_chmod_true(0605, file_all, RX, 0), "chmod-exact-other-true");
        check(!fsp_chmod_true(0640, file_all, 0, 0), "chmod-group-refused");
        check(!fsp_chmod_true(04600, file_all, 0, 0) && !fsp_chmod_true(02600, file_all, 0, 0) &&
              !fsp_chmod_true(01600, file_all, 0, 0), "chmod-setid-sticky-refused");
        check(!fsp_chmod_true(0600, FS_R_READ, 0, 0), "chmod-owner-more-than-held-refused");
        check(fsp_chmod_true(0400, FS_R_READ, 0, 0) && fsp_chmod_true(0000, FS_R_READ, 0, 0),
              "chmod-owner-fewer-true");
        check(fsp_chmod_true(0705, FS_R_ALL, FS_R_READ | FS_R_LOOKUP, 1), "chmod-dir-exact-true");
        check(fsp_chown_true(0xFFFFFFFFu, 0xFFFFFFFFu, 5, 7) && fsp_chown_true(5, 7, 5, 7) &&
              fsp_chown_true(5, 0xFFFFFFFFu, 5, 7), "chown-self-true");
        check(!fsp_chown_true(6, 0xFFFFFFFFu, 5, 7) && !fsp_chown_true(5, 8, 5, 7) &&
              !fsp_chown_true(0, 0, 5, 7), "chown-other-refused");
    }

    printf("FS_POLICY_TEST: PASS %d checks\n", checks);
    return 0;
}
