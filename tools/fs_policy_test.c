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
 * the first check that did not hold, and exits non-zero then.
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
    struct fsp_who who = { name, home, admin };
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

int main(void)
{
    unsigned bad;
    uint32_t carry;
    int node;

    /* ---- the language ---- */
    check(parses(fsp_default_text, 0) && pol.n == 5, "default-parses");
    check(parses(fsp_admin_only_text, 0) && pol.n == 1, "admin-only-parses");
    check(parses("# a comment\n\n   \n@all /bin read # trailing\r\n", 0) && pol.n == 1 &&
          pol.line[0].rights == FS_R_READ, "comments-blank-crlf");
    check(parses("alice\t/home/alice\tread,write,lookup", 0) && pol.n == 1 &&
          pol.line[0].depth == 2 && strcmp(pol.line[0].comp[1], "alice") == 0, "tabs-no-final-newline");
    check(parses("@all / all\n", 0) && pol.line[0].depth == 0 && pol.line[0].rights == FS_R_ALL, "root-path");

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
    check(tree.node[0].eff == 0 && tree.node[0].nchild == 4, "user-root-not-granted");
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
    /* A file standing where the policy names a directory on the way to a grant
     * is absent, never readable as a pass-through. */
    check(walk("/home", 1, &carry, &node) == -1, "pass-through-file-absent");

    /* ---- which policy applies ---- */
    {
        const char *junk = "this is not a policy\n";
        const char *good = "@all /bin read\n";
        check(fsp_load(1, 1, junk, (uint32_t)strlen(junk), &pol, &bad) == FS_SESSION_SRC_DEFAULT &&
              pol.n == 5, "ephemeral-ignores-file");
        check(fsp_load(0, 0, 0, 0, &pol, &bad) == FS_SESSION_SRC_ADMIN_ONLY && pol.n == 1,
              "persistent-absent-admin-only");
        check(fsp_load(0, 1, junk, (uint32_t)strlen(junk), &pol, &bad) == FS_SESSION_SRC_MALFORMED &&
              pol.n == 1 && bad == 1, "persistent-malformed-admin-only");
        check(fsp_load(0, 1, good, (uint32_t)strlen(good), &pol, &bad) == FS_SESSION_SRC_FILE &&
              pol.n == 1, "persistent-file");

        /* Admin-only means it: an ordinary account compiles to nothing at all. */
        struct fsp_who user = { "user", "/home/user", 0 }, root = { "root", "/", 1 };
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

    /* ---- a deeper grant adds ---- */
    {
        const char *t = "@all /usr read,lookup\nalice /usr/local all\n";
        check(compile(t, "alice", "/home/alice", 0) == 0, "compile-deeper");
        check(walk("/usr", 0, &carry, &node) == 1 &&
              fsp_op_rights(&tree, node) == (FS_R_READ | FS_R_LOOKUP), "deeper-parent-tracked-narrow");
        check(walk("/usr/local", 0, &carry, &node) == 0 && carry == FS_R_ALL, "deeper-grant-reachable");
        check(walk("/usr/bin", 0, &carry, &node) == 0 && carry == (FS_R_READ | FS_R_LOOKUP),
              "deeper-sibling-narrow");
        check(compile(t, "bob", "/home/bob", 0) == 0 &&
              walk("/usr", 0, &carry, &node) == 0 && carry == (FS_R_READ | FS_R_LOOKUP),
              "deeper-not-for-others");
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

    printf("FS_POLICY_TEST: PASS %d checks\n", checks);
    return 0;
}
