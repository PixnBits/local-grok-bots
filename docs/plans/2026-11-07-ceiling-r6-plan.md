# Ceiling r6 plan

Fail closed. Do not change the critical sole-reason exception.

1. Resolver and `pathParts` keep link-target and component bytes. NUL is `errPathUnrepresentable`. Tests plant the git-apply decoy chains (trailing space, leading space, leading tab, backslash names) onto `.git/config`, a hook, `.claude/settings.json`, and `.grok/settings.json`. Decoy files exist so a trim or a backslash rewrite would allow.
2. An existing regular file with `Nlink>1`, or the same inode as a sensitive file, is not ceiling-auto-approved. Outside hardlink kills Nlink removal. A linux bind mount with `Nlink==1` kills SameFile removal.
3. Symlink cwd equal to the workspace root allows. Symlink cwd to a subdir asks. The resolve fallback stays.
4. Take managed `GIT_DIR` / `GIT_WORK_TREE` place checks and quoted `ext::` on `git fetch` / `git ls-remote`. Leave the hook cache parent-mode check (test umask, not a code default).
5. Tests that need a uid-0 `/usr/bin` or `/bin` skip when those directories are the overflow uid. Do not weaken `rootOwnedDir` or `NoteHookFile`.
