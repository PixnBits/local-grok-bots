# Ceiling never-allow and non-literal shell words

The hard deny for credential output and for hook-path changes runs only
when the broker is `hook` and the bot has a ceiling. It sits after a
deny rule and before a one-time approval, an ask rule, and the ceiling.
A bot with no ceiling still asks. The audit actor and source are
`ceiling_never_allow`. The severity word is `critical`.

An unquoted backslash makes the shell word not literal. The check does
not unescape it. A quoted backslash stays in the word.

A set location, config, or command-helper git variable asks, including
an empty value and a shell assignment prefix. Identity variables such
as `GIT_AUTHOR_NAME` do not.

A created directory from `git clone` or `git init` uses the client-config
class on the spelled path and the resolved path. `.husky` and `.lgb`
are in that class. `.vscode` and `.idea` count when they are the
created directory.
