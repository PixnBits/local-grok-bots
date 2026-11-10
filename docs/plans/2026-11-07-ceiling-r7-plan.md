# Ceiling r7 plan

Fail closed. A bot with no ceiling keeps the human approval path.

1. An unquoted backslash makes the shell word non-literal. Do not unescape it. Quoted words stay as the parser returns them.
2. Destinations of git clone, git init, mkdir (including -p), install -d, and cp -r use the write class check on the spelled path and the resolved path. .husky and .lgb join the client-config class. .vscode and .idea count as that class when they are the created directory.
3. ext:: on git clone and git pull asks, same as fetch and ls-remote.
4. Any set location, config, or command-helper GIT_* variable asks, including a shell assignment prefix. Identity variables such as GIT_AUTHOR_NAME do not.
5. With a ceiling and broker hook, credential output and hook-path git changes are a hard deny at every ceiling. Actor and source are ceiling_never_allow. Audit severity is critical. No ceiling still asks.
6. A write whose resolved path or nearest existing parent has a different st_dev than the workspace root asks. Same-filesystem binds stay on SameFile.
7. Docs state the check-to-write window and that an already-hardlinked file asks.
