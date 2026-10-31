# Focus, shell cwd, and the banned outline string

## Focus does not survive a hidden dialog or a replaced node

At widths below the dock, `#approvals` is a modal. Leaving `aria-modal` on after the panel is hidden sends Escape focus to `body`, because the visible Approvals button sits outside that dialog. Remove `aria-modal` before focusing the opener, and pick the opener whose ancestors are actually shown. The roster button is `display: none` from 980px up, so the first `button.appr-btn` in the document is the wrong target.

Approve all and Deny all replace the queue. Put the next focus key on an element that still exists after the paint: `#approvals-empty-title` while the panel stays open, or the visible opener when an auto-opened dock closes. A rules Undo key must stay set until the restored row is in the DOM. A one-shot `activeElement` check can pass on a toast bridge and then fall back to `body`. Sample until the same non-body target holds across a poll.

`TestThemeStatic` rejects the literals `outline: none` and `outline: 0` in the embedded page. Suppress a programmatic ring with `outline-style: none` and `focus({ focusVisible: false })`.

## Shell cwd is the bot workspace, and the jail must actually `cd`

`run_shell` used to report the bot workspace for every call, so two identical low commands never differed by cwd and the live batch buttons stayed hidden. Track the directory across `cd` inside that workspace, reject `..`, `~`, `cd -`, and symlinks that leave it. Update the tracked directory only when the sandbox returns success. From `s1`, the sibling is `cd ../s2`. Prove the session directory with `pwd` printing `/work/s2`.

A stored path that is still lexically inside the workspace can be replaced by a symlink to an outside directory. Re-resolve it before the broker evaluates the command and again immediately before the jail runs. On Linux open the workspace directory and `openat2` the relative path with `RESOLVE_BENEATH` (`ENOSYS` uses `filepath.EvalSymlinks`; other OS use `EvalSymlinks` only). The resolved path must be a directory inside `EvalSymlinks(workspace)`. Pass that path as the broker `Cwd`. The jail uses `bwrap --chdir /work/<rel>` (unshare chdirs the same way), not a `cd -- rel &&` prefix. If the check fails, put that bot's cwd back at the workspace root and refuse with "working directory is no longer inside the workspace; reset to the workspace root". A stored cwd that is still the workspace root is not a failure when `EvalSymlinks` says that directory does not exist yet: `gateShell` resolves before `shellWorkspace` creates the bot directory. The next command then starts at the workspace root.

The shotkit Playwright package asks for Chromium 1248. The installed browser is `~/.cache/ms-playwright/chromium-1243`. Launch that binary with `executablePath`. Do not download a browser.
