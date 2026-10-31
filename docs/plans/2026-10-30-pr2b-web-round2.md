# WEB round-2 (permission broker 2b)

## Goal

Land designer M1–M7 and S1–S7, soft F1–F4, and tester MUST 2 plus SHOULD 3, 4 (client), 6, 7, 9 in the self-served page. CSP stays `default-src 'self'`: no inline script, style, `style=`, or `on*=` in `index.html`.

## Wrong if

Focus lands on `document.body` after a decision, Escape, revoke, or chevron re-render. Batch ignores per-item results or stays clickable in flight. Non-literal cards offer a ladder. Legacy rows tell people to write a trailing `*`. Edit still posts create plus delete. Risk rows stay flat text. A second Approvals button shows beside the thread at ≥980.

## Do

- Store an intended-focus key and apply it after render. Decisions go to the next card's primary action (Deny on high/critical), or the queue heading when empty. Escape goes to the visible Approvals button. Revoke goes to the next row's actions button or the section heading. Chevron open focuses the first ladder step; close focuses the chevron.
- Slide-over and sheet: `role=dialog` and `aria-modal="true"` with the existing Tab trap. Docked (≥1180): `role=region` and no `aria-modal`. Rule menu: ArrowUp/Down, Home, End, Escape back to the trigger.
- Batch uses approve-all and deny-all, disables both buttons while in flight, and toasts the success count. Stale ids add "N done, M already answered."
- `allowed_scopes` of only `once` shows Approve once and Deny. High and unclassified never offer global.
- Legacy copy, hide Confirm when `confirmable` is false, show `never_reason`. Pattern help: one word, not last. `git_reason` as a plain line. Edit posts `/replace` and toasts when `revoked` is false.
- Home-relative cwd, risk labels, provenance phrases, "Not yet", edit note, 44px targets, task clamp, Open thread, group counts, one batch row, critical chip icon, model-note copy, real risk tables.

## Check

`gofmt -l .`, `go vet ./...`, `go test -race ./...`. String tests in `web/approvals_test.go` cover each item.
