# Permission broker PR 2b UI

Goal: Approvals queue, shared request cards, Rules page, and critical alerts in `web/index.html`, backed by the existing `/api/permbroker/` routes.

Wrong if a deny stops a run, a prompt offers a pattern, an asset loads from another origin, Esc approves, or the page offers a scope outside `allowed_scopes`.

## Units

- Header control on every top bar; queue dock / slide-over / sheet; `#approvals`.
- One card renderer for the queue and the thread. Friction, ladder, nudge, compound note, advisory, critical band.
- `/rules` and `/rules?bot=` served by the daemon. Rules list, risk tables, new-rule form.
- Notifications API from the page only. Legacy permission cards stay, without stop-on-deny copy.
- String tests in `web/approvals_test.go`.
