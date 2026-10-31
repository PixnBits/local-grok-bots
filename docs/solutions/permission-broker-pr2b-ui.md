# Approvals UI: same-origin page and the /rules path

The broker UI is the daemon's own `web/index.html`. Nothing on that page
may load from another origin. The only `http://` string that belongs in
the file is the SVG namespace `http://www.w3.org/2000/svg`, used by
`createElementNS`. A test that bans `http://` and `https://` has to
strip that namespace first, and it should still fail on `//cdn` and on
a `<script src>` or `<link href>` that is not a same-origin path.

`GET /rules` (including `?bot=`) has to serve that same HTML. Any other
extra path 404s, so a client-side route is not enough. `#approvals` is
a hash on the current page, not a path and not a view name.

## Focus after a decision survives the rebuild

`renderApprovals` and `paintRules` replace the nodes that held focus, so
`document.activeElement` is `document.body` unless a key is stored first.
`approvals.intendedFocus` is that key (`q:deny:<id>`, `q:approve:<id>`,
`approvals-title`, `approvals-opener`, `rules:<data-rules-focus>`, or a
`t:` thread key). Set it before the render that drops the card, and call
`applyIntendedFocus` at the end of the render, including the signature
short-circuit. Do not capture `activeElement` for a control that the
rebuild removes.

The queue and the thread both rebuild. A `t:` key is applied from
`renderBrokerThread` before the queue render, which clears the key.
A `q:` key is left for the queue. If the resolved node sits inside
`[hidden]` (the queue is closed while a thread card was answered), fall
back to the visible Approvals button, skipping `display: none` copies.
Opening the ladder focuses its first step (`q:`/`t:ladder:<id>`); closing
it focuses the chevron. Sending focus to the next card would close the
ladder before it can be used.
