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
