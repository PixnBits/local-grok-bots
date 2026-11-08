# GitHub read proxy queries are rebuilt

`classifyAPI` used to reject every query string. Issue and pull-request list routes need `page` and `per_page`. The proxy rebuilds those and, only on the issues collection, `state=open`. Any other key, a duplicate, or `state=closed` is still refused. `GET /repos/{owner}/{repo}?page=2` stays refused. A new read route has to be added to `apiReadPath` and `canonicalAPIQuery` together, or the jail socket returns 403 before the daemon's size cap runs.
