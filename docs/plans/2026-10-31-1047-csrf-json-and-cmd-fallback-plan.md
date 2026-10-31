# CSRF JSON wrapper + command fallback

## Goal

One Origin / Sec-Fetch-Site + JSON Content-Type check on every state-changing `/api` route. Permission card command text falls back to `args.cmd` when `args.command` is missing or whitespace.

Wrong if a same-origin UI mutation 415s, a token-auth non-browser caller (MCP / STT audio) breaks, or tests/docs use a real address.

## Decisions

- Wrap `withAuth` with one middleware on `Handler()`. POST/PUT/PATCH/DELETE under `/api/` run `brokerPostOK` (same `sttCrossSite` + `originAllowed` as today), then require media type `application/json` (parameters allowed).
- Missing Content-Type is 415 when the request has a body. Bodyless DELETE may omit it.
- Exceptions (keep existing auth; origin check still applied because empty Origin / Sec-Fetch-Site already pass):
  - `POST /api/mcp/permission` and `POST /api/mcp/permission/{token}`: CLI MCP, token auth, skip JSON Content-Type.
  - `POST /api/stt`: PCM `application/octet-stream`, skip JSON Content-Type.
- `web/app.js` `api()` and `brokerCall()` always send `Content-Type: application/json` on mutating fetches, body `"{}"` when none.
- `do()` sets JSON Content-Type on POST/PUT/PATCH even with a nil body so cancel/continue/retry tests keep working.
- `liveToolLine` and `toolCallLabel`: if `command` is blank/whitespace/missing, use `cmd`.

## Units

- U1: middleware + `do()` + daemon tests + doc note
- U2: `app.js` headers + web fetch test
- U3: command fallback + `web/approvals_test.go` string test

## Tests

- `TestMutatingAPICrossOriginForbidden`
- `TestMutatingAPINonJSONContentType`
- `TestMutatingAPISameOriginJSON`
- `TestMutatingFetchSetsJSONContentType`
- `TestCommandFallsBackToCmd`

Cross-origin Origin is `http://192.0.2.10:9999` with `Sec-Fetch-Site: cross-site`.

## Out of scope

Commit, push, GET CSRF, changing MCP/STT auth.
