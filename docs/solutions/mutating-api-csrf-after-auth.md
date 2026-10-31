# Mutating /api CSRF runs after auth

`originAllowed` requires a Host port. `httptest.NewRequest` with `Host: 127.0.0.1` and no port fails that check. If the Origin / Sec-Fetch-Site wrapper runs before auth, gated routes return 403 `forbidden` instead of 403 `admin token required` or 401.

Apply `mutatingAPIOK` after credential checks: wrap the mux with `protectMutatingAPI` inside `withAuth`, and call `mutatingAPIOK` at the end of `guardPermission` so gated routes (which never reach the mux) get the same check.
