# COI proxy jail

The jailed CLI must not read a real credential, mount host `/run`, or open TCP except through an allowlisted egress proxy.

## Decisions

- `--unshare-net` means no `resolv.conf` bind and no host `/run` mount. The host proxy resolves DNS.
- Also `--unshare-ipc` and `--new-session`. The only socket bind is `/coi-proxy.sock`.
- Reverse proxy, not CONNECT. CONNECT cannot inject `Authorization`. The CLI uses an `http://127.0.0.1` base URL. The proxy does TLS to the first `proxy_hosts` entry.
- Grok chat host is `cli-chat-proxy.grok.com`. Bearer comes from `auth.json` `key`. Refresh is host-side and can rotate the refresh token.
- Placeholder in the jail. Real bytes only with managed `allow_jail_credentials`. That opt-in logs a warning. Local policy cannot turn it on. `credential_files` plus `--always-approve` without the proxy and without the opt-in is denied before the hourly slot.
- Proxy failure audits `coi_proxy_unavailable` and does not copy secrets.
- Homes live under `<data>/coi/homes`. Startup deletes stale `coi-home-*`. `<workspace>/.lgb` is covered by tmpfs.
- The daemon jail is the only sandbox for this path. No `sandbox.toml` and no `--sandbox` from the daemon. The CLI backend mode is a different path.

## Tests

- Generated bwrap args mount no `/run`, `/var/run`, or `*.sock` except `/coi-proxy.sock`.
- Inside the jail, `/run`, `<ws>/.lgb/tok`, host loopback, and a documentation LAN address are unreachable.
- Placeholder omits the host token. Managed opt-in still redacts stdout.
- Local `allow_jail_credentials = true` is ignored and does not clear a managed grant. Local `proxy_hosts` can only narrow.
- Daemon denies the opt-in-missing always-approve case and a proxy with no usable token, without taking the hourly slot.
