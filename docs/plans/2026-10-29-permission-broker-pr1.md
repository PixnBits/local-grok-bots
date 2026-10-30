# Permission broker PR 1 (backend core)

## Goal

Fail closed. A tool runs only when the broker returns an explicit allow for that exact input. A down, late, or ambiguous broker denies. A non-admin path cannot approve or create a rule.

## In this run

- `cmd/lgb-permhook`: stdlib PreToolUse hook. Exit 2 plus JSON deny on every doubt. Exit 0 only for verdict `allow`. Own deadline 2.5s, under the 30s settings timeout.
- Policy `cli.permission.broker` default off. `hook` arms Claude `--settings` with only our PreToolUse hook (`matcher` `*`, timeout 30, `onFailure` `block`, `continueOnBlock` true) and keeps `--setting-sources=`. Launch refuses bypass flags, `acceptEdits`, and `--allowedTools`. Headless asks deny.
- `internal/permbroker`: per-bot unix socket, SO_PEERCRED, evaluate-only JSON, decision order, pending store, one-time tokens, approval scopes, append-only redacted audit, classifier stub that can only raise.
- Admin HTTP list / approve / deny / deny-all on the existing admin token, host allowlist, and cross-site check. Run tokens get 403.
- `run_shell` uses the same engine when the flag is on. Literal `git push` still uses the push card. Allowed shells may use `bash --norc --noprofile`.
- Shell parse starts with `mvdan.cc/sh/v3` v3.12.0. Literal simple commands yield an argv vector. Anything else asks. Go stays 1.24.

## Out of this run

Full compound parsing, shipped git/gh/path tables beyond the small starter table, per-part task grants, the bypass corpus, the approvals UI, pattern rules, and installing `/etc/claude-code/managed-settings.json`.

## Decision order

Deny rule, then a one-time human token, then critical asks, then a non-eligible or compound input (task grant of the full input only), then per-bot rules (ask beats allow), then global rules (ask beats allow; no global allow when the level forbids global), then a task grant, then ask. Ask becomes a pending item and a hook deny. Pending items do not expire. They are cancelled on session end, bot restart, or a ruleset change. Identical asks collapse.

## Tests that must exist

Daemon stopped, daemon hang past the hook deadline, hook SIGKILLed, hook over the CLI timeout, garbage / empty / unknown / oversized verdict, approve-then-retry once, second retry and different argv / cwd / session blocked, project and user Claude settings ignored, jail socket cannot approve or create rules, deny lets the run continue, classifier only escalates, policy cannot lower a shipped level, critical and compound cannot be saved as bot or global rules.
