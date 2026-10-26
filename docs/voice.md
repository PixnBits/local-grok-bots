# Voice (daemon)

`POST /api/stt` transcribes audio with a local whisper.cpp binary. It is off
until policy sets `[voice] enabled = true`. The route uses the same
authentication as the other `/api` routes. `GET /api/health` stays open.
There is no remote speech service. A missing binary, a missing model, or an
unset pair returns 503 and does not call anything else.

The request body is raw PCM: 16 kHz, mono, signed 16-bit little-endian.
A success response is JSON `{"text":"..."}`. The transcript is the response
body only. It is not written to the log or the audit sink.

| Result | When |
| --- | --- |
| 401 | A token is configured and the request has none |
| 403 | Voice is disabled. An audit row is still written |
| 413 | The body exceeds `max_body_bytes`, or the PCM is longer than `max_audio_seconds` |
| 400 | The body is shorter than one sample, or its length is odd |
| 429 | That user is over `max_requests_per_hour`. The message is `speech recognition rate limit exceeded` |
| 429 | A transcription is already running and the 2 second wait elapsed. The message is `speech recognition is busy` |
| 408 | The request context ended while waiting for the transcription slot (the client went away, or the 60 second limit elapsed). Whisper is not started. The status is 408 Request Timeout |
| 503 | Whisper is unset, or the binary or model file is missing |
| 502 | The local binary ran and failed. The message is `speech recognition failed` |

The rate limit is a rolling hour, keyed by the token name (`default` for
`AUTH_TOKEN`). It is checked after the enabled check and before the body is
read. A limit of zero or less denies the request. Audio longer than the cap
is rejected before whisper runs.

One transcription runs at a time. A second request waits up to 2 seconds
for that slot, then returns 429. If the request context ends while it is
still waiting, the response is 408 Request Timeout and whisper is not
started. 499 is not used.

## Policy

Precedence matches the rest of the daemon: managed settings, then
`policy.toml`, then the built-in default. `[voice]` keys:

| Key | Default | Hard range |
| --- | --- | --- |
| `enabled` | false | boolean |
| `bin` | unset | absolute path, with `model` |
| `model` | unset | absolute path, with `bin` |
| `max_audio_seconds` | 240 | 1 to 86400 |
| `max_body_bytes` | 8388608 (8 MiB) | 1 to 67108864 (64 MiB) |
| `max_requests_per_hour` | 60 | 1 to 100000 |

`bin` and `model` are one setting. One without the other, a relative path,
or an empty string makes the file unparseable. Environment `WHISPER_BIN` and
`WHISPER_MODEL` are the same pair. When policy sets either path, both
environment values are replaced and a warning names the override.

Managed policy may set ceilings in `[managed]`:

- `max_voice_audio_seconds`
- `max_voice_body_bytes`
- `max_voice_requests_per_hour`

A ceiling in `policy.toml` is ignored after its range is checked, with a
warning that only managed policy can set it. A `[voice]` value above a
managed ceiling is lowered to that ceiling and warned, for example
`voice.max_audio_seconds 600 lowered to managed max_voice_audio_seconds 30`.
A value already within the ceiling is not warned. Zero means no ceiling was
set. The effective limit is the `[voice]` value, or the default, then the
ceiling when the ceiling is greater than zero.

Unknown keys, the wrong type, zero, a negative number, or a value above the
hard range fail-close the file that contains them. The daemon keeps serving
with CLI backends off, the same way as any other unparseable policy. A
managed value that differs from a non-empty environment variable refuses
startup when `conflict_policy` is `refuse`.

## Audit

Every request that passes authentication writes a log row of kind `stt` and,
when an audit sink is configured, an audit record with `action` `stt`. The
fields are `who`, `bytes`, `code`, and `duration_ms` when the whole body was
read. `duration_ms` is omitted when the body was not fully read, including a
body rejected for size. The transcript, the PCM, and whisper's own output
are not fields.

## TLS

HTTPS is optional and uses the listener that `BIND_ADDR` or `[daemon] bind`
already opened. The daemon calls `ServeTLS` on that listener. It does not
open a second one.

`TLS_CERT` and `TLS_KEY` are a pair of PEM files. `TLS_SELF_SIGNED=1` writes
`DATA_DIR/tls/cert.pem` and `DATA_DIR/tls/key.pem` as mode 0600, owned by the
daemon user. An existing pair in that directory is reused and tightened to
0600. A cert without a key, or a key without a cert, refuses startup.
Self-signed mode is not combined with a cert pair.

`[daemon]` may set `tls_cert`, `tls_key`, and `tls_self_signed`. Any one of
those keys replaces the whole TLS setting: the unset siblings become empty
or false. Policy wins over the environment and warns. Managed policy that
disagrees with a non-empty `TLS_CERT`, `TLS_KEY`, or `TLS_SELF_SIGNED`
refuses startup. Operator-supplied cert files are not chmodded. Only the
generated or reused self-signed files are mode 0600.

## Permission callback

Claude's MCP permission tool needs a plain HTTP origin. When the main
listener is HTTPS, that origin is a separate loopback listener. The listener
starts only when the effective backend is Claude, `claude_transport` is
`mcp` (the default), and at least one bot is stored. An empty transport
counts as `mcp`. Ollama, Grok, `stream_control`, and `none` do not listen.
With no such bot, nothing listens and no other feature uses the port.

The address is `PERM_CALLBACK_ADDR`, or `[daemon] perm_callback_addr`, or
`127.0.0.1:0`. Policy replaces the environment. The host must be a loopback
IP (`127.0.0.0/8` or `::1`) with a port. `localhost`, `0.0.0.0`, and `::`
are rejected. After the socket is bound, a non-loopback address closes it
and the error is returned. Creating or deleting a bot starts or stops the
listener. A bind failure at startup, when a matching bot already exists,
refuses startup. A bind failure while creating a bot is logged as
`perm_callback_error` and the bot is still created.

The callback accepts only `POST /api/mcp/permission` and
`POST /api/mcp/permission/{token}`. Other paths and methods are 404. While
the main listener is plain HTTP, MCP keeps using that listener's origin.
While it is HTTPS, MCP uses the callback origin, which is empty until the
listener is up.
