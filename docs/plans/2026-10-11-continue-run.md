# Continue a capped run

A run that spends its 8 model rounds ends `error` / `tool round limit`, the same as today. The thread can offer another 8 rounds for that work only.

Tool calls and tool results stay in the run's in-memory transcript. The thread stores the bot's short texts, so a new user message cannot see what the tools returned. Continue has to reuse the transcript. The recent CodeSmith cap cannot be continued: its tool results were never stored. The offer appears on the next cap after this ships.

## Decisions

- The default cap stays 8. Continue does not raise it for other bots or later runs. The bot has no tool that extends the cap.
- The capped run stays `error`. Continue is a new run. A run still ends in exactly one terminal status.
- The daemon keeps one transcript per bot, in memory, keyed by the capped run. The client does not send a transcript. A restart drops it.
- `GET /api/bots` and `GET /api/bots/{id}` include `continue_run_id` while the offer is held. `POST /api/bots/{id}/runs/{run_id}/continue` starts the new run and returns its `run_id`. While that bot is running, a second continue is 409 and does not take the transcript. A missing or mismatched offer is 404. A paused bot and a shutting-down daemon refuse without taking it. A timed-out Ollama run uses the same continue offer (partial included). `POST /api/bots/{id}/runs/{run_id}/retry` starts a new run of that user turn without the partial or the notice; see `docs/specs.md`.
- A new user message drops the offer before the next run starts. A timer or DM turn drops it by running without the saved transcript. Hitting the cap again offers continue for the new run.
- The note says "Stopped after 8 tool rounds." and has a Continue button. Other failures still say "Run failed". Hide, pin, and the rest of the page stay as they are.

## Out

Raising the default cap, persisting tool transcripts, resuming a run the daemon already finished, resuming the historical CodeSmith run, auto-continue, a round-count picker.

Lesson: `~/.grok/lessons/local-grok-bots/tool-round-continue.md`.

## Tests

- Eight `list_bots` rounds end `error` / `tool round limit` with `continue_run_id` set. Continue's next model call sees a tool result and then finishes `done`. The capped run stays `error`. The offer is cleared. The default cap is still 8.
- A new user message after the cap is a model call with no tool result. The old continue id is 404.
- A second continue, while the first continuation is inside the model call, is 409. The first continuation still finishes and has seen the tool result.
- Continue with no offer is 404. A paused bot is refused and the offer stays.
