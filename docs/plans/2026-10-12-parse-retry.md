# Parse-error retry

CodeSmith's run ended `error` with `ollama: XML syntax error on line 3: unexpected end element </parameter>`. The model emitted a tool call Ollama could not parse, and the daemon treated that like Ollama being down.

## Decisions

- A tool-call parse error is diagnosed in the run transcript and the model is called once more in that same run. The diagnosis is not a thread message.
- A second parse error ends the run. The 8-round cap still applies. A parse error on the last round is that error. It does not take a ninth call and it does not become `tool round limit`.
- Unreachable Ollama, an HTTP error, a stream failure, and a timeout are not retried.

## Tests

- The XML error from this run is classified as a parse error. "model not found" is not.
- A fake model that returns that error, then `list_bots`, then a sentence, stores only the sentence. The retry sees the diagnosis. A second parse error ends the run. An unreachable error is still one call.
