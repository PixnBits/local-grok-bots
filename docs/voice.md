# Local voice conversations

**Status:** design. Not yet implemented. Target branch: `voice/local-browser`.
**Goal:** Grok-Bots-style voice on the existing web UI, using browser APIs and local processing only. No audio leaves the machine (no Google, no vendor STT).

This document describes the architecture. Implementation notes and current state live in the specs and README. The PRD lists voice as a later feature; this is the design for it.

## Requirements

- Real-time speech-to-text that shows words as they are recognized (interim results), like Grok, not a batch transcription that appears only at the end.
- TTS for finished bot messages.
- Interactive voice conversation mode whose turns land in the thread as normal messages.
- Fully local: browser APIs or on-device models. Optional daemon-side models on the Framework Desktop are allowed because the daemon is already local.
- Reuse the existing message path: `POST /api/bots/{id}/thread/messages` + SSE `/thread/stream`.

## Secure context

`getUserMedia` (microphone) and some Speech APIs require a secure context. Plain `http://192.168.x.x` (or any non-localhost HTTP) is not a secure context in modern Chrome/Edge/Firefox.

Options:
- Serve the UI from `localhost` (or `127.0.0.1`) on the Framework Desktop and access it that way.
- Put a local reverse proxy (Caddy, nginx, or the existing trusted proxy) in front with a self-signed or LAN cert and use HTTPS.
- For development only: browser flags or insecure-origin exceptions (not recommended for daily use).

Document the chosen path in the deploy notes when the feature lands. The daemon itself does not need to speak HTTPS; the browser context does.

## Phase 1 — Mic button + live words + TTS

**Speech-to-text (real-time words):**
- Mic button next to the existing Send button on the composer.
- Primary: Web Speech API (`SpeechRecognition` / `webkitSpeechRecognition`).
  - `processLocally = true` (Chrome 139+ / recent Edge). One-time language pack download via `SpeechRecognition.available()` + `SpeechRecognition.install()`.
  - `continuous = true`, `interimResults = true`.
  - On `result` events, update a live preview (lighter-styled span or overlay above the textarea) so interim hypotheses appear and refine immediately. Finals are solid. Do not fight the textarea caret.
  - On final / silence / stop: flush into the composer or call the existing `send()`.
- Fallback: Transformers.js + Moonshine (preferred for low-latency short utterances) or Whisper tiny/base via WebGPU with WASM fallback, running in a Web Worker. Capture via `getUserMedia` + AudioWorklet, resample to 16 kHz mono, emit progressive updates. Models cached in the browser.
- Optional daemon path for consistency: stream PCM chunks to a new `/api/stt/stream` endpoint. Daemon runs faster-whisper or whisper.cpp. Stream interim/final text back via SSE. Same live preview UI.

**TTS:**
- After the stream `done` event (or when a bot message is fully rendered), speak the final text with `window.speechSynthesis`.
- Prefer voices where `localService === true`.
- `speechSynthesis.cancel()` on new user speech for barge-in.
- Optional later: Piper or Kokoro via WASM in the browser, or daemon-side Piper returning a WAV.

**Integration:**
- Voice fills or replaces content before calling the existing `send()` function.
- TTS hooks the existing `follow(run_id)` `done` path.
- No daemon changes required for the pure-browser path.

## Phase 2 — Interactive voice mode

- Voice-mode toggle in the conversation view.
- Loop: listen → end-of-utterance (silence, VAD, or endpoint) → auto-`send()` the final transcript → follow stream → TTS the bot reply → resume listening.
- Keep the full raw transcript of the voice session in client memory.
- "End voice" just stops listening and speaking. No summary is posted.
- Decision (after phone testing): the summary option is no longer used. Every voice turn is already sent through the normal message path, so the thread already holds the full conversation as ordinary user and bot messages. A summary would duplicate it, add an extra model run, and put a long synthetic prompt in the thread. An explicit summary can still be requested by just asking the bot.
- Barge-in: new speech cancels current TTS and restarts recognition.

## Phase 2 latency reduction (streaming words into LLM, LLM into synthesizer)

After the initial Phase 2 loop is solid, explore cutting the delay between the user pausing and the bot starting to speak:

- Once the interim transcript has been stable for a short window (or on endpoint), begin streaming the partial user text into the LLM as a streaming prompt (or as an early message that can be updated).
- As LLM tokens arrive via the existing SSE stream, feed complete sentence chunks (or punctuation-bounded segments) directly into the synthesizer instead of waiting for the full `done` event.
- Cancel or revise if the user continues speaking (barge-in / correction).
- This requires careful stability detection on the STT side and sentence buffering on the TTS side. It is an optimization on top of the Phase 2 state machine, not a prerequisite.

The existing message and stream path remains the source of truth; the streaming is a latency overlay.

## User settings and device detection

Avoid loading heavy models on lightweight devices.

- Settings (stored in localStorage or a simple daemon preference later):
  - Preferred STT path: Web Speech (processLocally) / WASM Moonshine / WASM Whisper / daemon STT.
  - Preferred TTS: system voices / Piper WASM / daemon Piper.
  - Voice mode auto-submit on endpoint vs manual confirm.
  - Maximum model size / quality floor.
- Device detection at first use (or on demand):
  - `navigator.hardwareConcurrency`, `navigator.deviceMemory` (where available).
  - WebGPU presence (`navigator.gpu`).
  - Optional short benchmark of a tiny model load time.
- Decision rule: on low-core / low-memory / no-WebGPU devices, default to Web Speech API (processLocally) + system TTS and disable WASM model options. On the Framework Desktop (or high-resource clients), offer the heavier local models.
- Always allow the user to override. Never silently load a 500 MB model on a phone.

## Non-goals for the first implementation

- Multi-speaker diarization.
- Always-on wake word (push-to-talk or explicit voice mode is enough).
- Cloud fallback.
- Computer-use or screen sharing during voice.

## Acceptance for the design

- A user on Chrome with a language pack can press the mic, see words appear live, and have the final transcript submitted as a normal message.
- Bot replies are spoken when they finish.
- A voice-mode session can be ended; its turns remain in the thread as normal messages.
- No audio leaves the browser or the Framework Desktop.
- On a lightweight device the defaults stay light; the user can still force heavier models if they want.

See also: `docs/PRD.md` (interface and later), `docs/specs.md` (API contracts, which stay unchanged for the pure-browser path).

## Implementation status (branch `voice/local-browser`)

Implemented (pure browser path, no new API endpoints):
- Composer: 🎤 dictation, **Voice** mode toggle, ⚙ voice settings (stored in `localStorage` key `lgb.voice`).
- STT: Web Speech API with `processLocally = true` only. Fail closed: if the browser has no on-device mode (`SpeechRecognition.available`), the mic refuses rather than falling back to cloud recognition. Language pack is installed on first use via `SpeechRecognition.install()`. Interim words show in a preview strip above the composer (finals solid, interim italic); on stop, finals are appended to the textarea, or sent if "send automatically" is on.
- TTS: `speechSynthesis` with `localService === true` voices only; if none exist, nothing is spoken (message shown). Markdown and code blocks are stripped before speaking. Any send cancels speech.
- Voice mode: listen → ~0.9 s silence after a final result ends the utterance → `send()` → follow stream → speak reply → listen again. Barge-in is a setting (default off, because without headphones the mic hears the TTS). "End voice" stops; turns remain in the thread as normal messages (no summary, see Phase 2).
- Device detection: cores / deviceMemory / WebGPU shown in settings; no heavy models are loaded anywhere.

Secure context: the daemon can now serve HTTPS itself. `TLS_CERT` + `TLS_KEY` use an existing pair; `TLS_SELF_SIGNED=1` generates (once) an ECDSA cert under `DATA_DIR/tls/` for localhost, the host name, and all interface IPs. Setting only one of `TLS_CERT`/`TLS_KEY` is a startup error. TLS mode is recorded in the event log (`tls_enabled`). Accept the browser's certificate warning once per device, or import `DATA_DIR/tls/cert.pem` as trusted.

Not yet: WASM Moonshine/Whisper fallback, true streaming `/api/stt/stream`, Piper/Kokoro, streaming LLM tokens into TTS (Phase 2 latency work).

### Daemon speech recognition (fallback for Android Chrome and other browsers without on-device Web Speech)

- `GET /api/stt/status` → `{"available", "engine"}`. `POST /api/stt` with a raw body of 16 kHz mono s16le PCM → `{"text", "took_ms"}`. Same bearer auth as the rest of the API.
- Configure with `WHISPER_BIN` (whisper.cpp `whisper-cli`) and `WHISPER_MODEL` (ggml model). Neither set: endpoint returns 503 "not available" and the UI says so. Only one set: daemon refuses to start.
- Caps: 8 MB body (about 4 min), 60 s transcription timeout, one transcription at a time. Requests with `X-STT-Partial: 1` (live preview) get 429 instead of queueing.
- Audio is written to a temp dir only for whisper-cli and deleted right after; nothing is kept. Each request is audited as event kind `stt` with byte count, duration, latency, character count and outcome, never the audio or text.
- Language is fixed to English (`-l en`) for now.
- Browser side: if `SpeechRecognition` is missing or on-device mode is unavailable, the mic and voice mode capture audio with `getUserMedia` (echo cancellation and noise suppression on), downsample to 16 kHz, and send it to the daemon. While you talk, the whole buffer so far is re-sent every 1.5 s as a partial for a live preview; on stop the final pass fills the composer. Voice mode ends an utterance after 1 s below an adaptive energy threshold. ⚙ shows the active engine.
- Setup on the Framework (user space, Vulkan GPU): clone `ggml-org/whisper.cpp`, `cmake -B build -DGGML_VULKAN=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build -j --target whisper-cli`, download `ggml-large-v3-turbo-q5_0.bin` from `huggingface.co/ggerganov/whisper.cpp`.

Composer: a single pill. Empty: ⚙, 🎤 (dictation) and a round waveform button (voice mode). With text: only a round send arrow. Placeholder is "Message <bot name>".

TLS and CLI backends: the Claude CLI's MCP permission callback is plain HTTP to the daemon, so when TLS is enabled the daemon gives it no callback base. CLI runs then use `--permission-prompts none` (or stream_control when the policy selects it) and the broker denies anything that would have needed a UI prompt. `/api/stt` and `/api/stt/status` sit behind the same admin-token gate as every other API route (Bearer or the `/login` cookie); STT events also go to the policy audit sink (`event: "stt"`) when one is configured.
