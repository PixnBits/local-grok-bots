# Local voice conversations

**Status:** design. Not yet implemented. Target branch: `voice/local-browser`.
**Goal:** Grok-Bots-style voice on the existing web UI, using browser APIs and local processing only. No audio leaves the machine (no Google, no vendor STT).

This document describes the architecture. Implementation notes and current state live in the specs and README. The PRD lists voice as a later feature; this is the design for it.

## Requirements

- Real-time speech-to-text that shows words as they are recognized (interim results), like Grok, not a batch transcription that appears only at the end.
- TTS for finished bot messages.
- Interactive voice conversation mode that can be summarized into a single message in the thread.
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

## Phase 2 — Interactive voice mode + summary

- Voice-mode toggle in the conversation view.
- Loop: listen → end-of-utterance (silence, VAD, or endpoint) → auto-`send()` the final transcript → follow stream → TTS the bot reply → resume listening.
- Keep the full raw transcript of the voice session in client memory.
- On "End voice" / "Summarize" (or mode exit):
  - Inject a short message such as "Summarize the preceding voice conversation into a single concise, self-contained message for the thread" and let the existing bot + Ollama loop produce it, or
  - Client posts one clean summary message (optionally with a collapsed transcript for the log).
- Raw intermediate turns can stay temporary or be posted then archived. The thread ends with one coherent message.
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
- A voice-mode session can be ended and produce a single summarized message in the thread.
- No audio leaves the browser or the Framework Desktop.
- On a lightweight device the defaults stay light; the user can still force heavier models if they want.

See also: `docs/PRD.md` (interface and later), `docs/specs.md` (API contracts, which stay unchanged for the pure-browser path).
