# Local Grok Bot bootstrap — personal PRD

**Target:** one always-on Framework Desktop (128 GB RAM), local models, a daemon, and a web interface on the home network.
**Purpose:** bootstrap the same interface and operations as Grok Bot / Rakazo for personal use. Not a product, not multi-tenant, not a general agent framework.
**Out of this round:** desktop computer-use, virtual displays, channels, GUI automation, family/multi-user, enterprise controls.

“Rockbox” in the request is treated as **Rakazo** — the self-hosted Grok Bot alternative whose web client lists bots and chats with them. The interface target is that shape: a bot list, a conversation with a named bot, and the controls to define it.

## 1. What this is

A daemon on the Framework Desktop that owns the roster of named bots, their memory, their timers, and the log. A web page, reachable on the network, talks to that daemon. You open it, see the bots, talk to one, and watch what it did.

The machine is always intended to be on. If it shuts down, the system pauses. That is expected. On boot the daemon comes back, reloads state, and continues. No catch-up storm is required for MVP; missed timers are reported, not silently replayed.

Models run locally (Ollama or equivalent on the same box). No weekly token pool, no vendor computer, no phone app required. The web page is the client.

## 2. What this is not

- Not Hermes, not Claw, not a general coding agent. Those solve different jobs. This is the bot roster, the conversation, and the coordination between bots.
- Not a desktop automation layer. No browser-on-a-virtual-display, no pointer, no teach-by-clicking. Bots act through tools the daemon exposes (files, shell inside a declared workspace, local model calls, messages to other bots). Computer-use can be added later; it is not in this interface.
- Not multi-user. One person. The web page can sit on the LAN; it does not need accounts, teams, or SCIM.
- Not a workflow builder. You name a bot, write its instructions, and talk to it.

## 3. System shape

```
Framework Desktop (always-on, 128 GB)
  daemon
    roster of bots (name, instructions, memory)
    timer / routine scheduler
    message bus (user↔bot, bot↔bot DM)
    action and event log
    local model client (Ollama)
  web UI  ←→  daemon API (on the network)
    bot list
    conversation view (async, multi-message)
    bot editor (name, instructions)
    log viewer
```

The daemon is the source of truth. The web page is a client. Closing the browser does not stop a turn. Shutting the machine does; the daemon resumes from persisted state on the next boot.

## 4. Core objects (MVP)

### Bot
- Name
- Instructions (the standing prompt / role / boundaries)
- Memory (durable notes the bot keeps; not a substitute for the log)
- Status (idle, running, paused)
- Optional: model override (default is the local one)

A bot can be created and edited from the web UI. A bot can also create or update other bots if it is granted that tool. That meta-bot is how the roster stays manageable without you being the only editor.

### Conversation
- One primary thread per bot with the user.
- Messages are ordered, timestamped, and attributed (user or bot).
- The thread is persistent. It survives daemon restart.

### Direct message (bot ↔ bot)
- A bot can send a message to another named bot.
- The receiving bot sees it as an inbound message and can reply.
- DMs are stored and visible in the log, and ideally in a simple DM view so you can verify what was said.
- This is MVP. Channels (group rooms) are not.

### Action
- Anything a bot does besides emitting a chat message: tool call, file write, shell, model call, DM sent, bot created, timer set.
- Listing them in the UI is nice. Writing them to the log is required.

### Timer / routine
- A bot can have scheduled work (the daemon owns the clock).
- On fire, the daemon starts a turn for that bot with the routine prompt.
- If the machine was off, the timer is missed and logged. No automatic replay for MVP.

### Log
- Append-only record of messages, DMs, actions, timer fires, errors, and bot create/update.
- Queryable enough to answer “what did this bot do overnight?”
- This is the verification surface. Behavior you cannot see in the log did not happen, for the purposes of this bootstrap.

## 5. Interface requirements

The web page, on the network, must let you:

1. See the list of bots (name, short status).
2. Open a bot and read its conversation.
3. Send a message to a bot.
4. Send another message before the first reply has arrived. The daemon queues or interleaves; it does not block the input on “waiting for response.”
5. Edit the bot’s name and instructions.
6. See recent log entries for that bot (or a global log). Actions taken should be visible here even if the chat transcript only shows the final message.
7. See that a DM was sent or received (in the log at minimum; a small DM indicator in the UI is better).

Channels are explicitly deferred. A group room can be added later without changing the DM or user-thread model.

The page does not need to be pretty. It needs to be the same shape as the Rakazo / Grok Bot client: bots on one side, conversation in the middle, the bot’s definition close at hand.

## 6. Messaging model

Strict request-response is the wrong shape. You should be able to:

- Send a message.
- Send a follow-up while the bot is still working.
- Have the bot’s eventual reply (and any intermediate action notes) land in the same thread, ordered.

The daemon treats the user’s messages as a queue against that bot. A running turn can see new user messages before it finishes, or the next turn picks them up immediately after. Either is acceptable for MVP as long as nothing is dropped and order is preserved.

Bot-to-bot DMs use the same idea: a message arrives, the receiving bot gets a turn, and it can reply later. No requirement that the sender block until the reply.

## 7. Coordination

- Every bot can be addressed by name.
- A bot with the right tool can list other bots, read another bot’s instructions (or a summary), and send it a DM.
- A bot with the meta tool can create a bot or update another bot’s name and instructions. That change is logged.
- The user can always do the same things from the web UI. The meta-bot is a convenience, not a privilege the UI lacks.

No shared cookie jar, no shared desktop session. Coordination is messages plus whatever workspace directory the daemon gives the tools. For this round the workspace can be a single directory on the box; per-bot isolation of files is desirable but not required to call the interface done.

## 8. Logging (required)

Every one of these writes a log line:

- User message received
- Bot message emitted
- DM sent and DM received
- Tool / action started and finished (name, target, success or error)
- Bot created, renamed, or instructions changed (by user or by a bot)
- Timer fired, missed, or skipped
- Model call (which model, success or error; token counts if cheap to capture)
- Daemon start and clean shutdown

The log is the place you go to verify behavior. The chat transcript can stay readable; the log can be denser.

## 9. Lifecycle

- Daemon starts on boot (systemd user or system unit).
- State (bots, threads, DMs, timers, log, memory) is on disk.
- Shutdown or crash: in-flight turn is lost or marked failed. On restart the daemon reloads and accepts new messages. It does not invent a resume of a half-finished model call for MVP.
- Local model is the default. If Ollama is down, turns fail with a clear log line; they do not hang forever.
- The web UI binds on the LAN (or localhost plus a reverse proxy you already trust). No public exposure required.

## 10. Explicit non-goals this round

- Computer-use, virtual displays, pointer control, teach-by-demonstration.
- Channels / group rooms.
- Approvals with expiry cards. For personal bootstrap, log the action. Add an allow/deny gate later if a tool is dangerous.
- Multi-user auth. Optional shared secret or firewall is enough.
- Catch-up of missed timers.
- Per-bot microVMs. A single daemon process (or one process plus tool sandbox) is sufficient. Isolation can tighten later; the interface does not depend on it.
- Mobile app, voice, X integration, Slack bridges.

## 11. Acceptance criteria

1. Daemon is running on the Framework Desktop and survives a reboot by coming back with the same bots and threads.
2. From another machine on the network you can open the web page, see the bot list, and send a message.
3. You can send a second message before the first reply arrives, and both appear in order in the thread.
4. You can create a bot, set its name and instructions, and talk to it.
5. One bot can DM another. Both sides are in the log. The receiving bot can reply.
6. A bot (or the UI) can create or update another bot, and the change is logged.
7. An action the bot takes (file write, shell, DM, timer) appears in the log with enough detail to verify what happened.
8. If the machine is powered off at a scheduled time, the timer is recorded as missed, not replayed on boot.
9. No desktop session or virtual display is required for any of the above.

## 12. Later, not now

- Channels.
- A visible action list inside the chat (the log already has the data).
- Approval gates on specific tools.
- Per-bot file isolation or microVMs (AegisClaw can sit underneath later; this PRD does not require it).
- Computer-use on a virtual display.
- A phone-friendly layout of the same web page.

This is the bootstrap: the daemon, the bot objects, the async conversation, the DMs, the meta-bot, and the log, behind a web page that looks like the Rakazo / Grok Bot client. Desktop usage waits.
