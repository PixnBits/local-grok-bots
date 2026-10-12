# Local Grok Bot bootstrap — personal PRD

**Target:** one always-on Framework Desktop (128 GB RAM), local models, a daemon, and a web interface on the home network.
**Purpose:** bootstrap the same interface and operations as Grok Bot for personal use. Not a product, not multi-tenant, not a general agent framework.
**Out of scope:** desktop computer-use, virtual displays, channels, GUI automation, family/multi-user, enterprise controls.

This document is the target. It describes the system we are building toward, not the state of a given deploy. Implementation notes and what has shipped live in the specs and the README.

The interface target is the Grok Bot client: a roster of named bots, a conversation with one of them, and a profile you open when you want to change what the bot is. Not a dashboard with the definition sitting beside the chat.

## 1. What this is

A daemon on the Framework Desktop that owns the roster of named bots, their memory, their timers, and the log. A web page, reachable on the network, talks to that daemon. You open it, see the bots, talk to one, and watch what it did.

The machine is always intended to be on. If it shuts down, the system pauses. That is expected. On boot the daemon comes back, reloads state, and continues. Missed timers are reported, not silently replayed.

Models run locally (Ollama or equivalent on the same box). No weekly token pool, no vendor computer, no phone app required. The web page is the client.

## 2. What this is not

- Not Hermes, not Claw, not a general coding agent. Those solve different jobs. This is the bot roster, the conversation, and the coordination between bots.
- Not a desktop automation layer. No browser-on-a-virtual-display, no pointer, no teach-by-clicking. Bots act through tools the daemon exposes (files, shell inside a declared workspace, local model calls, messages to other bots). Computer-use can be added later; it is not in this interface.
- Not multi-user. One person. The web page defaults to loopback. It can sit on the LAN only with `AUTH_TOKEN`. It does not need accounts, teams, or SCIM.
- Not a workflow builder. You name a bot, write its description, and talk to it.

## 3. System shape

```
Framework Desktop (always-on, 128 GB)
  daemon
    roster of bots (name, label, description, mark, memory)
    timer / routine scheduler
    message bus (user↔bot, bot↔bot DM)
    action and event log
    local model client (Ollama)
  web UI  ←→  daemon API (on the network)
    roster
    conversation
    profile (opened from the bot menu)
    log
```

The daemon is the source of truth. The web page is a client. Closing the browser does not stop a turn. Shutting the machine does; the daemon resumes from persisted state on the next boot.

## 4. Core objects

### Bot
- Name
- Label — a short role line, shown under the name (“what this bot is”)
- Description — the standing prompt: role, boundaries, durable rules. Distinct from a message. A message is a task; the description is what stays true.
- Mark — a colour and a shape, so the roster is scannable
- Memory — durable notes the bot keeps; not a substitute for the log
- Status — idle, running, paused
- Optional model override (default is the local one)

A bot can be created and edited from the profile. A bot can also create or update other bots if it is granted that tool. That meta-bot is how the roster stays manageable without you being the only editor.

### Conversation
- One primary thread per bot with the user.
- Messages are ordered, timestamped, and attributed (user or bot).
- The thread is persistent. It survives daemon restart.
- Inbound messages from other bots appear in this thread as a line (“Message from {name}”), not only in a side list.

### Direct message (bot ↔ bot)
- A bot can send a message to another named bot.
- The receiving bot sees it as an inbound message and can reply.
- DMs are stored, visible in the log, and surfaced in the receiving thread.
- Channels (group rooms) are not in scope.

### Action
- Anything a bot does besides emitting a chat message: tool call, file write, shell, model call, DM sent, bot created, timer set.
- Writing them to the log is required. The conversation stays readable.

### Timer / routine
- A bot can have scheduled work (the daemon owns the clock).
- On fire, the daemon starts a turn for that bot with the routine prompt.
- If the machine was off, the timer is missed and logged. No automatic replay.
- Routines are reviewed on the profile: name, schedule, next run, instruction, and whether it is active. Add, pause, and delete live there.

### Log
- Append-only record of messages, DMs, actions, timer fires, errors, and bot create/update.
- Queryable enough to answer “what did this bot do overnight?”
- This is the verification surface. Behavior you cannot see in the log did not happen.
- The log is a view you open. It is not mixed into the conversation. The official app folds some of this into quiet system lines; we keep the dense log, because that is how you verify what a local bot actually did.

## 5. Interface

The page is a messenger, not a form. The conversation is the main surface. The bot’s definition is not on that page.

### Roster
A list of bots. Each row shows the mark, the name, the label, and a status. Click to open the conversation. A control to create a bot. Pin and hide are desirable; hide does not pause the bot or its routines.

### Conversation
The thread, and only the thread, plus the composer.

- The composer is never disabled while a run is in progress. A second message before the first reply is normal.
- While the bot is working, a status animation sits at the bottom of the message screen, beside the most recent messages. It is the glanceable “this bot is working” signal. It is not a banner at the top, and it is not only a dot on the roster. When the run ends, the animation goes away and the reply is in the thread.
- Inbound DMs from other bots appear as a line in this thread.
- A failed run may leave a short note; the detail is in the log.

### Bot menu
Opened from the conversation (the overflow on the bot, not a panel beside the messages). It holds:

- View profile
- Pin / hide
- Duplicate
- Delete

Share as template is later.

### Profile
A separate view, opened from the bot menu. This is where the bot is defined.

- Mark (colour and shape)
- Name
- Label
- Description
- Routines: list, schedule, next run, active toggle, add, pause, delete
- Model override

Saving here changes the bot. It does not happen from the conversation page. Putting the description editor on the same page as the thread is a deviation from this target.

### Log
A separate view. Filterable by bot and by kind. This is where you verify actions that did not become a chat message.

## 6. Messaging model

Strict request-response is the wrong shape. You should be able to:

- Send a message.
- Send a follow-up while the bot is still working.
- Have the bot’s eventual reply (and any intermediate notes) land in the same thread, ordered.
- See that it is working, from the animation at the bottom of the thread, without leaving the conversation.

The daemon treats the user’s messages as a queue against that bot. A running turn can see new user messages before it finishes, or the next turn picks them up immediately after. Either is acceptable as long as nothing is dropped and order is preserved.

Bot-to-bot DMs use the same idea: a message arrives, the receiving bot gets a turn, and it can reply later. No requirement that the sender block until the reply.

## 7. Coordination and the workspace

- Every bot can be addressed by name.
- A bot with the right tool can list other bots, read another bot’s description (or a summary), and send it a DM.
- A bot with the meta tool can create a bot or update another bot’s name, label, and description. That change is logged.
- The user can always do the same things from the profile. The meta-bot is a convenience, not a privilege the UI lacks.

No shared cookie jar, no shared desktop session. Coordination is messages plus the workspace directory the daemon gives the tools.

File and shell tools cannot leave the workspace. Shell runs inside a jail rooted on that directory. Anything the bot should read or run has to be present in the workspace; the host filesystem outside it is not visible. Mounting or copying work into the workspace is how a bot gets material. Per-bot file isolation is desirable later; one shared workspace is enough for this target.

The sandbox model — base jail plus named capability grants for network, git, SSH, builds, and later a headless browser — is in `docs/sandbox.md`. The user sets those grants on the profile. Bots cannot grant them. The default remains the locked-down workspace. The browser grant is not built.

## 8. Logging

Every one of these writes a log line:

- User message received
- Bot message emitted
- DM sent and DM received
- Tool / action started and finished (name, target, success or error)
- Bot created, renamed, or description changed (by user or by a bot)
- Timer fired, missed, or skipped
- Model call (which model, success or error; token counts if cheap to capture)
- Daemon start and clean shutdown
- Run finished, including the reason when it is an error

The log is the place you go to verify behavior. The chat transcript stays readable; the log can be denser.

## 9. Lifecycle

- Daemon starts on boot (systemd user or system unit).
- State (bots, threads, DMs, timers, log, memory) is on disk.
- Shutdown or crash: in-flight turn is lost or marked failed. On restart the daemon reloads and accepts new messages. It does not invent a resume of a half-finished model call.
- Local model is the default. If Ollama is down, turns fail with a clear log line; they do not hang forever.
- The web UI binds on loopback by default. A non-loopback address requires `AUTH_TOKEN`. No public exposure required.

## 10. Explicit non-goals

- Computer-use, virtual displays, pointer control, teach-by-demonstration.
- Channels / group rooms.
- Approvals with expiry cards. Log the action. Add an allow/deny gate later if a tool is dangerous.
- Multi-user auth. Optional shared secret or firewall is enough.
- Catch-up of missed timers.
- Per-bot microVMs. A single daemon process (or one process plus tool sandbox) is sufficient.
- Mobile app, voice, X integration, Slack bridges.
- Share as template, a documents tab, a links tab, a notifications toggle.

## 11. Acceptance criteria

1. Daemon is running on the Framework Desktop and survives a reboot by coming back with the same bots and threads.
2. From another machine on the network you can open the web page, see the roster, and send a message.
3. You can send a second message before the first reply arrives, and both appear in order in the thread.
4. While a bot is working, a status animation is visible at the bottom of the message screen, near the latest messages.
5. You can create a bot and set its name, label, and description from the profile, which is a separate view from the conversation.
6. One bot can DM another. The exchange is in the log, and the inbound message appears in the receiving thread. The receiving bot can reply.
7. A bot (or the profile) can create or update another bot, and the change is logged.
8. An action the bot takes appears in the log with enough detail to verify what happened.
9. Routines are listed on the profile and can be added, paused, and deleted there.
10. If the machine is powered off at a scheduled time, the timer is recorded as missed, not replayed on boot.
11. No desktop session or virtual display is required for any of the above.

## 12. Later

- Channels.
- A visible action list inside the chat (the log already has the data).
- Approval gates on specific tools.
- Per-bot file isolation or microVMs.
- Computer-use on a virtual display, opened from the conversation the way the official app opens Agent Computer.
- Share as template.
- A phone-native client. The page should already be usable on a phone.

This is the bootstrap: the daemon, the bot objects, the async conversation, the DMs, the meta-bot, and the log, behind a page whose menu matches the Grok Bot client. The conversation is the surface. The profile is where the bot is defined. Desktop usage waits.
