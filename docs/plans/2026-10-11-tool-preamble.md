# Tool-round narration

A model response that says "Let me check" and also calls a tool is stored as a finished assistant turn. The tool call is not stored. The next turn copies the announcement and stops with no tool call.

## Decisions

- Text that arrives in the same response as a tool call stays on the live token stream and in that run's in-memory transcript, including a continuation. It is not written to the thread.
- A response with no tool call is still the stored reply, including a short real answer.
- The system prompt tells the model to call a tool in the same response, and that an announcement such as "Let me check" is not a reply. Existing threads already contain those announcements.
- Do not turn thinking off, reorder tools, persist tool results, or raise the round cap.

## Tests

- A round that returns "Let me check the roster." plus `list_bots`, then "Ada is the only bot.", stores only the second sentence. The stream still carries the first sentence. The following user turn does not see the first sentence. The in-run follow-up still does.
- The system prompt contains the announcement instruction.

Lesson: ~/.grok/lessons/local-grok-bots/preamble-without-tool.md
