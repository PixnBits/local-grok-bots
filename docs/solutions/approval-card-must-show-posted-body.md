# Approval cards must show the body that will be posted

`audit.RedactValue` clips strings at 500 bytes. The permission broker used that value as the card arguments, and the issue and comment tools also clipped the body before asking. An approver could allow a tail the card never showed.

`create_issue`, `create_comment`, and `create_pr` put a JSON clone of the raw arguments on the card. The audit log still uses `RedactValue`. A body longer than `ValidPullBody` (65536 bytes) or longer than 400 lines is refused before the card, so the approved text and the posted text are the same. A cut that remains, such as a long target title, stops on a UTF-8 boundary and is marked as clipped. Do not raise the audit clip to make the card honest.

Do not put format, tag, default-ignorable, or private-use characters on a card as themselves. Refuse them in bot-supplied title and body text. Escape them in a fetched title. A tall body shows its line count and a cue outside the scrolling box. The cue is named on the card payload so it does not depend on measuring a visible card.
