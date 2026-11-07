# GitHub card and read budget

Wrong if a write card can show different text from the bytes that would be posted, or if a long read page drops check state and names no continuation.

## Decisions

- User-supplied issue, comment, and pull-request title and body are refused before any card or write when they contain format characters, tag characters, C1 controls, or variation selectors. The tool error is `text is not allowed`. C0 controls other than newline and tab stay `invalid arguments`.
- A body over 400 lines is refused with `too many lines`. The 65536-byte cap stays. The card shows the line count and, above eight lines, a scroll cue outside the scrolling box.
- A fetched comment target title is not refused. Those same characters are shown as `⟦U+XXXX⟧`. A title over 2000 bytes stays clipped and marked.
- `\r\n` is stored as `\n`. A bare CR is still refused.
- A read page that does not fit in 256 KiB shortens text windows until it fits. `checks`, `statuses`, `combined_state`, and `count` stay. A shortened field sets `next_offset`. The page is not replaced by an omitted object.
- API writes require an audit log. A disabled log, or a log that cannot take the intent row, refuses the write before the card. The intent row is written again after allow.
- A comment target URL number must match the requested number. `read_issue` on a pull request tells the caller to use `read_pr`.
- The card warns on secret-looking strings and lists http(s) links whose host is not github.com. The body text stays on the card.
- The nil check in the proxy opener stays before the policy read.

## Left

- Reads still succeed when the audit sink is closed.
- Status rows past 100 stay unreachable. The result is marked truncated.
- A later card does not remember an unverified write.
- The jail socket path length is unchanged.
- One read result stays capped at 256 KiB. A failed conversation request still fails the pull read.
- `git push` keeps its existing audit path.

## Tests

- Each refused class in a title and a body, the line cap, and the visible title escape.
- Card DOM: line count, scroll cue, and the comment number row.
- Escape-heavy read keeps checks and `combined_state` and sets `next_offset`.
- Check-run, status, and conversation truncation flags; shortest field offset; clipped target title.
