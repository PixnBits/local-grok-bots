# GitHub card text checks

Wrong if a write card can hide or reorder text, if line breaks the browser shows are ignored by the cap, or if the scroll cue appears only after measuring a visible card.

## Decisions

- One predicate in `internal/github/text.go` refuses hidden or private-use characters in every title and body before any card or write. A fetched target title shows the same set as `⟦U+XXXX⟧`.
- Line and paragraph separators count as line breaks for the 400-line cap and the card line count.
- The card payload names the line count and whether a scroll cue is needed (line count or length). The UI uses that field so a hidden or narrow view still shows the cue.
- A read page with long file names or paths windows those strings. A summary-only fallback is marked omitted and does not name a continuation that cannot show content.
- The card notes more token-shaped strings and more link shapes. Push commit text on the card is escaped with the same predicate. The pre-card audit row is named proposed.

## Tests

- Table of refused classes, including DEL and title limits.
- Line counting of separators, card `body_lines` / `scroll_cue`, markTallCard overflow, jail re-check while a card is pending, summary-only omitted fallback, windowed file names.

## Left

- Reads still succeed when the audit sink is closed.
- Status rows past 100 stay unreachable.
- A later card does not remember an unverified write.
