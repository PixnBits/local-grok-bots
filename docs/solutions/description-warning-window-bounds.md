# Description warning windows stay inside the lowered text

`descriptionWarnings` searches the lowered description, then takes 40 bytes on either side of a tool-like name. `strings.ToLower` can change the UTF-8 length, and a name in the last 40 bytes makes an unclamped end panic. `GET /api/bots` runs this for every bot, so one description fails the list.

Take the end from `idx + len(strings.ToLower(name)) + 40`, clamp it to the lowered string, clamp the start to 0, and skip the name when the start is past the end. Leave the panic to the test. Do not recover in the handler.
