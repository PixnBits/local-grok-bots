package github

// Emoji allowances are contextual. The tables are closed ranges from Unicode
// 15.0, the edition Go's unicode tables use. There is no external data file.
//
// emojiPictographic is Extended_Pictographic plus the regional indicators
// U+1F1E6..U+1F1FF. Those indicators are Emoji_Presentation and are not in
// Extended_Pictographic. Skin tones are Emoji_Presentation too; they are
// modifiers, not bases, and they are absent from this table.
//
// emojiModifierBase is Emoji_Modifier_Base. A skin tone is U+1F3FB..U+1F3FF
// and is allowed only immediately after one of these.
//
// A tag sequence is allowed only as a short subdivision-flag shape: U+1F3F4,
// then 2..7 tag characters U+E0020..U+E007E, then U+E007F. The tags are not
// checked against a subdivision registry. Any other tag, ZWJ, variation
// selector, or skin tone stays refused.

const (
	blackFlag   = 0x1F3F4
	vs16        = 0xFE0F
	vs15        = 0xFE0E
	zwj         = 0x200D
	keycap      = 0x20E3
	minFlagTags = 2
	maxFlagTags = 7
)

var emojiPictographic = [][2]rune{
	{0xA9, 0xA9},
	{0xAE, 0xAE},
	{0x203C, 0x203C},
	{0x2049, 0x2049},
	{0x2122, 0x2122},
	{0x2139, 0x2139},
	{0x2194, 0x2199},
	{0x21A9, 0x21AA},
	{0x231A, 0x231B},
	{0x2328, 0x2328},
	{0x2388, 0x2388},
	{0x23CF, 0x23CF},
	{0x23E9, 0x23F3},
	{0x23F8, 0x23FA},
	{0x24C2, 0x24C2},
	{0x25AA, 0x25AB},
	{0x25B6, 0x25B6},
	{0x25C0, 0x25C0},
	{0x25FB, 0x25FE},
	{0x2600, 0x2605},
	{0x2607, 0x2612},
	{0x2614, 0x2685},
	{0x2690, 0x2705},
	{0x2708, 0x2712},
	{0x2714, 0x2714},
	{0x2716, 0x2716},
	{0x271D, 0x271D},
	{0x2721, 0x2721},
	{0x2728, 0x2728},
	{0x2733, 0x2734},
	{0x2744, 0x2744},
	{0x2747, 0x2747},
	{0x274C, 0x274C},
	{0x274E, 0x274E},
	{0x2753, 0x2755},
	{0x2757, 0x2757},
	{0x2763, 0x2767},
	{0x2795, 0x2797},
	{0x27A1, 0x27A1},
	{0x27B0, 0x27B0},
	{0x27BF, 0x27BF},
	{0x2934, 0x2935},
	{0x2B05, 0x2B07},
	{0x2B1B, 0x2B1C},
	{0x2B50, 0x2B50},
	{0x2B55, 0x2B55},
	{0x3030, 0x3030},
	{0x303D, 0x303D},
	{0x3297, 0x3297},
	{0x3299, 0x3299},
	{0x1F000, 0x1F0FF},
	{0x1F10D, 0x1F10F},
	{0x1F12F, 0x1F12F},
	{0x1F16C, 0x1F171},
	{0x1F17E, 0x1F17F},
	{0x1F18E, 0x1F18E},
	{0x1F191, 0x1F19A},
	{0x1F1AD, 0x1F1FF},
	{0x1F201, 0x1F20F},
	{0x1F21A, 0x1F21A},
	{0x1F22F, 0x1F22F},
	{0x1F232, 0x1F23A},
	{0x1F23C, 0x1F23F},
	{0x1F249, 0x1F3FA},
	{0x1F400, 0x1F53D},
	{0x1F546, 0x1F64F},
	{0x1F680, 0x1F6FF},
	{0x1F774, 0x1F77F},
	{0x1F7D5, 0x1F7FF},
	{0x1F80C, 0x1F80F},
	{0x1F848, 0x1F84F},
	{0x1F85A, 0x1F85F},
	{0x1F888, 0x1F88F},
	{0x1F8AE, 0x1F8FF},
	{0x1F90C, 0x1F93A},
	{0x1F93C, 0x1F945},
	{0x1F947, 0x1FAFF},
	{0x1FC00, 0x1FFFD},
}

var emojiModifierBase = [][2]rune{
	{0x261D, 0x261D},
	{0x26F9, 0x26F9},
	{0x270A, 0x270D},
	{0x1F385, 0x1F385},
	{0x1F3C2, 0x1F3C4},
	{0x1F3C7, 0x1F3C7},
	{0x1F3CA, 0x1F3CC},
	{0x1F442, 0x1F443},
	{0x1F446, 0x1F450},
	{0x1F466, 0x1F478},
	{0x1F47C, 0x1F47C},
	{0x1F481, 0x1F483},
	{0x1F485, 0x1F487},
	{0x1F48F, 0x1F48F},
	{0x1F491, 0x1F491},
	{0x1F4AA, 0x1F4AA},
	{0x1F574, 0x1F575},
	{0x1F57A, 0x1F57A},
	{0x1F590, 0x1F590},
	{0x1F595, 0x1F596},
	{0x1F645, 0x1F647},
	{0x1F64B, 0x1F64F},
	{0x1F6A3, 0x1F6A3},
	{0x1F6B4, 0x1F6B6},
	{0x1F6C0, 0x1F6C0},
	{0x1F6CC, 0x1F6CC},
	{0x1F90C, 0x1F90C},
	{0x1F90F, 0x1F90F},
	{0x1F918, 0x1F91F},
	{0x1F926, 0x1F926},
	{0x1F930, 0x1F939},
	{0x1F93C, 0x1F93E},
	{0x1F977, 0x1F977},
	{0x1F9B5, 0x1F9B6},
	{0x1F9B8, 0x1F9B9},
	{0x1F9BB, 0x1F9BB},
	{0x1F9CD, 0x1F9CF},
	{0x1F9D1, 0x1F9DD},
	{0x1FAC3, 0x1FAC5},
	{0x1FAF0, 0x1FAF8},
}

func inRuneRanges(r rune, tab [][2]rune) bool {
	for _, span := range tab {
		if r < span[0] {
			return false
		}
		if r <= span[1] {
			return true
		}
	}
	return false
}

func emojiBase(r rune) bool {
	return inRuneRanges(r, emojiPictographic)
}

func emojiModBase(r rune) bool {
	return inRuneRanges(r, emojiModifierBase)
}

func isSkinTone(r rune) bool {
	return r >= 0x1F3FB && r <= 0x1F3FF
}

func isKeycapBase(r rune) bool {
	return (r >= '0' && r <= '9') || r == '#' || r == '*'
}

func isTagSpec(r rune) bool {
	return r >= 0xE0020 && r <= 0xE007E
}

// emojiExempt reports which runes are an allowed ZWJ, variation selector,
// skin tone, or subdivision-flag tag. Every other such rune stays refused.
func emojiExempt(rs []rune) []bool {
	ex := make([]bool, len(rs))
	for i, r := range rs {
		switch r {
		case vs16, vs15:
			if i > 0 && emojiBase(rs[i-1]) {
				ex[i] = true
			} else if r == vs16 && i > 0 && i+1 < len(rs) && isKeycapBase(rs[i-1]) && rs[i+1] == keycap {
				ex[i] = true
			}
		case zwj:
			ex[i] = zwjBetweenEmoji(rs, i)
		default:
			if isSkinTone(r) && i > 0 && emojiModBase(rs[i-1]) {
				ex[i] = true
			} else if isTagSpec(r) || r == 0xE007F {
				ex[i] = tagFlagExempt(rs, i)
			}
		}
	}
	return ex
}

func zwjBetweenEmoji(rs []rune, i int) bool {
	if i+1 >= len(rs) || !emojiBase(rs[i+1]) || i == 0 {
		return false
	}
	prev := rs[i-1]
	if emojiBase(prev) {
		return true
	}
	if isSkinTone(prev) {
		return i >= 2 && emojiModBase(rs[i-2])
	}
	if prev == vs16 || prev == vs15 {
		return i >= 2 && emojiBase(rs[i-2])
	}
	return false
}

func tagFlagExempt(rs []rune, i int) bool {
	if i >= len(rs) || (!isTagSpec(rs[i]) && rs[i] != 0xE007F) {
		return false
	}
	start := i
	for start > 0 && (isTagSpec(rs[start-1]) || rs[start-1] == 0xE007F) {
		start--
	}
	if start == 0 || rs[start-1] != blackFlag {
		return false
	}
	n := 0
	k := start
	for k < len(rs) && isTagSpec(rs[k]) {
		n++
		k++
	}
	if n < minFlagTags || n > maxFlagTags || k >= len(rs) || rs[k] != 0xE007F {
		return false
	}
	// Only the recommended subdivision flags; any other tag text stays refused.
	tag := make([]byte, 0, n)
	for _, t := range rs[start:k] {
		tag = append(tag, byte(t-0xE0000))
	}
	if s := string(tag); s != "gbeng" && s != "gbsct" && s != "gbwls" {
		return false
	}
	return i <= k
}
