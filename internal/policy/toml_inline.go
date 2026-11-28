package policy

import "fmt"

// rejectTOML11Inline rejects inline-table syntax that TOML 1.0 does not allow.
// A trailing comma, a newline, or a comment is an error unless it sits inside
// a string or an array value. Array trailing commas are allowed.
func rejectTOML11Inline(body []byte) error {
	i := 0
	for i < len(body) {
		next := skipSpaceNL(body, i)
		if next >= len(body) {
			return nil
		}
		var err error
		switch body[next] {
		case '#':
			i = skipComment(body, next)
		case '[':
			i, err = skipTableHeader(body, next)
		default:
			i, err = skipKeyVal(body, next)
		}
		if err != nil {
			return err
		}
		if i <= next {
			i = next + 1
		}
	}
	return nil
}

func skipSpace(body []byte, i int) int {
	for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
		i++
	}
	return i
}

func skipSpaceNL(body []byte, i int) int {
	for i < len(body) {
		switch body[i] {
		case ' ', '\t', '\n':
			i++
		case '\r':
			i++
			if i < len(body) && body[i] == '\n' {
				i++
			}
		default:
			return i
		}
	}
	return i
}

func skipComment(body []byte, i int) int {
	i++
	for i < len(body) && body[i] != '\n' && body[i] != '\r' {
		i++
	}
	return i
}

func isBareKey(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
}

func skipKeyVal(body []byte, i int) (int, error) {
	j, err := skipKey(body, i)
	if err != nil {
		return 0, err
	}
	j = skipSpace(body, j)
	if j >= len(body) || body[j] != '=' {
		if j == i && j < len(body) {
			return i + 1, nil
		}
		return j, nil
	}
	return skipValue(body, j+1)
}

func skipKey(body []byte, i int) (int, error) {
	for {
		i = skipSpace(body, i)
		if i >= len(body) {
			return i, nil
		}
		switch body[i] {
		case '"', '\'':
			var err error
			i, err = skipString(body, i)
			if err != nil {
				return 0, err
			}
		default:
			if !isBareKey(body[i]) {
				return i, nil
			}
			for i < len(body) && isBareKey(body[i]) {
				i++
			}
		}
		j := skipSpace(body, i)
		if j < len(body) && body[j] == '.' {
			i = j + 1
			continue
		}
		return i, nil
	}
}

func skipValue(body []byte, i int) (int, error) {
	i = skipSpace(body, i)
	if i >= len(body) {
		return i, nil
	}
	switch body[i] {
	case '"', '\'':
		return skipString(body, i)
	case '{':
		return skipInline(body, i+1)
	case '[':
		return skipArray(body, i+1)
	default:
		return skipScalar(body, i), nil
	}
}

func skipScalar(body []byte, i int) int {
	for i < len(body) {
		switch body[i] {
		case ' ', '\t', '\n', '\r', '#', ',', '[', ']', '{', '}', '"', '\'':
			return i
		default:
			i++
		}
	}
	return i
}

func skipInline(body []byte, i int) (int, error) {
	pendingComma := false
	for i < len(body) {
		i = skipSpace(body, i)
		if i >= len(body) {
			return i, fmt.Errorf("toml: inline table: unclosed")
		}
		switch body[i] {
		case '\n', '\r':
			return 0, fmt.Errorf("toml: inline table: newline")
		case '#':
			return 0, fmt.Errorf("toml: inline table: comment")
		case '}':
			if pendingComma {
				return 0, fmt.Errorf("toml: inline table: trailing comma")
			}
			return i + 1, nil
		case ',':
			pendingComma = true
			i++
		case '"', '\'':
			var err error
			i, err = skipString(body, i)
			if err != nil {
				return 0, err
			}
			pendingComma = false
		case '{':
			var err error
			i, err = skipInline(body, i+1)
			if err != nil {
				return 0, err
			}
			pendingComma = false
		case '[':
			var err error
			i, err = skipArray(body, i+1)
			if err != nil {
				return 0, err
			}
			pendingComma = false
		default:
			j := skipScalar(body, i)
			if j == i {
				j++
			}
			i = j
			pendingComma = false
		}
	}
	return i, fmt.Errorf("toml: inline table: unclosed")
}

func skipArray(body []byte, i int) (int, error) {
	for i < len(body) {
		i = skipSpace(body, i)
		if i >= len(body) {
			return i, fmt.Errorf("toml: array: unclosed")
		}
		switch body[i] {
		case '\n':
			i++
		case '\r':
			i++
			if i < len(body) && body[i] == '\n' {
				i++
			}
		case '#':
			i = skipComment(body, i)
		case ']':
			return i + 1, nil
		case ',':
			i++
		case '"', '\'':
			var err error
			i, err = skipString(body, i)
			if err != nil {
				return 0, err
			}
		case '{':
			var err error
			i, err = skipInline(body, i+1)
			if err != nil {
				return 0, err
			}
		case '[':
			var err error
			i, err = skipArray(body, i+1)
			if err != nil {
				return 0, err
			}
		default:
			j := skipScalar(body, i)
			if j == i {
				j++
			}
			i = j
		}
	}
	return i, fmt.Errorf("toml: array: unclosed")
}

func skipTableHeader(body []byte, i int) (int, error) {
	if i >= len(body) || body[i] != '[' {
		return i, nil
	}
	double := i+1 < len(body) && body[i+1] == '['
	i++
	if double {
		i++
	}
	for i < len(body) {
		switch body[i] {
		case '"', '\'':
			var err error
			i, err = skipString(body, i)
			if err != nil {
				return 0, err
			}
		case '\n', '\r':
			return i, nil
		case ']':
			if double {
				if i+1 < len(body) && body[i+1] == ']' {
					return i + 2, nil
				}
				i++
				continue
			}
			return i + 1, nil
		default:
			i++
		}
	}
	return i, nil
}

func skipString(body []byte, i int) (int, error) {
	if i >= len(body) {
		return i, nil
	}
	q := body[i]
	if q != '"' && q != '\'' {
		return i, nil
	}
	if i+2 < len(body) && body[i+1] == q && body[i+2] == q {
		return skipMultiline(body, i+3, q)
	}
	return skipSimple(body, i+1, q), nil
}

func skipSimple(body []byte, i int, q byte) int {
	for i < len(body) {
		if q == '"' && body[i] == '\\' {
			if i+1 >= len(body) {
				return len(body)
			}
			i += 2
			continue
		}
		if body[i] == q {
			return i + 1
		}
		if body[i] == '\n' || body[i] == '\r' {
			return i
		}
		i++
	}
	return i
}

func skipMultiline(body []byte, i int, q byte) (int, error) {
	for i < len(body) {
		if q == '"' && body[i] == '\\' {
			if i+1 >= len(body) {
				return len(body), nil
			}
			i += 2
			continue
		}
		if body[i] != q {
			i++
			continue
		}
		n := 0
		for i+n < len(body) && body[i+n] == q {
			n++
		}
		if n < 3 {
			i += n
			continue
		}
		if n > 5 {
			return 0, fmt.Errorf("toml: invalid multiline string")
		}
		return i + n, nil
	}
	return i, nil
}
