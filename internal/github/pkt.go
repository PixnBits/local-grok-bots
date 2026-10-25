package github

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	maxPushCommand = 64 << 10
	maxPullBody    = 1 << 20
)

var errPkt = errors.New("ref")
var errPullBase = errors.New("base")

type refUpdate struct {
	old string
	new string
	ref string
}

// checkReceivePack reads the command section of a receive-pack body, checks
// that it is one non-delete update of refs/heads/<branch>, and returns a
// reader of the original bytes. The pack that follows the flush is not buffered.
func checkReceivePack(r io.Reader, branch, def, old string) (io.Reader, error) {
	if r == nil || !BranchOK(branch) || !oidOK(old) {
		return nil, errPkt
	}
	prefix, err := readCommandSection(r)
	if err != nil {
		return nil, errPkt
	}
	cmds, err := parseRefUpdates(prefix)
	if err != nil || len(cmds) != 1 {
		return nil, errPkt
	}
	cmd := cmds[0]
	if !oidOK(cmd.old) || !oidOK(cmd.new) || isZeroOID(cmd.new) {
		return nil, errPkt
	}
	if strings.HasPrefix(strings.ToLower(cmd.ref), "refs/tags/") {
		return nil, errPkt
	}
	want := "refs/heads/" + branch
	if cmd.ref != want {
		return nil, errPkt
	}
	if def != "" && strings.EqualFold(cmd.ref, "refs/heads/"+def) {
		return nil, errPkt
	}
	if cmd.old != old {
		return nil, errPkt
	}
	return io.MultiReader(bytes.NewReader(prefix), r), nil
}

// AdvertisedOID reads a smart-HTTP info/refs body and returns the object id
// of ref. A missing ref is the zero id: 40 hex zeros, or 64 when the
// advertisement is sha256. The error is errPkt and contains no body bytes.
func AdvertisedOID(buf []byte, ref string) (string, error) {
	if ref == "" || strings.ContainsAny(ref, " \t\r\n\x00") || len(buf) == 0 || len(buf) > 1<<20 {
		return "", errPkt
	}
	payloads, err := pktPayloads(buf)
	if err != nil {
		return "", errPkt
	}
	sha256 := false
	sawFlush := false
	found := ""
	saw := false
	for _, data := range payloads {
		if data == nil {
			sawFlush = true
			continue
		}
		if bytes.HasPrefix(data, []byte("#")) {
			continue
		}
		var caps []byte
		if j := bytes.IndexByte(data, 0); j >= 0 {
			caps = data[j+1:]
			data = data[:j]
		}
		if bytes.Contains(caps, []byte("object-format=sha256")) {
			sha256 = true
		}
		data = bytes.TrimRight(data, "\n")
		parts := bytes.Split(data, []byte{' '})
		if len(parts) != 2 {
			return "", errPkt
		}
		oid := string(parts[0])
		name := string(parts[1])
		if !oidOK(oid) {
			return "", errPkt
		}
		if len(oid) == 64 {
			sha256 = true
		}
		if name == "capabilities^{}" {
			if !isZeroOID(oid) {
				return "", errPkt
			}
			continue
		}
		if strings.ContainsAny(name, "\r\n\x00") || name == "" {
			return "", errPkt
		}
		if name == ref {
			if saw && found != oid {
				return "", errPkt
			}
			found = oid
			saw = true
		}
	}
	if !sawFlush {
		return "", errPkt
	}
	if saw {
		return found, nil
	}
	n := 40
	if sha256 {
		n = 64
	}
	return strings.Repeat("0", n), nil
}

func pktPayloads(buf []byte) ([][]byte, error) {
	var out [][]byte
	i := 0
	for i < len(buf) {
		if len(buf)-i < 4 {
			return nil, errPkt
		}
		n, ok := pktSize(buf[i : i+4])
		if !ok {
			return nil, errPkt
		}
		if n == 0 {
			out = append(out, nil)
			i += 4
			continue
		}
		if n < 4 || i+n > len(buf) {
			return nil, errPkt
		}
		out = append(out, append([]byte(nil), buf[i+4:i+n]...))
		i += n
	}
	return out, nil
}

// checkPullHead reads a pull-request body up to a fixed limit. Keys must be
// the exact lowercase names head, base, title, body, and draft. head and base
// are required. A base that differs from the approved base is errPullBase.
// Any other failure is errPkt. The original bytes are returned.
func checkPullHead(r io.Reader, head, base string) (io.Reader, error) {
	if r == nil || !PullBranch(head) || !PullBranch(base) {
		return nil, errPkt
	}
	buf, err := io.ReadAll(io.LimitReader(r, maxPullBody+1))
	if err != nil || len(buf) == 0 || len(buf) > maxPullBody {
		return nil, errPkt
	}
	gotHead, gotBase, err := pullObject(buf)
	if err != nil {
		return nil, errPkt
	}
	if gotHead != head {
		return nil, errPkt
	}
	if gotBase != base {
		return nil, errPullBase
	}
	return bytes.NewReader(buf), nil
}

func pullObject(buf []byte) (head, base string, err error) {
	dec := json.NewDecoder(bytes.NewReader(buf))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return "", "", errPkt
	}
	seen := map[string]bool{}
	var sawHead, sawBase bool
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", "", errPkt
		}
		key, ok := keyTok.(string)
		if !ok || seen[key] {
			return "", "", errPkt
		}
		seen[key] = true
		switch key {
		case "head", "base", "title", "body":
			val, err := dec.Token()
			if err != nil {
				return "", "", errPkt
			}
			s, ok := val.(string)
			if !ok {
				return "", "", errPkt
			}
			switch key {
			case "head":
				head, sawHead = s, true
			case "base":
				base, sawBase = s, true
			}
		case "draft":
			val, err := dec.Token()
			if err != nil {
				return "", "", errPkt
			}
			if _, ok := val.(bool); !ok {
				return "", "", errPkt
			}
		default:
			return "", "", errPkt
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return "", "", errPkt
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return "", "", errPkt
	}
	if !sawHead || !sawBase {
		return "", "", errPkt
	}
	return head, base, nil
}

func readCommandSection(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	hdr := make([]byte, 4)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return nil, err
		}
		n, ok := pktSize(hdr)
		if !ok {
			return nil, errPkt
		}
		if n == 0 {
			buf.Write(hdr)
			return buf.Bytes(), nil
		}
		if n < 4 || buf.Len()+n > maxPushCommand {
			return nil, errPkt
		}
		buf.Write(hdr)
		if _, err := io.CopyN(&buf, r, int64(n-4)); err != nil {
			return nil, err
		}
	}
}

func pktSize(hdr []byte) (int, bool) {
	if len(hdr) != 4 {
		return 0, false
	}
	n := 0
	for _, c := range hdr {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += int(c - '0')
		case c >= 'a' && c <= 'f':
			n += int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n += int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return n, true
}

func parseRefUpdates(buf []byte) ([]refUpdate, error) {
	var out []refUpdate
	i := 0
	sawFlush := false
	for i < len(buf) {
		if len(buf)-i < 4 {
			return nil, errPkt
		}
		n, ok := pktSize(buf[i : i+4])
		if !ok {
			return nil, errPkt
		}
		if n == 0 {
			if i+4 != len(buf) {
				return nil, errPkt
			}
			sawFlush = true
			break
		}
		if n < 4 || i+n > len(buf) {
			return nil, errPkt
		}
		data := buf[i+4 : i+n]
		i += n
		if j := bytes.IndexByte(data, 0); j >= 0 {
			caps := data[j+1:]
			if n := bytes.IndexByte(caps, '\n'); n >= 0 && n != len(caps)-1 {
				return nil, errPkt
			}
			data = data[:j]
		}
		data = bytes.TrimRight(data, "\n")
		parts := bytes.Split(data, []byte{' '})
		if len(parts) != 3 {
			return nil, errPkt
		}
		cmd := refUpdate{old: string(parts[0]), new: string(parts[1]), ref: string(parts[2])}
		if strings.ContainsAny(cmd.ref, "\r\n\x00") || cmd.ref == "" {
			return nil, errPkt
		}
		out = append(out, cmd)
	}
	if !sawFlush {
		return nil, errPkt
	}
	return out, nil
}

func oidOK(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func isZeroOID(s string) bool {
	if !oidOK(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}
