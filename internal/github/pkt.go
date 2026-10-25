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

type refUpdate struct {
	old string
	new string
	ref string
}

// checkReceivePack reads the command section of a receive-pack body, checks
// that it is one non-delete update of refs/heads/<branch>, and returns a
// reader of the original bytes. The pack that follows the flush is not buffered.
func checkReceivePack(r io.Reader, branch, def string) (io.Reader, error) {
	if r == nil || !BranchOK(branch) {
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
	return io.MultiReader(bytes.NewReader(prefix), r), nil
}

// checkPullHead reads a pull-request body up to a fixed limit and requires
// the JSON head to be the approved head. The original bytes are returned.
func checkPullHead(r io.Reader, head string) (io.Reader, error) {
	if r == nil || !PullBranch(head) {
		return nil, errPkt
	}
	buf, err := io.ReadAll(io.LimitReader(r, maxPullBody+1))
	if err != nil || len(buf) == 0 || len(buf) > maxPullBody {
		return nil, errPkt
	}
	var body struct {
		Head string `json:"head"`
	}
	if json.Unmarshal(buf, &body) != nil || body.Head != head {
		return nil, errPkt
	}
	return bytes.NewReader(buf), nil
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
