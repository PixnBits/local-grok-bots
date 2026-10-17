package sandbox

import (
	"bufio"
	"io"
	"strings"
)

// readConnectSNI reads one TLS record and requires a ClientHello whose SNI
// equals host. A missing name, a different name, or a flight that is not a
// complete ClientHello is denied. The returned bytes are the record, to be
// forwarded only when reason is empty.
func readConnectSNI(r *bufio.Reader, host string) ([]byte, string) {
	rec, err := readTLSRecord(r)
	if err != nil {
		return nil, "sni-missing"
	}
	name, clean := clientHelloSNI(rec)
	if !clean || name == "" {
		return nil, "sni-missing"
	}
	if !sniEqual(name, host) {
		return nil, "sni-mismatch"
	}
	return rec, ""
}

func sniEqual(name, host string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	return name != "" && name == host && !strings.ContainsAny(name, " \t/\\%")
}

func readTLSRecord(r *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 22 || hdr[1] != 3 || hdr[2] > 4 {
		return nil, io.ErrUnexpectedEOF
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n < 4 || n > 16384 {
		return nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// clientHelloSNI parses one handshake record. clean is false when the bytes
// are not a single well-formed ClientHello. A clean hello with no host name
// returns an empty name.
func clientHelloSNI(rec []byte) (string, bool) {
	if len(rec) < 5 || rec[0] != 22 {
		return "", false
	}
	n := int(rec[3])<<8 | int(rec[4])
	if n < 4 || len(rec) != 5+n {
		return "", false
	}
	hs := rec[5:]
	if hs[0] != 1 {
		return "", false
	}
	hl := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if hl < 34 || 4+hl > len(hs) {
		return "", false
	}
	body := hs[4 : 4+hl]
	// version (2) + random (32)
	i := 34
	if i >= len(body) {
		return "", false
	}
	sidLen := int(body[i])
	i++
	if sidLen > 32 || i+sidLen > len(body) {
		return "", false
	}
	i += sidLen
	if i+2 > len(body) {
		return "", false
	}
	csLen := int(body[i])<<8 | int(body[i+1])
	i += 2
	if csLen < 2 || csLen%2 != 0 || i+csLen > len(body) {
		return "", false
	}
	i += csLen
	if i >= len(body) {
		return "", false
	}
	compLen := int(body[i])
	i++
	if compLen < 1 || i+compLen > len(body) {
		return "", false
	}
	i += compLen
	if i == len(body) {
		return "", true
	}
	if i+2 > len(body) {
		return "", false
	}
	extLen := int(body[i])<<8 | int(body[i+1])
	i += 2
	if extLen != len(body)-i {
		return "", false
	}
	end := i + extLen
	var name string
	var saw bool
	for i < end {
		if i+4 > end {
			return "", false
		}
		typ := int(body[i])<<8 | int(body[i+1])
		elen := int(body[i+2])<<8 | int(body[i+3])
		i += 4
		if elen < 0 || i+elen > end {
			return "", false
		}
		data := body[i : i+elen]
		i += elen
		if typ != 0 {
			continue
		}
		host, ok := serverName(data)
		if !ok {
			return "", false
		}
		if saw {
			return "", false
		}
		saw = true
		name = host
	}
	if i != end {
		return "", false
	}
	return name, true
}

func serverName(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	listLen := int(data[0])<<8 | int(data[1])
	if listLen != len(data)-2 {
		return "", false
	}
	i := 2
	var host string
	var saw bool
	for i < len(data) {
		if i+3 > len(data) {
			return "", false
		}
		typ := data[i]
		nlen := int(data[i+1])<<8 | int(data[i+2])
		i += 3
		if nlen < 1 || i+nlen > len(data) {
			return "", false
		}
		raw := data[i : i+nlen]
		i += nlen
		if typ != 0 {
			continue
		}
		if saw || strings.ContainsRune(string(raw), 0) {
			return "", false
		}
		saw = true
		host = string(raw)
	}
	if i != len(data) || !saw {
		return "", false
	}
	return host, true
}
