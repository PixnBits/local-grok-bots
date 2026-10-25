package sandbox

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	pushArgMax  = 4096
	pushArgsMax = 32
	pushOutMax  = 1 << 20
)

// PushResult is the daemon's reply to one git push. Code 0 is a real send.
type PushResult struct {
	Code   int
	Stdout string
	Stderr string
	Events []Event
}

// pushSrv accepts push requests while a shell is running.
type pushSrv struct {
	ln    net.Listener
	ctx   context.Context
	fn    func(context.Context, string, []string) PushResult
	start func()
	mu    sync.Mutex
	wg    sync.WaitGroup
	ev    []Event
}

func startPush(ctx context.Context, path string, fn func(context.Context, string, []string) PushResult, start func()) (*pushSrv, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := os.MkdirAll(filepathDir(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o666)
	s := &pushSrv{ln: ln, ctx: ctx, fn: fn, start: start}
	go s.serve()
	return s, nil
}

func (s *pushSrv) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

func (s *pushSrv) close() {
	if s == nil {
		return
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func (s *pushSrv) drain() []Event {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.ev
	s.ev = nil
	return out
}

func (s *pushSrv) add(evs []Event) {
	if len(evs) == 0 {
		return
	}
	s.mu.Lock()
	s.ev = append(s.ev, evs...)
	s.mu.Unlock()
}

func (s *pushSrv) handle(conn net.Conn) {
	defer conn.Close()
	res := PushResult{Code: 1, Stderr: "git push denied: not sent\n"}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	cwd, args, err := readPush(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		s.add([]Event{{Kind: "grant_denied", Grant: "git", Detail: "push not sent"}})
		_ = writePush(conn, res)
		return
	}
	if s.start != nil {
		s.start()
	}
	if s.fn == nil {
		res.Events = []Event{{Kind: "grant_denied", Grant: "git", Detail: "push not sent"}}
	} else {
		res = s.fn(s.ctx, cwd, args)
		if res.Code != 0 && res.Stderr == "" {
			res.Stderr = "git push denied: not sent\n"
		}
	}
	if res.Code < 0 || res.Code > 255 {
		res.Code = 1
	}
	s.add(res.Events)
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = writePush(conn, res)
}

func readPush(conn net.Conn) (string, []string, error) {
	br := bufio.NewReader(conn)
	line, err := readLimitedLine(br, 16)
	if err != nil || line != "PUSH" {
		return "", nil, fmt.Errorf("push request")
	}
	cwd, err := readCounted(br)
	if err != nil {
		return "", nil, err
	}
	argcLine, err := readLimitedLine(br, 8)
	if err != nil {
		return "", nil, err
	}
	argc, err := strconv.Atoi(argcLine)
	if err != nil || argc < 0 || argc > pushArgsMax || fmt.Sprint(argc) != argcLine {
		return "", nil, fmt.Errorf("push argc")
	}
	args := make([]string, argc)
	for i := 0; i < argc; i++ {
		arg, err := readCounted(br)
		if err != nil {
			return "", nil, err
		}
		args[i] = arg
	}
	return cwd, args, nil
}

func readCounted(br *bufio.Reader) (string, error) {
	nLine, err := readLimitedLine(br, 8)
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(nLine)
	if err != nil || n < 0 || n > pushArgMax || fmt.Sprint(n) != nLine {
		return "", fmt.Errorf("push arg")
	}
	if n == 0 {
		return "", nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readLimitedLine(br *bufio.Reader, max int) (string, error) {
	var b []byte
	for len(b) < max {
		c, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return string(b), nil
		}
		if c == '\r' || c == 0 {
			return "", fmt.Errorf("push line")
		}
		b = append(b, c)
	}
	return "", fmt.Errorf("push line")
}

func writePush(conn net.Conn, res PushResult) error {
	stdout := clipPush(res.Stdout)
	stderr := clipPush(res.Stderr)
	if _, err := fmt.Fprintf(conn, "%d\n%d\n", res.Code, len(stdout)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, stdout); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "%d\n", len(stderr)); err != nil {
		return err
	}
	_, err := io.WriteString(conn, stderr)
	return err
}

func clipPush(s string) string {
	if len(s) <= pushOutMax {
		return s
	}
	return s[:pushOutMax]
}
