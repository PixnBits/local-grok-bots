package coi

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// HandleForward runs the hidden in-jail forwarder. It returns true when the
// argument vector is that subcommand. The process then exits.
func HandleForward(args []string) bool {
	if len(args) == 0 || args[0] != "--coi-forward" {
		return false
	}
	os.Exit(RunForward(args[1:]))
	return true
}

// RunForward listens on 127.0.0.1:0, bridges accepted TCP to the unix socket,
// sets base-URL environment variables, and runs the CLI.
func RunForward(args []string) int {
	sock := ""
	var envs []string
	prefix := ""
	cli := []string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			cli = args[i+1:]
			i = len(args)
		case a == "--sock" && i+1 < len(args):
			i++
			sock = args[i]
		case a == "--env" && i+1 < len(args):
			i++
			envs = append(envs, args[i])
		case a == "--prefix" && i+1 < len(args):
			i++
			prefix = args[i]
		default:
			return 2
		}
	}
	if sock == "" || len(cli) == 0 || cli[0] == "" {
		return 2
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 1
	}
	defer ln.Close()
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return 1
	}
	go serveBridge(ln, sock)
	env := os.Environ()
	base := "http://127.0.0.1:" + itoa(tcp.Port) + prefix
	for _, name := range envs {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		env = append(env, name+"="+base)
	}
	cmd := exec.Command(cli[0], cli[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code := exit.ExitCode()
			if code < 0 {
				return 1
			}
			return code
		}
		return 1
	}
	return 0
}

func serveBridge(ln net.Listener, sock string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			right, err := net.Dial("unix", sock)
			if err != nil {
				_ = conn.Close()
				return
			}
			bridge(conn, right)
		}(c)
	}
}

func bridge(left, right net.Conn) {
	defer left.Close()
	defer right.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		_, _ = io.Copy(right, left)
		wg.Done()
	}()
	go func() {
		_, _ = io.Copy(left, right)
		wg.Done()
	}()
	wg.Wait()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
