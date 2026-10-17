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

// RunForward listens on 127.0.0.1 inside the jail network namespace, bridges
// accepted TCP to host unix sockets, sets the CLI environment, and runs the CLI.
// --sock is the credential proxy. --http-sock is an HTTP proxy. At least one
// is required. --keep-key leaves XAI_API_KEY alone so a per-run gate token is
// not replaced by the shared placeholder.
func RunForward(args []string) int {
	sock := ""
	httpSock := ""
	keepKey := false
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
		case a == "--http-sock" && i+1 < len(args):
			i++
			httpSock = args[i]
		case a == "--keep-key":
			keepKey = true
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
	if (sock == "" && httpSock == "") || len(cli) == 0 || cli[0] == "" {
		return 2
	}
	env := os.Environ()
	if sock != "" {
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
		base := "http://127.0.0.1:" + itoa(tcp.Port) + prefix
		grok := false
		for _, name := range envs {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if name == "GROK_CLI_CHAT_PROXY_BASE_URL" || name == "XAI_API_BASE_URL" || name == "GROK_XAI_API_BASE_URL" {
				grok = true
			}
			env = setEnv(env, name, base)
		}
		// Grok 1.0.52 does not treat a synthetic auth.json as a session. It does
		// send Authorization: Bearer from XAI_API_KEY. The host proxy replaces that.
		// --keep-key preserves a per-run gate token the loopback proxy admitted.
		if grok && !keepKey {
			env = setEnv(env, "XAI_API_KEY", PlaceholderToken)
		}
	}
	if httpSock != "" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 1
		}
		defer ln.Close()
		tcp, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			return 1
		}
		go serveBridge(ln, httpSock)
		proxyURL := "http://127.0.0.1:" + itoa(tcp.Port)
		for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			env = setEnv(env, name, proxyURL)
		}
		// The credential origin is loopback in this namespace. It must not be
		// sent through the egress proxy.
		for _, name := range []string{"NO_PROXY", "no_proxy"} {
			env = setEnv(env, name, "127.0.0.1,localhost,::1")
		}
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

func setEnv(env []string, key, val string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return append(out, prefix+val)
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
