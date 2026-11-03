package sandbox

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

//go:embed netbridge.c.txt
var netBridgeSrc string

// jailHTTPProxyPort is the HTTP CONNECT listener inside the jail network
// namespace. The namespace has no other listeners, so a fixed port is safe.
const jailHTTPProxyPort = 18080

// ensureNetBridge compiles the in-jail TCP-to-unix splice once and caches it.
// Without gcc the HTTP proxy env is not set. LD_PRELOAD still applies when
// the connect shim compiled.
func ensureNetBridge() (string, error) {
	sum := sha256.Sum256([]byte(netBridgeSrc))
	dest := filepath.Join(os.TempDir(), fmt.Sprintf("lgb-netbridge-%x", sum[:8]))
	if st, err := os.Stat(dest); err == nil && st.Size() > 0 && st.Mode()&0o111 != 0 {
		return dest, nil
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		return "", fmt.Errorf("gcc not available: %w", err)
	}
	dir, err := os.MkdirTemp("", "lgb-cc-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "netbridge.c")
	if err := os.WriteFile(src, []byte(netBridgeSrc), 0o644); err != nil {
		return "", err
	}
	out := filepath.Join(dir, "netbridge")
	cmd := exec.Command("gcc", "-O2", "-o", out, src)
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("net bridge compile: %v %s", err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return "", err
	}
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return dest, nil
}

func shellProxyURL() string {
	return "http://127.0.0.1:" + strconv.Itoa(jailHTTPProxyPort)
}

func shellProxyEnv() []string {
	u := shellProxyURL()
	return []string{
		"HTTPS_PROXY=" + u,
		"HTTP_PROXY=" + u,
		"https_proxy=" + u,
		"http_proxy=" + u,
		"NO_PROXY=localhost,127.0.0.1",
		"no_proxy=localhost,127.0.0.1",
	}
}

// netWrapScript starts the in-jail listener and waits until it accepts,
// then runs the real command. The listener is killed when the script exits.
func netWrapScript() string {
	port := strconv.Itoa(jailHTTPProxyPort)
	return `#!/bin/sh
bridge=/lgb/bin/netbridge
sock=/lgb/sock/egress.sock
port=` + port + `
if [ ! -x "$bridge" ] || [ ! -S "$sock" ]; then
  echo "network proxy unavailable" >&2
  exit 1
fi
"$bridge" "$port" "$sock" >/tmp/lgb-net.ready &
pid=$!
trap 'kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null; wait "$pid" 2>/dev/null' EXIT
i=0
ok=0
while [ "$i" -lt 100000 ]; do
  if [ -s /tmp/lgb-net.ready ] && "$bridge" probe "$port"; then
    ok=1
    break
  fi
  i=$((i + 1))
done
if [ "$ok" != 1 ]; then
  echo "network proxy unavailable" >&2
  exit 1
fi
"$@"
exit $?
`
}
