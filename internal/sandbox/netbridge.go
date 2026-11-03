package sandbox

import (
	_ "embed"
	"strconv"
)

//go:embed netbridge.c.txt
var netBridgeSrc string

// jailHTTPProxyPort is the HTTP CONNECT listener inside the jail network
// namespace. The namespace has no other listeners, so a fixed port is safe.
const jailHTTPProxyPort = 18080

func netBridgeBin() cachedBin {
	return cachedBin{
		name: "lgb-netbridge",
		src:  netBridgeSrc,
		build: func() ([]byte, error) {
			return gccBytes("netbridge.c", []byte(netBridgeSrc), "netbridge", "net bridge compile",
				[]string{"-O2"}, nil)
		},
	}
}

// ensureNetBridge compiles the in-jail TCP-to-unix splice once and caches it.
// Without gcc the HTTP proxy env is not set. LD_PRELOAD still applies when
// the connect shim compiled.
func ensureNetBridge() (string, error) {
	return ensureCached(netBridgeBin())
}

func ensureNetBridgeIn(dir string) (string, error) {
	return ensureCachedIn(dir, netBridgeBin())
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
deadline=$(($(date +%s) + 5))
ok=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if [ -s /tmp/lgb-net.ready ] && "$bridge" probe "$port"; then
    ok=1
    break
  fi
  sleep 0.1
done
if [ "$ok" != 1 ]; then
  echo "network proxy unavailable" >&2
  exit 1
fi
"$@"
exit $?
`
}
