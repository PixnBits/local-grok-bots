//go:build linux

package sandbox

import (
	"context"
	"path/filepath"
)

func init() {
	attachShellEgress = attachShellEgressLinux
}

// attachShellEgressLinux listens on the prep directory's egress socket and
// sets the proxy environment when the net grant is on and the listener
// started. The in-jail binary splices 127.0.0.1 to that socket. A failure
// leaves the connect shim in place and does not set the proxy variables.
func attachShellEgressLinux(ctx context.Context, p *prepared, req Request, rw, ro string) {
	if p == nil || !p.grants["net"] || p.proxy == nil {
		return
	}
	bin, err := ensureNetBridge()
	if err != nil {
		p.extra = append(p.extra, Event{Kind: "grant_denied", Grant: "net", Detail: "http proxy unavailable"})
		return
	}
	eg, err := listenShellEgress(ctx, filepath.Join(rw, "sock", "egress.sock"), EgressConfig{
		Resolve: req.Resolve,
		Dial:    req.Dial,
		Decide:  p.proxy.decide,
		Record:  p.proxy.add,
	})
	if err != nil {
		p.extra = append(p.extra, Event{Kind: "grant_denied", Grant: "net", Detail: "http proxy unavailable"})
		return
	}
	fail := func() {
		eg.Close()
		p.extra = append(p.extra, Event{Kind: "grant_denied", Grant: "net", Detail: "http proxy unavailable"})
	}
	if err := overlayFile(ro, "netbridge", mustRead(bin), 0o755); err != nil {
		fail()
		return
	}
	if err := writeExec(filepath.Join(ro, "netwrap"), netWrapScript()); err != nil {
		fail()
		return
	}
	touch(filepath.Join(rw, "bin", "netbridge"))
	touch(filepath.Join(rw, "netwrap"))
	p.mounts = append(p.mounts,
		mount{Src: filepath.Join(ro, "netbridge"), Dst: "/lgb/bin/netbridge", RO: true},
		mount{Src: filepath.Join(ro, "netwrap"), Dst: "/lgb/netwrap", RO: true},
	)
	p.env = append(p.env, shellProxyEnv()...)
	p.egress = eg
	p.egressOn = true
}
