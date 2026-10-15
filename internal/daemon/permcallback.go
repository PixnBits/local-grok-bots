package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// defaultPermCallbackAddr is the loopback listener the Claude CLI's MCP
// permission tool calls when the main listener speaks TLS. Port 0 picks a
// free port at startup.
const defaultPermCallbackAddr = "127.0.0.1:0"

// checkLoopbackAddr refuses any bind that is not a loopback IP. "localhost"
// is refused too, since it can resolve to a non-loopback address.
func checkLoopbackAddr(addr string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("PERM_CALLBACK_ADDR %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("PERM_CALLBACK_ADDR %q: missing port", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("PERM_CALLBACK_ADDR %q must bind a loopback IP such as 127.0.0.1", addr)
	}
	return nil
}

// permCallbackHandler serves only the per-run MCP permission route. The
// handler checks the per-run token itself; everything else is 404.
func (a *App) permCallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && mcpPermissionOpen(r.URL.Path) {
			if tok := strings.TrimPrefix(r.URL.Path, "/api/mcp/permission/"); tok != r.URL.Path {
				if tok == "" || strings.Contains(tok, "/") {
					http.NotFound(w, r)
					return
				}
				r.SetPathValue("token", tok)
			}
			a.handleMCPPermission(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// startPermCallback opens the loopback listener and points CLIs at it.
// Fails closed: a non-loopback or unbindable address stops startup.
func (a *App) startPermCallback() error {
	addr := a.cfg.PermCallbackAddr
	if addr == "" {
		addr = defaultPermCallbackAddr
	}
	if err := checkLoopbackAddr(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("permission callback listener: %w", err)
	}
	srv := &http.Server{Handler: a.permCallbackHandler(), ReadHeaderTimeout: 10 * time.Second}
	a.permSrv = srv
	a.permBase = "http://" + ln.Addr().String()
	fields := map[string]any{"addr": ln.Addr().String(), "reason": "tls"}
	a.log("", "perm_callback_listen", fields)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "perm_callback_listen"}
		for k, v := range fields {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log("", "perm_callback_error", map[string]any{"error": err.Error()})
		}
	}()
	return nil
}

func (a *App) stopPermCallback() {
	if a.permSrv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = a.permSrv.Shutdown(ctx)
}
