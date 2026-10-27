package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

const defaultPermCallbackAddr = "127.0.0.1:0"

func (a *App) permCallbackListenAddr() string {
	addr := strings.TrimSpace(a.cfg.PermCallbackAddr)
	if addr == "" {
		return defaultPermCallbackAddr
	}
	return addr
}

// usesMCPTransport reports whether Claude turns on this daemon ask over MCP.
func (a *App) usesMCPTransport() bool {
	a.rtMu.Lock()
	pol := a.policy
	a.rtMu.Unlock()
	if !strings.EqualFold(pol.EffectiveBackend(), "claude") {
		return false
	}
	mode, err := policy.NormClaudeTransport(pol.ClaudeTransport)
	return err == nil && mode == policy.TransportMCP
}

func (a *App) mcpBotsExist() bool {
	if !a.usesMCPTransport() {
		return false
	}
	bots, err := a.st.ListBots()
	return err == nil && len(bots) > 0
}

// syncPermCallback starts the loopback listener when an MCP bot exists and
// stops it otherwise. A failure to bind does not change other listeners.
func (a *App) syncPermCallback() error {
	if !a.mcpBotsExist() {
		a.stopPermCallback()
		return nil
	}
	return a.startPermCallback()
}

// notePermCallback starts or stops the callback after a bot change.
// The bot change itself does not depend on the listener.
func (a *App) notePermCallback() {
	if err := a.syncPermCallback(); err != nil {
		a.log("", "perm_callback_error", map[string]any{"error": err.Error()})
	}
}

// mcpHostBase is the origin written into mcp.json. Plain HTTP keeps permBase.
// TLS uses the callback, which is empty unless an MCP bot started it.
func (a *App) mcpHostBase() string {
	if tlsConfigured(a.cfg) {
		a.permCbMu.Lock()
		base := a.permCallbackBase
		a.permCbMu.Unlock()
		return base
	}
	return a.permBase
}

func (a *App) permCallbackOn() (string, bool) {
	a.permCbMu.Lock()
	defer a.permCbMu.Unlock()
	if a.permLn == nil {
		return "", false
	}
	return a.permLn.Addr().String(), true
}

func (a *App) permCallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !mcpPermissionOpen(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		if tok := strings.TrimPrefix(r.URL.Path, "/api/mcp/permission/"); tok != r.URL.Path {
			if tok == "" || strings.Contains(tok, "/") {
				http.NotFound(w, r)
				return
			}
			r.SetPathValue("token", tok)
		}
		a.handleMCPPermission(w, r)
	})
}

func (a *App) startPermCallback() error {
	a.permCbMu.Lock()
	defer a.permCbMu.Unlock()
	if a.permSrv != nil {
		return nil
	}
	addr := a.permCallbackListenAddr()
	if err := policy.RequireLoopbackAddr(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("permission callback listener: %w", err)
	}
	if err := policy.RequireLoopbackAddr(ln.Addr().String()); err != nil {
		_ = ln.Close()
		return fmt.Errorf("permission callback bound %s, which is not loopback", ln.Addr().String())
	}
	srv := &http.Server{Handler: a.permCallbackHandler(), ReadHeaderTimeout: 10 * time.Second}
	bound := ln.Addr().String()
	a.permSrv = srv
	a.permLn = ln
	a.permCallbackBase = "http://" + bound
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log("", "perm_callback_error", map[string]any{"error": err.Error()})
		}
	}()
	a.log("", "perm_callback_listen", map[string]any{"addr": bound})
	return nil
}

func (a *App) stopPermCallback() {
	a.permCbMu.Lock()
	srv := a.permSrv
	a.permSrv = nil
	a.permLn = nil
	a.permCallbackBase = ""
	a.permCbMu.Unlock()
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
