package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestLGBThroughFakeCLI(t *testing.T) {
	t.Setenv("AUTH_TOKEN", "")
	dir := t.TempDir()
	installCLIStub(t, dir, "claude")
	out := filepath.Join(dir, "lgb.out")
	argvLog := filepath.Join(dir, "argv.log")
	t.Setenv("LGB_OUT", out)
	t.Setenv("LGB_ARGV_LOG", argvLog)
	t.Setenv("LGB_CLI_MODE", "lgb")
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	tok := app.cfg.AuthToken
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{"name": "Ada", "description": "d"}, tok)
	if res.StatusCode != 201 && res.StatusCode != 200 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]any{"content": "hi"}, tok)
	if res.StatusCode != 200 {
		t.Fatalf("post %d %s", res.StatusCode, b)
	}
	waitIdle(t, srv.URL, bot.ID, tok)
	got, _ := os.ReadFile(out)
	text := string(got)
	want := []string{"rc=0\n", "unknown command", "off by policy", "lgb: not authorized"}
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Fatalf("lgb output lacks %q:\n%s", w, text)
		}
	}
	if strings.Count(text, "rc=0") != 3 {
		t.Fatalf("want 3 successes:\n%s", text)
	}
	if strings.Contains(text, tok) || !strings.Contains(text, "token=lgbr_") {
		t.Fatalf("lgb token is the admin token or missing:\n%s", text)
	}
	mem, _ := app.st.ListMemory(bot.ID)
	if len(mem) != 1 || mem[0].Key != "color" || mem[0].Value != "blue" {
		t.Fatalf("memory %+v", mem)
	}
	timers, _ := app.st.ListTimers(bot.ID)
	if len(timers) != 1 || timers[0].Prompt != "check in with the user" {
		t.Fatalf("timers %+v", timers)
	}
	if bots, _ := app.st.ListBots(); len(bots) != 1 {
		t.Fatalf("lgb created a bot without policy")
	}
	argv := readArgv(t, argvLog)
	if !strings.Contains(argv, "--allowedTools\nBash(lgb *)\n") {
		t.Fatalf("lgb allow rule missing:\n%s", argv)
	}
	// The run token is useless against the HTTP API.
	runTok := strings.TrimSpace(text[strings.Index(text, "token=")+len("token="):])
	if r, _ := do(t, "GET", srv.URL+"/api/bots", nil, runTok); r.StatusCode != 401 {
		t.Fatalf("run token opened the API: %d", r.StatusCode)
	}
	_, lb := do(t, "GET", srv.URL+"/api/log?kind=lgb_call&limit=50", nil, tok)
	var events []store.LogEvent
	decodeJSON(t, lb, &events)
	if len(events) != 6 {
		t.Fatalf("want 6 audited lgb calls, got %d: %s", len(events), lb)
	}
	if !strings.Contains(string(lb), `"run_id"`) {
		t.Fatalf("lgb log lacks run id: %s", lb)
	}
	// After the run the spool is closed.
	ws, err := cliWorkspace(app.ws, bot.ID)
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "lgb.sh")
	_ = os.WriteFile(script, []byte(lgbScript), 0o700)
	cmd := exec.Command("sh", script, "memory", "list")
	cmd.Env = append(os.Environ(), "LGB_SPOOL="+filepath.Join(ws, lgbDirName), "LGB_TOKEN="+runTok)
	if o, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(o), "not available") {
		t.Fatalf("lgb after the run: %v %s", err, o)
	}
}

func TestLGBRequestTooLarge(t *testing.T) {
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	bot, err := app.st.CreateBot("Ada", "d", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	r, _, err := app.startLGB(context.Background(), bot, "run1", ws)
	if err != nil || r == nil {
		t.Fatal(err)
	}
	r.cancel()
	<-r.done
	const name = "00112233445566778899ddee"
	body := make([]byte, lgbMaxReq+1)
	copy(body, r.token+"\x00memory\x00set\x00k\x00")
	if err := os.WriteFile(filepath.Join(ws, lgbDirName, "req", name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	r.drain(context.Background())
	got, err := os.ReadFile(filepath.Join(ws, lgbDirName, "resp", name))
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if !strings.HasPrefix(text, "2\n") || !strings.Contains(text, "request too large (max 64 KiB)") || strings.Contains(text, "unreadable") {
		t.Fatalf("response %q", text)
	}
	exactName := "aabbccddeeff00112233bbcc"
	exact := make([]byte, lgbMaxReq)
	copy(exact, r.token+"\x00memory\x00list\x00")
	if err := os.WriteFile(filepath.Join(ws, lgbDirName, "req", exactName), exact, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.req.read(exactName, lgbMaxReq); err != nil {
		t.Fatalf("a request of exactly %d bytes was refused: %v", lgbMaxReq, err)
	}
	r.req.close()
	r.resp.close()
}

func TestLGBRejectsOneSecondRepeat(t *testing.T) {
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	bot, err := app.st.CreateBot("Ada", "d", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	r, _, err := app.startLGB(context.Background(), bot, "run1", ws)
	if err != nil || r == nil {
		t.Fatal(err)
	}
	r.cancel()
	<-r.done
	const name = "00112233445566778899ccdd"
	body := r.token + "\x00timer\x00every\x001s\x00spam\x00"
	if err := os.WriteFile(filepath.Join(ws, lgbDirName, "req", name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r.drain(context.Background())
	got, err := os.ReadFile(filepath.Join(ws, lgbDirName, "resp", name))
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if !strings.HasPrefix(text, "1\n") || !strings.Contains(text, "shorter than the minimum 5m") {
		t.Fatalf("response %q", text)
	}
	if timers, _ := app.st.ListTimers(bot.ID); len(timers) != 0 {
		t.Fatalf("timer stored: %+v", timers)
	}
	r.req.close()
	r.resp.close()
}

func TestLGBSpoolIgnoresSwappedLinks(t *testing.T) {
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	bot, err := app.st.CreateBot("Ada", "d", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(dir, "ws")
	_ = os.MkdirAll(ws, 0o755)
	r, env, err := app.startLGB(context.Background(), bot, "run1", ws)
	if err != nil || env == nil {
		t.Fatal(err)
	}
	r.cancel()
	<-r.done
	outside := filepath.Join(dir, "outside")
	_ = os.MkdirAll(outside, 0o755)
	root := filepath.Join(ws, lgbDirName)
	// The bot swaps resp for a link and plants a request that is itself a link.
	_ = os.Rename(filepath.Join(root, "resp"), filepath.Join(root, "resp.old"))
	_ = os.Symlink(outside, filepath.Join(root, "resp"))
	_ = os.WriteFile(filepath.Join(root, "req", "00112233445566778899aabb"), []byte(r.token+"\x00memory\x00list\x00"), 0o600)
	_ = os.Symlink("/etc/passwd", filepath.Join(root, "req", "aabbccddeeff00112233aabb"))
	r.drain(context.Background())
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("daemon wrote through the swapped link: %v", ents)
	}
	b, err := os.ReadFile(filepath.Join(root, "resp.old", "00112233445566778899aabb"))
	if err != nil || !strings.HasPrefix(string(b), "0\n") {
		t.Fatalf("answer not in the real spool: %q %v", b, err)
	}
	b, _ = os.ReadFile(filepath.Join(root, "resp.old", "aabbccddeeff00112233aabb"))
	if !strings.Contains(string(b), "unreadable") {
		t.Fatalf("link request was read: %q", b)
	}
	r.token = ""
	r.req.close()
	r.resp.close()
}
