package web

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// Composer voice: browser recognition stays on-device, and speech uses a local voice.

func TestComposerVoiceOnDevice(t *testing.T) {
	src := ClientSource()
	if strings.Contains(src, "webkitSpeechRecognition") || strings.Contains(strings.ToLower(src), "webkitspeechrecognition") {
		t.Fatal("index.html names the prefixed speech recognizer")
	}
	if strings.Count(src, "// voice-sr:begin") != 1 || strings.Count(src, "// voice-sr:end") != 1 {
		t.Fatal("voice-sr markers must wrap the recognizer once")
	}
	if strings.Count(src, "// voice-tts:begin") != 1 || strings.Count(src, "// voice-tts:end") != 1 {
		t.Fatal("voice-tts markers must wrap speech once")
	}
	sr := between(t, src, "// voice-sr:begin", "// voice-sr:end")
	if strings.Count(src, "new SpeechRecognition") != 1 || strings.Count(sr, "new SpeechRecognition") != 1 {
		t.Fatalf("want one SpeechRecognition construction inside voice-sr, file %d block %d", strings.Count(src, "new SpeechRecognition"), strings.Count(sr, "new SpeechRecognition"))
	}
	if strings.Count(src, ".start(") != 1 || strings.Count(sr, ".start(") != 1 {
		t.Fatalf("want one recognizer start, inside voice-sr: file %d block %d", strings.Count(src, ".start("), strings.Count(sr, ".start("))
	}
	setAt := strings.Index(sr, "processLocally = true")
	readAt := strings.Index(sr, "processLocally !== true")
	startAt := strings.Index(sr, ".start(")
	if setAt < 0 || readAt < setAt || startAt < readAt {
		t.Fatal("processLocally = true and its read-back must precede start")
	}
	consentAt := strings.Index(sr, "needsConsent")
	installAt := strings.Index(sr, "SR.install")
	if consentAt < 0 || installAt < consentAt {
		t.Fatal("install must follow the consent return")
	}
	if strings.Contains(src, "End & summarize") || strings.Contains(src, "voiceSummaryPrompt") {
		t.Fatal("voice mode must not offer an end-and-summarize action")
	}
	field := strings.Index(src, `id="composer-input"`)
	mic := strings.Index(src, `id="mic-btn"`)
	voice := strings.Index(src, `id="voice-btn"`)
	stop := strings.Index(src, `id="stop-btn"`)
	send := strings.Index(src, `id="send-btn"`)
	if field < 0 || mic < 0 || voice < 0 || stop < 0 || send < 0 || !(field < mic && mic < voice && voice < stop && stop < send) {
		t.Fatal("tab order must be the field, then voice, then Stop, then Send")
	}
	if !strings.Contains(src, `id="voice-status" class="sr" role="status" aria-live="polite"`) {
		t.Fatal("missing polite voice status region")
	}
	for _, sentence := range []string{
		"Speech recognition is turned off on this computer.",
		"That audio format isn't supported.",
		"Speech recognition is busy. Try again in a moment.",
		"Speech recognition timed out. Try again.",
		"Speech recognition isn't available right now.",
		"Speech recognition didn't work. Try again.",
	} {
		if !strings.Contains(src, sentence) {
			t.Errorf("missing speech sentence %q", sentence)
		}
	}
	if !strings.Contains(src, "#mic-btn, #voice-btn, #voice-cfg {\n      width: 44px; height: 44px; min-width: 44px; min-height: 44px;") {
		t.Fatal("narrow layout must give voice controls a 44px hit area")
	}
	tts := between(t, src, "// voice-tts:begin", "// voice-tts:end")
	if !strings.Contains(tts, "localService === true") || !strings.Contains(tts, "synth.speak(") {
		t.Fatal("speech block must keep local voices and the speak call together")
	}
	speakAt := strings.Index(tts, "synth.speak(")
	guardAt := strings.Index(tts, "voice.localService !== true")
	if guardAt < 0 || speakAt < guardAt {
		t.Fatal("speak must follow the local-voice guard")
	}
}

func TestComposerVoiceNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required")
	}
	sr, err := json.Marshal(between(t, ClientSource(), "// voice-sr:begin", "// voice-sr:end"))
	if err != nil {
		t.Fatal(err)
	}
	tts, err := json.Marshal(between(t, ClientSource(), "// voice-tts:begin", "// voice-tts:end"))
	if err != nil {
		t.Fatal(err)
	}
	script := `const vm = require("vm");
const srSrc = ` + string(sr) + `;
const ttsSrc = ` + string(tts) + `;
function runSR(opts) {
  const sandbox = {};
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  const prelude = [
    "const __opts = " + JSON.stringify(opts) + ";",
    "const __stats = { starts: 0, installs: 0, available: 0, constructed: 0, flags: [] };",
    "function SpeechRecognition() {",
    "  __stats.constructed += 1;",
    "  const n = __stats.constructed;",
    "  let stick = true;",
    "  if (__opts.stick === \"none\") stick = false;",
    "  if (__opts.stick === \"first\") stick = n === 1;",
    "  if (!stick) {",
    "    Object.defineProperty(this, \"processLocally\", {",
    "      configurable: true, enumerable: true,",
    "      set: function () {},",
    "      get: function () { return false; }",
    "    });",
    "  }",
    "  const self = this;",
    "  this.start = function () {",
    "    __stats.starts += 1;",
    "    __stats.flags.push(self.processLocally === true);",
    "  };",
    "}",
    "if (__opts.prototype !== false) SpeechRecognition.prototype.processLocally = false;",
    "SpeechRecognition.available = async function (q) {",
    "  __stats.available += 1;",
    "  __stats.query = q;",
    "  if (__opts.throwOnAvailable) throw new Error(\"down\");",
    "  if (__opts.seq) return __opts.seq[__stats.available - 1];",
    "  return __opts.status;",
    "};",
    "SpeechRecognition.install = async function (q) {",
    "  __stats.installs += 1;",
    "  __stats.installQuery = q;",
    "  return __opts.installResult;",
    "};",
    "this.SpeechRecognition = SpeechRecognition;",
    "this.__stats = __stats;"
  ].join("\n");
  vm.runInContext(prelude + "\n" + srSrc + "\nthis.startLocalRecognition = startLocalRecognition;", sandbox);
  return sandbox;
}
(async function () {
  const out = {};
  {
    const h = runSR({ prototype: false, status: "available" });
    const r = await h.startLocalRecognition({ lang: "en-US" });
    out.c1 = { fallback: !!(r && r.fallback), starts: h.__stats.starts, installs: h.__stats.installs, available: h.__stats.available };
  }
  {
    const h = runSR({ status: "unavailable" });
    const r = await h.startLocalRecognition({ lang: "en-US" });
    out.c2 = { fallback: !!(r && r.fallback), ok: !!(r && r.ok), starts: h.__stats.starts, installs: h.__stats.installs };
  }
  {
    const h = runSR({ status: "downloadable" });
    const r = await h.startLocalRecognition({ lang: "en-US" });
    out.c3a = { needsConsent: !!(r && r.needsConsent), starts: h.__stats.starts, installs: h.__stats.installs };
  }
  {
    const h = runSR({ status: "downloading" });
    const r = await h.startLocalRecognition({ lang: "en-US", consent: false });
    out.c3b = { needsConsent: !!(r && r.needsConsent), starts: h.__stats.starts, installs: h.__stats.installs };
  }
  {
    const h = runSR({ seq: ["downloadable", "available"], installResult: true });
    const r = await h.startLocalRecognition({ lang: "en-GB", consent: true });
    out.c3c = {
      ok: !!(r && r.ok),
      starts: h.__stats.starts,
      installs: h.__stats.installs,
      flag: h.__stats.flags[0] === true,
      lang: r && r.rec && r.rec.lang,
      queryLocal: !!(h.__stats.query && h.__stats.query.processLocally === true),
      installLocal: !!(h.__stats.installQuery && h.__stats.installQuery.processLocally === true)
    };
  }
  {
    const h = runSR({ seq: ["downloadable", "downloadable"], installResult: true });
    const r = await h.startLocalRecognition({ lang: "en-US", consent: true });
    out.c3d = { fallback: !!(r && r.fallback), ok: !!(r && r.ok), starts: h.__stats.starts, installs: h.__stats.installs };
  }
  {
    const h = runSR({ status: "available" });
    const r = await h.startLocalRecognition({ lang: "en-US" });
    out.c4 = {
      ok: !!(r && r.ok),
      starts: h.__stats.starts,
      installs: h.__stats.installs,
      constructed: h.__stats.constructed,
      flag: h.__stats.flags[0] === true,
      lang: r && r.rec && r.rec.lang,
      queryLocal: !!(h.__stats.query && h.__stats.query.processLocally === true && h.__stats.query.langs && h.__stats.query.langs[0] === "en-US")
    };
  }
  {
    const h = runSR({ status: "available", stick: "none" });
    const r = await h.startLocalRecognition({ lang: "en-US" });
    out.c5 = { fallback: !!(r && r.fallback), ok: !!(r && r.ok), starts: h.__stats.starts, constructed: h.__stats.constructed };
  }
  {
    const h = runSR({ throwOnAvailable: true, status: "available" });
    const r = await h.startLocalRecognition({ lang: "en-US" });
    out.cthrow = { fallback: !!(r && r.fallback), starts: h.__stats.starts };
  }
  {
    const h = runSR({ status: "available", stick: "first" });
    let restarted = null;
    const r = await h.startLocalRecognition({
      lang: "en-US",
      voiceMode: function () { return true; },
      onRestart: function (next) { restarted = next; }
    });
    await r.rec.onend();
    out.c6 = {
      firstOk: !!(r && r.ok),
      starts: h.__stats.starts,
      available: h.__stats.available,
      constructed: h.__stats.constructed,
      firstFlag: h.__stats.flags[0] === true,
      restartFallback: !!(restarted && restarted.fallback),
      restartOk: !!(restarted && restarted.ok),
      queryLocal: !!(h.__stats.query && h.__stats.query.processLocally === true)
    };
  }
  const box = {};
  box.window = box;
  function SpeechSynthesisUtterance(text) { this.text = text; }
  box.SpeechSynthesisUtterance = SpeechSynthesisUtterance;
  const spoken = [];
  const synth = {
    speak: function (u) { spoken.push({ voiceURI: u.voice && u.voice.voiceURI, local: !!(u.voice && u.voice.localService === true) }); },
    cancel: function () {}
  };
  vm.createContext(box);
  vm.runInContext(ttsSrc + "\nthis.speakableText = speakableText;\nthis.speakLocal = speakLocal;\nthis.speakWithVoice = speakWithVoice;", box);
  const tick = String.fromCharCode(96);
  const fence = tick + tick + tick;
  const md = "# Title\n\n**Bold** and [link](place) with " + tick + "code" + tick + "\n\n" + fence + "\ncode\n" + fence + "\n\n- item";
  const remote = [{ name: "Remote", lang: "en-US", localService: false, voiceURI: "remote" }];
  const mixed = remote.concat([{ name: "Local", lang: "en-US", localService: true, voiceURI: "local" }]);
  const only = box.speakLocal(synth, "hello", remote, "", "en-US", {});
  const afterRemote = spoken.length;
  const mixedOk = box.speakLocal(synth, "hello", mixed, "", "en-US", {});
  const heard = spoken[spoken.length - 1] || {};
  const before = spoken.length;
  const nullVoice = box.speakWithVoice(synth, "hello", null, {});
  const remoteVoice = box.speakWithVoice(synth, "hello", remote[0], {});
  out.tts = {
    text: box.speakableText(md),
    only: only,
    afterRemote: afterRemote,
    mixedOk: mixedOk,
    voiceURI: heard.voiceURI || "",
    local: heard.local === true,
    nullVoice: nullVoice,
    remoteVoice: remoteVoice,
    extra: spoken.length - before
  };
  console.log(JSON.stringify(out));
})().catch(function (err) { console.error(err && err.stack || err); process.exit(1); });
`
	raw := runNode(t, node, script)
	var got struct {
		C1 struct {
			Fallback  bool `json:"fallback"`
			Starts    int  `json:"starts"`
			Installs  int  `json:"installs"`
			Available int  `json:"available"`
		} `json:"c1"`
		C2 struct {
			Fallback bool `json:"fallback"`
			OK       bool `json:"ok"`
			Starts   int  `json:"starts"`
			Installs int  `json:"installs"`
		} `json:"c2"`
		C3a struct {
			NeedsConsent bool `json:"needsConsent"`
			Starts       int  `json:"starts"`
			Installs     int  `json:"installs"`
		} `json:"c3a"`
		C3b struct {
			NeedsConsent bool `json:"needsConsent"`
			Starts       int  `json:"starts"`
			Installs     int  `json:"installs"`
		} `json:"c3b"`
		C3c struct {
			OK           bool   `json:"ok"`
			Starts       int    `json:"starts"`
			Installs     int    `json:"installs"`
			Flag         bool   `json:"flag"`
			Lang         string `json:"lang"`
			QueryLocal   bool   `json:"queryLocal"`
			InstallLocal bool   `json:"installLocal"`
		} `json:"c3c"`
		C3d struct {
			Fallback bool `json:"fallback"`
			OK       bool `json:"ok"`
			Starts   int  `json:"starts"`
			Installs int  `json:"installs"`
		} `json:"c3d"`
		C4 struct {
			OK          bool   `json:"ok"`
			Starts      int    `json:"starts"`
			Installs    int    `json:"installs"`
			Constructed int    `json:"constructed"`
			Flag        bool   `json:"flag"`
			Lang        string `json:"lang"`
			QueryLocal  bool   `json:"queryLocal"`
		} `json:"c4"`
		C5 struct {
			Fallback    bool `json:"fallback"`
			OK          bool `json:"ok"`
			Starts      int  `json:"starts"`
			Constructed int  `json:"constructed"`
		} `json:"c5"`
		Cthrow struct {
			Fallback bool `json:"fallback"`
			Starts   int  `json:"starts"`
		} `json:"cthrow"`
		C6 struct {
			FirstOk         bool `json:"firstOk"`
			Starts          int  `json:"starts"`
			Available       int  `json:"available"`
			Constructed     int  `json:"constructed"`
			FirstFlag       bool `json:"firstFlag"`
			RestartFallback bool `json:"restartFallback"`
			RestartOk       bool `json:"restartOk"`
			QueryLocal      bool `json:"queryLocal"`
		} `json:"c6"`
		TTS struct {
			Text        string `json:"text"`
			Only        bool   `json:"only"`
			AfterRemote int    `json:"afterRemote"`
			MixedOk     bool   `json:"mixedOk"`
			VoiceURI    string `json:"voiceURI"`
			Local       bool   `json:"local"`
			NullVoice   bool   `json:"nullVoice"`
			RemoteVoice bool   `json:"remoteVoice"`
			Extra       int    `json:"extra"`
		} `json:"tts"`
	}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode %v: %s", err, raw)
	}
	if !got.C1.Fallback || got.C1.Starts != 0 || got.C1.Installs != 0 || got.C1.Available != 0 {
		t.Fatalf("no processLocally: %+v", got.C1)
	}
	if !got.C2.Fallback || got.C2.OK || got.C2.Starts != 0 || got.C2.Installs != 0 {
		t.Fatalf("unavailable: %+v", got.C2)
	}
	if !got.C3a.NeedsConsent || got.C3a.Starts != 0 || got.C3a.Installs != 0 {
		t.Fatalf("downloadable without consent: %+v", got.C3a)
	}
	if !got.C3b.NeedsConsent || got.C3b.Starts != 0 || got.C3b.Installs != 0 {
		t.Fatalf("downloading without consent: %+v", got.C3b)
	}
	if !got.C3c.OK || got.C3c.Starts != 1 || got.C3c.Installs != 1 || !got.C3c.Flag || got.C3c.Lang != "en-GB" || !got.C3c.QueryLocal || !got.C3c.InstallLocal {
		t.Fatalf("consent then available: %+v", got.C3c)
	}
	if !got.C3d.Fallback || got.C3d.OK || got.C3d.Starts != 0 || got.C3d.Installs != 1 {
		t.Fatalf("consent still downloadable: %+v", got.C3d)
	}
	if !got.C4.OK || got.C4.Starts != 1 || got.C4.Installs != 0 || got.C4.Constructed != 1 || !got.C4.Flag || got.C4.Lang != "en-US" || !got.C4.QueryLocal {
		t.Fatalf("available: %+v", got.C4)
	}
	if !got.C5.Fallback || got.C5.OK || got.C5.Starts != 0 || got.C5.Constructed != 1 {
		t.Fatalf("processLocally does not stick: %+v", got.C5)
	}
	if !got.Cthrow.Fallback || got.Cthrow.Starts != 0 {
		t.Fatalf("available threw: %+v", got.Cthrow)
	}
	if !got.C6.FirstOk || got.C6.Starts != 1 || got.C6.Available < 2 || got.C6.Constructed != 2 || !got.C6.FirstFlag || !got.C6.RestartFallback || got.C6.RestartOk || !got.C6.QueryLocal {
		t.Fatalf("voice-mode restart: %+v", got.C6)
	}
	if got.TTS.Text != "Title Bold and link with code (code omitted) item" {
		t.Fatalf("speakable text %q", got.TTS.Text)
	}
	if got.TTS.Only || got.TTS.AfterRemote != 0 || !got.TTS.MixedOk || got.TTS.VoiceURI != "local" || !got.TTS.Local {
		t.Fatalf("local voice: %+v", got.TTS)
	}
	if got.TTS.NullVoice || got.TTS.RemoteVoice || got.TTS.Extra != 0 {
		t.Fatalf("refused voices still spoke: %+v", got.TTS)
	}
}

// Voice controls keep focus, announce every error, and name the mic problem.
func TestComposerVoiceFocusAndErrors(t *testing.T) {
	src := ClientSource()
	slot := between(t, src, "function syncVoiceSlot(hasText) {", "function syncSendEmpty()")
	if !strings.Contains(slot, "had.hidden") || !strings.Contains(slot, `getElementById("send-btn")`) {
		t.Fatal("hiding the focused mic, voice or settings button must move focus to Send or the field")
	}
	stop := between(t, src, "function stopAll() {", "async function toggleMic()")
	if !strings.Contains(stop, "voiceHome().focus()") || !strings.Contains(stop, "prompt.contains(act)") {
		t.Fatal("stopAll must move focus out of the voice bar and prompt before hiding them")
	}
	if !strings.Contains(stop, "if (v.errorShown) return;") || !strings.Contains(stop, "v.rec.onend = null") {
		t.Fatal("stopAll must not announce over an error or after Voice mode off")
	}
	if strings.Count(src, "rescueFocus(box);") != 2 {
		t.Fatal("both language-pack buttons must move focus before the prompt hides")
	}
	if strings.Count(src, `if (!v.errorShown) announceVoice("Dictation stopped");`) != 2 {
		t.Fatal("Dictation stopped must not replace an error announcement")
	}
	if !strings.Contains(src, "announceVoice(text, true);") || !strings.Contains(src, `text + "\u00a0"`) {
		t.Fatal("errors must be announced even when repeated")
	}
	if !strings.Contains(src, `.voice-settings label:has(#vs-tts), .voice-settings input:not([type="checkbox"]), .voice-settings select { min-height: 44px; }`) {
		t.Fatal("the voice settings controls need 44px targets on phones")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required")
	}
	fn, err := json.Marshal(between(t, src, "function micErrorMessage(name) {", "function sttErrorMessage(status) {"))
	if err != nil {
		t.Fatal(err)
	}
	script := `const f = new Function("return function micErrorMessage(name) {" + ` + string(fn) + ` + ";")();
const out = {};
for (const k of ["NotAllowedError", "not-allowed", "NotFoundError", "NotReadableError", "mic", "language-not-supported", "insecure"]) out[k] = f(k);
console.log(JSON.stringify(out));`
	var got map[string]string
	if err := json.Unmarshal([]byte(runNode(t, node, script)), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"NotAllowedError":        "Microphone access is blocked.",
		"not-allowed":            "Microphone access is blocked.",
		"NotFoundError":          "No microphone was found.",
		"NotReadableError":       "in use by another app",
		"mic":                    "can't record audio",
		"language-not-supported": "doesn't support this language",
	}
	for k, w := range want {
		if !strings.Contains(got[k], w) {
			t.Fatalf("%s: got %q, want it to contain %q", k, got[k], w)
		}
	}
	if got["insecure"] != "" {
		t.Fatalf("insecure should fall through, got %q", got["insecure"])
	}
	seen := map[string]bool{}
	for _, k := range []string{"NotAllowedError", "NotFoundError", "NotReadableError", "mic"} {
		if seen[got[k]] {
			t.Fatalf("mic errors must read differently, %s repeats %q", k, got[k])
		}
		seen[got[k]] = true
	}
}
