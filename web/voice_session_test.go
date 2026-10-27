package web

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func voicePageSource(t *testing.T) string {
	t.Helper()
	src := string(IndexHTML)
	i := strings.Index(src, "// voice-sr:begin")
	j := strings.LastIndex(src, "state.stop = freshStop()")
	if i < 0 || j < i {
		t.Fatal("voice script markers missing")
	}
	return src[i:j]
}

func runVoice(t *testing.T, scenario string) map[string]any {
	t.Helper()
	node := mustNode(t)
	pageJSON, err := json.Marshal(voicePageSource(t))
	if err != nil {
		t.Fatal(err)
	}
	scenJSON, err := json.Marshal(scenario)
	if err != nil {
		t.Fatal(err)
	}
	script := voiceHarness + "\nconst pageSrc = " + string(pageJSON) + ";\nconst scenario = " + string(scenJSON) + ";\n" + voiceHarnessTail
	out := runNode(t, node, script)
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode %v: %s", err, out)
	}
	if thrown, ok := got["thrown"].(string); ok && thrown != "" {
		t.Fatalf("voice script: %s", thrown)
	}
	return got
}

func mustNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required")
	}
	return node
}

const voiceHarness = `
const vm = require("vm");
const sandbox = {
  console, setTimeout, clearTimeout, setInterval, clearInterval,
  Promise, JSON, Date, Math, Object, Array, Error, RegExp
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(` + "`" + `
var els = {};
function makeEl(id) {
  var node = {
    id: id,
    hidden: id !== "composer-input" && id !== "mic-btn" && id !== "voice-btn" && id !== "send-btn",
    textContent: "",
    value: "",
    title: "",
    selectionStart: 0,
    selectionEnd: 0,
    attrs: {},
    listeners: {},
    classList: { toggle() {}, add() {}, remove() {} },
    setAttribute(k, v) { this.attrs[k] = String(v); },
    getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; },
    removeAttribute(k) { delete this.attrs[k]; },
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
    click() { (this.listeners.click || []).forEach((fn) => fn()); },
    focus() { document.activeElement = this; },
    getClientRects() { return this.hidden ? [] : [{}]; },
    contains() { return false; },
    append() {},
    replaceChildren() {}
  };
  return node;
}
var document = {
  activeElement: null,
  createElement() { return makeEl("option"); },
  querySelector(sel) {
    var id = String(sel || "").replace(/^#/, "");
    if (!els[id]) els[id] = makeEl(id);
    return els[id];
  },
  getElementById(id) { return document.querySelector("#" + id); }
};
function $(sel) { return document.querySelector(sel); }
var state = { token: "tok", botId: "bot", streaming: false };
function base() { return ""; }
var authShown = 0;
function showAuth() { authShown += 1; }
function fitComposer() {}
function syncSendEmpty() {}
var sendGate = null;
function send() {
  if (sendGate) return new Promise((resolve) => { sendGate.push(resolve); });
  return Promise.resolve(true);
}
var store = {};
var localStorage = {
  getItem(k) { return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null; },
  setItem(k, v) { store[k] = String(v); }
};
var posts = [];
var statusCalls = 0;
var statusWaiters = [];
var holdStatus = 0;
var micCalls = 0;
var micWaiters = [];
var tracks = [];
var contexts = [];
var processors = [];
var sttCode = 200;
var sttReason = "";
var sttText = "dictated";
var sttWaiters = [];
var holdSTT = false;
var statusEnabled = true;
var statusAvailable = true;
var navigator = { language: "en-US", mediaDevices: {
  getUserMedia() {
    micCalls += 1;
    return new Promise((resolve) => {
      micWaiters.push(() => {
        var track = { readyState: "live", stop() { this.readyState = "ended"; this.stopped = true; } };
        tracks.push(track);
        resolve({ getTracks() { return [track]; } });
      });
    });
  }
} };
function AudioContext() {
  this.state = "running";
  this.sampleRate = 48000;
  this.closed = false;
  this.destination = {};
  this.resume = () => Promise.resolve();
  this.close = () => { this.closed = true; return Promise.resolve(); };
  this.createMediaStreamSource = () => ({ connect() {}, disconnect() {} });
  this.createScriptProcessor = () => {
    var p = { connect() {}, disconnect() {}, onaudioprocess: null };
    processors.push(p);
    return p;
  };
  this.createGain = () => ({ gain: { value: 1 }, connect() {}, disconnect() {} });
  contexts.push(this);
}
function SpeechRecognition() {
  SpeechRecognition.live.push(this);
  SpeechRecognition.constructed += 1;
  this.started = false;
  this.aborted = false;
  this.stopped = false;
  this.abort = () => { this.aborted = true; };
  this.stop = () => { this.stopped = true; if (typeof this.onend === "function") this.onend(); };
  this.start = () => { this.started = true; };
}
SpeechRecognition.live = [];
SpeechRecognition.constructed = 0;
SpeechRecognition.prototype.processLocally = true;
SpeechRecognition.mode = "unavailable";
SpeechRecognition.available = function () { return Promise.resolve(SpeechRecognition.mode || "unavailable"); };
SpeechRecognition.install = function () { return Promise.resolve(true); };
var performance = { at: 1000, now() { return performance.at; } };
function fetch(url, opts) {
  var u = String(url);
  if (u.indexOf("/api/stt/status") >= 0) {
    statusCalls += 1;
    var n = statusCalls;
    return Promise.resolve().then(async () => {
      if (holdStatus && n > holdStatus) {
        await new Promise((resolve) => { statusWaiters.push(resolve); });
      }
      return { ok: true, status: 200, json: async () => ({ enabled: statusEnabled, available: statusAvailable }) };
    });
  }
  posts.push({ url: u, partial: opts && opts.headers && opts.headers["X-STT-Partial"] });
  return Promise.resolve().then(async () => {
    if (holdSTT) await new Promise((resolve) => { sttWaiters.push(resolve); });
    var code = sttCode;
    return { ok: code >= 200 && code < 300, status: code, json: async () => ({ text: sttText, reason: sttReason }) };
  });
}
window.SpeechRecognition = SpeechRecognition;
window.AudioContext = AudioContext;
window.isSecureContext = true;
window.speechSynthesis = { getVoices() { return []; }, cancel() {}, speak() {}, addEventListener() {} };
function flush() { return new Promise((resolve) => setTimeout(resolve, 0)); }
function grantMic() { var fn = micWaiters.shift(); if (fn) fn(); }
function releaseStatus() { var fn = statusWaiters.shift(); if (fn) fn(); }
function releaseSTT() { sttWaiters.splice(0).forEach((fn) => fn()); }
function micBtn() { return document.querySelector("#mic-btn"); }
function voiceBtn() { return document.querySelector("#voice-btn"); }
function field() { return document.querySelector("#composer-input"); }
function msg() { return document.querySelector("#voice-msg"); }
function statusEl() { return document.querySelector("#voice-status"); }
function liveRecs() { return SpeechRecognition.live.filter((r) => r.started && !r.aborted && !r.stopped); }
function openGraphs() { return contexts.filter((c) => !c.closed).length; }
function liveTracks() { return tracks.filter((t) => t.readyState === "live").length; }
function loadPage() { eval(pageSrc); }
function loud() { return { inputBuffer: { getChannelData() { return [0.5, 0.5, 0.5, 0.5]; } } }; }
` + "`" + `, sandbox);
`

const voiceHarnessTail = `
vm.runInContext("var pageSrc = " + JSON.stringify(pageSrc) + ";", sandbox);
const done = vm.runInContext("(async () => {\ntry {\n" + scenario + "\n} catch (e) {\nconsole.log(JSON.stringify({thrown: String(e && e.stack || e)}));\n}\n})()", sandbox);
done.then(() => {}, (e) => { console.log(JSON.stringify({thrown: String(e && e.stack || e)})); });
`

func num(t *testing.T, got map[string]any, key string) float64 {
	t.Helper()
	v, ok := got[key].(float64)
	if !ok {
		t.Fatalf("%s = %#v in %#v", key, got[key], got)
	}
	return v
}

func TestVoiceCancelDuringStatusAndMic(t *testing.T) {
	got := runVoice(t, `
holdStatus = 1;
loadPage();
await flush();
await flush();
micBtn().click();
await flush();
await flush();
if (statusWaiters.length < 1) throw new Error("status was not held");
micBtn().click();
releaseStatus();
await flush();
await flush();
const afterStatus = { mic: micCalls, posts: posts.length, pressed: micBtn().attrs["aria-pressed"] || "false" };
holdStatus = 0;
micBtn().click();
await flush();
await flush();
if (micWaiters.length < 1) throw new Error("mic was not held");
micBtn().click();
grantMic();
await flush();
await flush();
console.log(JSON.stringify({
  afterStatus,
  posts: posts.length,
  pressed: micBtn().attrs["aria-pressed"] || "false",
  stopped: tracks.filter((t) => t.stopped).length,
  closed: contexts.filter((c) => c.closed).length,
  liveTracks: liveTracks(),
  openGraphs: openGraphs()
}));
`)
	after, _ := got["afterStatus"].(map[string]any)
	if after == nil || after["mic"].(float64) != 0 || after["posts"].(float64) != 0 {
		t.Fatalf("cancel during status %#v", got)
	}
	if num(t, got, "posts") != 0 || num(t, got, "stopped") < 1 || num(t, got, "closed") < 1 {
		t.Fatalf("cancel during mic %#v", got)
	}
	if got["pressed"] != "false" || num(t, got, "liveTracks") != 0 || num(t, got, "openGraphs") != 0 {
		t.Fatalf("left live %#v", got)
	}
}

func TestVoiceDoubleToggle(t *testing.T) {
	got := runVoice(t, `
let availResolve;
SpeechRecognition.available = () => new Promise((resolve) => { availResolve = resolve; });
loadPage();
await flush();
micBtn().click();
await flush();
micBtn().click();
await flush();
if (availResolve) availResolve("available");
await flush();
await flush();
console.log(JSON.stringify({
  constructed: SpeechRecognition.constructed,
  live: liveRecs().length,
  liveTracks: liveTracks(),
  openGraphs: openGraphs(),
  pressed: micBtn().attrs["aria-pressed"] || "false"
}));
`)
	if num(t, got, "constructed") > 1 || num(t, got, "live") != 0 || num(t, got, "liveTracks") != 0 || num(t, got, "openGraphs") != 0 {
		t.Fatalf("%#v", got)
	}
	if got["pressed"] != "false" {
		t.Fatalf("pressed %#v", got)
	}
}

func TestVoiceStaleEvents(t *testing.T) {
	got := runVoice(t, `
SpeechRecognition.mode = "available";
loadPage();
await flush();
await flush();
field().value = "KEEP";
field().selectionStart = 4;
field().selectionEnd = 4;
micBtn().click();
await flush();
await flush();
const rec = SpeechRecognition.live[SpeechRecognition.live.length - 1];
if (!rec) throw new Error("no rec");
micBtn().click();
await flush();
const before = { value: field().value, pressed: micBtn().attrs["aria-pressed"] || "false", status: statusEl().textContent };
rec.onresult && rec.onresult({ resultIndex: 0, results: [{ 0: { transcript: "nope" }, isFinal: true, length: 1 }] });
rec.onend && rec.onend();
await flush();
const afterRec = { value: field().value, pressed: micBtn().attrs["aria-pressed"] || "false", status: statusEl().textContent };
SpeechRecognition.mode = "unavailable";
holdSTT = true;
micBtn().click();
await flush();
await flush();
if (!micWaiters.length) throw new Error("expected mic");
grantMic();
await flush();
await flush();
const proc = processors[processors.length - 1];
if (!proc || !proc.onaudioprocess) throw new Error("no processor");
performance.at = 1000;
proc.onaudioprocess(loud());
await flush();
field().value = "KEEP2";
micBtn().click();
await flush();
if (!sttWaiters.length) throw new Error("stt was not held");
micBtn().click();
await flush();
const snap = field().value;
releaseSTT();
await flush();
await flush();
voiceStop();
while (micWaiters.length) grantMic();
await flush();
console.log(JSON.stringify({ before, afterRec, snap, value: field().value, posts: posts.length }));
`)
	before, _ := got["before"].(map[string]any)
	afterRec, _ := got["afterRec"].(map[string]any)
	if before == nil || afterRec["value"] != before["value"] || afterRec["pressed"] != before["pressed"] || afterRec["status"] != before["status"] {
		t.Fatalf("stale rec %#v", got)
	}
	if got["value"] != got["snap"] || strings.Contains(got["value"].(string), "dictated") {
		t.Fatalf("stale fetch %#v", got)
	}
}

func TestVoiceModeStopsOnError(t *testing.T) {
	got := runVoice(t, `
sttCode = 403;
loadPage();
await flush();
await flush();
voiceBtn().click();
await flush();
await flush();
if (!micWaiters.length) throw new Error("expected mic");
grantMic();
await flush();
await flush();
const proc = processors[processors.length - 1];
if (!proc) throw new Error("no processor");
const beforeMic = micCalls;
performance.at = 1000;
proc.onaudioprocess(loud());
performance.at = 2000;
proc.onaudioprocess({ inputBuffer: { getChannelData() { return [0, 0, 0, 0]; } } });
await flush();
await flush();
console.log(JSON.stringify({
  posts: posts.length,
  mode: voiceModeOn(),
  msg: msg().textContent,
  hidden: msg().hidden,
  pressed: voiceBtn().attrs["aria-pressed"] || "false",
  beforeMic: beforeMic,
  mic: micCalls
}));
`)
	if num(t, got, "posts") != 1 || got["mode"] != false || got["pressed"] != "false" {
		t.Fatalf("%#v", got)
	}
	if got["msg"] != "Speech recognition is turned off on this computer." || got["hidden"] != false {
		t.Fatalf("error text %#v", got)
	}
	if num(t, got, "mic") != num(t, got, "beforeMic") {
		t.Fatalf("mic reopened %#v", got)
	}
}

func TestVoiceDictationKeepsTypedText(t *testing.T) {
	got := runVoice(t, `
SpeechRecognition.mode = "available";
loadPage();
await flush();
field().value = "Hello";
field().selectionStart = 5;
field().selectionEnd = 5;
micBtn().click();
await flush();
await flush();
const rec = SpeechRecognition.live[SpeechRecognition.live.length - 1];
if (!rec || !rec.onresult) throw new Error("no rec");
rec.onresult({ resultIndex: 0, results: [{ 0: { transcript: "there" }, isFinal: false, length: 1 }] });
field().value = field().value + " EXTRA";
rec.onresult({ resultIndex: 0, results: [{ 0: { transcript: "there now" }, isFinal: true, length: 1 }] });
console.log(JSON.stringify({ value: field().value }));
`)
	if got["value"] != "Hello there now EXTRA" {
		t.Fatalf("value %q", got["value"])
	}
}

func TestVoiceKeepsNoVoiceError(t *testing.T) {
	got := runVoice(t, `
loadPage();
await flush();
voiceBtn().click();
await flush();
await flush();
if (!micWaiters.length) throw new Error("expected mic");
grantMic();
await flush();
await flush();
const proc = processors[processors.length - 1];
if (!proc) throw new Error("no processor");
sendGate = [];
state.streaming = true;
performance.at = 1000;
proc.onaudioprocess(loud());
performance.at = 3000;
proc.onaudioprocess(loud());
await flush();
await flush();
voiceOnRunEnd("Hello from the bot", false);
await flush();
await flush();
console.log(JSON.stringify({ msg: msg().textContent, hidden: msg().hidden, mode: voiceModeOn() }));
voiceStop();
while (micWaiters.length) grantMic();
while (statusWaiters.length) releaseStatus();
if (sendGate && sendGate.length) sendGate.splice(0).forEach((fn) => fn(true));
await flush();
`)
	if got["msg"] != "No on-device voice is available, so this reply stays on screen." || got["hidden"] != false {
		t.Fatalf("%#v", got)
	}
}

func TestVoiceStatusOnce(t *testing.T) {
	got := runVoice(t, `
statusEnabled = false;
statusAvailable = false;
loadPage();
await flush();
await flush();
voiceStop();
await flush();
console.log(JSON.stringify({
  fetches: statusCalls,
  mic: micBtn().attrs["aria-disabled"] || "",
  voice: voiceBtn().attrs["aria-disabled"] || "",
  title: micBtn().title
}));
`)
	if num(t, got, "fetches") != 1 || got["mic"] != "true" || got["voice"] != "true" {
		t.Fatalf("%#v", got)
	}
	if got["title"] != "Speech recognition is turned off on this computer." {
		t.Fatalf("title %#v", got)
	}
}

func TestVoiceNoSpeechAnnounces(t *testing.T) {
	got := runVoice(t, `
loadPage();
await flush();
micBtn().click();
await flush();
await flush();
if (!micWaiters.length) throw new Error("expected mic");
grantMic();
await flush();
await flush();
micBtn().click();
await flush();
await flush();
console.log(JSON.stringify({
  status: statusEl().textContent,
  pressed: micBtn().attrs["aria-pressed"] || "false",
  posts: posts.length
}));
`)
	if got["status"] != "Dictation stopped" || got["pressed"] != "false" || num(t, got, "posts") != 0 {
		t.Fatalf("%#v", got)
	}
}
