// Idle job cards stay on the open bot page. Run from the worktree:
// node web/testdata/job_cards_test.mjs
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const here = path.dirname(fileURLToPath(import.meta.url));
const src = fs.readFileSync(path.join(here, "..", "app.js"), "utf8");

function extractFunction(name) {
  const re = new RegExp("(?:async\\s+)?function\\s+" + name + "\\s*\\(");
  const m = re.exec(src);
  if (!m) throw new Error("missing " + name);
  let i = src.indexOf("{", m.index);
  let depth = 0;
  let quote = "";
  let escape = false;
  for (let j = i; j < src.length; j++) {
    const c = src[j];
    if (quote) {
      if (escape) { escape = false; continue; }
      if (c === "\\") { escape = true; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "/" && src[j + 1] === "/") {
      const nl = src.indexOf("\n", j);
      j = nl < 0 ? src.length : nl;
      continue;
    }
    if (c === "/" && src[j + 1] === "*") {
      const end = src.indexOf("*/", j + 2);
      if (end < 0) break;
      j = end + 1;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") { quote = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return src.slice(m.index, j + 1);
    }
  }
  throw new Error("unclosed " + name);
}

const names = [
  "el", "permissionArgsText", "mmss", "addKV", "markTallCard", "fillCardBody",
  "jobPermissionRec", "clearPermissionCards", "showPermissionRequest",
  "loadPendingPermissions", "wantsPermissionPoll", "stopStream", "loadBots",
];
const factory = new Function(names.map(extractFunction).join("\n") + `
  globalThis.el = el;
  globalThis.jobPermissionRec = jobPermissionRec;
  globalThis.clearPermissionCards = clearPermissionCards;
  globalThis.showPermissionRequest = showPermissionRequest;
  globalThis.loadPendingPermissions = loadPendingPermissions;
  globalThis.wantsPermissionPoll = wantsPermissionPoll;
  globalThis.stopStream = stopStream;
  globalThis.loadBots = loadBots;
`);

function createElement(tag) {
  const n = {
    tagName: String(tag || ""),
    className: "",
    textContent: "",
    id: "",
    type: "",
    dataset: {},
    style: {},
    children: [],
    parentNode: null,
    classList: { add() {}, remove() {} },
    append(...xs) {
      for (const x of xs) {
        if (!x) continue;
        x.parentNode = n;
        n.children.push(x);
      }
    },
    replaceChildren() {
      for (const c of n.children) c.parentNode = null;
      n.children = [];
    },
    remove() {
      const p = n.parentNode;
      if (p && p.children) p.children = p.children.filter(c => c !== n);
      n.parentNode = null;
    },
    setAttribute() {},
    addEventListener() {},
    querySelector() { return null; },
    querySelectorAll() { return []; },
    focus() {},
    scrollIntoView() {},
  };
  return n;
}

const live = createElement("div");
const permCards = new Map();
const state = {
  streaming: "",
  botId: "bot1",
  bots: [],
  botsLoaded: false,
  stop: null,
  streamCtl: null,
  approvalWait: false,
  workingHold: "",
};
let pending = [];
const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();

function bot(extra) {
  return Object.assign({
    id: "bot1", name: "Ada", pending_permissions: 0, status: "idle",
    last_run_status: "done", archived: false,
  }, extra);
}

function reset() {
  for (const rec of permCards.values()) {
    clearInterval(rec.timer);
    clearTimeout(rec.expire);
  }
  permCards.clear();
  live.replaceChildren();
  state.streaming = "";
  state.botId = "bot1";
  state.bots = [bot()];
  state.stop = null;
  state.streamCtl = null;
  pending = [];
}

function countCards() {
  return live.children.filter(n => String(n.className).indexOf("perm-card") >= 0).length;
}

function jobCard(id, runId, persistent) {
  const card = { id: id, run_id: runId, tool: "Bash", arguments: { command: "true" }, deadline: future };
  if (persistent) card.persistent = true;
  return card;
}

globalThis.document = {
  createElement,
  getElementById() { return null; },
  activeElement: null,
};
globalThis.permCards = permCards;
globalThis.state = state;
globalThis.live = live;
globalThis.$ = (sel) => sel === "#live" ? live : null;
globalThis.api = async (url) => {
  const u = String(url);
  if (u === "/api/bots") return state.bots;
  if (u.indexOf("/permissions") >= 0) return { pending: pending.slice() };
  return {};
};
globalThis.currentBot = () => state.bots.find(b => b.id === state.botId) || null;
globalThis.renderBots = () => {};
globalThis.paintHeader = () => {};
globalThis.follow = () => {};
globalThis.setWorking = () => {};
factory();

function fail(msg) {
  console.error(msg);
  process.exitCode = 1;
  throw new Error(msg);
}

async function flush() {
  await new Promise(resolve => setTimeout(resolve, 0));
}

reset();
state.bots[0].pending_permissions = 1;
pending = [jobCard("job-a", "job:job1", true)];
await loadBots();
if (countCards() !== 1) fail("A idle-open+poll shown " + countCards());
const recA = permCards.get("job-a");
if (!recA || recA.persistent !== true || recA.runId !== "job:job1") fail("A did not record the job card");

reset();
pending = [jobCard("job-b", "job:job2", false)];
await loadPendingPermissions("");
if (countCards() !== 1 || !permCards.has("job-b")) fail("B openBot shown " + countCards());
if (permCards.get("job-b").runId !== "job:job2") fail("B run id");

state.streaming = "run-2";
state.bots[0].pending_permissions = 1;
pending = [jobCard("job-b", "job:job2", false), jobCard("run-c", "run-2", false)];
await loadBots();
if (!permCards.has("job-b") || countCards() < 1) fail("C during next run lost the job card");
if (!permCards.has("run-c")) fail("C did not show the run card");

state.bots[0].pending_permissions = 0;
pending = [jobCard("job-b", "job:job2", false)];
stopStream();
if (!permCards.has("job-b") || permCards.has("run-c") || countCards() !== 1) {
  fail("D after run end shown " + countCards() + " job " + permCards.has("job-b"));
}
if (permCards.get("job-b").card.parentNode !== live) fail("D job card was detached");
await flush();

reset();
pending = [jobCard("pers", "run-9", true)];
await loadPendingPermissions("");
stopStream();
if (!permCards.has("pers") || permCards.get("pers").persistent !== true || countCards() !== 1) {
  fail("persistent run card was cleared");
}
await flush();

reset();
state.streaming = "run-1";
pending = [jobCard("ord", "run-1", false)];
await loadPendingPermissions("run-1");
if (!permCards.has("ord")) fail("ordinary card was not shown");
state.bots[0].pending_permissions = 0;
pending = [];
stopStream();
if (permCards.has("ord") || countCards() !== 0) fail("ordinary card stayed");
await flush();

reset();
pending = [jobCard("job-p", "job:job3", false)];
await loadPendingPermissions("");
if (!wantsPermissionPoll(state.bots[0], "")) fail("idle poll stopped while a job card is open");
if (wantsPermissionPoll(state.bots[0], "run-1")) fail("streaming poll ignored the roster count");

for (const rec of permCards.values()) {
  clearInterval(rec.timer);
  clearTimeout(rec.expire);
}
if (process.exitCode) process.exit(process.exitCode);
console.log("ok");
