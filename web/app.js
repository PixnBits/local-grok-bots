
const KINDS = ["user_message","bot_message","dm_sent","dm_received","tool_start","tool_end","bot_created","bot_updated","bot_deleted","timer_fired","timer_missed","model_call","run_input","run_started","run_finished","run_timed_out","daemon_start","daemon_stop","grant_use","grant_denied","net_request","sandbox_block"];
const SHAPES = ["circle","square","diamond","triangle","hex"];
const COLORS = ["#4C77DD","#218C57","#A8700E","#D44E4A","#8B60ED","#10898E","#C65C2F","#787B8A"];
const COLOR_NAMES = {"#4C77DD": "Blue", "#218C57": "Green", "#A8700E": "Gold", "#D44E4A": "Red", "#8B60ED": "Violet", "#10898E": "Teal", "#C65C2F": "Rust", "#787B8A": "Slate"};
const SHAPE_NAMES = {circle: "Circle", square: "Square", diamond: "Diamond", triangle: "Triangle", hex: "Hexagon"};
const state = {
  view: "bots",
  botId: null,
  bots: [],
  messages: [],
  tools: {},
  hasMore: false,
  pinned: true,
  loadingOlder: false,
  token: sessionStorage.getItem("lgb_token") || "",
  streamCtl: null,
  streaming: "",
  showHidden: false,
  showArchived: false,
  mark: {shape: "circle", color: COLORS[0]},
  draft: false,
  profilePane: "main",
  profileBase: null,
  profileLoad: 0,
  chipLists: {net: [], ssh: [], github: []},
  saveError: "",
  saveErrorChip: false,
  expectPop: false,
  routineEdit: "",
  pendingLeave: null,
  saving: false,
  desktopLog: false,
  conn: "loading",
  botsLoaded: false,
  everFailed: false,
  backoff: 1000,
  version: "",
  toastTimer: 0,
  queuedIds: [],
  queuedDuringRun: "",
  userStops: {},
  cardRecords: [],
  localPartials: [],
  stop: null,
  liveTool: "",
  stopNote: "",
  stopTimer: 0,
  dismissedRunError: ""
};
const $ = (s, r=document) => r.querySelector(s);
function syncThemeControl(mode) {
  const m = mode === "light" || mode === "dark" ? mode : "system";
  document.querySelectorAll("#theme-seg [role='radio']").forEach((btn) => {
    const on = btn.getAttribute("data-theme") === m;
    btn.setAttribute("aria-checked", on ? "true" : "false");
    btn.tabIndex = on ? 0 : -1;
  });
}
window.syncThemeControl = syncThemeControl;
function setThemeMode(mode) {
  if (mode !== "light" && mode !== "dark") mode = "system";
  try { localStorage.setItem("lgb.theme", mode); } catch (e) {}
  applyStoredTheme();
  syncThemeControl(mode);
}
syncThemeControl(applyStoredTheme());
$("#theme-seg").addEventListener("click", (e) => {
  const btn = e.target.closest("[role='radio']");
  if (!btn) return;
  setThemeMode(btn.getAttribute("data-theme"));
});
function base() {
  const m = location.pathname.match(/^(\/hds-[a-z0-9]+-\d+-[a-z0-9]+)/i);
  return m ? m[1] : "";
}
function showAuth() { $("#auth").classList.add("on"); }
async function api(path, opts={}) {
  const headers = Object.assign({}, opts.headers || {});
  const method = String(opts.method || "GET").toUpperCase();
  const mutating = method === "POST" || method === "PUT" || method === "PATCH" || method === "DELETE";
  let body = opts.body;
  if (mutating) {
    if (!headers["Content-Type"]) headers["Content-Type"] = "application/json";
    if (body == null || body === "") body = "{}";
  }
  if (state.token) headers.Authorization = "Bearer " + state.token;
  const res = await fetch(base() + path, Object.assign({}, opts, {headers, body}));
  if (res.status === 401) { showAuth(); throw new Error("unauthorized"); }
  if (res.status === 204) return null;
  const text = await res.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch { data = {error: text}; } }
  if (!res.ok) throw new Error((data && data.error) || res.statusText);
  return data;
}
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
// mark:begin
function paintMark(n, mark) {
  if (!n) return n;
  const m = mark || {};
  n.dataset.shape = m.shape || "circle";
  const c = m.color;
  if (typeof c === "string" && /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(c)) n.style.setProperty("--c", c);
  else n.style.removeProperty("--c");
  return n;
}
// mark:end
function markEl(mark) {
  return paintMark(el("span", "mark"), mark);
}
function isWide() { return window.matchMedia("(min-width: 980px)").matches; }
// drill:begin
function shouldFocusDrill(prev, next, wide) {
  return !wide && prev !== next;
}
function drillFocusTarget(name, wide) {
  if (wide) return null;
  if (name === "bots") return { sel: "#view-bots h1", tabindex: -1 };
  if (name === "chat") return { sel: "#thread-name", tabindex: -1 };
  if (name === "profile") return { sel: "#profile-heading", tabindex: -1 };
  if (name === "log") return { sel: "#view-log h2.solo-title", tabindex: -1 };
  if (name === "rules") return { sel: "#rules-title", tabindex: -1 };
  return null;
}
function applyDrillFocus(el, tabindex) {
  if (!el || typeof el.focus !== "function") return false;
  if (tabindex != null) el.tabIndex = tabindex;
  try { el.focus({ preventScroll: true, focusVisible: false }); }
  catch (e) { el.focus({ preventScroll: true }); }
  return true;
}
function focusDrillView(name, wide, query) {
  const spec = drillFocusTarget(name, wide);
  if (!spec) return false;
  const el = typeof query === "function" ? query(spec.sel) : null;
  return applyDrillFocus(el, spec.tabindex);
}
// drill:end
// pane-focus:begin
function desktopPaneFocusTarget(name, wide) {
  if (!wide) return null;
  if (name === "chat") return { sel: "#thread-name", tabindex: -1 };
  if (name === "profile") return { sel: "#profile-heading", tabindex: -1 };
  if (name === "log") return { sel: "#view-log h2.solo-title", tabindex: -1 };
  if (name === "rules") return { sel: "#rules-title", tabindex: -1 };
  return null;
}
// pane-focus:end
function focusPane(name) {
  const spec = desktopPaneFocusTarget(name, isWide());
  if (!spec) return false;
  return applyDrillFocus($(spec.sel), spec.tabindex);
}
function setView(name) {
  const prev = state.view;
  const enter = prev !== name;
  state.view = name;
  if (name !== "profile") {
    state.draft = false;
    state.profileBase = null;
  }
  const wide = isWide();
  const solo = name === "profile" || name === "log" || name === "rules";
  document.body.classList.toggle("solo", solo);
  state.desktopLog = name === "log";
  for (const v of ["bots","chat","profile","log","rules"]) {
    const node = $("#view-" + v);
    if (!node) continue;
    let on = v === name;
    if (wide && !solo && (v === "bots" || v === "chat")) on = true;
    node.classList.toggle("on", on);
  }
  if (name === "log" && enter) loadLog();
  if (shouldFocusDrill(prev, name, wide)) focusDrillView(name, wide, (sel) => $(sel));
  if (name === "profile") bindProfileSpy();
}
$("#log-toggle").addEventListener("click", () => {
  if (state.view === "log") navBack();
  else openLog(true);
});
$("#profile-log").addEventListener("click", () => openLog(true));
$("#solo-back").addEventListener("click", navBack);
$("#log-back").addEventListener("click", navBack);
$("#thread-back").addEventListener("click", navBack);
$("#profile-menu").addEventListener("click", (e) => {
  e.stopPropagation();
  toggleBotMenu($("#profile-menu"));
});
const wideMq = window.matchMedia("(min-width: 980px)");
const onWideChange = () => setView(state.view);
if (wideMq.addEventListener) wideMq.addEventListener("change", onWideChange);
else wideMq.addListener(onWideChange);
function statusNode(status) {
  const kind = status === "needs approval" ? "needs" : (status || "idle");
  const s = el("span", "status " + kind);
  s.append(el("i", "dot"), document.createTextNode(status || "idle"));
  return s;
}
function eyeOffIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "14");
  svg.setAttribute("height", "14");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  svg.classList.add("eye-off");
  const add = (d) => {
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", d);
    p.setAttribute("fill", "none");
    p.setAttribute("stroke", "currentColor");
    p.setAttribute("stroke-width", "2");
    p.setAttribute("stroke-linecap", "round");
    p.setAttribute("stroke-linejoin", "round");
    svg.append(p);
  };
  add("M3 3l18 18");
  add("M10.6 6.1A9.7 9.7 0 0 1 12 6c5 0 8.5 4.5 9.5 6a17 17 0 0 1-3 3.5M6.5 7.6A16 16 0 0 0 2.5 12c1 1.5 4.5 6 9.5 6a9 9 0 0 0 4-.9");
  add("M9.9 10a3 3 0 0 0 4.1 4.1");
  return svg;
}
function currentBot() { return state.bots.find(b => b.id === state.botId) || null; }
function syncVoiceSlot(hasText) {
  const had = document.activeElement;
  const listening = typeof window.voiceListening === "function" && window.voiceListening();
  const mode = typeof window.voiceModeOn === "function" && window.voiceModeOn();
  const mic = document.getElementById("mic-btn");
  const voice = document.getElementById("voice-btn");
  const cfg = document.getElementById("voice-cfg");
  if (cfg) cfg.hidden = hasText && !mode;
  if (mic) mic.hidden = mode || (hasText && !listening);
  if (voice) voice.hidden = hasText && !mode;
  if (had && (had === mic || had === voice || had === cfg) && had.hidden) {
    const send = document.getElementById("send-btn");
    if (send && !send.hidden) send.focus(); else $("#composer-input").focus();
  }
}
function syncSendEmpty() {
  const input = $("#composer-input");
  const send = $("#send-btn");
  if (!send || !input) return;
  const text = String(input.value || "").trim() !== "";
  send.classList.toggle("is-empty", !text);
  send.hidden = !text;
  syncVoiceSlot(text);
}
function syncComposer() {
  const on = !!(state.botId && currentBot());
  const form = $("#composer");
  const menuBtn = $("#menu-btn");
  if (form) form.hidden = !on;
  if (menuBtn) menuBtn.hidden = !on;
  const hint = $("#composer-hint");
  const running = !!(state.stop && (state.stop.phase === "running" || state.stop.phase === "stopping"));
  if (hint) {
    hint.hidden = !on;
    hint.textContent = (typeof composerHint === "function") ? composerHint(running) : "";
  }
  const input = $("#composer-input");
  if (input) {
    const b = currentBot();
    const narrow = window.matchMedia && window.matchMedia("(max-width: 540px)").matches;
    input.placeholder = (typeof composerPlaceholder === "function") ? composerPlaceholder(b && b.name, !!narrow) : "Message";
  }
  syncSendEmpty();
  if (typeof syncStopButton === "function") syncStopButton();
}
// roster-logic:begin
function rosterListMode(loaded, everFailed, conn) {
  if (!loaded && !everFailed) return "loading";
  if (conn === "down" || (conn === "retrying" && everFailed)) return "error";
  return "ready";
}
function approvalWords(n) {
  return n === 1 ? "1 approval waiting" : n + " approvals waiting";
}
// roster-logic:end
// roster-sig:begin
function rowStatus(b) {
  if (b && !b.archived && b.pending_permissions > 0) return "needs approval";
  return (b && b.status) || "idle";
}
function displayStatus(b, stale) {
  if (stale) return "unknown";
  return rowStatus(b);
}
function rosterSignature(inputs) {
  const src = inputs || {};
  const bots = Array.isArray(src.bots) ? src.bots : [];
  const botsLoaded = !!src.botsLoaded;
  const everFailed = !!src.everFailed;
  const conn = src.conn == null ? "" : String(src.conn);
  const mode = src.mode != null && src.mode !== "" ? String(src.mode) : rosterListMode(botsLoaded, everFailed, conn);
  // The displayed word is part of the signature, so entering and leaving
  // the stale list rebuilds rows and real statuses come back on recovery.
  const stale = src.stale != null ? !!src.stale : mode === "error" && botsLoaded;
  const lines = [];
  for (let i = 0; i < bots.length; i++) {
    const b = bots[i] || {};
    const mark = b.mark && typeof b.mark === "object" ? b.mark : {};
    const pending = Number(b.pending_permissions);
    lines.push([
      b.id == null ? "" : String(b.id),
      b.name == null ? "" : String(b.name),
      b.label == null ? "" : String(b.label),
      mark.shape || "",
      mark.color || "",
      displayStatus(b, stale),
      b.hidden ? 1 : 0,
      b.pinned ? 1 : 0,
      b.archived ? 1 : 0,
      pending > 0 ? pending : 0
    ]);
  }
  return JSON.stringify([
    mode,
    stale ? 1 : 0,
    botsLoaded ? 1 : 0,
    everFailed ? 1 : 0,
    src.showHidden ? 1 : 0,
    src.showArchived ? 1 : 0,
    src.botId == null ? "" : String(src.botId),
    lines
  ]);
}
function rosterFocusKey(kind, botId) {
  if (kind === "back") return "back";
  if (kind === "retry") return "retry";
  if (kind !== "bot" && kind !== "unarchive") return "";
  if (botId == null || botId === "") return "";
  return kind + ":" + botId;
}
function rosterFocusMatch(key, kind, botId) {
  const want = rosterFocusKey(kind, botId);
  return !!key && !!want && key === want;
}
// roster-sig:end
let rosterSig = null;
function rosterFocusKeyFromEl(el) {
  if (!el || !el.classList) return "";
  if (el.id === "retry-now" || el.classList.contains("retry-now")) return rosterFocusKey("retry", "");
  if (el.classList.contains("roster-back")) return rosterFocusKey("back", "");
  if (el.classList.contains("unarchive")) return rosterFocusKey("unarchive", el.getAttribute("data-bot-id") || "");
  if (el.classList.contains("bot")) return rosterFocusKey("bot", el.getAttribute("data-bot-id") || "");
  return "";
}
function restoreRosterFocus(list, key) {
  if (!list || !key || !list.querySelectorAll) return;
  const buttons = list.querySelectorAll("button");
  for (const el of buttons) {
    let kind = "";
    if (el.id === "retry-now" || el.classList.contains("retry-now")) kind = "retry";
    else if (el.classList.contains("roster-back")) kind = "back";
    else if (el.classList.contains("unarchive")) kind = "unarchive";
    else if (el.classList.contains("bot")) kind = "bot";
    else continue;
    const botId = kind === "retry" ? "" : (el.getAttribute("data-bot-id") || "");
    if (!rosterFocusMatch(key, kind, botId)) continue;
    if (typeof el.focus === "function") el.focus({ preventScroll: true });
    return;
  }
  if (key === rosterFocusKey("retry", "")) {
    const h = document.querySelector("#view-bots h1");
    if (h && h.offsetParent !== null) {
      if (!h.hasAttribute("tabindex")) h.setAttribute("tabindex", "-1");
      h.focus({ preventScroll: true });
    }
  }
}
function syncRosterMenus(live, archived) {
  const hiddenCount = live.filter(b => b.hidden).length;
  const showHiddenBtn = $("#menu-show-hidden");
  if (showHiddenBtn) {
    showHiddenBtn.setAttribute("aria-checked", state.showHidden ? "true" : "false");
    const count = $("#hidden-count");
    if (count) count.textContent = hiddenCount ? String(hiddenCount) : "";
  }
  const archBtn = $("#menu-archived");
  if (archBtn) {
    const label = archivedMenuLabel(state.botsLoaded ? archived.length : null);
    archBtn.hidden = !label;
    archBtn.textContent = label;
  }
}
function syncLogBots() {
  const sel = $("#log-bot");
  if (!sel) return;
  const cur = sel.value;
  sel.replaceChildren(new Option("All bots", ""));
  for (const b of state.bots) sel.append(new Option(b.name, b.id));
  if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
}
function syncRosterBusy(list, mode) {
  const stale = !!(list && mode === "error" && state.botsLoaded);
  if (!list || !list.classList) return;
  list.classList.toggle("is-stale", stale);
  if (stale) list.setAttribute("aria-busy", "true");
  else list.removeAttribute("aria-busy");
}
function renderBots() {
  const list = $("#bot-list");
  // The archived view lists only archived bots; the normal roster never does.
  const live = state.bots.filter(b => !b.archived);
  const archived = state.bots.filter(b => b.archived);
  syncRosterMenus(live, archived);
  const mode = rosterListMode(state.botsLoaded, state.everFailed, state.conn);
  const stale = mode === "error" && !!state.botsLoaded;
  syncRosterBusy(list, mode);
  const sig = rosterSignature({
    bots: state.bots,
    botsLoaded: state.botsLoaded,
    everFailed: state.everFailed,
    conn: state.conn,
    showHidden: state.showHidden,
    showArchived: state.showArchived,
    botId: state.botId,
    mode: mode,
    stale: stale
  });
  // Polls call this every few seconds. Skip the rebuild when the rows would
  // look the same, so a focused row keeps receiving arrow keys.
  if (sig === rosterSig) {
    syncLogBots();
    syncComposer();
    if (typeof syncRetryButton === "function") syncRetryButton();
    if (typeof syncBrokerBadges === "function") syncBrokerBadges();
    return;
  }
  let focusKey = "";
  const active = document.activeElement;
  // A hidden phone pane (chat/log covers the roster) must not steal focus back.
  const listShown = list && list.getClientRects && list.getClientRects().length > 0;
  if (active && listShown && list.contains(active)) focusKey = rosterFocusKeyFromEl(active);
  list.replaceChildren();
  const commit = () => {
    if (focusKey) restoreRosterFocus(list, focusKey);
    rosterSig = sig;
    syncLogBots();
    syncComposer();
  };
  if (mode === "loading") {
    for (let i = 0; i < 3; i++) {
      const row = el("div", "skel-row");
      row.setAttribute("aria-hidden", "true");
      const lines = el("span", "skel-lines");
      lines.append(el("span", "skel-line"), el("span", "skel-line short"));
      row.append(el("span", "skel-mark"), lines);
      list.append(row);
    }
    commit();
    return;
  }
  if (mode === "error") {
    const note = el("p", "roster-error", ROSTER_ERROR_NOTE);
    const retry = el("button", "secondary small retry-now", "Retry now");
    retry.type = "button";
    retry.id = "retry-now";
    retry.addEventListener("click", () => {
      if (retry.getAttribute("aria-disabled") === "true") return;
      if (typeof retryDaemonNow === "function") retryDaemonNow();
    });
    note.append(retry);
    list.append(note);
    if (typeof syncRetryButton === "function") syncRetryButton();
  }
  if (mode === "error" && !state.botsLoaded) {
    commit();
    return;
  }
  if (state.showArchived) {
    const back = el("button", "roster-back", "‹ Archived");
    back.type = "button";
    back.addEventListener("click", () => { state.showArchived = false; renderBots(); });
    list.append(back);
  }
  const shown = state.showArchived ? archived : live.filter(b => state.showHidden || !b.hidden);
  if (!shown.length && mode !== "error") {
    if (state.showArchived) list.append(el("p", "empty", "No archived bots."));
    else if (live.length) list.append(el("p", "empty", "Every bot is hidden."));
    else {
      const empty = el("div", "empty-state");
      empty.append(el("p", "empty", "No bots yet."));
      const nb = el("button", "primary", "New bot");
      nb.type = "button";
      nb.addEventListener("click", () => openDraft(true));
      empty.append(nb);
      list.append(empty);
    }
  }
  const appendRow = (b) => {
    const btn = el("button", "bot" + (b.hidden ? " dim" : "") + (b.id === state.botId ? " is-selected" : ""));
    btn.type = "button";
    btn.setAttribute("data-bot-id", b.id);
    if (b.id === state.botId) btn.setAttribute("aria-current", "page");
    const copy = el("span", "bot-copy");
    const line1 = el("span", "bot-line");
    line1.append(el("span", "bot-name", b.name || ""));
    if (b.hidden) line1.append(eyeOffIcon());
    line1.append(statusNode(displayStatus(b, stale)));
    const line2 = el("span", "bot-line");
    line2.append(el("span", "bot-label", b.label || ""));
    // Waiting beats running. The count pill is the visible badge; bot-attn
    // keeps the accessible name the roster tests pin.
    if (typeof appendPendingBadge === "function") appendPendingBadge(copy, line2, btn, b);
    else if (b.pending_permissions > 0 && !b.archived) {
      const n = b.pending_permissions;
      const words = approvalWords(n);
      copy.append(el("small", "bot-attn", words));
      const badge = el("span", "perm-badge", String(n));
      badge.setAttribute("aria-label", words);
      line2.append(badge);
      btn.title = "Waiting for your approval";
    }
    copy.append(line1, line2);
    btn.append(markEl(b.mark), copy);
    btn.addEventListener("click", () => openBot(b.id));
    if (state.showArchived) {
      const row = el("div", "bot-row");
      const un = el("button", "ghost unarchive", "Unarchive");
      un.type = "button";
      un.setAttribute("data-bot-id", b.id);
      un.addEventListener("click", (e) => { e.stopPropagation(); setArchived(b.id, false); });
      row.append(btn, un);
      list.append(row);
    } else {
      list.append(btn);
    }
  };
  if (!state.showArchived) {
    const pinned = shown.filter(b => b.pinned);
    const rest = shown.filter(b => !b.pinned);
    if (pinned.length) {
      list.append(el("div", "roster-group", "Pinned"));
      pinned.forEach(appendRow);
      if (rest.length) list.append(el("div", "roster-group", "All bots"));
      rest.forEach(appendRow);
    } else {
      shown.forEach(appendRow);
    }
  } else {
    shown.forEach(appendRow);
  }
  commit();
}
async function loadBots() {
  const fresh = await api("/api/bots");
  if (state.streaming && state.botId) {
    const cur = fresh.find(x => x.id === state.botId);
    if (cur && cur.status !== "running") cur.status = "running";
  }
  if (state.stop && state.stop.phase === "stopped" && state.botId) {
    const cur = fresh.find(x => x.id === state.botId);
    if (cur && !cur.active_run_id && cur.status === "running") cur.status = "idle";
  }
  state.bots = fresh;
  state.botsLoaded = true;
  renderBots();
  const b = currentBot();
  if (b) {
    if (b.last_run_status === "waiting") state.approvalWait = true;
    else if (typeof pendingApproval !== "function" || !pendingApproval()) state.approvalWait = false;
    paintHeader(b);
    // A message sent mid-run can start a follow-up run after the stream
    // ended; pick it up so its reply streams in.
    if (b.active_run_id && b.active_run_id !== state.streaming) follow(b.active_run_id);
    else if (b.pending_permissions > 0 && state.streaming) loadPendingPermissions(state.streaming).catch(() => {});
    if (b.last_run_status === "waiting") {
      state.approvalWait = true;
      if (b.waiting_tool) state.liveTool = b.waiting_tool;
      setWorking(true);
    }
  }
}
function setMenuText(id, text) {
  const n = $("#" + id);
  if (n) n.textContent = text;
}
function paintNote(kind, text, actions) {
  const note = $("#run-note");
  if (!note) return;
  note.hidden = false;
  note.className = "note" + (kind ? " " + kind : "");
  note.replaceChildren();
  if (text) note.append(el("span", "note-text", text));
  for (const a of actions || []) note.append(a);
}
function paintFailedNote(text) {
  if (state.dismissedRunError && state.dismissedRunError === text) {
    const note = $("#run-note");
    if (note) note.hidden = true;
    return;
  }
  const open = el("button", "small", "Open in Log");
  open.type = "button";
  open.addEventListener("click", () => openLog(true));
  const dismiss = el("button", "small", "×");
  dismiss.type = "button";
  dismiss.setAttribute("aria-label", "Dismiss");
  dismiss.addEventListener("click", () => {
    state.dismissedRunError = text;
    const note = $("#run-note");
    if (note) note.hidden = true;
  });
  paintNote("", text, [open, dismiss]);
}
function paintStopFailedNote() {
  const again = el("button", "secondary small", "Try again");
  again.type = "button";
  again.addEventListener("click", () => { if (typeof requestStop === "function") requestStop(); });
  paintNote("", (typeof STOP_FAILED_NOTE === "string") ? STOP_FAILED_NOTE : "Couldn't stop the run. The daemon didn't respond.", [again]);
}
function paintHeader(b) {
  syncComposer();
  $("#thread-name").textContent = b.name;
  paintMark($("#thread-mark"), b.mark);
  $("#thread-mark").hidden = false;
  setTitle();
  if (typeof paintSubline === "function") paintSubline(b);
  else $("#thread-label").textContent = b.label || "";
  setMenuText("menu-pin-label", b.pinned ? "Unpin" : "Pin");
  setMenuText("menu-hide-label", b.hidden ? "Unhide" : "Hide");
  setMenuText("menu-archive-label", b.archived ? "Unarchive" : "Archive");
  setMenuText("menu-log-label", "Log for " + (b.name || "bot"));
  const note = $("#run-note");
  const running = !!(state.streaming || b.status === "running" || (state.stop && (state.stop.phase === "running" || state.stop.phase === "stopping")));
  if (state.stopNote === "failed" && running) {
    paintStopFailedNote();
    return;
  }
  if (b.archived) {
    const btn = el("button", "secondary small", "Unarchive");
    btn.type = "button";
    btn.addEventListener("click", () => setArchived(b.id, false));
    paintNote("quiet", "Archived. Routines are paused and new messages wait until it is restored.", [btn]);
    return;
  }
  const timeoutOffer = (typeof timeoutNoteActions === "function") ? timeoutNoteActions(b, !!state.streaming) : null;
  if (timeoutOffer) {
    const runId = (typeof timeoutRunId === "function") ? timeoutRunId(b, state.messages, state.timeoutRunId) : (b.continue_run_id || "");
    // With a partial, Continue is primary. With none, Retry alone is primary.
    const retry = el("button", b.continue_run_id ? "secondary small" : "primary small", "Retry");
    retry.type = "button";
    const actions = [retry];
    let cont = null;
    if (b.continue_run_id) {
      cont = el("button", "primary small", "Continue");
      cont.type = "button";
      actions.push(cont);
    }
    const disableBoth = () => {
      retry.disabled = true;
      if (cont) cont.disabled = true;
    };
    retry.addEventListener("click", () => { disableBoth(); retryTimeout(runId || timeoutRunId(b, state.messages, state.timeoutRunId)); });
    if (cont) {
      const id = b.continue_run_id;
      cont.addEventListener("click", () => { disableBoth(); continueRun(id); });
    }
    paintNote("attention", timeoutOffer.text, actions);
    return;
  }
  const offer = !state.streaming && b.status !== "running" && b.last_run_error === "tool round limit" && b.continue_run_id;
  if (offer) {
    const btn = el("button", "primary small", "Continue");
    btn.type = "button";
    const runId = b.continue_run_id;
    btn.addEventListener("click", () => continueRun(runId));
    paintNote("continue", "Stopped after 8 tool rounds. Continue picks up the same work for 8 more.", [btn]);
    return;
  }
  if (!state.streaming && b.status !== "running" && b.last_run_status === "error" && b.last_run_error) {
    paintFailedNote("Run failed: " + b.last_run_error);
  } else if (!state.streaming && state.stopNote !== "failed") {
    note.hidden = true;
    note.replaceChildren();
  }
}
function showRunError(text) {
  const t = text == null ? "" : String(text);
  if (t.indexOf("Run failed:") === 0) { paintFailedNote(t); return; }
  paintNote("", t);
}
function menuTriggers() { return document.querySelectorAll("[aria-controls='bot-menu']"); }
function closeMenu() {
  const menu = $("#bot-menu");
  if (menu) menu.hidden = true;
  for (const b of menuTriggers()) b.setAttribute("aria-expanded", "false");
}
// One menu node. The thread ⋯ and the profile ⋯ both anchor it.
function toggleBotMenu(btn) {
  closeRosterMenu();
  const menu = $("#bot-menu");
  const wrap = btn && btn.closest(".menu");
  if (wrap && menu.parentElement !== wrap) {
    wrap.append(menu);
    menu.hidden = true;
  }
  const willOpen = menu.hidden;
  menu.hidden = !willOpen;
  for (const b of menuTriggers()) b.setAttribute("aria-expanded", b === btn && willOpen ? "true" : "false");
}
// The selected bot lives in the URL as {base}/bots/{id}. Profile and log stay
// on that same path (or /) with a hash. The daemon also serves /rules (the
// client reads ?bot=). #approvals opens the queue and is not a view. Any
// other extra path segment 404s on reload.
// route:begin
function botFromPathname(pathname, root) {
  const rest = String(pathname || "").slice(String(root || "").length);
  const m = rest.match(/^\/bots\/([^/]+)\/?$/);
  return m ? decodeURIComponent(m[1]) : null;
}
function rulesBotFromSearch(search) {
  const q = String(search || "");
  const m = q.match(/[?&]bot=([^&]*)/);
  if (!m) return null;
  try {
    const v = decodeURIComponent(m[1].replace(/\+/g, " "));
    return v || null;
  } catch (e) {
    return m[1] || null;
  }
}
function levelURL(root, view, bot, search) {
  if (view === "draft") return root + "/" + (search || "") + "#new";
  if (view === "rules") {
    const q = bot ? "?bot=" + encodeURIComponent(bot) : "";
    return root + "/rules" + q;
  }
  const id = view !== "bots" && bot ? bot : null;
  const path = root + (id ? "/bots/" + encodeURIComponent(id) : "/");
  const hash = view === "profile" ? "#profile" : view === "log" ? "#log" : "";
  return path + (search || "") + hash;
}
function parseLevel(pathname, hash, root, hist, search) {
  const rest = String(pathname || "").slice(String(root || "").length);
  if (/^\/rules\/?$/.test(rest)) return { view: "rules", bot: rulesBotFromSearch(search) };
  const bot = botFromPathname(pathname, root);
  const raw = String(hash || "").replace(/^#/, "");
  const h = raw === "approvals" ? "" : raw;
  if (h === "profile" && bot) return { view: "profile", bot: bot };
  if (h === "log") return { view: "log", bot: bot };
  if (h === "new") return { view: "draft", bot: null };
  if (hist && hist.lgb === 1 && hist.view === "profile" && (hist.bot || bot)) {
    return { view: "profile", bot: hist.bot || bot };
  }
  if (hist && hist.lgb === 1 && hist.view === "log") {
    return { view: "log", bot: hist.bot || bot };
  }
  if (hist && hist.lgb === 1 && hist.view === "rules") {
    return { view: "rules", bot: hist.bot || rulesBotFromSearch(search) };
  }
  if (hist && hist.lgb === 1 && hist.view === "draft") return { view: "draft", bot: null };
  if (bot) return { view: "chat", bot: bot };
  return { view: "bots", bot: null };
}
function backAction(hist) {
  if (hist && hist.lgb === 1 && hist.idx > 0) return "back";
  return "up";
}
function parentLevel(level) {
  const bot = level && level.bot ? level.bot : null;
  if (level && level.view === "draft") return { view: "bots", bot: null };
  if (level && level.view === "profile" && bot) return { view: "chat", bot: bot };
  if (level && level.view === "log") return bot ? { view: "chat", bot: bot } : { view: "bots", bot: null };
  if (level && level.view === "rules") return bot ? { view: "chat", bot: bot } : { view: "bots", bot: null };
  return { view: "bots", bot: null };
}
function historyStamp(hist, pathname, hash, root, search) {
  if (hist && hist.lgb === 1) return null;
  const level = parseLevel(pathname, hash, root, hist, search);
  return { op: "replace", view: level.view, bot: level.bot };
}
// route:end
function botPath(id) { return base() + (id ? "/bots/" + encodeURIComponent(id) : "/"); }
function botFromPath() { return botFromPathname(location.pathname, base()); }
function commitSearch(view) {
  if (view === "rules") return "";
  let search = location.search || "";
  search = search.replace(/([?&])bot=[^&]*/g, "$1").replace(/[?&]$/, "").replace(/\?&/, "?").replace(/&&/g, "&");
  if (search === "?") search = "";
  return search;
}
function commitLevel(level, mode) {
  const view = level && level.view ? level.view : "bots";
  const bot = level && level.bot ? level.bot : null;
  let url = levelURL(base(), view, bot, commitSearch(view));
  if (url.indexOf("#") < 0 && typeof hashIsApprovals === "function" && hashIsApprovals(location.hash)) url += "#approvals";
  const prev = history.state && history.state.lgb === 1 ? history.state : null;
  const here = location.pathname + location.search + location.hash;
  if (prev && prev.view === view && (prev.bot || null) === bot && here === url) return;
  const idx = mode === "push" ? ((prev ? prev.idx : 0) + 1) : (prev ? prev.idx : 0);
  const rec = { lgb: 1, view: view, bot: bot, idx: idx };
  if (mode === "push") history.pushState(rec, "", url);
  else history.replaceState(rec, "", url);
}
function ensureHistory() {
  const stamp = historyStamp(history.state, location.pathname, location.hash, base(), location.search);
  if (!stamp) return;
  commitLevel(stamp, "replace");
}
function navBack() {
  if (state.view === "profile" && state.profilePane === "access") {
    setProfilePane("main");
    return;
  }
  if (backAction(history.state) === "back") {
    history.back();
    return;
  }
  confirmLeave(leaveProfile);
}
function knownBot(id) { return !!(id && state.bots.some(b => b.id === id)); }
function revealLevel(level) {
  if (level.view === "draft") return openDraft(false);
  if (level.view === "rules") return openRules(level.bot || "", false);
  if (level.view === "profile" && knownBot(level.bot)) return openProfile(level.bot, false);
  if (level.view === "chat" && knownBot(level.bot)) return openBot(level.bot, false);
  if (level.view === "log") {
    if (level.bot && !knownBot(level.bot)) {
      goHome(false);
      commitLevel({ view: "bots", bot: null }, "replace");
      return;
    }
    if (level.bot) state.botId = level.bot;
    return openLog(false);
  }
  if (level.bot && !knownBot(level.bot)) {
    goHome(false);
    commitLevel({ view: "bots", bot: null }, "replace");
    return;
  }
  return goHome(false);
}
function openLog(push = true) {
  if (!navBypass && profileDirty()) {
    confirmLeave(() => openLog(push));
    return;
  }
  closeState();
  closeRosterMenu();
  if (push) commitLevel({ view: "log", bot: state.botId }, "push");
  setView("log");
  setTitle();
  focusPane("log");
}
function setTitle() {
  if (state.view === "log") document.title = "Log — Local Grok Bots";
  else if (state.view === "rules") document.title = "Approval rules — Local Grok Bots";
  else if (state.draft) document.title = "New bot — Local Grok Bots";
  else {
    const b = state.botId && currentBot();
    document.title = b ? b.name + " — Local Grok Bots" : "Local Grok Bots";
  }
  document.title = criticalTitle(document.title, approvalsCriticalCount());
}
function goHome(push = true) {
  closeState();
  state.botState = null;
  state.botId = null;
  paintStateChip();
  state.loadedFor = null;
  state.hasMore = false;
  stopStream();
  if (window.voiceStop) window.voiceStop();
  if (push) commitLevel({ view: "bots", bot: null }, "push");
  $("#thread-name").textContent = "No bot selected";
  $("#thread-mark").hidden = true;
  $("#thread-label").textContent = "";
  $("#run-note").hidden = true;
  const homeDot = $("#thread-dot");
  if (homeDot) homeDot.hidden = true;
  if (typeof resetThreadRun === "function") resetThreadRun();
  state.messages = [];
  $("#msgs").replaceChildren(el("p", "empty", "Choose a bot to read its thread."), $("#live"), $("#working"));
  syncComposer();
  setView("bots");
  setTitle();
}
window.addEventListener("hashchange", () => {
  if (typeof syncApprovalsHash === "function") syncApprovalsHash();
  if (history.state && history.state.lgb === 1) return;
  ensureHistory();
  revealLevel(parseLevel(location.pathname, location.hash, base(), history.state, location.search));
});
window.addEventListener("popstate", () => {
  if (state.expectPop) {
    state.expectPop = false;
    navBypass = true;
    try {
      ensureHistory();
      revealLevel(parseLevel(location.pathname, location.hash, base(), history.state, location.search));
    } finally { navBypass = false; }
    return;
  }
  if (discardOpen()) {
    commitLevel(stayingLevel(), "push");
    return;
  }
  if (profileDirty()) {
    commitLevel(stayingLevel(), "push");
    state.pendingLeave = () => {
      state.expectPop = true;
      history.back();
    };
    openDiscardDialog();
    return;
  }
  ensureHistory();
  revealLevel(parseLevel(location.pathname, location.hash, base(), history.state, location.search));
});
async function openBot(id, push = true) {
  if (!navBypass && profileDirty()) {
    confirmLeave(() => openBot(id, push));
    return;
  }
  if (state.botId !== id) {
    if (window.voiceStop) window.voiceStop();
    stopStream();
    state.loadedFor = null;
    closeState();
    state.botState = null;
    state.timeoutRunId = "";
    paintStateChip();
    if (typeof resetThreadRun === "function") resetThreadRun();
  }
  state.botId = id;
  if (push) commitLevel({ view: "chat", bot: id }, "push");
  closeMenu();
  closeRosterMenu();
  const named = currentBot();
  if (named && named.name) $("#thread-name").textContent = named.name;
  setView("chat");
  focusPane("chat");
  setTitle();
  syncComposer();
  await refreshBot();
  focusPane("chat");
  await loadThread();
  loadState().catch(() => {});
  const b = currentBot();
  if (b && b.active_run_id) follow(b.active_run_id);
}
async function refreshBot() {
  if (!state.botId) return null;
  const b = await api("/api/bots/" + state.botId);
  if (state.streaming && b.status !== "running") b.status = "running";
  // FinishRun lands before the loop marks the bot idle. A user stop with no
  // active run should not flash the row back to running.
  if (state.stop && state.stop.phase === "stopped" && !b.active_run_id && b.status === "running") b.status = "idle";
  const i = state.bots.findIndex(x => x.id === b.id);
  if (i >= 0) state.bots[i] = b;
  else state.bots.push(b);
  if (b.last_run_status === "waiting") {
    state.approvalWait = true;
    if (b.waiting_tool) state.liveTool = b.waiting_tool;
  } else if (!pendingApproval()) {
    state.approvalWait = false;
  }
  paintHeader(b);
  renderBots();
  if (b.last_run_status === "waiting") setWorking(true);
  return b;
}
function whoText(m) {
  if (m.role === "user") return "You";
  if (m.role === "bot") {
    const b = currentBot();
    return b ? b.name : "Bot";
  }
  const note = hookNoteBody(m.content, m.kind);
  const body = note || (m.content || "");
  if (body.startsWith("Message from ") || body.startsWith("Notice: ")) return "";
  return "Scheduled";
}
// md:begin
// copyText puts text on the clipboard. navigator.clipboard needs a secure
// context, and the page is plain HTTP on the LAN, so it falls back to a
// hidden textarea and execCommand("copy").
async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try { await navigator.clipboard.writeText(text); return true; } catch {}
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.top = "-1000px";
  ta.style.opacity = "0";
  document.body.append(ta);
  ta.select();
  ta.setSelectionRange(0, text.length);
  let ok = false;
  try { ok = document.execCommand("copy"); } catch {}
  ta.remove();
  return ok;
}
// copyButton shows "Copied" (or "Copy failed") briefly after a tap.
function copyButton(cls, label, getText) {
  const b = el("button", "copy-btn " + cls, "Copy");
  b.type = "button";
  b.title = label;
  b.setAttribute("aria-label", label);
  b.addEventListener("click", async (e) => {
    e.stopPropagation();
    const ok = await copyText(getText());
    b.textContent = ok ? "Copied" : "Copy failed";
    b.classList.add("done");
    clearTimeout(b._t);
    b._t = setTimeout(() => { b.textContent = "Copy"; b.classList.remove("done"); }, 1500);
  });
  return b;
}
// toolSummary is the collapsed "N tool calls: a, b" line on a reply.
// It opens to show each call with its arguments and result.
// permline:begin
function toolVerdict(ok, result, status) {
  if (ok === false && (status === "denied" || result === "denied")) return "denied";
  return ok ? "ok" : "error";
}
// permissionLine is one stored permission decision, e.g.
// "✅ allowed Bash(git status) · ui". Plain text; callers use textContent.
function permissionLine(r) {
  let d = {};
  try { d = JSON.parse(r.result_or_error || "{}") || {}; } catch (e) { d = {}; }
  // ok is the stored verdict. A UI allow is decision allow_once or allow_session.
  const allowed = r.ok === true || /^allow/.test(d.decision || "");
  const a = r.arguments || {};
  let arg = "";
  for (const k of ["command", "file_path", "path", "url", "pattern"]) {
    if (typeof a[k] === "string" && a[k]) { arg = a[k]; break; }
  }
  if (!arg && Object.keys(a).length) arg = JSON.stringify(a);
  if (arg.length > 120) arg = arg.slice(0, 117) + "…";
  const tool = (r.name || "tool") + (arg ? "(" + arg + ")" : "");
  let line = (allowed ? "✅ allowed " : "⛔ denied ") + tool;
  if (d.source) line += " · " + d.source;
  if (d.rule) line += " · " + d.rule;
  return line;
}
// hasToolRecords is true when a run has calls or permission decisions to show.
function hasToolRecords(recs) {
  return (recs || []).some(r => { const k = r.kind || "call"; return k === "call" || k === "permission"; });
}
// permline:end
function toolSummary(recs) {
  const calls = recs.filter(r => (r.kind || "call") === "call");
  const perms = recs.filter(r => r.kind === "permission");
  const names = [...new Set(calls.map(r => r.name))];
  const denied = perms.filter(r => !r.ok).length;
  const wrap = el("div", "tsum-wrap");
  const btn = el("button", "tsum");
  btn.type = "button";
  btn.setAttribute("aria-expanded", "false");
  const n = el("span", "n", calls.length + (calls.length === 1 ? " tool call" : " tool calls"));
  btn.append(chipIcon("wrench", 14), n);
  if (names.length) btn.append(el("span", "names", names.join(", ")));
  if (perms.length) {
    const word = perms.length + (perms.length === 1 ? " permission" : " permissions");
    const extra = denied ? " (" + denied + " denied)" : " (allowed)";
    btn.append(el("span", denied ? "denied" : "", " · " + word + extra));
  }
  btn.append(chipIcon("chev", 14));
  const panel = el("div", "tsum-panel");
  panel.hidden = true;
  // Records arrive in order: each round's pre-tool text, then its calls,
  // with permission decisions where the CLI asked.
  for (const r of recs) {
    if (r.kind === "text") {
      const narr = el("div", "narr");
      renderMarkdown(r.result_or_error, narr);
      panel.append(narr);
      continue;
    }
    if (r.kind === "permission") {
      const row = el("div", "tool tool-perm" + (r.ok ? "" : " denied"));
      row.append(permIcon(!!r.ok), document.createTextNode(permissionLine(r)));
      panel.append(row);
      continue;
    }
    const call = el("div", "tool");
    let args = r.arguments;
    if (typeof args === "string") { try { args = JSON.parse(args); } catch (e) { args = {}; } }
    const mark = r.ok === false ? "✗ " : "✓ ";
    call.append(el("div", null, mark + (r.name || "tool") + " " + JSON.stringify(args || {})));
    let result = r.result_or_error || "";
    let clipped = false;
    if (result.length > 400) { result = result.slice(0, 400); clipped = true; }
    call.append(el("div", "tool-result", toolVerdict(r.ok, r.result_or_error, r.status) + ": " + result + (clipped ? " (clipped)" : "")));
    panel.append(call);
  }
  btn.addEventListener("click", () => {
    panel.hidden = !panel.hidden;
    btn.setAttribute("aria-expanded", panel.hidden ? "false" : "true");
  });
  wrap.append(btn, panel);
  return wrap;
}
// Markdown to DOM for message bubbles. Presentation only: the stored text is
// unchanged. Every piece of text goes in through textContent, so raw HTML in
// a message shows as text. Links keep http, https, and mailto only.
function mdInline(src, parent) {
  const re = /(`+)([\s\S]*?[^`])\1(?!`)|\*\*([^*]+?)\*\*|__([^_]+?)__|\*([^*\s][^*]*?)\*|(^|[^\w])_([^_\s][^_]*?)_(?!\w)|\[([^\]]+)\]\(([^)\s]+)\)|(https?:\/\/[^\s<>()]+[^\s<>().,;:!?'"])/;
  let rest = src;
  while (rest) {
    const m = re.exec(rest);
    if (!m) { parent.append(document.createTextNode(rest)); break; }
    let start = m.index;
    if (m[6] !== undefined) start += m[6].length;
    if (start > 0) parent.append(document.createTextNode(rest.slice(0, start)));
    if (m[1]) parent.append(el("code", null, m[2].replace(/^ (.*) $/, "$1")));
    else if (m[3] !== undefined || m[4] !== undefined) {
      const b = el("strong"); mdInline(m[3] !== undefined ? m[3] : m[4], b); parent.append(b);
    } else if (m[5] !== undefined || m[7] !== undefined) {
      const i = el("em"); mdInline(m[5] !== undefined ? m[5] : m[7], i); parent.append(i);
    } else if (m[8] !== undefined) {
      const href = m[9];
      if (/^(https?:|mailto:)/i.test(href)) {
        const a = el("a"); a.href = href; a.target = "_blank"; a.rel = "noopener noreferrer";
        mdInline(m[8], a); parent.append(a);
      } else parent.append(document.createTextNode(m[0]));
    } else if (m[10]) {
      const a = el("a", null, m[10]); a.href = m[10]; a.target = "_blank"; a.rel = "noopener noreferrer";
      parent.append(a);
    }
    rest = rest.slice(m.index + m[0].length);
  }
}
// GFM pipe tables: a header row, an alignment row (---, :--, --:, :-:),
// then body rows until a blank line or a line without a pipe.
function tableCells(line) {
  let t = line.trim();
  if (t.startsWith("|")) t = t.slice(1);
  if (t.endsWith("|") && !t.endsWith("\\|")) t = t.slice(0, -1);
  const cells = [];
  let cur = "";
  for (let k = 0; k < t.length; k++) {
    if (t[k] === "\\" && t[k + 1] === "|") { cur += "|"; k++; continue; }
    if (t[k] === "|") { cells.push(cur.trim()); cur = ""; continue; }
    cur += t[k];
  }
  cells.push(cur.trim());
  return cells;
}
function isTableStart(lines, i) {
  if (i + 1 >= lines.length || !lines[i].includes("|")) return false;
  const sep = lines[i + 1];
  if (!/^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/.test(sep) || !sep.includes("-")) return false;
  if (!sep.includes("|") && tableCells(lines[i]).length < 2) return false;
  return tableCells(lines[i]).length === tableCells(sep).length;
}
function mdTable(lines, i, parent) {
  // Models sometimes put alignment tokens (":---:") in the header row where
  // the column names belong. Such a cell is shown empty, and a header row
  // that is all alignment tokens is dropped.
  const isAlign = (c) => /^:?-{1,}:?$/.test(c);
  const head = tableCells(lines[i]).map(c => isAlign(c) ? "" : c);
  const aligns = tableCells(lines[i + 1]).map(c => c.startsWith(":") && c.endsWith(":") ? "center" : c.endsWith(":") ? "right" : c.startsWith(":") ? "left" : "");
  i += 2;
  const wrap = el("div", "table-wrap");
  const table = el("table");
  const row = (cells, tag) => {
    const tr = el("tr");
    head.forEach((_, k) => {
      const c = el(tag);
      if (aligns[k]) c.style.textAlign = aligns[k];
      mdInline(cells[k] || "", c);
      tr.append(c);
    });
    return tr;
  };
  if (head.some(c => c)) {
    const thead = el("thead");
    thead.append(row(head, "th"));
    table.append(thead);
  }
  const tbody = el("tbody");
  while (i < lines.length && lines[i].trim() && lines[i].includes("|")) tbody.append(row(tableCells(lines[i++]), "td"));
  if (tbody.children.length) table.append(tbody);
  wrap.append(table);
  parent.append(wrap);
  return i;
}
function mdLines(lines, parent) {
  const isList = (l) => /^\s*([-*+]|\d+[.)])\s+/.test(l);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const fence = line.match(/^(\s*)(`{3,}|~{3,})\s*([^`\s]*)[^`]*$/);
    if (fence) {
      // Body lines keep their whitespace; the fence's own indent is removed.
      const indent = fence[1].length, mark = fence[2];
      const close = new RegExp("^\\s*" + mark[0] + "{" + mark.length + ",}\\s*$");
      const body = [];
      i++;
      while (i < lines.length && !close.test(lines[i])) {
        body.push(lines[i].replace(new RegExp("^ {0," + indent + "}"), ""));
        i++;
      }
      i++;
      const box = el("div", "code");
      if (fence[3]) box.append(el("span", "code-lang", fence[3]));
      box.append(copyButton("code-copy", "Copy code", () => body.join("\n")));
      const pre = el("pre");
      const code = el("code", null, body.join("\n"));
      if (fence[3]) code.dataset.lang = fence[3];
      pre.append(code);
      box.append(pre);
      parent.append(box);
      continue;
    }
    if (isTableStart(lines, i)) {
      i = mdTable(lines, i, parent);
      continue;
    }
    if (!line.trim()) { i++; continue; }
    const h = line.match(/^(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (h) {
      const n = el("h" + Math.min(6, h[1].length + 2));
      mdInline(h[2], n); parent.append(n); i++; continue;
    }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { parent.append(el("hr")); i++; continue; }
    if (/^\s*>/.test(line)) {
      const body = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) body.push(lines[i++].replace(/^\s*>\s?/, ""));
      const q = el("blockquote"); mdLines(body, q); parent.append(q); continue;
    }
    if (isList(line) && line.search(/\S/) < 2) {
      const ordered = /^\s*\d/.test(line);
      const list = el(ordered ? "ol" : "ul");
      if (ordered) {
        const s = parseInt(line.trim(), 10);
        if (s > 1) list.start = s;
      }
      let item = null;
      while (i < lines.length) {
        const l = lines[i];
        if (isList(l) && /^\s*\d/.test(l) === ordered && l.search(/\S/) < 2) {
          item = [l.replace(/^\s*([-*+]|\d+[.)])\s+/, "")];
          const li = el("li"); li._md = item; list.append(li);
          i++;
        } else if (item && l.trim() && /^\s+/.test(l)) {
          item.push(l.replace(/^\s{1,4}/, "")); i++;
        } else if (item && !l.trim() && i + 1 < lines.length && /^\s+\S/.test(lines[i + 1])) {
          item.push(""); i++;
        } else break;
      }
      for (const li of list.children) {
        const body = li._md;
        if (body.length === 1) mdInline(body[0], li); else mdLines(body, li);
      }
      parent.append(list);
      continue;
    }
    // The first line always joins the paragraph, so a line no block rule
    // took (a fence with an info string, an indented list marker) cannot
    // stall the loop.
    const para = [lines[i++]];
    while (i < lines.length && lines[i].trim() && !/^\s*(```|~~~|#{1,6}\s|>)/.test(lines[i]) && !isList(lines[i]) && !isTableStart(lines, i)) {
      para.push(lines[i++]);
    }
    const p = el("p");
    para.forEach((l, k) => {
      if (k) p.append(el("br"));
      mdInline(l, p);
    });
    parent.append(p);
  }
}
function renderMarkdown(text, target) {
  target.replaceChildren();
  mdLines(String(text || "").replace(/\r\n?/g, "\n").split("\n"), target);
  return target;
}
// md:end
// renderMessages rebuilds the list. mode "bottom" lands at the newest
// message; "prepend" keeps the visible messages where they were after older
// ones are added above; "keep" leaves the scroll offset alone.
function dayLabel(iso) {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const now = new Date();
  const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(now) - day(d)) / 86400000);
  if (diff === 0) return "Today";
  if (diff === 1) return "Yesterday";
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return months[d.getMonth()] + " " + d.getDate();
}
function msgCopyButton(getText) {
  const b = el("button", "copy-btn msg-copy");
  b.type = "button";
  b.title = "Copy message text";
  b.setAttribute("aria-label", "Copy message text");
  const paint = () => { b.replaceChildren(chipIcon("copy", 14)); };
  paint();
  b.addEventListener("click", async (e) => {
    e.stopPropagation();
    const ok = await copyText(getText());
    b.textContent = ok ? "Copied" : "Copy failed";
    b.classList.add("done");
    clearTimeout(b._t);
    b._t = setTimeout(() => {
      b.classList.remove("done");
      paint();
      b.setAttribute("aria-label", "Copy message text");
    }, 1500);
  });
  return b;
}
function recordPill(kind, toolLabel, timeLabel, duration) {
  const row = el("div", "card-record show");
  const text = cardRecordText({ kind: kind, toolLabel: toolLabel, timeLabel: timeLabel || "", duration: duration || "" });
  if (kind === "cancelled") row.append(stopCircleIcon());
  row.append(document.createTextNode(text));
  return row;
}
function renderRunRecords(parent, runId) {
  const merged = mergeRunRecords((state.tools && state.tools[runId]) || [], state.cardRecords || [], runId, state.botId);
  for (const rec of merged) {
    parent.append(recordPill(rec.kind, rec.toolLabel, rec.timeLabel, rec.duration));
  }
}
// Cards for a run that renderRunRecords did not draw. That call already merged
// the run's local cards, so a rendered run is skipped whole.
function renderPendingRunRecords(box, renderedRuns) {
  const done = renderedRuns || {};
  const runs = [];
  const listed = {};
  for (const c of state.cardRecords || []) {
    if (!c || c.botId !== state.botId) continue;
    const id = c.runId || "";
    if (done[id] || listed[id]) continue;
    listed[id] = true;
    runs.push(id);
  }
  for (const id of runs) {
    const extra = mergeRunRecords([], state.cardRecords || [], id, state.botId);
    for (const rec of extra) {
      box.append(recordPill(rec.kind, rec.toolLabel, rec.timeLabel, rec.duration));
    }
  }
}
function stoppedPill(info) {
  const line = el("div", "sys stopped");
  line.append(stopCircleIcon(), document.createTextNode(stoppedNoticeText(true, !!info.queued, info.time || "")));
  return line;
}
function stopInfoFor(runId) {
  const info = state.userStops && state.userStops[runId];
  if (!info || info.botId !== state.botId) return null;
  return info;
}
function renderMessages(mode = "bottom") {
  const box = $("#msgs");
  const prevH = box.scrollHeight, prevTop = box.scrollTop;
  const live = $("#live"), working = $("#working");
  box.replaceChildren();
  const showing = partialsToShow(state.messages, state.localPartials, state.botId);
  const keepPartial = new Set(showing);
  state.localPartials = (state.localPartials || []).filter(p => p && (p.botId !== state.botId || keepPartial.has(p)));
  if (!state.messages.length && working.hidden && !showing.length) {
    box.append(el("p", "empty", "No messages yet. The composer stays available while a run is in progress."));
  }
  const partialAt = {};
  for (const p of showing) {
    let at = state.messages.length;
    const id = p && p.runId != null && p.runId !== "" ? String(p.runId) : "";
    if (id) {
      for (let i = 0; i < state.messages.length; i++) {
        const row = state.messages[i];
        const rowId = row && row.run_id != null && row.run_id !== "" ? String(row.run_id) : "";
        if (rowId === id) { at = i; break; }
      }
    }
    if (!partialAt[at]) partialAt[at] = [];
    partialAt[at].push(p);
  }
  const appendPartial = (p) => {
    const bubble = el("div", "bubble bot");
    bubble.append(renderMarkdown(p.content, el("div", "md")));
    box.append(bubble);
  };
  const shownTools = new Set();
  const drawnStops = {};
  const renderedRuns = {};
  let lastDay = "";
  for (let mi = 0; mi < state.messages.length; mi++) {
    const m = state.messages[mi];
    const day = m.created_at ? dayLabel(m.created_at) : "";
    if (day && day !== lastDay) {
      lastDay = day;
      box.append(el("div", "day-line", day));
    }
    for (const p of partialAt[mi] || []) appendPartial(p);
    // A reload has no userStops entry. The saved cancel notice is still the
    // stop line; "Stopped by you" only while this session pressed Stop.
    if (m.role === "system" && m.content === "Notice: Run cancelled.") {
      const info = stopInfoFor(m.run_id);
      if (info) {
        box.append(stoppedPill(info));
      } else {
        const line = el("div", "sys stopped");
        line.append(stopCircleIcon(), document.createTextNode(stoppedNoticeText(false, false, clockLabel(m.created_at))));
        box.append(line);
      }
      drawnStops[m.run_id] = true;
      if (m.run_id && !shownTools.has(m.run_id) && hasToolRecords(state.tools[m.run_id])) {
        shownTools.add(m.run_id);
        box.append(toolSummary(state.tools[m.run_id]));
        renderRunRecords(box, m.run_id);
        renderedRuns[m.run_id] = true;
      }
      continue;
    }
    const queued = m.role === "user" && (state.queuedIds || []).indexOf(String(m.id)) >= 0;
    if (m.role === "user" || m.role === "bot") {
      const group = el("div", "msg-group " + m.role);
      const bubble = el("div", "bubble " + m.role + (queued ? " is-queued" : ""));
      bubble.append(renderMarkdown(m.content, el("div", "md")));
      group.append(bubble);
      if (m.role === "bot" && m.run_id && !shownTools.has(m.run_id) && hasToolRecords(state.tools[m.run_id])) {
        shownTools.add(m.run_id);
        group.append(toolSummary(state.tools[m.run_id]));
        renderRunRecords(group, m.run_id);
        renderedRuns[m.run_id] = true;
      }
      const meta = el("div", "msg-meta");
      const time = clockLabel(m.created_at);
      const who = m.role === "bot" ? ((currentBot() && currentBot().name) || "Bot") : "";
      meta.append(document.createTextNode(who && time ? who + " · " + time : (who || time)));
      if (m.role === "bot" && m.timed_out) meta.append(el("span", "timed-out", "Timed out"));
      const raw = m.content || "";
      meta.append(msgCopyButton(() => raw));
      group.append(meta);
      if (queued) {
        const cap = el("div", "queued-cap");
        cap.append(chipIcon("clock", 12), document.createTextNode(" " + QUEUED_CAPTION));
        group.append(cap);
      }
      box.append(group);
    } else {
      const bubble = el("div", "bubble system");
      if (whoText(m)) bubble.append(el("span", "who", whoText(m)));
      bubble.append(document.createTextNode(hookNoteBody(m.content, m.kind) || (m.content || "")));
      box.append(bubble);
      if (m.run_id && !shownTools.has(m.run_id) && hasToolRecords(state.tools[m.run_id])) {
        shownTools.add(m.run_id);
        box.append(toolSummary(state.tools[m.run_id]));
        renderRunRecords(box, m.run_id);
        renderedRuns[m.run_id] = true;
      }
    }
  }
  for (const p of partialAt[state.messages.length] || []) appendPartial(p);
  for (const runId in (state.userStops || {})) {
    if (drawnStops[runId]) continue;
    const info = stopInfoFor(runId);
    if (info) box.append(stoppedPill(info));
  }
  renderPendingRunRecords(box, renderedRuns);
  // The live run and the working indicator sit where the next reply will appear.
  box.append(live, working);
  if (mode === "prepend") box.scrollTop = prevTop + (box.scrollHeight - prevH);
  else if (mode === "keep") box.scrollTop = prevTop;
  else box.scrollTop = box.scrollHeight;
  if (mode === "bottom") { state.pinned = true; $("#new-pill").hidden = true; }
  // A short page (or a prepend that still leaves the top in view) loads more.
  if (state.hasMore && box.scrollTop < 200) setTimeout(loadOlder, 0);
}
const PAGE = 50;
// loadThread fetches the newest page. Older pages already loaded stay, so a
// refresh after a run does not throw away what the user scrolled back to.
async function loadThread(mode = "auto") {
  if (!state.botId) return;
  const id = state.botId;
  const data = await api("/api/bots/" + id + "/thread?limit=" + PAGE);
  if (state.botId !== id) return;
  const page = data.messages || [];
  const fresh = state.loadedFor !== id;
  const prevMessages = state.messages.slice();
  const lastBefore = state.messages.length ? state.messages[state.messages.length - 1].id : null;
  state.loadedFor = id;
  if (fresh || !page.length) {
    state.messages = page;
    state.tools = data.tools || {};
    state.hasMore = !!data.has_more;
    // A freshly opened thread is history. Queued styling is never restored.
    if (fresh) { state.queuedIds = []; state.queuedDuringRun = ""; }
  } else {
    const first = page[0].created_at;
    state.messages = state.messages.filter(m => m.created_at < first).concat(page);
    state.tools = Object.assign({}, state.tools, data.tools || {});
    if (state.messages.length === page.length) state.hasMore = !!data.has_more;
    if (queuedClearOnThread(prevMessages, state.messages, state.queuedIds, state.queuedDuringRun) && shouldClearQueued("stored-reply")) {
      state.queuedIds = [];
      state.queuedDuringRun = "";
      if (state.stop) state.stop = reduceStop(state.stop, { type: "unqueue" });
    }
  }
  const grew = !fresh && page.length && state.messages[state.messages.length - 1].id !== lastBefore;
  renderMessages(fresh ? "bottom" : mode === "auto" ? (state.pinned ? "bottom" : "keep") : mode);
  if (grew && !state.pinned) $("#new-pill").hidden = false;
}
// loadOlder prepends the page before the oldest loaded message.
async function loadOlder() {
  if (!state.botId || !state.hasMore || state.loadingOlder || !state.messages.length) return;
  state.loadingOlder = true;
  const id = state.botId;
  try {
    const data = await api("/api/bots/" + id + "/thread?limit=" + PAGE + "&before=" + encodeURIComponent(state.messages[0].id));
    if (state.botId !== id) return;
    state.messages = (data.messages || []).concat(state.messages);
    state.tools = Object.assign({}, data.tools || {}, state.tools);
    state.hasMore = !!data.has_more;
    renderMessages("prepend");
  } finally {
    state.loadingOlder = false;
  }
}
// Auto-scroll follows new output only while the reader is at the bottom
// (within 80px). Scrolled away, new output shows the "New messages" pill.
const PIN_PX = 80;
function distFromBottom() {
  const b = $("#msgs");
  return b.scrollHeight - b.scrollTop - b.clientHeight;
}
function stick() {
  const b = $("#msgs");
  if (state.pinned) b.scrollTop = b.scrollHeight;
  else $("#new-pill").hidden = false;
}
$("#msgs").addEventListener("scroll", () => {
  const b = $("#msgs");
  // Only a scroll that moved the view changes pinning; content growth while
  // pinned is handled by stick() and the observers below.
  state.pinned = distFromBottom() <= PIN_PX;
  if (state.pinned) $("#new-pill").hidden = true;
  if (b.scrollTop < 200) loadOlder();
}, {passive: true});
$("#new-pill").addEventListener("click", () => {
  state.pinned = true;
  $("#new-pill").hidden = true;
  const b = $("#msgs");
  b.scrollTo({top: b.scrollHeight, behavior: "smooth"});
});
// Streaming text, markdown and code re-renders, tool lines, and the working
// line change heights; stay pinned through all of them.
new MutationObserver((muts) => {
  if (!state.pinned) {
    // Growth in the live area while scrolled away gets the pill.
    if (muts.some(m => $("#live").contains(m.target) || m.target === $("#live"))) $("#new-pill").hidden = false;
    return;
  }
  const b = $("#msgs");
  b.scrollTop = b.scrollHeight;
}).observe($("#msgs"), {childList: true, subtree: true, characterData: true});
new ResizeObserver(() => { if (state.pinned) { const b = $("#msgs"); b.scrollTop = b.scrollHeight; } }).observe($("#msgs"));
function pendingApproval() {
  for (const rec of permCards.values()) {
    if (rec && !rec.settled) return true;
  }
  return false;
}
function workPhase() {
  if (state.stop && state.stop.phase === "stopping") return "stopping";
  if (pendingApproval() || state.approvalWait) return "waiting";
  if (typeof hookRunWaiting === "function" && hookRunWaiting(state.botId, typeof approvalItems === "undefined" ? null : approvalItems)) return "waiting";
  return "working";
}
function setWorking(on, text) {
  const w = $("#working");
  if (!w) return;
  const box = $("#msgs");
  if (text && text !== "working" && text !== "Working") state.liveTool = text;
  const phase = workPhase();
  const keep = phase === "stopping";
  w.hidden = !on && !keep;
  const label = workingIndicatorText(phase, phase === "stopping" ? "" : (state.liveTool || ""));
  const node = $("#working-text");
  if (node) node.textContent = label;
  w.classList.toggle("is-waiting", phase === "waiting");
  w.classList.toggle("is-stopping", phase === "stopping");
  if (!w.hidden) {
    const empty = box.querySelector(":scope > p.empty");
    if (empty) empty.remove();
    if (w.parentNode !== box || box.lastElementChild !== w) box.append($("#live"), w);
    stick();
  }
}
$("#new-bot").addEventListener("click", () => openDraft(true));
$("#menu-show-hidden").addEventListener("click", () => {
  state.showHidden = !state.showHidden;
  renderBots();
});
$("#menu-archived").addEventListener("click", () => {
  closeRosterMenu();
  state.showArchived = true;
  renderBots();
});
$("#menu-log").addEventListener("click", () => {
  closeRosterMenu();
  if (state.view === "log") navBack();
  else openLog(true);
});
$("#composer").addEventListener("submit", (e) => { e.preventDefault(); send(); });
$("#stop-btn").addEventListener("click", () => {
  const btn = $("#stop-btn");
  if (!btn || btn.getAttribute("aria-disabled") === "true") return;
  requestStop();
});
// Enter sends; Shift+Enter (or Enter while an IME is composing) inserts a
// newline. The box grows with its content up to 40% of the viewport.
$("#composer-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); return; }
  if (e.key !== "Escape") return;
  const input = $("#composer-input");
  const touch = window.matchMedia && window.matchMedia("(hover: none)").matches;
  const menuOpen = ($("#bot-menu") && !$("#bot-menu").hidden) || ($("#roster-menu") && !$("#roster-menu").hidden);
  const sheetOpen = (typeof stateOpen === "function" && stateOpen()) || (typeof discardOpen === "function" && discardOpen());
  let dialogOpen = false;
  if (typeof permCards !== "undefined") {
    for (const rec of permCards.values()) if (rec && !rec.settled) dialogOpen = true;
  }
  if (typeof queueIsOpen === "function" && queueIsOpen()) dialogOpen = true;
  if (typeof brokerCardPending === "function" && brokerCardPending()) dialogOpen = true;
  const stop = !touch && escStopsRun({
    key: "Escape",
    empty: !String(input && input.value || "").trim(),
    inComposer: true,
    runActive: !!(state.stop && state.stop.phase === "running"),
    menuOpen: !!menuOpen,
    sheetOpen: !!sheetOpen,
    dialogOpen: dialogOpen
  });
  if (stop) { e.preventDefault(); requestStop(); }
});
function fitComposer() {
  const t = $("#composer-input");
  t.style.height = "auto";
  const max = window.innerHeight * 0.4;
  t.style.height = Math.min(t.scrollHeight + 2, max) + "px";
  t.style.overflowY = t.scrollHeight + 2 > max ? "auto" : "hidden";
}
$("#composer-input").addEventListener("input", () => { fitComposer(); syncSendEmpty(); });
async function send(override) {
  const input = $("#composer-input");
  const fromField = typeof override !== "string";
  const content = (fromField ? input.value : override).trim();
  if (!content || !state.botId) return false;
  const runningBefore = !!(state.streaming || (currentBot() && currentBot().status === "running") || (state.stop && (state.stop.phase === "running" || state.stop.phase === "stopping")));
  const duringRun = state.streaming || (state.stop && state.stop.runId) || "";
  input.value = "";
  fitComposer();
  syncSendEmpty();
  if (window.voiceOnSend) window.voiceOnSend(content);
  if (state.stopNote !== "failed") $("#run-note").hidden = true;
  try {
    const data = await api("/api/bots/" + state.botId + "/thread/messages", {
      method: "POST", body: JSON.stringify({content})
    });
    if (runningBefore && data && data.message && data.message.id != null) {
      state.queuedIds = state.queuedIds || [];
      const qid = String(data.message.id);
      if (state.queuedIds.indexOf(qid) < 0) state.queuedIds.push(qid);
      if (!state.queuedDuringRun) state.queuedDuringRun = duringRun;
      if (state.stop) state.stop = reduceStop(state.stop, { type: "queue" });
    }
    // Sending is a jump to the bottom, wherever the reader was.
    await loadThread("bottom");
    if (data.run_id) {
      if (noteRunStarted(state.bots, state.botId)) renderBots();
      follow(data.run_id);
    } else pollActive();
    return true;
  } catch (err) {
    showRunError(err.message);
    if (window.voiceOnRunEnd) window.voiceOnRunEnd("", true);
    return false;
  }
}
function focusAfterTimeoutNote() {
  const active = document.activeElement;
  const tag = active && active.tagName ? active.tagName : "";
  const input = $("#composer-input");
  const usable = !!(input && !input.disabled && input.offsetParent !== null);
  const id = (typeof focusTargetAfterNote === "function") ? focusTargetAfterNote(tag, usable) : (usable ? "composer-input" : "thread-name");
  if (!id) return;
  const node = document.getElementById(id);
  if (!node || typeof node.focus !== "function") return;
  if (id === "thread-name") node.tabIndex = -1;
  node.focus({ preventScroll: true });
}
async function retryTimeout(runId) {
  if (!state.botId || !runId || state.continuing) return;
  state.continuing = true;
  const note = $("#run-note");
  if (note) { note.hidden = true; note.replaceChildren(); }
  focusAfterTimeoutNote();
  try {
    const data = await api("/api/bots/" + state.botId + "/runs/" + encodeURIComponent(runId) + "/retry", {method: "POST"});
    if (data && data.run_id) {
      state.timeoutRunId = "";
      if (noteRunStarted(state.bots, state.botId)) renderBots();
      await follow(data.run_id);
    }
  } catch (err) {
    showRunError(err.message);
  } finally {
    state.continuing = false;
  }
}
async function continueRun(runId) {
  if (!state.botId || !runId || state.continuing) return;
  state.continuing = true;
  const note = $("#run-note");
  if (note) { note.hidden = true; note.replaceChildren(); }
  focusAfterTimeoutNote();
  try {
    const data = await api("/api/bots/" + state.botId + "/runs/" + encodeURIComponent(runId) + "/continue", {method: "POST"});
    if (data.run_id) {
      if (noteRunStarted(state.bots, state.botId)) renderBots();
      await follow(data.run_id);
    }
  } catch (err) {
    showRunError(err.message);
  } finally {
    state.continuing = false;
  }
}
// perm:begin
const permCards = new Map();

function permissionArgsText(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  try { return JSON.stringify(value, null, 2); } catch (e) { return ""; }
}

function clearPermissionCards() {
  for (const rec of permCards.values()) {
    clearInterval(rec.timer);
    clearTimeout(rec.expire);
  }
  permCards.clear();
}

function mmss(left) {
  const s = Math.max(0, left | 0);
  const m = Math.floor(s / 60);
  const r = s % 60;
  return m + ":" + (r < 10 ? "0" : "") + r;
}
function addKV(parent, k, v) {
  const row = el("div", "kv");
  row.append(el("span", "kv-k", k), el("span", "kv-v", v == null ? "" : String(v)));
  parent.append(row);
}
function fillCardBody(body, payload) {
  const tool = payload && payload.tool ? String(payload.tool) : "";
  const args = payload && payload.arguments && typeof payload.arguments === "object" ? payload.arguments : {};
  if (payload && payload.kind === "question") return;
  if (tool === "ExitPlanMode" && typeof args.plan === "string") {
    const plan = el("pre", "perm-plan sr");
    plan.textContent = args.plan;
    body.append(plan);
    const lines = args.plan.split(/\n+/).map(s => s.replace(/^\s*\d+[.)]\s*/, "").trim()).filter(Boolean);
    const ol = el("ol", "card-plan");
    (lines.length ? lines : [args.plan]).forEach(line => ol.append(el("li", null, line)));
    body.append(ol);
  }
  if (tool === "git_push") {
    addKV(body, "Branch", args.branch || "");
    addKV(body, "Remote", args.remote || "");
    let commits = args.commits == null ? "" : (typeof args.commits === "string" ? args.commits : permissionArgsText(args.commits));
    if (commits.length > 4000) commits = commits.slice(0, 4000);
    const pre = el("pre", "card-pre");
    pre.textContent = commits;
    body.append(pre);
    body.append(el("div", "card-note", "Every push asks. Session approval does not apply. Default branch, force and tags are refused before this card."));
  } else if (tool === "create_pr") {
    const head = args.head == null ? "" : String(args.head);
    const baseName = args.base == null ? "" : String(args.base);
    addKV(body, "Branches", head + " → " + baseName);
    addKV(body, "Title", args.title == null ? "" : String(args.title));
    addKV(body, "Draft", args.draft ? "yes" : "no");
    let bodyText = args.body == null ? "" : String(args.body);
    const clipped = bodyText.length > 2000;
    if (clipped) bodyText = bodyText.slice(0, 2000);
    const pre = el("pre", "card-pre");
    pre.textContent = bodyText;
    body.append(pre);
    if (clipped) body.append(el("div", "card-note", "Body preview · clipped at 2,000 characters"));
    body.append(el("div", "card-note", "Every pull request asks. Nothing is sent to GitHub until you allow it."));
  } else if (tool === "Bash") {
    body.append(el("div", "card-note", "Denied automatically when the timer runs out."));
  }
  const argsPre = el("pre", "perm-args");
  argsPre.textContent = permissionArgsText(payload ? payload.arguments : "");
  if (tool === "git_push" || tool === "create_pr") argsPre.className = "perm-args sr";
  body.append(argsPre);
}
function showPermissionRequest(payload, runId) {
  const id = payload && payload.id ? String(payload.id) : "";
  if (!id || permCards.has(id)) return permCards.get(id) || null;
  const run = (payload && payload.run_id) || runId || "";
  const card = el("div", "perm-card");
  card.dataset.id = id;
  const toolName = payload && payload.tool == null ? "" : String(payload && payload.tool != null ? payload.tool : "");
  let botName = "";
  if (typeof currentBot === "function") {
    const b = currentBot();
    if (b && b.name) botName = String(b.name);
  }
  const top = el("div", "card-top");
  const tile = el("span", "card-tile");
  const glyph = el("span", null, payload && payload.kind === "question" ? "?" : "!");
  tile.append(glyph);
  const main = el("div", "card-main");
  if (typeof cardEyebrow === "function") {
    const eye = cardEyebrow(payload, botName);
    if (eye) main.append(el("div", "card-eyebrow", eye));
  }
  const tool = el("div", "perm-tool");
  const titleText = (typeof cardTitle === "function") ? cardTitle(payload) : toolName;
  tool.textContent = titleText;
  if (toolName && String(titleText).indexOf(toolName) < 0) {
    const raw = el("span", "sr");
    raw.textContent = toolName;
    tool.append(raw);
  }
  if (typeof tool.id === "string" || typeof document !== "undefined") tool.id = "perm-title-" + id;
  main.append(tool);
  const meta = el("div", "card-meta");
  const digits = el("div", "card-digits");
  const bar = el("div", "card-bar");
  const barI = el("i");
  bar.append(barI);
  meta.append(digits, bar);
  top.append(tile, main, meta);
  const body = el("div", "card-body");
  const count = el("div", "perm-count");
  const outcome = el("div", "perm-outcome");
  const errLine = el("div", "perm-err");
  const actions = el("div", "perm-actions");
  const record = el("div", "card-record");
  const announceEl = el("div", "sr");
  if (typeof announceEl.setAttribute === "function") announceEl.setAttribute("aria-live", "polite");
  const inputs = [];
  let groups = [];
  if (typeof card.setAttribute === "function") {
    card.setAttribute("role", "alertdialog");
    if (tool.id) card.setAttribute("aria-labelledby", tool.id);
  }
  if (payload && payload.kind === "question") {
    groups = appendQuestions(body, payload, inputs);
    const submit = el("button", "primary", "Submit");
    submit.type = "button";
    const skip = el("button", null, "Skip");
    skip.type = "button";
    submit.addEventListener("click", () => {
      if (submit.classList && typeof submit.classList.add === "function") submit.classList.add("is-loading");
      submitQuestion(id, run);
    });
    skip.addEventListener("click", () => {
      if (skip.classList && typeof skip.classList.add === "function") skip.classList.add("is-loading");
      postPermission(id, run, "deny");
    });
    actions.append(submit, skip);
  } else {
    fillCardBody(body, payload);
    const allow = el("button", "primary", "Allow once");
    allow.type = "button";
    const deny = el("button", "deny", "Deny");
    deny.type = "button";
    allow.addEventListener("click", () => {
      if (allow.classList && typeof allow.classList.add === "function") allow.classList.add("is-loading");
      postPermission(id, run, "allow_once");
    });
    deny.addEventListener("click", () => {
      if (deny.classList && typeof deny.classList.add === "function") deny.classList.add("is-loading");
      postPermission(id, run, "deny");
    });
    actions.append(allow);
    if (payload.session_allowed) {
      const sess = el("button", null, "Allow for session");
      sess.type = "button";
      sess.addEventListener("click", () => {
        if (sess.classList && typeof sess.classList.add === "function") sess.classList.add("is-loading");
        postPermission(id, run, "allow_session");
      });
      actions.append(sess);
    }
    actions.append(deny);
    if (typeof document !== "undefined" && typeof allow.focus === "function") {
      let typing = false;
      try {
        const field = document.getElementById && document.getElementById("composer-input");
        typing = !!(document.activeElement && field && document.activeElement === field);
      } catch (e) { typing = false; }
      if (!typing) allow.focus();
    }
  }
  card.append(top, body, count, actions, outcome, errLine, record, announceEl);
  const live = $("#live");
  if (live) live.append(card);
  if (typeof card.scrollIntoView === "function") {
    try { card.scrollIntoView({ block: "nearest" }); } catch (e) {}
  }
  const deadline = Date.parse(payload.deadline || "");
  const rec = {
    card, count, actions, outcome, errLine, inputs, groups, record, digits, barI, announceEl,
    timer: 0, expire: 0, settled: false, server: false, pending: false,
    tool: toolName, args: payload && payload.arguments, runId: run, reqId: id,
    prevLeft: null, initialLeft: null
  };
  permCards.set(id, rec);
  const paint = (maySettle) => {
    const cur = permCards.get(id);
    if (!cur || cur.server) return;
    if (Number.isNaN(deadline)) {
      cur.count.textContent = "";
      return;
    }
    const left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    cur.count.textContent = left >= 60 ? Math.floor(left / 60) + "m " + (left % 60) + "s" : left + "s";
    if (cur.initialLeft == null) cur.initialLeft = left;
    if (cur.digits) cur.digits.textContent = mmss(left);
    const total = cur.initialLeft > 0 ? cur.initialLeft : left;
    if (cur.barI && cur.barI.style) {
      const pct = total > 0 ? Math.max(0, Math.min(100, (left / total) * 100)) : 0;
      cur.barI.style.width = pct + "%";
    }
    const spoken = (typeof countdownAnnounce === "function") ? countdownAnnounce(cur.prevLeft, left) : "";
    cur.prevLeft = left;
    if (spoken && cur.announceEl) cur.announceEl.textContent = spoken;
    if (maySettle && left <= 0) settlePermission(id, "deny", "timeout", false);
  };
  paint(false);
  rec.timer = setInterval(() => paint(true), 250);
  if (!Number.isNaN(deadline)) rec.expire = setTimeout(() => paint(true), Math.max(0, deadline - Date.now()));
  if (typeof setWorking === "function" && typeof state !== "undefined" && state.streaming) setWorking(true);
  return rec;
}

function appendQuestions(card, payload, inputs) {
  const groups = [];
  const list = Array.isArray(payload.questions) ? payload.questions : [];
  list.forEach((q, qi) => {
    const header = el("div", "perm-header");
    header.textContent = q && q.header != null ? String(q.header) : "";
    const text = el("div", "perm-question");
    text.textContent = q && q.question != null ? String(q.question) : "";
    card.append(header, text);
    const multi = !!(q && q.multiSelect);
    const name = "perm-" + String(payload.id || qi) + "-" + qi;
    const group = {question: text.textContent, multi: multi, options: [], other: null, otherText: null};
    const opts = q && Array.isArray(q.options) ? q.options : [];
    opts.forEach((o) => {
      const label = o && o.label != null ? String(o.label) : "";
      const row = el("label", "perm-option");
      const input = el("input");
      input.type = multi ? "checkbox" : "radio";
      input.name = name;
      input.value = label;
      const lab = el("span", null, label);
      const desc = el("div", "perm-desc");
      desc.textContent = o && o.description != null ? String(o.description) : "";
      row.append(input, lab, desc);
      card.append(row);
      inputs.push(input);
      group.options.push({label: label, input: input});
      if (!multi) {
        input.addEventListener("change", () => {
          if (input.checked && group.other) group.other.checked = false;
        });
      }
    });
    const row = el("div", "perm-option");
    const textIn = el("input");
    textIn.type = "text";
    textIn.className = "perm-other";
    inputs.push(textIn);
    group.otherText = textIn;
    if (multi) {
      row.append(el("span", null, "Other"), textIn);
    } else {
      const other = el("input");
      other.type = "radio";
      other.name = name;
      other.value = "";
      inputs.push(other);
      group.other = other;
      row.append(other, el("span", null, "Other"), textIn);
      textIn.addEventListener("input", () => {
        other.checked = true;
        group.options.forEach((opt) => { opt.input.checked = false; });
      });
      other.addEventListener("change", () => {
        if (other.checked) group.options.forEach((opt) => { opt.input.checked = false; });
      });
    }
    card.append(row);
    groups.push(group);
  });
  return groups;
}

function collectQuestionAnswers(rec) {
  if (!rec.groups || !rec.groups.length) return null;
  const answers = {};
  for (const group of rec.groups) {
    const extra = group.otherText && group.otherText.value ? String(group.otherText.value).trim() : "";
    if (group.multi) {
      const parts = [];
      for (const opt of group.options) if (opt.input.checked) parts.push(opt.label);
      if (extra) parts.push(extra);
      if (!parts.length) return null;
      answers[group.question] = parts.join(", ");
      continue;
    }
    if (group.other && group.other.checked) {
      if (!extra) return null;
      answers[group.question] = extra;
      continue;
    }
    let value = "";
    for (const opt of group.options) if (opt.input.checked) value = opt.label;
    if (!value) return null;
    answers[group.question] = value;
  }
  return answers;
}

function submitQuestion(id, runId) {
  const rec = permCards.get(id);
  if (!rec || rec.settled || rec.pending) return;
  const answers = collectQuestionAnswers(rec);
  if (!answers) {
    rec.errLine.textContent = "Answer each question";
    return;
  }
  rec.errLine.textContent = "";
  postPermission(id, runId, "answer", {answers: answers});
}

function setPermDisabled(rec, disabled) {
  for (const b of rec.actions.querySelectorAll("button")) b.disabled = disabled;
  if (rec.inputs) for (const n of rec.inputs) n.disabled = disabled;
}

function fillCardRecord(rec, decision, source) {
  if (!rec || !rec.record) return;
  const kind = (typeof recordKind === "function") ? recordKind(decision, source) : "";
  const toolLabel = (typeof toolCallLabel === "function") ? toolCallLabel(rec.tool, rec.args) : (rec.tool || "");
  const timeLabel = (typeof clockLabel === "function") ? clockLabel(new Date()) : "";
  const duration = (typeof durationLabel === "function") ? durationLabel(rec.initialLeft || 0) : "";
  const text = (typeof cardRecordText === "function") ? cardRecordText({ kind: kind, toolLabel: toolLabel, timeLabel: timeLabel, duration: duration }) : "";
  rec.record.textContent = text;
  if (kind && typeof rememberCardRecord === "function") rememberCardRecord(rec, kind, toolLabel, timeLabel, duration);
}
function settlePermission(id, decision, source, fromServer) {
  const rec = permCards.get(id);
  if (!rec) return;
  if (rec.server) return;
  if (rec.settled && !fromServer) return;
  rec.settled = true;
  if (fromServer) rec.server = true;
  clearInterval(rec.timer);
  clearTimeout(rec.expire);
  rec.card.classList.add("settled");
  setPermDisabled(rec, true);
  rec.outcome.textContent = (decision || "deny") + " (" + (source || "") + ")";
  fillCardRecord(rec, decision, source);
  if (typeof setWorking === "function") setWorking(!!(typeof state !== "undefined" && state.streaming));
}

function showPermissionDecision(payload) {
  if (!payload) return;
  const id = payload.id ? String(payload.id) : "";
  if (!id) return;
  if (!permCards.has(id)) {
    showPermissionRequest({
      id: id,
      tool: payload.tool,
      arguments: payload.arguments,
      run_id: payload.run_id,
      session_allowed: false,
      kind: payload.kind,
      questions: payload.questions
    }, payload.run_id || "");
  }
  settlePermission(id, payload.decision, payload.source, true);
}

async function postPermission(id, runId, decision, extra) {
  const rec = permCards.get(id);
  if (!rec || rec.settled || rec.pending) return;
  rec.pending = true;
  setPermDisabled(rec, true);
  try {
    await api("/api/bots/" + state.botId + "/runs/" + encodeURIComponent(runId) + "/permissions/" + encodeURIComponent(id), {
      method: "POST",
      body: JSON.stringify(Object.assign({decision: decision}, extra || {}))
    });
  } catch (err) {
    rec.pending = false;
    if (!rec.settled) {
      setPermDisabled(rec, false);
      rec.errLine.textContent = "Couldn't send your answer. The daemon didn't respond. Try again.";
      if (rec.actions && rec.actions.querySelectorAll) {
        rec.actions.querySelectorAll("button").forEach((b) => {
          if (b.classList && typeof b.classList.remove === "function") b.classList.remove("is-loading");
        });
      }
    }
  }
}
// perm:end
function announce(text) {
  const n = $("#a11y-status");
  if (n) n.textContent = text || "";
}
function paintSubline(b) {
  const label = $("#thread-label");
  const dot = $("#thread-dot");
  if (!b) {
    if (label) label.textContent = "";
    if (dot) dot.hidden = true;
    return;
  }
  const phase = state.stop && state.stop.phase;
  const word = headerPhaseWord(b, !!state.streaming, phase || "", !!state.approvalWait);
  if (label) label.textContent = threadSubline(word, word === "running" ? state.liveTool : "", b.label || "");
  if (dot) {
    dot.hidden = false;
    const dotWord = word === "running" || word === "paused" || word === "waiting" ? word : "idle";
    dot.className = "dot " + dotWord;
  }
}
function syncStopButton() {
  const btn = $("#stop-btn");
  const menuStop = $("#menu-stop");
  const phase = state.stop && state.stop.phase;
  const show = phase === "running" || phase === "stopping";
  if (btn) {
    btn.hidden = !show;
    const stopping = phase === "stopping";
    btn.classList.toggle("is-stopping", stopping);
    if (stopping) {
      btn.setAttribute("aria-disabled", "true");
      btn.setAttribute("aria-label", "Stopping…");
    } else {
      btn.removeAttribute("aria-disabled");
      btn.setAttribute("aria-label", "Stop run");
    }
  }
  if (menuStop) menuStop.hidden = !show;
}
function armStopTimer() {
  clearTimeout(state.stopTimer);
  state.stopTimer = 0;
  if (!state.stop || state.stop.phase !== "stopping") return;
  const since = state.stop.since || Date.now();
  const wait = Math.max(0, STOP_TIMEOUT_MS - (Date.now() - since));
  state.stopTimer = setTimeout(() => {
    if (!state.stop || state.stop.phase !== "stopping") return;
    applyStop(reduceStop(state.stop, { type: "tick", now: Date.now() }));
  }, wait);
}
function applyStop(next) {
  state.stop = next || freshStop();
  clearTimeout(state.stopTimer);
  state.stopTimer = 0;
  if (state.stop.phase === "stopping") armStopTimer();
  if (state.stop.note === "stop-failed") state.stopNote = "failed";
  else if (state.stop.phase !== "running") state.stopNote = "";
  syncStopButton();
  syncComposer();
  const b = typeof currentBot === "function" ? currentBot() : null;
  if (b && typeof paintHeader === "function") paintHeader(b);
  else if (typeof paintSubline === "function") paintSubline(b);
  if (state.stop.phase === "stopping" || (state.streaming && state.stop.phase === "running")) setWorking(!!state.streaming || state.stop.phase === "stopping");
}
function resetThreadRun() {
  clearTimeout(state.stopTimer);
  state.stopTimer = 0;
  state.stop = freshStop();
  state.queuedIds = [];
  state.queuedDuringRun = "";
  state.liveTool = "";
  state.stopNote = "";
  state.cardRecords = [];
  state.userStops = {};
  state.localPartials = [];
  state.dismissedRunError = "";
  syncStopButton();
}
function rememberCardRecord(rec, kind, toolLabel, timeLabel, duration) {
  if (!rec || !kind) return;
  const runId = rec.runId || state.streaming || "";
  const key = (rec.tool || "") + "|" + kind + "|" + (rec.reqId || "");
  state.cardRecords = (state.cardRecords || []).filter(c => c.key !== key);
  state.cardRecords.push({
    key: key, runId: runId, botId: state.botId, kind: kind,
    toolLabel: toolLabel, timeLabel: timeLabel, duration: duration
  });
}
function settleStoppedCards() {
  if (typeof permCards === "undefined") return;
  for (const id of [...permCards.keys()]) {
    const rec = permCards.get(id);
    if (!rec || rec.settled) continue;
    settlePermission(id, "deny", "cancel", false);
  }
}
// After Stop from the button or the ⋯ item, the control hides under focus
// and the browser drops focus on body. Put it back on the composer unless
// the user has already moved to some other control.
function focusComposerAfterStop() {
  const active = document.activeElement;
  const stopBtn = $("#stop-btn");
  const menuStop = $("#menu-stop");
  if (active && active !== document.body && active !== stopBtn && active !== menuStop) return;
  const input = $("#composer-input");
  if (input && typeof input.focus === "function") input.focus({ preventScroll: true });
}
function rememberPartial(runId, text) {
  const content = String(text || "");
  if (!content || !runId) return;
  state.localPartials = (state.localPartials || []).filter(p => p.runId !== runId);
  state.localPartials.push({ runId: runId, botId: state.botId, content: content });
}
async function requestStop() {
  if (!state.botId || !state.stop || state.stop.phase !== "running" || !state.stop.runId) return;
  const runId = state.stop.runId;
  const queued = !!(state.queuedIds && state.queuedIds.length);
  applyStop(reduceStop(state.stop, { type: "press", now: Date.now(), runId: runId, queued: queued }));
  focusComposerAfterStop();
  announce("Stopping run");
  setWorking(true);
  let data = null;
  try {
    data = await api("/api/bots/" + state.botId + "/runs/" + encodeURIComponent(runId) + "/cancel", { method: "POST" });
  } catch (err) {
    if (state.stop && state.stop.phase === "stopping" && state.stop.runId === runId) {
      applyStop(reduceStop(state.stop, { type: "cancel-error" }));
    }
    return;
  }
  if (!state.stop || state.stop.phase !== "stopping" || state.stop.runId !== runId) return;
  const status = data && data.status != null ? String(data.status) : "";
  const streamEnded = state.streaming !== runId;
  applyStop(reduceStop(state.stop, { type: "cancel-result", status: status, streamEnded: streamEnded }));
}
// placeCaret keeps the streaming caret at the end of the last text block.
function placeCaret(bubble, text) {
  // renderMarkdown replaces the text's children, so keep our own reference.
  if (!bubble) return;
  if (!bubble.lgbCaret && bubble.querySelector) bubble.lgbCaret = bubble.querySelector(".caret");
  const caret = bubble.lgbCaret;
  if (!caret || !text) return;
  let tgt = text;
  while (tgt.lastElementChild && /^(P|LI|UL|OL|BLOCKQUOTE|H[1-6])$/.test(tgt.lastElementChild.tagName)) tgt = tgt.lastElementChild;
  if (caret.parentNode !== tgt || tgt.lastChild !== caret) tgt.append(caret);
}
function stopStream() {
  clearPermissionCards();
  if (state.streamCtl) { state.streamCtl.abort(); state.streamCtl = null; }
  state.streaming = "";
  $("#live").replaceChildren();
  setWorking(false);
}
// loadPendingPermissions shows open requests the stream did not replay
// (the page opened later, or the run's event history was trimmed).
async function loadPendingPermissions(runId) {
  if (!state.botId || !runId) return;
  const data = await api("/api/bots/" + state.botId + "/permissions");
  if (state.streaming !== runId) return;
  for (const p of (data && data.pending) || []) {
    if (p && p.run_id === runId) showPermissionRequest(p, runId);
  }
}
async function follow(runId) {
  if (!runId || state.streaming === runId) return;
  // A run this client already stopped must not be subscribed again: the
  // daemon's synthesized "done" has no status and would clear the stopped line.
  const priorStop = state.userStops && state.userStops[runId];
  if (priorStop && priorStop.botId === state.botId) return;
  stopStream();
  state.streaming = runId;
  state.stop = reduceStop(state.stop || freshStop(), { type: "run", runId: runId });
  syncComposer();
  state.liveTool = "";
  syncStopButton();
  if (noteRunStarted(state.bots, state.botId)) renderBots();
  setWorking(true);
  paintSubline(currentBot());
  const ctl = new AbortController();
  state.streamCtl = ctl;
  const live = $("#live");
  // Each model round's text gets its own bubble. A tool call closes the
  // current bubble, so the next round's tokens start a new one.
  let acc = "";
  let voiceText = "";
  let bubble = null, text = null;
  const newBubble = () => {
    acc = "";
    bubble = el("div", "bubble bot");
    text = el("div", "md");
    const caret = el("span", "caret");
    caret.setAttribute("aria-hidden", "true");
    bubble.append(text, caret);
  };
  const closeBubble = () => {
    if (bubble && bubble.querySelector) {
      const caret = bubble.querySelector(".caret");
      if (caret) caret.remove();
    }
    bubble = null;
  };
  try {
    const headers = {};
    if (state.token) headers.Authorization = "Bearer " + state.token;
    const res = await fetch(base() + "/api/bots/" + state.botId + "/thread/stream?run_id=" + encodeURIComponent(runId) + "&prompts=1", {headers, signal: ctl.signal});
    if (res.status === 401) { showAuth(); return; }
    if (!res.ok || !res.body) throw new Error("stream failed");
    loadPendingPermissions(runId).catch(() => {});
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      buf += dec.decode(value, {stream: true});
      let idx;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const raw = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        let event = "message", data = "";
        for (const line of raw.split("\n")) {
          if (line.startsWith("event:")) event = line.slice(6).trim();
          else if (line.startsWith("data:")) data += line.slice(5).trim();
        }
        if (!data) continue;
        let payload = {};
        try { payload = JSON.parse(data); } catch { continue; }
        if (event === "status") {
          if (noteRunStarted(state.bots, state.botId)) renderBots();
          const applied = applyStreamStatus(currentBot(), state.approvalWait, "status", payload);
          state.approvalWait = applied.approvalWait;
          if (applied.bot && applied.bot.id) {
            const bi = state.bots.findIndex(x => x.id === applied.bot.id);
            if (bi >= 0) state.bots[bi] = applied.bot;
          }
          if (payload.state === "waiting") {
            if (payload.text) state.liveTool = payload.text;
          } else {
            const tool = payload.text || payload.state || "";
            if (tool && tool !== "working" && tool !== "running" && tool !== "retrying") state.liveTool = tool;
          }
          if (!state.stop || state.stop.phase !== "stopping") setWorking(true);
          paintSubline(currentBot());
        } else if (event === "stream_reset") {
          if (typeof streamResetApplies !== "function" || streamResetApplies(payload.run_id, runId)) {
            acc = "";
            voiceText = "";
            if (bubble && bubble.remove) bubble.remove();
            bubble = null;
            text = null;
          }
        } else if (event === "token") {
          if (!bubble) {
            if ((state.queuedIds || []).length && shouldClearQueued("new-bot-token")) {
              state.queuedIds = [];
              state.queuedDuringRun = "";
              if (state.stop) state.stop = reduceStop(state.stop, { type: "unqueue" });
            }
            newBubble();
          }
          acc += payload.text || "";
          voiceText += payload.text || "";
          renderMarkdown(acc, text);
          placeCaret(bubble, text);
          if (!bubble.parentNode) live.append(bubble);
        } else if (event === "tool_call") {
          closeBubble();
          state.liveTool = payload.name || state.liveTool;
          const line = el("div", "live-tool");
          line.dataset.name = payload.name || "";
          line.textContent = liveToolLine(payload.name, payload.arguments, null);
          live.append(line);
          if (!state.stop || state.stop.phase !== "stopping") setWorking(true);
          paintSubline(currentBot());
        } else if (event === "tool_result") {
          const lines = live.querySelectorAll ? live.querySelectorAll(".live-tool") : [];
          let line = null;
          for (let i = lines.length - 1; i >= 0; i--) {
            if (!payload.name || lines[i].dataset.name === payload.name) { line = lines[i]; break; }
          }
          const textLine = liveToolLine(payload.name, payload.arguments, payload.ok);
          if (line) line.textContent = textLine;
          else live.append(el("div", "live-tool", textLine));
        } else if (event === "permission_request") {
          if (payload && payload.tool) state.liveTool = payload.tool;
          showPermissionRequest(payload, runId);
          if (!state.stop || state.stop.phase !== "stopping") setWorking(true);
          paintSubline(currentBot());
        } else if (event === "permission_decision") {
          showPermissionDecision(payload);
          if (!state.stop || state.stop.phase !== "stopping") setWorking(!!state.streaming);
        } else if (event === "done" || event === "error" || event === "timeout") {
          const status = event === "error" ? "error" : (event === "timeout" ? "timeout" : (payload.status || ""));
          if (event === "timeout" && payload.run_id) state.timeoutRunId = String(payload.run_id);
          if (event === "timeout") announce(timeoutAnnouncement(payload.error));
          const applied = applyStreamStatus(currentBot(), state.approvalWait, event, payload);
          state.approvalWait = applied.approvalWait;
          if (applied.bot && applied.bot.id) {
            const bi = state.bots.findIndex(x => x.id === applied.bot.id);
            if (bi >= 0) state.bots[bi] = applied.bot;
          }
          paintSubline(currentBot());
          const prevPhase = state.stop ? state.stop.phase : "";
          applyStop(reduceStop(state.stop || freshStop(), { type: "stream-done", status: status }));
          if (prevPhase === "stopping" && state.stop.phase === "stopped") {
            state.userStops[runId] = {
              botId: state.botId,
              queued: !!(state.queuedIds && state.queuedIds.length),
              time: clockLabel(new Date())
            };
            announce("Run stopped");
            settleStoppedCards();
            if (bubble && acc) rememberPartial(runId, acc);
            const bot = currentBot();
            if (bot) {
              if (bot.status === "running") bot.status = "idle";
              bot.pending_permissions = 0;
            }
          }
          setWorking(false);
          if (state.stop.phase !== "stopped") {
            if (event === "error" && payload.error !== "tool round limit") showRunError("Run failed: " + (payload.error || "unknown error"));
          }
          stopStream();
          if (state.stop && state.stop.phase === "stopped") {
            const note = $("#run-note");
            if (note) { note.hidden = true; note.replaceChildren(); }
            renderBots();
            paintSubline(currentBot());
          }
          await loadThread();
          await refreshBot();
          loadState().catch(() => {});
          if (event === "error" && payload.error === "tool round limit" && currentBot() && currentBot().status === "running") {
            await refreshBot();
          }
          if (event === "done") pollActive();
          if (window.voiceOnRunEnd) {
            const speakFail = event !== "done" || status === "cancelled" || status === "stopped" || status === "error" || status === "timeout";
            window.voiceOnRunEnd(speakFail ? "" : voiceText, speakFail);
          }
          return;
        }
      }
    }
  } catch (err) {
    if (err.name === "AbortError") return;
    setWorking(false);
    if (window.voiceOnRunEnd) window.voiceOnRunEnd("", true);
    await loadThread();
  } finally {
    if (state.streaming === runId) {
      state.streaming = "";
      setWorking(false);
    }
  }
}
async function pollActive() {
  if (!state.botId) return;
  const b = await refreshBot();
  if (b && b.active_run_id && b.active_run_id !== state.streaming) follow(b.active_run_id);
}
$("#menu-btn").addEventListener("click", (e) => {
  e.stopPropagation();
  toggleBotMenu($("#menu-btn"));
});
document.addEventListener("click", (e) => {
  if (!e.target.closest("#roster-menu-wrap")) closeRosterMenu();
  if (!e.target.closest(".menu")) { closeMenu(); closeRoutineMenus(); }
});
$("#bot-menu").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn || !state.botId) return;
  closeMenu();
  const act = btn.dataset.act;
  const b = currentBot();
  try {
    if (act === "stop") { await requestStop(); }
    else if (act === "log") { openLog(true); }
    else if (act === "profile") { await openProfile(state.botId); }
    else if (act === "state") { await openState(btn); }
    else if (act === "pin") {
      await api("/api/bots/" + state.botId, {method:"PATCH", body: JSON.stringify({pinned: !(b && b.pinned)})});
      await loadBots();
    } else if (act === "hide") {
      const leaving = !(b && b.hidden);
      const run = async () => {
        await api("/api/bots/" + state.botId, {method:"PATCH", body: JSON.stringify({hidden: !(b && b.hidden)})});
        await loadBots();
        if (leaving) setView("bots");
      };
      if (leaving) confirmLeave(() => run().catch(err2 => showRunError(err2.message)));
      else await run();
    } else if (act === "duplicate") {
      confirmLeave(() => duplicateBot(state.botId).catch(err2 => showRunError(err2.message)));
    } else if (act === "archive") {
      confirmLeave(() => setArchived(state.botId, !(b && b.archived)).catch(err2 => showRunError(err2.message)));
    }
  } catch (err) {
    showRunError(err.message);
  }
});
// Archive keeps the bot, its thread, and its routines (paused). The main UI
// has no delete; DELETE /api/bots/{id} stays in the API.
function rosterRowIds() {
  const ids = [];
  document.querySelectorAll("#bot-list button.bot").forEach((b) => {
    const bid = b.getAttribute("data-bot-id") || "";
    if (bid) ids.push(bid);
  });
  return ids;
}
function focusRosterTarget(target) {
  if (!target || target.kind !== "row") {
    const h = document.querySelector("#view-bots h1");
    if (h) { h.tabIndex = -1; if (typeof h.focus === "function") h.focus(); }
    return;
  }
  const rows = document.querySelectorAll("#bot-list button.bot");
  for (const row of rows) {
    if ((row.getAttribute("data-bot-id") || "") === target.id) {
      if (typeof row.focus === "function") row.focus();
      return;
    }
  }
  const h = document.querySelector("#view-bots h1");
  if (h) { h.tabIndex = -1; if (typeof h.focus === "function") h.focus(); }
}
async function setArchived(id, archived, opts) {
  const existing = state.bots.find(x => x.id === id);
  const name = (existing && existing.name) || "bot";
  const prev = { view: state.view, botId: state.botId, showArchived: state.showArchived };
  const idsBefore = rosterRowIds();
  await api("/api/bots/" + id, {method:"PATCH", body: JSON.stringify({archived: !!archived})});
  await loadBots();
  if (archived) {
    state.showArchived = false;
    goHome();
    renderBots();
    showArchiveToast(id, name, prev);
    focusRosterTarget(archiveFocusTarget(isWide(), idsBefore, id));
    return;
  }
  dismissToast();
  const restore = opts && opts.restore;
  if (restore) {
    state.showArchived = !!restore.showArchived;
    renderBots();
    if (restore.view === "profile" && restore.botId) await openProfile(restore.botId, true);
    else if (restore.view === "log") {
      if (restore.botId) state.botId = restore.botId;
      openLog(true);
    } else if (restore.view === "chat" && restore.botId) await openBot(restore.botId, true);
    else if (state.botId === id) await refreshBot();
    return;
  }
  renderBots();
  focusRosterTarget(archiveFocusTarget(isWide(), idsBefore, id));
  if (state.botId === id) await refreshBot();
}
// profile-logic:begin
const PHX_WHEN = new Intl.DateTimeFormat("en-US", {
  timeZone: "America/Phoenix",
  weekday: "short", month: "short", day: "numeric",
  hour: "numeric", minute: "2-digit", hourCycle: "h12"
});
const PHX_DAY = new Intl.DateTimeFormat("en-CA", {
  timeZone: "America/Phoenix", year: "numeric", month: "2-digit", day: "2-digit"
});
const RESERVED_TLD = { example: 1, invalid: 1, test: 1, localhost: 1 };

function splitChipTokens(text) {
  return String(text == null ? "" : text).split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
}
function portOK(port) {
  if (!/^\d+$/.test(port || "")) return false;
  const n = Number(port);
  return n >= 1 && n <= 65535;
}
function ipv4ok(host) {
  const parts = String(host || "").split(".");
  if (parts.length !== 4) return false;
  return parts.every(x => /^\d{1,3}$/.test(x) && Number(x) <= 255);
}
function ipv6ok(host) {
  if (!/^[0-9a-fA-F:]+$/.test(host || "")) return false;
  const colons = (String(host).match(/:/g) || []).length;
  return colons >= 2 && colons <= 7;
}
function dnsLabelOK(label) {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(label || "");
}
function dnsok(host) {
  const labels = String(host || "").split(".");
  if (labels.length < 2) return false;
  if (!labels.every(dnsLabelOK)) return false;
  const tld = labels[labels.length - 1].toLowerCase();
  if (!/^[a-z]{2,24}$/.test(tld)) return false;
  if (RESERVED_TLD[tld]) return false;
  return true;
}
function hostEntryValid(raw) {
  let s = String(raw == null ? "" : raw).trim();
  if (!s || /[\s/]/.test(s)) return false;
  if (s.startsWith("[")) {
    const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
    if (!m) return false;
    return ipv6ok(m[1]) && (!m[2] || portOK(m[2]));
  }
  const colons = (s.match(/:/g) || []).length;
  if (colons >= 2) return ipv6ok(s);
  let host = s;
  if (colons === 1) {
    const i = s.lastIndexOf(":");
    host = s.slice(0, i);
    if (!portOK(s.slice(i + 1))) return false;
  }
  if (host.startsWith("*.")) host = host.slice(2);
  if (!host || host.startsWith(".") || host.endsWith(".")) return false;
  if (ipv4ok(host)) return true;
  return dnsok(host);
}
function repoPartOK(p) {
  if (!p || p.length > 100) return false;
  if (p.indexOf("..") >= 0) return false;
  if (!/^[a-z0-9._-]+$/.test(p)) return false;
  if (p[0] === "." || p[0] === "-" || p[p.length - 1] === ".") return false;
  return true;
}
function repoEntryValid(raw) {
  const s = String(raw == null ? "" : raw).trim();
  if (/[\r\n\t\0]/.test(s)) return false;
  const slash = s.indexOf("/");
  if (slash <= 0 || slash !== s.lastIndexOf("/")) return false;
  const owner = s.slice(0, slash).toLowerCase();
  const repo = s.slice(slash + 1).toLowerCase();
  return repoPartOK(owner) && repoPartOK(repo) && !repo.endsWith(".git");
}
function chipInvalidMessage(kind, value) {
  const v = String(value == null ? "" : value);
  if (kind === "repo" || kind === "github") {
    return '"' + v + '" is not owner/repo. Use a name like example-org/notes-site.';
  }
  return '"' + v + '" is not a host name. Use a name like docs.example.org.';
}
function sameList(a, b) {
  const aa = a || [];
  const bb = b || [];
  if (aa.length !== bb.length) return false;
  for (let i = 0; i < aa.length; i++) if (aa[i] !== bb[i]) return false;
  return true;
}
function sameTools(a, b) {
  if (a == null && b == null) return true;
  if (a == null || b == null) return false;
  const as = a.slice().sort();
  const bs = b.slice().sort();
  return sameList(as, bs);
}
function dirtyFieldLabels(base, cur) {
  const out = [];
  const b = base || {};
  const c = cur || {};
  if ((b.name || "") !== (c.name || "")) out.push("Name");
  if ((b.label || "") !== (c.label || "")) out.push("Label");
  if ((b.description || "") !== (c.description || "")) out.push("Description");
  if ((b.model || "") !== (c.model || "")) out.push("Model override");
  const bm = b.mark || {};
  const cm = c.mark || {};
  if ((bm.shape || "") !== (cm.shape || "") || String(bm.color || "").toLowerCase() !== String(cm.color || "").toLowerCase()) out.push("Mark");
  if (!sameList(b.grants, c.grants)) out.push("Grants");
  if (!sameList(b.net, c.net)) out.push("Network allowlist");
  if (!sameList(b.ssh, c.ssh)) out.push("SSH allowlist");
  if (!sameList(b.github, c.github)) out.push("GitHub repositories");
  if (!sameTools(b.server_tools, c.server_tools)) out.push("Server tools");
  return out;
}
function scheduleFromBuilder(mode, n, unit) {
  if (mode !== "every") return "";
  const num = typeof n === "number" ? n : Number(String(n == null ? "" : n).trim());
  if (!Number.isInteger(num) || num <= 0) return "";
  const suffix = unit === "minutes" ? "m" : unit === "hours" ? "h" : unit === "days" ? "d" : "";
  if (!suffix) return "";
  return "every " + num + suffix;
}
function scheduleLabel(schedule) {
  const raw = String(schedule == null ? "" : schedule).trim();
  const s = raw.toLowerCase();
  if (s === "once") return "once";
  const body = s.replace(/^every\s+/, "");
  const m = body.match(/^(\d+)(s|m|h|d)$/);
  if (!m) return raw;
  const n = Number(m[1]);
  const unit = m[2];
  let word = "sec";
  if (unit === "m") word = "min";
  else if (unit === "h") word = n === 1 ? "hour" : "hours";
  else if (unit === "d") word = n === 1 ? "day" : "days";
  return "every " + n + " " + word;
}
function intervalMs(schedule) {
  const s = String(schedule == null ? "" : schedule).trim().toLowerCase().replace(/^every\s+/, "");
  const m = s.match(/^(\d+)(s|m|h|d)$/);
  if (!m) return 0;
  const n = Number(m[1]);
  if (m[2] === "s") return n * 1000;
  if (m[2] === "m") return n * 60000;
  if (m[2] === "h") return n * 3600000;
  return n * 86400000;
}
function phxParts(ms) {
  const o = {};
  for (const part of PHX_WHEN.formatToParts(new Date(ms))) {
    if (part.type !== "literal") o[part.type] = part.value;
  }
  return o;
}
function phxDayKey(ms) {
  return PHX_DAY.format(new Date(ms));
}
function dayDiff(fromKey, toKey) {
  const a = String(fromKey || "").split("-").map(Number);
  const b = String(toKey || "").split("-").map(Number);
  const ua = Date.UTC(a[0], a[1] - 1, a[2]);
  const ub = Date.UTC(b[0], b[1] - 1, b[2]);
  return Math.round((ub - ua) / 86400000);
}
function clockFrom(p) {
  return String(p.hour || "") + ":" + String(p.minute || "00") + (p.dayPeriod ? " " + p.dayPeriod : "");
}
function routineWhen(iso, nowMs) {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (isNaN(t)) return "";
  const now = typeof nowMs === "number" ? nowMs : Date.now();
  const diff = dayDiff(phxDayKey(now), phxDayKey(t));
  const p = phxParts(t);
  let when = (p.month || "") + " " + (p.day || "");
  if (diff === 0) when = "today";
  else if (diff === 1) when = "tomorrow";
  else if (diff === -1) when = "yesterday";
  else if (diff >= -6 && diff <= 6) when = p.weekday || when;
  return when + " " + clockFrom(p) + " MST";
}
function routineRelative(iso, nowMs) {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (isNaN(t)) return "";
  const now = typeof nowMs === "number" ? nowMs : Date.now();
  const future = t >= now;
  let mins = Math.round(Math.abs(t - now) / 60000);
  if (mins < 0) mins = 0;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  let body = m + "m";
  if (h && m) body = h + "h " + m + "m";
  else if (h) body = h + "h";
  return future ? "in " + body : body + " ago";
}
function routineMeta(timer, nowMs) {
  const t = timer || {};
  if (!t.enabled) return "Paused · turn on to schedule";
  const next = t.next_fire_at ? routineWhen(t.next_fire_at, nowMs) : "";
  const rel = t.next_fire_at ? routineRelative(t.next_fire_at, nowMs) : "";
  const last = t.last_fire_at ? routineWhen(t.last_fire_at, nowMs) : "";
  const bits = [];
  if (next) bits.push("Next: " + next);
  if (rel) bits.push(rel);
  if (last) bits.push("Last: " + last);
  return bits.join(" · ");
}
function routinePreview(schedule, nowMs) {
  const label = scheduleLabel(schedule);
  const ms = intervalMs(schedule);
  if (!label || !ms) return "";
  const now = typeof nowMs === "number" ? nowMs : Date.now();
  const p = phxParts(now + ms);
  const when = (p.weekday || "") + " " + (p.month || "") + " " + (p.day || "") + " " + clockFrom(p) + " MST";
  return "Runs " + label + ", first run " + when;
}
function builderFromSchedule(schedule) {
  const s = String(schedule == null ? "" : schedule).trim().toLowerCase().replace(/^every\s+/, "");
  const m = s.match(/^(\d+)(m|h|d)$/);
  if (!m) return null;
  const unit = m[2] === "m" ? "minutes" : m[2] === "h" ? "hours" : "days";
  return { n: Number(m[1]), unit: unit };
}
// profile-logic:end
const GRANT_ORDER = ["net", "git", "github", "ssh", "build"];
const CHIP_KINDS = ["net", "ssh", "github"];
const CHIP_HELP = {
  net: "Press Enter or comma to add. Paste a list to add several.",
  ssh: "Empty allows no hosts.",
  github: "An empty GitHub list allows no repositories. It does not inherit the policy list. It can only narrow the policy ceiling."
};
const DIRTY_FIELDS = [
  ["Name", "fld-name"],
  ["Label", "fld-label"],
  ["Description", "fld-description"],
  ["Model override", "fld-model"],
  ["Mark", "fld-mark"],
  ["Grants", "fld-grants"],
  ["Network allowlist", "fld-net"],
  ["SSH allowlist", "fld-ssh"],
  ["GitHub repositories", "fld-github"],
  ["Server tools", "fld-tools"]
];
let navBypass = false;

function cloneTpl(id) {
  const tpl = document.getElementById(id);
  const node = tpl && tpl.content && tpl.content.firstElementChild;
  return node ? node.cloneNode(true) : document.createElement("span");
}
function alertSvg() { return cloneTpl("tpl-alert"); }
function moreSvg() { return cloneTpl("tpl-more"); }
function chipKindOf(kind) { return kind === "github" ? "repo" : "host"; }
function chipValid(kind, value) {
  return kind === "github" ? repoEntryValid(value) : hostEntryValid(value);
}
function ensureChipState() {
  if (!state.chipLists) state.chipLists = { net: [], ssh: [], github: [] };
  for (const k of CHIP_KINDS) if (!state.chipLists[k]) state.chipLists[k] = [];
}
function setChipList(kind, values) {
  ensureChipState();
  state.chipLists[kind] = (values || []).map(v => ({ value: String(v), bad: !chipValid(kind, v), fresh: false }));
  paintChips(kind);
}
function addChipTokens(kind, text, markFresh) {
  ensureChipState();
  const have = new Set(state.chipLists[kind].map(c => c.value));
  let added = false;
  for (const token of splitChipTokens(text)) {
    if (have.has(token)) continue;
    have.add(token);
    state.chipLists[kind].push({ value: token, bad: !chipValid(kind, token), fresh: !!markFresh });
    added = true;
  }
  if (!added) return;
  paintChips(kind);
  paintDirty();
  if (markFresh) {
    setTimeout(() => {
      for (const c of state.chipLists[kind] || []) c.fresh = false;
      paintChips(kind);
    }, 2000);
  }
}
function removeChipAt(kind, index) {
  ensureChipState();
  state.chipLists[kind].splice(index, 1);
  paintChips(kind);
  paintDirty();
}
function paintChips(kind) {
  ensureChipState();
  const box = $("#chips-" + kind);
  const input = $("#profile-" + kind);
  if (!box || !input) return;
  box.querySelectorAll(".chip").forEach(n => n.remove());
  const list = state.chipLists[kind];
  for (let i = 0; i < list.length; i++) {
    const item = list[i];
    const chip = el("span", "chip" + (item.fresh ? " is-new" : "") + (item.bad ? " bad" : ""));
    chip.append(document.createTextNode(item.value));
    const x = el("button", "chip-x", "×");
    x.type = "button";
    x.setAttribute("aria-label", "Remove " + item.value);
    x.addEventListener("click", () => { removeChipAt(kind, i); input.focus(); });
    chip.append(x);
    box.insertBefore(chip, input);
  }
  const bad = list.find(c => c.bad);
  box.classList.toggle("is-error", !!bad);
  const help = $("#help-" + kind);
  if (help) {
    help.replaceChildren();
    if (bad) {
      help.classList.add("is-error");
      help.append(alertSvg(), document.createTextNode(chipInvalidMessage(chipKindOf(kind), bad.value)));
    } else {
      help.classList.remove("is-error");
      help.textContent = CHIP_HELP[kind];
    }
  }
}
function commitChipInput(kind) {
  const input = $("#profile-" + kind);
  if (!input) return;
  const text = input.value;
  input.value = "";
  if (String(text || "").trim()) addChipTokens(kind, text, true);
}
function onChipKey(kind, e) {
  const input = e.target;
  if (e.key === "Enter" || e.key === ",") {
    e.preventDefault();
    commitChipInput(kind);
    return;
  }
  if (e.key === "Backspace" && !input.value) {
    ensureChipState();
    if (state.chipLists[kind].length) {
      e.preventDefault();
      removeChipAt(kind, state.chipLists[kind].length - 1);
    }
  }
}
function onChipPaste(kind, e) {
  const text = (e.clipboardData && e.clipboardData.getData("text")) || "";
  if (!text) return;
  e.preventDefault();
  addChipTokens(kind, text, true);
  e.target.value = "";
}
function chipValues(kind) {
  ensureChipState();
  return state.chipLists[kind].map(c => c.value);
}
function badChipMessage() {
  ensureChipState();
  for (const kind of CHIP_KINDS) {
    const bad = state.chipLists[kind].find(c => c.bad);
    if (bad) return chipInvalidMessage(chipKindOf(kind), bad.value);
  }
  return "";
}
function readGrants() {
  const on = new Set();
  document.querySelectorAll("[data-grant]").forEach(b => {
    if (b.getAttribute("aria-checked") === "true") on.add(b.getAttribute("data-grant"));
  });
  return GRANT_ORDER.filter(g => on.has(g));
}
function serverToolsExplicit() {
  const btn = $("#server-tools-explicit");
  return !!(btn && btn.getAttribute("aria-checked") === "true");
}
$("#profile-form").addEventListener("submit", (e) => { e.preventDefault(); saveProfile(); });
function serverToolsPayload() {
  const picked = document.querySelector("#server-tools-seg [aria-checked='true']");
  const value = picked && picked.id === "server-tools-explicit" ? "explicit" : "inherit";
  if (value !== "explicit") return null;
  const list = [];
  for (const box of document.querySelectorAll('#server-tools-picks input[name="server-tool"]')) {
    if (box.checked) list.push(box.value);
  }
  return list;
}
function readProfile() {
  return {
    name: $("#profile-name") ? $("#profile-name").value : "",
    label: $("#profile-label") ? $("#profile-label").value : "",
    description: $("#profile-description") ? $("#profile-description").value : "",
    model: $("#profile-model") ? $("#profile-model").value.trim() : "",
    mark: { shape: (state.mark && state.mark.shape) || "circle", color: String((state.mark && state.mark.color) || "").toLowerCase() },
    grants: readGrants(),
    net: chipValues("net"),
    ssh: chipValues("ssh"),
    github: chipValues("github"),
    server_tools: serverToolsPayload()
  };
}
function profilePayload() {
  const cur = readProfile();
  const model = cur.model;
  return {
    name: cur.name,
    label: cur.label,
    description: cur.description,
    mark: { shape: state.mark.shape, color: state.mark.color },
    model: model || null,
    grants: cur.grants,
    net_allow: cur.net,
    ssh_allow: cur.ssh,
    github_allow: cur.github,
    server_tools: cur.server_tools
  };
}
function profileDirty() {
  if (navBypass) return false;
  if (state.view !== "profile" || !state.profileBase) return false;
  return dirtyFieldLabels(state.profileBase, readProfile()).length > 0;
}
function changeCountLabel(n) {
  return n === 1 ? "1 change" : n + " changes";
}
const DIRTY_CONTROLS = {
  "Name": "profile-name",
  "Label": "profile-label",
  "Description": "profile-description",
  "Model override": "profile-model",
  "Mark": "mark-block",
  "Network allowlist": "chips-net",
  "SSH allowlist": "chips-ssh",
  "GitHub repositories": "chips-github",
  "Server tools": "server-tools"
};
function changedNote(node) {
  if (!node) return null;
  if (node.classList.contains("changed")) return node;
  return node.querySelector(":scope > .changed");
}
function clearGrantChips() {
  document.querySelectorAll(".grant .grant-name").forEach(function (wrap) {
    const name = wrap.querySelector("b");
    if (name) wrap.replaceWith(name);
    else wrap.remove();
  });
}
function paintFieldMarks(labels) {
  document.querySelectorAll(".is-dirty").forEach(n => n.classList.remove("is-dirty"));
  clearGrantChips();
  for (const pair of DIRTY_FIELDS) {
    const ch = changedNote(document.getElementById(pair[1]));
    if (ch) ch.hidden = true;
  }
  if (state.draft) return;
  const set = new Set(labels || []);
  for (const pair of DIRTY_FIELDS) {
    const ch = changedNote(document.getElementById(pair[1]));
    if (ch) ch.hidden = !set.has(pair[0]);
  }
  for (const label in DIRTY_CONTROLS) {
    if (!set.has(label)) continue;
    const ctl = document.getElementById(DIRTY_CONTROLS[label]);
    if (ctl) ctl.classList.add("is-dirty");
  }
  if (!set.has("Grants") || !state.profileBase) return;
  const base = new Set(state.profileBase.grants || []);
  const cur = new Set(readGrants());
  for (const g of GRANT_ORDER) {
    if (base.has(g) === cur.has(g)) continue;
    const row = document.getElementById("grant-" + g);
    if (!row) continue;
    row.classList.add("is-dirty");
    const name = row.querySelector("b");
    const chip = el("span", "chip changed-chip", "Changed");
    chip.setAttribute("aria-label", "Changed since last save");
    if (name) {
      const wrap = document.createElement("span");
      wrap.className = "grant-name";
      name.replaceWith(wrap);
      wrap.append(name, chip);
    } else row.append(chip);
  }
}
function paintSaveBar() {
  if (state.saveErrorChip && !badChipMessage()) { state.saveError = ""; state.saveErrorChip = false; }
  const bar = $("#savebar");
  if (!bar) return;
  const labels = state.profileBase ? dirtyFieldLabels(state.profileBase, readProfile()) : [];
  const draft = !!state.draft;
  const show = state.view === "profile" && (draft || labels.length > 0);
  bar.hidden = !show;
  bar.classList.toggle("is-draft", draft);
  const phone = window.matchMedia("(max-width: 540px)").matches;
  const lead = $("#save-lead");
  const sub = $("#save-sub");
  const fields = $("#save-fields");
  const go = $("#save-go-label");
  if (lead) {
    if (draft) lead.textContent = phone ? "New bot" : "New bot · nothing is created until you press Create";
    else lead.textContent = phone ? changeCountLabel(labels.length) : "Unsaved changes";
  }
  if (sub) sub.hidden = !(draft && phone);
  if (go) go.textContent = draft ? "Create bot" : (phone ? "Save" : "Save changes");
  if (fields) {
    if (state.saveError) {
      fields.textContent = state.saveError;
      fields.classList.add("is-error");
      fields.classList.remove("wide-only");
    } else if (draft) {
      fields.textContent = "";
      fields.classList.remove("is-error");
    } else {
      fields.textContent = labels.length ? "· " + labels.join(", ") : "";
      fields.classList.remove("is-error");
      fields.classList.add("wide-only");
    }
  }
}
function paintDirty() {
  const labels = state.profileBase ? dirtyFieldLabels(state.profileBase, readProfile()) : [];
  paintFieldMarks(labels);
  paintSaveBar();
}
function paintWarnings(list) {
  const box = $("#profile-warn");
  const text = $("#profile-warn-text");
  if (!box || !text) return;
  const words = (list || []).filter(Boolean);
  if (!words.length) {
    box.hidden = true;
    text.textContent = "";
    return;
  }
  let msg = words.join(" ");
  if (msg.indexOf("Saving still works") < 0) msg += " Saving still works.";
  text.textContent = msg;
  box.hidden = false;
}
function setGrants(list) {
  const on = new Set(list || []);
  document.querySelectorAll("[data-grant]").forEach(b => {
    b.setAttribute("aria-checked", on.has(b.getAttribute("data-grant")) ? "true" : "false");
  });
}
function setServerMode(explicit) {
  const inherit = $("#server-tools-inherit");
  const chosen = $("#server-tools-explicit");
  if (inherit) inherit.setAttribute("aria-checked", explicit ? "false" : "true");
  if (chosen) chosen.setAttribute("aria-checked", explicit ? "true" : "false");
  syncServerToolsMode();
}
function syncServerToolsMode() {
  const on = serverToolsExplicit();
  const picks = $("#server-tools-picks");
  if (picks) picks.classList.toggle("is-off", !on);
  for (const box of document.querySelectorAll('#server-tools-picks input[name="server-tool"]')) box.disabled = !on;
}
const SERVER_TOOL_NAMES = ["web_search", "x_search"];
function paintServerTools(selected) {
  const box = $("#server-tools-picks");
  if (!box) return;
  box.replaceChildren();
  const have = new Set(selected || []);
  const names = SERVER_TOOL_NAMES.slice();
  for (const n of have) if (!names.includes(n)) names.push(n);
  for (const name of names) {
    const label = el("label", "tool-pick");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = "server-tool";
    input.value = name;
    input.checked = have.has(name);
    input.addEventListener("change", paintDirty);
    label.append(input, document.createTextNode(" " + name));
    box.append(label);
  }
  syncServerToolsMode();
}
async function duplicateBot(id) {
  const full = await api("/api/bots/" + id);
  const timers = await api("/api/bots/" + id + "/timers");
  const baseName = full.name + " copy";
  let name = baseName;
  let created = null;
  for (let n = 2; n < 30; n++) {
    try {
      created = await api("/api/bots", {method:"POST", body: JSON.stringify({
        name, label: full.label || "", description: full.description || "",
        mark: full.mark, model: full.model,
        server_tools: full.server_tools == null ? null : full.server_tools
      })});
      break;
    } catch (err) {
      if (!/exists/i.test(err.message)) throw err;
      name = baseName + " " + n;
    }
  }
  if (!created) throw new Error("could not duplicate");
  for (const t of timers) {
    await api("/api/bots/" + created.id + "/timers", {method:"POST", body: JSON.stringify({
      name: t.name, schedule: t.schedule, prompt: t.prompt, enabled: t.enabled
    })});
  }
  await loadBots();
  await openProfile(created.id);
}
function paintMarkPicker() {
  const shapes = $("#shape-picker");
  shapes.replaceChildren();
  for (const shape of SHAPES) {
    const b = el("button", "shape-btn");
    b.type = "button";
    b.setAttribute("aria-label", SHAPE_NAMES[shape] || shape);
    b.title = SHAPE_NAMES[shape] || shape;
    b.setAttribute("aria-pressed", shape === state.mark.shape ? "true" : "false");
    b.append(markEl({shape, color: state.mark.color}));
    b.addEventListener("click", () => { state.mark.shape = shape; paintMarkPicker(); paintDirty(); });
    shapes.append(b);
  }
  const colors = $("#color-picker");
  colors.replaceChildren();
  // A colour set outside the palette (API or the custom input) is shown as
  // one more swatch, selected, so the current colour is never hidden.
  // Matching a preset ignores case and does not rewrite the stored value.
  const sameColor = (a, b) => String(a || "").toLowerCase() === String(b || "").toLowerCase();
  const known = COLORS.some(c => sameColor(c, state.mark.color));
  const list = known ? COLORS : COLORS.concat([state.mark.color]);
  for (const color of list) {
    const b = el("button", "swatch");
    b.type = "button";
    b.style.background = color;
    let named = COLOR_NAMES[color];
    if (!named) {
      for (const k in COLOR_NAMES) if (sameColor(k, color)) named = COLOR_NAMES[k];
    }
    const name = named ? named : "Current colour " + color;
    b.setAttribute("aria-label", name);
    b.title = name;
    b.setAttribute("aria-pressed", sameColor(color, state.mark.color) ? "true" : "false");
    b.addEventListener("click", () => { state.mark.color = color; paintMarkPicker(); paintDirty(); });
    colors.append(b);
  }
  const preview = $("#mark-preview");
  if (preview) preview.replaceChildren(markEl(state.mark));
  paintMark($("#profile-head-mark"), state.mark);
  if (/^#[0-9a-fA-F]{6}$/.test(state.mark.color || "")) $("#color-custom").value = state.mark.color;
  const adv = $("#mark-advisory");
  if (adv) {
    const notes = contrastAdvisories(state.mark.color);
    adv.hidden = !notes.length;
    adv.textContent = notes.join(" ");
  }
}
function syncProfileHeadingName() {
  const name = $("#profile-name").value.trim();
  $("#profile-head-name").textContent = name || "Profile";
  if (state.draft && !name) $("#profile-head-name").textContent = "New bot";
}
function syncProfileChrome() {
  const draft = !!state.draft;
  const access = state.profilePane === "access";
  const chip = $("#draft-chip");
  const sub = $("#draft-sub");
  const kicker = $("#profile-kicker");
  const crumb = $("#access-crumb");
  const log = $("#profile-log");
  const menu = $("#profile-menu");
  if (chip) chip.hidden = !draft;
  if (sub) sub.hidden = !draft;
  if (kicker) kicker.hidden = draft;
  if (crumb) crumb.hidden = !access;
  if (log) log.hidden = draft;
  if (menu) menu.hidden = draft;
  const routineDraft = $("#routine-draft");
  const routineLive = $("#routine-live");
  const routineAside = $("#routine-aside");
  if (routineDraft) routineDraft.hidden = !draft;
  if (routineLive) routineLive.hidden = draft;
  if (routineAside) routineAside.hidden = draft;
  const permDraft = $("#perm-draft");
  const permEditor = $("#perm-editor");
  const permRules = $("#perm-rules");
  const permSug = $("#perm-suggestions");
  const permHead = $("#perm-sug-head");
  if (permDraft) permDraft.hidden = !draft;
  if (permEditor) permEditor.hidden = draft;
  if (permRules) permRules.hidden = draft;
  if (permSug) permSug.hidden = draft;
  if (permHead) permHead.hidden = draft;
}
function setProfilePane(pane) {
  state.profilePane = pane === "access" ? "access" : "main";
  const access = state.profilePane === "access";
  const main = $("#profile-main");
  const sub = $("#profile-access");
  const navMain = $("#profile-nav-main");
  const navAccess = $("#profile-nav-access");
  const layout = document.querySelector(".profile-layout");
  const view = $("#view-profile");
  if (main) main.hidden = access;
  if (sub) sub.hidden = !access;
  if (navMain) navMain.hidden = access;
  if (navAccess) navAccess.hidden = !access;
  if (layout) layout.classList.toggle("is-access", access);
  if (view) view.classList.toggle("is-access", access);
  syncProfileChrome();
  resetScrollTops(document.querySelectorAll(".profile-layout, .profile-col"));
  bindProfileSpy();
}
function profileScroller() {
  return isWide() ? $("#profile-col") : document.querySelector(".profile-layout");
}
function profileNav() {
  return state.profilePane === "access" ? $("#profile-nav-access") : $("#profile-nav-main");
}
function profileSectionNodes() {
  const nav = profileNav();
  if (!nav) return [];
  const out = [];
  nav.querySelectorAll("[data-sec]").forEach(b => {
    const n = document.getElementById(b.getAttribute("data-sec"));
    if (n) out.push(n);
  });
  return out;
}
function setProfileNavCurrent(id) {
  const nav = profileNav();
  if (!nav) return;
  nav.querySelectorAll("[data-sec]").forEach(b => {
    if (id && b.getAttribute("data-sec") === id) b.setAttribute("aria-current", "true");
    else b.removeAttribute("aria-current");
  });
}
function nearestProfileSection() {
  const scroller = profileScroller();
  const sections = profileSectionNodes();
  if (!scroller || !sections.length || scroller.clientHeight <= 0) return "";
  const overflow = scroller.scrollHeight - scroller.clientHeight;
  if (overflow > 2 && scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight <= 2) {
    return sections[sections.length - 1].id || "";
  }
  const edge = scroller.getBoundingClientRect().top + 16;
  let current = sections[0].id || "";
  for (const sec of sections) {
    if (sec.getBoundingClientRect().top <= edge + 1) current = sec.id || current;
  }
  return current;
}
function syncProfileNav() {
  const id = nearestProfileSection();
  if (id) setProfileNavCurrent(id);
}
function onProfileColumnScroll() {
  syncProfileNav();
}
let profileSpy = null;
let profileScrollEl = null;
function bindProfileSpy() {
  const scroller = profileScroller();
  if (profileSpy) { profileSpy.disconnect(); profileSpy = null; }
  if (profileScrollEl && profileScrollEl !== scroller) {
    profileScrollEl.removeEventListener("scroll", onProfileColumnScroll);
    profileScrollEl = null;
  }
  const sections = profileSectionNodes();
  if (scroller && typeof IntersectionObserver === "function") {
    profileSpy = new IntersectionObserver(() => { syncProfileNav(); }, {
      root: scroller,
      rootMargin: "-8px 0px -60% 0px",
      threshold: [0, 0.01, 0.1, 0.25, 0.5, 1]
    });
    for (const sec of sections) profileSpy.observe(sec);
  }
  if (scroller && profileScrollEl !== scroller) {
    scroller.addEventListener("scroll", onProfileColumnScroll, { passive: true });
    profileScrollEl = scroller;
  }
  syncProfileNav();
}
function scrollProfileTo(id) {
  const target = document.getElementById(id);
  if (!target) return;
  const scroller = profileScroller();
  if (!scroller) return;
  const top = target.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scroller.scrollTop;
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  scroller.scrollTo({ top: Math.max(0, top - 8), behavior: reduce ? "auto" : "smooth" });
  setProfileNavCurrent(id);
}
function applyBotFields(b) {
  const bot = b || {};
  state.mark = { shape: (bot.mark && bot.mark.shape) || "circle", color: (bot.mark && bot.mark.color) || COLORS[0] };
  $("#profile-name").value = bot.name || "";
  $("#profile-label").value = bot.label || "";
  $("#profile-description").value = bot.description || "";
  $("#profile-model").value = bot.model || "";
  setGrants(bot.grants || []);
  setChipList("net", bot.net_allow || []);
  setChipList("ssh", bot.ssh_allow || []);
  setChipList("github", bot.github_allow || []);
  const tools = bot.server_tools;
  setServerMode(tools != null);
  paintServerTools(Array.isArray(tools) ? tools : []);
  paintWarnings(bot.warnings || []);
  paintMarkPicker();
  syncProfileHeadingName();
}
function blankDraftFields() {
  state.mark = { shape: "circle", color: COLORS[0] };
  $("#profile-name").value = "";
  $("#profile-label").value = "";
  $("#profile-description").value = "";
  $("#profile-model").value = "";
  setGrants([]);
  setChipList("net", []);
  setChipList("ssh", []);
  setChipList("github", []);
  setServerMode(false);
  paintServerTools([]);
  paintWarnings([]);
  const err = $("#profile-err");
  if (err) { err.style.color = ""; err.textContent = ""; }
  paintMarkPicker();
  syncProfileHeadingName();
}
function applySnapshot(snap) {
  const s = snap || {};
  state.mark = { shape: (s.mark && s.mark.shape) || "circle", color: (s.mark && s.mark.color) || COLORS[0] };
  $("#profile-name").value = s.name || "";
  $("#profile-label").value = s.label || "";
  $("#profile-description").value = s.description || "";
  $("#profile-model").value = s.model || "";
  setGrants(s.grants || []);
  setChipList("net", s.net || []);
  setChipList("ssh", s.ssh || []);
  setChipList("github", s.github || []);
  setServerMode(s.server_tools != null);
  paintServerTools(Array.isArray(s.server_tools) ? s.server_tools : []);
  paintMarkPicker();
  syncProfileHeadingName();
  state.saveError = "";
  state.saveErrorChip = false;
  paintDirty();
}
function showStatusToast(message, undo) {
  const toast = $("#toast");
  if (!toast) return;
  clearTimeout(state.toastTimer);
  let text = message == null ? "" : String(message);
  const kids = [];
  if (typeof undo === "function") {
    const undoAt = text.lastIndexOf("Undo");
    kids.push(el("span", "toast-copy", undoAt >= 0 ? text.slice(0, undoAt) : text));
    const undoBtn = btn("ghost", "Undo");
    undoBtn.addEventListener("click", function () {
      dismissToast();
      const rulesView = document.getElementById("view-rules");
      if (rulesView && rulesView.classList.contains("on")) {
        const bridge = rulesView.querySelector("#rules-list h3[data-rules-focus]") || document.getElementById("rules-title");
        if (bridge && typeof bridge.focus === "function") bridge.focus({ preventScroll: true });
      }
      undo();
    });
    kids.push(undoBtn);
  } else {
    kids.push(el("span", "toast-copy", text));
  }
  toast.replaceChildren.apply(toast, kids);
  toast.hidden = false;
  const ms = arguments.length > 1 ? ((typeof ARCHIVE_TOAST_MS === "number") ? ARCHIVE_TOAST_MS : 6000) : 2000;
  state.toastTimer = setTimeout(dismissToast, ms);
}
function focusProfileHeading() {
  const h = $("#profile-heading");
  if (h && typeof h.focus === "function") h.focus({ preventScroll: true });
}
function rescueFocus(fallback) {
  const a = document.activeElement;
  if (!a || a === document.body || !document.contains(a) || (a.closest && a.closest("[hidden]"))) (fallback || focusProfileHeading)();
}
function setSaving(on) {
  state.saving = !!on;
  const btn = $("#save-go");
  const discard = $("#save-discard");
  if (btn) {
    btn.classList.toggle("is-loading", !!on);
    btn.disabled = !!on;
    if (on) btn.setAttribute("aria-busy", "true");
    else btn.removeAttribute("aria-busy");
  }
  if (discard) discard.disabled = !!on;
}
async function saveProfile() {
  if (state.saving) return;
  const blocked = badChipMessage();
  if (blocked) {
    state.saveError = blocked;
    state.saveErrorChip = true;
    paintSaveBar();
    return;
  }
  state.saveError = "";
  state.saveErrorChip = false;
  paintSaveBar();
  setSaving(true);
  try {
    if (state.draft) {
      const bot = await api("/api/bots", { method: "POST", body: JSON.stringify(profilePayload()) });
      await loadBots();
      navBypass = true;
      try {
        await openBot(bot.id, false);
        commitLevel({ view: "chat", bot: bot.id }, "replace");
      } finally { navBypass = false; }
      return;
    }
    if (!state.botId) return;
    const updated = await api("/api/bots/" + state.botId, { method: "PATCH", body: JSON.stringify(profilePayload()) });
    if (updated) applyBotFields(updated);
    state.profileBase = readProfile();
    state.saveError = "";
    state.saveErrorChip = false;
    paintDirty();
    showStatusToast("Saved");
    announce("Saved");
    rescueFocus();
    await loadBots();
  } catch (err) {
    state.saveError = (state.draft ? "Couldn't create the bot. The daemon said: " : "Couldn't save. The daemon said: ") + (err && err.message ? err.message : String(err || ""));
    paintSaveBar();
    setSaving(false);
    rescueFocus(() => $("#save-go").focus());
  } finally {
    setSaving(false);
  }
}
function discardOpen() {
  const d = $("#discard-dialog");
  return !!d && !d.hidden;
}
function openDiscardDialog() {
  const d = $("#discard-dialog");
  const b = $("#discard-backdrop");
  if (!d) return;
  state.discardReturn = document.activeElement;
  d.hidden = false;
  if (b) b.hidden = false;
  const keep = $("#discard-keep");
  if (keep) keep.focus();
}
function closeDiscardDialog() {
  const d = $("#discard-dialog");
  const b = $("#discard-backdrop");
  if (d) d.hidden = true;
  if (b) b.hidden = true;
}
function keepEditing() {
  state.pendingLeave = null;
  closeDiscardDialog();
  const back = state.discardReturn;
  state.discardReturn = null;
  if (back && document.contains(back) && typeof back.focus === "function") back.focus();
}
function allowLeave(proceed) {
  navBypass = true;
  return Promise.resolve().then(proceed).finally(() => { navBypass = false; });
}
function confirmLeave(proceed) {
  if (navBypass || !profileDirty()) return Promise.resolve().then(proceed);
  state.pendingLeave = proceed;
  openDiscardDialog();
  return Promise.resolve();
}
function discardAndLeave() {
  const fn = state.pendingLeave;
  state.pendingLeave = null;
  closeDiscardDialog();
  allowLeave(fn || function () {});
}
function stayingLevel() {
  if (state.draft) return { view: "draft", bot: null };
  return { view: "profile", bot: state.botId };
}
function leaveProfile() {
  if (backAction(history.state) === "back") {
    state.expectPop = true;
    history.back();
    return;
  }
  const parent = parentLevel(parseLevel(location.pathname, location.hash, base(), history.state, location.search));
  commitLevel(parent, "replace");
  if (parent.view === "chat" && parent.bot) openBot(parent.bot, false);
  else if (parent.view === "log") openLog(false);
  else if (parent.view === "rules") openRules(parent.bot || "", false);
  else goHome(false);
}
function discardSaveBar() {
  if (state.draft) {
    allowLeave(leaveProfile);
    return;
  }
  applySnapshot(state.profileBase);
  focusProfileHeading();
}
function showRoutineErr(err) {
  const note = $("#routine-err");
  if (!note) return;
  note.hidden = !err;
  note.textContent = err ? (err.message || String(err)) : "";
}
function closeRoutineForm() {
  state.routineEdit = "";
  const form = $("#routine-form");
  if (form) form.hidden = true;
  const add = $("#routine-add");
  if (add) add.textContent = "Add routine";
  showRoutineErr(null);
}
function setRoutineUnit(unit) {
  document.querySelectorAll("#routine-unit [data-unit]").forEach(b => {
    const on = b.getAttribute("data-unit") === unit;
    b.setAttribute("aria-checked", on ? "true" : "false");
    b.tabIndex = on ? 0 : -1;
  });
}
function routineUnit() {
  const on = document.querySelector("#routine-unit [aria-checked='true']");
  return on ? on.getAttribute("data-unit") : "days";
}
function paintRoutinePreview() {
  const n = $("#routine-n");
  const out = $("#routine-preview");
  if (!out) return;
  const schedule = scheduleFromBuilder("every", n ? n.value : "", routineUnit());
  out.textContent = schedule ? routinePreview(schedule, Date.now()) : "";
}
function openRoutineForm(timer) {
  const form = $("#routine-form");
  if (!form) return;
  form.hidden = false;
  state.routineEdit = timer && timer.id ? timer.id : "";
  $("#routine-name").value = timer && timer.name ? timer.name : "";
  $("#routine-prompt").value = timer && timer.prompt ? timer.prompt : "";
  const parsed = builderFromSchedule(timer && timer.schedule);
  if (parsed) {
    $("#routine-n").value = String(parsed.n);
    setRoutineUnit(parsed.unit);
  } else if (timer && timer.schedule) {
    $("#routine-n").value = "";
    setRoutineUnit("days");
  } else {
    $("#routine-n").value = "1";
    setRoutineUnit("days");
  }
  const add = $("#routine-add");
  if (add) add.textContent = state.routineEdit ? "Save routine" : "Add routine";
  showRoutineErr(null);
  paintRoutinePreview();
  const name = $("#routine-name");
  if (name) name.focus();
}
function closeRoutineMenus() {
  document.querySelectorAll("#routines .menu-pop").forEach(pop => {
    pop.hidden = true;
    const trigger = menuTriggerOf(pop);
    if (trigger) trigger.setAttribute("aria-expanded", "false");
  });
}
function bindRoutineMenu(pop) {
  pop.addEventListener("keydown", (e) => {
    if (handleMenuEscape(e, pop)) return;
    const items = [...pop.querySelectorAll("[role='menuitem']")].filter(b => !b.hidden && !b.disabled);
    const act = menuKeyAction(e.key, items, items.indexOf(document.activeElement));
    if (!act) return;
    if (act.close) {
      pop.hidden = true;
      const trigger = menuTriggerOf(pop);
      if (trigger) {
        trigger.setAttribute("aria-expanded", "false");
        if (e.key !== "Escape" && typeof trigger.focus === "function") trigger.focus();
      }
      return;
    }
    if (act.move != null && items[act.move]) {
      e.preventDefault();
      items[act.move].focus();
    }
  });
  pop.addEventListener("focusout", (e) => { handleMenuFocusOut(e, pop); });
}

async function submitRoutine() {
  if (!state.botId || state.draft) return;
  showRoutineErr(null);
  const schedule = scheduleFromBuilder("every", $("#routine-n").value, routineUnit());
  if (!schedule) {
    showRoutineErr(new Error("Enter a positive number of minutes, hours, or days."));
    return;
  }
  const body = {
    name: $("#routine-name").value.trim(),
    schedule: schedule,
    prompt: $("#routine-prompt").value
  };
  try {
    if (state.routineEdit) {
      await api("/api/timers/" + state.routineEdit, { method: "PATCH", body: JSON.stringify(body) });
    } else {
      body.enabled = true;
      await api("/api/bots/" + state.botId + "/timers", { method: "POST", body: JSON.stringify(body) });
    }
    closeRoutineForm();
    showStatusToast("Routine saved");
    await loadRoutines();
    rescueFocus(() => $("#routine-new").focus());
  } catch (err) { showRoutineErr(err); }
}
function openDraft(push) {
  if (push !== true) push = false;
  if (state.draft && state.view === "profile" && !push) return;
  if (!navBypass && profileDirty()) {
    confirmLeave(() => openDraft(push));
    return;
  }
  state.profileLoad = (state.profileLoad || 0) + 1;
  closeMenu();
  closeState();
  closeRosterMenu();
  closeRoutineForm();
  state.draft = true;
  state.botId = null;
  state.profilePane = "main";
  state.saveError = "";
  state.saveErrorChip = false;
  blankDraftFields();
  const rules = $("#perm-rules");
  const sug = $("#perm-suggestions");
  if (rules) rules.replaceChildren();
  if (sug) sug.replaceChildren();
  state.profileBase = readProfile();
  if (push) commitLevel({ view: "draft", bot: null }, "push");
  setProfilePane("main");
  setView("profile");
  setTitle();
  focusPane("profile");
  resetScrollTops(document.querySelectorAll(".profile-layout, .profile-col"));
  paintDirty();
  const name = $("#profile-name");
  if (name) name.focus();
}
async function openProfile(id, push = true) {
  if (!navBypass && state.view === "profile" && !state.draft && state.botId === id && state.profileBase) {
    setProfilePane("main");
    return;
  }
  if (!navBypass && profileDirty()) {
    confirmLeave(() => { openProfile(id, push); });
    return;
  }
  const seq = ++state.profileLoad;
  closeMenu();
  closeState();
  closeRoutineForm();
  const b = await api("/api/bots/" + id);
  if (seq !== state.profileLoad) return;
  state.draft = false;
  state.botId = id;
  const i = state.bots.findIndex(x => x.id === b.id);
  if (i >= 0) state.bots[i] = b; else state.bots.push(b);
  state.saveError = "";
  state.saveErrorChip = false;
  applyBotFields(b);
  state.profileBase = readProfile();
  const err = $("#profile-err");
  if (err) { err.style.color = ""; err.textContent = ""; }
  try { await loadRoutines(); } catch (err2) { showRoutineErr(err2); }
  if (seq !== state.profileLoad) return;
  try { await loadPermPanel(); } catch (err3) { showPermErr(err3); }
  if (seq !== state.profileLoad) return;
  if (push) commitLevel({ view: "profile", bot: id }, "push");
  setProfilePane("main");
  setView("profile");
  setTitle();
  focusPane("profile");
  resetScrollTops(document.querySelectorAll(".profile-layout, .profile-col"));
  paintDirty();
}

// scroll:begin
function resetScrollTops(nodes) {
  if (!nodes) return;
  for (const n of nodes) if (n) n.scrollTop = 0;
}
// scroll:end

function fillRoutineMeta(node, text) {
  if (!node) return;
  node.replaceChildren();
  const parts = String(text || "").split(" · ");
  for (let i = 0; i < parts.length; i++) {
    const chunk = el("span", "meta-chunk");
    chunk.append(document.createTextNode(parts[i]));
    if (i < parts.length - 1) chunk.append(el("span", "meta-sep", " · "));
    node.append(chunk);
  }
}
async function loadRoutines() {
  const box = $("#routines");
  if (!box) return;
  box.replaceChildren();
  if (!state.botId || state.draft) return;
  const timers = await api("/api/bots/" + state.botId + "/timers");
  if (!timers.length) box.append(el("p", "empty", "No routines."));
  const now = Date.now();
  for (const t of timers) {
    const row = el("div", "routine-row" + (t.enabled ? "" : " is-paused"));
    const main = el("div", "routine-main");
    const top = el("div", "routine-top");
    const name = t.name || "Untitled";
    top.append(el("span", "routine-name", name));
    top.append(el("span", "sched-chip", scheduleLabel(t.schedule || "")));
    main.append(top);
    const meta = el("div", "routine-meta");
    fillRoutineMeta(meta, routineMeta(t, now));
    main.append(meta);
    if (t.prompt) main.append(el("div", "routine-prompt", t.prompt));
    const toggle = el("button", "toggle");
    toggle.type = "button";
    toggle.dataset.timer = t.id;
    toggle.setAttribute("role", "switch");
    toggle.setAttribute("aria-checked", t.enabled ? "true" : "false");
    toggle.setAttribute("aria-label", "Turn " + name + " on/off");
    toggle.addEventListener("click", async () => {
      showRoutineErr(null);
      try {
        await api("/api/timers/" + t.id, { method: "PATCH", body: JSON.stringify({ enabled: !t.enabled }) });
        showStatusToast("Routine saved");
        await loadRoutines();
        const n = document.querySelector('#routines .toggle[data-timer="' + t.id + '"]');
        if (n) n.focus();
      } catch (err) { showRoutineErr(err); }
    });
    const menu = el("div", "menu");
    const more = el("button", "icon-btn routine-more");
    more.type = "button";
    more.setAttribute("aria-haspopup", "menu");
    more.setAttribute("aria-expanded", "false");
    more.setAttribute("aria-label", "Actions for " + name);
    more.append(moreSvg());
    const pop = el("div", "menu-pop");
    pop.hidden = true;
    pop.setAttribute("role", "menu");
    const edit = el("button", null, "Edit");
    edit.type = "button";
    edit.setAttribute("role", "menuitem");
    edit.addEventListener("click", () => { closeRoutineMenus(); openRoutineForm(t); });
    const del = el("button", null, "Delete");
    del.type = "button";
    del.setAttribute("role", "menuitem");
    del.addEventListener("click", async () => {
      // Move focus off the menu item before the pop is hidden and the row is removed.
      const keep = $("#routine-new");
      if (keep && typeof keep.focus === "function") keep.focus();
      closeRoutineMenus();
      showRoutineErr(null);
      try {
        await api("/api/timers/" + t.id, { method: "DELETE" });
        showStatusToast("Routine deleted");
        await loadRoutines();
      } catch (err) { showRoutineErr(err); }
      rescueFocus(() => $("#routine-new").focus());
    });
    pop.append(edit, del);
    bindRoutineMenu(pop);
    more.addEventListener("click", (e) => {
      e.stopPropagation();
      const willOpen = pop.hidden;
      closeRoutineMenus();
      closeMenu();
      pop.hidden = !willOpen;
      more.setAttribute("aria-expanded", willOpen ? "true" : "false");
      if (willOpen) edit.focus();
    });
    menu.append(more, pop);
    row.append(main, toggle, menu);
    box.append(row);
  }
}


$("#profile-name").addEventListener("input", syncProfileHeadingName);
$("#profile-name").addEventListener("input", paintDirty);
$("#profile-label").addEventListener("input", paintDirty);
$("#profile-description").addEventListener("input", paintDirty);
$("#profile-model").addEventListener("input", paintDirty);
["profile-name", "profile-label", "profile-model"].forEach(id => {
  $("#" + id).addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
    e.preventDefault();
    if (state.draft || profileDirty()) saveProfile();
  });
});
$("#color-custom").addEventListener("input", (e) => {
  const v = String(e.target.value || "").toLowerCase();
  if (/^#[0-9a-f]{6}$/.test(v)) { state.mark.color = v; paintMarkPicker(); paintDirty(); }
});
document.querySelectorAll("[data-grant]").forEach(b => {
  b.addEventListener("click", () => {
    const on = b.getAttribute("aria-checked") === "true";
    b.setAttribute("aria-checked", on ? "false" : "true");
    paintDirty();
  });
});
function selectSeg(buttons, index) {
  buttons.forEach((btn, i) => {
    const on = i === index;
    btn.setAttribute("aria-checked", on ? "true" : "false");
    btn.tabIndex = on ? 0 : -1;
  });
}
function wireRadios(root, onChange) {
  if (!root) return;
  const buttons = [...root.querySelectorAll("[role='radio']")];
  buttons.forEach((btn, i) => {
    if (!btn.hasAttribute("tabindex")) btn.tabIndex = btn.getAttribute("aria-checked") === "true" ? 0 : -1;
    btn.addEventListener("click", () => { selectSeg(buttons, i); onChange(btn, i); });
    btn.addEventListener("keydown", (e) => {
      const act = themeRadioKey(e.key, buttons.findIndex(b => b.getAttribute("aria-checked") === "true"), buttons.length);
      if (!act || act.index == null || !act.select) return;
      e.preventDefault();
      selectSeg(buttons, act.index);
      buttons[act.index].focus();
      onChange(buttons[act.index], act.index);
    });
  });
}
wireRadios($("#server-tools-seg"), () => { syncServerToolsMode(); paintDirty(); });
wireRadios($("#routine-unit"), () => paintRoutinePreview());
for (const kind of CHIP_KINDS) {
  const input = $("#profile-" + kind);
  if (!input) continue;
  input.addEventListener("keydown", (e) => onChipKey(kind, e));
  input.addEventListener("paste", (e) => onChipPaste(kind, e));
  input.addEventListener("blur", () => commitChipInput(kind));
}
document.querySelectorAll("#profile-nav-main [data-sec], #profile-nav-access [data-sec]").forEach(b => {
  b.addEventListener("click", () => scrollProfileTo(b.getAttribute("data-sec")));
});
bindProfileSpy();
window.addEventListener("resize", () => { if (state.view === "profile") bindProfileSpy(); });
$("#nav-access").addEventListener("click", () => { setProfilePane("access"); focusProfileHeading(); });
$("#open-access").addEventListener("click", () => { setProfilePane("access"); focusProfileHeading(); });
$("#routine-new").addEventListener("click", () => openRoutineForm(null));
$("#routine-add").addEventListener("click", submitRoutine);
$("#routine-cancel").addEventListener("click", () => { closeRoutineForm(); rescueFocus(() => $("#routine-new").focus()); });
$("#routine-form").addEventListener("submit", (e) => { e.preventDefault(); submitRoutine(); });
$("#routine-n").addEventListener("input", paintRoutinePreview);
$("#save-go").addEventListener("click", saveProfile);
$("#save-discard").addEventListener("click", discardSaveBar);
$("#discard-go").addEventListener("click", discardAndLeave);
$("#discard-keep").addEventListener("click", keepEditing);
$("#discard-backdrop").addEventListener("click", keepEditing);
window.addEventListener("beforeunload", (e) => {
  if (!profileDirty()) return;
  e.preventDefault();
  e.returnValue = "";
});
const phoneMq = window.matchMedia("(max-width: 540px)");
const onPhoneChange = () => { if (state.view === "profile") paintSaveBar(); };
if (phoneMq.addEventListener) phoneMq.addEventListener("change", onPhoneChange);
else if (phoneMq.addListener) phoneMq.addListener(onPhoneChange);

function riskBadge(risk, effect) {
  const label = risk || effect || "rule";
  return el("span", "risk " + (risk || effect || ""), label);
}
// perm-rules:begin
function clearPermErr() {
  const note = $("#profile-err");
  if (!note) return;
  note.style.color = "";
  note.textContent = "";
}
function showPermErr(err) {
  const note = $("#profile-err");
  if (!note) return;
  note.style.color = "";
  note.textContent = err && err.message ? err.message : String(err || "");
}
async function loadPermPanel() {
  const rulesBox = $("#perm-rules");
  const sugBox = $("#perm-suggestions");
  if (!rulesBox || !state.botId) return;
  rulesBox.replaceChildren();
  sugBox.replaceChildren();
  const rules = await api("/api/bots/" + state.botId + "/permission-rules");
  const list = (rules && rules.rules) || [];
  if (!list.length) rulesBox.append(el("p", "empty", "No durable rules."));
  for (const rule of list) {
    const row = el("div", "perm-rule");
    const effect = rule.effect || "allow";
    row.append(el("span", "risk " + effect, effect));
    row.append(el("code", null, rule.pattern || ""));
    const revoke = el("button", "ghost small", "Revoke");
    revoke.type = "button";
    revoke.addEventListener("click", async () => {
      clearPermErr();
      try {
        await api("/api/bots/" + state.botId + "/permission-rules/" + encodeURIComponent(rule.id), {method: "DELETE"});
        await loadPermPanel();
      } catch (err) { showPermErr(err); }
    });
    row.append(revoke);
    rulesBox.append(row);
  }
  const sug = await api("/api/bots/" + state.botId + "/permission-suggestions");
  const pending = (sug && sug.suggestions) || [];
  if (!pending.length) sugBox.append(el("p", "empty", "No suggestions."));
  for (const s of pending) {
    const card = el("div", "perm-card");
    card.dataset.status = s.status || "";
    const head = el("div", "row");
    head.append(riskBadge(s.risk, s.status === "refused" ? "high" : s.effect));
    head.append(el("strong", null, s.status === "refused" ? "refused" : "suggestion"));
    card.append(head);
    const pattern = el("input");
    pattern.value = s.pattern || "";
    pattern.setAttribute("aria-label", "Pattern");
    const lab = el("label", null, "Pattern");
    lab.append(pattern);
    card.append(lab);
    card.append(el("div", "meta", s.summary || ""));
    if (s.warning) card.append(el("div", "meta", s.warning));
    if (s.match_form) card.append(el("div", "meta", "Matches: " + s.match_form));
    const examples = (s.examples || []).join(" · ");
    if (examples) card.append(el("div", "meta", examples));
    const actions = el("div", "row");
    if (s.status !== "refused") {
      const accept = el("button", "primary small", "Accept");
      accept.type = "button";
      accept.addEventListener("click", async () => {
        clearPermErr();
        try {
          await api("/api/bots/" + state.botId + "/permission-suggestions/" + encodeURIComponent(s.id) + "/accept", {
            method: "POST",
            body: JSON.stringify({effect: "allow", pattern: pattern.value})
          });
          await loadPermPanel();
        } catch (err) { showPermErr(err); }
      });
      actions.append(accept);
    }
    const dismiss = el("button", "ghost small", "Dismiss");
    dismiss.type = "button";
    dismiss.addEventListener("click", async () => {
      clearPermErr();
      try {
        await api("/api/bots/" + state.botId + "/permission-suggestions/" + encodeURIComponent(s.id) + "/dismiss", {method: "POST"});
        await loadPermPanel();
      } catch (err) { showPermErr(err); }
    });
    actions.append(dismiss);
    card.append(actions);
    sugBox.append(card);
  }
}
$("#perm-add").addEventListener("click", async () => {
  if (!state.botId) return;
  clearPermErr();
  try {
    await api("/api/bots/" + state.botId + "/permission-rules", {method: "POST", body: JSON.stringify({
      effect: $("#perm-effect").value,
      pattern: $("#perm-pattern").value.trim()
    })});
    $("#perm-pattern").value = "";
    await loadPermPanel();
  } catch (err) { showPermErr(err); }
});
$("#perm-analyze").addEventListener("click", async () => {
  if (!state.botId) return;
  clearPermErr();
  try {
    await api("/api/bots/" + state.botId + "/permission-suggestions/analyze", {method: "POST", body: "{}"});
    await loadPermPanel();
  } catch (err) { showPermErr(err); }
});
// perm-rules:end
function fillKinds() {
  const sel = $("#log-kind");
  for (const k of KINDS) sel.append(new Option(k, k));
}
async function loadLog() {
  const bot = $("#log-bot").value;
  const kind = $("#log-kind").value;
  const q = new URLSearchParams();
  if (bot) q.set("bot_id", bot);
  if (kind) q.set("kind", kind);
  q.set("limit", "150");
  const events = await api("/api/log?" + q.toString());
  const box = $("#log");
  box.replaceChildren();
  if (!events.length) { box.append(el("p", "empty", "No log lines for this filter.")); return; }
  for (const ev of events) {
    const row = el("div", "event");
    const meta = el("div", "meta");
    meta.append(el("span", "kind", ev.kind), el("span", null, ev.ts || ""), el("span", null, ev.bot_id || "daemon"));
    const pre = el("pre");
    pre.textContent = JSON.stringify(ev.detail || {}, null, 0);
    row.append(meta, pre);
    box.append(row);
  }
}
$("#log-refresh").addEventListener("click", loadLog);
$("#log-bot").addEventListener("change", loadLog);
$("#log-kind").addEventListener("change", loadLog);
$("#auth form").addEventListener("submit", async (e) => {
  e.preventDefault();
  state.token = $("#auth-token").value.trim();
  sessionStorage.setItem("lgb_token", state.token);
  $("#auth-err").textContent = "";
  try {
    await loadBots();
    $("#auth").classList.remove("on");
    refreshDaemon();
  } catch (err) { $("#auth-err").textContent = err.message; }
});
fillKinds();
// ---- Bot state panel ----
// The header chip (⏱ timers · 🧠 notes) and the ⋯ menu open a slide-over
// on desktop and a bottom sheet under 980px.
const PHX = new Intl.DateTimeFormat("en-US", {timeZone: "America/Phoenix", month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit"});
const PHX_SHORT = new Intl.DateTimeFormat("en-US", {timeZone: "America/Phoenix", month: "short", day: "numeric", hour: "numeric", minute: "2-digit"});
function phx(iso, short) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return (short ? PHX_SHORT : PHX).format(d) + " MST";
}
function countdown(ms) {
  const neg = ms < 0;
  let s = Math.round(Math.abs(ms) / 1000);
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  const parts = d ? [d + "d", h + "h"] : h ? [h + "h", m + "m"] : m ? [m + "m", s + "s"] : [s + "s"];
  return neg ? parts.join(" ") + " ago" : "in " + parts.join(" ");
}
function stateOpen() {
  const sheet = $("#state-sheet");
  return !!sheet && !sheet.hidden && sheet.classList.contains("is-open");
}
function stateBox() { return $("#state-sheet-body"); }
async function loadState() {
  const id = state.botId;
  if (!id) return;
  const s = await api("/api/bots/" + id + "/state");
  if (state.botId !== id) return;
  state.botState = s;
  state.stateReloadAt = 0;
  paintStateChip();
  if (stateOpen()) renderState(stateBox(), s);
}
function chipIcon(kind, size) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const px = String(size || 16);
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", px);
  svg.setAttribute("height", px);
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const add = (tag, attrs) => {
    const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    svg.append(n);
  };
  const stroke = { fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round" };
  if (kind === "clock") {
    add("circle", { cx: "12", cy: "12", r: "8", fill: "none", stroke: "currentColor", "stroke-width": "2" });
    add("path", Object.assign({ d: "M12 8v5l3 2" }, stroke));
  } else if (kind === "note") {
    add("path", Object.assign({ d: "M7 4h8l4 4v12H7z" }, stroke));
    add("path", Object.assign({ d: "M15 4v4h4M9 12h6M9 16h4" }, stroke));
  } else if (kind === "warn") {
    add("path", Object.assign({ d: "M12 4l9 16H3z" }, stroke));
    add("path", Object.assign({ d: "M12 10v4M12 17h.01" }, stroke));
  } else if (kind === "chev") {
    add("path", Object.assign({ d: "M9 6l6 6-6 6" }, stroke));
  } else if (kind === "wrench") {
    add("path", Object.assign({ d: "M14.5 6.5a3.5 3.5 0 0 0-4.9 4.9L4 17l3 3 5.6-5.6a3.5 3.5 0 0 0 4.9-4.9L15 12l-3-3z" }, stroke));
  } else if (kind === "copy") {
    add("rect", { x: "8", y: "8", width: "11", height: "11", rx: "2", fill: "none", stroke: "currentColor", "stroke-width": "2" });
    add("path", Object.assign({ d: "M5 15V5h10" }, stroke));
  }
  return svg;
}
function permIcon(allowed) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "14");
  svg.setAttribute("height", "14");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
  p.setAttribute("fill", "none");
  p.setAttribute("stroke", "currentColor");
  p.setAttribute("stroke-width", "2");
  p.setAttribute("stroke-linecap", "round");
  p.setAttribute("stroke-linejoin", "round");
  p.setAttribute("d", allowed ? "M5 12.5l4.5 4.5L19 7.5" : "M7 7l10 10M17 7L7 17");
  svg.append(p);
  return svg;
}
function stopCircleIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "14");
  svg.setAttribute("height", "14");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  c.setAttribute("cx", "12");
  c.setAttribute("cy", "12");
  c.setAttribute("r", "8");
  c.setAttribute("fill", "none");
  c.setAttribute("stroke", "currentColor");
  c.setAttribute("stroke-width", "2");
  const r = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  r.setAttribute("x", "9");
  r.setAttribute("y", "9");
  r.setAttribute("width", "6");
  r.setAttribute("height", "6");
  r.setAttribute("rx", "1");
  r.setAttribute("fill", "currentColor");
  svg.append(c, r);
  return svg;
}
function paintStateChip() {
  const chip = $("#state-chip");
  if (!chip) return;
  chip.hidden = !state.botId;
  const s = state.botState;
  const on = s ? s.timers.filter(t => t.enabled).length : 0;
  const notes = s ? s.memory.length : 0;
  const warns = s && s.warnings ? s.warnings.length : 0;
  const name = stateChipName(on, notes, warns);
  chip.setAttribute("aria-label", name);
  chip.title = name;
  chip.classList.toggle("zero", !on && !notes && !warns);
  chip.classList.toggle("warn", warns > 0);
  chip.replaceChildren();
  const seg = (kind, n, warn) => {
    const g = el("span", "chip-seg" + (warn ? " warn" : ""));
    g.append(chipIcon(kind, 16), document.createTextNode(String(n)));
    return g;
  };
  chip.append(seg("clock", on, false), seg("note", notes, false));
  if (warns > 0) chip.append(seg("warn", warns, true));
  const chev = chipIcon("chev", 14);
  chev.classList.add("chip-chev");
  chip.append(chev);
}
let stateReturnFocus = null;
let stateHideToken = 0;
function motionOff() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}
// menu:begin
function menuTriggerOf(pop) {
  if (!pop) return null;
  const owner = (pop.closest && pop.closest(".menu")) || pop.parentElement || null;
  if (!owner || typeof owner.querySelector !== "function") return null;
  return owner.querySelector("[aria-haspopup='menu']");
}
function restoreMenuOrOpener(opener) {
  const pop = opener && opener.closest && opener.closest(".menu-pop");
  if (!pop) return opener || null;
  pop.hidden = true;
  const trigger = menuTriggerOf(pop);
  if (trigger && trigger.setAttribute) trigger.setAttribute("aria-expanded", "false");
  return trigger || null;
}
function restoreStateFocus() {
  const opener = stateReturnFocus;
  stateReturnFocus = null;
  if (!opener || !document.contains(opener)) return;
  // After the closing click, so focus lands on the trigger once the sheet is gone.
  setTimeout(() => {
    if (!document.contains(opener)) return;
    const target = restoreMenuOrOpener(opener);
    if (typeof closeMenu === "function") closeMenu();
    if (target && typeof target.focus === "function") target.focus();
  }, 0);
}
function handleMenuEscape(event, pop) {
  if (!pop || pop.hidden || !event || event.key !== "Escape") return false;
  if (event.preventDefault) event.preventDefault();
  if (event.stopPropagation) event.stopPropagation();
  if (event.stopImmediatePropagation) event.stopImmediatePropagation();
  pop.hidden = true;
  const trigger = menuTriggerOf(pop);
  if (trigger && trigger.setAttribute) trigger.setAttribute("aria-expanded", "false");
  if (trigger && typeof trigger.focus === "function") trigger.focus();
  return true;
}
function handleMenuFocusOut(event, pop) {
  if (!pop || pop.hidden) return false;
  const next = event && event.relatedTarget;
  if (next && pop.contains && pop.contains(next)) return false;
  const owner = (pop.closest && pop.closest(".menu")) || pop.parentElement || null;
  if (next && owner && owner.contains && owner.contains(next)) return false;
  pop.hidden = true;
  const trigger = menuTriggerOf(pop);
  if (trigger && trigger.setAttribute) trigger.setAttribute("aria-expanded", "false");
  return true;
}
// menu:end
document.addEventListener("keydown", (e) => {
  if (handleMenuEscape(e, $("#bot-menu"))) closeMenu();
}, true);
$("#bot-menu").addEventListener("focusout", (e) => {
  if (handleMenuFocusOut(e, $("#bot-menu"))) closeMenu();
});
function closeState() {
  const sheet = $("#state-sheet");
  const backdrop = $("#state-backdrop");
  if (!sheet || sheet.hidden || !sheet.classList.contains("is-open")) return;
  const token = ++stateHideToken;
  sheet.classList.remove("is-open");
  if (backdrop) backdrop.classList.remove("is-open");
  $("#state-chip").setAttribute("aria-expanded", "false");
  const hide = () => {
    if (token !== stateHideToken) return;
    if (sheet.classList.contains("is-open")) return;
    sheet.hidden = true;
    if (backdrop) backdrop.hidden = true;
    restoreStateFocus();
  };
  if (motionOff()) hide();
  else {
    sheet.addEventListener("transitionend", function onEnd(ev) {
      if (ev.target !== sheet || ev.propertyName !== "transform") return;
      sheet.removeEventListener("transitionend", onEnd);
      hide();
    });
    setTimeout(hide, 300);
  }
}
async function openState(opener) {
  if (!state.botId) return;
  closeMenu();
  stateHideToken++;
  stateReturnFocus = opener || null;
  const b = currentBot();
  const title = b && b.name ? b.name + " · state" : "state";
  $("#state-sheet-title").textContent = title;
  $("#state-sheet").setAttribute("aria-label", title);
  const sheetMark = $("#state-sheet-mark");
  if (b) { paintMark(sheetMark, b.mark); sheetMark.hidden = false; }
  else sheetMark.hidden = true;
  const sheet = $("#state-sheet");
  const backdrop = $("#state-backdrop");
  sheet.hidden = false;
  backdrop.hidden = false;
  if (motionOff()) {
    sheet.classList.add("is-open");
    backdrop.classList.add("is-open");
  } else {
    sheet.classList.remove("is-open");
    backdrop.classList.remove("is-open");
    void sheet.offsetWidth;
    sheet.classList.add("is-open");
    backdrop.classList.add("is-open");
  }
  $("#state-chip").setAttribute("aria-expanded", "true");
  const closeBtn = $("#state-close");
  if (closeBtn) closeBtn.focus();
  if (state.botState) renderState(stateBox(), state.botState);
  else stateBox().replaceChildren(el("p", "st-empty", "Loading…"));
  await loadState();
}
function stSection(title, count) {
  const sec = el("section", "st-sec");
  sec.append(el("h3", null, count == null ? title : title + " · " + count));
  return sec;
}
function stRow(main, sub, action) {
  const row = el("div", "st-row");
  const m = el("div", "st-main");
  if (typeof main === "string") m.append(el("b", null, main)); else m.append(main);
  for (const line of [].concat(sub || [])) if (line) m.append(line instanceof Node ? line : el("div", "st-sub", line));
  row.append(m);
  if (action) row.append(action);
  return row;
}
function stAction(label, confirmText, fn) {
  const b = el("button", "ghost st-act", label);
  b.type = "button";
  b.addEventListener("click", async () => {
    if (!confirm(confirmText)) return;
    b.disabled = true;
    try { await fn(); await loadState(); }
    catch (err) { alert(err.message); b.disabled = false; }
  });
  return b;
}
function renderState(box, s) {
  const out = [];
  if (s.warnings && s.warnings.length) {
    const sec = stSection("Warnings");
    for (const w of s.warnings) sec.append(stRow(el("span", null, "⚠ " + w)));
    out.push(sec);
  }
  const timers = [...s.timers].sort((a, b) => (b.enabled - a.enabled) || String(a.next_fire_at).localeCompare(String(b.next_fire_at)));
  const ts = stSection("Timers", timers.length);
  if (!timers.length) ts.append(el("p", "st-empty", "No timers."));
  for (const t of timers) {
    const kind = t.schedule === "once" ? "once" : "every " + t.schedule;
    const head = el("div");
    head.append(el("b", null, t.name || "(unnamed)"), " ", el("span", "st-tag" + (t.enabled ? "" : " off"), t.enabled ? kind : kind + " · off"));
    const when = el("div", "st-sub");
    if (t.enabled) {
      const cd = el("span", "st-fire");
      cd.dataset.fire = t.next_fire_at;
      when.append("Next: ", cd, " · " + phx(t.next_fire_at));
    } else {
      when.textContent = t.last_fire_at ? "Fired " + phx(t.last_fire_at) : "Not scheduled";
    }
    const prompt = el("div", "st-sub", t.prompt.length > 160 ? t.prompt.slice(0, 157) + "…" : t.prompt);
    ts.append(stRow(head, [when, prompt], stAction("Clear", "Delete timer “" + (t.name || t.prompt.slice(0, 40)) + "”?", () => api("/api/timers/" + t.id, {method: "DELETE"}))));
  }
  out.push(ts);
  const ms = stSection("Memory", s.memory.length);
  if (!s.memory.length) ms.append(el("p", "st-empty", "No memory notes."));
  for (const m of s.memory) {
    ms.append(stRow(m.key, [m.value, el("div", "st-sub", "Updated " + phx(m.updated_at, true))],
      stAction("Delete", "Delete memory note “" + m.key + "”?", () => api("/api/bots/" + state.botId + "/memory/" + encodeURIComponent(m.key), {method: "DELETE"}))));
  }
  out.push(ms);
  const as = stSection("Access");
  const tags = el("div");
  for (const g of ["net", "git", "github", "ssh", "build"]) tags.append(el("span", "st-tag" + ((s.grants || []).includes(g) ? " ok" : " off"), g));
  as.append(stRow(tags, [
    (s.net_allow && s.net_allow.length) ? "Network: " + s.net_allow.join(", ") : "",
    (s.ssh_allow && s.ssh_allow.length) ? "SSH: " + s.ssh_allow.join(", ") : "",
    (s.github_allow && s.github_allow.length) ? "GitHub: " + s.github_allow.join(", ") : "GitHub: no repositories"
  ]));
  out.push(as);
  const tl = stSection("Tools", s.tools.current.length);
  const st = el("div");
  if (s.tools.up_to_date) st.append(el("span", "st-tag ok", "bot is up to date"));
  else if (!s.tools.seen.length) st.append(el("span", "st-tag", "not yet told · notice on next run"));
  else st.append(el("span", "st-tag bad", "changed since last run · notice on next run"));
  tl.append(stRow(st, [
    s.tools.current.join(", "),
    s.tools.last_notice ? el("div", "st-sub", "Last notice " + phx(s.tools.last_notice.created_at, true) + ": " + s.tools.last_notice.content.replace(/^Notice: /, "")) : ""
  ]));
  out.push(tl);
  const rs = stSection("Recent runs", s.runs.length);
  if (!s.runs.length) rs.append(el("p", "st-empty", "No runs yet."));
  for (const r of s.runs) {
    const head = el("div");
    const cls = r.status === "done" ? " ok" : (r.status === "error" || r.status === "timeout" ? " bad" : "");
    head.append(el("span", "st-tag" + cls, r.status), " " + phx(r.started_at, true));
    let dur = "";
    if (r.finished_at) dur = Math.max(0, Math.round((new Date(r.finished_at) - new Date(r.started_at)) / 1000)) + "s";
    rs.append(stRow(head, [dur ? "Took " + dur : "", r.error ? "Error: " + r.error : ""]));
  }
  out.push(rs);
  box.replaceChildren(...out);
  tickFires();
}
function tickFires() {
  const now = Date.now();
  let due = false;
  for (const n of document.querySelectorAll("[data-fire]")) {
    const t = new Date(n.dataset.fire).getTime();
    if (isNaN(t)) continue;
    const ms = t - now;
    n.textContent = ms > -1000 ? countdown(Math.max(ms, 0)) : "due " + countdown(ms);
    if (ms < -3000) due = true;
  }
  // A timer just fired: refetch once so next_fire_at moves on.
  if (due && state.botId && !state.stateReloadAt) {
    state.stateReloadAt = now;
    loadState().catch(() => {});
  }
}
setInterval(tickFires, 1000);
// focus:begin
function stateFocusables(root) {
  const sel = "button, [href], input, select, textarea, [tabindex]";
  const all = root && root.querySelectorAll ? root.querySelectorAll(sel) : [];
  const out = [];
  for (const el of all) {
    if (!el || el.disabled || el.hidden) continue;
    const tab = el.getAttribute && el.getAttribute("tabindex");
    if (tab === "-1") continue;
    out.push(el);
  }
  return out;
}
function trapStateTab(event, root, active) {
  if (!event || event.key !== "Tab") return false;
  const nodes = stateFocusables(root);
  if (!nodes.length) {
    event.preventDefault();
    return true;
  }
  const first = nodes[0];
  const last = nodes[nodes.length - 1];
  const inside = !!(root && root.contains && root.contains(active));
  if (event.shiftKey && (active === first || !inside)) {
    event.preventDefault();
    last.focus();
    return true;
  }
  if (!event.shiftKey && (active === last || !inside)) {
    event.preventDefault();
    first.focus();
    return true;
  }
  return false;
}
// focus:end
function onStateKey(e) {
  if (!stateOpen()) return;
  if (e.key === "Escape") {
    e.preventDefault();
    closeState();
    return;
  }
  if (e.key === "Tab") trapStateTab(e, $("#state-sheet"), document.activeElement);
}
$("#state-chip").addEventListener("click", () => { if (stateOpen()) closeState(); else openState($("#state-chip")); });
$("#state-close").addEventListener("click", closeState);
$("#state-backdrop").addEventListener("click", closeState);
document.addEventListener("keydown", onStateKey);
// health:begin
const DOWN_AFTER_MS = 10000;
function healthView(phase, version) {
  if (phase === "loading") return { text: "connecting…", dot: "retry" };
  if (phase === "retrying") return { text: "reconnecting…", dot: "retry" };
  if (phase === "down") return { text: "daemon unreachable", dot: "down" };
  return { text: "daemon " + (version || "") + " · connected", dot: "ok" };
}
function connPhase(failSince, now) {
  if (typeof failSince !== "number" || !isFinite(failSince)) return "ok";
  if (typeof now !== "number" || !isFinite(now)) return "retrying";
  if (now - failSince >= DOWN_AFTER_MS) return "down";
  return "retrying";
}
function makeConnTracker(opts) {
  const opt = opts || {};
  const now = typeof opt.now === "function" ? opt.now : function () { return Date.now(); };
  const setTimer = typeof opt.setTimeout === "function" ? opt.setTimeout : function (fn, ms) { return setTimeout(fn, ms); };
  const clearTimer = typeof opt.clearTimeout === "function" ? opt.clearTimeout : function (id) { clearTimeout(id); };
  const onChange = typeof opt.onChange === "function" ? opt.onChange : function () {};
  let failSince = null;
  let phase = "ok";
  let timer = 0;
  let armed = false;
  function setPhase(next) {
    if (next === phase) return;
    phase = next;
    onChange(phase);
  }
  function disarm() {
    if (!armed) return;
    clearTimer(timer);
    armed = false;
    timer = 0;
  }
  function arm(t) {
    disarm();
    if (failSince == null) return;
    const remain = DOWN_AFTER_MS - (t - failSince);
    if (remain <= 0) return;
    armed = true;
    timer = setTimer(function () {
      armed = false;
      timer = 0;
      if (failSince == null) return;
      const tick = now();
      const next = connPhase(failSince, tick);
      setPhase(next);
      if (next === "retrying") arm(tick);
    }, remain);
  }
  return {
    phase: function () { return phase; },
    fail: function () {
      const t = now();
      if (failSince == null) failSince = t;
      const next = connPhase(failSince, t);
      arm(t);
      setPhase(next);
    },
    ok: function () {
      failSince = null;
      disarm();
      setPhase("ok");
    }
  };
}
function archivedMenuLabel(count) {
  if (typeof count !== "number" || !isFinite(count) || count < 0) return "";
  return "Archived (" + count + ") ›";
}
const ROSTER_ERROR_NOTE = "Can't reach the daemon. Retrying…";
function nextBackoff(prev) {
  const n = prev && prev >= 1000 ? prev * 2 : 1000;
  return n > 15000 ? 15000 : n;
}
// health:end
// contrast:begin
const MARK_SURFACES = {
  light: ["#F6F6F7", "#FFFFFF", "#F1F1F3", "#E9EEFD"],
  dark: ["#0F0F11", "#17171A", "#202024", "#1E2642"]
};
function hexChannels(hex) {
  if (typeof hex !== "string") return null;
  let h = hex.trim();
  if (h[0] !== "#") return null;
  h = h.slice(1);
  if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
  if (!/^[0-9a-fA-F]{6}$/.test(h)) return null;
  const n = parseInt(h, 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
function channelLin(c) {
  const s = c / 255;
  return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
}
function relLuminance(hex) {
  const rgb = hexChannels(hex);
  if (!rgb) return null;
  return 0.2126 * channelLin(rgb[0]) + 0.7152 * channelLin(rgb[1]) + 0.0722 * channelLin(rgb[2]);
}
function contrastRatio(a, b) {
  const L1 = relLuminance(a);
  const L2 = relLuminance(b);
  if (L1 == null || L2 == null) return 0;
  const hi = Math.max(L1, L2);
  const lo = Math.min(L1, L2);
  return (hi + 0.05) / (lo + 0.05);
}
function markContrastFails(color, mode) {
  const surfaces = MARK_SURFACES[mode];
  if (!surfaces || !hexChannels(color)) return false;
  for (let i = 0; i < surfaces.length; i++) {
    if (contrastRatio(color, surfaces[i]) < 3) return true;
  }
  return false;
}
function contrastAdvisories(color) {
  const out = [];
  if (markContrastFails(color, "dark")) out.push("This colour is hard to see in dark mode. Pick a preset to fix it.");
  if (markContrastFails(color, "light")) out.push("This colour is hard to see in light mode. Pick a preset to fix it.");
  return out;
}
// contrast:end
// runstate:begin
function noteRunStarted(bots, id) {
  if (!id || !bots || typeof bots.find !== "function") return false;
  const b = bots.find(x => x && x.id === id);
  if (!b || b.status === "running") return false;
  b.status = "running";
  return true;
}
// runstate:end
// thread-logic:begin
// Pure helpers for the thread, Stop control, cards, roster focus, theme keys,
// and the unreachable retry. No DOM here so node tests can run this section.
const STOP_TIMEOUT_MS = 10000;
const QUEUED_CAPTION = "Queued · the bot reads this before its next step";
const STOP_FAILED_NOTE = "Couldn't stop the run. The daemon didn't respond.";
const HINT_IDLE = "Enter to send · Shift+Enter for a new line · the bot reads follow-ups while it works";
const HINT_RUNNING = "Enter to send · Esc to stop · the bot reads follow-ups while it works";

function freshStop() {
  return { phase: "idle", pressed: false, runId: "", queued: false, since: 0, line: "", note: "", normalEnd: false };
}

// Stop phases: idle -> running -> stopping -> stopped.
// A cancel error or the 10s tick returns to running with note "stop-failed".
// A cancel result whose status is already finished (not "cancelled") is a
// normal end: no stopped line. The stopped line is emitted only from a
// stream-done of status "cancelled" while this client is in stopping
// (the user pressed Stop). A later stream-done does not emit it again.
function reduceStop(state, event) {
  const s = state || freshStop();
  const ev = event || {};
  const type = ev.type || "";
  const next = {
    phase: s.phase || "idle",
    pressed: !!s.pressed,
    runId: s.runId || "",
    queued: !!s.queued,
    since: typeof s.since === "number" ? s.since : 0,
    line: "",
    note: "",
    normalEnd: false
  };
  // Once the user-stop line is emitted, only a new run or an explicit idle
  // leaves it. Later done/error/tick events must not draw the line again.
  if ((s.phase === "stopped") && type !== "idle" && type !== "run") {
    next.phase = "stopped";
    next.line = s.line || "";
    next.pressed = !!s.pressed;
    next.queued = !!s.queued;
    return next;
  }
  if (type === "run") {
    if (next.phase === "stopping" && ev.runId && ev.runId === next.runId) return next;
    next.phase = "running";
    next.pressed = false;
    next.runId = ev.runId || next.runId;
    next.since = 0;
    return next;
  }
  if (type === "queue") { next.queued = true; return next; }
  if (type === "unqueue") { next.queued = false; return next; }
  if (type === "press") {
    if (next.phase !== "running") return next;
    next.phase = "stopping";
    next.pressed = true;
    next.since = typeof ev.now === "number" ? ev.now : 0;
    if (ev.runId) next.runId = ev.runId;
    if (ev.queued != null) next.queued = !!ev.queued;
    return next;
  }
  if (type === "tick") {
    if (next.phase !== "stopping") return next;
    const now = typeof ev.now === "number" ? ev.now : 0;
    if (now - next.since >= STOP_TIMEOUT_MS) {
      next.phase = "running";
      next.pressed = false;
      next.since = 0;
      next.note = "stop-failed";
    }
    return next;
  }
  if (type === "cancel-error") {
    if (next.phase !== "stopping") return next;
    next.phase = "running";
    next.pressed = false;
    next.since = 0;
    next.note = "stop-failed";
    return next;
  }
  if (type === "cancel-result") {
    if (next.phase !== "stopping") return next;
    const status = ev.status == null ? "" : String(ev.status);
    if (status === "cancelled") {
      if (ev.streamEnded) {
        next.phase = "idle";
        next.pressed = false;
        next.runId = "";
        next.since = 0;
        next.normalEnd = true;
      }
      return next;
    }
    if (status && status !== "running") {
      next.phase = "idle";
      next.pressed = false;
      next.runId = "";
      next.since = 0;
      next.normalEnd = true;
      return next;
    }
    next.phase = "running";
    next.pressed = false;
    next.since = 0;
    next.note = "stop-failed";
    return next;
  }
  if (type === "stream-done") {
    const status = ev.status == null ? "" : String(ev.status);
    if (next.phase === "stopped") {
      next.line = s.line || "";
      return next;
    }
    if (next.phase === "stopping" && next.pressed && status === "cancelled") {
      next.phase = "stopped";
      next.line = next.queued ? "queued" : "time";
      next.since = 0;
      return next;
    }
    next.phase = "idle";
    next.pressed = false;
    next.runId = "";
    next.since = 0;
    next.normalEnd = true;
    return next;
  }
  if (type === "idle") return freshStop();
  return next;
}

function stoppedLineText(queued, timeLabel) {
  if (queued) return "Stopped by you · your queued message starts the next run";
  return "Stopped by you · " + (timeLabel || "");
}

// Live Stop keeps the "by you" line, including the queued copy. A saved
// "Notice: Run cancelled." has no session stop, so it is the neutral line.
function stoppedNoticeText(isUserStop, queued, timeLabel) {
  if (isUserStop) return stoppedLineText(!!queued, timeLabel || "");
  const time = timeLabel ? String(timeLabel) : "";
  return time ? "Run stopped · " + time : "Run stopped";
}

function clockLabel(date) {
  const d = date instanceof Date ? date : new Date(date);
  if (isNaN(d.getTime())) return "";
  let h = d.getHours();
  const m = d.getMinutes();
  const ap = h >= 12 ? "PM" : "AM";
  h = h % 12;
  if (h === 0) h = 12;
  return h + ":" + (m < 10 ? "0" : "") + m + " " + ap;
}

function durationLabel(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  const m = Math.floor(s / 60);
  const r = s % 60;
  return m + ":" + (r < 10 ? "0" : "") + r;
}

// Queued styling is client-side. It clears on the first token of a new bot
// bubble, or when a stored bot reply arrives after the queued message.
// Run end, done, error, and Stop do not clear it. Loaded history never sets it.
function shouldClearQueued(reason) {
  return reason === "new-bot-token" || reason === "stored-reply";
}

function queuedClearOnThread(prev, next, queuedIds, duringRun) {
  const ids = queuedIds || [];
  if (!ids.length) return false;
  const want = {};
  for (let i = 0; i < ids.length; i++) want[String(ids[i])] = true;
  let earliest = null;
  const messages = next || [];
  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    if (!m || !want[String(m.id)]) continue;
    const t = Date.parse(m.created_at || "");
    if (!isNaN(t) && (earliest == null || t < earliest)) earliest = t;
  }
  if (earliest == null) return false;
  const seen = {};
  const before = prev || [];
  for (let i = 0; i < before.length; i++) if (before[i] && before[i].id != null) seen[String(before[i].id)] = true;
  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    if (!m || m.role !== "bot" || seen[String(m.id)]) continue;
    const t = Date.parse(m.created_at || "");
    if (isNaN(t) || t < earliest) continue;
    // The reply saved for the run that was already going is not the next bubble.
    if (duringRun && String(m.run_id || "") === String(duringRun)) continue;
    return true;
  }
  return false;
}

// Esc stops only from an empty composer, and only when no menu, sheet, or
// card dialog is open. Text in the field, or focus outside the composer, does nothing.
function escStopsRun(input) {
  const o = input || {};
  if (o.key !== "Escape") return false;
  if (!o.runActive) return false;
  if (!o.empty) return false;
  if (o.menuOpen || o.sheetOpen || o.dialogOpen) return false;
  if (!o.inComposer) return false;
  return true;
}

function workingIndicatorText(phase, tool) {
  const name = tool ? String(tool) : "";
  if (phase === "stopping") return "Stopping…";
  if (phase === "waiting") return name ? "Waiting for your approval · " + name : "Waiting for your approval";
  return name ? "Working · " + name : "Working";
}

function threadSubline(status, tool, label) {
  const word = status ? String(status) : "idle";
  const parts = [word];
  if (word === "running" && tool) parts.push(String(tool));
  if (label) parts.push(String(label));
  return parts.join(" · ");
}

function stateChipName(timers, memory, warnings) {
  const t = Math.max(0, Number(timers) || 0);
  const m = Math.max(0, Number(memory) || 0);
  const w = Math.max(0, Number(warnings) || 0);
  let name = "Bot state: " + t + (t === 1 ? " timer" : " timers") + ", " + m + " memory " + (m === 1 ? "entry" : "entries");
  if (w > 0) name += ", " + w + (w === 1 ? " warning" : " warnings");
  return name;
}

function composerHint(running) {
  return running ? HINT_RUNNING : HINT_IDLE;
}

function composerPlaceholder(name, narrow) {
  void narrow;
  const n = name ? String(name) : "";
  return n ? "Message " + n : "Message";
}

function liveToolLine(name, args, ok) {
  const mark = ok === false ? "✗" : ok === true ? "✓" : "…";
  let arg = "";
  const a = args && typeof args === "object" ? args : null;
  if (a) {
    if (typeof a.command === "string" && a.command.trim()) arg = a.command;
    else if (typeof a.cmd === "string" && a.cmd.trim()) arg = a.cmd;
    else if (typeof a.file_path === "string" && a.file_path) arg = a.file_path;
    else if (typeof a.path === "string" && a.path) arg = a.path;
    else {
      try { arg = JSON.stringify(a); } catch (e) { arg = ""; }
    }
  }
  if (arg.length > 160) arg = arg.slice(0, 157) + "…";
  return mark + " " + (name || "tool") + (arg ? " · " + arg : "");
}

function toolSummaryLabel(callCount, names, permCount, deniedCount) {
  const n = Number(callCount) || 0;
  const p = Number(permCount) || 0;
  const d = Number(deniedCount) || 0;
  let label = n + (n === 1 ? " tool call" : " tool calls");
  const list = Array.isArray(names) ? names.filter(Boolean) : [];
  if (list.length) label += " " + list.join(", ");
  if (p) {
    const word = p === 1 ? " permission" : " permissions";
    label += " · " + p + word + (d ? " (" + d + " denied)" : " (allowed)");
  }
  return label;
}

function toolCallLabel(tool, args) {
  const name = tool == null || tool === "" ? "tool" : String(tool);
  const a = args && typeof args === "object" ? args : {};
  let arg = "";
  if (typeof a.command === "string" && a.command.trim()) arg = a.command;
  else if (typeof a.cmd === "string" && a.cmd.trim()) arg = a.cmd;
  else if (typeof a.repo === "string" && a.repo) arg = a.repo;
  else if (typeof a.file_path === "string" && a.file_path) arg = a.file_path;
  else if (typeof a.path === "string" && a.path) arg = a.path;
  else if (typeof a.url === "string" && a.url) arg = a.url;
  if (arg.length > 80) arg = arg.slice(0, 77) + "…";
  if (name === "git_push" || name === "create_pr") return arg ? name + " " + arg : name;
  return arg ? name + "(" + arg + ")" : name;
}

function cardEyebrow(payload, botName) {
  const p = payload || {};
  const tool = p.tool == null ? "" : String(p.tool);
  if (p.kind === "question") return "QUESTION FROM " + (botName ? String(botName) : "BOT");
  if (tool === "git_push") return "APPROVAL REQUIRED · GIT_PUSH";
  if (tool === "create_pr") return "APPROVAL REQUIRED · CREATE_PR";
  if (tool === "ExitPlanMode") return "PERMISSION NEEDED · EXITPLANMODE";
  return "PERMISSION NEEDED";
}

function cardTitle(payload) {
  const p = payload || {};
  const tool = p.tool == null ? "" : String(p.tool);
  const args = p.arguments && typeof p.arguments === "object" ? p.arguments : {};
  if (p.kind === "question") return "Answer a question";
  if (tool === "Bash") return "Run a shell command (Bash)";
  if (tool === "git_push") {
    const repo = args.repo ? String(args.repo) : "the remote";
    return "Push commits to " + repo;
  }
  if (tool === "create_pr") return "Open a pull request" + (args.title ? ": " + String(args.title) : "");
  if (tool === "ExitPlanMode") return "Approve the plan (ExitPlanMode)";
  return "Allow " + tool;
}

function cardRecordText(input) {
  const o = input || {};
  const tool = o.toolLabel == null ? "" : String(o.toolLabel);
  const time = o.timeLabel == null ? "" : String(o.timeLabel);
  const dur = o.duration == null ? "" : String(o.duration);
  const kind = o.kind || "";
  if (kind === "allow_once") return "Allowed once · `" + tool + "` · " + time;
  if (kind === "allow_session") return "Allowed for session · `" + tool + "` · " + time;
  if (kind === "deny") return "Denied · `" + tool + "` · by you";
  if (kind === "expired") {
    return dur ? "Expired · denied after " + dur + " · `" + tool + "`" : "Expired · denied · `" + tool + "`";
  }
  if (kind === "cancelled") return "Cancelled · run stopped by you · `" + tool + "`";
  return "";
}

function recordKind(decision, source) {
  const src = source || "";
  const dec = decision || "";
  if (src === "cancel") return "cancelled";
  if (src === "timeout") return "expired";
  if (dec === "allow_session") return "allow_session";
  if (dec === "allow_once" || dec === "allow") return "allow_once";
  if (dec === "deny") return "deny";
  return "";
}

// Pairing key for one run, one kind, and one tool label. A later run does not
// pair with an earlier one. Identical decisions in the same run stay separate;
// the key only matches a local card to a single server row.
function runRecordKey(runId, kind, toolLabel) {
  return String(runId || "") + "|" + String(kind || "") + "|" + String(toolLabel || "");
}

function permRecordFields(rec) {
  let d = {};
  const raw = rec && rec.result_or_error;
  if (raw && typeof raw === "object") d = raw;
  else {
    try { d = JSON.parse(raw || "{}") || {}; } catch (e) { d = {}; }
  }
  if (!d || typeof d !== "object") d = {};
  let args = rec && rec.arguments;
  if (typeof args === "string") {
    try { args = JSON.parse(args); } catch (e) { args = {}; }
  }
  if (!args || typeof args !== "object") args = {};
  return {
    kind: recordKind(d.decision, d.source),
    toolLabel: toolCallLabel(rec && rec.name, args)
  };
}

// Every valid server permission is one record, in created_at order. Equal
// times keep input order. Each server row absorbs at most one local card with
// the same key, in card order; that card may fill an empty duration. The
// countdown lives only on the card. Unmatched local cards follow, once each.
function mergeRunRecords(serverRecs, cardRecords, runId, botId) {
  const out = [];
  const open = {};
  const recs = Array.isArray(serverRecs) ? serverRecs : [];
  const order = [];
  for (let i = 0; i < recs.length; i++) order.push(i);
  order.sort(function (i, j) {
    const ta = Date.parse(recs[i] && recs[i].created_at || "") || 0;
    const tb = Date.parse(recs[j] && recs[j].created_at || "") || 0;
    if (ta !== tb) return ta - tb;
    return i - j;
  });
  for (let n = 0; n < order.length; n++) {
    const r = recs[order[n]];
    if (!r || r.kind !== "permission") continue;
    const fields = permRecordFields(r);
    if (!fields.kind) continue;
    const key = runRecordKey(runId, fields.kind, fields.toolLabel);
    if (!Object.prototype.hasOwnProperty.call(open, key)) open[key] = [];
    open[key].push(out.length);
    out.push({
      kind: fields.kind,
      toolLabel: fields.toolLabel,
      timeLabel: clockLabel(r.created_at),
      duration: ""
    });
  }
  const extra = [];
  const cards = Array.isArray(cardRecords) ? cardRecords : [];
  for (let i = 0; i < cards.length; i++) {
    const c = cards[i];
    if (!c || c.runId !== runId || c.botId !== botId || !c.kind) continue;
    const key = runRecordKey(c.runId || runId, c.kind, c.toolLabel);
    const slots = open[key];
    if (slots && slots.length) {
      const cur = out[slots.shift()];
      if (cur && !cur.duration && c.duration) cur.duration = String(c.duration);
      continue;
    }
    extra.push({
      kind: c.kind,
      toolLabel: c.toolLabel || "",
      timeLabel: c.timeLabel || "",
      duration: c.duration || ""
    });
  }
  for (let i = 0; i < extra.length; i++) out.push(extra[i]);
  return out;
}

// A saved bot reply drops its local partial by run id. Trimmed text is only
// a fallback when that reply has no run id (the daemon trims trailing
// whitespace, so the strings do not match). One entry per run; the last
// unsaved copy wins.
function partialAlreadyStored(messages, partial) {
  const runId = partial && partial.runId != null && partial.runId !== "" ? String(partial.runId) : "";
  const text = String(partial && partial.content || "").trim();
  const list = Array.isArray(messages) ? messages : [];
  for (let i = 0; i < list.length; i++) {
    const m = list[i];
    if (!m || m.role !== "bot") continue;
    const mid = m.run_id != null && m.run_id !== "" ? String(m.run_id) : "";
    if (runId && mid === runId) return true;
    if (!mid && text && String(m.content || "").trim() === text) return true;
  }
  return false;
}

function partialsToShow(messages, partials, botId) {
  const list = Array.isArray(partials) ? partials : [];
  const byRun = {};
  const order = [];
  for (let i = 0; i < list.length; i++) {
    const p = list[i];
    if (!p || !p.content || p.botId !== botId) continue;
    if (partialAlreadyStored(messages, p)) continue;
    const id = p.runId == null ? "" : String(p.runId);
    if (!Object.prototype.hasOwnProperty.call(byRun, id)) order.push(id);
    byRun[id] = p;
  }
  const out = [];
  for (let i = 0; i < order.length; i++) out.push(byRun[order[i]]);
  return out;
}

// Announce only when the remaining whole seconds first land on 60 or 10.
function countdownAnnounce(prev, left) {
  if (typeof left !== "number" || !isFinite(left)) return "";
  if (left === 60 && prev !== 60) return "1 minute remaining";
  if (left === 10 && prev !== 10) return "10 seconds remaining";
  return "";
}

// After a row leaves the roster: the next row, else the previous, else the
// Bots heading. On a narrow screen the heading is always the target.
function archiveFocusTarget(wide, ids, removedId) {
  if (!wide) return { kind: "heading" };
  const list = Array.isArray(ids) ? ids : [];
  const i = list.indexOf(removedId);
  if (i >= 0 && i + 1 < list.length) return { kind: "row", id: list[i + 1] };
  if (i >= 0 && i - 1 >= 0) return { kind: "row", id: list[i - 1] };
  return { kind: "heading" };
}

// Left/Right and Home/End move and select a radio (wrap). Up/Down are not
// handled here: the radiogroup sits inside the roster menu, and Up/Down keep
// moving between menu items. The caller leaves the group on those keys.
function themeRadioKey(key, index, count) {
  const n = count | 0;
  if (n <= 0) return null;
  let i = typeof index === "number" ? index : -1;
  if (i < 0 || i >= n) i = 0;
  if (key === "ArrowRight") return { index: (i + 1) % n, select: true };
  if (key === "ArrowLeft") return { index: (i - 1 + n) % n, select: true };
  if (key === "Home") return { index: 0, select: true };
  if (key === "End") return { index: n - 1, select: true };
  if (key === "ArrowUp" || key === "ArrowDown") return { menu: key };
  return null;
}

// Immediate retry only when the daemon is unreachable and a refresh is not
// already in flight. Hidden, blur, and offline do not retry.
function retryTrigger(kind, unreachable, busy) {
  if (!unreachable || busy) return false;
  return kind === "visible" || kind === "focus" || kind === "online" || kind === "click";
}

// Timeout note actions. Null hides the note. Continue is only offered
// while the daemon still holds continue_run_id.
function timeoutNoteActions(bot, streaming) {
  if (streaming || !bot || bot.status === "running") return null;
  if (bot.last_run_status !== "timeout") return null;
  const actions = ["Retry"];
  if (bot.continue_run_id) actions.push("Continue");
  return { text: bot.last_run_error || "", actions: actions };
}

// A stream_reset clears the live bubble unless it names a different run.
function streamResetApplies(eventRunId, currentRunId) {
  const a = eventRunId == null || eventRunId === "" ? "" : String(eventRunId);
  const b = currentRunId == null || currentRunId === "" ? "" : String(currentRunId);
  if (a && b && a !== b) return false;
  return true;
}

// The docked timeout note is not a live region. The polite #a11y-status
// region says the notice once, when the timeout event arrives.
function timeoutAnnouncement(error) {
  const t = error == null ? "" : String(error).trim();
  return t ? "Run timed out. " + t : "Run timed out.";
}

function timedOutTag(message) {
  if (!message || message.role !== "bot" || !message.timed_out) return "";
  return "Timed out";
}

// Prefer the resume offer, then the run id from the timeout event, then
// the newest message that still carries a run id.
function timeoutRunId(bot, messages, remembered) {
  if (bot && bot.continue_run_id) return String(bot.continue_run_id);
  if (remembered) return String(remembered);
  const list = Array.isArray(messages) ? messages : [];
  for (let i = list.length - 1; i >= 0; i--) {
    const m = list[i];
    if (m && m.run_id) return String(m.run_id);
  }
  return "";
}

// After the timeout note is replaced, focus stays off body. An already
// focused field is left alone. Otherwise the composer, or the thread heading.
function focusTargetAfterNote(activeTag, composerUsable) {
  const tag = String(activeTag || "").toUpperCase();
  if (tag && tag !== "BODY" && tag !== "BUTTON") return "";
  if (composerUsable) return "composer-input";
  return "thread-name";
}

// Header word while a run is waiting on approval. Stopping stays "running".
function headerPhaseWord(bot, streaming, stopPhase, approvalWait) {
  if (bot && bot.archived) return "paused";
  const phase = stopPhase || "";
  if (phase !== "stopping" && phase !== "stopped" && (approvalWait || (bot && bot.last_run_status === "waiting"))) return "waiting";
  const live = phase !== "stopped" && (streaming || (bot && bot.status === "running") || phase === "running" || phase === "stopping");
  if (live) return "running";
  if (bot && bot.status === "paused") return "paused";
  return "idle";
}

// Header word after a stream event. A finished or non-waiting status
// clears a cached "waiting" run so the pill updates before the next reload.
function applyStreamStatus(bot, approvalWait, event, payload) {
  const b = bot ? Object.assign({}, bot) : null;
  let wait = !!approvalWait;
  const ev = String(event || "");
  const p = payload || {};
  if (ev === "status") {
    if (p.state === "waiting") {
      wait = true;
      if (b) b.last_run_status = "waiting";
    } else {
      wait = false;
      if (b && b.last_run_status === "waiting") b.last_run_status = p.state || "working";
    }
  } else if (ev === "done" || ev === "error" || ev === "timeout") {
    wait = false;
    let status = ev === "error" ? "error" : (ev === "timeout" ? "timeout" : (p.status || "done"));
    if (!status) status = "done";
    if (b) b.last_run_status = status;
  }
  return { bot: b, approvalWait: wait };
}

// True when this bot has a hook approval card. Native cards use the
// in-thread permission wait. The origin is the check.
function hookRunWaiting(botId, items) {
  if (!botId || !items || !items.length) return false;
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    if (it && it.bot_id === botId && it.origin === "hook") return true;
  }
  return false;
}

// Copy for a decision the server already settled. 409 is the conflict.
function decidedConflictCopy(status) {
  if (status === 409) return "Already decided";
  return "";
}

// Body of a daemon hook note. Empty means this text is not that note.
// kind is the check. A prefix in the text is not.
function hookNoteBody(content, kind) {
  if (kind !== "hook_note") return "";
  return content == null ? "" : String(content);
}
// thread-logic:end
// roster-keys:begin
function rosterRowMove(key, rows, active) {
  const list = rows || [];
  if (key !== "ArrowDown" && key !== "ArrowUp" && key !== "Enter") return null;
  const i = list.indexOf(active);
  if (key === "Enter") return i >= 0 ? { openIndex: i } : null;
  if (!list.length) return null;
  if (key === "ArrowDown") return { focusIndex: i < 0 ? 0 : Math.min(list.length - 1, i + 1) };
  return { focusIndex: i < 0 ? list.length - 1 : Math.max(0, i - 1) };
}
// roster-keys:end
// menu-keys:begin
function menuKeyAction(key, items, activeIndex) {
  const list = items || [];
  if (key === "Escape") return { close: true, focusTrigger: true };
  if (key === "Tab") return { close: true };
  if (key === "ArrowDown" || key === "ArrowUp") {
    if (!list.length) return { move: -1 };
    let i = typeof activeIndex === "number" ? activeIndex : -1;
    if (i < 0) i = key === "ArrowDown" ? -1 : 0;
    const dir = key === "ArrowDown" ? 1 : -1;
    return { move: (i + dir + list.length) % list.length };
  }
  if (key === "Enter") return { activate: typeof activeIndex === "number" ? activeIndex : -1 };
  return null;
}
// menu-keys:end
// toast:begin
const ARCHIVE_TOAST_MS = 6000;
function archiveToastText(name) {
  return "Archived " + name + " · Undo";
}
// toast:end
function dismissToast() {
  clearTimeout(state.toastTimer);
  state.toastTimer = 0;
  const toast = $("#toast");
  if (!toast) return;
  toast.hidden = true;
  toast.replaceChildren();
}
function showArchiveToast(id, name, prev) {
  const toast = $("#toast");
  if (!toast) return;
  clearTimeout(state.toastTimer);
  const shown = name == null ? "" : String(name);
  const full = archiveToastText(shown);
  const undoAt = full.lastIndexOf("Undo");
  const lead = undoAt >= 0 ? full.slice(0, undoAt) : full;
  const head = "Archived ";
  const copy = el("span", "toast-copy");
  const nameAt = lead.startsWith(head) ? head.length : -1;
  if (nameAt >= 0 && lead.slice(nameAt, nameAt + shown.length) === shown) {
    const sepText = lead.slice(nameAt + shown.length);
    const sep = el("span", "toast-sep", sepText);
    sep.setAttribute("aria-hidden", "true");
    copy.append(document.createTextNode(lead.slice(0, nameAt)), el("span", "toast-name", shown), sep);
  } else {
    copy.append(el("span", "toast-name", lead));
  }
  const undo = el("button", "ghost", "Undo");
  undo.type = "button";
  undo.addEventListener("click", () => undoArchive(id, prev));
  toast.replaceChildren(copy, undo);
  toast.hidden = false;
  state.toastTimer = setTimeout(dismissToast, ARCHIVE_TOAST_MS);
}
async function undoArchive(id, prev) {
  dismissToast();
  await setArchived(id, false, { restore: prev });
}
function paintHealth() {
  const text = $("#health-text");
  const dot = $("#health-dot");
  if (!text || !dot) return;
  const known = state.conn === "ok" || state.conn === "down" || state.conn === "retrying" || state.conn === "loading";
  const phase = known ? state.conn : "loading";
  const view = healthView(phase, state.version);
  text.textContent = view.text;
  dot.className = "dot health-" + view.dot;
}
function closeRosterMenu() {
  const menu = $("#roster-menu");
  const btn = $("#roster-menu-btn");
  if (menu) menu.hidden = true;
  if (btn) {
    btn.setAttribute("aria-expanded", "false");
    btn.classList.remove("is-active");
  }
}
function toggleRosterMenu() {
  const menu = $("#roster-menu");
  const btn = $("#roster-menu-btn");
  if (!menu || !btn) return;
  if (!menu.hidden) { closeRosterMenu(); return; }
  closeMenu();
  menu.hidden = false;
  btn.setAttribute("aria-expanded", "true");
  btn.classList.add("is-active");
  const first = [...menu.querySelectorAll("button")].find(b => !b.hidden && !b.disabled);
  if (first) first.focus();
}
$("#roster-menu-btn").addEventListener("click", (e) => {
  e.stopPropagation();
  toggleRosterMenu();
});
$("#roster-menu").addEventListener("keydown", (e) => {
  const pop = $("#roster-menu");
  if (handleMenuEscape(e, pop)) {
    closeRosterMenu();
    const btn = $("#roster-menu-btn");
    if (btn) btn.focus();
    return;
  }
  const seg = $("#theme-seg");
  const radios = seg ? [...seg.querySelectorAll("[role='radio']")] : [];
  const inSeg = !!(seg && seg.contains(document.activeElement));
  // Left/Right and Home/End change the theme radio. Up/Down keep moving
  // between menu items; the radiogroup is one stop in that list.
  if (inSeg && (e.key === "ArrowLeft" || e.key === "ArrowRight" || e.key === "Home" || e.key === "End")) {
    const move = themeRadioKey(e.key, radios.indexOf(document.activeElement), radios.length);
    if (move && move.select && radios[move.index]) {
      e.preventDefault();
      radios.forEach((b, i) => { b.tabIndex = i === move.index ? 0 : -1; });
      radios[move.index].focus();
      setThemeMode(radios[move.index].getAttribute("data-theme"));
    }
    return;
  }
  const before = [...pop.querySelectorAll("button")].filter(b => !b.hidden && !b.disabled && !(seg && seg.contains(b)));
  const checked = radios.find(b => b.getAttribute("aria-checked") === "true") || radios[0];
  const entries = checked ? before.concat([checked]) : before;
  const idx = inSeg ? entries.length - 1 : entries.indexOf(document.activeElement);
  const act = menuKeyAction(e.key, entries, idx);
  if (act && act.move != null && entries[act.move]) {
    e.preventDefault();
    entries[act.move].focus();
  }
});
$("#roster-menu").addEventListener("focusout", (e) => {
  if (handleMenuFocusOut(e, $("#roster-menu"))) closeRosterMenu();
});
$("#bot-list").addEventListener("keydown", (e) => {
  if (e.altKey || e.ctrlKey || e.metaKey) return;
  const rows = [...$("#bot-list").querySelectorAll("button.bot")];
  const act = rosterRowMove(e.key, rows, document.activeElement);
  if (!act) return;
  if (act.focusIndex != null && rows[act.focusIndex]) {
    e.preventDefault();
    rows[act.focusIndex].focus();
  }
  if (act.openIndex != null && rows[act.openIndex]) {
    e.preventDefault();
    rows[act.openIndex].click();
  }
});
document.addEventListener("keydown", (e) => {
  if (discardOpen()) {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      keepEditing();
    } else if (e.key === "Tab") trapStateTab(e, $("#discard-dialog"), document.activeElement);
    return;
  }
  if (typeof approvalKey === "function" && typeof closeApprovalLayer === "function") {
    const act = approvalKey(e, typeof isTypingTarget === "function" && isTypingTarget(e.target));
    if (act && act.close && closeApprovalLayer()) {
      e.preventDefault();
      return;
    }
    if (act && act.open && typeof openApprovals === "function" && !(typeof queueIsOpen === "function" && queueIsOpen())) {
      e.preventDefault();
      openApprovals({ manual: true, focus: true });
      return;
    }
  }
  if (e.key !== "Escape") return;
  // hidden stays set until the sheet finishes closing, so the same Escape
  // that starts closeState does not also dismiss the toast.
  // Escape closes the approvals queue and never approves, denies, or stops a run.
  const sheet = $("#state-sheet");
  if (sheet && !sheet.hidden) return;
  const roster = $("#roster-menu");
  if (roster && !roster.hidden) return;
  const botMenu = $("#bot-menu");
  if (botMenu && !botMenu.hidden) return;
  dismissToast();
});
let daemonTimer = 0;
let daemonBusy = false;
let didBoot = false;
const connTracker = makeConnTracker({
  now: () => Date.now(),
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (id) => clearTimeout(id),
  onChange: (phase) => {
    state.conn = phase;
    state.everFailed = phase !== "ok";
    paintHealth();
    renderBots();
  }
});
function scheduleDaemon(ms) {
  clearTimeout(daemonTimer);
  daemonTimer = setTimeout(() => { refreshDaemon(); }, ms);
}
async function bootFromURL() {
  if (didBoot) return;
  didBoot = true;
  const level = parseLevel(location.pathname, location.hash, base(), history.state, location.search);
  if (typeof hashIsApprovals === "function" && hashIsApprovals(location.hash) && typeof openApprovals === "function") {
    openApprovals({ manual: true, focus: false });
  }
  if (level.view === "rules") {
    await revealLevel(level);
    return;
  }
  if (level.bot && !knownBot(level.bot)) {
    goHome(false);
    commitLevel({ view: "bots", bot: null }, "replace");
  } else {
    await revealLevel(level);
  }
}
function daemonUnreachable() {
  return state.conn === "down" || (state.conn === "retrying" && !!state.everFailed);
}
function syncRetryButton() {
  const btn = $("#retry-now");
  if (!btn) return;
  if (daemonBusy) {
    btn.textContent = "Retrying…";
    btn.setAttribute("aria-disabled", "true");
  } else {
    btn.textContent = "Retry now";
    btn.removeAttribute("aria-disabled");
  }
}
function retryDaemonNow() {
  if (!retryTrigger("click", daemonUnreachable(), daemonBusy)) return;
  clearTimeout(daemonTimer);
  refreshDaemon();
}
function retryIfTrigger(kind) {
  if (!retryTrigger(kind, daemonUnreachable(), daemonBusy)) return;
  clearTimeout(daemonTimer);
  refreshDaemon();
}
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") retryIfTrigger("visible");
});
window.addEventListener("focus", () => retryIfTrigger("focus"));
window.addEventListener("online", () => retryIfTrigger("online"));
async function refreshDaemon() {
  if (daemonBusy) return;
  daemonBusy = true;
  syncRetryButton();
  try {
    const h = await api("/api/health");
    state.version = (h && h.version) || "";
    state.backoff = 1000;
    state.everFailed = false;
    state.conn = "ok";
    connTracker.ok();
    paintHealth();
    await loadBots();
    if (state.view === "log" || state.desktopLog) loadLog().catch(() => {});
    await bootFromURL();
    scheduleDaemon(3000);
  } catch (err) {
    if (err && err.message === "unauthorized") {
      scheduleDaemon(3000);
      return;
    }
    const wait = state.backoff || 1000;
    state.backoff = nextBackoff(wait);
    try {
      // Phase is how long this outage has lasted, not which retry is in flight.
      connTracker.fail();
    } finally {
      scheduleDaemon(wait);
    }
  } finally {
    daemonBusy = false;
    syncRetryButton();
  }
}
// voice-sr:begin
async function startLocalRecognition(opts) {
  opts = opts || {};
  const lang = typeof opts.lang === "string" ? opts.lang : "";
  try {
    if (typeof window === "undefined" || typeof window.SpeechRecognition !== "function") return {fallback: true};
    const SR = window.SpeechRecognition;
    if (!SR.prototype || !("processLocally" in SR.prototype) || typeof SR.available !== "function") return {fallback: true};
    const query = {langs: [lang], processLocally: true};
    let status = await SR.available(query);
    if (typeof opts.stale === "function" && opts.stale()) return {stale: true};
    if (status === "downloadable" || status === "downloading") {
      if (!opts.consent) return {needsConsent: true};
      const installed = await SR.install(query);
      if (installed === false) return {fallback: true};
      status = await SR.available(query);
      if (typeof opts.stale === "function" && opts.stale()) return {stale: true};
    }
    if (status !== "available") return {fallback: true};
    if (typeof opts.stale === "function" && opts.stale()) return {stale: true};
    const rec = new SpeechRecognition();
    rec.processLocally = true;
    if (rec.processLocally !== true) return {fallback: true};
    rec.lang = lang;
    rec.continuous = true;
    rec.interimResults = true;
    if (typeof opts.onresult === "function") rec.onresult = opts.onresult;
    if (typeof opts.onerror === "function") rec.onerror = opts.onerror;
    rec.onend = function () {
      let restart = false;
      try { restart = typeof opts.voiceMode === "function" && !!opts.voiceMode(); }
      catch (err) { restart = false; }
      if (restart) {
        return startLocalRecognition(opts).then(function (next) {
          if (typeof opts.onRestart === "function") {
            try { opts.onRestart(next); } catch (err) {}
          }
          return next;
        });
      }
      if (typeof opts.onEnd === "function") {
        try { opts.onEnd(); } catch (err) {}
      }
    };
    rec.start();
    return {ok: true, rec: rec};
  } catch (err) {
    return {fallback: true};
  }
}
// voice-sr:end
// voice-tts:begin
function speakableText(md) {
  return String(md || "")
    .replace(/```[\s\S]*?```/g, " (code omitted) ")
    .replace(/`([^`]*)`/g, "$1")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/^\s{0,3}#{1,6}\s+/gm, "")
    .replace(/^\s*[-*+]\s+/gm, "")
    .replace(/[*_~]{1,3}([^*_~]+)[*_~]{1,3}/g, "$1")
    .replace(/\s+/g, " ")
    .trim();
}
function localVoiceList(list) {
  const out = [];
  const all = list || [];
  for (let i = 0; i < all.length; i++) {
    if (all[i] && all[i].localService === true) out.push(all[i]);
  }
  return out;
}
function pickLocalVoice(list, pref, lang) {
  const local = localVoiceList(list);
  const want = String(pref || "");
  for (let i = 0; i < local.length; i++) {
    if (want && local[i].voiceURI === want) return local[i];
  }
  const prefix = String(lang || "").slice(0, 2).toLowerCase();
  if (prefix) {
    for (let i = 0; i < local.length; i++) {
      const code = String(local[i].lang || "").toLowerCase();
      if (code.indexOf(prefix) === 0) return local[i];
    }
  }
  return local.length ? local[0] : null;
}
function speakWithVoice(synth, text, voice, hooks) {
  if (!synth || typeof synth.speak !== "function" || !text || !voice || voice.localService !== true) return false;
  if (typeof SpeechSynthesisUtterance !== "function") return false;
  const u = new SpeechSynthesisUtterance(text);
  u.voice = voice;
  if (voice.lang) u.lang = voice.lang;
  if (hooks && typeof hooks.onend === "function") u.onend = hooks.onend;
  if (hooks && typeof hooks.onerror === "function") u.onerror = hooks.onerror;
  synth.speak(u);
  return true;
}
function speakLocal(synth, text, voices, pref, lang, hooks) {
  const voice = pickLocalVoice(voices, pref, lang);
  if (!voice || voice.localService !== true) return false;
  return speakWithVoice(synth, text, voice, hooks);
}
// voice-tts:end
function micErrorMessage(name) {
  if (name === "NotAllowedError" || name === "SecurityError" || name === "not-allowed" || name === "service-not-allowed") return "Microphone access is blocked. Allow the microphone for this page in your browser's site settings, then try again.";
  if (name === "NotFoundError" || name === "OverconstrainedError" || name === "audio-capture") return "No microphone was found. Connect one and try again.";
  if (name === "NotReadableError") return "The microphone is in use by another app.";
  if (name === "mic" || name === "audio") return "This browser can't record audio, so voice input isn't available here.";
  if (name === "language-not-supported") return "On-device recognition doesn't support this language. Change it in Voice settings.";
  return "";
}
function sttErrorMessage(status) {
  const reason = arguments.length > 1 ? arguments[1] : "";
  if (status === 403) return "Speech recognition is turned off on this computer.";
  if (status === 415) return "That audio format isn't supported.";
  if (status === 429 && reason === "limit") return "Speech recognition has reached its hourly limit. Try again later.";
  if (status === 429) return "Speech recognition is busy. Try again in a moment.";
  if (status === 408) return "Speech recognition timed out. Try again.";
  if (status === 503) return "Speech recognition isn't available right now.";
  return "Speech recognition didn't work. Try again.";
}
(function voiceInit() {
  const KEY = "lgb.voice";
  const STT_RATE = 16000;
  const RMS_MIN = 0.012;
  const HANGOVER_MS = 900;
  const PARTIAL_MS = 1500;
  const MAX_PARTIALS = 4;
  const MAX_SAMPLES = STT_RATE * 240;
  const cfg = {tts: true, lang: "", voice: ""};
  try {
    const saved = JSON.parse(localStorage.getItem(KEY) || "{}");
    if (saved && typeof saved === "object") {
      if (typeof saved.tts === "boolean") cfg.tts = saved.tts;
      if (typeof saved.lang === "string") cfg.lang = saved.lang;
      if (typeof saved.voice === "string") cfg.voice = saved.voice;
    }
  } catch (err) {}
  const v = {
    rec: null, cap: null, finals: "", base: "", mode: false, awaiting: false,
    speaking: false, listeningDesired: false, consentFor: "", pendingLang: "", lastAnn: "",
    gen: 0, starting: false, keepError: false, ending: false, voiceOff: false,
    spanStart: 0, spanText: ""
  };
  function nextGen() { v.gen += 1; return v.gen; }
  function saveCfg() {
    try { localStorage.setItem(KEY, JSON.stringify({tts: cfg.tts, lang: cfg.lang, voice: cfg.voice})); } catch (err) {}
  }
  function currentLang() {
    const typed = String(cfg.lang || "").trim();
    if (typed) return typed;
    return navigator.language || "en-US";
  }
  function announceVoice(text, force) {
    if (!text || (!force && v.lastAnn === text)) return;
    const n = $("#voice-status");
    if (n) n.textContent = n.textContent === text ? text + "\u00a0" : text;
    v.lastAnn = text;
  }
  function showVoiceError(text) {
    const n = $("#voice-msg");
    if (n) {
      n.hidden = !text;
      n.textContent = text || "";
    }
    v.errorShown = !!text;
    if (text) announceVoice(text, true);
  }
  function voiceHome() {
    const order = v.mode ? ["#voice-btn", "#composer-input"] : ["#mic-btn", "#voice-btn", "#send-btn", "#composer-input"];
    for (let i = 0; i < order.length; i++) {
      const n = $(order[i]);
      if (n && !n.hidden && n.getClientRects().length) return n;
    }
    return $("#composer-input");
  }
  function rescueFocus(box) {
    const a = document.activeElement;
    if (box && a && box.contains(a)) voiceHome().focus();
  }
  function clearVoiceError() {
    if (v.keepError) return;
    const n = $("#voice-msg");
    if (n) { n.hidden = true; n.textContent = ""; }
    v.errorShown = false;
  }
  function showPreview(finalText, interim) {
    const fin = $("#vp-final");
    const mid = $("#vp-interim");
    const box = $("#voice-preview");
    if (fin) fin.textContent = finalText || "";
    if (mid) mid.textContent = interim || "";
    if (box) box.hidden = !(finalText || interim);
  }
  function setVoiceState(text) {
    const n = $("#voice-state");
    if (n) n.textContent = text || "";
  }
  function setMicPressed(on) {
    const mic = $("#mic-btn");
    if (!mic) return;
    mic.classList.toggle("is-listening", !!on);
    mic.setAttribute("aria-pressed", on ? "true" : "false");
    mic.setAttribute("aria-label", on ? "Stop dictation" : "Dictate");
    syncSendEmpty();
  }
  function setVoicePressed(on) {
    const btn = $("#voice-btn");
    if (!btn) return;
    btn.setAttribute("aria-pressed", on ? "true" : "false");
    btn.setAttribute("aria-label", on ? "End voice mode" : "Voice mode");
    syncSendEmpty();
  }
  function rememberSpan() {
    const input = $("#composer-input");
    const value = input ? String(input.value || "") : "";
    let start = value.length;
    let end = value.length;
    if (input && typeof input.selectionStart === "number") {
      start = input.selectionStart;
      end = typeof input.selectionEnd === "number" ? input.selectionEnd : start;
    }
    if (start < 0) start = 0;
    if (end < start) end = start;
    v.spanStart = start;
    v.spanText = value.slice(start, end);
    v.base = value;
  }
  function writeDictationField(finalText, interim) {
    const input = $("#composer-input");
    if (!input) return;
    const spoken = (String(finalText || "") + " " + String(interim || "")).trim();
    let value = String(input.value || "");
    let start = v.spanStart || 0;
    const prev = String(v.spanText || "");
    if (prev) {
      if (value.slice(start, start + prev.length) !== prev) {
        const at = value.indexOf(prev);
        if (at >= 0) start = at;
      }
    } else if (start > value.length) {
      start = value.length;
    }
    const prefix = value.slice(0, start);
    const suffix = value.slice(start + (value.slice(start, start + prev.length) === prev ? prev.length : 0));
    let insert = spoken;
    if (insert && prefix && !/\s$/.test(prefix)) insert = " " + insert;
    if (insert && suffix && !/^\s/.test(suffix) && !/\s$/.test(insert)) insert = insert + " ";
    input.value = prefix + insert + suffix;
    v.spanStart = start;
    v.spanText = insert;
    fitComposer();
    syncSendEmpty();
  }
  function showPackPrompt(lang) {
    v.pendingLang = lang;
    const p = $("#voice-prompt-text");
    if (p) p.textContent = "Your browser will download a one-time " + lang + " language pack from its maker. Audio stays on this device.";
    const box = $("#voice-prompt");
    if (box) box.hidden = false;
    setMicPressed(false);
    announceVoice("A language pack download needs your OK.");
  }
  function cleanTranscript(text) {
    return String(text || "").replace(/\[(BLANK_AUDIO|MUSIC|NOISE)[^\]]*\]/gi, "").replace(/\s+/g, " ").trim();
  }
  function delay(ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); }
  async function loadStatus() {
    try {
      const headers = {};
      if (state.token) headers.Authorization = "Bearer " + state.token;
      const res = await fetch(base() + "/api/stt/status", {headers: headers, cache: "no-store"});
      if (res.status === 401) { showAuth(); return null; }
      if (!res.ok) return {enabled: false, available: false};
      const j = await res.json();
      return {enabled: j && j.enabled === true, available: j && j.available === true};
    } catch (err) {
      return {enabled: false, available: false};
    }
  }
  async function daemonTranscribe(pcm, partial) {
    const headers = {"Content-Type": "application/octet-stream"};
    if (partial) headers["X-STT-Partial"] = "1";
    if (state.token) headers.Authorization = "Bearer " + state.token;
    const res = await fetch(base() + "/api/stt", {method: "POST", body: pcm, headers: headers});
    if (res.status === 401) { showAuth(); return {error: "", auth: true, fatal: true, status: 401}; }
    if (partial && (res.status === 429 || res.status === 408)) return {skip: true};
    if (!res.ok) {
      let reason = "";
      try {
        const j = await res.json();
        reason = j && j.reason;
      } catch (err) {}
      const retry = res.status === 429 || res.status === 408;
      return {error: sttErrorMessage(res.status, reason), retry: retry, fatal: !retry, status: res.status};
    }
    const j = await res.json().catch(function () { return {}; });
    return {text: cleanTranscript(j && j.text)};
  }
  function frameRMS(input) {
    let sum = 0;
    const n = input.length || 1;
    for (let i = 0; i < input.length; i++) sum += input[i] * input[i];
    return Math.sqrt(sum / n);
  }
  function downsample(input, ratio) {
    const n = Math.max(1, Math.floor(input.length / ratio));
    const out = new Int16Array(n);
    for (let i = 0; i < n; i++) {
      let s = input[Math.floor(i * ratio)] || 0;
      if (s > 1) s = 1;
      else if (s < -1) s = -1;
      out[i] = s < 0 ? s * 0x8000 : s * 0x7fff;
    }
    return out;
  }
  function joinPCM(chunks) {
    let n = 0;
    for (let i = 0; i < chunks.length; i++) n += chunks[i].length;
    const out = new Int16Array(n);
    let o = 0;
    for (let i = 0; i < chunks.length; i++) {
      out.set(chunks[i], o);
      o += chunks[i].length;
    }
    return out.buffer;
  }
  function sampleCount(chunks) {
    let n = 0;
    for (let i = 0; i < chunks.length; i++) n += chunks[i].length;
    return n;
  }
  function closeGraph(stream, ctx, proc) {
    try { if (proc && proc.disconnect) proc.disconnect(); } catch (err) {}
    try {
      if (stream && stream.getTracks) stream.getTracks().forEach(function (t) { t.stop(); });
    } catch (err) {}
    try {
      if (ctx && ctx.close) {
        const done = ctx.close();
        if (done && typeof done.catch === "function") done.catch(function () {});
      }
    } catch (err) {}
  }
  function sessionCurrent(gen) { return v.gen === gen && v.listeningDesired; }
  async function startCapture(voiceMode, gen) {
    if (gen == null) gen = v.gen;
    if (!navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== "function") throw new Error("mic");
    if (window.isSecureContext === false) throw new Error("insecure");
    const Ctx = window.AudioContext;
    if (typeof Ctx !== "function") throw new Error("audio");
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: {channelCount: 1, echoCancellation: true, noiseSuppression: true, autoGainControl: true}
    });
    let ctx = null;
    try { ctx = new Ctx(); } catch (err) {
      closeGraph(stream, null, null);
      throw err;
    }
    if (ctx.state === "suspended" && typeof ctx.resume === "function") await ctx.resume();
    if (!sessionCurrent(gen)) {
      closeGraph(stream, ctx, null);
      return;
    }
    const src = ctx.createMediaStreamSource(stream);
    const proc = ctx.createScriptProcessor(4096, 1, 1);
    const mute = ctx.createGain();
    mute.gain.value = 0;
    if (!sessionCurrent(gen)) {
      try { proc.disconnect(); } catch (err) {}
      try { src.disconnect(); } catch (err) {}
      try { mute.disconnect(); } catch (err) {}
      closeGraph(stream, ctx, proc);
      return;
    }
    const ratio = (ctx.sampleRate || 48000) / STT_RATE;
    const cap = {
      stream: stream, ctx: ctx, src: src, proc: proc, mute: mute, chunks: [],
      speech: false, lastVoice: 0, voiceMode: !!voiceMode, busy: false,
      partials: 0, partialText: "", gen: gen
    };
    v.cap = cap;
    proc.onaudioprocess = function (ev) {
      if (v.cap !== cap || v.gen !== gen) return;
      const inp = ev.inputBuffer.getChannelData(0);
      const now = (window.performance && performance.now) ? performance.now() : Date.now();
      if (frameRMS(inp) >= RMS_MIN) {
        cap.lastVoice = now;
        cap.speech = true;
      }
      cap.chunks.push(downsample(inp, ratio));
      if (!cap.speech && cap.chunks.length > 4) cap.chunks.shift();
      if (sampleCount(cap.chunks) >= MAX_SAMPLES) { stopCapture(true); return; }
      if (cap.speech && cap.voiceMode && cap.lastVoice && now - cap.lastVoice > HANGOVER_MS) stopCapture(true);
    };
    src.connect(proc);
    proc.connect(mute);
    mute.connect(ctx.destination);
    cap.timer = setInterval(async function () {
      if (v.cap !== cap || v.gen !== gen || !v.listeningDesired || !cap.speech || cap.busy || cap.partials >= MAX_PARTIALS) return;
      cap.busy = true;
      cap.partials += 1;
      try {
        if (v.gen !== gen || !v.listeningDesired) return;
        const got = await daemonTranscribe(joinPCM(cap.chunks), true);
        if (v.cap !== cap || v.gen !== gen) return;
        if (got && got.fatal) {
          if (got.error) showVoiceError(got.error);
          if (cap.voiceMode) stopAll();
          else { v.listeningDesired = false; setMicPressed(false); stopCapture(false); }
          return;
        }
        if (got && !got.skip && !got.error && got.text) {
          cap.partialText = got.text;
          showPreview(got.text, "");
          if (!cap.voiceMode) writeDictationField(got.text, "");
        }
      } catch (err) {} finally { cap.busy = false; }
    }, PARTIAL_MS);
  }
  async function stopCapture(transcribe) {
    const cap = v.cap;
    if (!cap) return;
    const gen = nextGen();
    v.cap = null;
    clearInterval(cap.timer);
    try { cap.proc.disconnect(); } catch (err) {}
    try { cap.src.disconnect(); } catch (err) {}
    try { cap.mute.disconnect(); } catch (err) {}
    try { cap.stream.getTracks().forEach(function (t) { t.stop(); }); } catch (err) {}
    try {
      const done = cap.ctx.close();
      if (done && typeof done.catch === "function") done.catch(function () {});
    } catch (err) {}
    if (v.gen !== gen) return;
    let text = "";
    let failed = false;
    if (transcribe && cap.speech) {
      announceVoice("Transcribing");
      showPreview(cap.partialText, "");
      while (cap.busy) await delay(40);
      if (v.gen !== gen) return;
      let got = null;
      try {
        got = await daemonTranscribe(joinPCM(cap.chunks), false);
      } catch (err) {
        got = {error: sttErrorMessage(0), retry: true, fatal: false};
      }
      if (v.gen !== gen) return;
      if (cap.voiceMode && got && got.retry) {
        await delay(400);
        if (v.gen !== gen) return;
        try {
          got = await daemonTranscribe(joinPCM(cap.chunks), false);
        } catch (err) {
          got = {error: sttErrorMessage(0), fatal: true};
        }
        if (got && got.retry) got.fatal = true;
        if (v.gen !== gen) return;
      }
      if (got && got.error) {
        showVoiceError(got.error);
        failed = true;
      } else if (got && got.fatal) {
        failed = true;
      } else if (got && got.text) {
        text = got.text;
      }
      showPreview("", "");
      if (cap.voiceMode && (failed || (got && got.fatal))) {
        stopAll();
        return;
      }
      if (cap.voiceMode) {
        if (!v.mode) return;
        if (!text) { resumeListening(); return; }
        v.finals = text;
        endUtterance();
        return;
      }
      if (text) writeDictationField(text, "");
      v.finals = "";
      setMicPressed(false);
    } else {
      showPreview("", "");
      if (!cap.voiceMode) setMicPressed(false);
      if (transcribe && cap.voiceMode && v.mode && v.listeningDesired && v.gen === gen) {
        resumeListening();
        return;
      }
      if (cap.voiceMode) return;
    }
    if (!v.errorShown) announceVoice("Dictation stopped");
  }
  function stopRec() {
    v.listeningDesired = false;
    const r = v.rec;
    if (!r) { nextGen(); return; }
    if (!v.mode && !v.ending) onRecEnd();
    nextGen();
    v.rec = null;
    try { r.stop(); } catch (err) {}
  }
  function onRecResult(e) {
    let interim = "";
    const results = e && e.results;
    if (!results) return;
    const from = typeof e.resultIndex === "number" ? e.resultIndex : 0;
    for (let i = from; i < results.length; i++) {
      const res = results[i];
      const bit = res && res[0] ? String(res[0].transcript || "") : "";
      if (res && res.isFinal) v.finals = (v.finals + " " + bit).trim();
      else interim += bit;
    }
    showPreview(v.finals, interim);
    if (!v.mode) writeDictationField(v.finals, interim);
    if (v.mode) {
      clearTimeout(v.endT);
      if (v.finals && !interim) v.endT = setTimeout(endUtterance, HANGOVER_MS);
    }
  }
  function onRecError(e) {
    const code = e && e.error;
    if (code === "no-speech" || code === "aborted") return;
    showVoiceError(micErrorMessage(code) || sttErrorMessage(0));
    if (code === "not-allowed" || code === "service-not-allowed" || code === "language-not-supported") {
      v.listeningDesired = false;
      if (v.mode) stopAll();
      else setMicPressed(false);
    }
  }
  function onRecEnd() {
    if (v.mode) return;
    v.rec = null;
    v.listeningDesired = false;
    const text = String(v.finals || "").trim();
    v.finals = "";
    if (text) writeDictationField(text, "");
    showPreview("", "");
    setMicPressed(false);
    if (!v.errorShown) announceVoice("Dictation stopped");
  }
  function recognitionOpts(gen) {
    const box = {rec: null};
    function current() { return v.gen === gen && v.rec === box.rec; }
    return {
      box: box,
      lang: currentLang(),
      consent: v.consentFor === currentLang(),
      stale: function () { return v.gen !== gen || !v.listeningDesired; },
      voiceMode: function () { return current() && v.mode && v.listeningDesired; },
      onresult: function (e) { if (!current()) return; onRecResult(e); },
      onerror: function (e) { if (!current()) return; onRecError(e); },
      onEnd: function () { if (!current()) return; onRecEnd(); },
      onRestart: function (next) {
        if (v.gen !== gen) {
          if (next && next.rec) { try { next.rec.abort(); } catch (err) {} }
          return;
        }
        if (!v.mode || !v.listeningDesired) {
          if (next && next.rec) { try { next.rec.abort(); } catch (err) {} }
          return;
        }
        if (next && next.ok && next.rec) {
          v.rec = next.rec;
          box.rec = next.rec;
          return;
        }
        v.rec = null;
        box.rec = null;
        if (next && next.needsConsent) { showPackPrompt(currentLang()); return; }
        beginDaemonOrUnavailable(true, gen);
      }
    };
  }
  async function beginBrowserOrDaemon(voiceMode) {
    if (!v.keepError) clearVoiceError();
    const gen = nextGen();
    v.listeningDesired = true;
    v.starting = true;
    try {
      const opts = recognitionOpts(gen);
      const result = await startLocalRecognition(opts);
      if ((result && result.stale) || v.gen !== gen || !v.listeningDesired) {
        if (result && result.rec) { try { result.rec.abort(); } catch (err) {} }
        return;
      }
      if (result && result.needsConsent) {
        v.listeningDesired = false;
        showPackPrompt(currentLang());
        return;
      }
      if (result && result.ok) {
        v.rec = result.rec;
        opts.box.rec = result.rec;
        if (voiceMode) { setVoicePressed(true); setVoiceState("Listening"); }
        else setMicPressed(true);
        if (!v.keepError) announceVoice("Listening");
        showPreview("", "Listening…");
        return;
      }
      await beginDaemonOrUnavailable(voiceMode, gen);
    } finally {
      if (v.gen === gen) v.starting = false;
    }
  }
  async function beginDaemonOrUnavailable(voiceMode, gen) {
    if (gen == null) gen = v.gen;
    const status = await loadStatus();
    if (v.gen !== gen || !v.listeningDesired) return;
    if (!status) return;
    if (!status.available) {
      v.listeningDesired = false;
      setMicPressed(false);
      showVoiceError(status.enabled ? sttErrorMessage(503) : sttErrorMessage(403));
      if (voiceMode) stopAll();
      return;
    }
    try {
      await startCapture(!!voiceMode, gen);
      if (v.gen !== gen || !v.listeningDesired) return;
      if (voiceMode) { setVoicePressed(true); setVoiceState("Listening"); }
      else setMicPressed(true);
      if (!v.keepError) announceVoice("Listening");
      showPreview("", "Listening…");
    } catch (err) {
      v.listeningDesired = false;
      const why = err && (err.name === "Error" ? err.message : err.name);
      showVoiceError(window.isSecureContext === false ? "The microphone needs a secure page." : (micErrorMessage(why) || "The microphone isn't available."));
      if (voiceMode) stopAll();
      else setMicPressed(false);
    }
  }
  async function resumeListening() {
    if (!v.mode || v.awaiting || v.rec || v.cap || v.starting) return;
    if (v.errorShown) v.keepError = true;
    setVoiceState("Listening");
    if (!v.keepError) announceVoice("Listening");
    await beginBrowserOrDaemon(true);
  }
  async function endUtterance() {
    const text = String(v.finals || "").trim();
    v.finals = "";
    if (!text) {
      if (v.mode && !v.awaiting) resumeListening();
      return;
    }
    if (v.awaiting) return;
    v.awaiting = true;
    v.listeningDesired = false;
    stopRec();
    showPreview("", "");
    setVoiceState("Thinking");
    const ok = await send(text);
    if (!v.mode) { v.awaiting = false; return; }
    if (!ok || !state.streaming) {
      v.awaiting = false;
      resumeListening();
    }
  }
  function speakReply(text, then) {
    const synth = window.speechSynthesis;
    const spoken = speakableText(text);
    const voices = synth && typeof synth.getVoices === "function" ? synth.getVoices() : [];
    if (!synth || !spoken) return false;
    const voice = pickLocalVoice(voices, cfg.voice, currentLang());
    if (!voice) {
      showVoiceError("No on-device voice is available, so this reply stays on screen.");
      return false;
    }
    try { synth.cancel(); } catch (err) {}
    v.speaking = true;
    const ok = speakWithVoice(synth, spoken, voice, {
      onend: function () { v.speaking = false; if (then) then(); },
      onerror: function () { v.speaking = false; if (then) then(); }
    });
    if (!ok) v.speaking = false;
    return ok;
  }
  function stopAll() {
    const mode = v.mode;
    const dict = !mode && !!(v.rec || v.cap);
    v.ending = true;
    v.mode = false;
    v.listeningDesired = false;
    v.starting = false;
    v.awaiting = false;
    nextGen();
    clearTimeout(v.endT);
    if (mode && v.rec) v.rec.onend = null;
    stopRec();
    stopCapture(false);
    v.ending = false;
    const synth = window.speechSynthesis;
    if (synth) { try { synth.cancel(); } catch (err) {} }
    v.speaking = false;
    v.finals = "";
    showPreview("", "");
    const prompt = $("#voice-prompt");
    const bar = $("#voice-bar");
    const act = document.activeElement;
    const lost = !!act && ((bar && bar.contains(act)) || (prompt && prompt.contains(act)));
    if (prompt) prompt.hidden = true;
    if (bar) bar.hidden = true;
    setMicPressed(false);
    setVoicePressed(false);
    if (lost) voiceHome().focus();
    if (v.errorShown) return;
    if (mode) announceVoice("Voice mode off");
    else if (dict) announceVoice("Dictation stopped");
  }
  async function toggleMic() {
    if (v.voiceOff) { showVoiceError(sttErrorMessage(403)); return; }
    if (v.mode) return;
    if (v.starting || v.rec || v.cap) {
      v.listeningDesired = false;
      v.starting = false;
      if (v.rec) stopRec();
      else if (v.cap) await stopCapture(true);
      else nextGen();
      return;
    }
    const synth = window.speechSynthesis;
    if (synth) { try { synth.cancel(); } catch (err) {} }
    v.finals = "";
    v.keepError = false;
    rememberSpan();
    await beginBrowserOrDaemon(false);
  }
  async function toggleMode() {
    if (v.voiceOff) { showVoiceError(sttErrorMessage(403)); return; }
    if (v.mode || v.starting) { v.keepError = false; clearVoiceError(); stopAll(); return; }
    if (!state.botId) { showVoiceError("Choose a bot first."); return; }
    if (v.rec || v.cap) {
      v.listeningDesired = false;
      stopRec();
      await stopCapture(false);
    }
    v.keepError = false;
    v.mode = true;
    v.awaiting = false;
    v.finals = "";
    v.base = "";
    const bar = $("#voice-bar");
    if (bar) bar.hidden = false;
    setVoicePressed(true);
    setVoiceState("Listening");
    announceVoice("Voice mode on");
    await beginBrowserOrDaemon(true);
  }
  function renderSettings() {
    const tts = $("#vs-tts");
    const lang = $("#vs-lang");
    const sel = $("#vs-voice");
    if (tts) tts.checked = cfg.tts !== false;
    if (lang && document.activeElement !== lang) lang.value = cfg.lang || currentLang();
    if (!sel) return;
    const synth = window.speechSynthesis;
    const local = localVoiceList(synth && typeof synth.getVoices === "function" ? synth.getVoices() : []);
    sel.replaceChildren();
    const auto = document.createElement("option");
    auto.value = "";
    auto.textContent = local.length ? "Auto (on-device)" : "No on-device voices";
    sel.append(auto);
    for (let i = 0; i < local.length; i++) {
      const o = document.createElement("option");
      o.value = local[i].voiceURI || "";
      o.textContent = (local[i].name || "Voice") + " (" + (local[i].lang || "") + ")";
      sel.append(o);
    }
    sel.value = cfg.voice;
    if (sel.value !== cfg.voice) sel.value = "";
  }
  window.voiceListening = function () { return !v.mode && !!(v.rec || v.cap); };
  window.voiceModeOn = function () { return !!v.mode; };
  window.voiceStop = stopAll;
  window.voiceOnSend = function () {
    const synth = window.speechSynthesis;
    if (synth) { try { synth.cancel(); } catch (err) {} }
    v.speaking = false;
  };
  window.voiceOnRunEnd = function (text, failed) {
    if (!v.mode) return;
    v.awaiting = false;
    if (failed || !text || cfg.tts === false) {
      resumeListening();
      return;
    }
    v.listeningDesired = false;
    setVoiceState("Speaking");
    announceVoice("Speaking");
    const spoke = speakReply(text, function () {
      if (v.mode) resumeListening();
    });
    if (!spoke && v.mode) resumeListening();
  };
  const cfgBtn = $("#voice-cfg");
  if (cfgBtn) cfgBtn.addEventListener("click", function () {
    const s = $("#voice-settings");
    if (!s) return;
    const opening = !!s.hidden;
    s.hidden = !opening;
    cfgBtn.setAttribute("aria-expanded", opening ? "true" : "false");
    if (opening) renderSettings();
  });
  const ttsBox = $("#vs-tts");
  if (ttsBox) ttsBox.addEventListener("change", function () {
    cfg.tts = !!ttsBox.checked;
    saveCfg();
  });
  const langBox = $("#vs-lang");
  if (langBox) langBox.addEventListener("change", async function () {
    cfg.lang = langBox.value.trim();
    v.consentFor = "";
    saveCfg();
    if (!(v.rec || v.cap || v.mode)) return;
    const mode = v.mode;
    v.listeningDesired = false;
    v.starting = false;
    v.keepError = false;
    stopRec();
    await stopCapture(false);
    v.finals = "";
    if (mode) {
      v.mode = true;
      const bar = $("#voice-bar");
      if (bar) bar.hidden = false;
    }
    await beginBrowserOrDaemon(mode);
  });
  const voiceSel = $("#vs-voice");
  if (voiceSel) voiceSel.addEventListener("change", function () {
    cfg.voice = voiceSel.value;
    saveCfg();
  });
  const synth = window.speechSynthesis;
  if (synth && typeof synth.addEventListener === "function") {
    synth.addEventListener("voiceschanged", function () {
      const s = $("#voice-settings");
      if (s && !s.hidden) renderSettings();
    });
  }
  const mic = $("#mic-btn");
  if (mic) mic.addEventListener("click", function () { toggleMic(); });
  const modeBtn = $("#voice-btn");
  if (modeBtn) modeBtn.addEventListener("click", function () { toggleMode(); });
  const endBtn = $("#voice-end");
  if (endBtn) endBtn.addEventListener("click", function () { v.keepError = false; clearVoiceError(); stopAll(); });
  const yes = $("#voice-pack-yes");
  if (yes) yes.addEventListener("click", async function () {
    const lang = v.pendingLang || currentLang();
    v.consentFor = lang;
    v.keepError = false;
    const box = $("#voice-prompt");
    rescueFocus(box);
    if (box) box.hidden = true;
    await beginBrowserOrDaemon(!!v.mode);
  });
  const no = $("#voice-pack-no");
  if (no) no.addEventListener("click", async function () {
    const box = $("#voice-prompt");
    rescueFocus(box);
    if (box) box.hidden = true;
    v.consentFor = "";
    v.listeningDesired = true;
    await beginDaemonOrUnavailable(!!v.mode);
  });
  function applyVoiceAvailability(status) {
    const off = !status || status.enabled !== true;
    v.voiceOff = off;
    [["#mic-btn", "Dictate"], ["#voice-btn", "Voice mode"]].forEach(function (pair) {
      const n = $(pair[0]);
      if (!n) return;
      if (off) {
        n.setAttribute("aria-disabled", "true");
        n.title = "Speech recognition is turned off on this computer.";
      } else {
        n.removeAttribute("aria-disabled");
        if (n.title === "Speech recognition is turned off on this computer.") n.title = pair[1];
      }
    });
  }
  let voiceStatusOnce = null;
  function prefetchVoiceStatus() {
    if (voiceStatusOnce) return voiceStatusOnce;
    const headers = {};
    if (state.token) headers.Authorization = "Bearer " + state.token;
    voiceStatusOnce = fetch(base() + "/api/stt/status", {headers: headers, cache: "no-store"})
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(function (j) { if (j && j.enabled === false) applyVoiceAvailability(j); return j; })
      .catch(function () { return null; });
    return voiceStatusOnce;
  }
  prefetchVoiceStatus();
  syncSendEmpty();
})();
// approvals-pure:begin
const APPROVE_ARM_MS = 1500;
const APPROVAL_POLL_MS = 2000;
const DENY_BODY = '{"decision":"deny"}';
const EMPTY_QUEUE_TITLE = "Nothing waiting";
const EMPTY_QUEUE_BODY = "When a bot needs your OK, it shows up here, sorted by risk. Requests wait until you answer or the bot stops. This panel closes by itself once it's empty, unless you opened it.";
const RECONNECT_COPY = "Reconnect to answer.";
const UNREACHABLE_COPY = "Can't reach the daemon. Answers are paused until it's back.";
const CRITICAL_BAND = "⚠ CRITICAL · WE RECOMMEND DENYING";
const CRITICAL_EYEBROW = "CRITICAL RISK · PERMISSION NEEDED";
const SEND_FAILED_COPY = "Couldn't send your answer. The daemon didn't respond. Try again.";
const NOTIFY_TITLE = "Critical approval waiting";
const MODEL_NOTE_TITLE = "Model note · untrusted";
const MODEL_NOTE_SUB = "A model's guess, not a check. Judge by the command above.";
const MODEL_NOTE_HIDDEN = "Model note hidden for high-risk requests.";
const REPLACE_NOTE = "Saves a new rule and removes the old one.";
const REPLACE_BOTH = "Saved the new rule, but couldn't remove the old one. Both are listed.";
const STAR_WORD = "A * stands for exactly one word and can't be the last word.";
const NOTIFY_UNAVAILABLE = "Browsers don't allow notifications on plain http. Critical approvals still show here and in the tab title.";
const NOTIFY_BLOCKED = "Notifications are blocked. Allow notifications for this page in your browser's site settings. Critical approvals still show here and in the tab title.";
const PREPROMPT_TITLE = "Get a notification for critical approvals?";
const PREPROMPT_BODY = "When a bot asks for a critical approval and this tab is in the background, your browser can show a notification. It comes from this page only, with no outside service. You still decide here.";
const EXACT_HELP = "Matches this exact command only. To cover more than one command, add a pattern rule. Commands with ; && | $( ) can't be saved.";
const PATTERN_HELP = "Patterns match the command word for word. " + STAR_WORD + " It never matches a flag (a word starting with `-`). Write flags out in full. Case-sensitive.";
const LEGACY_NOTE = "Imported from an older version. Revoke it, or add an exact or pattern rule that covers what you need.";
const BUILTIN_RISK = "Built-in";
const BUILTIN_RISK_NOTE = "Ships with the daemon. Updated with it.";
const STRICTER_RISK = "Your stricter entries";
const STRICTER_RISK_NOTE = "From your policy file. They can only raise a level, never lower it.";
const LADDER_HEADING = "HOW LONG SHOULD THIS LAST?";
const LADDER_NOTE = "Rules match the exact command above, character for character.";
const LOCK_GLOBAL = "All bots isn't offered";
const CANT_BE_A_RULE = "Can't be a rule";
const HOOK_CRITICAL_ONCE = "Deny this. A critical command from the CLI can't be approved once, because that approval can't be tied to one run.";

function hashIsApprovals(hash) {
  return String(hash || "").replace(/^#/, "") === "approvals";
}
function approvalRank(level) {
  const l = String(level || "").toLowerCase();
  if (l === "critical") return 0;
  if (l === "high") return 1;
  if (l === "low") return 3;
  return 2;
}
function groupTitle(rank) {
  if (rank === 0) return "Critical";
  if (rank === 1) return "High";
  if (rank === 3) return "Low";
  return "Medium & Unclassified";
}
function orderApprovalIds(items, prevIds, focusId) {
  const list = (items || []).slice();
  list.sort(function (a, b) {
    const r = approvalRank(a && a.level) - approvalRank(b && b.level);
    if (r) return r;
    const ta = Date.parse(a && a.created_at) || 0;
    const tb = Date.parse(b && b.created_at) || 0;
    if (ta !== tb) return ta - tb;
    const ia = String((a && a.id) || "");
    const ib = String((b && b.id) || "");
    return ia < ib ? -1 : ia > ib ? 1 : 0;
  });
  const ids = list.map(function (x) { return x.id; });
  if (!focusId || !prevIds || prevIds.indexOf(focusId) < 0 || ids.indexOf(focusId) < 0) return ids;
  const from = ids.indexOf(focusId);
  ids.splice(from, 1);
  let dest = prevIds.indexOf(focusId);
  if (dest > ids.length) dest = ids.length;
  ids.splice(dest, 0, focusId);
  return ids;
}
function approvalAge(created, now, frozenAt) {
  const end = frozenAt ? frozenAt : now;
  const start = created instanceof Date ? created.getTime() : Date.parse(created);
  if (!isFinite(start) || !isFinite(end)) return "";
  let ms = end - start;
  if (ms < 0) ms = 0;
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return mins + "m";
  const hours = Math.floor(mins / 60);
  if (hours < 24) return hours + "h " + (mins % 60) + "m";
  return approvalSince(new Date(start));
}
function approvalSince(date) {
  const d = date instanceof Date ? date : new Date(date);
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  let h = d.getHours();
  const am = h < 12;
  h = h % 12;
  if (h === 0) h = 12;
  const m = String(d.getMinutes()).padStart(2, "0");
  return "since " + days[d.getDay()] + " " + h + ":" + m + " " + (am ? "AM" : "PM");
}
function approvalKey(e, typing) {
  const ev = e || {};
  if (ev.altKey || ev.ctrlKey || ev.metaKey) return { close: false, open: false, approve: false };
  if (ev.key === "Escape") return { close: true, open: false, approve: false };
  if ((ev.key === "a" || ev.key === "A") && !typing) return { close: false, open: true, approve: false };
  return { close: false, open: false, approve: false };
}
function approvalFriction(item) {
  if (!item) return "medium";
  if (item.compound) return "compound";
  const l = String(item.level || "unclassified");
  if (l === "critical" || l === "high" || l === "low" || l === "medium") return l;
  return "unclassified";
}
function onceOnlyScopes(item) {
  const allowed = item && item.allowed_scopes;
  if (!allowed || !allowed.length) return false;
  for (let i = 0; i < allowed.length; i++) if (allowed[i] !== "once") return false;
  return true;
}
function approvalActions(item) {
  const friction = approvalFriction(item);
  const level = item && item.level;
  const lockGlobal = level === "high" || level === "unclassified";
  if (friction === "compound") return { approve: "once", chevron: false, deny: "outline", batch: false, note: CANT_BE_A_RULE, lockGlobal: false };
  if (friction === "critical" && item && item.origin === "hook") return { approve: "none", chevron: false, deny: "fill", batch: false, note: HOOK_CRITICAL_ONCE, lockGlobal: false };
  if (friction === "critical") return { approve: "confirm", chevron: false, deny: "fill", batch: false, note: CANT_BE_A_RULE, lockGlobal: false };
  if (onceOnlyScopes(item)) return { approve: "once", chevron: false, deny: "outline", batch: false, note: "", lockGlobal: false };
  if (friction === "high") return { approve: "split-secondary", chevron: true, deny: "outline", batch: false, lockGlobal: true };
  if (friction === "low") return { approve: "split-primary", chevron: true, deny: "outline", batch: true, lockGlobal: false };
  if (friction === "unclassified") return { approve: "split-primary", chevron: true, deny: "outline", batch: false, lockGlobal: true };
  return { approve: "split-primary", chevron: true, deny: "outline", batch: false, lockGlobal: !!lockGlobal };
}
function ladderSteps(item) {
  const allowed = (item && item.allowed_scopes) || [];
  const has = function (s) { return allowed.indexOf(s) >= 0; };
  const level = String((item && item.level) || "");
  const capGlobal = level === "high" || level === "unclassified";
  const steps = [];
  if (has("once")) steps.push({ scope: "once", label: "Just this once" });
  if (has("task")) steps.push({ scope: "task", label: "This task" });
  if (has("bot")) steps.push({ scope: "bot", label: "Always for {bot}" });
  if (has("global") && !capGlobal) steps.push({ scope: "global", label: "All bots" });
  return { steps: steps, lockGlobal: capGlobal };
}
function taskStepCopy(bot, task) {
  return "Until " + (bot || "the bot") + " finishes your message \"" + (task || "") + "\". Your next message asks again.";
}
function botStepCopy(bot) {
  const name = bot || "this bot";
  return "This exact command only, for " + name + ". Any change to the arguments asks again.";
}
function globalStepCopy() {
  return "This exact command, for every bot, including ones you add later. Deny rules still win.";
}
function commitLabel(scope, bot) {
  const name = bot || "this bot";
  if (scope === "task") return "Approve for this task";
  if (scope === "bot") return "Approve · always for " + name;
  if (scope === "global") return "Approve · always for all bots";
  return "Approve once";
}
function patternErrorCopy(code, cmd, wrappers) {
  const c = String(code || "");
  if (c === "trailing_wildcard") return "There's no \"match the rest\" wildcard. A * stands for exactly one word and cannot be last.";
  if (c === "wrapper") {
    const list = (wrappers || []).filter(Boolean);
    const prefer = ["sh", "env", "sudo", "xargs", "python", "node"];
    const picked = [];
    for (let i = 0; i < prefer.length; i++) if (list.indexOf(prefer[i]) >= 0) picked.push(prefer[i]);
    for (let j = 0; j < list.length && picked.length < 6; j++) {
      if (picked.indexOf(list[j]) < 0 && list[j] !== ".") picked.push(list[j]);
    }
    const shown = picked.slice(0, 6).map(function (w) { return "`" + w + "`"; }).join(", ");
    return "`" + (cmd || "that command") + "` can run any other command, so it can't start a pattern. The same goes for " + (shown || "the commands on the daemon's list") + " and others on the daemon's list.";
  }
  if (c === "flag_star") return "A `*` can't stand for a flag or be part of one. Write the flag out in full, for example `--json`.";
  if (c === "star_in_word") return "A `*` must be a whole word on its own.";
  if (c === "star_first") return "Start with the command name, for example `gh`.";
  if (c === "operators") return "Patterns can't contain ; && | $( ) or backticks. Commands with several parts always ask.";
  if (c === "never_matches") return "This command cannot be allowed by a rule.";
  return "";
}
function denyToast(bot) { return "Denied. " + (bot || "The bot") + " carries on without it."; }
function denyAllToast(n, bot) { return "Denied " + n + " requests. " + (bot || "The bot") + " carries on without them."; }
function denyRecord(bot, argv) { return "Denied · " + (bot || "The bot") + " carries on without it · " + (argv || ""); }
function denyAllRecord(n, bot, argv) { return "Denied " + n + " · " + (bot || "The bot") + " carried on · " + (argv || ""); }
function denyAllDesc(n, bot) { return "Denies these " + n + " requests. " + (bot || "The bot") + " carries on without them."; }
function partStatus(part, bot) {
  if (part && part.granted_for_task) return "Granted for this task";
  if (part && part.has_bot_rule) return "Has a " + (bot || "bot") + " rule, but no task grant";
  return "Not granted for this task";
}
function compoundIntro(item) {
  const parts = (item && item.parts) || [];
  const n = parts.length;
  const ops = (item && item.operators) || [];
  const joined = ops.length ? " joined by " + ops.join(" and ") : "";
  const missing = parts.filter(function (p) { return !p.granted_for_task; }).length;
  const here = missing === 1 ? "Here one part isn't granted" : "Here " + missing + " parts aren't granted";
  const noun = n === 1 ? "part" : "parts";
  return "This command has " + n + " " + noun + joined + ". Commands with several parts ask and can't be saved as a rule. The one exception: when every part is already granted for this task, the task grant covers the whole command. Other rules don't count. " + here + ", so it asks:";
}
function recentLabel(kind, bot) {
  if (kind === "expired") return "Expired · " + (bot || "bot") + " stopped";
  if (kind === "approved") return "Approved on another device";
  if (kind === "allowed_by_rule") return "Allowed by rule";
  if (kind === "denied_by_rule") return "Denied by rule";
  if (kind === "allowed_by_task_grant") return "Allowed by task grant";
  return "";
}
function showRecent(row, own) {
  if (!row) return "";
  if (row.kind === "denied") return "";
  if (row.kind === "approved" && own) return "";
  return recentLabel(row.kind, row.bot_name || row.bot_id || "bot");
}
function criticalTitle(base, n) {
  const title = String(base || "");
  const count = Number(n) || 0;
  if (count <= 0) return title;
  return "(" + count + ") Critical approval · " + title;
}
function commandBasename(argv) {
  let name = "";
  if (Array.isArray(argv)) name = argv.length ? String(argv[0] || "") : "";
  else name = String(argv || "").trim().split(/\s+/)[0] || "";
  name = name.replace(/\\/g, "/");
  const cut = name.lastIndexOf("/");
  if (cut >= 0) name = name.slice(cut + 1);
  return name || "A command";
}
function notifyTitle(bot) {
  return "Critical request · " + (bot || "A bot");
}
function notifyBody(argv) {
  return commandBasename(argv) + " needs your approval.";
}
function notifyStateLabel(secure, permission, locallyOff) {
  if (secure === false) return "Not available";
  if (permission === "denied") return "Blocked";
  if (permission === "granted" && !locallyOff) return "On";
  return "Off";
}
function identicalKey(item) {
  if (!item || item.compound || String(item.level) !== "low") return "";
  return String(item.bot_id || "") + "\n" + JSON.stringify(item.argv || []);
}
function splitArgv(text) {
  const s = String(text || "").trim();
  const out = [];
  let i = 0;
  while (i < s.length) {
    while (s.charAt(i) === " ") i++;
    if (i >= s.length) break;
    const q = s.charAt(i);
    if (q === "\"" || q === "'") {
      let j = i + 1;
      while (j < s.length && s.charAt(j) !== q) j++;
      const end = s.charAt(j) === q ? j + 1 : j;
      out.push(s.slice(i, end));
      i = end;
    } else {
      let j = i;
      while (j < s.length && s.charAt(j) !== " ") j++;
      out.push(s.slice(i, j));
      i = j;
    }
  }
  return out;
}
function exactHasOp(text) {
  const s = String(text || "");
  return /[;|&`\n()]/.test(s) || s.indexOf("$(") >= 0;
}
function matchAllowRule(rules, item, scope) {
  const argv = JSON.stringify((item && item.argv) || []);
  const bot = scope === "global" ? "" : ((item && item.bot_id) || "");
  let best = null;
  for (let i = 0; i < (rules || []).length; i++) {
    const r = rules[i];
    if (!r || r.effect !== "allow") continue;
    if (r.kind === "pattern" || r.kind === "legacy") continue;
    if (r.scope !== scope) continue;
    if (scope === "bot" && (r.bot_id || "") !== bot) continue;
    if (scope === "global" && r.bot_id) continue;
    if (JSON.stringify(r.argv || []) !== argv) continue;
    if (!best || String(r.created_at || "") > String(best.created_at || "")) best = r;
  }
  return best;
}
function previewSummary(summary, name) {
  const s = summary || {};
  const allow = s.would_allow || 0;
  const ask = (s.would_ask || 0) + (s.still_asks_compound || 0) + (s.still_asks_critical || 0);
  const who = name ? name + "'s" : "the";
  return allow + " of " + who + " last 50 requests would be allowed · " + ask + " still asks";
}
function outcomeLabel(outcome, reason) {
  if (outcome === "would_allow") return "Would be allowed";
  if (outcome === "would_ask") return "Would ask";
  if (outcome === "would_deny") return "Would be denied";
  if (outcome === "still_asks_compound") return "Still asks · several parts";
  if (outcome === "still_asks_critical") return "Still asks · critical";
  let text = "Doesn't match";
  if (reason === "flag_in_star") text += " · `*` never matches a flag";
  else if (reason === "extra_word") text += " · extra word";
  else if (reason === "missing_word") text += " · missing word";
  return text;
}
function armReady(ui, now) {
  if (!ui || !ui.armedAt) return false;
  return (now || 0) - ui.armedAt >= APPROVE_ARM_MS;
}
function levelWord(level) {
  const l = String(level || "unclassified");
  return l.charAt(0).toUpperCase() + l.slice(1);
}
function approvalTitle(item) {
  const it = item || {};
  const reason = String(it.critical_reason || "");
  if (reason) return reason;
  if (it.compound) return "Run a command with several parts";
  const tool = String(it.tool || "").toLowerCase();
  if (tool === "shell" || tool === "bash") return "Run a shell command";
  if (tool === "edit" || tool === "write" || tool === "multiedit" || tool === "notebookedit") return "Edit a file";
  if (tool === "read" || tool === "glob" || tool === "grep") return "Read a file";
  return "Permission needed";
}
function flattenTaskText(text) {
  return String(text == null ? "" : text).replace(/\s+/g, " ").trim();
}
function queueBotCount(items) {
  const seen = {};
  let n = 0;
  (items || []).forEach(function (item) {
    const id = String((item && item.bot_id) || "");
    if (!id || seen[id]) return;
    seen[id] = true;
    n += 1;
  });
  return n;
}
function queueSubtitle(requests, bots) {
  const n = Number(requests) || 0;
  const m = Number(bots) || 0;
  const req = n === 1 ? "1 request" : n + " requests";
  const bot = m === 1 ? "1 bot" : m + " bots";
  return req + " · " + bot;
}
function advisorySource(advisory, level) {
  const a = advisory || {};
  const src = String(a.source || "");
  if (!a.checked && (!src || src === "table")) return "Not checked";
  const raised = src.match(/^local model raised this to ([a-z]+)$/i);
  if (raised) return "Local model raised this to " + raised[1].toLowerCase();
  if (!src || src === "table") return levelWord(level) + " from the built-in table. Local model: no change.";
  return src.charAt(0).toUpperCase() + src.slice(1);
}
function eyebrowFor(level) {
  if (String(level || "").toLowerCase() === "critical") return CRITICAL_EYEBROW;
  return String(level || "unclassified").toUpperCase() + " RISK · PERMISSION NEEDED";
}
function shortCwd(cwd) {
  const s = String(cwd || "");
  const home = s.match(/^\/(?:home|Users)\/[^/]+(\/.*)?$/);
  if (!home) return s;
  return "~" + (home[1] || "");
}
function primaryActionKey(item, mode) {
  const prefix = mode === "thread" ? "t:" : "q:";
  const level = String((item && item.level) || "");
  if (level === "high" || level === "critical") return prefix + "deny:" + item.id;
  return prefix + "approve:" + item.id;
}
function nextQueueFocusKey(items, removeIds) {
  const gone = {};
  (removeIds || []).forEach(function (id) { gone[id] = true; });
  const all = items || [];
  const left = all.filter(function (item) { return item && !gone[item.id]; });
  if (!left.length) return "approvals-empty";
  const ordered = orderApprovalIds(all, [], "");
  let next = "";
  for (let i = 0; i < ordered.length; i++) {
    if (!gone[ordered[i]]) continue;
    for (let j = i + 1; j < ordered.length; j++) {
      if (!gone[ordered[j]]) { next = ordered[j]; break; }
    }
    if (next) break;
  }
  if (!next) {
    const remain = orderApprovalIds(left, [], "");
    next = remain.length ? remain[remain.length - 1] : "";
  }
  let item = null;
  for (let k = 0; k < left.length; k++) if (left[k].id === next) item = left[k];
  return item ? primaryActionKey(item, "queue") : "approvals-title";
}
function batchCount(okCount, sent) {
  if (okCount == null || okCount === "") {
    const n = Number(sent);
    return isFinite(n) && n > 0 ? n : 0;
  }
  const n = Number(okCount);
  if (isFinite(n)) return n;
  const fallback = Number(sent);
  return isFinite(fallback) ? fallback : 0;
}
function batchResultCopy(kind, okCount, skipped, bot) {
  const ok = Number(okCount) || 0;
  const skip = Number(skipped) || 0;
  if (skip > 0) return ok + " done, " + skip + " already answered.";
  if (kind === "approve") return "Approved " + ok + " requests.";
  return denyAllToast(ok, bot);
}
function ruleMenuKey(key, count, index) {
  const n = Number(count) || 0;
  if (key === "Escape") return { close: true, move: -1 };
  if (key === "Home" && n) return { close: false, move: 0 };
  if (key === "End" && n) return { close: false, move: n - 1 };
  if (key === "ArrowDown" && n) {
    const i = index < 0 ? 0 : Math.min(n - 1, index + 1);
    return { close: false, move: i };
  }
  if (key === "ArrowUp" && n) {
    const i = index <= 0 ? 0 : index - 1;
    return { close: false, move: i };
  }
  return { close: false, move: -1 };
}
function riskLabel(row) {
  if (row && row.label) return String(row.label);
  const matches = (row && row.matches) || [];
  const first = String(matches[0] || "").trim().split(/\s+/)[0];
  if (first === "rm") return "Deletes files";
  if (first === "edit" || first === "write" || first === "multiedit" || first === "notebookedit") return "Changes files";
  if (first === "grep" || first === "read" || first === "glob" || first === "cat") return "Reads files";
  if (first === "cut" || first === "head" || first === "wc") return "Reads text";
  const two = String(matches[0] || "").trim().split(/\s+/).slice(0, 2).join(" ");
  if (two === "gh alias") return "Changes GitHub CLI settings";
  if (two === "git push") return "Publishes code";
  return "Runs a command";
}
function ruleDateLabel(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (!isFinite(d.getTime()) || d.getFullYear() < 2000) return "";
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return months[d.getMonth()] + " " + d.getDate();
}
function provenanceLine(rule) {
  const r = rule || {};
  if (r.kind === "legacy" || r.source === "legacy") return LEGACY_NOTE;
  const date = ruleDateLabel(r.created_at);
  const tail = date ? " · " + date : "";
  if (r.source === "prompt") return "Saved from a prompt" + tail;
  return "Added by you" + tail;
}
function groupCountLabel(rank, count) {
  return groupTitle(rank) + " · " + (Number(count) || 0);
}
function ruleSheetSaveError(res) {
  if (!res || res.network) return { message: SEND_FAILED_COPY, invalid: false };
  const status = Number(res.status) || 0;
  const code = res.data && res.data.code;
  if (status >= 400 && status < 500 && code === "never_matches") {
    return { message: patternErrorCopy("never_matches"), invalid: true };
  }
  const data = res.data || {};
  const message = String(data.error || data.message || "Couldn't save this rule.");
  return { message: message, invalid: false };
}
function firstIdenticalId(items, item) {
  const key = identicalKey(item);
  if (!key) return "";
  const ordered = orderApprovalIds(items || [], [], "");
  const byId = {};
  (items || []).forEach(function (other) { if (other) byId[other.id] = other; });
  for (let i = 0; i < ordered.length; i++) {
    const other = byId[ordered[i]];
    if (other && identicalKey(other) === key) return other.id;
  }
  return item && item.id;
}
// approvals-pure:end
// approvals-dom:begin
let approvalItems = null;
let approvalRules = [];
let approvalGrants = [];
let approvalRecent = [];
let approvalRisk = null;
let cardUI = {};
let localRecords = [];
let uiRev = 0;
let queueOpen = false;
let queueManual = false;
let queueDismissed = false;
let queueSig = "";
let threadSig = "";
let prevOrder = [];
let rulesFilter = "all";
let rulesSig = "";
let rulesForce = false;
let alertsSig = "";
let pollTimer = 0;
let pollAgain = false;
let ruleDraft = null;
let ruleToken = 0;
const approvals = {
  netDown: false,
  frozenAt: 0,
  polled: false,
  wrappers: null,
  seenCritical: [],
  seenReady: false,
  lastCount: null,
  notes: {},
  notified: {},
  own: [],
  forceAlerts: false,
  focusDeny: "",
  wantFocus: false,
  polling: false,
  started: false,
  editingId: "",
  intendedFocus: ""
};
let batchFlight = null;

function approvalsCriticalCount() {
  let n = 0;
  const items = approvalItems || [];
  for (let i = 0; i < items.length; i++) if (items[i].level === "critical") n += 1;
  return n;
}
function approvalCountsFor(id) {
  if (approvalItems == null) return null;
  let total = 0;
  let critical = 0;
  for (let i = 0; i < approvalItems.length; i++) {
    const item = approvalItems[i];
    if (item.bot_id !== id) continue;
    total += 1;
    if (item.level === "critical") critical += 1;
  }
  return { total: total, critical: critical };
}
function queueIsOpen() { return !!queueOpen; }
function brokerCardPending() {
  const host = document.getElementById("broker-thread");
  return !!(host && host.querySelector(".appr-card"));
}
function isTypingTarget(node) {
  if (!node || !node.tagName) return false;
  const tag = node.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  return !!node.isContentEditable;
}
function botLabel(id, fallback) {
  const list = (state && state.bots) || [];
  for (let i = 0; i < list.length; i++) if (list[i].id === id && list[i].name) return list[i].name;
  return fallback || id || "bot";
}
function itemBot(item) {
  if (!item) return "The bot";
  return item.bot_name || botLabel(item.bot_id, "The bot");
}
function itemArgv(item) {
  if (!item) return "";
  if (item.command) return item.command;
  return (item.argv || []).join(" ");
}
function approvalsUnreachable() {
  if (approvals.netDown) return true;
  if (typeof daemonUnreachable === "function" && daemonUnreachable()) return true;
  return false;
}
function syncFreeze() {
  if (approvalsUnreachable()) {
    if (!approvals.frozenAt) approvals.frozenAt = Date.now();
  } else approvals.frozenAt = 0;
}
function approvalMode() {
  if (window.matchMedia && window.matchMedia("(min-width: 1180px)").matches) return "dock";
  if (window.matchMedia && window.matchMedia("(min-width: 980px)").matches) return "slide";
  return "sheet";
}
function ensureUI(id) {
  if (!cardUI[id]) cardUI[id] = {};
  return cardUI[id];
}
function focusedApprovalId() {
  const active = document.activeElement;
  if (!active || !active.getAttribute) return "";
  const key = active.getAttribute("data-appr-focus") || "";
  const m = key.match(/:([^:]+)$/);
  return m ? m[1] : "";
}
function cloneTpl(id) {
  const tpl = document.getElementById(id);
  if (tpl && tpl.content) return tpl.content.cloneNode(true);
  return document.createTextNode("");
}
function btn(cls, text) {
  const n = el("button", cls, text);
  n.type = "button";
  return n;
}
function setAriaDisabled(node, on) {
  if (!node) return;
  if (on) node.setAttribute("aria-disabled", "true");
  else node.removeAttribute("aria-disabled");
}
function rememberOwn(item, kind) {
  approvals.own.push({ bot_id: item.bot_id, command: itemArgv(item), kind: kind });
  if (approvals.own.length > 50) approvals.own.shift();
}
function isOwnRecent(row) {
  const cmd = row.command || (row.argv || []).join(" ");
  for (let i = 0; i < approvals.own.length; i++) {
    const o = approvals.own[i];
    if (o.bot_id !== row.bot_id || o.command !== cmd) continue;
    if (o.kind === "approve" && row.kind === "approved") return true;
    if (o.kind === "deny" && row.kind === "denied") return true;
  }
  return false;
}
function closeNote(id) {
  const note = approvals.notes[id];
  if (!note) return;
  try { note.close(); } catch (e) {}
  delete approvals.notes[id];
}
async function brokerCall(path, opts) {
  const headers = {};
  const method = String((opts && opts.method) || "GET").toUpperCase();
  const mutating = method === "POST" || method === "PUT" || method === "PATCH" || method === "DELETE";
  let body = opts && opts.body;
  if (mutating) {
    headers["Content-Type"] = "application/json";
    if (body == null || body === "") body = "{}";
  }
  if (state.token) headers.Authorization = "Bearer " + state.token;
  try {
    const res = await fetch(base() + path, {
      method: method,
      headers: headers,
      body: body || undefined,
      cache: "no-store"
    });
    const text = await res.text();
    let data = null;
    if (text) { try { data = JSON.parse(text); } catch (e) { data = { error: text }; } }
    if (res.status === 401 && typeof showAuth === "function") showAuth();
    return { network: false, status: res.status, data: data };
  } catch (e) {
    return { network: true, status: 0, data: null };
  }
}
function showReconnect() {
  const note = $("#approvals-banner");
  if (!note) return;
  note.hidden = false;
  note.textContent = RECONNECT_COPY;
}
function guardAnswer(ev) {
  if (!approvalsUnreachable()) return false;
  if (ev) ev.preventDefault();
  showReconnect();
  return true;
}
function paintApprovalButtons() {
  const items = approvalItems || [];
  const n = items.length;
  let c = 0;
  for (let i = 0; i < items.length; i++) if (items[i].level === "critical") c += 1;
  const down = approvalsUnreachable();
  const label = "Approvals, " + n + " waiting, " + c + " critical";
  document.querySelectorAll("button.appr-btn").forEach(function (button) {
    button.classList.toggle("is-zero", n === 0 && !down);
    button.classList.toggle("is-wait", n > 0 && c === 0 && !down);
    button.classList.toggle("is-critical", c > 0 && !down);
    button.classList.toggle("is-open", queueOpen);
    button.classList.toggle("is-down", down);
    button.setAttribute("aria-expanded", queueOpen ? "true" : "false");
    button.setAttribute("aria-label", label);
    const num = button.querySelector(".appr-num");
    if (num) num.textContent = String(n);
    const badge = button.querySelector(".appr-badge");
    if (badge) {
      badge.hidden = n === 0 && !down;
      badge.textContent = String(n);
    }
  });
}
function appendPendingBadge(copy, line2, button, b) {
  if (!b || b.archived || !copy || !line2) return;
  const brokerCounts = approvalCountsFor(b.id);
  const legacyN = Number(b.pending_permissions) || 0;
  const n = brokerCounts ? Math.max(brokerCounts.total, legacyN) : legacyN;
  if (n <= 0) return;
  const critical = !!(brokerCounts && brokerCounts.critical);
  const words = approvalWords(n) + (critical ? ", critical" : "");
  copy.append(el("small", "bot-attn", words));
  const badge = el("span", "perm-badge" + (critical ? " is-critical" : ""), String(n));
  badge.setAttribute("aria-label", words);
  line2.append(badge);
  button.title = critical ? "Critical approval waiting" : "Waiting for your approval";
}
function syncBrokerBadges() {
  const list = document.getElementById("bot-list");
  if (!list) return;
  list.querySelectorAll("button.bot").forEach(function (button) {
    const id = button.getAttribute("data-bot-id");
    const bot = (state.bots || []).find(function (b) { return b.id === id; });
    if (!bot) return;
    const copy = button.querySelector(".bot-copy");
    const lines = button.querySelectorAll(".bot-line");
    const line2 = lines.length > 1 ? lines[1] : null;
    const oldAttn = button.querySelector(".bot-attn");
    const oldBadge = button.querySelector(".perm-badge");
    if (oldAttn) oldAttn.remove();
    if (oldBadge) oldBadge.remove();
    if (copy && line2) appendPendingBadge(copy, line2, button, bot);
  });
}
function notifyBell() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "18");
  svg.setAttribute("height", "18");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const add = function (d) {
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", d);
    p.setAttribute("fill", "none");
    p.setAttribute("stroke", "currentColor");
    p.setAttribute("stroke-width", "2");
    p.setAttribute("stroke-linecap", "round");
    p.setAttribute("stroke-linejoin", "round");
    svg.append(p);
  };
  add("M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z");
  add("M10 19a2 2 0 0 0 4 0");
  return svg;
}
function paintQueueHeader() {
  const sub = $("#approvals-sub");
  const items = approvalItems || [];
  if (sub) sub.textContent = queueSubtitle(items.length, queueBotCount(items));
  const link = $("#approvals-rules");
  if (link && typeof levelURL === "function" && typeof base === "function") {
    link.setAttribute("href", levelURL(base(), "rules", null, ""));
  }
}
function paintRulesLinks() {
  const n = (approvalRules || []).length;
  const menu = $("#menu-rules");
  if (menu) menu.textContent = "Approval rules · " + n;
  const alerts = $("#menu-alerts");
  if (alerts) alerts.textContent = "Critical alerts · " + currentNotifyLabel();
  const link = $("#open-approval-rules");
  if (link) {
    const bot = typeof currentBot === "function" ? currentBot() : null;
    const name = bot ? bot.name : "this bot";
    let mine = n;
    if (bot) {
      mine = 0;
      for (let i = 0; i < approvalRules.length; i++) {
        if (approvalRules[i].scope === "bot" && approvalRules[i].bot_id === bot.id) mine += 1;
      }
    }
    link.textContent = mine + " rules for " + name + " · Open Approval rules";
  }
}
function currentNotifyLabel() {
  if (typeof window !== "undefined" && window.isSecureContext === false) return notifyStateLabel(false, "", false);
  if (typeof window.Notification === "undefined") return "Not available";
  let off = false;
  try { off = localStorage.getItem("lgb.notify.off") === "1"; } catch (e) {}
  return notifyStateLabel(true, window.Notification.permission, off);
}
function notifySnoozed() {
  try { return Number(localStorage.getItem("lgb.notify.snoozeUntil") || 0) > Date.now(); } catch (e) { return false; }
}
function setApprovalsHash(on) {
  if (!on) {
    if (hashIsApprovals(location.hash)) history.replaceState(history.state, "", location.pathname + location.search);
    return;
  }
  if (!queueManual) return;
  if (location.hash && !hashIsApprovals(location.hash)) return;
  if (hashIsApprovals(location.hash)) return;
  history.replaceState(history.state, "", location.pathname + location.search + "#approvals");
}
function applyQueueChrome() {
  const panel = $("#approvals");
  const scrim = $("#approvals-scrim");
  const mode = approvalMode();
  const dock = queueOpen && mode === "dock";
  document.body.classList.toggle("queue-dock", dock);
  if (panel) {
    panel.hidden = !queueOpen;
    panel.classList.toggle("is-dock", queueOpen && mode === "dock");
    panel.classList.toggle("is-slide", queueOpen && mode === "slide");
    panel.classList.toggle("is-sheet", queueOpen && mode === "sheet");
    if (!queueOpen || mode === "dock") {
      panel.setAttribute("role", "region");
      panel.removeAttribute("aria-modal");
    } else {
      panel.setAttribute("role", "dialog");
      panel.setAttribute("aria-modal", "true");
    }
  }
  if (scrim) scrim.hidden = !(queueOpen && mode !== "dock");
  setApprovalsHash(queueOpen);
  paintApprovalButtons();
}
function reconcileQueue() {
  const waiting = (approvalItems || []).length > 0;
  const dock = approvalMode() === "dock";
  if (!waiting) queueDismissed = false;
  if (queueOpen && !waiting && !queueManual) queueOpen = false;
  if (!queueOpen && dock && waiting && !queueDismissed) {
    queueOpen = true;
    queueManual = false;
  }
}
function openApprovals(opts) {
  queueOpen = true;
  queueManual = !(opts && opts.auto);
  queueDismissed = false;
  if (opts && opts.focus) approvals.wantFocus = true;
  if (typeof closeRosterMenu === "function") closeRosterMenu();
  if (typeof closeMenu === "function") closeMenu();
  applyQueueChrome();
  approvals.force = true;
  renderApprovals();
}
function setIntendedFocus(key) {
  approvals.intendedFocus = key || "";
}
function nodeShown(node) {
  if (!node || !node.isConnected) return false;
  let el = node;
  while (el && el.nodeType === 1) {
    if (el.hidden) return false;
    if (window.getComputedStyle) {
      const st = window.getComputedStyle(el);
      if (st.display === "none" || st.visibility === "hidden") return false;
    }
    el = el.parentElement;
  }
  return true;
}
function approvalOpener() {
  const list = document.querySelectorAll("button.appr-btn");
  for (let i = 0; i < list.length; i++) {
    if (nodeShown(list[i])) return list[i];
  }
  return null;
}
function focusNode(node) {
  if (!nodeShown(node) || typeof node.focus !== "function") return false;
  try { node.focus({ preventScroll: true }); }
  catch (e) { node.focus(); }
  const card = node.closest ? node.closest(".appr-card") : null;
  if (card && card.scrollIntoView) card.scrollIntoView({ block: "nearest" });
  const again = function () {
    if (!nodeShown(node)) return;
    const active = document.activeElement;
    if (active === node) return;
    if (!active || active === document.body || active === document.documentElement || !active.isConnected || (active.closest && active.closest("[hidden]"))) {
      try { node.focus({ preventScroll: true }); }
      catch (e2) { node.focus(); }
    }
  };
  if (typeof requestAnimationFrame === "function") requestAnimationFrame(again);
  setTimeout(again, 0);
  setTimeout(again, 50);
  return document.activeElement !== document.body;
}
function applyIntendedFocus(root) {
  const key = approvals.intendedFocus;
  if (!key) return false;
  const rulesKey = key.indexOf("rules:") === 0;
  let node = null;
  if (key === "approvals-empty" || key === "approvals-title") {
    const panel = document.getElementById("approvals");
    const open = !!(panel && !panel.hidden && nodeShown(panel));
    const empty = document.getElementById("approvals-empty-title");
    if (key === "approvals-empty" && open && nodeShown(empty)) node = empty;
    else if (key === "approvals-title" && open && nodeShown(document.getElementById("approvals-title"))) node = document.getElementById("approvals-title");
    else node = approvalOpener();
  } else if (key === "approvals-opener") {
    node = approvalOpener();
  } else if (rulesKey) {
    node = findByAttr(document.getElementById("rules-list") || document, "data-rules-focus", key.slice(6));
    if (!nodeShown(node)) return false;
  } else {
    node = findByAttr(root || document, "data-appr-focus", key) || findByAttr(document, "data-appr-focus", key);
  }
  if (!rulesKey && !nodeShown(node)) node = approvalOpener();
  if (!nodeShown(node)) {
    if (!rulesKey) approvals.intendedFocus = "";
    return false;
  }
  approvals.intendedFocus = "";
  const landed = focusNode(node);
  return landed && document.activeElement !== document.body;
}
function closeApprovals() {
  const opener = approvalOpener();
  const panel = $("#approvals");
  if (panel) panel.removeAttribute("aria-modal");
  if (opener) {
    try { opener.focus({ preventScroll: true }); }
    catch (e) { opener.focus(); }
  }
  const waiting = (approvalItems || []).length > 0;
  queueOpen = false;
  queueManual = false;
  if (waiting) queueDismissed = true;
  applyQueueChrome();
  setIntendedFocus("approvals-opener");
  applyIntendedFocus(document);
}
function closeApprovalLayer() {
  const sheet = $("#rule-sheet");
  if (sheet && !sheet.hidden) { closeRuleSheet(); return true; }
  const pop = document.querySelector("#view-rules .rules-pop:not([hidden])");
  if (pop) { pop.hidden = true; return true; }
  if (queueOpen) { closeApprovals(); return true; }
  return false;
}
function syncApprovalsHash() {
  if (hashIsApprovals(location.hash)) openApprovals({ manual: true, focus: false });
}
function openRules(bot, push) {
  if (typeof navBypass !== "undefined" && !navBypass && typeof profileDirty === "function" && profileDirty()) {
    confirmLeave(function () { openRules(bot, push); });
    return;
  }
  if (typeof closeState === "function") closeState();
  if (typeof closeRosterMenu === "function") closeRosterMenu();
  if (typeof closeMenu === "function") closeMenu();
  const id = bot || "";
  state.rulesBot = id;
  if (push !== false) commitLevel({ view: "rules", bot: id || null }, "push");
  setView("rules");
  setTitle();
  if (typeof focusPane === "function") focusPane("rules");
  rulesForce = true;
  paintRules();
}
function findByAttr(root, name, value) {
  if (!root || !root.querySelectorAll) return null;
  const all = root.querySelectorAll("[" + name + "]");
  for (let i = 0; i < all.length; i++) if (all[i].getAttribute(name) === value) return all[i];
  return null;
}
function typingFocus() { return isTypingTarget(document.activeElement); }
function patchAges(root) {
  if (!root) return;
  const byId = {};
  (approvalItems || []).forEach(function (item) { byId[item.id] = item; });
  root.querySelectorAll("[data-age-for]").forEach(function (node) {
    const item = byId[node.getAttribute("data-age-for")];
    if (item) node.textContent = approvalAge(item.created_at, Date.now(), approvals.frozenAt || 0);
  });
}
function appendCommand(pre, item) {
  const raw = itemArgv(item);
  const ops = (item.compound && item.operators) || [];
  if (!ops.length) { pre.textContent = raw; return; }
  const sorted = ops.slice().sort(function (a, b) { return b.length - a.length; });
  let rest = raw;
  while (rest.length) {
    let at = -1;
    let hit = "";
    for (let i = 0; i < sorted.length; i++) {
      const iAt = rest.indexOf(sorted[i]);
      if (iAt >= 0 && (at < 0 || iAt < at)) { at = iAt; hit = sorted[i]; }
    }
    if (at < 0) { pre.append(document.createTextNode(rest)); break; }
    if (at > 0) pre.append(document.createTextNode(rest.slice(0, at)));
    pre.append(el("span", "appr-op", hit));
    rest = rest.slice(at + hit.length);
  }
}
function scheduleArm(id) {
  const ui = cardUI[id];
  if (!ui || !ui.confirm || !ui.armedAt || ui.armTimer) return;
  const left = APPROVE_ARM_MS - (Date.now() - ui.armedAt);
  if (left <= 0) return;
  ui.armTimer = setTimeout(function () {
    if (cardUI[id]) cardUI[id].armTimer = 0;
    if (!cardUI[id] || !cardUI[id].confirm) return;
    uiRev += 1;
    renderApprovals();
  }, left + 40);
}
function copyCommand(text) {
  const value = String(text || "");
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(value).catch(function () { copyFallback(value); });
    return;
  }
  copyFallback(value);
}
function copyFallback(value) {
  const area = document.createElement("textarea");
  area.value = value;
  document.body.append(area);
  area.select();
  try { document.execCommand("copy"); } catch (e) {}
  area.remove();
}
function renderApprovalCard(item, mode) {
  const friction = approvalFriction(item);
  const actions = approvalActions(item);
  const ui = ensureUI(item.id);
  const level = String(item.level || "unclassified");
  const card = el("article", "appr-card is-" + (item.compound ? friction === "compound" ? (level === "unclassified" ? "unclassified" : level) : level : (level === "unclassified" ? "unclassified" : level)));
  if (level === "critical") card.classList.add("is-critical");
  if (level === "high") card.classList.add("is-high");
  if (level === "low") card.classList.add("is-low");
  if (level === "medium") card.classList.add("is-medium");
  if (level === "unclassified") card.classList.add("is-unclassified");
  if (mode === "thread") card.classList.add("is-thread");
  card.setAttribute("data-level", level);
  card.setAttribute("data-id", item.id);
  if (level === "critical") card.append(el("div", "appr-band", CRITICAL_BAND));
  const inner = el("div", "appr-in");
  const argv = el("div", "appr-argv");
  const head = el("div", "appr-argv-h");
  head.append(el("span", "", item.compound ? "Exact command · several parts" : "Exact command"));
  const copy = btn("ghost small appr-copy", "Copy");
  copy.setAttribute("aria-label", "Copy command");
  copy.addEventListener("click", function () { copyCommand(itemArgv(item)); });
  head.append(copy);
  argv.append(head);
  const pre = el("pre", "appr-pre");
  appendCommand(pre, item);
  argv.append(pre);
  const cwd = String(item.cwd || "");
  const tool = String(item.tool || "");
  if (cwd || tool) {
    const meta = el("div", "appr-meta", [cwd ? shortCwd(cwd) : "", tool].filter(Boolean).join(" · "));
    if (cwd) meta.title = cwd;
    argv.append(meta);
  }
  if (cwd) {
    const details = document.createElement("details");
    details.className = "appr-details";
    const summary = document.createElement("summary");
    summary.textContent = "Working directory";
    details.append(summary, el("p", "appr-cwd-full", cwd));
    argv.append(details);
  }
  inner.append(argv);
  if (item.git_reason) inner.append(el("p", "appr-git", item.git_reason));
  if (mode === "queue") {
    const top = el("div", "appr-top");
    top.append(el("b", "", itemBot(item)));
    const age = el("span", "appr-age", approvalAge(item.created_at, Date.now(), approvals.frozenAt || 0));
    age.setAttribute("data-age-for", item.id);
    top.append(age);
    inner.append(top);
  } else {
    inner.append(el("div", "appr-eyebrow", eyebrowFor(level)));
  }
  const title = el("div", "appr-title");
  const chip = el("span", "appr-chip " + level);
  if (level === "critical") chip.append(cloneTpl("tpl-alert"));
  chip.append(document.createTextNode(level));
  title.append(chip, document.createTextNode(approvalTitle(item)));
  inner.append(title);
  if (item.compound) {
    const note = el("div", "appr-compound");
    note.append(document.createTextNode(compoundIntro(item)));
    const ol = document.createElement("ol");
    (item.parts || []).forEach(function (part) {
      const li = document.createElement("li");
      const row = el("div", "appr-part");
      row.append(el("code", "", part.raw || (part.argv || []).join(" ")));
      row.append(el("span", "", partStatus(part, itemBot(item))));
      li.append(row);
      ol.append(li);
    });
    note.append(ol);
    inner.append(note);
  }
  if (level === "high" || level === "critical") {
    inner.append(el("p", "appr-note-hidden", MODEL_NOTE_HIDDEN));
  } else if (item.advisory) {
    const adv = el("div", "appr-adv");
    adv.append(el("b", "", MODEL_NOTE_TITLE));
    adv.append(el("p", "appr-note-sub", MODEL_NOTE_SUB));
    const noteText = item.advisory ? String(item.advisory.text || "") : "";
    if (noteText) adv.append(el("p", "", noteText));
    adv.append(el("p", "appr-src", advisorySource(item.advisory, item.level)));
    inner.append(adv);
  }
  const prefix = mode === "thread" ? "t:" : "q:";
  if (item.task_text) {
    const task = el("div", "appr-task" + (ui.taskOpen ? " is-open" : ""));
    task.append(el("span", "appr-task-clamp", "Task: " + flattenTaskText(item.task_text)));
    const toggle = btn("ghost small", ui.taskOpen ? "Hide task" : "Show task");
    toggle.setAttribute("data-appr-focus", prefix + "task:" + item.id);
    toggle.addEventListener("click", function () {
      ui.taskOpen = !ui.taskOpen;
      uiRev += 1;
      setIntendedFocus(prefix + "task:" + item.id);
      renderApprovals();
    });
    task.append(toggle);
    inner.append(task);
  }
  if (mode === "queue" && item.bot_id) {
    const open = document.createElement("a");
    open.className = "appr-open";
    open.textContent = "Open thread";
    open.href = (typeof levelURL === "function" && typeof base === "function") ? levelURL(base(), "chat", item.bot_id, "") : "/";
    open.addEventListener("click", function (ev) {
      if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey || ev.button) return;
      ev.preventDefault();
      if (typeof openBot === "function") openBot(item.bot_id, true);
    });
    inner.append(open);
  }
  card.append(inner);
  if (ui.sendError) {
    const err = el("div", "appr-err");
    err.append(document.createTextNode(SEND_FAILED_COPY + " "));
    const retry = btn("secondary small", "Try again");
    retry.addEventListener("click", function (ev) {
      if (guardAnswer(ev)) return;
      const last = ui.lastTry || { decision: "deny" };
      if (last.batch) postBatch(last.kind || "deny", last.ids, item);
      else postDecision(item, last.decision, last.scope);
    });
    err.append(retry);
    card.append(err);
  }
  const bar = el("div", "appr-actions");
  const down = approvalsUnreachable();
  const steps = ladderSteps(item);
  const showChevron = actions.chevron && (steps.steps.length > 1 || steps.lockGlobal);
  function wireAnswer(node, fn) {
    setAriaDisabled(node, down);
    node.addEventListener("click", function (ev) {
      if (guardAnswer(ev)) return;
      fn();
    });
  }
  if (actions.approve === "confirm") {
    const approve = btn("secondary", "Approve…");
    approve.setAttribute("data-appr-focus", prefix + "approve:" + item.id);
    wireAnswer(approve, function () {
      ui.confirm = true;
      ui.armedAt = Date.now();
      ui.staleGesture = false;
      ui.armTimer = 0;
      uiRev += 1;
      renderApprovals();
    });
    bar.append(approve);
  } else if (actions.approve === "once") {
    const approve = btn("secondary", "Approve once");
    approve.setAttribute("data-appr-focus", prefix + "approve:" + item.id);
    wireAnswer(approve, function () { postDecision(item, "approve", "once"); });
    bar.append(approve);
  } else if (actions.approve !== "none") {
    const split = el("span", "appr-split");
    const primary = actions.approve === "split-primary";
    const approve = btn(primary ? "primary" : "secondary", "Approve once");
    approve.setAttribute("data-appr-focus", prefix + "approve:" + item.id);
    wireAnswer(approve, function () { postDecision(item, "approve", "once"); });
    split.append(approve);
    if (showChevron) {
      const chev = btn((primary ? "primary" : "secondary") + " appr-chev", "");
      chev.setAttribute("aria-label", "More approve options");
      chev.setAttribute("aria-expanded", ui.ladder ? "true" : "false");
      chev.append(cloneTpl("tpl-chev"));
      setAriaDisabled(chev, down);
      chev.setAttribute("data-appr-focus", prefix + "chevron:" + item.id);
      chev.addEventListener("click", function (ev) {
        if (guardAnswer(ev)) return;
        const opening = !ui.ladder;
        ui.ladder = opening;
        if (!ui.scope) ui.scope = "once";
        uiRev += 1;
        setIntendedFocus(opening ? prefix + "ladder:" + item.id : prefix + "chevron:" + item.id);
        renderApprovals();
      });
      split.append(chev);
    }
    bar.append(split);
  }
  if (actions.batch) {
    const key = identicalKey(item);
    const group = key ? (approvalItems || []).filter(function (other) { return identicalKey(other) === key; }) : [];
    if (group.length > 1 && firstIdenticalId(approvalItems, item) === item.id) {
      const ids = group.map(function (g) { return g.id; });
      const busy = !!(batchFlight && ids.some(function (id) { return batchFlight.ids[id]; }));
      const all = btn("secondary", "Approve all " + group.length);
      all.setAttribute("data-appr-focus", prefix + "approve-all:" + item.id);
      setAriaDisabled(all, down || busy);
      all.addEventListener("click", function (ev) {
        if (all.getAttribute("aria-disabled") === "true" || batchFlight) { ev.preventDefault(); return; }
        if (guardAnswer(ev)) return;
        postBatch("approve", ids, item);
      });
      const denyAll = btn("appr-deny-line", "Deny all " + group.length);
      denyAll.setAttribute("data-appr-focus", prefix + "deny-all:" + item.id);
      const desc = el("p", "appr-src", denyAllDesc(group.length, itemBot(item)));
      desc.id = "deny-all-desc-" + mode + "-" + item.id;
      denyAll.setAttribute("aria-describedby", desc.id);
      setAriaDisabled(denyAll, down || busy);
      denyAll.addEventListener("click", function (ev) {
        if (denyAll.getAttribute("aria-disabled") === "true" || batchFlight) { ev.preventDefault(); return; }
        if (guardAnswer(ev)) return;
        postBatch("deny", ids, item);
      });
      bar.append(all, denyAll, desc);
    }
  }
  const deny = btn(actions.deny === "fill" ? "appr-deny-fill appr-deny" : "appr-deny-line appr-deny", "Deny");
  deny.setAttribute("data-appr-focus", prefix + "deny:" + item.id);
  wireAnswer(deny, function () { postDecision(item, "deny", ""); });
  bar.append(deny);
  if (actions.note) bar.append(el("span", "appr-lock", actions.note));
  card.append(bar);
  if (item.suggest_always && !ui.suggestHidden && !item.compound && (level === "low" || level === "medium" || level === "unclassified")) {
    const nudge = el("div", "appr-nudge");
    nudge.append(el("strong", "", "Always allow it?"));
    const row = el("div", "appr-actions");
    const choose = btn("secondary", "Choose…");
    const later = btn("ghost", "Not now");
    wireAnswer(choose, function () {
      ui.suggestHidden = true;
      ui.ladder = true;
      ui.scope = (item.allowed_scopes || []).indexOf("bot") >= 0 ? "bot" : "once";
      uiRev += 1;
      renderApprovals();
    });
    later.addEventListener("click", function () {
      ui.suggestHidden = true;
      uiRev += 1;
      renderApprovals();
    });
    row.append(choose, later);
    nudge.append(row);
    card.append(nudge);
  }
  if (ui.confirm) {
    const box = el("div", "appr-confirm");
    box.append(el("p", "", "Approve once? " + itemBot(item) + " will run " + itemArgv(item) + ". This can't be undone from here and can't become a rule."));
    const armed = armReady(ui, Date.now());
    const arm = el("div", "appr-arm" + (armed ? " is-done" : ""));
    const fill = document.createElement("i");
    arm.append(fill);
    if (!armed) {
      requestAnimationFrame(function () {
        if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
        arm.classList.add("is-armed");
      });
      scheduleArm(item.id);
    }
    box.append(arm);
    const yes = btn("primary", "Yes");
    setAriaDisabled(yes, !armed || down);
    yes.setAttribute("data-appr-focus", prefix + "yes:" + item.id);
    const ignore = function () { if (!armReady(ui, Date.now())) ui.staleGesture = true; };
    yes.addEventListener("pointerdown", ignore);
    yes.addEventListener("keydown", function (ev) {
      if (ev.key !== "Enter" && ev.key !== " ") return;
      ignore();
    });
    yes.addEventListener("click", function (ev) {
      if (guardAnswer(ev)) return;
      if (!armReady(ui, Date.now()) || ui.staleGesture) { ui.staleGesture = false; return; }
      postDecision(item, "approve", "once");
    });
    const no = btn("ghost", "No");
    no.addEventListener("click", function () {
      ui.confirm = false;
      ui.armedAt = 0;
      clearTimeout(ui.armTimer);
      ui.armTimer = 0;
      uiRev += 1;
      renderApprovals();
    });
    const row = el("div", "appr-actions");
    row.append(yes, no);
    box.append(row);
    card.append(box);
  }
  if (ui.ladder && showChevron) {
    const ladder = el("div", "appr-ladder");
    const h = document.createElement("h3");
    h.textContent = LADDER_HEADING;
    ladder.append(h, el("p", "appr-src", LADDER_NOTE));
    const picked = ui.scope || "once";
    steps.steps.forEach(function (step, stepIndex) {
      const stepBtn = btn("appr-step" + (picked === step.scope ? " is-on" : ""), "");
      stepBtn.setAttribute("aria-pressed", picked === step.scope ? "true" : "false");
      if (stepIndex === 0) stepBtn.setAttribute("data-appr-focus", prefix + "ladder:" + item.id);
      const label = step.scope === "bot" ? "Always for " + itemBot(item) : step.label;
      const strong = el("strong", "", label);
      let detail = "";
      if (step.scope === "task") detail = taskStepCopy(itemBot(item), flattenTaskText(item.task_text || ""));
      else if (step.scope === "bot") detail = botStepCopy(itemBot(item));
      else if (step.scope === "global") detail = globalStepCopy();
      stepBtn.append(strong);
      if (detail) stepBtn.append(el("small", "", detail));
      stepBtn.addEventListener("click", function () {
        ui.scope = step.scope;
        uiRev += 1;
        renderApprovals();
      });
      ladder.append(stepBtn);
    });
    if (steps.lockGlobal) ladder.append(el("div", "appr-step is-locked", LOCK_GLOBAL));
    const commit = btn("primary", commitLabel(picked, itemBot(item)));
    wireAnswer(commit, function () { postDecision(item, "approve", picked); });
    ladder.append(commit);
    card.append(ladder);
  }
  return card;
}
async function postDecision(item, decision, scope) {
  const ui = ensureUI(item.id);
  ui.lastTry = { decision: decision, scope: scope || "once" };
  ui.sendError = false;
  const body = decision === "deny" ? DENY_BODY : JSON.stringify({ decision: "approve", scope: scope || "once" });
  const res = await brokerCall("/api/permbroker/pending/" + encodeURIComponent(item.id), { method: "POST", body: body });
  if (res.network) {
    ui.sendError = true;
    uiRev += 1;
    renderApprovals();
    return;
  }
  if (res.status === 409) {
    const msg = decidedConflictCopy(res.status);
    localRecords.unshift({ text: msg });
    showStatusToast(msg, null);
    setIntendedFocus(nextQueueFocusKey(approvalItems, [item.id]));
    dropItem(item.id);
    return;
  }
  if (res.status === 404) {
    localRecords.unshift({ text: "Approved on another device" });
    setIntendedFocus(nextQueueFocusKey(approvalItems, [item.id]));
    dropItem(item.id);
    return;
  }
  if (res.status !== 200) {
    ui.sendError = true;
    uiRev += 1;
    renderApprovals();
    return;
  }
  setIntendedFocus(nextQueueFocusKey(approvalItems, [item.id]));
  if (decision === "deny") {
    rememberOwn(item, "deny");
    localRecords.unshift({ text: denyRecord(itemBot(item), itemArgv(item)) });
    showStatusToast(denyToast(itemBot(item)), null);
    dropItem(item.id);
    return;
  }
  rememberOwn(item, "approve");
  if (scope === "bot" || scope === "global") {
    showStatusToast("Rule saved · Undo", function () { undoScopeRule(item, scope); });
  } else if (scope === "task") showStatusToast("Approved for this task.", null);
  else showStatusToast("Approved once.", null);
  dropItem(item.id);
}
async function undoScopeRule(item, scope) {
  const res = await brokerCall("/api/permbroker/rules");
  const rules = (res.data && res.data.rules) || [];
  const match = matchAllowRule(rules, item, scope);
  if (match && match.id) await brokerCall("/api/permbroker/rules/" + encodeURIComponent(match.id), { method: "DELETE" });
  pollSoon();
}
function batchFocusKey(sample, kind) {
  const id = sample && sample.id;
  if (!id) return "approvals-title";
  const active = document.activeElement;
  const current = active && active.getAttribute ? (active.getAttribute("data-appr-focus") || "") : "";
  if (current && current.indexOf(id) >= 0) return current;
  return "q:" + (kind === "deny" ? "deny-all:" : "approve-all:") + id;
}
async function postBatch(kind, ids, sample) {
  if (batchFlight) return;
  const waiting = {};
  (ids || []).forEach(function (id) { waiting[id] = true; });
  batchFlight = { ids: waiting, kind: kind };
  (ids || []).forEach(function (id) {
    const ui = ensureUI(id);
    ui.batchBusy = true;
    ui.lastTry = { batch: true, ids: ids, kind: kind };
    ui.sendError = false;
  });
  setIntendedFocus(batchFocusKey(sample, kind));
  uiRev += 1;
  renderApprovals();
  const path = kind === "approve" ? "/api/permbroker/pending/approve-all" : "/api/permbroker/pending/deny-all";
  const res = await brokerCall(path, { method: "POST", body: JSON.stringify({ ids: ids || [] }) });
  batchFlight = null;
  (ids || []).forEach(function (id) { if (cardUI[id]) cardUI[id].batchBusy = false; });
  if (res.network || (res.status !== 200 && res.status !== 207)) {
    if (sample) {
      const ui = ensureUI(sample.id);
      ui.sendError = true;
      ui.lastTry = { batch: true, ids: ids, kind: kind };
      uiRev += 1;
      setIntendedFocus(batchFocusKey(sample, kind));
      renderApprovals();
    }
    return;
  }
  const data = res.data || {};
  let ok = data.ok_count;
  let skipped = data.skipped;
  const sent = (ids || []).length;
  const done = [];
  if (Array.isArray(data.results)) {
    let counted = 0;
    let skippedN = 0;
    data.results.forEach(function (row) {
      if (row && row.ok) { counted += 1; done.push(row.id); }
      else skippedN += 1;
    });
    if (ok == null) ok = counted;
    if (skipped == null) skipped = skippedN;
  } else {
    ok = batchCount(ok, sent);
    (ids || []).forEach(function (id) { done.push(id); });
  }
  ok = batchCount(ok, sent);
  skipped = Number(skipped) || 0;
  const bot = itemBot(sample);
  showStatusToast(batchResultCopy(kind, ok, skipped, bot), null);
  if (kind === "deny" && ok) localRecords.unshift({ text: denyAllRecord(ok, bot, itemArgv(sample)) });
  if (kind === "approve") {
    (approvalItems || []).forEach(function (item) {
      if (done.indexOf(item.id) >= 0) rememberOwn(item, "approve");
    });
  }
  if (done.length) setIntendedFocus(nextQueueFocusKey(approvalItems, done));
  else setIntendedFocus(batchFocusKey(sample, kind));
  if (done.length) {
    approvalItems = (approvalItems || []).filter(function (item) { return done.indexOf(item.id) < 0; });
    done.forEach(function (id) { delete cardUI[id]; closeNote(id); });
  }
  uiRev += 1;
  renderApprovals();
  pollSoon();
}
function dropItem(id) {
  closeNote(id);
  approvalItems = (approvalItems || []).filter(function (item) { return item.id !== id; });
  delete cardUI[id];
  uiRev += 1;
  renderApprovals();
  if (typeof setTitle === "function") setTitle();
}
function renderAlerts(host) {
  if (!host) return;
  const label = currentNotifyLabel();
  const perm = (typeof window.Notification !== "undefined") ? window.Notification.permission : "";
  const critical = approvalsCriticalCount() > 0;
  const showPre = critical && perm === "default" && label === "Off" && !notifySnoozed();
  const sig = [label, perm, showPre ? 1 : 0, approvals.forceAlerts ? 1 : 0, critical ? 1 : 0].join("|");
  if (sig === alertsSig) return;
  alertsSig = sig;
  host.replaceChildren();
  if (!approvals.forceAlerts && !showPre) return;
  const card = el("div", "appr-alert");
  if (label === "Not available") {
    const insecure = typeof window !== "undefined" && window.isSecureContext === false;
    card.append(el("p", "", insecure ? NOTIFY_UNAVAILABLE : "Notifications aren't available in this browser. Critical approvals still show here and in the tab title."));
  } else if (label === "Blocked") {
    card.append(el("p", "", NOTIFY_BLOCKED));
  } else if (label === "On") {
    card.append(el("p", "", "Critical alerts are on."));
    const off = btn("secondary", "Turn off");
    off.addEventListener("click", function () {
      try { localStorage.setItem("lgb.notify.off", "1"); } catch (e) {}
      renderApprovals();
    });
    card.append(off);
  } else {
    const head = el("div", "appr-alert-h");
    head.append(notifyBell(), el("strong", "", PREPROMPT_TITLE));
    card.append(head);
    card.append(el("p", "", PREPROMPT_BODY));
    const actions = el("div", "appr-alert-actions");
    const on = btn("primary", "Turn on notifications");
    on.addEventListener("click", function () { turnOnNotifications(); });
    const later = btn("ghost", "Not now");
    later.addEventListener("click", function () {
      try { localStorage.setItem("lgb.notify.snoozeUntil", String(Date.now() + 7 * 24 * 60 * 60 * 1000)); } catch (e) {}
      approvals.forceAlerts = false;
      renderApprovals();
    });
    actions.append(on, later);
    card.append(actions);
  }
  host.append(card);
}
function turnOnNotifications() {
  if (typeof window === "undefined") return;
  if (window.isSecureContext === false || typeof window.Notification === "undefined") return;
  try { localStorage.removeItem("lgb.notify.off"); } catch (e) {}
  if (window.Notification.permission === "granted") { renderApprovals(); return; }
  if (window.Notification.permission !== "default") return;
  window.Notification.requestPermission().then(function () { renderApprovals(); }).catch(function () {});
}
function syncNotifications(items) {
  const live = {};
  (items || []).forEach(function (item) { if (item.level === "critical") live[item.id] = item; });
  Object.keys(approvals.notes).forEach(function (id) { if (!live[id]) closeNote(id); });
  if (!document.hidden || currentNotifyLabel() !== "On") return;
  Object.keys(live).forEach(function (id) {
    if (approvals.notes[id] || approvals.notified[id]) return;
    const item = live[id];
    try {
      const n = new Notification(notifyTitle(item.bot_name || botLabel(item.bot_id, "A bot")), {
        body: notifyBody(item.argv && item.argv.length ? item.argv : itemArgv(item)),
        tag: id
      });
      n.onclick = function () {
        window.focus();
        ensureUI(id).taskOpen = true;
        approvals.focusDeny = id;
        setIntendedFocus("q:deny:" + id);
        openApprovals({ manual: true, focus: true });
      };
      approvals.notes[id] = n;
      approvals.notified[id] = true;
    } catch (e) {}
  });
}
function renderRecords(body) {
  const rows = [];
  localRecords.forEach(function (rec) { if (rec && rec.text) rows.push(rec.text); });
  (approvalRecent || []).forEach(function (row) {
    const text = showRecent(row, isOwnRecent(row));
    if (!text) return;
    const cmd = row.command || (row.argv || []).join(" ");
    rows.push(cmd ? text + " · " + cmd : text);
  });
  if (!rows.length) return;
  body.append(el("h3", "appr-group", "Recent"));
  rows.slice(0, 12).forEach(function (text) {
    const line = el("div", "appr-record");
    const cut = text.indexOf(" · ");
    if (cut > 0) {
      line.append(document.createTextNode(text.slice(0, cut) + " · "));
      line.append(el("code", "", text.slice(cut + 3)));
    } else line.append(document.createTextNode(text));
    body.append(line);
  });
}
function applyQueueFocus(panel) {
  if (typingFocus()) return;
  if (approvals.focusDeny) {
    const deny = findByAttr(panel, "data-appr-focus", "q:deny:" + approvals.focusDeny);
    approvals.focusDeny = "";
    if (deny) { deny.focus(); return; }
  }
  if (!approvals.wantFocus) return;
  approvals.wantFocus = false;
  const first = panel.querySelector(".appr-card");
  const level = first && first.getAttribute("data-level");
  if (first && (level === "critical" || level === "high")) {
    const deny = first.querySelector(".appr-deny");
    if (deny) { deny.focus(); return; }
  }
  const heading = $("#approvals-title");
  if (heading) heading.focus();
}
function renderApprovals() {
  syncFreeze();
  reconcileQueue();
  applyQueueChrome();
  const panel = $("#approvals");
  const body = $("#approvals-body");
  const items = approvalItems || [];
  const crits = items.filter(function (item) { return item.level === "critical"; }).map(function (item) { return item.id; });
  if (approvals.seenReady) {
    const fresh = crits.filter(function (id) { return approvals.seenCritical.indexOf(id) < 0; });
    if (fresh.length) {
      const region = $("#approvals-assert");
      if (region) {
        region.textContent = "";
        setTimeout(function () { region.textContent = NOTIFY_TITLE; }, 20);
      }
      if (queueOpen && !typingFocus()) approvals.focusDeny = fresh[0];
    }
  }
  approvals.seenCritical = crits;
  approvals.seenReady = true;
  const count = $("#approvals-count");
  if (count && approvals.lastCount !== items.length && approvals.polled) {
    count.textContent = items.length ? items.length + " waiting" : EMPTY_QUEUE_TITLE;
    approvals.lastCount = items.length;
  }
  const banner = $("#approvals-banner");
  if (banner) {
    const mode = banner.getAttribute("data-mode") || "";
    if (approvalsUnreachable()) {
      banner.hidden = false;
      if (mode !== "down" && banner.textContent !== RECONNECT_COPY) {
        banner.setAttribute("data-mode", "down");
        banner.replaceChildren(document.createTextNode(UNREACHABLE_COPY + " "));
        const retry = btn("secondary small", "Retry now");
        retry.addEventListener("click", function () { if (typeof retryDaemonNow === "function") retryDaemonNow(); });
        banner.append(retry);
      }
    } else if (mode === "down") {
      banner.hidden = true;
      banner.removeAttribute("data-mode");
      banner.replaceChildren();
    }
    if (!String(banner.textContent || "").trim()) banner.hidden = true;
  }
  paintQueueHeader();
  renderAlerts($("#approvals-alerts"));
  syncNotifications(items);
  paintRulesLinks();
  if (typeof setTitle === "function") setTitle();
  renderBrokerThread();
  if (state.view === "rules") paintRules();
  if (!panel || !body) return;
  const sig = [
    items.map(function (i) { return [i.id, i.level, i.ruleset, i.suggest_always ? 1 : 0, i.compound ? 1 : 0].join(":"); }).join("|"),
    uiRev,
    approvalsUnreachable() ? 1 : 0,
    queueOpen ? 1 : 0,
    localRecords.length,
    (approvalRecent || []).map(function (r) { return (r.kind || "") + (r.command || ""); }).join("~"),
    approvals.forceAlerts ? 1 : 0,
    currentNotifyLabel()
  ].join("#");
  if (sig === queueSig && !approvals.force) {
    patchAges(panel);
    if (!applyIntendedFocus(panel)) applyQueueFocus(panel);
    return;
  }
  approvals.force = false;
  queueSig = sig;
  const active = document.activeElement;
  const restore = active && panel.contains(active) && active.getAttribute ? (active.getAttribute("data-appr-focus") || "") : "";
  const focusId = focusedApprovalId();
  const ids = orderApprovalIds(items, prevOrder, focusId);
  prevOrder = ids.slice();
  const byId = {};
  items.forEach(function (item) { byId[item.id] = item; });
  body.replaceChildren();
  const rankCount = {};
  ids.forEach(function (id) {
    const item = byId[id];
    if (!item) return;
    const rank = approvalRank(item.level);
    rankCount[rank] = (rankCount[rank] || 0) + 1;
  });
  if (!items.length) {
    const empty = el("div", "appr-empty");
    const heading = el("h3", "", EMPTY_QUEUE_TITLE);
    heading.id = "approvals-empty-title";
    heading.tabIndex = -1;
    heading.setAttribute("data-appr-focus", "approvals-empty");
    empty.append(heading, el("p", "", EMPTY_QUEUE_BODY));
    body.append(empty);
  } else {
    let lastRank = -1;
    ids.forEach(function (id) {
      const item = byId[id];
      if (!item) return;
      const rank = approvalRank(item.level);
      if (rank !== lastRank) {
        body.append(el("h3", "appr-group", groupCountLabel(rank, rankCount[rank])));
        lastRank = rank;
      }
      body.append(renderApprovalCard(item, "queue"));
    });
  }
  renderRecords(body);
  if (applyIntendedFocus(panel)) return;
  if (restore && !approvals.focusDeny && !approvals.wantFocus) {
    const back = findByAttr(panel, "data-appr-focus", restore);
    if (back && !typingFocus()) focusNode(back);
  } else applyQueueFocus(panel);
}
function renderBrokerThread() {
  const host = document.getElementById("broker-thread");
  if (!host) return;
  const mine = (approvalItems || []).filter(function (item) { return state.botId && item.bot_id === state.botId; });
  const sig = mine.map(function (item) { return item.id + ":" + item.level + ":" + item.ruleset; }).join("|") + "#" + uiRev + "#" + (approvalsUnreachable() ? 1 : 0);
  if (sig === threadSig) { patchAges(host); return; }
  const active = document.activeElement;
  const restore = active && host.contains(active) && active.getAttribute ? (active.getAttribute("data-appr-focus") || "") : "";
  threadSig = sig;
  host.replaceChildren();
  mine.forEach(function (item) { host.append(renderApprovalCard(item, "thread")); });
  if (approvals.intendedFocus && String(approvals.intendedFocus).indexOf("t:") === 0) applyIntendedFocus(host);
  else if (restore && !typingFocus()) {
    const back = findByAttr(host, "data-appr-focus", restore);
    if (back) back.focus();
  }
}
function rulePayload(draft) {
  const kind = draft.kind === "pattern" ? "pattern" : "exact";
  return {
    kind: kind,
    argv: kind === "exact" ? splitArgv(draft.text) : [],
    pattern: kind === "pattern" ? String(draft.text || "").trim() : "",
    scope: draft.scope === "global" ? "global" : "bot",
    bot_id: draft.scope === "global" ? "" : (draft.bot_id || ""),
    effect: draft.effect || "allow"
  };
}
function fillBotPicker(select, selected) {
  if (!select) return;
  const cur = selected || select.value;
  select.replaceChildren();
  (state.bots || []).forEach(function (b) {
    if (b.archived) return;
    select.append(new Option(b.name || b.id, b.id));
  });
  if (cur && Array.from(select.options).some(function (o) { return o.value === cur; })) select.value = cur;
  else if (select.options.length) select.value = select.options[0].value;
}
function setSeg(root, attr, value) {
  if (!root) return;
  root.querySelectorAll("[role='radio']").forEach(function (button) {
    const on = button.getAttribute(attr) === value;
    button.setAttribute("aria-checked", on ? "true" : "false");
  });
}
function readRuleForm() {
  const kindBtn = document.querySelector("#rule-kind [aria-checked='true']");
  const scopeBtn = document.querySelector("#rule-scope [aria-checked='true']");
  const effectBtn = document.querySelector("#rule-effect [aria-checked='true']");
  return {
    kind: kindBtn ? kindBtn.getAttribute("data-kind") : "exact",
    scope: scopeBtn ? scopeBtn.getAttribute("data-scope") : "bot",
    effect: effectBtn ? effectBtn.getAttribute("data-effect") : "allow",
    text: ($("#rule-pattern") && $("#rule-pattern").value) || "",
    bot_id: ($("#rule-bot") && $("#rule-bot").value) || ""
  };
}
function openRuleSheet(preset) {
  ruleDraft = Object.assign({ kind: "exact", scope: "bot", effect: "allow", text: "", bot_id: state.rulesBot || state.botId || "", replaceId: "" }, preset || {});
  const sheet = $("#rule-sheet");
  const scrim = $("#rule-scrim");
  if (scrim) scrim.hidden = false;
  if (sheet) sheet.hidden = false;
  const title = $("#rule-sheet-title");
  if (title) title.textContent = ruleDraft.replaceId ? "Edit rule" : "New rule";
  setSeg($("#rule-kind"), "data-kind", ruleDraft.kind);
  setSeg($("#rule-scope"), "data-scope", ruleDraft.scope);
  setSeg($("#rule-effect"), "data-effect", ruleDraft.effect);
  const input = $("#rule-pattern");
  if (input) input.value = ruleDraft.text || "";
  fillBotPicker($("#rule-bot"), ruleDraft.bot_id);
  syncRuleForm();
  if (input) input.focus();
}
function closeRuleSheet() {
  const sheet = $("#rule-sheet");
  const scrim = $("#rule-scrim");
  if (sheet) sheet.hidden = true;
  if (scrim) scrim.hidden = true;
  ruleDraft = null;
}
function syncRuleForm() {
  const draft = readRuleForm();
  const pattern = draft.kind === "pattern";
  const label = $("#rule-input-label");
  const help = $("#rule-help");
  const input = $("#rule-pattern");
  const err = $("#rule-error");
  const bot = $("#rule-bot");
  if (label) label.textContent = pattern ? "Pattern" : "Exact command";
  if (help) help.textContent = pattern ? PATTERN_HELP : EXACT_HELP;
  const botField = $("#rule-bot-field");
  if (botField) botField.hidden = draft.scope !== "bot";
  else if (bot) bot.hidden = draft.scope !== "bot";
  const replacing = !!(ruleDraft && ruleDraft.replaceId);
  const note = $("#rule-replace-note");
  if (note) note.hidden = !replacing;
  const save = $("#rule-save");
  if (save) save.textContent = replacing ? "Save as new rule" : (pattern ? "Save pattern rule" : "Save exact rule");
  let invalid = false;
  let message = "";
  if (!pattern) {
    if (!String(draft.text || "").trim() || exactHasOp(draft.text)) {
      invalid = true;
      if (exactHasOp(draft.text)) message = patternErrorCopy("operators", "", approvals.wrappers);
    }
  } else if (!draft._ok) {
    invalid = true;
    message = draft._message || "";
  }
  if (input) {
    input.setAttribute("aria-invalid", invalid && String(draft.text || "").trim() ? "true" : "false");
  }
  if (err) {
    err.hidden = !message;
    err.replaceChildren();
    if (message) {
      err.append(cloneTpl("tpl-alert"));
      err.append(el("span", "", message));
    }
  }
  if (save) setAriaDisabled(save, invalid || (draft.scope === "bot" && !draft.bot_id));
  paintConsequence(draft);
}
function paintConsequence(draft) {
  const node = $("#rule-cons");
  if (!node) return;
  const name = draft.scope === "global" ? "Every bot" : botLabel(draft.bot_id, "This bot");
  const what = draft.kind === "pattern" ? ("`" + String(draft.text || "").trim() + "`") : ("`" + (splitArgv(draft.text).join(" ") || "this command") + "`");
  let line = "";
  if (draft.effect === "deny") line = name + " will deny " + what + ".";
  else if (draft.effect === "ask") line = name + " will ask before running " + what + ".";
  else {
    line = name + " will run " + what + " without asking. Commands with several parts and critical items still ask.";
    if (draft.kind === "pattern") line += " " + STAR_WORD;
  }
  node.classList.toggle("is-high", !!(draft._high && draft._high.length && draft.effect === "allow"));
  node.replaceChildren();
  if (draft._high && draft._high.length && draft.effect === "allow") node.append(cloneTpl("tpl-alert"));
  node.append(document.createTextNode(line));
  if (draft._high && draft._high.length && draft.effect === "allow") {
    node.append(document.createTextNode(" High-risk matches: " + draft._high.join("; ") + "."));
  }
}
let previewTimer = 0;
function scheduleRuleCheck() {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(runRuleCheck, 200);
}
async function runRuleCheck() {
  const draft = readRuleForm();
  const token = ++ruleToken;
  draft._ok = false;
  draft._message = "";
  draft._high = [];
  if (draft.kind === "pattern") {
    const res = await brokerCall("/api/permbroker/patterns/validate", {
      method: "POST",
      body: JSON.stringify({ pattern: draft.text })
    });
    if (token !== ruleToken) return;
    const data = res.data || {};
    draft._ok = !!data.ok;
    if (!data.ok) {
      const cmd = String(draft.text || "").trim().split(/\s+/)[0] || "";
      draft._message = patternErrorCopy(data.code, cmd, approvals.wrappers) || data.message || "";
    }
  } else if (exactHasOp(draft.text)) {
    draft._ok = false;
    draft._message = patternErrorCopy("operators", "", approvals.wrappers);
  } else {
    draft._ok = !!String(draft.text || "").trim();
  }
  const saveDisabled = (draft.kind === "pattern" && !draft._ok) || (draft.kind !== "pattern" && !draft._ok);
  if (!saveDisabled && (draft.kind === "pattern" ? String(draft.text || "").trim() : splitArgv(draft.text).length)) {
    const payload = rulePayload(draft);
    const prev = await brokerCall("/api/permbroker/patterns/preview", { method: "POST", body: JSON.stringify(payload) });
    if (token !== ruleToken) return;
    paintPreview(prev.data, draft);
    const hits = (prev.data && prev.data.requests) || [];
    draft._high = hits.filter(function (hit) {
      return hit && hit.outcome && hit.outcome !== "no_match" && (hit.level === "high" || hit.level === "critical");
    }).map(function (hit) { return (hit.argv || []).join(" "); });
  } else paintPreview(null, draft);
  const current = readRuleForm();
  current._ok = draft._ok;
  current._message = draft._message;
  current._high = draft._high;
  syncRuleFormFrom(current);
}
function syncRuleFormFrom(draft) {
  const input = $("#rule-pattern");
  const err = $("#rule-error");
  const save = $("#rule-save");
  const invalid = !draft._ok && !!String(draft.text || "").trim();
  if (input) input.setAttribute("aria-invalid", invalid ? "true" : "false");
  if (err) {
    err.hidden = !draft._message;
    err.replaceChildren();
    if (draft._message) {
      err.append(cloneTpl("tpl-alert"));
      err.append(el("span", "", draft._message));
    }
  }
  if (save) setAriaDisabled(save, !draft._ok || (draft.scope === "bot" && !draft.bot_id));
  paintConsequence(draft);
}
function paintPreview(data, draft) {
  const summary = $("#rule-summary");
  const list = $("#rule-hits");
  if (summary) {
    const name = draft.scope === "global" ? "" : botLabel(draft.bot_id, "");
    summary.textContent = data && data.summary ? previewSummary(data.summary, name) : "";
  }
  if (!list) return;
  list.replaceChildren();
  ((data && data.requests) || []).forEach(function (hit) {
    const li = document.createElement("li");
    li.append(el("code", "", (hit.argv || []).join(" ")));
    li.append(el("span", "", outcomeLabel(hit.outcome, hit.reason)));
    list.append(li);
  });
}
async function saveRuleFromForm() {
  const save = $("#rule-save");
  if (save && save.getAttribute("aria-disabled") === "true") {
    const input = $("#rule-pattern");
    if (input) input.focus();
    return;
  }
  const draft = readRuleForm();
  const payload = rulePayload(draft);
  const replaceId = ruleDraft && ruleDraft.replaceId;
  const previous = ruleDraft && ruleDraft.previous;
  const res = await brokerCall(replaceId ? "/api/permbroker/rules/" + encodeURIComponent(replaceId) + "/replace" : "/api/permbroker/rules", { method: "POST", body: JSON.stringify(payload) });
  const replaced = !!replaceId;
  const failed = res.network || (replaced ? (res.status !== 200 && res.status !== 207) : res.status !== 200);
  if (failed) {
    const failure = ruleSheetSaveError(res);
    const input = $("#rule-pattern");
    if (input) input.setAttribute("aria-invalid", failure.invalid ? "true" : "false");
    const err = $("#rule-error");
    if (err) {
      err.hidden = false;
      if (failure.invalid) {
        err.replaceChildren();
        err.append(cloneTpl("tpl-alert"));
        err.append(el("span", "", failure.message));
      } else {
        err.textContent = failure.message;
      }
    }
    return;
  }
  if (replaced && res.data && res.data.revoked === false) {
    closeRuleSheet();
    showStatusToast(REPLACE_BOTH, null);
    rulesForce = true;
    pollSoon();
    return;
  }
  const created = res.data && (replaced ? res.data.created : (res.data.rule && res.data.rule.id));
  const newId = created || "";
  closeRuleSheet();
  showStatusToast("Rule saved · Undo", function () {
    if (newId) brokerCall("/api/permbroker/rules/" + encodeURIComponent(newId), { method: "DELETE" }).then(function () {
      if (replaceId) brokerCall("/api/permbroker/rules", { method: "POST", body: JSON.stringify(previous || payload) });
      pollSoon();
    });
  });
  pollSoon();
}
function paintRules() {
  const root = $("#view-rules");
  const list = $("#rules-list");
  if (!root || !list || !root.classList.contains("on")) return;
  const pop = root.querySelector(".rules-pop:not([hidden])");
  if (pop && !rulesForce) return;
  const active = document.activeElement;
  if (active && isTypingTarget(active) && list.childElementCount && !rulesForce) return;
  const sig = rulesFilter + "#" + (state.rulesBot || "") + "#" + JSON.stringify(approvalRules) + "#" + JSON.stringify(approvalGrants) + "#" + JSON.stringify(approvalRisk);
  if (sig === rulesSig && !rulesForce) return;
  rulesForce = false;
  rulesSig = sig;
  let focusKey = "";
  if (active && active.getAttribute && list.contains(active)) focusKey = active.getAttribute("data-rules-focus") || "";
  root.querySelectorAll(".rules-filters [role='radio']").forEach(function (button) {
    button.setAttribute("aria-checked", button.getAttribute("data-filter") === rulesFilter ? "true" : "false");
  });
  list.replaceChildren();
  const show = function (name) { return rulesFilter === "all" || rulesFilter === name; };
  if (show("global") || (rulesFilter === "patterns")) {
    const globals = (approvalRules || []).filter(function (rule) {
      if (rule.scope !== "global") return false;
      if (rulesFilter === "patterns") return rule.kind === "pattern";
      return true;
    });
    if (rulesFilter !== "bot" && rulesFilter !== "grants" && rulesFilter !== "risk") list.append(renderRuleSection("Global", "", globals, []));
  }
  if (show("bot") || show("grants") || rulesFilter === "patterns" || rulesFilter === "all") {
    const bots = {};
    (approvalRules || []).forEach(function (rule) {
      if (rule.scope !== "bot") return;
      if (rulesFilter === "patterns" && rule.kind !== "pattern") return;
      if (rulesFilter === "grants") return;
      const id = rule.bot_id || "";
      if (state.rulesBot && rulesFilter === "bot" && id !== state.rulesBot) return;
      if (!bots[id]) bots[id] = { rules: [], grants: [] };
      bots[id].rules.push(rule);
    });
    (approvalGrants || []).forEach(function (grant) {
      if (!(show("grants") || show("bot") || rulesFilter === "all")) return;
      if (rulesFilter === "patterns" || rulesFilter === "global" || rulesFilter === "risk") return;
      const id = grant.bot_id || "";
      if (state.rulesBot && rulesFilter === "bot" && id !== state.rulesBot) return;
      if (!bots[id]) bots[id] = { rules: [], grants: [] };
      bots[id].grants.push(grant);
    });
    Object.keys(bots).forEach(function (id) {
      list.append(renderRuleSection(botLabel(id, "Bot"), id, bots[id].rules, bots[id].grants));
    });
  }
  if (show("risk")) list.append(renderRiskSection());
  if (approvals.intendedFocus && String(approvals.intendedFocus).indexOf("rules:") === 0) {
    if (applyIntendedFocus(list)) return;
  }
  if (focusKey) {
    const again = findByAttr(list, "data-rules-focus", focusKey);
    if (again) focusNode(again);
  }
}
function renderRuleSection(title, botId, rules, grants) {
  const sec = el("section", "rules-sec");
  const head = el("div", "rules-sec-h");
  const h = document.createElement("h3");
  h.tabIndex = -1;
  h.setAttribute("data-rules-focus", "sec:" + (botId || "global"));
  h.append(document.createTextNode(title));
  if (botId) {
    const sub = el("span", "rules-sub");
    sub.append(el("span", "rules-dot", " · "), document.createTextNode("Rules and task grants for this bot"));
    h.append(sub);
  }
  head.append(h);
  if (botId && rulesFilter !== "grants") {
    const add = btn("ghost small", "+ Add rule");
    add.setAttribute("data-rules-focus", "add:" + botId);
    add.addEventListener("click", function () {
      openRuleSheet({ scope: "bot", bot_id: botId, kind: "exact" });
    });
    head.append(add);
  }
  sec.append(head);
  if (rules.length || grants.length) {
    const cols = el("div", "rules-head");
    ["Effect", "Command", "Scope", "Last used", ""].forEach(function (name) { cols.append(el("span", "", name)); });
    sec.append(cols);
  }
  rules.forEach(function (rule) { sec.append(renderRuleRow(rule)); });
  grants.forEach(function (grant) { sec.append(renderGrantRow(grant)); });
  if (!rules.length && !grants.length) sec.append(el("p", "rules-subhead", "None yet."));
  return sec;
}
function renderRuleRow(rule) {
  const row = el("div", "rules-row");
  row.append(el("span", "appr-chip " + (rule.effect || "ask"), rule.effect || "ask"));
  const cmd = el("div", "");
  if (rule.kind === "pattern") {
    const line = el("div", "rules-cmd");
    line.append(el("span", "appr-chip pattern", "PATTERN"), document.createTextNode(" " + (rule.pattern || "")));
    cmd.append(line);
  } else {
    cmd.append(el("div", "rules-cmd", (rule.argv || []).join(" ") || rule.pattern || ""));
  }
  cmd.append(el("div", "rules-src", provenanceLine(rule)));
  if (!rule.confirmable && rule.never_reason) cmd.append(el("div", "rules-src", rule.never_reason));
  if (rule.confirmable) {
    const confirm = btn("secondary small", "Confirm");
    confirm.setAttribute("data-rules-focus", "rule:" + (rule.id || "") + ":confirm");
    confirm.addEventListener("click", function () {
      brokerCall("/api/permbroker/rules/" + encodeURIComponent(rule.id) + "/confirm", { method: "POST", body: "{}" }).then(pollSoon);
    });
    cmd.append(confirm);
  }
  row.append(cmd);
  row.append(el("span", "", rule.scope === "global" ? "All bots" : botLabel(rule.bot_id, "One bot")));
  const usedRaw = rule.last_used_at ? String(rule.last_used_at) : "";
  const used = !usedRaw || usedRaw.indexOf("0001") === 0 ? "Not yet" : (approvalAge(rule.last_used_at, Date.now(), 0) || "Not yet");
  row.append(el("span", "", used));
  const menu = el("div", "rules-menu");
  const more = btn("icon-btn", "⋯");
  more.setAttribute("aria-label", "Rule actions");
  more.setAttribute("aria-expanded", "false");
  more.setAttribute("data-rules-focus", "rule:" + (rule.id || "") + ":menu");
  const pop = el("div", "rules-pop");
  pop.hidden = true;
  pop.setAttribute("role", "menu");
  if (rule.kind !== "legacy") {
    const edit = btn("", "Edit");
    edit.setAttribute("role", "menuitem");
    edit.addEventListener("click", function () {
      pop.hidden = true;
      openRuleSheet({
        kind: rule.kind === "pattern" ? "pattern" : "exact",
        text: rule.kind === "pattern" ? (rule.pattern || "") : (rule.argv || []).join(" "),
        scope: rule.scope === "global" ? "global" : "bot",
        bot_id: rule.bot_id || "",
        effect: rule.effect || "allow",
        replaceId: rule.id,
        previous: {
          kind: rule.kind === "pattern" ? "pattern" : "exact",
          argv: rule.argv || [],
          pattern: rule.pattern || "",
          scope: rule.scope,
          bot_id: rule.bot_id || "",
          effect: rule.effect
        }
      });
    });
    pop.append(edit);
    pop.append(el("div", "rules-src", "Change effect"));
    ["allow", "ask", "deny"].forEach(function (effect) {
      const choice = btn("", effect.charAt(0).toUpperCase() + effect.slice(1));
      choice.setAttribute("role", "menuitem");
      choice.addEventListener("click", function () { changeRuleEffect(rule, effect); pop.hidden = true; });
      pop.append(choice);
    });
  }
  const revoke = btn("", "Revoke");
  revoke.setAttribute("role", "menuitem");
  revoke.addEventListener("click", function (ev) {
    ev.stopPropagation();
    pop.hidden = true;
    more.setAttribute("aria-expanded", "false");
    revokeRule(rule, more);
  });
  pop.append(revoke);
  bindRuleMenu(more, pop);
  menu.append(more, pop);
  row.append(menu);
  return row;
}
function bindRuleMenu(more, pop) {
  function items() { return Array.prototype.slice.call(pop.querySelectorAll("[role='menuitem']")); }
  function openMenu(index) {
    document.querySelectorAll("#view-rules .rules-pop").forEach(function (other) {
      other.hidden = true;
      const trigger = other.parentNode && other.parentNode.querySelector("[aria-label='Rule actions']");
      if (trigger && trigger !== more) trigger.setAttribute("aria-expanded", "false");
    });
    pop.hidden = false;
    more.setAttribute("aria-expanded", "true");
    const list = items();
    const at = index < 0 ? 0 : Math.min(index, list.length - 1);
    if (list[at]) list[at].focus();
  }
  function closeMenu() {
    pop.hidden = true;
    more.setAttribute("aria-expanded", "false");
    more.focus();
  }
  more.addEventListener("click", function (ev) {
    ev.stopPropagation();
    if (pop.hidden) openMenu(0);
    else closeMenu();
  });
  more.addEventListener("keydown", function (ev) {
    if (ev.key !== "ArrowDown" && ev.key !== "ArrowUp" && ev.key !== "Home" && ev.key !== "End") return;
    ev.preventDefault();
    ev.stopPropagation();
    const act = ruleMenuKey(ev.key, items().length, -1);
    openMenu(act.move);
  });
  pop.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape" && ev.key !== "ArrowDown" && ev.key !== "ArrowUp" && ev.key !== "Home" && ev.key !== "End") return;
    const list = items();
    const act = ruleMenuKey(ev.key, list.length, list.indexOf(document.activeElement));
    ev.preventDefault();
    ev.stopPropagation();
    if (act.close) { closeMenu(); return; }
    if (act.move >= 0 && list[act.move]) list[act.move].focus();
  });
  pop.addEventListener("click", function (ev) { ev.stopPropagation(); });
}
function renderGrantRow(grant) {
  const row = el("div", "rules-row");
  row.append(el("span", "appr-chip allow", "allow"));
  const cmd = el("div", "");
  cmd.append(el("div", "rules-cmd", grant.raw || (grant.argv || []).join(" ")));
  cmd.append(el("div", "rules-src", "Task grant" + (grant.task_text ? " · " + flattenTaskText(grant.task_text) : "")));
  row.append(cmd);
  row.append(el("span", "", "This task"));
  row.append(el("span", "", grant.expires ? approvalAge(grant.expires, Date.now(), 0) : ""));
  row.append(el("span", ""));
  return row;
}
function renderRiskSection() {
  const sec = el("section", "rules-sec");
  const head = el("div", "rules-sec-h");
  const h = document.createElement("h3");
  h.append(document.createTextNode("Risk tables "), cloneTpl("tpl-lock"));
  head.append(h);
  sec.append(head);
  const risk = approvalRisk || { builtin: [], stricter: [] };
  sec.append(renderRiskTable(BUILTIN_RISK, BUILTIN_RISK_NOTE, risk.builtin || [], false));
  sec.append(renderRiskTable(STRICTER_RISK, STRICTER_RISK_NOTE, risk.stricter || [], true));
  return sec;
}
function renderRiskTable(caption, note, rows, stricter) {
  const table = document.createElement("table");
  table.className = "rules-table";
  const cap = document.createElement("caption");
  cap.textContent = caption + " · " + note;
  table.append(cap);
  const thead = document.createElement("thead");
  const hr = document.createElement("tr");
  ["Level", "Pattern", "What it does", "Applies to"].forEach(function (name) {
    const th = document.createElement("th");
    th.setAttribute("scope", "col");
    th.textContent = name;
    hr.append(th);
  });
  thead.append(hr);
  table.append(thead);
  const body = document.createElement("tbody");
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.textContent = "None yet.";
    tr.append(td);
    body.append(tr);
  }
  rows.forEach(function (row) { body.append(renderRiskRow(row, stricter)); });
  table.append(body);
  return table;
}
function renderRiskRow(row, stricter) {
  const tr = document.createElement("tr");
  const level = document.createElement("td");
  const chip = el("span", "appr-chip " + (row.level || ""));
  if (String(row.level || "") === "critical") chip.append(cloneTpl("tpl-alert"));
  chip.append(document.createTextNode(row.level || ""));
  level.append(chip);
  const pattern = document.createElement("td");
  pattern.append(el("div", "rules-cmd", (row.matches || []).join("\n")));
  if (row.applies_to && row.applies_to !== "All bots") pattern.append(el("div", "rules-src", row.applies_to));
  if (stricter && row.raised_from) pattern.append(el("div", "rules-src", "Raised from " + row.raised_from + " to " + row.level));
  const what = document.createElement("td");
  what.textContent = riskLabel(row);
  const applies = document.createElement("td");
  applies.textContent = row.applies_to || "All bots";
  tr.append(level, pattern, what, applies);
  return tr;
}
async function changeRuleEffect(rule, effect) {
  const payload = {
    kind: rule.kind === "pattern" ? "pattern" : "exact",
    argv: rule.argv || [],
    pattern: rule.pattern || "",
    scope: rule.scope,
    bot_id: rule.bot_id || "",
    effect: effect
  };
  const res = await brokerCall("/api/permbroker/rules/" + encodeURIComponent(rule.id) + "/replace", { method: "POST", body: JSON.stringify(payload) });
  if (res.network || (res.status !== 200 && res.status !== 207)) return;
  if (res.data && res.data.revoked === false) {
    showStatusToast(REPLACE_BOTH, null);
    rulesForce = true;
    pollSoon();
    return;
  }
  const created = res.data && res.data.created;
  showStatusToast("Rule saved · Undo", function () {
    if (created) brokerCall("/api/permbroker/rules/" + encodeURIComponent(created), { method: "DELETE" });
    brokerCall("/api/permbroker/rules", { method: "POST", body: JSON.stringify(Object.assign({}, payload, { effect: rule.effect })) }).then(pollSoon);
  });
  pollSoon();
}
async function revokeRule(rule, trigger) {
  const list = document.getElementById("rules-list");
  let nextKey = "sec:" + ((rule && rule.bot_id) || (rule && rule.scope) || "global");
  if (trigger && trigger.closest && list) {
    const row = trigger.closest(".rules-row");
    let sib = row ? row.nextElementSibling : null;
    while (sib) {
      const menu = sib.querySelector ? sib.querySelector("[data-rules-focus$=':menu']") : null;
      if (menu) { nextKey = menu.getAttribute("data-rules-focus"); break; }
      sib = sib.nextElementSibling;
    }
  }
  setIntendedFocus("rules:" + nextKey);
  const payload = {
    kind: rule.kind === "legacy" ? "exact" : (rule.kind === "pattern" ? "pattern" : "exact"),
    argv: rule.argv || [],
    pattern: rule.pattern || "",
    scope: rule.scope,
    bot_id: rule.bot_id || "",
    effect: rule.effect
  };
  const res = await brokerCall("/api/permbroker/rules/" + encodeURIComponent(rule.id), { method: "DELETE" });
  if (res.status !== 200) { approvals.intendedFocus = ""; return; }
  if (rule.kind === "legacy") showStatusToast("Rule revoked.", null);
  else showStatusToast("Rule revoked · Undo", function () {
    brokerCall("/api/permbroker/rules", { method: "POST", body: JSON.stringify(payload) }).then(function (res) {
      const created = res && res.data && res.data.rule && res.data.rule.id;
      const sec = (rule && rule.scope === "global") ? "global" : ((rule && rule.bot_id) || "global");
      if (res && res.status === 200 && created) setIntendedFocus("rules:rule:" + created + ":menu");
      else setIntendedFocus("rules:sec:" + sec);
      pollSoon();
    });
  });
  pollSoon();
}
function syncHookWait() {
  if (typeof hookRunWaiting !== "function" || typeof state === "undefined" || !state) return;
  const b = typeof currentBot === "function" ? currentBot() : null;
  const live = !!(state.streaming || state.approvalWait || (b && (b.status === "running" || b.active_run_id)));
  if (!live) return;
  setWorking(true);
}
async function pollApprovals() {
  if (approvals.polling) { pollAgain = true; return; }
  approvals.polling = true;
  try {
    const pending = await brokerCall("/api/permbroker/pending");
    if (pending.network) {
      approvals.netDown = true;
    } else if (pending.status === 200) {
      approvals.netDown = false;
      approvals.polled = true;
      approvalItems = (pending.data && pending.data.pending) || [];
    } else if (pending.status === 403 || pending.status === 404) {
      approvals.netDown = false;
      approvals.polled = true;
      approvalItems = [];
    }
    const rules = await brokerCall("/api/permbroker/rules");
    if (rules.status === 200 && rules.data) {
      approvalRules = rules.data.rules || [];
      approvalGrants = rules.data.task_grants || [];
    }
    const recent = await brokerCall("/api/permbroker/recent");
    if (recent.status === 200 && recent.data) approvalRecent = recent.data.recent || [];
    const risk = await brokerCall("/api/permbroker/risk-tables");
    if (risk.status === 200) approvalRisk = risk.data;
    if (!approvals.wrappers) {
      const wrappers = await brokerCall("/api/permbroker/patterns/wrappers");
      if (wrappers.status === 200 && wrappers.data) approvals.wrappers = wrappers.data.wrappers || [];
    }
    const live = {};
    (approvalItems || []).forEach(function (item) { live[item.id] = true; });
    Object.keys(cardUI).forEach(function (id) { if (!live[id]) delete cardUI[id]; });
    renderApprovals();
    if (typeof renderBots === "function") renderBots();
    syncHookWait();
  } finally {
    approvals.polling = false;
    if (pollAgain) { pollAgain = false; pollApprovals(); return; }
    clearTimeout(pollTimer);
    pollTimer = setTimeout(pollApprovals, APPROVAL_POLL_MS);
  }
}
function pollSoon() {
  pollAgain = true;
  if (!approvals.polling) pollApprovals();
}
function startApprovals() {
  if (approvals.started) return;
  approvals.started = true;
  document.querySelectorAll("button.appr-btn").forEach(function (button) {
    button.addEventListener("click", function () {
      if (queueOpen) closeApprovals();
      else openApprovals({ manual: true, focus: true });
    });
  });
  const scrim = $("#approvals-scrim");
  if (scrim) scrim.addEventListener("click", closeApprovals);
  const close = $("#approvals-close");
  if (close) close.addEventListener("click", closeApprovals);
  const rulesLink = $("#approvals-rules");
  if (rulesLink) rulesLink.addEventListener("click", function (ev) {
    if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey || ev.button) return;
    ev.preventDefault();
    openRules("", true);
  });
  const panel = $("#approvals");
  if (panel) panel.addEventListener("keydown", function (e) {
    if (e.key !== "Tab" || approvalMode() === "dock") return;
    if (typeof trapStateTab === "function") trapStateTab(e, panel, document.activeElement);
  });
  const alerts = $("#menu-alerts");
  if (alerts) alerts.addEventListener("click", function () {
    if (typeof closeRosterMenu === "function") closeRosterMenu();
    approvals.forceAlerts = true;
    openApprovals({ manual: true, focus: true });
  });
  const rules = $("#menu-rules");
  if (rules) rules.addEventListener("click", function () {
    if (typeof closeRosterMenu === "function") closeRosterMenu();
    openRules("", true);
  });
  const profileRules = $("#open-approval-rules");
  if (profileRules) profileRules.addEventListener("click", function () {
    const bot = typeof currentBot === "function" ? currentBot() : null;
    openRules(bot ? bot.id : (state.botId || ""), true);
  });
  const back = $("#rules-back");
  if (back) back.addEventListener("click", function () { if (typeof navBack === "function") navBack(); });
  const add = $("#rules-new");
  if (add) add.addEventListener("click", function () {
    openRuleSheet({ scope: "bot", bot_id: state.rulesBot || state.botId || "" });
  });
  document.querySelectorAll("#view-rules .rules-filters [role='radio']").forEach(function (button) {
    button.addEventListener("click", function () {
      rulesFilter = button.getAttribute("data-filter") || "all";
      rulesForce = true;
      paintRules();
    });
  });
  document.addEventListener("click", function () {
    document.querySelectorAll("#view-rules .rules-pop").forEach(function (pop) { pop.hidden = true; });
  });
  ["#rule-kind", "#rule-scope", "#rule-effect"].forEach(function (sel) {
    const root = $(sel);
    if (!root) return;
    root.addEventListener("click", function (ev) {
      const button = ev.target.closest("[role='radio']");
      if (!button) return;
      const attr = sel === "#rule-kind" ? "data-kind" : sel === "#rule-scope" ? "data-scope" : "data-effect";
      setSeg(root, attr, button.getAttribute(attr));
      syncRuleForm();
      scheduleRuleCheck();
    });
  });
  const input = $("#rule-pattern");
  if (input) input.addEventListener("input", function () { syncRuleForm(); scheduleRuleCheck(); });
  const botPick = $("#rule-bot");
  if (botPick) botPick.addEventListener("change", function () { syncRuleForm(); scheduleRuleCheck(); });
  const save = $("#rule-save");
  if (save) save.addEventListener("click", saveRuleFromForm);
  const cancel = $("#rule-cancel");
  if (cancel) cancel.addEventListener("click", closeRuleSheet);
  const ruleClose = $("#rule-close");
  if (ruleClose) ruleClose.addEventListener("click", closeRuleSheet);
  const ruleScrim = $("#rule-scrim");
  if (ruleScrim) ruleScrim.addEventListener("click", closeRuleSheet);
  const sheet = $("#rule-sheet");
  if (sheet) sheet.addEventListener("keydown", function (e) {
    if (e.key === "Tab" && typeof trapStateTab === "function") trapStateTab(e, sheet, document.activeElement);
  });
  window.addEventListener("resize", function () { applyQueueChrome(); });
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) syncNotifications(approvalItems || []);
  });
  if (hashIsApprovals(location.hash)) openApprovals({ manual: true, focus: false });
  pollApprovals();
}
// approvals-dom:end

state.stop = freshStop();
ensureHistory();
paintHealth();
renderBots();
startApprovals();
refreshDaemon();
