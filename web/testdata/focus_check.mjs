// Behavioural focus check for the approvals queue and /rules Undo.
// Run: node focus_check.mjs --base http://127.0.0.1:PORT [--shots DIR]
// Playwright resolves from LGB_PLAYWRIGHT_DIR, then NODE_PATH, then the
// shotkit checkout used by the Go test.
import { createRequire } from "node:module";
import { existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const require = createRequire(import.meta.url);
const base = flag("--base").replace(/\/$/, "");
const shots = flag("--shots", "");
const pwDir = process.env.LGB_PLAYWRIGHT_DIR || "/home/pixnbits/lgb-dev-data/shotkit/node_modules/playwright";
const { chromium } = require(pwDir);

function flag(name, fallback) {
  const i = process.argv.indexOf(name);
  if (i < 0) {
    if (fallback !== undefined) return fallback;
    console.error("missing " + name);
    process.exit(2);
  }
  return process.argv[i + 1] || fallback || "";
}

const describe = `(() => {
  function shown(node) {
    let el = node;
    while (el && el.nodeType === 1) {
      if (el.hidden) return false;
      const st = getComputedStyle(el);
      if (st.display === "none" || st.visibility === "hidden") return false;
      el = el.parentElement;
    }
    return !!node;
  }
  const active = document.activeElement;
  const panel = document.querySelector("#approvals");
  const opener = [...document.querySelectorAll("button.appr-btn")].find(shown) || null;
  const toast = document.querySelector("#toast");
  return {
    tag: active ? active.tagName : "",
    id: active && active.id ? active.id : "",
    label: active && active.getAttribute ? (active.getAttribute("aria-label") || "") : "",
    focus: active && active.getAttribute ? (active.getAttribute("data-rules-focus") || active.getAttribute("data-appr-focus") || "") : "",
    body: !active || active === document.body || active === document.documentElement,
    panelOpen: !!(panel && !panel.hidden),
    opener: !!(opener && active === opener),
    empty: !!(active && active.id === "approvals-empty-title"),
    ruleMenu: !!(active && active.getAttribute && active.getAttribute("aria-label") === "Rule actions"),
    section: !!(active && active.matches && active.matches("#rules-list h3[data-rules-focus]")),
    rows: document.querySelectorAll("#rules-list .rules-row").length,
    toast: toast && !toast.hidden ? (toast.textContent || "").replace(/\\s+/g, " ").trim() : ""
  };
})()`;

function okEscape(info) {
  return !info.body && info.opener;
}
function okBatch(info) {
  if (info.body) return false;
  if (info.panelOpen) return info.empty;
  return info.opener;
}
function okUndo(info) {
  return info.rows > 0 && !info.body && (info.ruleMenu || info.section);
}

async function shot(page, name) {
  if (!shots) return;
  mkdirSync(shots, { recursive: true });
  await page.screenshot({ path: join(shots, name + ".png"), fullPage: true });
}

async function settle(page, pred, label) {
  let last = null;
  let stable = 0;
  const started = Date.now();
  while (Date.now() - started < 10000) {
    const info = await page.evaluate(describe);
    const key = JSON.stringify(info);
    if (pred(info) && key === JSON.stringify(last)) stable += 1;
    else stable = 0;
    last = info;
    if (stable >= 15) return info;
    await page.waitForTimeout(100);
  }
  throw new Error(label + " focus did not settle: " + JSON.stringify(last));
}

async function clickOpener(page) {
  const clicked = await page.evaluate(() => {
    function shown(node) {
      let el = node;
      while (el && el.nodeType === 1) {
        if (el.hidden) return false;
        const st = getComputedStyle(el);
        if (st.display === "none" || st.visibility === "hidden") return false;
        el = el.parentElement;
      }
      return !!node;
    }
    const button = [...document.querySelectorAll("button.appr-btn")].find(shown);
    if (!button) return false;
    button.click();
    return true;
  });
  if (!clicked) throw new Error("no visible Approvals button");
}

async function reset(page) {
  const res = await page.request.post(base + "/__focus/reset");
  if (!res.ok()) throw new Error("reset " + res.status());
}

async function boot(page, path) {
  await page.goto(base + path, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => {
    function shown(node) {
      let el = node;
      while (el && el.nodeType === 1) {
        if (el.hidden) return false;
        const st = getComputedStyle(el);
        if (st.display === "none" || st.visibility === "hidden") return false;
        el = el.parentElement;
      }
      return !!node;
    }
    return [...document.querySelectorAll("button.appr-btn")].some(shown);
  }, { timeout: 8000 });
}

async function runWidth(browser, width) {
  const page = await browser.newPage({ viewport: { width, height: width <= 600 ? 844 : 900 } });
  const failures = [];
  page.on("pageerror", (err) => failures.push(String(err)));
  try {
    await reset(page);
    await boot(page, "/");
    if (width >= 1180) {
      await page.waitForFunction(() => {
        const panel = document.querySelector("#approvals");
        return panel && !panel.hidden && !!document.querySelector("button[data-appr-focus*='approve-all']");
      }, { timeout: 8000 });
      await page.locator("button[data-appr-focus*='approve-all']").first().click();
      const batch = await settle(page, (info) => okBatch(info) && info.toast.indexOf("Approved 2") >= 0 && info.toast.indexOf("Approved 0") < 0, "approve-all@" + width);
      if (batch.body) throw new Error("approve-all left focus on body");
      await shot(page, "batch-" + width);
      await reset(page);
      await boot(page, "/");
      await page.waitForFunction(() => {
        const panel = document.querySelector("#approvals");
        return panel && !panel.hidden;
      }, { timeout: 8000 });
      await page.keyboard.press("Escape");
      const esc = await settle(page, okEscape, "escape@" + width);
      if (!esc.opener) throw new Error("escape focus " + JSON.stringify(esc));
      await shot(page, "escape-" + width);
    } else {
      await clickOpener(page);
      await page.waitForFunction(() => {
        const panel = document.querySelector("#approvals");
        return panel && !panel.hidden;
      }, { timeout: 8000 });
      await page.keyboard.press("Escape");
      const esc = await settle(page, okEscape, "escape@" + width);
      if (!esc.opener) throw new Error("escape focus " + JSON.stringify(esc));
      await shot(page, "escape-" + width);
      await clickOpener(page);
      await page.waitForSelector("button[data-appr-focus*='deny-all']", { timeout: 8000 });
      await page.locator("button[data-appr-focus*='deny-all']").first().click();
      const batch = await settle(page, (info) => okBatch(info) && info.toast.indexOf("Denied 2") >= 0 && info.toast.indexOf("Denied 0") < 0, "deny-all@" + width);
      if (batch.body) throw new Error("deny-all left focus on body");
      await shot(page, "batch-" + width);
    }
    await reset(page);
    await boot(page, "/rules");
    await page.waitForSelector("button[aria-label='Rule actions']", { timeout: 8000 });
    await page.locator("button[aria-label='Rule actions']").first().click();
    await page.locator("#view-rules [role='menuitem']", { hasText: "Revoke" }).click();
    await page.waitForSelector("#toast button", { timeout: 8000 });
    await page.locator("#toast button", { hasText: "Undo" }).click();
    const undo = await settle(page, okUndo, "undo@" + width);
    if (undo.body) throw new Error("undo left focus on body");
    await shot(page, "undo-" + width);
    if (failures.length) throw new Error("page errors: " + failures.join(" | "));
    console.log(JSON.stringify({ width, ok: true }));
  } finally {
    await page.close();
  }
}

function chromiumExecutable() {
  const fromEnv = process.env.LGB_CHROMIUM || "";
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  const home = homedir();
  const candidates = [
    join(home, ".cache/ms-playwright/chromium-1243/chrome-linux64/chrome"),
    join(home, ".cache/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell"),
  ];
  for (const path of candidates) {
    if (existsSync(path)) return path;
  }
  return "";
}

const executablePath = chromiumExecutable();
if (!executablePath) {
  console.error("skip: chromium-1243 is not installed under ~/.cache/ms-playwright");
  process.exit(2);
}
const browser = await chromium.launch({ headless: true, executablePath });
try {
  await runWidth(browser, 390);
  await runWidth(browser, 1280);
} finally {
  await browser.close();
}
console.log("focus ok");
