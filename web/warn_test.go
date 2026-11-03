package web

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestWarningMarkup(t *testing.T) {
	page := string(IndexHTML)
	css := string(AppCSS)
	js := string(AppJS)
	for _, id := range []string{"profile-warn", "warn-net", "warn-github"} {
		if strings.Count(page, `id="`+id+`"`) != 1 {
			t.Errorf("id %s count %d", id, strings.Count(page, `id="`+id+`"`))
		}
	}
	if strings.Count(page, `role="note"`) != 3 {
		t.Errorf("role=note count %d", strings.Count(page, `role="note"`))
	}
	if strings.Count(page, `<span class="sr">Warning: </span>`) != 3 {
		t.Errorf("warning prefix count %d", strings.Count(page, `<span class="sr">Warning: </span>`))
	}
	netHelp := strings.Index(page, `id="help-net"`)
	netWarn := strings.Index(page, `id="warn-net"`)
	ghHelp := strings.Index(page, `id="help-github"`)
	ghWarn := strings.Index(page, `id="warn-github"`)
	if netHelp < 0 || netWarn < netHelp || ghHelp < 0 || ghWarn < ghHelp {
		t.Fatalf("advisory placement net %d/%d github %d/%d", netHelp, netWarn, ghHelp, ghWarn)
	}
	if strings.Contains(page, `id="profile-warn-text"`) {
		t.Fatal("description warning is still one text node")
	}
	for _, s := range []string{
		`a.target = "_blank"`,
		`a.rel = "noopener noreferrer"`,
		` (opens in a new tab)`,
		`classList.add("st-warn")`,
		`descriptionWarningText(warningTextOf(row))`,
		`setAttribute("aria-describedby", helpId + " " + box.id)`,
		`removeAttribute("aria-describedby")`,
	} {
		if !strings.Contains(js, s) {
			t.Errorf("app.js missing %q", s)
		}
	}
	for _, s := range []string{"appendLinkedWarning", "Saving still works."} {
		if s == "Saving still works." {
			if strings.Count(js, s) == 0 {
				t.Error("description suffix removed")
			}
			continue
		}
		if strings.Contains(js, s) {
			t.Errorf("app.js still has %q", s)
		}
	}
	// The suffix is added for description warnings only.
	if strings.Contains(js, `msg += " Saving still works."`) {
		t.Fatal("blanket saving suffix is still appended")
	}
	body, ok := ruleBody(css, ".advisory a")
	if !ok || !strings.Contains(body, "color: var(--accent-text)") {
		t.Fatalf("advisory link colour %q", body)
	}
	phone := strings.Join(mediaBodies(t, css, "@media (max-width: 540px)"), "\n")
	tap, ok := ruleBody(phone, ".advisory a")
	if !ok || !strings.Contains(tap, "min-height: 44px") || !strings.Contains(tap, "display: flex") || !strings.Contains(tap, "align-items: center") {
		t.Fatalf("advisory tap target %q", tap)
	}
	warnRow, ok := ruleBody(css, ".st-warn")
	if !ok || !strings.Contains(warnRow, "color: var(--attention-text)") {
		t.Fatalf("state warning colour %q", warnRow)
	}
	urls := strings.ReplaceAll(js, "http://www.w3.org/2000/svg", "")
	for _, scheme := range []string{"http://", "https://"} {
		if i := strings.Index(urls, scheme); i >= 0 {
			t.Errorf("app.js has %q near %q", scheme, urls[i:min(i+40, len(urls))])
		}
	}
	if strings.Contains(page, "http://") || strings.Contains(page, "https://") {
		t.Fatal("index.html has a scheme literal")
	}
}

func TestWarningRender(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node not installed")
	}
	slice := between(t, string(AppJS), "// warn-logic:begin", "function setGrants")
	payload, err := json.Marshal(map[string]string{
		"issue": "https://github.com/PixnBits/local-grok-bots/issues/33",
		"other": "https://example.com/PixnBits/local-grok-bots/issues/33",
		"evil":  "https://github.com/PixnBits/local-grok-bots-evil/issues/1",
		"gap":   "Add it to `repos` under `[github]` in policy.toml, or remove it here.",
		"host":  "storage.googleapis.com gives this bot access to all of Google Cloud Storage, not just your project. Remove it unless the bot needs it.",
		"label": "Why this matters (GitHub issue #33)",
		"token": "The GitHub token file /tmp/token doesn't exist. Create it, or fix `token_file` in policy.toml.",
	})
	if err != nil {
		t.Fatal(err)
	}
	script := warningHarness + "\nconst data = " + string(payload) + ";\n" + slice + "\n" + warningChecks
	raw := runNode(t, node, script)
	assertCases(t, raw)
}

const warningHarness = `
class N {
  constructor(tag) {
    this.tag = tag;
    this.kids = [];
    this.className = "";
    this.attrs = {};
    this.hidden = false;
    this.id = "";
    this._text = "";
    this.href = "";
    this.target = "";
    this.rel = "";
  }
  appendChild(k) { this.kids.push(k); return k; }
  replaceChildren() { this.kids = []; }
  set textContent(v) { this._text = v == null ? "" : String(v); this.kids = []; }
  get textContent() { return this._text; }
  get childNodes() { return this.kids; }
  setAttribute(name, value) { this.attrs[name] = String(value); }
  removeAttribute(name) { delete this.attrs[name]; }
  getAttribute(name) { return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null; }
  querySelector(sel) {
    if (sel !== "ul") return null;
    const walk = (n) => {
      if (!n || !n.kids) return null;
      for (const k of n.kids) {
        if (k.tag === "ul") return k;
        const inner = walk(k);
        if (inner) return inner;
      }
      return null;
    };
    return walk(this);
  }
}
const document = {
  createElement(tag) { return new N(tag); },
  createTextNode(text) { return { text: String(text) }; }
};
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function makeBox(id) {
  const ul = new N("ul");
  const sr = new N("span");
  sr.className = "sr";
  sr.textContent = "Warning: ";
  const copy = new N("div");
  copy.className = "advisory-copy";
  copy.appendChild(sr);
  copy.appendChild(ul);
  const box = new N("div");
  box.id = id;
  box.hidden = true;
  box.appendChild(copy);
  return box;
}
function makeInput() {
  const attrs = {};
  return {
    setAttribute(name, value) { attrs[name] = String(value); },
    removeAttribute(name) { delete attrs[name]; },
    getAttribute(name) { return Object.prototype.hasOwnProperty.call(attrs, name) ? attrs[name] : null; }
  };
}
const boxes = {
  "profile-warn": makeBox("profile-warn"),
  "warn-net": makeBox("warn-net"),
  "warn-github": makeBox("warn-github")
};
const inputs = { "profile-net": makeInput(), "profile-github": makeInput() };
function $(s) {
  const id = s.charAt(0) === "#" ? s.slice(1) : s;
  return boxes[id] || inputs[id] || null;
}
`

const warningChecks = `
const cases = [];
function check(name, ok) { cases.push({name: name, ok: !!ok}); }
check("href-ok", githubProjectHref(data.issue) === true);
check("href-other", githubProjectHref(data.other) === false);
check("href-evil", githubProjectHref(data.evil) === false);
check("href-bad", githubProjectHref("not a url") === false);
check("parts", warningParts(data.gap).filter(function (p) { return p.code; }).map(function (p) { return p.text; }).join("|") === "repos|[github]");
check("save", descriptionWarningText("Hello.") === "Hello. Saving still works.");
check("save-once", descriptionWarningText("Already. Saving still works.") === "Already. Saving still works.");
const rows = [
  {field: "description", text: "One."},
  {field: "description", text: "Already. Saving still works."},
  {field: "net_allow", text: data.host, link: {href: data.issue, label: data.label}},
  {field: "github_allow", text: data.gap},
  {field: "github_token", text: data.token},
  {field: "net_allow", text: "Ignored host", link: {href: data.other, label: "Elsewhere"}}
];
paintWarnings(rows);
function lis(id) {
  const ul = boxes[id].querySelector("ul");
  return ul ? ul.kids : [];
}
function codes(li) {
  return li.kids.filter(function (k) { return k.tag === "code"; }).map(function (k) { return k._text; }).join("|");
}
function anchors(li) {
  return li.kids.filter(function (k) { return k.tag === "a"; });
}
function plain(li) {
  return li.kids.filter(function (k) { return !k.tag; }).map(function (k) { return k.text; }).join("");
}
const desc = lis("profile-warn");
const net = lis("warn-net");
const gh = lis("warn-github");
check("desc-count", desc.length === 2 && boxes["profile-warn"].hidden === false);
check("desc-suffix", plain(desc[0]).indexOf("Saving still works.") >= 0);
check("desc-once", plain(desc[1]).indexOf("Saving still works.") >= 0 && plain(desc[1]).indexOf("Saving still works. Saving still works.") < 0);
check("net-count", net.length === 2 && boxes["warn-net"].hidden === false);
check("net-no-save", plain(net[0]).indexOf("Saving still works") < 0 && plain(net[1]).indexOf("Saving still works") < 0);
check("gh-count", gh.length === 2 && boxes["warn-github"].hidden === false);
check("gh-codes", codes(gh[0]) === "repos|[github]" && codes(gh[1]) === "token_file");
check("gh-no-save", plain(gh[0]).indexOf("Saving still works") < 0 && plain(gh[1]).indexOf("Saving still works") < 0);
const a = anchors(net[0]);
check("link-one", a.length === 1);
check("link-attrs", a.length === 1 && a[0].href === data.issue && a[0].target === "_blank" && a[0].rel === "noopener noreferrer" && a[0]._text === data.label);
check("link-sr", a.length === 1 && a[0].kids.length === 1 && a[0].kids[0].className === "sr" && a[0].kids[0]._text === " (opens in a new tab)");
check("link-plain", anchors(net[1]).length === 0 && plain(net[1]).indexOf("Elsewhere") >= 0 && plain(net[1]).indexOf(data.other) < 0);
check("sr-kept", boxes["warn-net"].kids[0].kids[0].className === "sr" && boxes["warn-net"].kids[0].kids[0]._text === "Warning: ");
check("aria-net", inputs["profile-net"].getAttribute("aria-describedby") === "help-net warn-net");
check("aria-gh", inputs["profile-github"].getAttribute("aria-describedby") === "help-github warn-github");
paintWarnings([]);
check("cleared-net", boxes["warn-net"].hidden === true && lis("warn-net").length === 0);
check("cleared-gh", boxes["warn-github"].hidden === true && lis("warn-github").length === 0);
check("cleared-desc", boxes["profile-warn"].hidden === true);
check("aria-off", inputs["profile-net"].getAttribute("aria-describedby") == null && inputs["profile-github"].getAttribute("aria-describedby") == null);
console.log(JSON.stringify(cases));
`
