package web

import (
	"encoding/json"
	"os/exec"
	"testing"
)

func TestMutatingFetchSetsJSONContentType(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := ClientSource()
	apiSrc, err := json.Marshal(jsFunc(t, src, "async function api("))
	if err != nil {
		t.Fatal(err)
	}
	brokerSrc, err := json.Marshal(jsFunc(t, src, "async function brokerCall("))
	if err != nil {
		t.Fatal(err)
	}
	script := `const vm = require("vm");
const apiSrc = ` + string(apiSrc) + `;
const brokerSrc = ` + string(brokerSrc) + `;
const ctx = {
  state: {token: ""},
  calls: [],
  base: function () { return ""; },
  showAuth: function () {},
  fetch: async function (url, opts) {
    ctx.calls.push({url: url, opts: opts || {}});
    return {status: 204, text: async function () { return ""; }};
  }
};
vm.createContext(ctx);
vm.runInContext(apiSrc + "\nthis.api = api;", ctx);
vm.runInContext(brokerSrc + "\nthis.brokerCall = brokerCall;", ctx);
(async function () {
  const out = [];
  function check(name, cond, got) { out.push({name: name, ok: !!cond, got: got == null ? "" : String(got)}); }
  ctx.calls = [];
  await ctx.api("/api/bots", {method: "POST"});
  const post = ctx.calls[0] && ctx.calls[0].opts;
  check("api-post-ct", post && post.headers && post.headers["Content-Type"] === "application/json", post && post.headers && post.headers["Content-Type"]);
  check("api-post-body", post && post.body === "{}", post && post.body);
  ctx.calls = [];
  await ctx.api("/api/timers/t1", {method: "DELETE"});
  const del = ctx.calls[0] && ctx.calls[0].opts;
  check("api-delete-ct", del && del.headers && del.headers["Content-Type"] === "application/json", del && del.headers && del.headers["Content-Type"]);
  check("api-delete-body", del && del.body === "{}", del && del.body);
  ctx.calls = [];
  await ctx.api("/api/bots");
  const get = ctx.calls[0] && ctx.calls[0].opts;
  check("api-get-no-ct", get && (!get.headers || !get.headers["Content-Type"]), get && get.headers && get.headers["Content-Type"]);
  ctx.calls = [];
  await ctx.brokerCall("/api/permbroker/rules/r1", {method: "DELETE"});
  const bdel = ctx.calls[0] && ctx.calls[0].opts;
  check("broker-delete-ct", bdel && bdel.headers && bdel.headers["Content-Type"] === "application/json", bdel && bdel.headers && bdel.headers["Content-Type"]);
  check("broker-delete-body", bdel && bdel.body === "{}", bdel && bdel.body);
  console.log(JSON.stringify(out));
})().catch(function (err) { console.error(String(err)); process.exit(1); });
`
	out := runNode(t, node, script)
	var rows []checkRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("decode %v: %s", err, out)
	}
	reportChecks(t, "api", rows)
}
