package config

import "testing"

func TestScrubbedEnvironDropsSecrets(t *testing.T) {
	const token = "unit-auth-token-canary"
	env := []string{
		"PATH=/usr/bin",
		"DATA_DIR=/tmp/data",
		"BIND_ADDR=127.0.0.1:9",
		"AUTH_TOKEN=" + token,
		"XAI_API_KEY=xai-secret",
		"LGB_CANARY_PROC=unit-canary-proc-value",
		"LEAK=" + token,
		"HOME=/tmp",
		"API_KEY=k",
		"session_Token=t",
		"db_SECRET=s",
		"DB_PASS=p",
		"GPG_TTY=/dev/pts/1",
		"SSH_AUTH_SOCK=/tmp/agent.sock",
		"LANG=C",
	}
	got := scrubbedEnviron(env, token)
	m := map[string]string{}
	for _, kv := range got {
		k, v, _ := cutKV(kv)
		m[k] = v
	}
	if m["PATH"] != "/usr/bin" || m["DATA_DIR"] != "/tmp/data" || m["BIND_ADDR"] != "127.0.0.1:9" || m["HOME"] != "/tmp" || m["GPG_TTY"] != "/dev/pts/1" || m["SSH_AUTH_SOCK"] != "/tmp/agent.sock" || m["LANG"] != "C" {
		t.Fatalf("kept %#v", m)
	}
	if m[readyKey] != readyVal {
		t.Fatalf("marker %#v", m)
	}
	for _, k := range []string{"AUTH_TOKEN", "XAI_API_KEY", "LGB_CANARY_PROC", "LEAK", "API_KEY", "session_Token", "db_SECRET", "DB_PASS"} {
		if _, ok := m[k]; ok {
			t.Fatalf("kept %s", k)
		}
	}
}

func cutKV(kv string) (string, string, bool) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:], true
		}
	}
	return kv, "", false
}
