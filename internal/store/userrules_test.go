package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestUserPermRulesRoundTrip(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bot, err := st.CreateBot("perm", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	rule, err := st.InsertUserPermRule(UserPermRule{
		BotID: bot.ID, Effect: "allow", Pattern: "Bash(gh pr view *)",
		Classification: "read_only", Sensitivity: "project", Risk: "low", Reason: "rechecked",
	})
	if err != nil || rule.ID == "" {
		t.Fatal(err)
	}
	if _, err := st.InsertUserPermRule(rule); err != ErrConflict {
		t.Fatalf("duplicate %v", err)
	}
	got, err := st.ListUserPermRules(bot.ID)
	if err != nil || len(got) != 1 || got[0].Pattern != "Bash(gh pr view *)" {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := st.RevokeUserPermRule(bot.ID, rule.ID); err != nil {
		t.Fatal(err)
	}
	got, err = st.ListUserPermRules(bot.ID)
	if err != nil || len(got) != 0 {
		t.Fatalf("after revoke %+v %v", got, err)
	}
	if _, err := st.RevokeUserPermRule(bot.ID, rule.ID); err != ErrNotFound {
		t.Fatalf("second revoke %v", err)
	}
}

func TestAcceptUserPermRuleRollsBackOnWriteError(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bot, err := st.CreateBot("perm", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.AcceptUserPermRule(UserPermRule{
		BotID: bot.ID, Effect: "allow", Pattern: "Bash(pwd)",
		Classification: "read_only", Risk: "low",
	}, map[string]any{"action": "accept"}, func([]UserPermRule) error {
		return errInjected
	})
	if err != errInjected {
		t.Fatalf("err %v", err)
	}
	got, err := st.ListUserPermRules(bot.ID)
	if err != nil || len(got) != 0 {
		t.Fatalf("row survived %+v %v", got, err)
	}
	logs, err := st.ListLog(bot.ID, "user_perm_rule", "", 10)
	if err != nil || len(logs) != 0 {
		t.Fatalf("audit survived %+v %v", logs, err)
	}
}

func TestRevokeUserPermRuleApplyRollsBackOnWriteError(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bot, err := st.CreateBot("perm", "", nil, "user")
	if err != nil {
		t.Fatal(err)
	}
	rule, err := st.AcceptUserPermRule(UserPermRule{
		BotID: bot.ID, Effect: "allow", Pattern: "Bash(pwd)",
		Risk: "low",
	}, map[string]any{"action": "accept"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.RevokeUserPermRuleApply(bot.ID, rule.ID, nil, func([]UserPermRule) error {
		return errInjected
	})
	if err != errInjected {
		t.Fatalf("err %v", err)
	}
	got, err := st.ListUserPermRules(bot.ID)
	if err != nil || len(got) != 1 || got[0].ID != rule.ID {
		t.Fatalf("revoke stuck %+v %v", got, err)
	}
}

var errInjected = errors.New("injected write failure")
