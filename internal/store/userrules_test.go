package store

import (
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
