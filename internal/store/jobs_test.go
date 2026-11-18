package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestJobSlotsAndLost(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	put := func(id, bot string) {
		t.Helper()
		err := st.InsertRunningJob(Job{
			ID: id, BotID: bot, Command: "sleep", LogPath: ".lgb/jobs/" + id + ".log",
		}, 2, 4)
		if err != nil {
			t.Fatal(err)
		}
	}
	put("a1", "bot-a")
	put("a2", "bot-a")
	err = st.InsertRunningJob(Job{ID: "a3", BotID: "bot-a", Command: "sleep", LogPath: ".lgb/jobs/a3.log"}, 2, 4)
	var lim *JobLimitError
	if !errors.As(err, &lim) || !lim.PerBot || lim.Limit != 2 || lim.Count != 2 {
		t.Fatalf("per bot %v", err)
	}
	put("b1", "bot-b")
	put("b2", "bot-b")
	err = st.InsertRunningJob(Job{ID: "c1", BotID: "bot-c", Command: "sleep", LogPath: ".lgb/jobs/c1.log"}, 2, 4)
	lim = nil
	if !errors.As(err, &lim) || lim.PerBot || lim.Limit != 4 || lim.Count != 4 {
		t.Fatalf("total %v", err)
	}
	lost, err := st.MarkLostJobs(func(j Job) string {
		return "[job] " + j.ID + " " + j.Status + "\nThe log is at " + j.LogPath
	})
	if err != nil || len(lost) != 4 {
		t.Fatalf("lost %v %d", err, len(lost))
	}
	job, err := st.GetJob("a1")
	if err != nil || job.Status != JobLost || job.Reason != "daemon_restart" {
		t.Fatalf("%+v %v", job, err)
	}
	msgs, err := st.ListMessages("bot-a", "user", "", 10)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("messages %v %d", err, len(msgs))
	}
	for _, m := range msgs {
		if m.Role != "system" || !strings.HasPrefix(m.Content, "[job] ") || !strings.Contains(m.Content, "job_lost") {
			t.Fatalf("message %+v", m)
		}
	}
	again, err := st.MarkLostJobs(func(Job) string { return "again" })
	if err != nil || len(again) != 0 {
		t.Fatalf("second %v %d", err, len(again))
	}
}
