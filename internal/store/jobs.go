package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/PixnBits/local-grok-bots/internal/id"
)

const (
	JobRunning = "running"
	JobExited  = "exited"
	JobStopped = "stopped"
	JobExpired = "expired"
	JobLost    = "job_lost"
	JobError   = "error"
)

// Job is one background shell. Status running holds a slot.
// ExitCode is set when the process exited on its own.
type Job struct {
	ID         string `json:"id"`
	BotID      string `json:"bot_id"`
	Command    string `json:"command"`
	Status     string `json:"status"`
	LogPath    string `json:"log_path"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	Reason     string `json:"reason,omitempty"`
	PGID       int    `json:"pgid,omitempty"`
}

// JobLimitError is a refused background start. Count is how many are already running.
type JobLimitError struct {
	PerBot bool
	Count  int
	Limit  int
}

func (e *JobLimitError) Error() string {
	if e == nil {
		return "background job limit"
	}
	if e.PerBot {
		return fmt.Sprintf("this bot already has %d background jobs running; the limit is %d", e.Count, e.Limit)
	}
	return fmt.Sprintf("%d background jobs are already running; the limit is %d", e.Count, e.Limit)
}

// InsertRunningJob inserts a running row only when the bot and the daemon
// are both under their limits. The counts and the insert are one transaction.
func (s *Store) InsertRunningJob(j Job, maxBot, maxTotal int) error {
	if s == nil {
		return errors.New("store unavailable")
	}
	if j.ID == "" || j.BotID == "" {
		return errors.New("job id and bot required")
	}
	if j.Status == "" {
		j.Status = JobRunning
	}
	if j.Status != JobRunning {
		return errors.New("new job must be running")
	}
	if j.StartedAt == "" {
		j.StartedAt = FormatTime(Now())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var botN, total int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM jobs WHERE status=? AND bot_id=?`, JobRunning, j.BotID).Scan(&botN); err != nil {
		return err
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM jobs WHERE status=?`, JobRunning).Scan(&total); err != nil {
		return err
	}
	if maxBot > 0 && botN >= maxBot {
		return &JobLimitError{PerBot: true, Count: botN, Limit: maxBot}
	}
	if maxTotal > 0 && total >= maxTotal {
		return &JobLimitError{Count: total, Limit: maxTotal}
	}
	_, err = tx.Exec(`INSERT INTO jobs(id, bot_id, command, status, log_path, started_at, finished_at, exit_code, reason, pgid) VALUES(?,?,?,?,?,?,NULL,NULL,?,?)`,
		j.ID, j.BotID, j.Command, JobRunning, j.LogPath, j.StartedAt, j.Reason, j.PGID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// GetJob reads one job. A missing id is ErrNotFound.
func (s *Store) GetJob(id string) (Job, error) {
	if s == nil {
		return Job{}, errors.New("store unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT id, bot_id, command, status, log_path, started_at, finished_at, exit_code, reason, pgid FROM jobs WHERE id=?`, id)
	j, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	return j, err
}

// SetJobPGID records the process group while the job is still running.
func (s *Store) SetJobPGID(id string, pgid int) error {
	if s == nil {
		return errors.New("store unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE jobs SET pgid=? WHERE id=? AND status=?`, pgid, id, JobRunning)
	return err
}

// FinishJob moves a running job to status. A row that is no longer running
// is left as it is and ok is false.
func (s *Store) FinishJob(id, status string, exitCode *int, reason string) (bool, error) {
	if s == nil {
		return false, errors.New("store unavailable")
	}
	if status == "" || status == JobRunning {
		return false, errors.New("finish status required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var exit any
	if exitCode != nil {
		exit = *exitCode
	}
	res, err := s.db.Exec(`UPDATE jobs SET status=?, finished_at=?, exit_code=?, reason=? WHERE id=? AND status=?`,
		status, FormatTime(Now()), exit, reason, id, JobRunning)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DeleteRunningJob removes a running row that never became a background job.
func (s *Store) DeleteRunningJob(id string) error {
	if s == nil {
		return errors.New("store unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM jobs WHERE id=? AND status=?`, id, JobRunning)
	return err
}

// MarkLostJobs marks every running job job_lost and stores text(job) as a
// system message on that bot. Both writes are one transaction. A row that
// stops being running between the read and the update is skipped.
func (s *Store) MarkLostJobs(text func(Job) string) ([]Job, error) {
	if s == nil {
		return nil, errors.New("store unavailable")
	}
	if text == nil {
		text = func(Job) string { return "" }
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id, bot_id, command, status, log_path, started_at, finished_at, exit_code, reason, pgid FROM jobs WHERE status=?`, JobRunning)
	if err != nil {
		return nil, err
	}
	var running []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		running = append(running, j)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	now := FormatTime(Now())
	var lost []Job
	for _, j := range running {
		res, err := tx.Exec(`UPDATE jobs SET status=?, finished_at=?, reason=? WHERE id=? AND status=?`,
			JobLost, now, "daemon_restart", j.ID, JobRunning)
		if err != nil {
			return nil, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		j.Status = JobLost
		j.FinishedAt = now
		j.Reason = "daemon_restart"
		msg := SanitizeSystemText(text(j))
		if msg != "" {
			if _, err := tx.Exec(`INSERT INTO messages(id, bot_id, thread, role, content, run_id, created_at, timed_out, kind) VALUES(?,?,?,?,?,?,?,?,?)`,
				id.New(), j.BotID, "user", "system", msg, nil, FormatTime(Now()), 0, ""); err != nil {
				return nil, err
			}
		}
		lost = append(lost, j)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return lost, nil
}

type jobScanner interface {
	Scan(dest ...any) error
}

func scanJob(sc jobScanner) (Job, error) {
	var j Job
	var finished sql.NullString
	var exit sql.NullInt64
	err := sc.Scan(&j.ID, &j.BotID, &j.Command, &j.Status, &j.LogPath, &j.StartedAt, &finished, &exit, &j.Reason, &j.PGID)
	if err != nil {
		return Job{}, err
	}
	if finished.Valid {
		j.FinishedAt = finished.String
	}
	if exit.Valid {
		n := int(exit.Int64)
		j.ExitCode = &n
	}
	return j, nil
}
