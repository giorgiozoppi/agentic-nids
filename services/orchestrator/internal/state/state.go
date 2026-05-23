// Package state persists a timestamp between orchestrator CronJob runs.
package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const filename = "last_processed_at"

// Load reads the persisted timestamp from dir/last_processed_at.
// If the file does not exist (first run) it returns time.Now().Add(-24h).
func Load(dir string) (time.Time, error) {
	path := filepath.Join(dir, filename)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t := time.Now().Add(-24 * time.Hour)
		return t, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("read state file %s: %w", path, err)
	}

	raw := strings.TrimSpace(string(data))
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp %q: %w", raw, err)
	}
	return t, nil
}

// Save atomically writes t to dir/last_processed_at using a write-then-rename
// strategy to avoid partial writes.
func Save(dir string, t time.Time) error {
	finalPath := filepath.Join(dir, filename)
	tmpPath   := finalPath + ".tmp"

	if err := os.WriteFile(tmpPath, []byte(t.UTC().Format(time.RFC3339Nano)), 0o644); err != nil {
		return fmt.Errorf("write tmp state file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("rename state file: %w", err)
	}
	return nil
}
