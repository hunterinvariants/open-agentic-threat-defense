package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/collectors"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type Config struct {
	Source       string
	Path         string
	BaseURL      string
	Token        string
	BatchSize    int
	PollInterval time.Duration
	StatePath    string
	Once         bool
	Client       *http.Client
}

type State struct {
	Offset    int64     `json:"offset"`
	Remainder string    `json:"remainder"`
	LastSize  int64     `json:"last_size"`
	UpdatedAt time.Time `json:"updated_at"`
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.Source == "" {
		return errors.New("source is required")
	}
	if cfg.Path == "" {
		return errors.New("path is required")
	}
	if cfg.BaseURL == "" {
		return errors.New("base URL is required")
	}
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 100
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	state, err := loadState(cfg.StatePath)
	if err != nil {
		return err
	}

	for {
		processed, err := processOnce(ctx, cfg, client, &state)
		if err != nil {
			return err
		}
		if err := saveState(cfg.StatePath, state); err != nil {
			return err
		}
		if cfg.Once {
			return nil
		}
		if processed == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(cfg.PollInterval):
			}
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.PollInterval):
		}
	}
}

func processOnce(ctx context.Context, cfg Config, client *http.Client, state *State) (int, error) {
	info, err := os.Stat(cfg.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	if info.Size() < state.Offset {
		state.Offset = 0
		state.Remainder = ""
	}

	file, err := os.Open(cfg.Path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	if _, err := file.Seek(state.Offset, io.SeekStart); err != nil {
		return 0, err
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}

	state.LastSize = info.Size()
	state.UpdatedAt = time.Now().UTC()

	lines, remainder := splitCompleteLines(state.Remainder + string(data))
	state.Remainder = remainder
	state.Offset = info.Size() - int64(len(state.Remainder))
	if state.Offset < 0 {
		state.Offset = 0
	}
	if len(lines) == 0 {
		return len(data), nil
	}

	events, err := collectors.Normalize(cfg.Source, strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return len(data), nil
	}
	if err := postEvents(ctx, client, cfg.BaseURL, cfg.Token, cfg.BatchSize, events); err != nil {
		return 0, err
	}
	return len(events), nil
}

func splitCompleteLines(content string) ([]string, string) {
	if content == "" {
		return nil, ""
	}
	parts := strings.Split(content, "\n")
	if strings.HasSuffix(content, "\n") {
		return trimEmptyLines(parts), ""
	}
	if len(parts) == 1 {
		return nil, parts[0]
	}
	return trimEmptyLines(parts[:len(parts)-1]), parts[len(parts)-1]
}

func trimEmptyLines(lines []string) []string {
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		if line == "" {
			continue
		}
		result = append(result, line)
	}
	return result
}

func postEvents(ctx context.Context, client *http.Client, baseURL string, token string, batchSize int, events []domain.Event) error {
	endpoint := strings.TrimRight(baseURL, "/") + "/api/events"
	for start := 0; start < len(events); start += batchSize {
		end := start + batchSize
		if end > len(events) {
			end = len(events)
		}
		body, err := json.Marshal(events[start:end])
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("POST %s returned %s: %s", endpoint, resp.Status, strings.TrimSpace(string(respBody)))
		}
	}
	return nil
}

func loadState(path string) (State, error) {
	if path == "" {
		return State{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func saveState(path string, state State) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(path)
		return os.Rename(tmp, path)
	}
	return nil
}
