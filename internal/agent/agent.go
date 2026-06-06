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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/collectors"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type Config struct {
	Source            string
	Path              string
	BaseURL           string
	Token             string
	BatchSize         int
	PollInterval      time.Duration
	StatePath         string
	Once              bool
	Client            *http.Client
	Runner            CommandRunner
	NativeLogName     string
	NativeJournalUnit string
}

type State struct {
	Offset    int64     `json:"offset"`
	Remainder string    `json:"remainder"`
	LastSize  int64     `json:"last_size"`
	UpdatedAt time.Time `json:"updated_at"`
	Cursor    string    `json:"cursor,omitempty"`
	RecordID  int64     `json:"record_id,omitempty"`
}

type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

func Run(ctx context.Context, cfg Config) error {
	if cfg.Source == "" {
		return errors.New("source is required")
	}
	if !isNativeSource(cfg.Source) && cfg.Path == "" {
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
	if cfg.Runner == nil {
		cfg.Runner = defaultRunner
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
	if isNativeSource(cfg.Source) {
		return processNativeOnce(ctx, cfg, client, state)
	}

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

func processNativeOnce(ctx context.Context, cfg Config, client *http.Client, state *State) (int, error) {
	switch cfg.Source {
	case "windows-eventlog":
		events, err := collectWindowsEventLog(ctx, cfg, state)
		if err != nil {
			return 0, err
		}
		if len(events) == 0 {
			return 0, nil
		}
		if err := postEvents(ctx, client, cfg.BaseURL, cfg.Token, cfg.BatchSize, events); err != nil {
			return 0, err
		}
		return len(events), nil
	case "journald":
		events, err := collectJournalctl(ctx, cfg, state)
		if err != nil {
			return 0, err
		}
		if len(events) == 0 {
			return 0, nil
		}
		if err := postEvents(ctx, client, cfg.BaseURL, cfg.Token, cfg.BatchSize, events); err != nil {
			return 0, err
		}
		return len(events), nil
	default:
		return 0, fmt.Errorf("unsupported native collector source %q", cfg.Source)
	}
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

func isNativeSource(source string) bool {
	switch source {
	case "windows-eventlog", "journald":
		return true
	default:
		return false
	}
}

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return output, nil
}

type windowsEventRecord struct {
	RecordID     int64  `json:"RecordId"`
	EventID      int    `json:"EventId"`
	ProviderName string `json:"ProviderName"`
	MachineName  string `json:"MachineName"`
	TimeCreated  string `json:"TimeCreated"`
	Message      string `json:"Message"`
}

type journalRecord struct {
	Cursor     string `json:"__CURSOR"`
	Timestamp  string `json:"__REALTIME_TIMESTAMP"`
	Hostname   string `json:"_HOSTNAME"`
	Unit       string `json:"_SYSTEMD_UNIT"`
	Identifier string `json:"SYSLOG_IDENTIFIER"`
	Priority   string `json:"PRIORITY"`
	Message    string `json:"MESSAGE"`
}

func collectWindowsEventLog(ctx context.Context, cfg Config, state *State) ([]domain.Event, error) {
	logName := cfg.NativeLogName
	if logName == "" {
		logName = "Microsoft-Windows-Sysmon/Operational"
	}
	script := fmt.Sprintf(`$log = %q; $last = %d; $max = %d; $events = Get-WinEvent -LogName $log -MaxEvents $max | Where-Object { $_.RecordId -gt $last } | Sort-Object RecordId; $events | ForEach-Object { [pscustomobject]@{ RecordId = [int64]$_.RecordId; EventId = [int]$_.Id; ProviderName = $_.ProviderName; MachineName = $_.MachineName; TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o"); Message = $_.Message } | ConvertTo-Json -Compress }`, logName, state.RecordID, max(1, cfg.BatchSize))
	output, err := cfg.Runner(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return nil, err
	}
	return parseWindowsEventLog(output, state)
}

func collectJournalctl(ctx context.Context, cfg Config, state *State) ([]domain.Event, error) {
	args := []string{"--no-pager", "--output=json"}
	if cfg.NativeJournalUnit != "" {
		args = append(args, "-u", cfg.NativeJournalUnit)
	}
	if state.Cursor != "" {
		args = append(args, "--after-cursor", state.Cursor)
	} else {
		args = append(args, "-n", strconv.Itoa(max(1, cfg.BatchSize)))
	}
	output, err := cfg.Runner(ctx, "journalctl", args...)
	if err != nil {
		return nil, err
	}
	return parseJournalRecords(output, state)
}

func parseWindowsEventLog(output []byte, state *State) ([]domain.Event, error) {
	lines := splitOutputLines(output)
	events := make([]domain.Event, 0, len(lines))
	var maxRecordID int64 = state.RecordID
	for i, line := range lines {
		var rec windowsEventRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("windows event line %d: %w", i+1, err)
		}
		if rec.RecordID > maxRecordID {
			maxRecordID = rec.RecordID
		}
		events = append(events, windowEventToDomain(rec))
	}
	state.RecordID = maxRecordID
	if len(lines) > 0 {
		state.UpdatedAt = time.Now().UTC()
	}
	return events, nil
}

func parseJournalRecords(output []byte, state *State) ([]domain.Event, error) {
	lines := splitOutputLines(output)
	events := make([]domain.Event, 0, len(lines))
	for i, line := range lines {
		var rec journalRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("journal line %d: %w", i+1, err)
		}
		if rec.Cursor != "" {
			state.Cursor = rec.Cursor
		}
		events = append(events, journalRecordToDomain(rec))
	}
	if len(lines) > 0 {
		state.UpdatedAt = time.Now().UTC()
	}
	return events, nil
}

func splitOutputLines(output []byte) []string {
	lines := strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
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

func windowEventToDomain(rec windowsEventRecord) domain.Event {
	ts := parseTime(rec.TimeCreated)
	event := domain.Event{
		Timestamp: ts,
		Kind:      domain.EventHostObservation,
		AssetID:   firstNonEmpty(rec.MachineName, "windows-host"),
		Hostname:  rec.MachineName,
		Signal:    fmt.Sprintf("%s event %d", firstNonEmpty(rec.ProviderName, "windows"), rec.EventID),
		Labels:    []string{"windows", strings.ToLower(firstNonEmpty(rec.ProviderName, "eventlog"))},
		Metadata: map[string]string{
			"collector": "windows-eventlog",
			"provider":  rec.ProviderName,
			"record_id": strconv.FormatInt(rec.RecordID, 10),
			"event_id":  strconv.Itoa(rec.EventID),
			"message":   rec.Message,
			"source_os": runtime.GOOS,
		},
	}
	switch rec.EventID {
	case 1, 4688:
		event.Kind = domain.EventProcessStart
	case 3:
		event.Kind = domain.EventNetworkFlow
	case 4624, 4625:
		event.Kind = domain.EventAuth
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return event
}

func journalRecordToDomain(rec journalRecord) domain.Event {
	ts := parseJournalTime(rec.Timestamp)
	event := domain.Event{
		Timestamp: ts,
		Kind:      domain.EventHostObservation,
		AssetID:   firstNonEmpty(rec.Hostname, "journal-host"),
		Hostname:  rec.Hostname,
		Signal:    firstNonEmpty(rec.Message, rec.Identifier, "journald event"),
		Labels:    []string{"journald", strings.ToLower(firstNonEmpty(rec.Unit, rec.Identifier, "event"))},
		Metadata: map[string]string{
			"collector":  "journald",
			"cursor":     rec.Cursor,
			"unit":       rec.Unit,
			"identifier": rec.Identifier,
			"priority":   rec.Priority,
		},
	}
	if looksLikeAuthMessage(rec.Message) {
		event.Kind = domain.EventAuth
	}
	if strings.Contains(strings.ToLower(rec.Message), "execve") || strings.Contains(strings.ToLower(rec.Message), "process") {
		event.Kind = domain.EventProcessStart
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return event
}

func parseJournalTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if micros, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.UnixMicro(micros).UTC()
	}
	return parseTime(raw)
}

func looksLikeAuthMessage(msg string) bool {
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "failed password") || strings.Contains(msg, "accepted password") || strings.Contains(msg, "authentication failure")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func parseTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	formats := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999", "2006-01-02 15:04:05"}
	for _, format := range formats {
		parsed, err := time.Parse(format, value)
		if err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}
