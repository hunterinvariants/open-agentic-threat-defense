package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/agent"
	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
	"github.com/open-agentic-threat-defense/oadtd/internal/collectors"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
	"github.com/open-agentic-threat-defense/oadtd/internal/store"
	"github.com/open-agentic-threat-defense/oadtd/internal/telemetry"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "collect":
		if err := collect(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "replay":
		if err := replay(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "backup":
		if err := backup(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "restore":
		if err := restore(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "agent":
		if err := agentCommand(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "token-hash":
		if err := tokenHash(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "wedge-demo":
		if err := wedgeDemo(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func tokenHash(args []string) error {
	fs := flag.NewFlagSet("token-hash", flag.ContinueOnError)
	token := fs.String("token", "", "token to hash")
	if err := fs.Parse(args); err != nil {
		return err
	}
	value := *token
	if value == "" {
		value = os.Getenv("OATD_TOKEN")
	}
	if value == "" {
		return errors.New("token-hash requires --token or OATD_TOKEN")
	}
	fmt.Println(auth.HashToken(value))
	return nil
}

func collect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	source := fs.String("source", "", "collector source: "+strings.Join(collectors.Sources(), ", "))
	filePath := fs.String("file", "", "source log file, or - for stdin")
	outputPath := fs.String("output", "-", "output JSONL file, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" {
		return errors.New("collect requires --source")
	}
	if *filePath == "" {
		return errors.New("collect requires --file")
	}

	input, closeInput, err := openInput(*filePath)
	if err != nil {
		return err
	}
	defer closeInput()

	events, err := collectors.Normalize(*source, input)
	if err != nil {
		return err
	}

	output, closeOutput, err := openOutput(*outputPath)
	if err != nil {
		return err
	}
	defer closeOutput()

	encoder := json.NewEncoder(output)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	if *outputPath != "-" {
		fmt.Printf("events=%d output=%s\n", len(events), *outputPath)
	}
	return nil
}

func replay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	filePath := fs.String("file", "", "JSONL event file, or - for stdin")
	baseURL := fs.String("url", "http://localhost:8080", "OATD base URL")
	token := fs.String("token", os.Getenv("OATD_API_TOKEN"), "optional API token")
	batchSize := fs.Int("batch-size", 100, "events per request")
	dryRun := fs.Bool("dry-run", false, "parse input without sending events")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *filePath == "" {
		return errors.New("replay requires --file")
	}
	if *batchSize < 1 {
		return errors.New("--batch-size must be at least 1")
	}

	events, err := readEvents(*filePath)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Printf("events=%d dry_run=true\n", len(events))
		return nil
	}

	client := &http.Client{Timeout: 15 * time.Second}
	totalAlerts := 0
	for start := 0; start < len(events); start += *batchSize {
		end := start + *batchSize
		if end > len(events) {
			end = len(events)
		}
		alerts, err := postEvents(client, *baseURL, *token, events[start:end])
		if err != nil {
			return err
		}
		totalAlerts += alerts
	}

	fmt.Printf("events=%d alerts_created=%d\n", len(events), totalAlerts)
	return nil
}

func backup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	dsn := fs.String("postgres-dsn", os.Getenv("OATD_POSTGRES_DSN"), "Postgres DSN")
	outputPath := fs.String("output", "-", "backup JSON file, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return errors.New("backup requires --postgres-dsn or OATD_POSTGRES_DSN")
	}

	st, err := store.NewWithPostgres(*dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	snap := st.ExportSnapshot()
	output, closeOutput, err := openOutput(*outputPath)
	if err != nil {
		return err
	}
	defer closeOutput()

	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(snap); err != nil {
		return err
	}
	if *outputPath != "-" {
		fmt.Printf("backup=%s version=%d events=%d alerts=%d actions=%d audits=%d\n", *outputPath, snap.Version, len(snap.Events), len(snap.Alerts), len(snap.Actions), len(snap.Audits))
	}
	return nil
}

func restore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	dsn := fs.String("postgres-dsn", os.Getenv("OATD_POSTGRES_DSN"), "Postgres DSN")
	inputPath := fs.String("input", "", "backup JSON file, or - for stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return errors.New("restore requires --postgres-dsn or OATD_POSTGRES_DSN")
	}
	if *inputPath == "" {
		return errors.New("restore requires --input")
	}

	input, closeInput, err := openInput(*inputPath)
	if err != nil {
		return err
	}
	defer closeInput()

	var snap store.Snapshot
	if err := json.NewDecoder(input).Decode(&snap); err != nil {
		return err
	}

	st, err := store.NewWithPostgres(*dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.RestoreSnapshot(snap); err != nil {
		return err
	}
	fmt.Printf("restored version=%d events=%d alerts=%d actions=%d audits=%d\n", snap.Version, len(snap.Events), len(snap.Alerts), len(snap.Actions), len(snap.Audits))
	return nil
}

func agentCommand(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	source := fs.String("source", "", "collector source: "+strings.Join(agentSources(), ", "))
	filePath := fs.String("file", "", "path to the source log file")
	baseURL := fs.String("url", "http://localhost:8080", "OATD base URL")
	token := fs.String("token", os.Getenv("OATD_API_TOKEN"), "optional API token")
	batchSize := fs.Int("batch-size", 100, "events per request")
	pollInterval := fs.Duration("poll-interval", 5*time.Second, "poll interval for tailing")
	statePath := fs.String("state-file", "", "optional state file for offsets")
	nativeLogName := fs.String("log-name", "Microsoft-Windows-Sysmon/Operational", "Windows event log name for native collection")
	nativeJournalUnit := fs.String("journal-unit", "", "optional systemd unit filter for native journald collection")
	once := fs.Bool("once", false, "process available content once and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" {
		return errors.New("agent requires --source")
	}
	if !isNativeAgentSource(*source) && *filePath == "" {
		return errors.New("agent requires --file")
	}
	ctx := context.Background()
	if err := agent.Run(ctx, agent.Config{
		Source:            *source,
		Path:              *filePath,
		BaseURL:           *baseURL,
		Token:             *token,
		BatchSize:         *batchSize,
		PollInterval:      *pollInterval,
		StatePath:         *statePath,
		Once:              *once,
		NativeLogName:     *nativeLogName,
		NativeJournalUnit: *nativeJournalUnit,
	}); err != nil {
		return err
	}
	return nil
}

func wedgeDemo(args []string) error {
	fs := flag.NewFlagSet("wedge-demo", flag.ContinueOnError)
	baseURL := fs.String("url", "http://localhost:8080", "OADTD base URL")
	token := fs.String("token", os.Getenv("OATD_API_TOKEN"), "optional API token")
	approvedBy := fs.String("approved-by", "operator", "approver for held requests")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	cases := []struct {
		name string
		req  domain.ToolCallRequest
	}{
		{
			name: "benign",
			req: domain.ToolCallRequest{
				AssetID:  "demo-agent-01",
				Hostname: "demo-agent-01",
				Actor:    "demo-agent",
				ToolName: "asset_inventory",
				Command:  "list assets",
				Labels:   []string{"agent", "tool-call"},
			},
		},
		{
			name: "risky",
			req: domain.ToolCallRequest{
				AssetID:   "demo-agent-01",
				Hostname:  "demo-agent-01",
				Actor:     "demo-agent",
				ToolName:  "asset_inventory",
				Command:   "inspect inventory",
				Arguments: "token=abc123",
				Labels:    []string{"agent", "tool-call"},
			},
		},
		{
			name: "canary",
			req: domain.ToolCallRequest{
				AssetID:  "demo-agent-01",
				Hostname: "demo-agent-01",
				Actor:    "demo-agent",
				ToolName: "asset_inventory",
				Command:  "read protected vault",
				Signal:   "canary token touched",
				Labels:   []string{"agent", "tool-call", "canary", "deception"},
			},
		},
	}

	fmt.Println("wedge-demo:")
	for _, tc := range cases {
		result, err := postGatewayExecution(client, *baseURL, *token, tc.req)
		if err != nil {
			return fmt.Errorf("%s: %w", tc.name, err)
		}
		switch result.Status {
		case "allow":
			fmt.Printf("- %s: allow -> proceed\n", tc.name)
		case "executed":
			fmt.Printf("- %s: allow -> result=%s\n", tc.name, result.Result)
		case "blocked":
			fmt.Printf("- %s: deny -> alerts=%d evidence=%s\n", tc.name, len(result.Decision.Alerts), result.Decision.Reason)
		case "pending_approval":
			if result.Action == nil {
				return fmt.Errorf("%s: approval verdict without action", tc.name)
			}
			fmt.Printf("- %s: require approval -> pending action %s\n", tc.name, result.Action.ID)
			approved, err := approveGatewayAction(client, *baseURL, *token, result.Action.ID, *approvedBy)
			if err != nil {
				return fmt.Errorf("%s approve: %w", tc.name, err)
			}
			fmt.Printf("  approved by %s -> execution=%s\n", *approvedBy, approved.ExecutionStatus)
		default:
			return fmt.Errorf("%s: unexpected status %s", tc.name, result.Status)
		}
	}
	return nil
}

func readEvents(filePath string) ([]domain.Event, error) {
	input, closeInput, err := openInput(filePath)
	if err != nil {
		return nil, err
	}
	defer closeInput()
	return telemetry.ReadJSONL(input)
}

func openInput(filePath string) (io.Reader, func(), error) {
	if filePath == "-" {
		return os.Stdin, func() {}, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	return file, func() { _ = file.Close() }, nil
}

func openOutput(filePath string) (io.Writer, func(), error) {
	if filePath == "-" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.Create(filePath)
	if err != nil {
		return nil, nil, err
	}
	return file, func() { _ = file.Close() }, nil
}

func postGatewayExecution(client *http.Client, baseURL string, token string, request domain.ToolCallRequest) (domain.ToolExecutionResult, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return domain.ToolExecutionResult{}, err
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/api/gateway/execute"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return domain.ToolExecutionResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return domain.ToolExecutionResult{}, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusForbidden {
		return domain.ToolExecutionResult{}, fmt.Errorf("POST %s returned %s: %s", endpoint, resp.Status, strings.TrimSpace(string(respBody)))
	}

	var result domain.ToolExecutionResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return domain.ToolExecutionResult{}, err
	}
	if result.Status == "" {
		if resp.StatusCode == http.StatusForbidden {
			result.Status = "blocked"
		} else if resp.StatusCode == http.StatusAccepted {
			result.Status = "pending_approval"
		} else {
			result.Status = "executed"
		}
	}
	return result, nil
}

func approveGatewayAction(client *http.Client, baseURL string, token string, actionID string, approvedBy string) (domain.ResponseAction, error) {
	body, err := json.Marshal(map[string]string{
		"action_id":   actionID,
		"approved_by": approvedBy,
	})
	if err != nil {
		return domain.ResponseAction{}, err
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/api/responses/approve"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return domain.ResponseAction{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return domain.ResponseAction{}, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return domain.ResponseAction{}, fmt.Errorf("POST %s returned %s: %s", endpoint, resp.Status, strings.TrimSpace(string(respBody)))
	}

	var action domain.ResponseAction
	if err := json.Unmarshal(respBody, &action); err != nil {
		return domain.ResponseAction{}, err
	}
	return action, nil
}

func postEvents(client *http.Client, baseURL string, token string, events []domain.Event) (int, error) {
	body, err := json.Marshal(events)
	if err != nil {
		return 0, err
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/api/events"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("POST %s returned %s: %s", endpoint, resp.Status, strings.TrimSpace(string(respBody)))
	}

	var result struct {
		AlertsCreated int `json:"alerts_created"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return 0, err
	}
	return result.AlertsCreated, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  oadtdctl collect --source suricata-eve --file eve.json --output events.jsonl")
	fmt.Fprintln(os.Stderr, "  oadtdctl replay --file events.jsonl [--url http://localhost:8080] [--token TOKEN]")
	fmt.Fprintln(os.Stderr, "  oadtdctl backup --postgres-dsn DSN --output backup.json")
	fmt.Fprintln(os.Stderr, "  oadtdctl restore --postgres-dsn DSN --input backup.json")
	fmt.Fprintln(os.Stderr, "  oadtdctl agent --source sysmon-json --file sysmon.jsonl [--url http://localhost:8080]")
	fmt.Fprintln(os.Stderr, "  oadtdctl agent --source windows-eventlog [--log-name Microsoft-Windows-Sysmon/Operational]")
	fmt.Fprintln(os.Stderr, "  oadtdctl agent --source journald [--journal-unit ssh.service]")
	fmt.Fprintln(os.Stderr, "  oadtdctl token-hash --token TOKEN")
	fmt.Fprintln(os.Stderr, "  oadtdctl wedge-demo [--url http://localhost:8080] [--approved-by operator]")
}

func isNativeAgentSource(source string) bool {
	switch source {
	case "windows-eventlog", "journald":
		return true
	default:
		return false
	}
}

func agentSources() []string {
	return append(collectors.Sources(), "windows-eventlog", "journald")
}
