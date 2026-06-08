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
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/agent"
	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
	"github.com/open-agentic-threat-defense/oadtd/internal/collectors"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
	"github.com/open-agentic-threat-defense/oadtd/internal/license"
	"github.com/open-agentic-threat-defense/oadtd/internal/policy"
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
	case "sign-manifest":
		if err := signManifestCommand(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "license":
		if err := licenseCommand(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "validate":
		if err := validateCommand(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "mcp-stub":
		if err := mcpStubCommand(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "mcp-demo":
		if err := mcpDemoCommand(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "bench":
		if err := benchCommand(os.Args[2:]); err != nil {
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

func signManifestCommand(args []string) error {
	fs := flag.NewFlagSet("sign-manifest", flag.ContinueOnError)
	filePath := fs.String("file", "", "threat pack manifest JSON to sign")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *filePath == "" {
		return errors.New("sign-manifest requires --file")
	}
	sigPath, err := policy.SignThreatPackFile(*filePath)
	if err != nil {
		return err
	}
	fmt.Printf("manifest=%s signature=%s\n", *filePath, sigPath)
	return nil
}

func licenseCommand(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: oadtdctl license <keygen|issue|verify> ...")
	}
	switch args[0] {
	case "keygen":
		pub, priv, err := license.GenerateKeyPair()
		if err != nil {
			return err
		}
		fmt.Printf("public_key=%s\nprivate_key=%s\n", pub, priv)
		return nil
	case "issue":
		fs := flag.NewFlagSet("license issue", flag.ContinueOnError)
		privateKey := fs.String("private-key", os.Getenv("OATD_LICENSE_PRIVATE_KEY"), "base64 ed25519 private key")
		org := fs.String("org", "", "licensed organization")
		edition := fs.String("edition", "commercial", "license edition")
		features := fs.String("features", "", "comma-separated feature flags")
		validFor := fs.Duration("valid-for", 365*24*time.Hour, "validity duration from now")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*privateKey) == "" {
			return errors.New("license issue requires --private-key or OATD_LICENSE_PRIVATE_KEY")
		}
		if strings.TrimSpace(*org) == "" {
			return errors.New("license issue requires --org")
		}
		var feats []string
		for _, f := range strings.Split(*features, ",") {
			if s := strings.TrimSpace(f); s != "" {
				feats = append(feats, s)
			}
		}
		token, err := license.Issue(license.License{
			Org:       strings.TrimSpace(*org),
			Edition:   strings.TrimSpace(*edition),
			Features:  feats,
			ExpiresAt: time.Now().UTC().Add(*validFor),
		}, *privateKey)
		if err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	case "verify":
		fs := flag.NewFlagSet("license verify", flag.ContinueOnError)
		publicKey := fs.String("public-key", os.Getenv("OATD_LICENSE_PUBLIC_KEY"), "base64 ed25519 public key")
		token := fs.String("token", "", "license token to verify")
		tokenFile := fs.String("file", "", "file containing the license token")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		value := strings.TrimSpace(*token)
		if value == "" && strings.TrimSpace(*tokenFile) != "" {
			data, err := os.ReadFile(*tokenFile)
			if err != nil {
				return err
			}
			value = strings.TrimSpace(string(data))
		}
		if strings.TrimSpace(*publicKey) == "" || value == "" {
			return errors.New("license verify requires --public-key and --token or --file")
		}
		status := license.Evaluate(value, *publicKey, time.Now().UTC())
		out, err := json.MarshalIndent(status, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		if !status.Valid {
			return errors.New("license is not valid")
		}
		return nil
	default:
		return fmt.Errorf("unknown license subcommand %q", args[0])
	}
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
	maxRetries := fs.Int("max-retries", 3, "retry attempts per batch on transient failure")
	retryBackoff := fs.Duration("retry-backoff", 500*time.Millisecond, "base backoff between retries (doubles each attempt)")
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
	if *maxRetries < 0 {
		return errors.New("--max-retries must be >= 0")
	}

	events, err := readEvents(*filePath)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Printf("events=%d batches=%d dry_run=true\n", len(events), batchCount(len(events), *batchSize))
		return nil
	}

	client := &http.Client{Timeout: 15 * time.Second}
	report := replayReport{TotalEvents: len(events), BatchSize: *batchSize}
	for start := 0; start < len(events); start += *batchSize {
		end := start + *batchSize
		if end > len(events) {
			end = len(events)
		}
		report.Batches++
		alerts, attempts, err := postEventsWithRetry(client, *baseURL, *token, events[start:end], *maxRetries, *retryBackoff)
		if attempts > 1 {
			report.Retries += attempts - 1
		}
		if err != nil {
			report.FailedBatches++
			report.FailedEvents += end - start
			report.Errors = append(report.Errors, fmt.Sprintf("batch %d (events %d-%d): %v", report.Batches, start, end-1, err))
			continue
		}
		report.SentBatches++
		report.SentEvents += end - start
		report.AlertsCreated += alerts
	}

	report.print()
	if report.FailedBatches > 0 {
		return fmt.Errorf("replay completed with %d of %d batch(es) failed", report.FailedBatches, report.Batches)
	}
	return nil
}

type replayReport struct {
	TotalEvents   int
	BatchSize     int
	Batches       int
	SentBatches   int
	FailedBatches int
	SentEvents    int
	FailedEvents  int
	AlertsCreated int
	Retries       int
	Errors        []string
}

func (r replayReport) print() {
	fmt.Println("replay report:")
	fmt.Printf("  events_total=%d batch_size=%d batches=%d\n", r.TotalEvents, r.BatchSize, r.Batches)
	fmt.Printf("  sent_batches=%d failed_batches=%d retries=%d\n", r.SentBatches, r.FailedBatches, r.Retries)
	fmt.Printf("  sent_events=%d failed_events=%d alerts_created=%d\n", r.SentEvents, r.FailedEvents, r.AlertsCreated)
	for _, e := range r.Errors {
		fmt.Printf("  error: %s\n", e)
	}
}

func batchCount(events int, size int) int {
	if size < 1 || events <= 0 {
		return 0
	}
	return (events + size - 1) / size
}

func postEventsWithRetry(client *http.Client, baseURL string, token string, events []domain.Event, maxRetries int, backoff time.Duration) (int, int, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		alerts, err := postEvents(client, baseURL, token, events)
		if err == nil {
			return alerts, attempt + 1, nil
		}
		lastErr = err
		if attempt < maxRetries {
			wait := backoff << uint(attempt)
			if wait > 30*time.Second {
				wait = 30 * time.Second
			}
			if wait > 0 {
				time.Sleep(wait)
			}
		}
	}
	return 0, maxRetries + 1, lastErr
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
	awaitApproval := fs.Bool("await-approval", false, "wait for operator approval instead of auto-approving the pending action")
	approvalTimeout := fs.Duration("approval-timeout", 30*time.Second, "how long to wait for operator approval when awaiting")
	pollInterval := fs.Duration("poll-interval", 2*time.Second, "poll interval while waiting for operator approval")
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
			if *awaitApproval {
				updated, err := waitForGatewayActionExecution(client, *baseURL, *token, result.Action.ID, *approvalTimeout, *pollInterval)
				if err != nil {
					return fmt.Errorf("%s wait: %w", tc.name, err)
				}
				fmt.Printf("  operator approved -> execution=%s\n", updated.ExecutionStatus)
			} else {
				approved, err := approveGatewayAction(client, *baseURL, *token, result.Action.ID, *approvedBy)
				if err != nil {
					return fmt.Errorf("%s approve: %w", tc.name, err)
				}
				fmt.Printf("  approved by %s -> execution=%s\n", *approvedBy, approved.ExecutionStatus)
			}
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

func getGatewayAction(client *http.Client, baseURL string, token string, actionID string) (domain.ResponseAction, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/api/gateway/actions/" + url.PathEscape(actionID)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.ResponseAction{}, err
	}
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
		return domain.ResponseAction{}, fmt.Errorf("GET %s returned %s: %s", endpoint, resp.Status, strings.TrimSpace(string(respBody)))
	}
	var action domain.ResponseAction
	if err := json.Unmarshal(respBody, &action); err != nil {
		return domain.ResponseAction{}, err
	}
	return action, nil
}

func waitForGatewayActionExecution(client *http.Client, baseURL string, token string, actionID string, timeout time.Duration, interval time.Duration) (domain.ResponseAction, error) {
	deadline := time.Now().Add(timeout)
	for {
		action, err := getGatewayAction(client, baseURL, token, actionID)
		if err != nil {
			return domain.ResponseAction{}, err
		}
		if action.ExecutionStatus != "" && action.ExecutionStatus != "not_required" {
			return action, nil
		}
		if action.ApprovalStatus == "approved" {
			return action, nil
		}
		if time.Now().After(deadline) {
			return domain.ResponseAction{}, fmt.Errorf("timed out waiting for approval of %s", actionID)
		}
		time.Sleep(interval)
	}
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
	fmt.Fprintln(os.Stderr, "  oadtdctl wedge-demo [--url http://localhost:8080] [--approved-by operator] [--await-approval]")
	fmt.Fprintln(os.Stderr, "  oadtdctl validate [--url http://localhost:8080] [--token TOKEN] [--json]")
	fmt.Fprintln(os.Stderr, "  oadtdctl mcp-stub [--addr 127.0.0.1:9100]")
	fmt.Fprintln(os.Stderr, "  oadtdctl mcp-demo [--url http://localhost:8080] [--token TOKEN] [--json]")
	fmt.Fprintln(os.Stderr, "  oadtdctl bench [--url http://localhost:8080] [--token TOKEN] [--requests N] [--concurrency N]")
	fmt.Fprintln(os.Stderr, "  oadtdctl sign-manifest --file threatpack.manifest.json")
	fmt.Fprintln(os.Stderr, "  oadtdctl license keygen")
	fmt.Fprintln(os.Stderr, "  oadtdctl license issue --private-key KEY --org ACME [--features sso,multi-tenant] [--valid-for 8760h]")
	fmt.Fprintln(os.Stderr, "  oadtdctl license verify --public-key KEY --token TOKEN")
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
