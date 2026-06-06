package main

import (
	"bytes"
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

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
	"github.com/open-agentic-threat-defense/oadtd/internal/telemetry"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "replay":
		if err := replay(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
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

func readEvents(filePath string) ([]domain.Event, error) {
	if filePath == "-" {
		return telemetry.ReadJSONL(os.Stdin)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return telemetry.ReadJSONL(file)
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
	fmt.Fprintln(os.Stderr, "  oadtdctl replay --file events.jsonl [--url http://localhost:8080] [--token TOKEN]")
}
