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

	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
	"github.com/open-agentic-threat-defense/oadtd/internal/collectors"
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
	case "collect":
		if err := collect(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "replay":
		if err := replay(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "token-hash":
		if err := tokenHash(os.Args[2:]); err != nil {
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
	fmt.Fprintln(os.Stderr, "  oadtdctl token-hash --token TOKEN")
}
