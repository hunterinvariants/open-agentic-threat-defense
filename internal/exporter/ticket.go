package exporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

// ticketSummary builds a short human-readable title for an incident ticket.
func ticketSummary(action domain.ResponseAction) string {
	summary := strings.TrimSpace(action.Reason)
	if summary == "" {
		summary = "OATD response action"
	}
	if t := strings.TrimSpace(action.Type); t != "" {
		summary = t + ": " + summary
	}
	if action.AssetID != "" {
		summary += " [" + action.AssetID + "]"
	}
	return summary
}

// ticketDescription builds a detailed, deterministic incident body.
func ticketDescription(action domain.ResponseAction) string {
	var b strings.Builder
	fmt.Fprintf(&b, "OATD response action %s\n", action.ID)
	fmt.Fprintf(&b, "type=%s asset=%s\n", action.Type, action.AssetID)
	if action.Reason != "" {
		fmt.Fprintf(&b, "reason=%s\n", action.Reason)
	}
	keys := make([]string, 0, len(action.Metadata))
	for key := range action.Metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&b, "%s=%s\n", key, action.Metadata[key])
	}
	return b.String()
}

// postJSONTo posts a JSON payload to endpoint with the given headers and a
// bounded timeout, returning an error on non-2xx.
func postJSONTo(client *http.Client, endpoint string, payload any, headers map[string]string, connector string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s connector returned %s: %s", connector, resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}
