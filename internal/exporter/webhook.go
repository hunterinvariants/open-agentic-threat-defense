package exporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type Webhook struct {
	URL    string
	Token  string
	Client *http.Client
}

type AlertPayload struct {
	Type       string         `json:"type"`
	ExportedAt time.Time      `json:"exported_at"`
	Alerts     []domain.Alert `json:"alerts"`
}

type ResponseActionPayload struct {
	Type           string                `json:"type"`
	ExportedAt     time.Time             `json:"exported_at"`
	ResponseAction domain.ResponseAction `json:"response_action"`
}

func (w Webhook) ExportAlerts(alerts []domain.Alert) error {
	if w.URL == "" || len(alerts) == 0 {
		return nil
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	payload := AlertPayload{
		Type:       "oadtd.alerts",
		ExportedAt: time.Now().UTC(),
		Alerts:     alerts,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("webhook returned %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func (w Webhook) ExportResponseAction(action domain.ResponseAction) error {
	if w.URL == "" {
		return nil
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	payload := ResponseActionPayload{
		Type:           "oadtd.response_action",
		ExportedAt:     time.Now().UTC(),
		ResponseAction: action,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("response webhook returned %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}
