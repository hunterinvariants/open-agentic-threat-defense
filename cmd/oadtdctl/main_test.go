package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestBatchCount(t *testing.T) {
	cases := []struct{ n, size, want int }{
		{0, 100, 0},
		{1, 100, 1},
		{100, 100, 1},
		{101, 100, 2},
		{250, 100, 3},
		{5, 0, 0},
	}
	for _, c := range cases {
		if got := batchCount(c.n, c.size); got != c.want {
			t.Fatalf("batchCount(%d,%d)=%d want %d", c.n, c.size, got, c.want)
		}
	}
}

func TestPostEventsWithRetrySucceedsAfterTransientFailures(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"alerts_created":2}`))
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	alerts, attempts, err := postEventsWithRetry(client, srv.URL, "", []domain.Event{{ID: "e1"}}, 3, time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alerts != 2 {
		t.Fatalf("expected 2 alerts, got %d", alerts)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestPostEventsWithRetryExhaustsAndReportsAttempts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "always down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	_, attempts, err := postEventsWithRetry(client, srv.URL, "", []domain.Event{{ID: "e1"}}, 2, time.Millisecond)
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if attempts != 3 { // 1 initial + 2 retries
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}
