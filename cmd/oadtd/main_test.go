package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/server"
)

func TestParseFlexibleDuration(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  time.Duration
	}{
		{name: "days", input: "30d", want: 30 * 24 * time.Hour},
		{name: "weeks", input: "2w", want: 14 * 24 * time.Hour},
		{name: "hours", input: "720h", want: 720 * time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseFlexibleDuration(tc.input)
			if err != nil {
				t.Fatalf("parseFlexibleDuration(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("parseFlexibleDuration(%q) = %s, want %s", tc.input, got, tc.want)
			}
		})
	}
}

func TestSmokeServeHealthzOnLoopback(t *testing.T) {
	app, err := server.NewWithOptions(server.Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	srv := &http.Server{
		Handler:           app.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(listener)
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	url := "http://" + listener.Addr().String() + "/healthz"
	var resp *http.Response
	for i := 0; i < 30; i++ {
		resp, err = client.Get(url)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		_ = srv.Shutdown(context.Background())
		t.Fatalf("healthz request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	if err := srv.Shutdown(context.Background()); err != nil && err != http.ErrServerClosed {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}
