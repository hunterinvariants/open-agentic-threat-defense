package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeceptionTokensAPIAndGatewayDeny(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	// Neutral value: contains no taint/secret/discovery terms, so any deny must
	// come from the deception registry, not the heuristic analyzers.
	const canary = "ZQ7X9P2M4K8X"

	execCode := func(asset string) int {
		body := strings.NewReader(`{"tool_name":"asset_inventory","asset_id":"` + asset + `","command":"echo ` + canary + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/gateway/execute", body)
		rec := httptest.NewRecorder()
		app.Routes().ServeHTTP(rec, req)
		return rec.Code
	}

	// Baseline: an unregistered value is not blocked.
	if code := execCode("a-base"); code == http.StatusForbidden {
		t.Fatal("baseline call must not be blocked")
	}

	// Register the canary token.
	post := httptest.NewRequest(http.MethodPost, "/api/deception/tokens",
		strings.NewReader(`{"name":"c1","kind":"secret","value":"`+canary+`"}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, post)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d (%s)", rec.Code, rec.Body.String())
	}

	// It now appears in the list.
	get := httptest.NewRequest(http.MethodGet, "/api/deception/tokens", nil)
	rec = httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, get)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), canary) {
		t.Fatalf("list: expected token, got %d (%s)", rec.Code, rec.Body.String())
	}

	// The same tool call is now blocked (403) by the inline gateway.
	if code := execCode("a-hit"); code != http.StatusForbidden {
		t.Fatalf("registered canary call must be blocked, got %d", code)
	}

	// Remove it.
	del := httptest.NewRequest(http.MethodDelete, "/api/deception/tokens?id=dt-1", nil)
	rec = httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, del)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// After removal it is no longer blocked.
	if code := execCode("a-gone"); code == http.StatusForbidden {
		t.Fatal("call must not be blocked after removal")
	}
}
