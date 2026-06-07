package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/config"
	"github.com/open-agentic-threat-defense/oadtd/internal/server"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	webDir := flag.String("web", "web", "static dashboard directory")
	dataPath := flag.String("data", "", "optional JSON snapshot path for local persistence")
	postgresDSN := flag.String("postgres-dsn", os.Getenv("OATD_POSTGRES_DSN"), "Postgres DSN for production persistence")
	policyPath := flag.String("policy", "", "optional JSON policy configuration path")
	apiToken := flag.String("api-token", os.Getenv("OATD_API_TOKEN"), "optional API token for write endpoints")
	threatPackPath := flag.String("threat-pack", os.Getenv("OATD_THREAT_PACK"), "optional threat pack JSON file")
	alertWebhookURL := flag.String("alert-webhook-url", os.Getenv("OATD_ALERT_WEBHOOK_URL"), "optional SIEM/webhook URL for new alerts")
	alertWebhookToken := flag.String("alert-webhook-token", os.Getenv("OATD_ALERT_WEBHOOK_TOKEN"), "optional bearer token for alert webhook")
	ticketWebhookURL := flag.String("ticket-webhook-url", os.Getenv("OATD_TICKET_WEBHOOK_URL"), "optional webhook URL for incident ticket creation")
	ticketWebhookToken := flag.String("ticket-webhook-token", os.Getenv("OATD_TICKET_WEBHOOK_TOKEN"), "optional bearer token for ticket webhook")
	responseWebhookURL := flag.String("response-webhook-url", os.Getenv("OATD_RESPONSE_WEBHOOK_URL"), "optional webhook URL for approved response actions")
	responseWebhookToken := flag.String("response-webhook-token", os.Getenv("OATD_RESPONSE_WEBHOOK_TOKEN"), "optional bearer token for response webhook")
	githubAPIBaseURL := flag.String("github-api-base", os.Getenv("OATD_GITHUB_API_BASE"), "optional GitHub API base URL")
	githubOwner := flag.String("github-owner", os.Getenv("OATD_GITHUB_OWNER"), "GitHub owner for issue and workflow integrations")
	githubRepo := flag.String("github-repo", os.Getenv("OATD_GITHUB_REPO"), "GitHub repository for issue and workflow integrations")
	githubToken := flag.String("github-token", os.Getenv("OATD_GITHUB_TOKEN"), "GitHub token for issue and workflow integrations")
	githubWorkflowFile := flag.String("github-workflow-file", os.Getenv("OATD_GITHUB_WORKFLOW_FILE"), "GitHub workflow file for approved response actions")
	githubWorkflowRef := flag.String("github-workflow-ref", os.Getenv("OATD_GITHUB_WORKFLOW_REF"), "GitHub ref for workflow dispatch")
	trustedProxies := flag.String("trusted-proxies", os.Getenv("OATD_TRUSTED_PROXIES"), "comma-separated list of trusted proxy CIDRs or IPs")
	retentionWindow := flag.String("retention-window", defaultString(os.Getenv("OATD_RETENTION_WINDOW"), "30d"), "retention window for events, alerts, actions, and audits")
	gatewayMaxInFlight := flag.Int("gateway-max-in-flight", defaultIntEnv(os.Getenv("OATD_GATEWAY_MAX_IN_FLIGHT"), 64), "max in-flight gateway operations before backpressure")
	insecure := flag.Bool("insecure", parseBoolEnv(os.Getenv("OATD_INSECURE")), "allow open mode on non-loopback listen addresses")
	withDemo := flag.Bool("demo", false, "load safe demo telemetry at startup")
	flag.Parse()

	runtimeConfig, err := config.Load(*policyPath)
	if err != nil {
		log.Fatal(err)
	}
	if value := strings.TrimSpace(*threatPackPath); value != "" {
		runtimeConfig.ThreatPackPath = value
	}
	if err := server.ValidateListenAddress(*addr, len(runtimeConfig.Users) > 0 || strings.TrimSpace(*apiToken) != "", *insecure); err != nil {
		log.Fatal(err)
	}
	window, err := runtimeConfig.CorrelationWindowDuration()
	if err != nil {
		log.Fatal(err)
	}
	policyConfig, err := runtimeConfig.PolicyConfig()
	if err != nil {
		log.Fatal(err)
	}
	retention, err := parseFlexibleDuration(strings.TrimSpace(*retentionWindow))
	if err != nil {
		log.Fatal(err)
	}

	app, err := server.NewWithOptions(server.Options{
		WebDir:               *webDir,
		DataPath:             *dataPath,
		PostgresDSN:          *postgresDSN,
		APIToken:             *apiToken,
		Users:                runtimeConfig.Users,
		Policy:               policyConfig,
		CorrelationWindow:    window,
		ThreatPackPath:       strings.TrimSpace(*threatPackPath),
		AlertWebhookURL:      *alertWebhookURL,
		AlertWebhookToken:    *alertWebhookToken,
		TicketWebhookURL:     *ticketWebhookURL,
		TicketWebhookToken:   *ticketWebhookToken,
		ResponseWebhookURL:   *responseWebhookURL,
		ResponseWebhookToken: *responseWebhookToken,
		GitHubAPIBaseURL:     *githubAPIBaseURL,
		GitHubOwner:          *githubOwner,
		GitHubRepo:           *githubRepo,
		GitHubToken:          *githubToken,
		GitHubWorkflowFile:   *githubWorkflowFile,
		GitHubWorkflowRef:    *githubWorkflowRef,
		TrustedProxies:       splitCSV(*trustedProxies),
		RetentionWindow:      retention,
		GatewayMaxInFlight:   *gatewayMaxInFlight,
	})
	if err != nil {
		log.Fatal(err)
	}
	if *withDemo {
		alerts, err := app.LoadDemo()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("loaded demo telemetry with %d initial alerts", len(alerts))
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	actualAddr := listener.Addr().String()
	log.Printf("Open Agentic Threat Defense %s listening on http://%s", server.Version, actualAddr)
	srv := &http.Server{
		Addr:              actualAddr,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		values = append(values, part)
	}
	return values
}

func defaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func defaultIntEnv(value string, fallback int) int {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func parseBoolEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseFlexibleDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("duration is empty")
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return duration, nil
	}

	type unit struct {
		suffix     string
		multiplier time.Duration
	}
	for _, candidate := range []unit{
		{suffix: "w", multiplier: 7 * 24 * time.Hour},
		{suffix: "d", multiplier: 24 * time.Hour},
	} {
		if !strings.HasSuffix(value, candidate.suffix) {
			continue
		}
		number := strings.TrimSpace(strings.TrimSuffix(value, candidate.suffix))
		if number == "" {
			return 0, errors.New("duration is empty")
		}
		amount, err := strconv.ParseFloat(number, 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(amount * float64(candidate.multiplier)), nil
	}

	return 0, errors.New("invalid duration")
}
