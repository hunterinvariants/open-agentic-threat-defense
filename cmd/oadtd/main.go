package main

import (
	"flag"
	"log"
	"net/http"
	"os"

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
	withDemo := flag.Bool("demo", false, "load safe demo telemetry at startup")
	flag.Parse()

	runtimeConfig, err := config.Load(*policyPath)
	if err != nil {
		log.Fatal(err)
	}
	window, err := runtimeConfig.CorrelationWindowDuration()
	if err != nil {
		log.Fatal(err)
	}

	app, err := server.NewWithOptions(server.Options{
		WebDir:               *webDir,
		DataPath:             *dataPath,
		PostgresDSN:          *postgresDSN,
		APIToken:             *apiToken,
		Users:                runtimeConfig.Users,
		Policy:               runtimeConfig.PolicyConfig(),
		CorrelationWindow:    window,
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

	log.Printf("Open Agentic Threat Defense %s listening on http://localhost%s", server.Version, *addr)
	if err := http.ListenAndServe(*addr, app.Routes()); err != nil {
		log.Fatal(err)
	}
}
