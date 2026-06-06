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
	policyPath := flag.String("policy", "", "optional JSON policy configuration path")
	apiToken := flag.String("api-token", os.Getenv("OATD_API_TOKEN"), "optional API token for write endpoints")
	alertWebhookURL := flag.String("alert-webhook-url", os.Getenv("OATD_ALERT_WEBHOOK_URL"), "optional SIEM/webhook URL for new alerts")
	alertWebhookToken := flag.String("alert-webhook-token", os.Getenv("OATD_ALERT_WEBHOOK_TOKEN"), "optional bearer token for alert webhook")
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
		WebDir:            *webDir,
		DataPath:          *dataPath,
		APIToken:          *apiToken,
		Policy:            runtimeConfig.PolicyConfig(),
		CorrelationWindow: window,
		AlertWebhookURL:   *alertWebhookURL,
		AlertWebhookToken: *alertWebhookToken,
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
