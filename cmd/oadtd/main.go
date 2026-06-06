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
