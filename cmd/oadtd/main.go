package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/open-agentic-threat-defense/oadtd/internal/server"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	webDir := flag.String("web", "web", "static dashboard directory")
	withDemo := flag.Bool("demo", false, "load safe demo telemetry at startup")
	flag.Parse()

	app := server.New(*webDir)
	if *withDemo {
		alerts := app.LoadDemo()
		log.Printf("loaded demo telemetry with %d initial alerts", len(alerts))
	}

	log.Printf("Open Agentic Threat Defense %s listening on http://localhost%s", server.Version, *addr)
	if err := http.ListenAndServe(*addr, app.Routes()); err != nil {
		log.Fatal(err)
	}
}
