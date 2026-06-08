package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// benchCommand load-tests the inline gateway decision endpoint and reports
// latency percentiles and throughput — the proof that an inline PEP adds
// acceptable overhead to each agent tool call.
func benchCommand(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	baseURL := fs.String("url", "http://localhost:8080", "OADTD base URL")
	token := fs.String("token", os.Getenv("OATD_API_TOKEN"), "API token")
	tokenFile := fs.String("token-file", "", "read the API token from a file (overrides --token)")
	concurrency := fs.Int("concurrency", 16, "number of concurrent workers")
	total := fs.Int("requests", 2000, "total number of decisions to issue")
	warmup := fs.Int("warmup", 100, "warmup requests excluded from the measurement")
	jsonOut := fs.Bool("json", false, "emit results as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *concurrency < 1 {
		*concurrency = 1
	}
	if *total < 1 {
		*total = 1
	}
	tok := *token
	if strings.TrimSpace(*tokenFile) != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("read token file: %w", err)
		}
		tok = strings.TrimSpace(string(data))
	}

	endpoint := strings.TrimRight(*baseURL, "/") + "/api/gateway/decide"
	body := []byte(`{"asset_id":"bench","actor":"bench-agent","tool_name":"asset_inventory","command":"list assets"}`)
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        *concurrency * 2,
			MaxIdleConnsPerHost: *concurrency * 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	for i := 0; i < *warmup; i++ {
		if _, err := benchDecide(client, endpoint, tok, body); err != nil {
			return fmt.Errorf("warmup failed (is the server up and the token valid?): %w", err)
		}
	}

	latencies := make([]time.Duration, *total)
	var idx int64
	var errs int64
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := atomic.AddInt64(&idx, 1) - 1
				if i >= int64(*total) {
					return
				}
				t0 := time.Now()
				code, err := benchDecide(client, endpoint, tok, body)
				latencies[i] = time.Since(t0)
				if err != nil || code >= 500 || code == http.StatusUnauthorized {
					atomic.AddInt64(&errs, 1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pct := func(p float64) time.Duration {
		if len(latencies) == 0 {
			return 0
		}
		rank := int(p / 100 * float64(len(latencies)))
		if rank >= len(latencies) {
			rank = len(latencies) - 1
		}
		return latencies[rank]
	}
	throughput := float64(*total) / elapsed.Seconds()

	if *jsonOut {
		out, _ := json.MarshalIndent(map[string]any{
			"requests": *total, "concurrency": *concurrency, "errors": errs,
			"throughput_rps": throughput,
			"p50_ms":         float64(pct(50).Microseconds()) / 1000,
			"p90_ms":         float64(pct(90).Microseconds()) / 1000,
			"p99_ms":         float64(pct(99).Microseconds()) / 1000,
			"max_ms":         float64(latencies[len(latencies)-1].Microseconds()) / 1000,
		}, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Println("oadtdctl bench — inline gateway decision latency")
		fmt.Printf("  requests=%d concurrency=%d errors=%d\n", *total, *concurrency, errs)
		fmt.Printf("  throughput: %.0f req/s\n", throughput)
		fmt.Printf("  latency:    p50=%.2fms  p90=%.2fms  p99=%.2fms  max=%.2fms\n",
			ms(pct(50)), ms(pct(90)), ms(pct(99)), ms(latencies[len(latencies)-1]))
	}
	if errs > 0 {
		return fmt.Errorf("bench completed with %d errors", errs)
	}
	return nil
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

func benchDecide(client *http.Client, endpoint, token string, body []byte) (int, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, nil
}
