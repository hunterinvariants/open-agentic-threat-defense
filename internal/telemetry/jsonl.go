package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func ReadJSONL(r io.Reader) ([]domain.Event, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	events := []domain.Event{}
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var event domain.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}
